// Package applier is the provider pipeline of the exit worker, ported from
// applier/apply.py, applier/nordvpn.py and applier/pia.py: the relay
// catalogue's upkeep, the admission pipeline, the attempt state machine, the
// egress checks, the status record and the Gatus push.
//
// Every change to the live selection goes through one admission pipeline
// (admit and runPipeline), whatever asked for it: the configured SERVER, the
// panel's request, a restore, reconvergence and automatic retries. Its state
// is the attempt record (internal/attempt), written before every mutation's
// I/O and after every outcome. The status record it builds is schema 2
// (internal/verdict).
//
// What differs from the Python applier, by design:
//
//   - It executes nothing. Every kernel and network call goes through System
//     (system.go); HTTP is internal/netx.
//   - A Provider (provider.go) holds what the Python subclasses overrode, and
//     the core calls through it; there is no inheritance. NewMullvad,
//     NewNordVPN and NewPIA are the native providers; NewGluetun is the
//     gluetun backend's (gluetun_applier.go), one provider for every gluetun
//     registry entry and for the sidecar kind.
//   - It does not write result.json. Config.Publish receives every record and
//     the supervisor publishes (decision D7); the owner_record check stays
//     "unknown" in the records built here for the supervisor to fill.
//   - One goroutine owns it: the exit worker calls Tick every PollSec seconds.
//     Healthy only reads files and calls System, and may be called from
//     another goroutine.
//   - There is no doctor or command-line entry (decision D22).
//
// The package offers New (Config, Exit, Gatus), Tick, Inspect, Switch,
// Healthy, the System seam (and GluetunKernel, the extra reads of the gluetun
// backend) and Provider hooks, the native providers, the gluetun provider with
// its control-server client, catalogue and marked echo, Record, and
// ChangePIAAddress, the ordering of PIA's address-change transaction.
package applier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/irashack/molebridge/internal/attempt"
	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

// Applier owns the relay catalogue, admits selections, switches peers and
// reports health for one exit.
type Applier struct {
	sys        System
	hooks      Provider
	spec       *providers.Provider
	exit       Exit
	gatus      Gatus
	publish    func(*Record) error
	ownerCheck func() validate.Obj
	logf       func(string)

	clock   func() float64
	wallNow func() time.Time
	sleeper func(ctx context.Context, d time.Duration)

	configuredServer string
	configuredAt     string
	directory        string
	resultPath       string
	attemptPath      string
	desiredPath      string
	readJSON         func(path string, limit int64) any
	exists           func(path string) bool

	catalog Catalog
	bootID  string
	attempt *attempt.Attempt
	// request is the panel's latest valid request (its acknowledgement), or
	// the configured one; invalidDesired is whether desired.json is unreadable.
	request        *state.Request
	invalidDesired bool
	target         *Selection
	nextCatalog    float64
	nextHealth     float64
	// measurement is the last inspection's findings.
	measurement *Finding
	// unidentifiedSince is since when a live peer the catalogue can't name has
	// been seen.
	unidentifiedSince *float64
	// switchDeadline is, while a switch is being verified, the time it gives
	// up. retryDeadline is, while an egress check is asked a second time, the
	// time after which it starts no further request.
	switchDeadline *float64
	retryDeadline  *float64
	started        bool
}

// New builds the applier for a provider's settings.
func New(cfg Config) (*Applier, error) {
	if cfg.Provider == nil || cfg.System == nil {
		return nil, errors.New("applier: a provider and a system are required")
	}
	spec, err := providers.Get(cfg.Provider.ID())
	if err != nil {
		return nil, err
	}
	// Validate the provider and kind before building the catalogue.
	if _, err := verdict.NewExitConfig(spec.ID, cfg.Exit.Kind, ""); err != nil {
		return nil, err
	}
	if checker, ok := cfg.Provider.(SystemChecker); ok {
		if err := checker.CheckSystem(cfg.System, cfg.Exit); err != nil {
			return nil, err
		}
	}
	a := &Applier{sys: cfg.System, hooks: cfg.Provider, spec: spec, exit: cfg.Exit, gatus: cfg.Gatus,
		publish: cfg.Publish, ownerCheck: cfg.OwnerCheck, logf: cfg.Log, clock: cfg.Monotonic, wallNow: cfg.Wall, sleeper: cfg.Sleep,
		readJSON: state.ReadJSON, exists: fileExists}
	if a.exit.Kind == "" {
		a.exit.Kind = "overlay"
	}
	if a.clock == nil {
		a.clock = BootClock
	}
	if a.wallNow == nil {
		a.wallNow = time.Now
	}
	if a.sleeper == nil {
		a.sleeper = sleepContext
	}
	if a.logf == nil {
		a.logf = func(s string) { fmt.Fprintln(os.Stdout, s) }
	}
	a.configuredServer = surrogateEscape(cfg.Server)
	a.configuredAt = validate.FormatTime(a.wall())
	a.directory = filepath.Join(cfg.StateDir, "applier")
	a.resultPath = filepath.Join(a.directory, "result.json")
	a.attemptPath = filepath.Join(a.directory, "attempt.json")
	a.desiredPath = filepath.Join(cfg.StateDir, "panel", "desired.json")
	a.catalog = a.hooks.MakeCatalog(a)
	a.bootID = cfg.BootID
	if a.bootID == "" {
		a.bootID = attempt.ReadBootID(attempt.BootIDFile)
	}
	a.attempt = attempt.Load(a.attemptPath, a.bootID, a.clock())
	return a, nil
}

func sleepContext(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}

func (a *Applier) wall() time.Time { return a.wallNow() }

func (a *Applier) sleep(ctx context.Context, seconds float64) {
	a.sleeper(ctx, time.Duration(seconds*float64(time.Second)))
}

func (a *Applier) nowISO() string { return validate.FormatTime(a.wall()) }

func (a *Applier) log(message string) { a.logf(message) }

func (a *Applier) kind() string { return a.exit.Kind }

func (a *Applier) backend() string { return verdict.BackendOf(a.hooks.ID()) }

func (a *Applier) nativeSidecar() bool { return a.kind() == "sidecar" && a.backend() == "native" }

func (a *Applier) exitConfig() verdict.ExitConfig {
	return verdict.ExitConfig{Provider: a.hooks.ID(), Kind: a.kind()}
}

// ConfiguredServer is the SERVER setting as the applier holds it.
func (a *Applier) ConfiguredServer() string { return a.configuredServer }

// RequestPath is state/panel/desired.json.
func (a *Applier) RequestPath() string { return a.desiredPath }

// Attempt is the current attempt record (for tests and tools).
func (a *Applier) Attempt() *attempt.Attempt { return a.attempt }

func (a *Applier) configuredRequest() *state.Request {
	request, ok := state.DesiredRequest(map[string]any{"server": a.configuredServer, "requested_at": a.configuredAt},
		a.hooks.ID())
	if !ok {
		return nil
	}
	return &request
}

// configurationError is the message for an unusable SERVER, "" when there is
// none.
func (a *Applier) configurationError() string {
	if a.configuredServer == "" {
		return ""
	}
	// Quote untrusted text without allowing control characters into status/logs.
	raw, _ := validate.MarshalJSON(truncateChars(a.configuredServer, ServerReportChars))
	quoted := string(raw)
	if a.configuredRequest() == nil {
		return "Invalid SERVER " + quoted + "; no change applied."
	}
	if a.catalog.Usable() && !a.catalog.Relays().Has(a.configuredServer) {
		return "Unknown SERVER " + quoted + "; not in a fresh trusted relay catalogue; no change applied."
	}
	return ""
}

// DefaultFetchCatalog downloads the registry entry's server list. A redirect
// is refused, not followed.
func (a *Applier) DefaultFetchCatalog(ctx context.Context) ([]byte, error) {
	spec := a.spec
	response, err := a.sys.Fetch(ctx, netx.Request{
		URL: spec.CatalogURL, UserAgent: "molebridge-applier/0.2", MaxBytes: int64(spec.CatalogMaxBytes),
		Timeout: time.Duration(spec.CatalogTimeoutS) * time.Second, ConnectTimeout: 10 * time.Second})
	if err != nil {
		return nil, err
	}
	if response.Status != 200 {
		return nil, errors.New("unexpected catalogue HTTP status; redirects refused")
	}
	return response.Body, nil
}

// catalogSignature is what a rejection for an unlisted server waits to
// change: the catalogue's names, nil while it is unusable.
func (a *Applier) catalogSignature() []string {
	if !a.catalog.Usable() {
		return nil
	}
	names := a.catalog.Relays().Names()
	sort.Strings(names)
	return names
}

// tunnelAddresses are the global tunnel addresses by family, read from the
// interface, never its routes. Exactly one address per family is supported:
// the return-path rule and the kernel's ICMP source selection both assume a
// single address.
func (a *Applier) tunnelAddresses(ctx context.Context, requireIPv4 bool) (map[int]string, error) {
	addresses, err := a.sys.TunnelAddresses(ctx)
	if err != nil {
		return nil, err
	}
	return groupAddresses(addresses, requireIPv4)
}

// groupAddresses is tunnelAddresses' judgment of the interface's addresses.
func groupAddresses(addresses []netip.Addr, requireIPv4 bool) (map[int]string, error) {
	found := map[int]string{}
	for _, address := range addresses {
		version := 6
		if address.Is4() {
			version = 4
		}
		if _, dup := found[version]; dup {
			return nil, errors.New("multiple tunnel addresses for one family")
		}
		found[version] = address.String()
	}
	if _, ok := found[4]; !ok && requireIPv4 {
		return nil, errors.New("missing IPv4 tunnel address")
	}
	return found, nil
}

func sortedFamilies(addresses map[int]string) []int {
	families := make([]int, 0, len(addresses))
	for family := range addresses {
		families = append(families, family)
	}
	sort.Ints(families)
	return families
}

// DefaultRoutingStatus is (protected, fallback). Without requireAddress an
// interface that has no address yet passes when its guards are intact: a
// provider that assigns the address per server installs rules 94 and 98 with
// it.
func (a *Applier) DefaultRoutingStatus(ctx context.Context, requireAddress bool) (bool, bool) {
	if !a.nativeSidecar() {
		if err := a.sys.LinkExists(ctx, a.exit.OverlayIf); err != nil {
			return false, false
		}
	}
	addresses, err := a.tunnelAddresses(ctx, requireAddress)
	if err != nil {
		return false, false
	}
	protected, fallback := true, true
	if !a.nativeSidecar() {
		text, err := a.sys.ReadSysctl(ctx, ReturnPathSysctl)
		if err != nil {
			return false, false
		}
		protected = strings.TrimFunc(text, validate.IsSpace) == "1"
	}
	var failure error
	for _, family := range []int{4, 6} {
		p, f, err := a.sys.RoutingStatus(ctx, family, addresses[family])
		if err != nil {
			failure = err
			break
		}
		protected = protected && p
		fallback = fallback && f
	}
	if failure != nil {
		return false, false
	}
	return protected, fallback
}

func (a *Applier) routingStatus(ctx context.Context, requireAddress bool) (bool, bool) {
	return a.hooks.RoutingStatus(ctx, a, requireAddress)
}

// netbirdNative is true when NetBird runs kernel WireGuard on the overlay
// interface and its own kernel firewall is in place, as Molebridge requires.
func (a *Applier) netbirdNative(ctx context.Context) bool {
	native, err := a.sys.OverlayKernelWireGuard(ctx)
	if err != nil || !native {
		return false
	}
	present, err := a.sys.NetbirdFirewallPresent(ctx)
	return err == nil && present
}

func (a *Applier) peers(ctx context.Context) ([]string, error) {
	keys, err := a.sys.Peers(ctx)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if !validate.ValidKey(key) {
			return nil, errors.New("invalid peer key")
		}
	}
	return keys, nil
}

// DefaultServerFor is the server whose key is the one live peer's, if exactly
// one relay has it.
func (a *Applier) DefaultServerFor(keys []string) string {
	if len(keys) != 1 {
		return ""
	}
	var matches []string
	a.catalog.Relays().Each(func(name string, relay *providers.Relay) bool {
		if relay.PublicKey == keys[0] {
			matches = append(matches, name)
		}
		return true
	})
	if len(matches) == 1 {
		return matches[0]
	}
	return ""
}

// handshakeAge is the peer's last handshake age in seconds, nil when it has
// none or the clock disagrees.
func (a *Applier) handshakeAge(ctx context.Context, key string) (*int, error) {
	handshakes, err := a.sys.LatestHandshakes(ctx)
	if err != nil {
		return nil, err
	}
	timestamp, ok := handshakes[key]
	if !ok {
		return nil, nil
	}
	age := a.wall().Unix() - timestamp
	if timestamp > 0 && age >= 0 {
		return intPtr(int(age)), nil
	}
	return nil, nil
}

// DefaultApplyRelay points the tunnel at an approved relay (Mullvad's way: the
// other peers go, the relay's own key is updated in place). A failed removal
// aborts before any new peer is added.
func (a *Applier) DefaultApplyRelay(ctx context.Context, relay *providers.Relay, keys []string) error {
	var remove []string
	for _, key := range keys {
		if key != relay.PublicKey {
			remove = append(remove, key)
		}
	}
	return a.sys.ReplacePeer(ctx, remove, PeerConfig{PublicKey: relay.PublicKey, Endpoint: relay.IPv4AddrIn + ":51820",
		AllowedIPs: []string{"0.0.0.0/0", "::/0"}, KeepaliveSec: 25})
}

// -- the status record (schema 2, internal/verdict) -------------------------------------

// blankChecks is every check, unmeasured: required ones "unknown", the rest as
// the kind fixes them.
func (a *Applier) blankChecks() validate.Obj {
	kind, backend := a.kind(), a.backend()
	checks := validate.Obj{}
	for _, name := range verdict.RequiredChecks(kind, backend) {
		checks = append(checks, validate.Pair{Key: name, Value: validate.Members("state", "unknown")})
	}
	for _, fixed := range verdict.FixedChecks(kind, backend) {
		check := validate.Members("state", fixed.State)
		if fixed.State == "not-checked" {
			check = check.Set("by", verdict.NotCheckedBy[fixed.Name])
		}
		checks = checks.Set(fixed.Name, check)
	}
	return checks
}

// wallOf is a boot-clock deadline as wall-clock time, for display.
func (a *Applier) wallOf(deadline *float64) any {
	if deadline == nil {
		return nil
	}
	moment := a.wall().Add(time.Duration(math.Max(0, *deadline-a.clock()) * float64(time.Second)))
	return validate.FormatTime(moment)
}

// requestRejected is true while the panel's current request stands refused: it
// is acknowledged with its reason and never becomes the target (D12).
func (a *Applier) requestRejected() bool {
	if a.configuredServer != "" {
		return false
	}
	if a.invalidDesired {
		return true
	}
	rejected := a.attempt.Rejected
	return a.request != nil && rejected != nil && rejected.Key == state.RequestToken(*a.request)
}

func (a *Applier) rejectionMessage() string {
	if a.invalidDesired {
		return InvalidDesired
	}
	if r := a.attempt.Rejected; r != nil && r.Reason != "" {
		return r.Reason
	}
	return Unlisted
}

func (a *Applier) selectionRecord() validate.Obj {
	at := a.attempt
	if a.requestRejected() {
		var target any
		if a.request != nil {
			target = a.request.Server
		}
		return validate.Members("source", "panel", "outcome", "rejected", "attempt", 0, "target", target,
			"next_action", nil, "next_action_at", nil)
	}
	source := at.Source
	if source == "" {
		source = "seed"
	}
	var nextAt any
	if at.NextAction != "" {
		nextAt = a.wallOf(at.NextActionAt)
	}
	return validate.Members("source", source, "outcome", orNull(at.Outcome), "attempt", at.Attempts,
		"target", orNull(at.Target), "next_action", orNull(at.NextAction), "next_action_at", nextAt)
}

// publishRecord builds a status record and hands it to the supervisor.
func (a *Applier) publishRecord(status, message, server string, checks, fields validate.Obj) (*Record, error) {
	if len(checks) == 0 {
		checks = a.blankChecks()
	}
	var requested, requestID any
	if a.request != nil {
		requested, requestID = a.request.Server, state.RequestToken(*a.request)
	}
	members := validate.Members("schema", verdict.Schema, "kind", a.kind(), "backend", a.backend(),
		"provider", a.hooks.ID(), "status", status, "message", orNull(message), "checked_at", a.nowISO(),
		"server", orNull(server), "requested_server", requested,
		"configured_server", orNull(truncateChars(a.configuredServer, ServerReportChars)),
		"request_id", requestID, "selection", a.selectionRecord(), "checks", checks,
		"egress_ip", nil, "egress_ips", validate.Obj{}, "egress_city", nil, "egress_country", nil)
	members = append(members, a.hooks.ResultDefaults()...)
	all := append(validate.Obj(nil), fields...)
	for _, pair := range a.hooks.PublishDefaults() {
		present := false
		for _, have := range all {
			present = present || have.Key == pair.Key
		}
		if !present {
			all = append(all, pair)
		}
	}
	for _, pair := range all {
		members = members.Set(pair.Key, pair.Value)
	}
	record := &Record{members: members}
	if a.publish != nil {
		if err := a.publish(record); err != nil {
			return record, wrapIO(err)
		}
	}
	a.hooks.Published(a.judged(record))
	return record, nil
}

// judged is a record as the supervisor will publish it: with its owner_record
// check, which only the supervisor can measure, filled in (decision D7).
func (a *Applier) judged(record *Record) *Record {
	if a.ownerCheck == nil || record == nil {
		return record
	}
	checks, ok := record.Get("checks").(validate.Obj)
	if !ok {
		return record
	}
	unknown := false
	for _, pair := range checks {
		if check, isObj := pair.Value.(validate.Obj); pair.Key == "owner_record" && isObj && len(check) > 0 {
			unknown = check[0].Value == "unknown"
		}
	}
	if !unknown {
		return record
	}
	filled := append(validate.Obj(nil), checks...).Set("owner_record", a.ownerCheck())
	return &Record{members: append(validate.Obj(nil), record.members...).Set("checks", filled)}
}

func (a *Applier) saveAttempt() error {
	if err := a.attempt.Save(a.attemptPath); err != nil {
		return wrapIO(err)
	}
	return nil
}

// -- inspection --------------------------------------------------------------------------

// DefaultMeasureGuards fills the routing contract and traffic protection
// checks, with NetBird's kernel mode on an overlay or the firewall on a native
// sidecar. The overlay's owner record is the supervisor's check, left unknown
// here.
func (a *Applier) DefaultMeasureGuards(ctx context.Context, at string, f *Finding) {
	protected, fallback := a.routingStatus(ctx, true)
	routing := "fail"
	if protected {
		routing = "pass"
	}
	f.Checks = f.Checks.Set("routing", validate.Members("state", routing, "at", at, "fallback", fallback))
	if a.nativeSidecar() {
		firewall, _, err := a.sys.SidecarFirewall(ctx)
		f.Safe = protected && firewall && err == nil
		protection, from := "pass", "routing"
		if !protected {
			protection, f.Guard = "fail", RoutingFailed
		} else if !firewall || err != nil {
			protection, from, f.Guard = "fail", "firewall", SidecarFirewallFailed
		}
		f.Checks = f.Checks.Set("traffic_protection", validate.Members("state", protection, "at", at, "from", from))
		return
	}
	native := a.netbirdNative(ctx)
	f.Checks = f.Checks.Set("traffic_protection", validate.Members("state", routing, "at", at, "from", "routing"))
	nb := "fail"
	if native {
		nb = "pass"
	}
	f.Checks = f.Checks.Set("netbird", validate.Members("state", nb, "at", at))
	f.Safe = protected && native
	if !protected {
		f.Guard = RoutingFailed
	} else if !native {
		f.Guard = NetbirdModeFailed
	}
}

func (a *Applier) newFinding() *Finding {
	return &Finding{Status: "failed", Checks: a.blankChecks(), Safe: true, Peers: -1, At: a.clock()}
}

// measure is one inspection: every check this kind requires, each stamped
// with when it was measured, stopping where later checks can't pass. It
// returns the finding; emit publishes it.
func (a *Applier) measure(ctx context.Context, applying bool) *Finding {
	at := a.nowISO()
	f := a.newFinding()
	selected := a.target
	if selected == nil && a.configuredServer != "" {
		selected = a.configuredSelection()
	}
	target := ""
	if selected != nil {
		target = selected.Server
	}
	if message := a.configurationError(); message != "" {
		f.Message = message
		return f
	}
	failed := func() *Finding {
		f.Message = EgressFailedMessage
		return f
	}
	if a.kind() == "overlay" || a.nativeSidecar() {
		a.hooks.MeasureGuards(ctx, a, at, f)
	}
	keys, err := a.peers(ctx)
	if err != nil {
		return failed()
	}
	f.Peers = len(keys)
	server, err := a.hooks.ServerFor(ctx, a, keys)
	if err != nil {
		return failed()
	}
	f.Server = server
	peer := validate.Members("state", "fail", "at", at, "server", orNull(server))
	switch {
	case len(keys) == 0:
		peer = peer.Set("reason", "no-peer")
	case len(keys) > 1:
		peer = peer.Set("reason", "multiple-peers")
	case !a.catalog.Usable():
		peer = peer.Set("reason", "catalogue-stale")
	case server == "":
		peer = peer.Set("reason", "unidentified")
	case target != "" && server != target:
		peer = peer.Set("reason", "not-target")
	default:
		peer = peer.Set("state", "pass")
	}
	f.Checks = f.Checks.Set("peer", peer)
	if len(keys) != 1 {
		f.Message = a.hooks.NoPeerMessage(a, keys)
		return f
	}
	age, err := a.handshakeAge(ctx, keys[0])
	if err != nil {
		return failed()
	}
	f.Age = age
	fresh := age != nil && 0 <= *age && *age < HandshakeFreshSec
	handshake := "fail"
	if fresh {
		handshake = "pass"
	}
	var ageValue any
	if age != nil {
		ageValue = *age
	}
	f.Checks = f.Checks.Set("handshake", validate.Members("state", handshake, "at", at, "server", orNull(server),
		"age_s", ageValue))
	if f.Guard != "" {
		f.Message = f.Guard
		return f
	}
	tunnel, err := a.tunnelAddresses(ctx, true)
	if err != nil {
		return failed()
	}
	expected := make([]string, 0, 2)
	expectedAny := make([]any, 0, 2)
	for _, family := range sortedFamilies(tunnel) {
		expected = append(expected, strconv.Itoa(family))
		expectedAny = append(expectedAny, strconv.Itoa(family))
	}
	egress, err := a.checkedEgress(ctx, server, age, applying)
	if err != nil {
		f.Checks = f.Checks.Set("egress", validate.Members("state", "fail", "at", a.nowISO(), "server", orNull(server),
			"reason", "unanswered", "tier", nil, "expected_families", expectedAny, "families", validate.Obj{}))
		f.Message = EgressFailedMessage
		return f
	}
	tier := a.egressTier(egress)
	families := validate.Obj{}
	for _, name := range expected {
		if state, ok := egress.family(name); ok {
			families = append(families, validate.Pair{Key: name, Value: state})
		}
	}
	if tier != "" {
		families = validate.Obj{}
		for _, name := range expected {
			families = append(families, validate.Pair{Key: name, Value: "pass"})
		}
	}
	passing := map[string]bool{}
	for _, pair := range families {
		if pair.Value == "pass" {
			passing[pair.Key] = true
		}
	}
	reason := egress.Reason
	if reason == "" {
		reason = "not-confirmed"
		if a.spec.EgressTier == providers.TierTunnel {
			reason = "tunnel-checks-failed"
		}
	}
	shown := validate.Obj{}
	for _, name := range expected {
		value := "unknown"
		for _, pair := range families {
			if pair.Key == name {
				value, _ = pair.Value.(string)
			}
		}
		shown = append(shown, validate.Pair{Key: name, Value: value})
	}
	result := "fail"
	if tier != "" {
		result = "pass"
	}
	check := validate.Members("state", result, "at", a.nowISO(), "server", orNull(server), "tier", orNull(tier),
		"expected_families", expectedAny, "families", shown)
	if tier == "" {
		check = check.Set("reason", reason)
	}
	f.Checks = f.Checks.Set("egress", check)
	shownIPs := validate.Obj{}
	for _, pair := range egress.EgressIPs {
		if passing[pair.Key] {
			shownIPs = append(shownIPs, pair)
		}
	}
	f.Fields = validate.Members("egress_ip", orNull(egress.EgressIP), "egress_city", ptrOrNull(egress.EgressCity),
		"egress_country", ptrOrNull(egress.EgressCountry), "egress_ips", shownIPs)
	var failure string
	switch {
	case !fresh:
		failure = "Tunnel handshake is missing or stale; check the account and connectivity."
	case tier == "":
		failure = egress.Message
		if failure == "" {
			if a.spec.EgressTier == providers.TierTunnel {
				failure = "Tunnel egress did not pass the tunnel checks."
			} else {
				failure = "Tunnel egress is not confirmed as " + a.spec.Label + "."
			}
		}
	case !a.catalog.Usable() || server == "":
		failure = "Current peer cannot be verified against a fresh relay catalogue."
	case target != "" && server != target:
		if a.configuredServer != "" {
			failure = "The configured SERVER is not the current server; waiting for convergence."
		} else {
			failure = "The live server is not the selected one; waiting for convergence."
		}
	}
	if failure != "" {
		f.Status, f.Message = "failed", failure
	} else {
		f.Status, f.Message = "ok", "Healthy."
	}
	return f
}

// egressTier is "provider" when the provider confirmed egress; "tunnel" when
// the tunnel checks passed for a provider without its own check; else "".
func (a *Applier) egressTier(e EgressResult) string {
	if e.ExitConfirmed {
		return providers.TierProvider
	}
	if a.spec.EgressTier == providers.TierTunnel && e.EgressTier == providers.TierTunnel {
		return providers.TierTunnel
	}
	return ""
}

// emit publishes a finding, with the pipeline's own state taking precedence: a
// refused request, missing prerequisites or a failed mutation are what the
// exit reports until a check finds the target met.
func (a *Applier) emit(f *Finding, applying bool) (*Record, error) {
	status, message := f.Status, f.Message
	at := a.attempt
	held := (at.State == "pending" || at.State == "rejected") && (at.Target != "" || a.configuredServer != "")
	switch {
	case a.requestRejected():
		status, message = "failed", a.rejectionMessage()
	case held:
		status, message = "failed", at.Message
	case at.State == "failed" && status != "ok":
		status, message = "failed", at.Message
	case applying && status == "failed" && f.Safe:
		// A switch being verified: what isn't there yet is expected.
		status, message = "applying", a.hooks.WaitingMessage()
	}
	return a.publishRecord(status, message, f.Server, f.Checks, f.Fields)
}

// Inspect measures and publishes (tests and tools).
func (a *Applier) Inspect(ctx context.Context, applying bool) (*Record, error) {
	f := a.measure(ctx, applying)
	a.measurement = f
	return a.emit(f, applying)
}

func (a *Applier) withinRetryBudget() error {
	if a.retryDeadline != nil && a.clock() > *a.retryDeadline {
		return errors.New("egress retry ran out of time")
	}
	return nil
}

// checkedEgress is egressFor, asked once more after EgressRetrySec when it
// gets no usable answer. An answer that does not confirm the provider is never
// asked again: each check returns it as soon as it has one, before any further
// request. There is no second attempt while a switch is verified (its own loop
// asks again until its timeout), when the check fails whatever the answer (a
// missing or stale handshake, a rejected or pending selection, a peer not in a
// fresh catalogue), or when the first attempt took longer than
// EgressRetryWithinSec; the second starts no request after
// EgressRetryBudgetSec. The previous result stays published until this
// check's own result replaces it.
func (a *Applier) checkedEgress(ctx context.Context, server string, age *int, applying bool) (EgressResult, error) {
	started := a.clock()
	result, err := a.hooks.EgressFor(ctx, a, server, age)
	if err == nil {
		return result, nil
	}
	if ctx.Err() != nil {
		return EgressResult{}, ctx.Err()
	}
	fresh := age != nil && 0 <= *age && *age < HandshakeFreshSec
	doomed := !fresh || a.attempt.State == "pending" || a.attempt.State == "rejected" || a.requestRejected() ||
		server == "" || !a.catalog.Usable()
	slow := a.clock()-started > EgressRetryWithinSec
	if applying || a.switchDeadline != nil || doomed || slow {
		return EgressResult{}, err
	}
	a.log("applier: egress check got no answer; asking once more")
	a.sleep(ctx, EgressRetrySec)
	deadline := a.clock() + EgressRetryBudgetSec
	a.retryDeadline = &deadline
	defer func() { a.retryDeadline = nil }()
	result, err = a.hooks.EgressFor(ctx, a, server, age)
	if err != nil {
		a.log("applier: egress check got no answer twice")
		return EgressResult{}, err
	}
	return result, nil
}

// DefaultEgressFor is the egress fields for the current server. A provider
// with its own typed check confirms through its Egress; one without gets the
// tunnel checks.
func (a *Applier) DefaultEgressFor(ctx context.Context, server string, age *int) (EgressResult, error) {
	if a.spec.EgressTier == providers.TierTunnel {
		return a.TunnelEgress(ctx, server, age)
	}
	return a.hooks.Egress(ctx, a)
}

// -- check, resume and the target -----------------------------------------------------------

// check is the periodic check: it re-checks the selection, never switches.
func (a *Applier) check(ctx context.Context) (*Record, error) {
	f := a.measure(ctx, false)
	a.measurement = f
	at, target := a.attempt, a.target
	if target != nil && at.State != "pending" && at.State != "rejected" && at.State != "attempting" {
		onTarget := f.Server == target.Server
		switch {
		case f.Status == "ok" && onTarget:
			if at.State != "idle" || at.Outcome != "verified" {
				at.Settle()
				if err := a.saveAttempt(); err != nil {
					return nil, err
				}
			}
			if err := a.hooks.OnVerified(a, target.Server); err != nil {
				return nil, err
			}
		case onTarget && at.State == "idle":
			// Applied, not verified: re-checked, never switched again (D7).
			a.markUnverified()
			at.MutationCertainty = ""
			if err := a.saveAttempt(); err != nil {
				return nil, err
			}
		case at.State == "unverified":
			a.scheduleRecheck()
			if err := a.saveAttempt(); err != nil {
				return nil, err
			}
		}
	}
	if at.Generation == "" {
		if generation := a.sys.OwnerGeneration(ctx); generation != "" {
			// Known from the start, so the exit container's next start is seen
			// as one even before this applier changes anything.
			at.Generation = generation
			if err := a.saveAttempt(); err != nil {
				return nil, err
			}
		}
	}
	a.nextHealth = a.clock() + RefreshSec
	return a.emit(f, false)
}

func (a *Applier) markUnverified() {
	at := a.attempt
	at.State, at.Outcome, at.Message = "unverified", "applied-unverified", ""
	a.scheduleRecheck()
}

func (a *Applier) scheduleRecheck() {
	due := a.clock() + RefreshSec
	a.attempt.NextAction, a.attempt.NextActionAt = "recheck", &due
}

// resolve is the effective target: SERVER, else the panel's accepted request,
// else (gluetun) the server to restore, else nil. With peek, nothing is
// remembered (the Gatus push).
func (a *Applier) resolve(peek bool) *Selection {
	if a.configuredServer != "" {
		if !peek {
			a.request, a.invalidDesired = a.configuredRequest(), false
		}
		return a.configuredSelection()
	}
	raw := a.readJSON(a.desiredPath, 4096)
	request, ok := state.DesiredRequest(raw, a.hooks.ID())
	invalid := !ok && (raw != nil || a.exists(a.desiredPath))
	if !peek {
		if ok {
			a.request = &request
		} else {
			a.request = nil
		}
		a.invalidDesired = invalid
	}
	if ok && !a.refused(request) {
		return &Selection{Server: request.Server, Source: "panel", Request: &request}
	}
	return a.hooks.RestoreTarget(a)
}

func (a *Applier) configuredSelection() *Selection {
	// An invalid SERVER can't match any server: kept bounded, as reported.
	return &Selection{Server: truncateChars(a.configuredServer, ServerReportChars), Source: "configured"}
}

// refused is true while request stands rejected: the same request, and nothing
// changed that could let it pass.
func (a *Applier) refused(request state.Request) bool {
	rejected := a.attempt.Rejected
	return rejected != nil && rejected.Key == state.RequestToken(request) &&
		rejected.Release == a.releaseSignature(rejected.Why)
}

// releaseSignature is what a rejection waits for: the catalogue for an
// unlisted server, the credentials for a refused login. Others are never
// released.
func (a *Applier) releaseSignature(why string) string {
	if signature, ok := a.hooks.ReleaseSignature(a, why); ok {
		return signature
	}
	if why == "catalogue" {
		names := a.catalogSignature()
		if names == nil {
			return ""
		}
		sum := sha256.Sum256([]byte(strings.Join(names, "\n")))
		return hex.EncodeToString(sum[:])
	}
	return why
}

// -- admission -------------------------------------------------------------------------------

// Tick is one pass of the control loop (every PollSec seconds): it maintains
// the catalogue, resolves the target, resumes an interrupted attempt, admits a
// change or runs the periodic check. It returns the record it published, nil
// when it published none. An error is a failure of the applier's own file I/O
// or a canceled context; every other failure is a step that failed and is
// reported in the record.
func (a *Applier) Tick(ctx context.Context) (*Record, error) {
	a.hooks.BeforeTick(ctx, a)
	result, err := a.tick(ctx)
	if err != nil {
		return nil, err
	}
	a.hooks.AfterTick(ctx, a, result)
	return result, nil
}

func (a *Applier) tick(ctx context.Context) (*Record, error) {
	if err := a.hooks.MaintainCatalog(ctx, a); err != nil {
		return nil, err
	}
	a.target = a.resolve(false)
	var result *Record
	var err error
	if !a.started {
		a.started = true
		if result, err = a.resume(ctx); err != nil {
			return nil, err
		}
	}
	if result == nil {
		if result, err = a.admit(ctx, a.target); err != nil {
			return nil, err
		}
	}
	if result == nil && a.clock() >= a.nextHealth {
		if result, err = a.check(ctx); err != nil {
			return nil, err
		}
	}
	if result != nil {
		a.pushGatus(ctx, result)
	}
	return result, nil
}

// DefaultMaintainCatalog refreshes the catalogue when it is due.
func (a *Applier) DefaultMaintainCatalog(ctx context.Context) error {
	if a.clock() < a.nextCatalog {
		return nil
	}
	refreshed, err := a.catalog.Refresh(ctx, func() ([]byte, error) { return a.hooks.FetchCatalog(ctx, a) })
	// A provider's server list is megabytes of JSON parsed into a much smaller
	// catalogue; hand the parse's garbage back to the kernel now rather than
	// keep it as idle heap until the next refresh.
	debug.FreeOSMemory()
	if err != nil {
		return wrapIO(err)
	}
	interval := 60.0
	if refreshed {
		interval = providers.RefreshIntervalS
	}
	a.nextCatalog = a.clock() + interval
	return nil
}

// resume: at start, an attempt interrupted mid-mutation is inspected first,
// never replayed: its live server either is the target (verify) or not (a
// failed, uncertain attempt, re-applied on its backoff, which inspects again
// first).
func (a *Applier) resume(ctx context.Context) (*Record, error) {
	at := a.attempt
	if at.State != "attempting" {
		return nil, nil
	}
	a.log("applier: an interrupted switch is inspected before anything else")
	f := a.measure(ctx, false)
	a.measurement = f
	if at.Target != "" && f.Server == at.Target {
		if f.Status == "ok" {
			at.Settle()
			if err := a.hooks.OnVerified(a, at.Target); err != nil {
				return nil, err
			}
		} else {
			a.markUnverified()
		}
	} else {
		at.State, at.Outcome = "failed", "mutation-failed"
		at.MutationCertainty = "uncertain"
		at.Message = "The last switch was interrupted; retrying automatically."
		at.Schedule("reapply", a.clock())
	}
	if err := a.saveAttempt(); err != nil {
		return nil, err
	}
	a.nextHealth = a.clock() + RefreshSec
	return a.emit(f, false)
}

func isRestState(state string) bool { return state == "idle" || state == "unverified" }

// admit applies the triggers, in precedence order (docs/architecture.md):
// 1-2. a new effective target (a new request id is "Retry now");
// 3. no live peer: on the native backend at once from idle or unverified, and
// once per new owner generation whatever the state; on gluetun as 7;
// 4. a due re-apply on the backoff;
// 5. a lapsed registration (D15);
// 6-7. a live peer that isn't the target, only from idle or unverified; after
// UnidentifiedSec when the catalogue can't name it.
// Nothing re-applies within ReapplyGuardSec of the last mutation.
func (a *Applier) admit(ctx context.Context, target *Selection) (*Record, error) {
	at := a.attempt
	now := a.clock()
	key := ""
	if target != nil {
		key = target.Key()
	}
	if key != at.TargetKey {
		return a.start(ctx, target)
	}
	if target == nil || at.State == "attempting" {
		return nil, nil
	}
	source := func() string {
		if at.Source != "" {
			return at.Source
		}
		return target.Source
	}
	switch at.State {
	case "pending":
		if a.gate(ctx, target) != nil {
			return nil, nil
		}
		return a.runPipeline(ctx, target, source(), !a.askedNow(target), false)
	case "rejected":
		if at.Extra.Release != a.releaseSignature(at.Extra.Why) {
			return a.runPipeline(ctx, target, source(), true, false)
		}
		return nil, nil
	}
	keys, err := a.peers(ctx)
	if err != nil {
		return nil, nil
	}
	guard := at.GuardPassed(now)
	if len(keys) == 0 {
		// The native tunnel comes back from its config without the peer (the
		// exit's routing loop recreates a lost interface, NordVPN's and PIA's
		// configs have none): applied again at once from idle or unverified,
		// and once per new owner generation even while a failure backs off.
		// gluetun leaves its interface without a peer for a moment while it
		// reconnects by itself, so there no peer is waited out like an
		// unidentified one.
		generation := a.currentGeneration(ctx)
		freshOwner := generation != "" && at.Generation != "" && at.Generation != generation
		if guard && (freshOwner || (a.backend() == "native" && isRestState(at.State))) {
			if freshOwner {
				a.log("applier: the exit container started again; applying the selection")
			}
			return a.runPipeline(ctx, target, "reconverge", true, false)
		}
	}
	if at.NextAction == "reapply" && at.NextActionAt != nil && now >= *at.NextActionAt {
		return a.runPipeline(ctx, target, "retry", true, false)
	}
	live := ""
	switch {
	case len(keys) > 0 && a.catalog.Usable():
		live, err = a.hooks.ServerFor(ctx, a, keys)
		if err != nil {
			return nil, nil
		}
		if a.spec.RegistrationLapses && live == target.Server && isRestState(at.State) && a.registrationLapsed(now) &&
			(at.LastMutationAt == nil || now >= *at.LastMutationAt+float64(attempt.Backoff(at.BackoffStep))) {
			return a.runPipeline(ctx, target, "retry", false, true)
		}
	case len(keys) > 0:
		// A stale catalogue can't name anything: not drift.
		a.unidentifiedSince = nil
		return nil, nil
	}
	if live != "" {
		a.unidentifiedSince = nil
		if live != target.Server && isRestState(at.State) && guard {
			return a.runPipeline(ctx, target, "reconverge", true, false)
		}
		return nil, nil
	}
	if a.unidentifiedSince == nil {
		a.unidentifiedSince = &now
	} else if now-*a.unidentifiedSince >= attempt.UnidentifiedSec && isRestState(at.State) && guard {
		a.unidentifiedSince = nil
		return a.runPipeline(ctx, target, "reconverge", true, false)
	}
	return nil, nil
}

// currentGeneration is the native exit's owner generation now, "" for none.
func (a *Applier) currentGeneration(ctx context.Context) string {
	return a.sys.OwnerGeneration(ctx)
}

// registrationLapsed: the last inspection, recent, found the target's
// handshake stale for HandshakeFreshSec, or never completed that long after the
// last mutation. An egress failure alone never counts (D15).
func (a *Applier) registrationLapsed(now float64) bool {
	f := a.measurement
	if f == nil || now-f.At > 2*RefreshSec || a.target == nil {
		return false
	}
	return f.Server == a.target.Server && a.handshakeStale(f, &now)
}

func (a *Applier) handshakeStale(f *Finding, now *float64) bool {
	if f.Peers != 1 {
		return false
	}
	if f.Age == nil {
		last := a.attempt.LastMutationAt
		moment := a.clock()
		if now != nil {
			moment = *now
		}
		return last == nil || moment-*last >= HandshakeFreshSec
	}
	return *f.Age >= HandshakeFreshSec
}

// start: a new effective target is a new attempt, its backoff from the start.
func (a *Applier) start(ctx context.Context, target *Selection) (*Record, error) {
	previous := a.attempt
	a.unidentifiedSince = nil
	if target == nil {
		a.attempt = attempt.New(a.wall(), attempt.NewParams{Source: "seed", BootID: a.bootID,
			Rejected: previous.Rejected, Generation: previous.Generation})
		if err := a.saveAttempt(); err != nil {
			return nil, err
		}
		a.nextHealth = 0
		return nil, nil
	}
	source := target.Source
	if source == "panel" && previous.Target == target.Server &&
		(previous.State == "failed" || previous.State == "rejected" || previous.State == "unverified" ||
			previous.State == "pending") {
		source = "operator-retry"
	}
	fresh := a.askedNow(target)
	a.attempt = attempt.New(a.wall(), attempt.NewParams{Source: source, Target: target.Server, TargetKey: target.Key(),
		BootID: a.bootID, Rejected: previous.Rejected, Generation: previous.Generation})
	return a.runPipeline(ctx, target, source, !fresh, false)
}

// askedNow is true for a panel request made within FreshRequestSec: the
// operator asking now, applied even when the server is already live.
func (a *Applier) askedNow(target *Selection) bool {
	return target.Source == "panel" && target.Request != nil &&
		validate.Recent(target.Request.RequestedAt, FreshRequestSec, a.wall())
}

// Switch applies a panel request now, as a new target (tests and tools).
func (a *Applier) Switch(ctx context.Context, request map[string]any) (*Record, error) {
	a.target = a.resolveRequest(request)
	if a.target == nil {
		return a.Inspect(ctx, false)
	}
	target := a.target
	a.attempt = attempt.New(a.wall(), attempt.NewParams{Source: target.Source, Target: target.Server,
		TargetKey: target.Key(), BootID: a.bootID, Rejected: a.attempt.Rejected, Generation: a.attempt.Generation})
	return a.runPipeline(ctx, target, target.Source, false, false)
}

func (a *Applier) resolveRequest(raw map[string]any) *Selection {
	if a.configuredServer != "" {
		a.request, a.invalidDesired = a.configuredRequest(), false
		return a.configuredSelection()
	}
	var value any
	if raw != nil {
		value = raw
	}
	request, ok := state.DesiredRequest(value, a.hooks.ID())
	if ok {
		a.request = &request
	} else {
		a.request = nil
	}
	a.invalidDesired = !ok
	if !ok {
		return nil
	}
	return &Selection{Server: request.Server, Source: "panel", Request: &request}
}

type gateResult struct{ state, message, why string }

// gate is nil when the pipeline may mutate, else why not: pending
// (prerequisites missing) or rejected (invalid or unlisted).
func (a *Applier) gate(ctx context.Context, target *Selection) *gateResult {
	a.hooks.BeforeGate(ctx, a)
	if message := a.configurationError(); message != "" {
		why := "invalid"
		if strings.HasPrefix(message, "Unknown") {
			why = "catalogue"
		}
		return &gateResult{"rejected", message, why}
	}
	if !a.catalog.Usable() {
		return &gateResult{"pending", "Waiting for a fresh trusted relay catalogue; request will retry automatically.", ""}
	}
	if !a.catalog.Relays().Has(target.Server) {
		return &gateResult{"rejected", Unlisted, "catalogue"}
	}
	if a.kind() == "overlay" {
		if protected, _ := a.routingStatus(ctx, a.spec.AddressBeforeSwitch); !protected {
			return &gateResult{"pending", "Waiting for tunnel and overlay routing; request will retry automatically. " +
				"If this persists, recreate the exit (docs/operations.md#recovery).", ""}
		}
		if !a.netbirdNative(ctx) {
			return &gateResult{"pending", "Waiting for NetBird to run kernel WireGuard with its kernel firewall; " +
				"request will retry automatically.", ""}
		}
	}
	if a.nativeSidecar() {
		protected, _ := a.routingStatus(ctx, a.spec.AddressBeforeSwitch)
		firewall, _, err := a.sys.SidecarFirewall(ctx)
		if !protected || !firewall || err != nil {
			return &gateResult{"pending", "Waiting for the tunnel's routing and firewall; request will retry automatically.", ""}
		}
	}
	if _, err := a.peers(ctx); err != nil {
		return &gateResult{"pending", "Waiting for the WireGuard interface; request will retry automatically.", ""}
	}
	return nil
}

// runPipeline: gates, then (after a fresh inspection when re-applying) the
// mutation and its verification. The same steps for every source.
func (a *Applier) runPipeline(ctx context.Context, target *Selection, source string, reinspect, repair bool) (*Record, error) {
	at := a.attempt
	at.Source = source
	if gate := a.gate(ctx, target); gate != nil {
		at.State, at.Outcome, at.Message = gate.state, gate.state, gate.message
		at.NextAction, at.NextActionAt = "", nil
		at.Extra = attempt.Extra{}
		if gate.state == "rejected" {
			at.Extra = attempt.Extra{Why: gate.why, Release: a.releaseSignature(gate.why)}
			if target.Source == "panel" {
				at.Rejected = &attempt.Rejected{Key: target.Key(), Reason: gate.message, Why: gate.why,
					Release: at.Extra.Release}
			}
		}
		if err := a.saveAttempt(); err != nil {
			return nil, err
		}
		a.nextHealth = a.clock() + RefreshSec
		return a.Inspect(ctx, false)
	}
	if at.Rejected != nil && at.Rejected.Key == target.Key() {
		// Admitted again (what refused it changed): no longer refused.
		at.Rejected = nil
	}
	at.Extra = attempt.Extra{}
	if reinspect || repair {
		f := a.measure(ctx, false)
		a.measurement = f
		if f.Server == target.Server {
			if f.Status == "ok" {
				at.Settle()
				if err := a.saveAttempt(); err != nil {
					return nil, err
				}
				if err := a.hooks.OnVerified(a, target.Server); err != nil {
					return nil, err
				}
				a.nextHealth = a.clock() + RefreshSec
				return a.emit(f, false)
			}
			if !(repair && a.handshakeStale(f, nil)) {
				a.markUnverified()
				if err := a.saveAttempt(); err != nil {
					return nil, err
				}
				a.nextHealth = a.clock() + RefreshSec
				return a.emit(f, false)
			}
			a.log("applier: the registration lapsed; registering the same server again")
			// Repairs pace themselves on the backoff too (D15).
			at.BackoffStep++
		}
	}
	return a.mutate(ctx, target)
}

func (a *Applier) mutate(ctx context.Context, target *Selection) (*Record, error) {
	at := a.attempt
	relay, _ := a.catalog.Relays().Get(target.Server)
	keys, err := a.peers(ctx)
	current := ""
	if err == nil {
		current, err = a.hooks.ServerFor(ctx, a, keys)
	}
	if err != nil {
		at.State, at.Outcome = "pending", "pending"
		at.Message = "Waiting for the WireGuard interface; request will retry automatically."
		if err := a.saveAttempt(); err != nil {
			return nil, err
		}
		return a.Inspect(ctx, false)
	}
	if err := a.hooks.BeforeMutation(ctx, a, target); err != nil {
		return nil, err
	}
	at.State, at.Outcome, at.Message = "attempting", "", ""
	at.Attempts++
	now := a.clock()
	at.LastMutationAt = &now
	at.MutationCertainty = "uncertain"
	at.NextAction, at.NextActionAt = "", nil
	if generation := a.currentGeneration(ctx); generation != "" {
		at.Generation = generation
	}
	// Recorded before any I/O: a lost response can hide success.
	if err := a.saveAttempt(); err != nil {
		return nil, err
	}
	if _, err := a.publishRecord("applying", "Applying the requested server.", current, nil, nil); err != nil {
		return nil, err
	}
	err = a.hooks.ApplyRelay(ctx, a, relay, keys)
	switch {
	case err == nil:
		return a.verify(ctx, target)
	case errors.Is(err, ErrCredentialRejected):
		at.State, at.Outcome, at.MutationCertainty = "rejected", "rejected", "definite"
		at.Message = a.credentialsMessage()
		at.Extra = attempt.Extra{Why: "credentials", Release: a.releaseSignature("credentials")}
		if target.Source == "panel" {
			at.Rejected = &attempt.Rejected{Key: target.Key(), Reason: at.Message, Why: at.Extra.Why, Release: at.Extra.Release}
		}
		if err := a.saveAttempt(); err != nil {
			return nil, err
		}
		a.nextHealth = a.clock() + RefreshSec
		return a.Inspect(ctx, false)
	case caught(err):
		at.State, at.Outcome = "failed", "mutation-failed"
		at.MutationCertainty = "uncertain"
		if errors.Is(err, ErrMutationRefused) {
			at.MutationCertainty = "definite"
		}
		at.Message = a.hooks.MutationFailedMessage()
		at.Schedule("reapply", a.clock())
		if err := a.saveAttempt(); err != nil {
			return nil, err
		}
		// The target may be live all the same: the check says so.
		return a.check(ctx)
	}
	return nil, err
}

func (a *Applier) credentialsMessage() string {
	return a.spec.Label + " refused the login; correct the credentials, or retry."
}

// verify inspects until the target verifies or the provider's timeout. A lost
// protective guard aborts. At the timeout, a live target is applied but
// unverified (re-checked, D7); anything else is a failed attempt.
func (a *Applier) verify(ctx context.Context, target *Selection) (*Record, error) {
	at := a.attempt
	deadline := a.clock() + a.hooks.SwitchTimeout()
	a.switchDeadline = &deadline
	var f *Finding
	done, record, err := func() (bool, *Record, error) {
		defer func() { a.switchDeadline = nil }()
		for a.clock() < deadline {
			f = a.measure(ctx, true)
			a.measurement = f
			if f.Status == "ok" && f.Server == target.Server {
				at.Settle()
				if err := a.saveAttempt(); err != nil {
					return true, nil, err
				}
				if err := a.hooks.OnApplied(a, target.Server); err != nil {
					return true, nil, err
				}
				if err := a.hooks.OnVerified(a, target.Server); err != nil {
					return true, nil, err
				}
				a.nextHealth = a.clock() + RefreshSec
				record, err := a.emit(f, false)
				return true, record, err
			}
			if !f.Safe {
				at.State, at.Outcome = "failed", "mutation-failed"
				at.Message = "Routing changed during the switch; retrying after recovery."
				at.Schedule("reapply", a.clock())
				if err := a.saveAttempt(); err != nil {
					return true, nil, err
				}
				a.nextHealth = a.clock() + RefreshSec
				record, err := a.emit(f, false)
				return true, record, err
			}
			if _, err := a.emit(f, true); err != nil {
				return true, nil, err
			}
			if ctx.Err() != nil {
				return true, nil, ctx.Err()
			}
			a.sleep(ctx, 3)
		}
		return false, nil, nil
	}()
	if done {
		return record, err
	}
	// The loop's last inspection, seconds old, decides; measuring again would
	// only wait out the same answers.
	if f == nil {
		f = a.measure(ctx, false)
		a.measurement = f
	}
	if f.Server == target.Server {
		if err := a.hooks.OnApplied(a, target.Server); err != nil {
			return nil, err
		}
		if f.Status == "ok" {
			at.Settle()
			if err := a.hooks.OnVerified(a, target.Server); err != nil {
				return nil, err
			}
		} else {
			a.markUnverified()
		}
	} else {
		at.State, at.Outcome = "failed", "mutation-failed"
		at.Message = "Switch verification timed out; retrying automatically."
		at.Schedule("reapply", a.clock())
	}
	if err := a.saveAttempt(); err != nil {
		return nil, err
	}
	a.nextHealth = a.clock() + RefreshSec
	return a.emit(f, false)
}

// -- reporting -----------------------------------------------------------------------------------

// assess is this applier's verdict on a record, against its own target.
func (a *Applier) assess(result any) verdict.Verdict {
	return verdict.Assess(a.exitConfig(), result, a.resolve(true).target(), a.wall())
}

// pushGatus pushes the verdict, not the raw status. Never "applying": a
// switch in progress, or a request that arrived while one ran, isn't a sample.
func (a *Applier) pushGatus(ctx context.Context, result *Record) {
	base, token := a.gatus.URL, a.gatus.Token
	if base == "" || token == "" {
		return
	}
	endpoint := a.gatus.Endpoint
	if endpoint == "" {
		endpoint = "molebridge"
	}
	if !(strings.HasPrefix(base, "http://") || strings.HasPrefix(base, "https://")) || strings.ContainsAny(token, "\r\n") {
		return
	}
	decoded := a.judged(result).Decoded()
	v := a.assess(decoded)
	if v.State == "applying" {
		return
	}
	success := v.State == "ok"
	message := ""
	if !success {
		switch {
		case v.Message != nil && *v.Message != "":
			message = *v.Message
		default:
			if m, ok := decoded["message"].(string); ok && m != "" {
				message = m
			} else {
				message = v.Label
			}
		}
	}
	query := "success=" + strconv.FormatBool(success) + "&error=" + url.QueryEscape(message)
	_, err := a.sys.Fetch(ctx, netx.Request{
		URL:    strings.TrimRight(base, "/") + "/api/v1/endpoints/" + strings.ReplaceAll(url.QueryEscape(endpoint), "+", "%20") + "/external?" + query,
		Method: "POST", Header: map[string]string{"Authorization": "Bearer " + token},
		Timeout: 10 * time.Second, AllowHTTP: true})
	if err != nil {
		a.log("applier: monitoring push failed")
	}
}

// Healthy is the container health check, operational only (D5): a fresh
// completed check, ok or failed, and an intact namespace for the kind. Whether
// the exit is verified is the verdict's and monitoring's question, never a
// reason to restart it. On the overlay a missing peer is the pipeline's to
// repair, not the health check's: killing the worker for it would only delay
// the repair. A failed provider verification never fails health.
func (a *Applier) Healthy(ctx context.Context) bool {
	result, ok := jsonfile.ReadObject(a.resultPath, ResultMaxBytes)
	if !ok {
		return false
	}
	status, _ := result["status"].(string)
	if status != "ok" && status != "failed" {
		return false
	}
	if !validate.Recent(result["checked_at"], state.StatusMaxAge, a.wall()) {
		return false
	}
	if a.kind() == "sidecar" && a.backend() == "gluetun" {
		if !a.hooks.ControlAnswers(ctx, a) {
			return false
		}
		keys, err := a.peers(ctx)
		return err == nil && len(keys) == 1
	}
	if _, err := a.peers(ctx); err != nil { // the tunnel interface exists
		return false
	}
	protected, _ := a.routingStatus(ctx, true)
	if a.nativeSidecar() {
		firewall, _, err := a.sys.SidecarFirewall(ctx)
		return protected && firewall && err == nil
	}
	return protected && a.netbirdNative(ctx)
}
