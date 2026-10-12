package applier

// A fake machine for the applier's tests: the Python tests' Kernel, PiaKernel,
// NordKernel and EchoKernel in one struct that implements System. Nothing here
// touches a network beyond what a test starts on loopback, or any host state.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/egress"
	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

const (
	testKey      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	otherKey     = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	thirdKey     = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	testHost     = "se-sto-wg-001"
	otherHost    = "se-sto-wg-002"
	testBoot     = "00000000-0000-4000-8000-0000000000aa"
	tunnel4      = "203.0.113.1"
	tunnel6      = "2001:db8:3::1"
	hostIP4      = "198.51.100.99"
	hostIP6      = "2001:db8:4::99"
	exitIP4      = "203.0.113.10"
	exitIP6      = "2001:db8:3::10"
	testExitIf   = "mullvad"
	testOverlay  = "wt0"
	testTable    = "51821"
	testOverlay4 = "192.0.2.0/24"
)

var errInjected = errors.New("injected failure")

type echoKey struct {
	family int
	tunnel bool
}

// kernel is the fake System.
type kernel struct {
	t     testing.TB
	now   float64 // the boot clock the applier runs on
	calls []string
	reqs  []netx.Request
	exit  Exit

	// interfaces and addresses
	overlayPresent bool
	overlayWG      bool
	netbirdChains  bool
	netbirdErr     bool
	tunnelPresent  bool
	addrs          []netip.Addr
	returnPath     string
	generation     string
	namespaceNets  []netip.Prefix

	// the routing contract, by family
	routeFault      map[int]bool
	routeMissing    map[int]bool
	fallbackMissing map[int]bool
	rules           map[int][]Rule

	// WireGuard
	keys             []string
	endpoints        map[string]string
	endpointsErr     error
	age              int
	noHandshake      bool
	failSet          bool
	peersErr         error
	mutations        []string
	afterReplacePeer func()
	publicKey        string

	// HTTP: hooks run first (delay or fail), then the handler.
	hooks   []func(req netx.Request) error
	handler func(req netx.Request) (netx.Response, error)

	// egress, Mullvad and tunnel tier
	egressOK     bool
	failedEgress map[int]bool
	probes       map[int]map[string]any
	echo         map[echoKey][]string
	echoDown     map[echoKey]bool
	host6Routes  any
	host6Links   any

	// PIA
	failWhen       func(step string) bool
	expectedSource string
	returnGaps     int
	bothMissing    int
	nftOps         []string
	nftFailures    int
	nftAlwaysFail  bool
	guardInstalled int

	addrErr  error
	insights []any // each insights call takes the next answer; the last repeats
	logs     []string
	pushed   []string
}

func newKernel(t testing.TB) *kernel {
	k := &kernel{t: t, overlayPresent: true, overlayWG: true, netbirdChains: true, tunnelPresent: true,
		returnPath: "1\n", keys: []string{testKey}, age: 1, egressOK: true, publicKey: otherKey,
		exit:       Exit{ExitIf: testExitIf, OverlayIf: testOverlay, Table: testTable, Overlay: testOverlay4, Kind: "overlay"},
		routeFault: map[int]bool{}, routeMissing: map[int]bool{}, fallbackMissing: map[int]bool{},
		failedEgress: map[int]bool{}, echoDown: map[echoKey]bool{}, endpoints: map[string]string{},
		rules: map[int][]Rule{}}
	k.addrs = []netip.Addr{netip.MustParseAddr(tunnel4), netip.MustParseAddr(tunnel6)}
	for _, a := range k.addrs {
		k.rules[family(a)] = append(k.rules[family(a)], Rule{Priority: 94, Src: a.String(), SrcLen: -1, IPProto: 1, Table: 51821},
			Rule{Priority: 98, Src: a.String(), SrcLen: -1, IPProto: 1, Action: "unreachable"})
	}
	k.probes = map[int]map[string]any{
		4: {"ip": exitIP4, "city": "Example City", "country": "Example", "mullvad_exit_ip": true},
		6: {"ip": exitIP6, "city": "Example City", "country": "Example", "mullvad_exit_ip": true}}
	k.echo = map[echoKey][]string{{4, true}: {exitIP4, exitIP4}, {6, true}: {exitIP6, exitIP6},
		{4, false}: {hostIP4}, {6, false}: {hostIP6}}
	k.host6Routes = []any{map[string]any{"dst": "default", "gateway": "fe80::1", "dev": "eth0"}}
	k.host6Links = []any{map[string]any{"ifname": "eth0", "addr_info": []any{
		map[string]any{"family": "inet6", "scope": "global", "local": hostIP6}}}}
	k.handler = k.defaultHandler
	return k
}

func family(a netip.Addr) int {
	if a.Is4() {
		return 4
	}
	return 6
}

func (k *kernel) record(format string, args ...any) {
	k.calls = append(k.calls, fmt.Sprintf(format, args...))
}

func (k *kernel) clock() float64 { return k.now }

func (k *kernel) sleep(_ context.Context, d time.Duration) { k.now += d.Seconds() }

func (k *kernel) countCalls(prefix string) int {
	n := 0
	for _, c := range k.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func (k *kernel) requestsTo(substr string) []netx.Request {
	var found []netx.Request
	for _, r := range k.reqs {
		if strings.Contains(r.URL, substr) {
			found = append(found, r)
		}
	}
	return found
}

// peerMutations are the recorded peer changes that added a peer.
func (k *kernel) adds() []string {
	var found []string
	for _, m := range k.mutations {
		if !strings.HasPrefix(m, "remove ") {
			found = append(found, m)
		}
	}
	return found
}

// -- System: routing and interfaces --------------------------------------------------

func (k *kernel) LinkExists(_ context.Context, name string) error {
	k.record("LinkExists %s", name)
	if !k.overlayPresent {
		return errors.New("missing overlay interface")
	}
	return nil
}

func (k *kernel) TunnelAddresses(context.Context) ([]netip.Addr, error) {
	k.record("TunnelAddresses")
	if !k.tunnelPresent {
		return nil, errors.New("missing tunnel interface")
	}
	if k.addrErr != nil {
		return nil, k.addrErr
	}
	return append([]netip.Addr(nil), k.addrs...), nil
}

func (k *kernel) sources(family, priority int) map[string]bool {
	found := map[string]bool{}
	for _, r := range k.rules[family] {
		if r.Priority == priority {
			found[r.Src] = true
		}
	}
	return found
}

func sameSet(a map[string]bool, b ...string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, s := range b {
		if !a[s] {
			return false
		}
	}
	return true
}

func (k *kernel) RoutingStatus(_ context.Context, family int, address string) (bool, bool, error) {
	k.record("RoutingStatus %d %s", family, address)
	want := []string{}
	if address != "" {
		want = append(want, address)
	}
	protected := !k.routeFault[family] && !k.routeMissing[family] && !k.fallbackMissing[family] &&
		sameSet(k.sources(family, 94), want...) && sameSet(k.sources(family, 98), want...)
	return protected, !k.fallbackMissing[family], nil
}

func (k *kernel) ReadSysctl(_ context.Context, path string) (string, error) {
	k.record("ReadSysctl %s", path)
	return k.returnPath, nil
}

func (k *kernel) OverlayKernelWireGuard(context.Context) (bool, error) {
	k.record("OverlayKernelWireGuard")
	if !k.overlayPresent {
		return false, errors.New("missing overlay interface")
	}
	return k.overlayWG, nil
}

func (k *kernel) NetbirdFirewallPresent(context.Context) (bool, error) {
	k.record("NetbirdFirewallPresent")
	if k.netbirdErr {
		return false, errors.New("command failed")
	}
	return k.netbirdChains, nil
}

func (k *kernel) IPv6Evidence(context.Context) (any, any, error) {
	k.record("IPv6Evidence")
	return k.host6Routes, k.host6Links, nil
}

func (k *kernel) OwnerGeneration(context.Context) string { return k.generation }

// -- System: WireGuard ---------------------------------------------------------------------

func (k *kernel) Peers(context.Context) ([]string, error) {
	k.record("Peers")
	if !k.tunnelPresent {
		return nil, errors.New("missing tunnel interface")
	}
	if k.peersErr != nil {
		return nil, k.peersErr
	}
	return append([]string(nil), k.keys...), nil
}

func (k *kernel) LatestHandshakes(context.Context) (map[string]int64, error) {
	k.record("LatestHandshakes")
	out := map[string]int64{}
	if k.noHandshake {
		return out, nil
	}
	for _, key := range k.keys {
		out[key] = time.Now().Unix() - int64(k.age)
	}
	return out, nil
}

func (k *kernel) Endpoints(context.Context) (map[string]string, error) {
	k.record("Endpoints")
	if k.endpointsErr != nil {
		return nil, k.endpointsErr
	}
	out := map[string]string{}
	for key, endpoint := range k.endpoints {
		out[key] = endpoint
	}
	return out, nil
}

func (k *kernel) PublicKey(context.Context) (string, error) {
	k.record("PublicKey")
	return k.publicKey, nil
}

func (k *kernel) ReplacePeer(_ context.Context, remove []string, add PeerConfig) error {
	for _, key := range remove {
		k.mutations = append(k.mutations, "remove "+key)
		if k.failSet {
			return errInjected
		}
		k.keys = removeString(k.keys, key)
		delete(k.endpoints, key)
	}
	k.mutations = append(k.mutations, fmt.Sprintf("set %s endpoint %s allowed-ips %s keepalive %d", add.PublicKey,
		add.Endpoint, strings.Join(add.AllowedIPs, ","), add.KeepaliveSec))
	if k.failSet {
		return errInjected
	}
	k.keys = []string{add.PublicKey}
	k.endpoints = map[string]string{add.PublicKey: add.Endpoint}
	if k.afterReplacePeer != nil {
		k.afterReplacePeer()
	}
	return nil
}

func removeString(list []string, value string) []string {
	var out []string
	for _, s := range list {
		if s != value {
			out = append(out, s)
		}
	}
	return out
}

// -- System: HTTP ---------------------------------------------------------------------------------

func (k *kernel) Fetch(_ context.Context, req netx.Request) (netx.Response, error) {
	k.reqs = append(k.reqs, req)
	for _, hook := range k.hooks {
		if err := hook(req); err != nil {
			return netx.Response{}, err
		}
	}
	if _, query, ok := strings.Cut(req.URL, "/external?"); ok {
		k.pushed = append(k.pushed, query)
		return netx.Response{Status: 200}, nil
	}
	return k.handler(req)
}

func (k *kernel) defaultHandler(req netx.Request) (netx.Response, error) {
	if req.URL == providers.NordInsightsURL {
		if req.Family != 4 || req.BindInterface != k.exit.ExitIf || req.MaxBytes != 16384 || req.Timeout != 10*time.Second {
			k.t.Errorf("insights request %+v", req)
		}
		answer := k.insights[0]
		if len(k.insights) > 1 {
			k.insights = k.insights[1:]
		}
		if text, isText := answer.(string); isText {
			return netx.Response{Status: 200, Body: []byte(text)}, nil
		}
		return jsonBody(answer), nil
	}
	if response, handled, err := k.mullvadOrEcho(req); handled {
		return response, err
	}
	return netx.Response{}, fmt.Errorf("unexpected request %s", req.URL)
}

func jsonBody(v any) netx.Response {
	raw, err := validate.MarshalJSON(v)
	if err != nil {
		panic(err)
	}
	return netx.Response{Status: 200, Body: raw}
}

func (k *kernel) mullvadOrEcho(req netx.Request) (netx.Response, bool, error) {
	for f := 4; f <= 6; f += 2 {
		if req.URL == fmt.Sprintf("https://ipv%d.am.i.mullvad.net/json", f) {
			if req.Family != f || req.BindInterface != k.exit.ExitIf {
				k.t.Errorf("mullvad probe %d: family %d interface %q", f, req.Family, req.BindInterface)
			}
			if !k.egressOK || k.failedEgress[f] {
				return netx.Response{}, true, errors.New("injected probe failure")
			}
			return jsonBody(k.probes[f]), true, nil
		}
	}
	for f, urls := range egress.EchoURLs {
		for i, url := range urls {
			if req.URL != url {
				continue
			}
			tunnel := req.BindInterface != ""
			if tunnel && req.BindInterface != k.exit.ExitIf || req.Family != f || req.MaxBytes != egress.EchoMaxBytes {
				k.t.Errorf("echo %s: interface %q family %d max %d", url, req.BindInterface, req.Family, req.MaxBytes)
			}
			key := echoKey{f, tunnel}
			if k.echoDown[key] {
				return netx.Response{}, true, errors.New("injected echo failure")
			}
			answers := k.echo[key]
			answer := answers[0]
			if tunnel {
				answer = answers[i]
			}
			return netx.Response{Status: 200, Body: []byte(answer + "\n")}, true, nil
		}
	}
	return netx.Response{}, false, nil
}

// delayed makes the requests that match take `seconds` each, in order, and
// then answer (answered) or time out as a request that gets no answer does
// (not answered); later ones answer at once. It returns what it matched.
func (k *kernel) delayed(match func(netx.Request) bool, steps ...step) *[]netx.Request {
	var seen []netx.Request
	left := append([]step(nil), steps...)
	k.hooks = append(k.hooks, func(req netx.Request) error {
		if !match(req) {
			return nil
		}
		seen = append(seen, req)
		if len(left) > 0 {
			s := left[0]
			left = left[1:]
			k.now += s.seconds
			if !s.answered {
				return errors.New("command unavailable or timed out")
			}
		}
		return nil
	})
	return &seen
}

type step struct {
	seconds  float64
	answered bool
}

// unanswered: the next `times` requests that match time out after `seconds`.
func (k *kernel) unanswered(match func(netx.Request) bool, times int, seconds float64) *[]netx.Request {
	steps := make([]step, times)
	for i := range steps {
		steps[i] = step{seconds, false}
	}
	return k.delayed(match, steps...)
}

// -- System: PIA -------------------------------------------------------------------------------

func (k *kernel) NamespaceIPv4Prefixes(_ context.Context, exclude string) ([]netip.Prefix, error) {
	k.record("NamespaceIPv4Prefixes %s", exclude)
	return k.namespaceNets, nil
}

func (k *kernel) fail(step string) error {
	if k.failWhen != nil && k.failWhen(step) {
		k.failWhen = nil
		return errInjected
	}
	return nil
}

// noteReturnPath records whether every tunnel address in use had both its rule
// 94 and its backstop 98 at this step.
func (k *kernel) noteReturnPath() {
	found := map[int]map[string]bool{94: k.sources(4, 94), 98: k.sources(4, 98)}
	missing := func(priority int) int {
		n := 0
		for _, a := range k.addrs {
			if a.Is4() && !found[priority][a.String()] {
				n++
			}
		}
		return n
	}
	k.returnGaps += min(1, missing(94)) + min(1, missing(98))
	for _, a := range k.addrs {
		if a.Is4() && !found[94][a.String()] && !found[98][a.String()] {
			k.bothMissing++
			break
		}
	}
}

func (k *kernel) IPv4Rules(_ context.Context, priority int) ([]Rule, error) {
	k.record("IPv4Rules %d", priority)
	var found []Rule
	for _, r := range k.rules[4] {
		if r.Priority == priority {
			found = append(found, r)
		}
	}
	return found, nil
}

func (k *kernel) AddReturnPathRule(_ context.Context, priority int, addr netip.Addr) error {
	var step string
	rule := Rule{Priority: priority, Src: addr.String(), SrcLen: -1, IPProto: 1}
	if priority == 94 {
		step = fmt.Sprintf("rule add from %s ipproto icmp lookup %s priority 94", addr, k.exit.Table)
		rule.Table = 51821
	} else {
		step = fmt.Sprintf("rule add from %s ipproto icmp unreachable priority 98", addr)
		rule.Action = "unreachable"
	}
	k.record("%s", step)
	if err := k.fail(step); err != nil {
		return err
	}
	if k.expectedSource != "" && addr.String() != k.expectedSource {
		k.t.Errorf("rule for %s, expected %s", addr, k.expectedSource)
	}
	k.rules[4] = append(k.rules[4], rule)
	sort.SliceStable(k.rules[4], func(i, j int) bool { return k.rules[4][i].Priority < k.rules[4][j].Priority })
	k.noteReturnPath()
	return nil
}

func (k *kernel) DeleteReturnPathRule(_ context.Context, priority int, src netip.Addr) error {
	step := fmt.Sprintf("rule del priority %d", priority)
	if src.IsValid() {
		step += " from " + src.String()
	}
	k.record("%s", step)
	if err := k.fail(step); err != nil {
		return err
	}
	for i, r := range k.rules[4] {
		if r.Priority == priority && (!src.IsValid() || r.Src == src.String()) {
			k.rules[4] = append(append([]Rule(nil), k.rules[4][:i]...), k.rules[4][i+1:]...)
			k.noteReturnPath()
			return nil
		}
	}
	return errors.New("no such rule")
}

func (k *kernel) ReplaceTunnelAddress(_ context.Context, addr netip.Addr) error {
	step := fmt.Sprintf("address replace %s/32", addr)
	k.record("%s", step)
	if err := k.fail(step); err != nil {
		return err
	}
	for _, a := range k.addrs {
		if a == addr {
			return nil
		}
	}
	k.addrs = append(k.addrs, addr)
	return nil
}

func (k *kernel) DeleteTunnelAddress(_ context.Context, addr netip.Addr) error {
	step := fmt.Sprintf("address del %s/32", addr)
	k.record("%s", step)
	if err := k.fail(step); err != nil {
		return err
	}
	var kept []netip.Addr
	found := false
	for _, a := range k.addrs {
		if a == addr {
			found = true
		} else {
			kept = append(kept, a)
		}
	}
	if !found {
		return errors.New("no such address")
	}
	k.addrs = kept
	k.noteReturnPath()
	hasV4 := false
	for _, a := range k.addrs {
		hasV4 = hasV4 || a.Is4()
	}
	if !hasV4 {
		// The kernel drops routes through an interface with no IPv4 address.
		k.routeMissing[4] = true
	}
	return nil
}

func (k *kernel) ReplaceExitDefaultRoute(context.Context) error {
	step := "route replace default"
	k.record("%s", step)
	if err := k.fail(step); err != nil {
		return err
	}
	k.routeMissing[4] = false
	return nil
}

func (k *kernel) ChangePIAAddress(ctx context.Context, old, new netip.Addr) error {
	k.record("ChangePIAAddress %s %s", old, new)
	return ChangePIAAddress(ctx, k, old, new)
}

func (k *kernel) nft(what string) error {
	if k.nftAlwaysFail {
		k.record("nft failed %s", what)
		return errInjected
	}
	if k.nftFailures > 0 {
		k.nftFailures--
		k.record("nft failed %s", what)
		return errInjected
	}
	k.nftOps = append(k.nftOps, what)
	return nil
}

func (k *kernel) InstallIngressGuard(context.Context) error {
	if err := k.nft("guard"); err != nil {
		return err
	}
	k.guardInstalled++
	return nil
}

func (k *kernel) ApplyForwardRules(_ context.Context, port int, target netip.Addr) error {
	return k.nft(fmt.Sprintf("forward %d %s", port, target))
}

func (k *kernel) RemoveForwardRules(context.Context) error { return k.nft("remove-forward") }

// -- building appliers -----------------------------------------------------------------------------

func writeSnapshot(t testing.TB, dir, provider string, relays any) {
	t.Helper()
	snapshot := validate.Members("fetched_at", validate.FormatTime(time.Now()))
	if provider != "" {
		snapshot = append(snapshot, validate.Pair{Key: "provider", Value: provider})
	}
	snapshot = append(snapshot, validate.Pair{Key: "relays", Value: relays})
	if err := jsonfile.Write(filepath.Join(dir, "applier", "relays.json"), snapshot, jsonfile.Options{Public: true}); err != nil {
		t.Fatal(err)
	}
}

func mullvadEntry(host, key string) map[string]any {
	return map[string]any{"hostname": host, "public_key": key, "ipv4_addr_in": "198.51.100.10",
		"city": "Example City", "country": "Example", "location_code": "se-sto"}
}

// newApplier builds an applier on the fake kernel in a fresh state directory.
func newApplier(t testing.TB, k *kernel, dir string, provider Provider, server string) *Applier {
	t.Helper()
	cfg := Config{StateDir: dir, Exit: k.exit, Provider: provider, System: k, Server: server, BootID: testBoot,
		Monotonic: k.clock, Sleep: k.sleep, Log: func(s string) { k.logs = append(k.logs, s) }}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.nextCatalog = infinity
	// The supervisor's check, as it would write it while the lease is held.
	a.ownerCheck = func() validate.Obj {
		return validate.Members("state", "pass", "at", validate.FormatTime(time.Now()))
	}
	return a
}

// withPublished makes the applier write result.json, as the supervisor does,
// and collect the statuses it published.
func withPublished(a *Applier, dir string) *[]string {
	var statuses []string
	a.publish = func(r *Record) error {
		statuses = append(statuses, r.Get("status").(string))
		// The supervisor writes the file, with its own owner_record check.
		return jsonfile.Write(ResultPath(dir), a.judged(r), jsonfile.Options{Public: true})
	}
	return &statuses
}

func requestAt(server string, changes map[string]any) map[string]any {
	r := map[string]any{"server": server, "requested_at": validate.FormatTime(time.Now()), "request_id": strings.Repeat("0", 32)}
	for k, v := range changes {
		if v == nil {
			delete(r, k)
		} else {
			r[k] = v
		}
	}
	return r
}

func desire(t testing.TB, a *Applier, request map[string]any) {
	t.Helper()
	if err := jsonfile.Write(a.desiredPath, request, jsonfile.Options{}); err != nil {
		t.Fatal(err)
	}
}

func mustTick(t testing.TB, a *Applier) *Record {
	t.Helper()
	r, err := a.Tick(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func must(t testing.TB, r *Record, err error) *Record {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (a *Applier) inspect(t testing.TB) *Record {
	t.Helper()
	r, err := a.Inspect(context.Background(), false)
	return must(t, r, err)
}

func (a *Applier) switchTo(t testing.TB, request map[string]any) *Record {
	t.Helper()
	r, err := a.Switch(context.Background(), request)
	return must(t, r, err)
}

// checkState is a check's state in a schema-2 record.
func checkState(r *Record, name string) string {
	return r.Decoded()["checks"].(map[string]any)[name].(map[string]any)["state"].(string)
}

func checkField(r *Record, name, field string) any {
	return r.Decoded()["checks"].(map[string]any)[name].(map[string]any)[field]
}

func status(r *Record) string  { return r.Get("status").(string) }
func message(r *Record) string { s, _ := r.Get("message").(string); return s }

func writeFile(t testing.TB, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func (k *kernel) logged(substr string) bool {
	for _, l := range k.logs {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

func itoaF(n int) string { return strconv.Itoa(n) }

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func removeFile(path string) error { return os.Remove(path) }
