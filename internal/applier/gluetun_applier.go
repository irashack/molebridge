package applier

// The applier for the gluetun backend (applier/gluetun_applier.py): gluetun
// owns the tunnel, and this provider selects servers through gluetun's control
// server.
//
//   - Catalogue: gluetun's own server list, read from a read-only mount of its
//     storage directory (GLUETUN_SERVERS_FILE), never downloaded. The file is
//     untrusted: internal/providers reads it with the same limits as a
//     download, and a file that fails (gluetun truncates it while writing)
//     keeps the last good catalogue. The snapshot carries the provider data's
//     own date (data_timestamp) besides when it was read.
//   - Switch: PUT /v1/vpn/settings with the server's exact hostname filter and
//     every other filter cleared (gluetun_client.go). gluetun then restarts
//     its VPN loop in-process: its interface disappears and comes back, and
//     the guard puts the exit route back. Those transitions are not failures;
//     only the switch timeout is.
//   - Success needs what it needs on the native backend: exactly one peer
//     whose endpoint and key identify the selected server, a fresh handshake,
//     intact routing guards including rules 88/89/91/92 and the host table,
//     and egress at the provider's tier: Mullvad's and NordVPN's own checks
//     through the tunnel where the provider has one, the tunnel checks
//     otherwise.
//   - The selection Molebridge last put, the last one live after a PUT and the
//     last one verified are kept in gluetun-selection.json in the exit's
//     private directory (state/applier unless PRIVATE_STATE_DIR is set).
//     gluetun starts from its environment (GLUETUN_SERVER_*), not from what was
//     put at runtime. Without SERVER or an accepted panel request, the last
//     verified server is the target (restore), and the admission pipeline puts
//     it back like any other drift. A tunnel-tier sidecar is never verified,
//     so it restores the last one live after a PUT.
//   - While a switch is verified, gluetun's reconnection states withhold
//     readiness without aborting it; anything else the protective predicate
//     refuses does (contract.GluetunTransitionStatus).
//   - With EXIT_KIND=sidecar there is no routing contract and no NetBird:
//     traffic protection is gluetun's firewall, and which containers use the
//     tunnel is a documented procedure (decision D22).
//
// The API key (GLUETUN_API_KEY_FILE, mode 0600) is full gluetun
// administration; only this container mounts it. gluetun's control server
// listens on the namespace's loopback.
//
// The kernel facts the predicates read come from GluetunKernel (system.go),
// the HTTP from System.Fetch (netx): the host's own address is measured by an
// HTTPS echo whose socket carries NetBird's control mark (MarkedEcho).

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/egress"
	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
)

// Defaults of the gluetun settings.
const (
	DefaultGluetunControlURL = "http://127.0.0.1:8000"
	DefaultGluetunAPIKeyFile = "/run/secrets/gluetun/api_key"
	DefaultGluetunServers    = "/gluetun-servers/servers.json"
	DefaultUpdaterPeriod     = "24h"
)

// Timings of the gluetun backend, in seconds.
const (
	// CatalogPollSec: the server list is checked for changes this often, and
	// read again at least every CatalogRereadSec, so a fresh read never ages
	// past the 24-hour rule.
	CatalogPollSec   = 60
	CatalogRereadSec = 6 * 60 * 60
	// GluetunDataStaleSec is the age past which gluetun's data is stale.
	GluetunDataStaleSec = providers.GluetunDataStaleSec
	// UpdateIfOlderSec: one refresh of gluetun's server list after the applier
	// starts, when the data is older than gluetun's updater period or than
	// this, whichever is shorter: gluetun's own updater first runs one period
	// after gluetun starts, and its built-in data can be years old.
	UpdateIfOlderSec = 7 * 24 * 60 * 60
	UpdateAttempts   = 3
	// UpdateHandshakeSec: a WireGuard handshake this recent means the tunnel
	// answers. WireGuard renews it every two minutes while traffic flows.
	UpdateHandshakeSec = 150
	UpdateRetrySec     = 5 * 60
	// UpdateTimeoutSec: a run that hasn't finished by then counts as failed.
	UpdateTimeoutSec = 15 * 60
	// TransitionSamples: a snapshot taken while gluetun's interface changes
	// underneath is taken again, at most this many times; meanwhile the exit
	// isn't ready.
	TransitionSamples = 3
	// EchoTimeout bounds one marked echo.
	EchoTimeout = 10 * time.Second
)

// Why an owed refresh of gluetun's server list hasn't started, as
// server_list_update reports it.
const (
	UpdateWaitTunnel  = "waiting-for-tunnel"
	UpdateWaitControl = "waiting-for-control-server"
	UpdateWaitVPN     = "waiting-for-vpn"
	// UpdateWaitRetry: an attempt failed otherwise; the next starts after
	// UpdateRetrySec.
	UpdateWaitRetry = "waiting-to-retry"
)

// GluetunSwitchTimeoutSec: gluetun restarts its VPN loop on a settings change;
// the interface goes and comes back, then the handshake and the egress checks
// follow.
var GluetunSwitchTimeoutSec = float64(state.SwitchTimeouts[providers.BackendGluetun])

// ErrGluetunNotDownloaded is what fetching the server list says.
var ErrGluetunNotDownloaded = errors.New("with gluetun the server list is read from gluetun, not downloaded")

const gluetunCatalogError = "gluetun's server list is missing or invalid; retaining the last good catalogue."

var updaterPeriodRE = regexp.MustCompile(`^(?:([0-9]{1,4})h)?(?:([0-9]{1,4})m)?(?:([0-9]{1,6})s)?$`)

// UpdaterPeriod is the number of seconds in gluetun's UPDATER_PERIOD (a Go
// duration such as 24h or 1h30m; 0 turns the updater off).
func UpdaterPeriod(value string) (int, error) {
	if value == "0" || value == "0s" {
		return 0, nil
	}
	match := updaterPeriodRE.FindStringSubmatch(value)
	if value == "" || match == nil {
		return 0, errors.New("invalid GLUETUN_UPDATER_PERIOD")
	}
	var parts [3]int
	for i := range parts {
		if match[i+1] != "" {
			parts[i], _ = strconv.Atoi(match[i+1])
		}
	}
	return parts[0]*3600 + parts[1]*60 + parts[2], nil
}

// -- the catalogue --------------------------------------------------------------------------------

// GluetunCatalog is the applier's catalogue from gluetun's servers.json.
type GluetunCatalog struct {
	inner           *providers.RelayCatalog
	source          string
	provider        string
	gluetunProvider string
	now             func() time.Time

	signature  fileSignature
	haveSig    bool
	readAt     float64
	haveReadAt bool
	// reads counts the times the file was read and parsed (tests).
	reads int
	// failed: the last Refresh could not use the file.
	failed bool
}

// errGluetunCatalog is RefreshFailure's answer; like the error record, it
// says nothing of the file's content.
var errGluetunCatalog = errors.New("gluetun's server list is missing or invalid")

// RefreshFailure implements Catalog.
func (c *GluetunCatalog) RefreshFailure() error {
	if c.failed {
		return errGluetunCatalog
	}
	return nil
}

type fileSignature struct {
	ino   uint64
	size  int64
	mtime int64
}

// NewGluetunCatalog reads the snapshot already published in directory, if
// there is a valid one, and reads gluetun's file at source on Refresh. now is
// the wall clock; time.Now when nil.
func NewGluetunCatalog(directory, provider, source string, now func() time.Time) (*GluetunCatalog, error) {
	spec, err := providers.Get(provider)
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &GluetunCatalog{inner: providers.NewRelayCatalog(directory, provider, false, now), source: source,
		provider: provider, gluetunProvider: spec.GluetunProvider, now: now}, nil
}

// Usable implements Catalog.
func (c *GluetunCatalog) Usable() bool { return c.inner.Usable() }

// Relays implements Catalog.
func (c *GluetunCatalog) Relays() *providers.Entries { return c.inner.Relays }

// Snapshot implements Catalog.
func (c *GluetunCatalog) Snapshot() map[string]any { return c.inner.Snapshot }

// ReadThisProcess is whether the catalogue has been read from gluetun's file
// since it was made; before that it is the snapshot an earlier process
// published.
func (c *GluetunCatalog) ReadThisProcess() bool { return c.haveSig }

// ExitIPs implements Catalog: gluetun's list names no exit addresses.
func (c *GluetunCatalog) ExitIPs(string) []string { return nil }

func unixSeconds(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

// Refresh reads gluetun's file when it changed or the last read is getting
// old. fetch is ignored: nothing is downloaded. The returned error is only
// about writing the error record.
func (c *GluetunCatalog) Refresh(_ context.Context, _ func() ([]byte, error)) (bool, error) {
	c.failed = !c.read()
	if !c.failed {
		return true, nil
	}
	// Never log the file's content, paths or exception bodies.
	return false, c.inner.RecordFailure(gluetunCatalogError)
}

func (c *GluetunCatalog) read() bool {
	info, err := os.Lstat(c.source)
	if err != nil {
		return false
	}
	ino, mtime, _ := statIdentity(info)
	signature := fileSignature{ino, info.Size(), mtime}
	now := unixSeconds(c.now())
	if c.haveSig && signature == c.signature && c.haveReadAt && now-c.readAt < CatalogRereadSec && c.Usable() {
		return true
	}
	c.reads++
	// As after a native refresh (DefaultMaintainCatalog): the read's garbage
	// goes back to the kernel now, whether or not the file was usable.
	defer debug.FreeOSMemory()
	relays, timestamp, err := providers.ReadGluetunSnapshot(c.source, c.gluetunProvider, now)
	if err != nil {
		return false
	}
	entries := providers.NewEntries()
	relays.Each(func(id string, relay *providers.Relay) bool {
		raw, err := validate.MarshalJSON(providers.GluetunSnapshotEntry(relay))
		if err != nil {
			return true
		}
		decoded, err := validate.DecodeJSON(raw)
		if err != nil {
			return true
		}
		if entry := providers.ValidateGluetunEntry(decoded); entry != nil && entry.Hostname == id {
			entries.Set(id, entry)
		}
		return true
	})
	if entries.Len() == 0 {
		return false
	}
	extra := validate.Members("source", "gluetun", "data_timestamp", validate.FormatTime(time.Unix(timestamp, 0)))
	if err := c.inner.Publish(entries, extra); err != nil {
		return false
	}
	c.signature, c.haveSig = signature, true
	c.readAt, c.haveReadAt = now, true
	return true
}

// -- the selection state ----------------------------------------------------------------------------

const selectionMaxBytes = 4096

// selection is gluetun-selection.json: what Molebridge asked for, what was
// live after a PUT, and what was verified. "" is JSON null.
type selection struct {
	Desired, LastPut, LastApplied, LastSuccessful string
}

func (s selection) object() validate.Obj {
	return validate.Members("desired", orNull(s.Desired), "last_put", orNull(s.LastPut),
		"last_applied", orNull(s.LastApplied), "last_successful", orNull(s.LastSuccessful))
}

// -- the provider -------------------------------------------------------------------------------------

// GluetunControl is gluetun's control server as the provider uses it
// (*GluetunClient; tests fake it).
type GluetunControl interface {
	SelectRelay(ctx context.Context, relay *providers.Relay, selectionFilter string) (string, error)
	VPNStatus(ctx context.Context) (string, error)
	UpdaterStatus(ctx context.Context) (string, error)
	StartUpdate(ctx context.Context) (string, error)
}

// GluetunSettings are the gluetun provider's settings.
type GluetunSettings struct {
	// Routing is the routing configuration of a gluetun overlay exit
	// (contract.ConfigFromEnv); for a sidecar only its Kind, Backend and
	// ExitIf are read.
	Routing contract.Config
	// ServersFile is gluetun's servers.json.
	ServersFile string
	// UpdaterPeriodSec is gluetun's UPDATER_PERIOD in seconds; 0 turns the
	// server-list refresh off.
	UpdaterPeriodSec int
}

type gluetunProvider struct {
	BaseProvider
	spec     *providers.Provider
	client   GluetunControl
	settings GluetunSettings
	routing  contract.Config

	selectionPath string
	selection     selection
	// previous are the tunnel's addresses before the switch being verified: its
	// rule 94 may linger while gluetun reconnects.
	previous map[int]string

	// The one refresh of gluetun's server list this process may start:
	// updateState is "" (not needed or not yet), "updating", "done" or
	// "failed". updateWait is why a refresh that is owed hasn't started
	// (an UpdateWait value), "" otherwise.
	updateThreshold float64
	updateState     string
	updateWait      string
	updateAttempts  int
	updateStarted   float64
	nextUpdate      float64
}

// NewGluetun is the provider for a gluetun registry entry (id is
// "gluetun-<provider>"), controlling gluetun through client.
func NewGluetun(id string, settings GluetunSettings, client GluetunControl) (Provider, error) {
	g, err := newGluetun(id, settings, client)
	if err != nil {
		return nil, err
	}
	return g, nil
}

func newGluetun(id string, settings GluetunSettings, client GluetunControl) (*gluetunProvider, error) {
	spec, err := providers.Get(id)
	if err != nil {
		return nil, err
	}
	if spec.Backend != providers.BackendGluetun {
		return nil, errors.New("not a gluetun provider")
	}
	if settings.Routing.Backend != contract.Gluetun {
		return nil, errors.New("the gluetun applier needs TUNNEL_BACKEND=gluetun")
	}
	if client == nil {
		return nil, errors.New("the gluetun applier needs a control client")
	}
	g := &gluetunProvider{BaseProvider: BaseProvider{Name: spec.ID}, spec: spec, client: client, settings: settings,
		routing: settings.Routing, previous: map[int]string{}}
	if settings.UpdaterPeriodSec > 0 {
		g.updateThreshold = float64(min(UpdateIfOlderSec, settings.UpdaterPeriodSec))
	}
	return g, nil
}

// NewGluetunFromEnv builds the provider from the exit's settings: the control
// URL, the API key file and gluetun's server list and updater period. The
// routing configuration of an overlay exit is read with contract.ConfigFromEnv;
// a sidecar has none. fetch is the control client's HTTP (netx when nil).
func NewGluetunFromEnv(id string, exit Exit, getenv func(string) string, fetch FetchFunc) (Provider, error) {
	var routing contract.Config
	if exit.Kind == "sidecar" {
		routing = contract.Config{Kind: contract.Sidecar, Backend: contract.Gluetun, ExitIf: exit.ExitIf}
	} else {
		var err error
		if routing, err = contract.ConfigFromEnv(getenv); err != nil {
			return nil, err
		}
	}
	if routing.Backend != contract.Gluetun {
		return nil, errors.New("the gluetun applier needs TUNNEL_BACKEND=gluetun")
	}
	client, err := NewGluetunClient(orDefault(getenv("GLUETUN_CONTROL_URL"), DefaultGluetunControlURL),
		orDefault(getenv("GLUETUN_API_KEY_FILE"), DefaultGluetunAPIKeyFile), fetch)
	if err != nil {
		return nil, err
	}
	period, err := UpdaterPeriod(orDefault(getenv("GLUETUN_UPDATER_PERIOD"), DefaultUpdaterPeriod))
	if err != nil {
		return nil, err
	}
	return NewGluetun(id, GluetunSettings{Routing: routing,
		ServersFile:      orDefault(getenv("GLUETUN_SERVERS_FILE"), DefaultGluetunServers),
		UpdaterPeriodSec: period}, client)
}

func orDefault(value, def string) string {
	if value == "" {
		return def
	}
	return value
}

// CheckSystem implements SystemChecker: an overlay exit reads the namespace
// through GluetunKernel; the exit kind must be the settings'.
func (g *gluetunProvider) CheckSystem(sys System, exit Exit) error {
	kind := exit.Kind
	if kind == "" {
		kind = "overlay"
	}
	if kind != string(g.routing.Kind) {
		return errors.New("the exit kind does not match the gluetun routing settings")
	}
	if kind == "overlay" {
		if _, ok := sys.(GluetunKernel); !ok {
			return errors.New("the gluetun backend needs a system that reads the gluetun namespace")
		}
	}
	return nil
}

func (g *gluetunProvider) kernel(a *Applier) (GluetunKernel, bool) {
	k, ok := a.sys.(GluetunKernel)
	return k, ok
}

// SwitchTimeout implements Provider.
func (*gluetunProvider) SwitchTimeout() float64 { return GluetunSwitchTimeoutSec }

// MakeCatalog implements Provider: gluetun's own list. It also loads the
// selection state, which lives in the exit's private directory.
func (g *gluetunProvider) MakeCatalog(a *Applier) Catalog {
	g.selectionPath = filepath.Join(a.privateDir, "gluetun-selection.json")
	g.selection = g.loadSelection(a)
	catalog, err := NewGluetunCatalog(a.directory, g.Name, g.settings.ServersFile, a.wall)
	if err != nil {
		// The registry entry was resolved when the Applier was built.
		panic(err)
	}
	return catalog
}

// FetchCatalog implements Provider: nothing is downloaded.
func (*gluetunProvider) FetchCatalog(context.Context, *Applier) ([]byte, error) {
	return nil, ErrGluetunNotDownloaded
}

// MaintainCatalog implements Provider: gluetun's own list, checked every
// minute (the native refresh would wait six hours after a refresh), after one
// look at whether gluetun should refresh it.
func (g *gluetunProvider) MaintainCatalog(ctx context.Context, a *Applier) error {
	g.updateServers(ctx, a)
	if a.clock() >= a.nextCatalog {
		if _, err := a.catalog.Refresh(ctx, nil); err != nil {
			return wrapIO(err)
		}
		a.nextCatalog = a.clock() + CatalogPollSec
	}
	return nil
}

func (g *gluetunProvider) loadSelection(a *Applier) selection {
	raw, _ := a.readJSON(g.selectionPath, selectionMaxBytes).(map[string]any)
	pick := func(key string) string {
		value := raw[key]
		if raw == nil || !a.spec.ValidServerName(value) {
			return ""
		}
		s, _ := value.(string)
		return s
	}
	return selection{pick("desired"), pick("last_put"), pick("last_applied"), pick("last_successful")}
}

func (g *gluetunProvider) saveSelection(change func(*selection)) error {
	change(&g.selection)
	if err := jsonfile.Write(g.selectionPath, g.selection.object(), jsonfile.Options{}); err != nil {
		return wrapIO(err)
	}
	return nil
}

// ApplyRelay asks gluetun for exactly this server. The selection is recorded
// before the result is known: gluetun may apply one whose answer is lost.
func (g *gluetunProvider) ApplyRelay(ctx context.Context, a *Applier, relay *providers.Relay, _ []string) error {
	if err := g.saveSelection(func(s *selection) { s.LastPut = relay.Hostname }); err != nil {
		return err
	}
	_, err := g.client.SelectRelay(ctx, relay, "")
	return err
}

// RestoreTarget is the server to put back when nothing else selects one.
func (g *gluetunProvider) RestoreTarget(a *Applier) *Selection {
	server := g.selection.LastSuccessful
	if a.kind() == "sidecar" && g.spec.EgressTier == providers.TierTunnel {
		server = g.selection.LastApplied
	}
	if server == "" {
		return nil
	}
	return &Selection{Server: server, Source: "restore"}
}

// BeforeMutation records the panel's choice and the tunnel's addresses.
func (g *gluetunProvider) BeforeMutation(ctx context.Context, a *Applier, target *Selection) error {
	if target.Source == "panel" || target.Source == "operator-retry" {
		if err := g.saveSelection(func(s *selection) { s.Desired = target.Server }); err != nil {
			return err
		}
	}
	addresses, err := a.tunnelAddresses(ctx, false)
	if err != nil {
		addresses = map[int]string{}
	}
	g.previous = addresses
	return nil
}

// OnApplied records the server live after a mutation.
func (g *gluetunProvider) OnApplied(_ *Applier, server string) error {
	if g.selection.LastApplied == server {
		return nil
	}
	return g.saveSelection(func(s *selection) { s.LastApplied = server })
}

// OnVerified records a verified server.
func (g *gluetunProvider) OnVerified(_ *Applier, server string) error {
	if g.selection.LastSuccessful == server {
		return nil
	}
	return g.saveSelection(func(s *selection) { s.LastSuccessful = server })
}

// MutationFailedMessage implements Provider.
func (*gluetunProvider) MutationFailedMessage() string {
	return "gluetun did not accept the server selection; retrying automatically."
}

// WaitingMessage implements Provider.
func (*gluetunProvider) WaitingMessage() string {
	return "Waiting for gluetun to connect to the requested server."
}

// ControlAnswers is whether gluetun's control server answers with the key.
func (g *gluetunProvider) ControlAnswers(ctx context.Context, _ *Applier) bool {
	status, err := g.client.VPNStatus(ctx)
	if err != nil {
		return false
	}
	for _, known := range VPNStatuses {
		if status == known {
			return true
		}
	}
	return false
}

// ServerFor: exactly one peer whose endpoint and key identify a server.
func (g *gluetunProvider) ServerFor(ctx context.Context, a *Applier, keys []string) (string, error) {
	if len(keys) != 1 {
		return "", nil
	}
	endpoints, err := a.sys.Endpoints(ctx)
	if err != nil {
		return "", err
	}
	id, _ := providers.ServerForPeer(a.catalog.Relays(), keys[0], endpoints[keys[0]])
	return id, nil
}

// EgressFor is the provider's own check where it has one, the tunnel checks
// otherwise, and for a sidecar's tunnel tier no check at all.
func (g *gluetunProvider) EgressFor(ctx context.Context, a *Applier, server string, age *int) (EgressResult, error) {
	switch {
	case g.spec.EgressCheck == "nordvpn":
		return NordEgressFor(ctx, a, server)
	case g.spec.EgressCheck == "mullvad":
		return a.MullvadEgress(ctx)
	case a.kind() == "sidecar":
		return g.unmeasurableEgress(ctx, a)
	}
	return a.TunnelEgress(ctx, server, age)
}

// unmeasurableEgress: a tunnel-tier provider in a sidecar. In plain gluetun's
// namespace nothing leaves off the tunnel, so the host's own address can't be
// measured and the tunnel checks can't pass. The tunnel's address is still
// read, for display, from one echo service.
func (g *gluetunProvider) unmeasurableEgress(ctx context.Context, a *Applier) (EgressResult, error) {
	tunnel, err := a.tunnelAddresses(ctx, true)
	if err != nil {
		return EgressResult{}, err
	}
	found := map[string]string{}
	var ips validate.Obj
	for _, family := range sortedFamilies(tunnel) {
		address, err := a.echo(ctx, egress.EchoURLs[family][0], family, true)
		if err != nil {
			if !caught(err) {
				return EgressResult{}, err
			}
			continue
		}
		name := strconv.Itoa(family)
		found[name] = address
		ips = append(ips, validate.Pair{Key: name, Value: address})
	}
	return EgressResult{EgressIP: found["4"], ExitConfirmed: false, EgressIPs: ips, Families: validate.Obj{},
		Reason:  "host-address-not-measurable",
		Message: "Switched; the egress couldn't be compared with this host's address."}, nil
}

// Echo: through the tunnel interface as the native backend does; off it, the
// socket carries NetBird's control mark (MarkedEcho).
func (g *gluetunProvider) Echo(ctx context.Context, a *Applier, rawURL string, family int, tunnel bool) (string, error) {
	if tunnel {
		return a.DefaultEcho(ctx, rawURL, family, true)
	}
	raw, err := MarkedEcho(ctx, a.sys.Fetch, rawURL, family, g.routing.ControlMark, EchoTimeout)
	if err != nil {
		return "", err
	}
	return egress.ParseEcho(raw, family)
}

// PublishDefaults: whether gluetun is refreshing its server list, gave up, or
// owes a refresh that waits, and for what.
func (g *gluetunProvider) PublishDefaults() validate.Obj {
	var update any
	if g.updateState == "updating" || g.updateState == "failed" {
		update = g.updateState
	} else if g.updateWait != "" {
		update = g.updateWait
	}
	return validate.Members("server_list_update", update)
}

// -- marked echo ---------------------------------------------------------------------------------------

// Errors of MarkedEcho. They carry no detail.
var (
	ErrEchoURL    = errors.New("invalid echo URL")
	ErrEchoFailed = errors.New("echo failed")
)

// MarkedEcho is an IP echo service's answer over the host's own route, from a
// socket carrying NetBird's control mark. In gluetun's namespace every
// unmarked socket goes into the tunnel (gluetun's rule 101), so this is the
// one way to measure the host's own address there: rule 88 sends the mark to
// the host table, and the post-rules accept output on HOST_IF. It needs
// NET_ADMIN, which the exit holds. The name lookup, every address tried, the
// TLS handshake, the request and the read all end within timeout. Errors carry
// no detail.
//
// The URL must be plain https with a host and no port, user or query.
func MarkedEcho(ctx context.Context, fetch FetchFunc, rawURL string, family int, mark uint32, timeout time.Duration) (string, error) {
	parts, err := url.Parse(rawURL)
	if err != nil || parts.Scheme != "https" || parts.Hostname() == "" || parts.Port() != "" || parts.User != nil ||
		parts.RawQuery != "" {
		return "", ErrEchoURL
	}
	path := parts.EscapedPath()
	if path == "" {
		path = "/"
	}
	response, err := fetch(ctx, netx.Request{URL: "https://" + parts.Host + path, UserAgent: "molebridge-applier",
		Header: map[string]string{"Accept": "text/plain"}, Family: family, SocketMark: mark,
		MaxBytes: egress.EchoMaxBytes, Timeout: timeout, ConnectTimeout: timeout, AnyStatus: true})
	if err != nil {
		if errors.Is(err, netx.ErrCanceled) || errors.Is(err, context.Canceled) {
			return "", context.Canceled
		}
		return "", ErrEchoFailed
	}
	if response.Status != 200 || len(response.Body) > egress.EchoMaxBytes {
		return "", ErrEchoFailed
	}
	for _, c := range response.Body {
		if c >= utf8.RuneSelf {
			return "", ErrEchoFailed
		}
	}
	return string(response.Body), nil
}

// -- routing --------------------------------------------------------------------------------------------

func familyOf(n int) rtnl.Family {
	if n == 6 {
		return rtnl.V6
	}
	return rtnl.V4
}

func addrOrZero(addresses map[int]string, family int) netip.Addr {
	address, err := netip.ParseAddr(addresses[family])
	if err != nil {
		return netip.Addr{}
	}
	return address
}

// tunnelAddressesOf reads the tunnel's addresses while the interface is
// there: absent is true when it can't be read (gluetun has no interface), and
// an error is an answer that makes no sense (several addresses of a family).
func (g *gluetunProvider) tunnelAddressesOf(ctx context.Context, a *Applier) (addresses map[int]string, absent bool, err error) {
	listed, err := a.sys.TunnelAddresses(ctx)
	if err != nil {
		return nil, true, nil
	}
	addresses, err = groupAddresses(listed, false)
	return addresses, false, err
}

// RoutingStatus is (protected, fallback) for gluetun's namespace: the whole
// guard in both families, including the host table. gluetun's interface coming
// and going is not a routing failure: without it, or while it is down, no
// tunnel route belongs in the exit table and the fallback holds.
func (g *gluetunProvider) RoutingStatus(ctx context.Context, a *Applier, _ bool) (bool, bool) {
	kernel, ok := g.kernel(a)
	if !ok {
		return false, false
	}
	if err := a.sys.LinkExists(ctx, g.routing.OverlayIf); err != nil {
		return false, false
	}
	links, err := kernel.GluetunLinks(ctx)
	if err != nil {
		return false, false
	}
	var addresses map[int]string
	if links.Tunnel.Present {
		var absent bool
		if addresses, absent, err = g.tunnelAddressesOf(ctx, a); err != nil {
			return false, false
		} else if absent {
			addresses = nil
		}
	}
	text, err := a.sys.ReadSysctl(ctx, ReturnPathSysctl)
	if err != nil {
		return false, false
	}
	protected, fallback := contract.ReturnPathEnabled(text), true
	spec := contract.Spec{Config: g.routing}
	for _, family := range []int{4, 6} {
		tables, err := kernel.GluetunTables(ctx, family)
		if err != nil {
			return false, false
		}
		ready, fb := contract.FamilyStatus(spec, familyOf(family), tables.Rules, tables.Exit, contract.StatusOptions{
			TunnelAddress: addrOrZero(addresses, family), NoTunnelRoute: !links.Tunnel.Up, ExitIfIndex: links.Tunnel.Index})
		protected = protected && ready && contract.HostTableStatus(tables.Host, links.HostIndex, familyOf(family),
			tables.Main, true)
		fallback = fallback && fb
	}
	return protected, fallback
}

// transitionStatus is (safe, ready) while a switch is verified, by the
// protective predicate. The interface, addresses and rules are read
// separately, so a sample is taken again when the interface changed during it
// (its presence or index differ before and after, or it is present with
// detached rules); after TransitionSamples such samples the exit is safe so
// far and not ready.
func (g *gluetunProvider) transitionStatus(ctx context.Context, a *Applier) (safe, ready bool, err error) {
	kernel, ok := g.kernel(a)
	if !ok {
		return false, false, errors.New("no gluetun kernel")
	}
	spec := contract.Spec{Config: g.routing}
	for range TransitionSamples {
		before, err := kernel.GluetunLinks(ctx)
		if err != nil {
			return false, false, err
		}
		if err := a.sys.LinkExists(ctx, g.routing.OverlayIf); err != nil {
			return false, false, err
		}
		var addresses map[int]string
		if before.Tunnel.Present {
			var absent bool
			if addresses, absent, err = g.tunnelAddressesOf(ctx, a); err != nil {
				return false, false, err
			} else if absent {
				addresses = nil
			}
		} else {
			addresses = map[int]string{}
		}
		text, err := a.sys.ReadSysctl(ctx, ReturnPathSysctl)
		if err != nil {
			return false, false, err
		}
		returnPath := contract.ReturnPathEnabled(text)
		tables := map[int]GluetunTables{}
		for _, family := range []int{4, 6} {
			if tables[family], err = kernel.GluetunTables(ctx, family); err != nil {
				return false, false, err
			}
		}
		after, err := kernel.GluetunLinks(ctx)
		if err != nil {
			return false, false, err
		}
		detached := false
		if before.Tunnel.Present {
			for _, t := range tables {
				for _, r := range t.Rules {
					detached = detached || r.IifDetached() || r.OifDetached()
				}
			}
		}
		if before.Tunnel != after.Tunnel || addresses == nil || detached {
			continue
		}
		safe, ready = returnPath, returnPath
		for _, family := range []int{4, 6} {
			t := tables[family]
			familySafe, familyReady := contract.GluetunTransitionStatus(spec, familyOf(family), t.Rules, t.Exit,
				contract.TransitionOptions{TunnelAddress: addrOrZero(addresses, family),
					PreviousAddress: addrOrZero(g.previous, family), InterfacePresent: before.Tunnel.Present,
					InterfaceUp: before.Tunnel.Up, ExitIfIndex: before.Tunnel.Index})
			safe = safe && familySafe
			ready = ready && familyReady && contract.HostTableStatus(t.Host, after.HostIndex, familyOf(family), t.Main, true)
		}
		return safe, ready, nil
	}
	return true, false, nil
}

// MeasureGuards: outside a switch the full validation; while one is verified,
// the reconnection states gluetun and the guard pass through are tolerated.
func (g *gluetunProvider) MeasureGuards(ctx context.Context, a *Applier, at string, f *Finding) {
	if a.switchDeadline == nil {
		a.DefaultMeasureGuards(ctx, at, f)
		return
	}
	safe, ready, err := g.transitionStatus(ctx, a)
	if err != nil {
		safe, ready = false, false
	}
	native := a.netbirdNative(ctx)
	routing := "fail"
	if ready {
		routing = "pass"
	}
	check := validate.Members("state", routing, "at", at, "fallback", safe)
	if safe && !ready {
		check = check.Set("reason", "reconnecting")
	}
	f.Checks = f.Checks.Set("routing", check)
	f.Checks = f.Checks.Set("traffic_protection", validate.Members("state", routing, "at", at, "from", "routing"))
	nb := "fail"
	if native {
		nb = "pass"
	}
	f.Checks = f.Checks.Set("netbird", validate.Members("state", nb, "at", at))
	f.Safe = safe && native
	if !ready {
		f.Guard = RoutingFailed
	} else if !native {
		f.Guard = NetbirdModeFailed
	}
}

// -- gluetun's own server list -----------------------------------------------------------------------------

// tunnelWorks: gluetun's tunnel carries traffic now: one peer with a
// handshake in the last UpdateHandshakeSec. gluetun's VPN status says
// "running" while it still tries servers that don't answer, so the update waits
// for this instead of starting into a tunnel that fails. Otherwise it says
// what it saw.
func (g *gluetunProvider) tunnelWorks(ctx context.Context, a *Applier) (bool, string) {
	keys, err := a.peers(ctx)
	if err != nil {
		return false, "its interface can't be read"
	}
	if len(keys) != 1 {
		return false, fmt.Sprintf("it has %d peers", len(keys))
	}
	age, err := a.handshakeAge(ctx, keys[0])
	if err != nil || age == nil {
		return false, "its peer has no handshake"
	}
	if *age >= UpdateHandshakeSec {
		return false, fmt.Sprintf("its last handshake was %d seconds ago", *age)
	}
	return true, ""
}

// waitUpdate records why the owed refresh hasn't started, logging each change
// of reason once.
func (g *gluetunProvider) waitUpdate(a *Applier, reason, detail string) {
	if reason != g.updateWait {
		a.log("applier: gluetun's server list is out of date; its update waits: " + detail)
	}
	g.updateWait = reason
}

// updateServers starts one refresh of gluetun's server list when its data is
// old and gluetun's tunnel works, and follows it. gluetun's updater fetches the
// provider's public list through the tunnel, from gluetun's own process, and
// doesn't restart the VPN. Bounded: UpdateAttempts starts per process, each
// given UpdateTimeoutSec; a failed answer of gluetun's control server counts as
// an attempt. While the refresh is owed but waits for gluetun's tunnel or VPN,
// server_list_update says which. The new data reaches the catalogue through
// its usual re-read when the file changes.
func (g *gluetunProvider) updateServers(ctx context.Context, a *Applier) {
	if g.updateThreshold <= 0 || g.updateState == "done" || g.updateState == "failed" {
		return
	}
	now := a.clock()
	failed := func(wait, what string) {
		g.updateState, g.updateWait = "", wait
		g.nextUpdate = now + UpdateRetrySec
		if g.updateAttempts >= UpdateAttempts {
			g.updateState, g.updateWait = "failed", ""
			a.log(fmt.Sprintf("applier: gluetun's server list update failed (%s); gave up after %d attempts", what, g.updateAttempts))
			return
		}
		a.log(fmt.Sprintf("applier: gluetun's server list update failed (%s); attempt %d of %d, retrying in %d seconds",
			what, g.updateAttempts, UpdateAttempts, UpdateRetrySec))
	}
	if g.updateState == "updating" {
		status, err := g.client.UpdaterStatus(ctx)
		if err != nil {
			status = ""
		}
		if status == "completed" {
			g.updateState = "done"
			a.nextCatalog = 0
			a.log("applier: gluetun's server list update finished")
			return
		}
		if (status == "starting" || status == "running") && now-g.updateStarted < UpdateTimeoutSec {
			return
		}
		switch {
		case err != nil:
			failed(UpdateWaitControl, "its control server: "+controlFailure(err))
		case status == "starting" || status == "running":
			failed(UpdateWaitRetry, fmt.Sprintf("not finished after %d seconds", UpdateTimeoutSec))
		default:
			failed(UpdateWaitRetry, "the updater is "+status)
		}
		return
	}
	if now < g.nextUpdate {
		return
	}
	// The snapshot an earlier process published says nothing about the file
	// gluetun has now: a new pod can start from gluetun's built-in list beside
	// state kept from before, and judging that snapshot fresh would settle the
	// refresh as not needed. Only a list read from gluetun's file decides.
	if c, ok := a.catalog.(*GluetunCatalog); ok && !c.ReadThisProcess() {
		return
	}
	relays := a.catalog.Relays()
	age, known := dataAge(a.catalog.Snapshot()["data_timestamp"], unixSeconds(a.wall()))
	if relays.Len() == 0 || (known && age <= g.updateThreshold) {
		// Nothing read yet (gluetun hasn't written the file), or fresh enough.
		if relays.Len() > 0 {
			g.updateState, g.updateWait = "done", ""
		}
		return
	}
	if ok, seen := g.tunnelWorks(ctx, a); !ok {
		g.waitUpdate(a, UpdateWaitTunnel, "gluetun's tunnel doesn't answer yet ("+seen+")")
		return
	}
	status, err := g.client.VPNStatus(ctx)
	if err != nil {
		g.updateAttempts++
		failed(UpdateWaitControl, "its control server: "+controlFailure(err))
		return
	}
	if status != "running" {
		g.waitUpdate(a, UpdateWaitVPN, "gluetun's VPN is "+status+", not running")
		return
	}
	g.updateAttempts++
	if _, err := g.client.StartUpdate(ctx); err != nil {
		failed(UpdateWaitControl, "its control server: "+controlFailure(err))
		return
	}
	g.updateState, g.updateWait, g.updateStarted = "updating", "", now
	a.nextHealth = 0
	a.log(fmt.Sprintf("applier: asked gluetun to update its server list (attempt %d of %d)", g.updateAttempts, UpdateAttempts))
}

// controlFailure is a control-client error's fixed message; any other error
// is reported without its detail.
func controlFailure(err error) string {
	var known GluetunError
	if errors.As(err, &known) {
		return known.Error()
	}
	return string(ErrGluetunRequest)
}

// dataAge is the seconds since gluetun's provider data was dated, or false.
func dataAge(value any, now float64) (float64, bool) {
	text, ok := value.(string)
	if !ok {
		return 0, false
	}
	when, err := time.Parse(validate.TimeLayout, text)
	if err != nil {
		return 0, false
	}
	moment := unixSeconds(when)
	if moment > now {
		return 0, false
	}
	return now - moment, true
}
