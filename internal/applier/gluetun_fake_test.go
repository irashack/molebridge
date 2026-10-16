package applier

// The gluetun tests' fake machine: the Python tests' Kernel and FakeGluetun
// (tools/test_gluetun_applier.py) and Reconnecting (test_gluetun_transition.py)
// as one System + GluetunKernel, and a fake control server. It sits on the
// generic kernel of fake_test.go for what the gluetun backend shares with the
// native one (HTTP recording, delays, the overlay and NetBird facts). Nothing
// here touches a network or host state.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/validate"
)

const (
	keyA, keyB       = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="
	hostA, hostB     = "one.example.test", "two.example.test"
	hostC            = "three.example.test"
	glTunnel4        = "10.64.0.2"
	glExit4          = "203.0.113.50"
	glHost4          = "198.51.100.200"
	glHostIfIndex    = 2
	glOverlayIfIndex = 3
	glTunnelIfIndex  = 7
)

var glEndpoint = map[string]string{hostA: "198.51.100.11", hostB: "198.51.100.22", hostC: "198.51.100.33"}

// glRouting is the Python CONFIG: a gluetun overlay exit.
func glRouting(t testing.TB) contract.Config {
	t.Helper()
	env := map[string]string{"TUNNEL_BACKEND": "gluetun", "OVERLAY_CIDR": "192.0.2.0/24", "OVERLAY6_CIDR": "2001:db8:1::/64",
		"EXIT_IF": "wg0"}
	c, err := contract.ConfigFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func glSidecar() contract.Config {
	return contract.Config{Kind: contract.Sidecar, Backend: contract.Gluetun, ExitIf: "wg0"}
}

// serversJSON is the Python servers_json: gluetun's storage file for one
// provider. timestamp 0 is an hour ago.
func serversJSON(provider string, timestamp int64, hosts ...string) string {
	if len(hosts) == 0 {
		hosts = []string{hostA, hostB, hostC}
	}
	var servers []any
	for i, host := range hosts {
		key := keyA
		if host == hostB {
			key = keyB
		}
		s := map[string]any{"vpn": "wireguard", "country": "Exampleland", "city": fmt.Sprintf("City %d", i), "hostname": host,
			"wgpubkey": key, "ips": []any{glEndpoint[host]}}
		if provider == "nordvpn" {
			s["categories"] = []any{"Standard VPN servers", "P2P"}
		}
		servers = append(servers, s)
	}
	if provider == "nordvpn" {
		servers = append(servers, map[string]any{"vpn": "wireguard", "country": "Exampleland", "city": "City 9",
			"hostname": "dedicated.example.test", "categories": []any{"Dedicated IP"}, "wgpubkey": keyA,
			"ips": []any{"198.51.100.99"}})
	}
	if timestamp == 0 {
		timestamp = time.Now().Unix() - 3600
	}
	raw, err := json.Marshal(map[string]any{"version": 1, provider: map[string]any{"version": 1, "timestamp": timestamp,
		"servers": servers}})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// glRule is the contract's rule at one priority for a tunnel address ("" for
// none): what `ip rule show` prints, built by the contract itself.
func glRule(t testing.TB, c contract.Config, f rtnl.Family, priority uint32, tunnel string) rtnl.Rule {
	t.Helper()
	spec := contract.Spec{Config: c}
	if tunnel != "" {
		spec.ReturnPath = map[rtnl.Family][]netip.Addr{f: {netip.MustParseAddr(tunnel)}}
	}
	for _, r := range spec.Rules(f) {
		if r.Priority == priority {
			return r
		}
	}
	t.Fatalf("the contract has no rule %d", priority)
	return rtnl.Rule{}
}

// glRules is the Python rules(family): the gluetun contract as the kernel shows
// it, with gluetun's own rule 101.
func glRules(t testing.TB, c contract.Config, f rtnl.Family) []rtnl.Rule {
	t.Helper()
	spec := contract.Spec{Config: c}
	if f == rtnl.V4 {
		spec.ReturnPath = map[rtnl.Family][]netip.Addr{f: {netip.MustParseAddr(glTunnel4)}}
	}
	rules := spec.Rules(f)
	rules = append(rules, rtnl.Rule{Family: f, Priority: 101, Action: rtnl.FRActToTbl, Table: contract.GluetunTable,
		Flags: rtnl.FIBRuleInvert, FwMark: rtnl.Some(contract.GluetunMark), FwMask: rtnl.Some(uint32(0xffffffff))})
	slices.SortStableFunc(rules, func(a, b rtnl.Rule) int { return int(a.Priority) - int(b.Priority) })
	return rules
}

func glHostRoutes(f rtnl.Family, table uint32) []rtnl.Route {
	if f == rtnl.V6 {
		return nil
	}
	return []rtnl.Route{
		{Family: f, Dst: netip.MustParsePrefix("198.51.100.0/28"), Table: table, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(glHostIfIndex)),
			Scope: rtnl.RTScopeLink},
		{Family: f, Dst: netip.MustParsePrefix("0.0.0.0/0"), Table: table, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(glHostIfIndex)),
			Gateway: netip.MustParseAddr("198.51.100.2")}}
}

// glKernel is the fake System and GluetunKernel.
type glKernel struct {
	*kernel
	t testing.TB
	c contract.Config

	// tunnel is the live server, "" while gluetun has no interface.
	tunnel string
	// pending is a PUT's restart: the reads left before the tunnel is back, and
	// the server it ends up on.
	pendingTicks int
	pendingHost  string
	hasPending   bool

	twoAddresses       bool
	rules              map[int][]rtnl.Rule
	hostRoutes         map[int][]rtnl.Route
	tunnelRoutePresent bool
	tunnelUp           bool

	egress            string
	mullvadExit       bool
	insightsProtected bool
	endpointOverride  string
	marked            []netx.Request

	// reconnecting, when set, is the Python Reconnecting kernel's state.
	rc *reconnecting
	// linkScript, when set, answers GluetunLinks' tunnel (a test scripting the
	// interface changing under a sample).
	linkScript func() TunnelLink
	lastIndex  uint32
}

func newGlKernel(t testing.TB, c contract.Config) *glKernel {
	t.Helper()
	g := &glKernel{kernel: newKernel(t), t: t, c: c, tunnel: hostA, tunnelRoutePresent: true, tunnelUp: true,
		egress: glExit4, mullvadExit: true, insightsProtected: true, rules: map[int][]rtnl.Rule{},
		hostRoutes: map[int][]rtnl.Route{}}
	g.exit = Exit{ExitIf: "wg0", OverlayIf: "wt0", Table: "51821", Overlay: "192.0.2.0/24", Kind: "overlay"}
	if c.Kind == contract.Sidecar {
		g.exit = Exit{ExitIf: "wg0", Kind: "sidecar"}
	} else {
		for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
			g.rules[int(f)] = glRules(t, c, f)
			g.hostRoutes[int(f)] = glHostRoutes(f, c.HostTable)
		}
	}
	g.handler = g.handle
	return g
}

func (g *glKernel) advance() {
	if g.rc != nil && g.rc.advance(g) {
		return
	}
	if g.hasPending {
		if g.pendingTicks <= 0 {
			g.tunnel, g.hasPending = g.pendingHost, false
		} else {
			g.pendingTicks--
		}
	}
}

// wgRead is `wg show`: it counts as a kernel read, and fails while gluetun has
// no interface or is reconnecting.
func (g *glKernel) wgRead() error {
	was := g.rc != nil && g.rc.active()
	g.advance()
	if was || g.tunnel == "" {
		return errors.New("command failed")
	}
	return nil
}

func (g *glKernel) key() string {
	if g.tunnel == hostB {
		return keyB
	}
	return keyA
}

// -- System ----------------------------------------------------------------------------------------

func (g *glKernel) TunnelAddresses(context.Context) ([]netip.Addr, error) {
	g.record("TunnelAddresses")
	if g.rc != nil {
		return g.rc.addresses()
	}
	if g.tunnel == "" {
		return nil, errors.New("missing tunnel interface")
	}
	if g.addrErr != nil {
		return nil, g.addrErr
	}
	if g.twoAddresses {
		return []netip.Addr{netip.MustParseAddr(glTunnel4), netip.MustParseAddr("10.64.0.3")}, nil
	}
	return []netip.Addr{netip.MustParseAddr(glTunnel4)}, nil
}

func (g *glKernel) Peers(context.Context) ([]string, error) {
	g.record("Peers")
	if err := g.wgRead(); err != nil {
		return nil, err
	}
	if g.peersErr != nil {
		return nil, g.peersErr
	}
	return []string{g.key()}, nil
}

func (g *glKernel) Endpoints(context.Context) (map[string]string, error) {
	g.record("Endpoints")
	if err := g.wgRead(); err != nil {
		return nil, err
	}
	if g.endpointsErr != nil {
		return nil, g.endpointsErr
	}
	endpoint := g.endpointOverride
	if endpoint == "" {
		endpoint = glEndpoint[g.tunnel] + ":51820"
	}
	return map[string]string{g.key(): endpoint}, nil
}

func (g *glKernel) LatestHandshakes(context.Context) (map[string]int64, error) {
	g.record("LatestHandshakes")
	if err := g.wgRead(); err != nil {
		return nil, err
	}
	return map[string]int64{g.key(): time.Now().Unix() - int64(g.age)}, nil
}

// handle answers the HTTP requests: through the tunnel interface the provider
// checks and the echo services; with a socket mark, the host's own address.
func (g *glKernel) handle(req netx.Request) (netx.Response, error) {
	if req.SocketMark != 0 {
		g.marked = append(g.marked, req)
		if req.BindInterface != "" || req.Family != 4 && req.Family != 6 {
			g.t.Errorf("marked request %+v", req)
		}
		return netx.Response{Status: 200, Body: []byte(glHost4 + "\n")}, nil
	}
	if req.BindInterface != "wg0" || req.MaxBytes == 0 {
		g.t.Errorf("request %s: interface %q max %d", req.URL, req.BindInterface, req.MaxBytes)
	}
	if g.tunnel == "" {
		return netx.Response{}, errors.New("command failed")
	}
	switch {
	case contains2(req.URL, "am.i.mullvad.net"):
		return jsonBody(map[string]any{"ip": g.egress, "mullvad_exit_ip": g.mullvadExit, "city": "City 0",
			"country": "Exampleland"}), nil
	case req.URL == providers.NordInsightsURL:
		return jsonBody(map[string]any{"ip": g.egress, "protected": g.insightsProtected, "city": "City 0",
			"country": "Exampleland", "country_code": "EX"}), nil
	}
	return netx.Response{Status: 200, Body: []byte(g.egress + "\n")}, nil
}

// -- GluetunKernel ---------------------------------------------------------------------------------

func (g *glKernel) GluetunLinks(context.Context) (GluetunLinks, error) {
	g.record("GluetunLinks")
	g.advance()
	if g.linkScript != nil {
		link := g.linkScript()
		g.lastIndex = link.Index
		return GluetunLinks{Tunnel: link, HostIndex: glHostIfIndex}, nil
	}
	if g.rc != nil {
		return g.rc.links(), nil
	}
	if g.tunnel == "" {
		return GluetunLinks{HostIndex: glHostIfIndex}, nil
	}
	return GluetunLinks{Tunnel: TunnelLink{Present: true, Up: g.tunnelUp, Index: glTunnelIfIndex}, HostIndex: glHostIfIndex}, nil
}

// tunnelIndex is the index the tunnel route names: the interface's current one.
func (g *glKernel) tunnelIndex() uint32 {
	switch {
	case g.rc != nil:
		return g.rc.ifindex
	case g.linkScript != nil:
		return g.lastIndex
	}
	return glTunnelIfIndex
}

func (g *glKernel) exitRoutes(f rtnl.Family, tunnelRoute bool) []rtnl.Route {
	routes := []rtnl.Route{contract.FallbackRoute(f, g.c.Table)}
	if f == rtnl.V4 && tunnelRoute {
		routes = append([]rtnl.Route{contract.TunnelRoute(f, g.c.Table, g.tunnelIndex())}, routes...)
	}
	return routes
}

func (g *glKernel) mainRoutes(f rtnl.Family) []rtnl.Route {
	routes := glHostRoutes(f, rtnl.TableMain)
	if f == rtnl.V4 {
		routes = append(routes, rtnl.Route{Family: f, Dst: netip.MustParsePrefix("192.0.2.0/24"), Table: rtnl.TableMain,
			Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(glOverlayIfIndex)), Scope: rtnl.RTScopeLink})
	}
	return routes
}

func (g *glKernel) GluetunTables(_ context.Context, family int) (GluetunTables, error) {
	g.record("GluetunTables %d", family)
	f := rtnl.Family(family)
	if g.rc != nil && family == 4 {
		return GluetunTables{Rules: g.rc.rules(g), Exit: g.rc.exit(g), Host: g.hostRoutes[4], Main: g.mainRoutes(f)}, nil
	}
	rules := slices.Clone(g.rules[family])
	if g.tunnel == "" && g.rc == nil {
		rules = slices.DeleteFunc(rules, func(r rtnl.Rule) bool { return r.Priority == 94 })
	}
	return GluetunTables{Rules: rules, Exit: g.exitRoutes(f, g.tunnel != "" && g.tunnelRoutePresent),
		Host: slices.Clone(g.hostRoutes[family]), Main: g.mainRoutes(f)}, nil
}

// dropRule removes the rules at a priority from a family (the Python tests
// filtered the kernel's list).
func (g *glKernel) dropRule(family int, priority uint32) {
	g.rules[family] = slices.DeleteFunc(g.rules[family], func(r rtnl.Rule) bool { return r.Priority == priority })
}

// -- the control server --------------------------------------------------------------------------

// fakeGluetun is the Python FakeGluetun: gluetun's control server and the
// tunnel it manages. A PUT restarts the tunnel, which is gone for
// restartTicks kernel reads, then comes back with the selected server's peer.
type fakeGluetun struct {
	k            *glKernel
	puts         []string
	fail         bool
	restartTicks int
	connectTo    string // overrides the server gluetun ends up on
	status       string
	statusErr    error
	updater      string
	updates      int
	updateFails  bool
	updaterErr   error
	// onPut replaces the default PUT behavior (the reconnecting kernel).
	onPut func(host string)
}

func newFakeGluetun(k *glKernel) *fakeGluetun {
	return &fakeGluetun{k: k, restartTicks: 2, status: "running", updater: "stopped"}
}

func (f *fakeGluetun) SelectRelay(_ context.Context, relay *providers.Relay, _ string) (string, error) {
	if f.fail {
		return "", ErrGluetunRequest
	}
	f.puts = append(f.puts, relay.Hostname)
	if f.onPut != nil {
		f.onPut(relay.Hostname)
		return "settings updated", nil
	}
	host := f.connectTo
	if host == "" {
		host = relay.Hostname
	}
	f.k.tunnel, f.k.hasPending, f.k.pendingTicks, f.k.pendingHost = "", true, f.restartTicks, host
	return "settings updated", nil
}

func (f *fakeGluetun) VPNStatus(context.Context) (string, error) {
	if f.statusErr != nil {
		return "", f.statusErr
	}
	return f.status, nil
}

func (f *fakeGluetun) StartUpdate(context.Context) (string, error) {
	if f.updateFails {
		return "", ErrGluetunRequest
	}
	f.updates++
	f.updater = "running"
	return "running", nil
}

func (f *fakeGluetun) UpdaterStatus(context.Context) (string, error) {
	if f.updaterErr != nil {
		return "", f.updaterErr
	}
	return f.updater, nil
}

// -- reconnecting ------------------------------------------------------------------------------------

const (
	rcOld   = glTunnel4
	rcNew   = "10.64.0.9"
	rcThird = "10.64.0.77"
)

// reconnecting is gluetun's reconnection as Linux and the guard show it (the
// Python Reconnecting): while the interface is gone, rules 90 and 96 are
// detached; the new interface comes up first, its address next, and the guard
// adds rule 94 for it before deleting the old one, then puts the route back.
type reconnecting struct {
	phase    []string
	address  string
	ifindex  uint32
	nextHost string
	// third adds a stable rule 94 for a third address while a switch runs.
	third bool
}

func (r *reconnecting) put(host string) {
	r.phase = []string{"gone", "gone", "up", "addressed", "both", "new-only", "routed"}
	r.nextHost = host
}

func (r *reconnecting) current() string {
	if len(r.phase) > 0 {
		return r.phase[0]
	}
	return "routed"
}

func (r *reconnecting) active() bool { return len(r.phase) > 0 }

// advance moves a phase on; it reports whether it did (the base kernel's own
// restart is not used while reconnecting).
func (r *reconnecting) advance(g *glKernel) bool {
	if len(r.phase) > 0 {
		r.phase = r.phase[1:]
		if len(r.phase) > 0 && r.phase[0] == "up" {
			r.ifindex++
		}
		if len(r.phase) == 0 || r.phase[0] == "routed" {
			g.tunnel, r.phase, r.address = r.nextHost, nil, rcNew
		}
	}
	return true
}

func (r *reconnecting) links() GluetunLinks {
	if r.current() == "gone" {
		return GluetunLinks{HostIndex: glHostIfIndex}
	}
	return GluetunLinks{Tunnel: TunnelLink{Present: true, Up: true, Index: r.ifindex}, HostIndex: glHostIfIndex}
}

func (r *reconnecting) addresses() ([]netip.Addr, error) {
	phase := r.current()
	if phase == "gone" {
		return nil, errors.New("command failed")
	}
	if phase == "up" {
		return nil, nil
	}
	if len(r.phase) > 0 {
		return []netip.Addr{netip.MustParseAddr(rcNew)}, nil
	}
	return []netip.Addr{netip.MustParseAddr(r.address)}, nil
}

func (r *reconnecting) rules(g *glKernel) []rtnl.Rule {
	phase := r.current()
	var returns []string
	switch phase {
	case "gone", "up":
		returns = []string{rcOld}
	case "addressed":
		returns = nil
	case "both":
		returns = []string{rcOld, rcNew}
	case "new-only":
		returns = []string{rcNew}
	default:
		returns = []string{r.address}
	}
	table := snapshotRules(g.t, g.c, returns, phase == "gone")
	if r.third && len(r.phase) > 0 {
		table = append(table, glRule(g.t, g.c, rtnl.V4, 94, rcThird))
		slices.SortStableFunc(table, func(a, b rtnl.Rule) int { return int(a.Priority) - int(b.Priority) })
	}
	return table
}

func (r *reconnecting) exit(g *glKernel) []rtnl.Route {
	return g.exitRoutes(rtnl.V4, len(r.phase) == 0)
}

// snapshotRules is the Python snapshot(): the IPv4 contract with rule 94 for
// each return path, and rules 90 and 96 detached when asked.
func snapshotRules(t testing.TB, c contract.Config, returnPaths []string, detached bool) []rtnl.Rule {
	t.Helper()
	var table []rtnl.Rule
	for _, r := range glRules(t, c, rtnl.V4) {
		if r.Priority == 94 {
			continue
		}
		if detached && r.Priority == 90 {
			r.Flags |= rtnl.FIBRuleIifDetached
		}
		if detached && r.Priority == 96 {
			r.Flags |= rtnl.FIBRuleOifDetached
		}
		table = append(table, r)
	}
	for _, a := range returnPaths {
		table = append(table, glRule(t, c, rtnl.V4, 94, a))
	}
	slices.SortStableFunc(table, func(a, b rtnl.Rule) int { return int(a.Priority) - int(b.Priority) })
	return table
}

// -- building appliers ------------------------------------------------------------------------------------

// glFixture is the Python make(): an applier on the fake kernel with gluetun's
// server list in a temporary directory.
type glFixture struct {
	a        *Applier
	k        *glKernel
	control  *fakeGluetun
	provider *gluetunProvider
	dir      string
	servers  string
}

type glOptions struct {
	provider string // gluetun's own id; ivpn when empty
	sidecar  bool
	noWrite  bool
	server   string
	period   int // seconds; the default 24 h when 0, off when negative
	kernel   *glKernel
	setup    func(*glKernel, *fakeGluetun)
}

func newGluetunFixture(t testing.TB, o glOptions) *glFixture {
	t.Helper()
	if o.provider == "" {
		o.provider = "ivpn"
	}
	c := glRouting(t)
	if o.sidecar {
		c = glSidecar()
	}
	k := o.kernel
	if k == nil {
		k = newGlKernel(t, c)
	}
	dir := t.TempDir()
	servers := filepath.Join(dir, "gluetun-servers", "servers.json")
	if err := os.MkdirAll(filepath.Dir(servers), 0o777); err != nil {
		t.Fatal(err)
	}
	if !o.noWrite {
		writeFile(t, servers, serversJSON(o.provider, 0), 0o644)
	}
	control := newFakeGluetun(k)
	period := o.period
	switch {
	case period == 0:
		period = 24 * 60 * 60
	case period < 0:
		period = 0
	}
	provider, err := newGluetun("gluetun-"+o.provider, GluetunSettings{Routing: c, ServersFile: servers, UpdaterPeriodSec: period}, control)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{StateDir: dir, Exit: k.exit, Provider: provider, System: k, Server: o.server, BootID: testBoot,
		Monotonic: k.clock, Sleep: k.sleep, Log: func(s string) { k.logs = append(k.logs, s) }}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a.ownerCheck = func() validate.Obj {
		return validate.Members("state", "pass", "at", validate.FormatTime(time.Now()))
	}
	if _, err := a.catalog.Refresh(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if o.setup != nil {
		o.setup(k, control)
	}
	return &glFixture{a: a, k: k, control: control, provider: provider, dir: dir, servers: servers}
}

func (f *glFixture) gluetunCatalog() *GluetunCatalog { return f.a.catalog.(*GluetunCatalog) }

// request is the Python request(): a panel request for a server.
func glRequest(server string) map[string]any {
	return requestAt(server, map[string]any{"request_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"})
}
