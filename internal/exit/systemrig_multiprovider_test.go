//go:build drill && systemrig && linux

package exit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/nstest"
	"github.com/irashack/molebridge/internal/providers"
)

// The multi-provider drills (docs/design/multi-provider.md, "System rig
// drills"): an exit with PROVIDERS, on the drill build (the release build
// refuses PROVIDERS until multi-provider exits are switched on), changes
// its whole tunnel between the rig's Mullvad relays, a fake NordVPN server
// and a fake PIA server (systemrig_pia_test.go) without a restart, while a
// client behind the overlay keeps probing. The fake NordVPN network is
// shaped like NordVPN's: a catalogue in the shape of GET /v2/servers
// (tools/fixtures/nordvpn), one WireGuard server on port 51820 that knows
// the exit's nordvpn.conf key and its tunnel address 10.5.0.2, IPv4 only, an
// SNAT to the server's own egress address, and the ips/insights check, which
// says protected only for that address.
//
//	client ──▶ exit (wt0 … vpn) ──▶ relayA | relayB | nord | pia ──SNAT──▶ internet

const (
	rigNordHost     = "us9001.nordvpn.com" // the fixture's server
	rigNordEndpoint = "198.51.100.17"
	rigNordGateway  = "198.51.100.18"
	rigNordEgress   = "203.0.113.30"
	rigNordLink     = "nord0"
)

// rigNord is the fake NordVPN server.
type rigNord struct {
	ns     *nstest.NS
	key    wgtypes.Key // the server's
	exit   wgtypes.Key // the exit's nordvpn.conf key
	served []byte      // the catalogue it serves
}

// addNord builds the fake NordVPN server, its catalogue and insights, and
// the exit's nordvpn.conf. It must run before the exit starts.
func (r *systemRig) addNord() *rigNord {
	t := r.t
	n := &rigNord{ns: nstest.New(t, "nord"), key: rigKey(t), exit: rigKey(t)}
	ns, in := n.ns, r.internet
	rigSysctls(ns)
	ns.Sysctl("net.ipv4.ip_forward=1")
	ns.Veth("eth0", in, rigNordLink)
	addrUp(ns, "eth0", rigNordEndpoint+"/30")
	addrUp(in, rigNordLink, rigNordGateway+"/30")
	ns.IP("route", "add", "default", "via", rigNordGateway)
	in.IP("route", "add", rigNordEgress+"/32", "via", rigNordEndpoint)
	ns.IP("link", "add", "wg0", "type", "wireguard")
	port := providers.NordPort
	wgSet(t, ns, "wg0", wgtypes.Config{PrivateKey: &n.key, ListenPort: &port, ReplacePeers: true, Peers: []wgtypes.PeerConfig{{
		PublicKey: n.exit.PublicKey(), ReplaceAllowedIPs: true,
		// NordLynx's one tunnel address, and the overlay's (the fake NetBird
		// does not masquerade the client). No IPv6: NordLynx carries none.
		AllowedIPs: rigPrefixes(t, providers.NordAddress, "192.0.2.0/24"),
	}}})
	addrUp(ns, "wg0", "10.5.0.1/32")
	for _, c := range []string{providers.NordAddress, "192.0.2.0/24"} {
		ns.IP("route", "add", c, "dev", "wg0")
	}
	nat := `table inet relay {
  chain post {
    type nat hook postrouting priority srcnat; policy accept;
    iifname "wg0" oifname "eth0" meta nfproto ipv4 snat ip to ` + rigNordEgress + `
  }
}
`
	if out, err := ns.ExecInput(nat, "nft", "-f", "-"); err != nil {
		t.Fatalf("nft in nord: %v\n%s", err, out)
	}

	// The exit's NordVPN config, as prepare-config --nordvpn writes it: the
	// account key, the shared address, no peer.
	conf := "[Interface]\nPrivateKey = " + n.exit.String() + "\nAddress = " + providers.NordAddress + "\nMTU = 1420\nTable = off\n" +
		"PostUp = ip route replace default dev %i table 51821\nPreDown = ip route del default dev %i table 51821\n"
	if err := os.WriteFile(filepath.Join(r.confDir, "nordvpn.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}

	n.served = nordCatalog(t, n.key)
	serversPath := strings.SplitN(strings.TrimPrefix(providers.NordServersURL, "https://api.nordvpn.com"), "?", 2)[0]
	insightsPath := strings.TrimPrefix(providers.NordInsightsURL, "https://api.nordvpn.com")
	nordAPI := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		host, _, _ := net.SplitHostPort(req.RemoteAddr)
		src, err := netip.ParseAddr(host)
		if err != nil {
			http.Error(w, "bad source", http.StatusInternalServerError)
			return
		}
		src = src.Unmap()
		r.logServed("nordvpn %s%s from %s", req.Host, req.URL.Path, src)
		w.Header().Set("Content-Type", "application/json")
		switch req.URL.Path {
		case serversPath:
			_, _ = w.Write(n.served)
		case insightsPath:
			_ = json.NewEncoder(w).Encode(map[string]any{"ip": src.String(), "city": rigCity, "country": rigCountry,
				"country_code": "ZZ", "protected": src.String() == rigNordEgress})
		default:
			http.NotFound(w, req)
		}
	})
	r.mu.Lock()
	if r.apis == nil {
		r.apis = map[string]http.Handler{}
	}
	r.apis["api.nordvpn.com"] = nordAPI
	r.mu.Unlock()
	return n
}

// nordCatalog is the fixture's NordVPN catalogue with only its first
// server, reached at the fake server's address with the fake server's key.
func nordCatalog(t *testing.T, key wgtypes.Key) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tools", "fixtures", "nordvpn", "nordvpn-servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var kept []any
	list, _ := doc["servers"].([]any)
	for _, s := range list {
		server, _ := s.(map[string]any)
		if server["hostname"] != rigNordHost {
			continue
		}
		server["station"] = rigNordEndpoint
		for _, e := range server["ips"].([]any) {
			e.(map[string]any)["ip"].(map[string]any)["ip"] = rigNordEndpoint
		}
		for _, tech := range server["technologies"].([]any) {
			metadata, _ := tech.(map[string]any)["metadata"].([]any)
			for _, m := range metadata {
				if meta, _ := m.(map[string]any); meta["name"] == "public_key" {
					meta["value"] = key.PublicKey().String()
				}
			}
		}
		kept = append(kept, server)
	}
	doc["servers"] = kept
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	// The exit must read it as the fake server.
	entries, err := providers.ParseNordCatalogBody(out, false)
	if err != nil {
		t.Fatalf("the fake NordVPN catalogue: %v", err)
	}
	relay, ok := entries.Get(rigNordHost)
	if !ok || entries.Len() != 1 || relay.IPv4AddrIn != rigNordEndpoint || relay.PublicKey != key.PublicKey().String() {
		t.Fatalf("the fake NordVPN catalogue reads as %d servers, %+v", entries.Len(), relay)
	}
	return out
}

// request writes the panel's request for a provider's server, as the
// panel writes it, and returns its id.
func (r *systemRig) request(provider, server string) string {
	t := r.t
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	id := hex.EncodeToString(b)
	raw, err := json.Marshal(map[string]any{"provider": provider, "server": server,
		"requested_at": time.Now().UTC().Format(time.RFC3339), "request_id": id})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(r.stateDir, "panel")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, ".desired.json.tmp")
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, "desired.json")); err != nil {
		t.Fatal(err)
	}
	return id
}

// rigExit is one provider's server on the rig, as a drill asks for it and
// checks it.
type rigExit struct {
	provider, server string
	endpoint         string // its WireGuard endpoint's address
	egress4, egress6 string // egress6 "" for a provider with no IPv6
	link             string // its interface in "internet", for its via_ counter
	relay            *rigRelay
}

func mullvadExit(rl *rigRelay) rigExit {
	return rigExit{provider: "mullvad", server: rl.host, endpoint: rl.endpoint, egress4: rl.egress4, egress6: rl.egress6, link: rl.link, relay: rl}
}

func nordExit() rigExit {
	return rigExit{provider: "nordvpn", server: rigNordHost, endpoint: rigNordEndpoint, egress4: rigNordEgress, link: rigNordLink}
}

func piaExit() rigExit {
	return rigExit{provider: "pia", server: rigPIARegion, endpoint: rigPIAEndpoint, egress4: rigPIAEgress, link: rigPIALink}
}

// via is how probeLoop names a probe that left by e.
func (e rigExit) via() string {
	if e.relay != nil {
		return e.relay.host
	}
	return "other:" + e.egress4
}

func (e rigExit) String() string { return e.provider + " " + e.server }

// multiProvider makes the exit a multi-provider one on the drill build,
// with providers (PROVIDERS) and the tunnel interface vpn.
func (r *systemRig) multiProvider(providers string) {
	r.exitExtra = append(r.exitExtra, "PROVIDERS="+providers, "EXIT_IF=vpn", "NB_EXTRA_IFACE_BLACKLIST=vpn")
	// The drill build: the release build refuses PROVIDERS until
	// multi-provider exits are switched on (multi_available.go).
	r.bin = filepath.Join(filepath.Dir(r.bin), "molebridge-drill")
}

// verifiedOn is whether result.json is ok on e, verified by e's provider's
// own check from e's egress addresses, for requestID when it is set.
func (r *systemRig) verifiedOn(e rigExit, requestID string) bool {
	res := r.result()
	if res == nil || res["status"] != "ok" || res["provider"] != e.provider || res["server"] != e.server {
		return false
	}
	if requestID != "" {
		sel, _ := res["selection"].(map[string]any)
		if res["request_id"] != requestID || sel["outcome"] != "verified" || sel["target_provider"] != e.provider {
			return false
		}
	}
	if e.relay != nil {
		return r.verified(e.relay, requestID)
	}
	checks, _ := res["checks"].(map[string]any)
	eg, _ := checks["egress"].(map[string]any)
	ips, _ := res["egress_ips"].(map[string]any)
	return eg["state"] == "pass" && ips["4"] == e.egress4 && ips["6"] == nil
}

// waitOn waits for verifiedOn while the exit runs.
func (r *systemRig) waitOn(p *exitProc, e rigExit, requestID string, d time.Duration) {
	r.t.Helper()
	r.waitFor(d, "result.json verified on "+e.String()+" (request "+requestID+")", func() bool {
		if !p.running() {
			r.t.Fatalf("the exit stopped (%d):\n%s", p.code, p.out.String())
		}
		return r.verifiedOn(e, requestID)
	})
}

// clientOn waits until the client's traffic leaves by e: both families by a
// Mullvad relay; IPv4 by the others, whose tunnels carry no IPv6, so the
// client's IPv6 then has no way out.
func (r *systemRig) clientOn(e rigExit, d time.Duration) {
	r.t.Helper()
	if e.relay != nil {
		r.clientVia(e.relay, d)
		return
	}
	client := nsClient(r.client, r.roots, "echo.example.net", 3*time.Second)
	var last string
	r.waitFor(d, "the client's IPv4 to leave by "+e.String(), func() bool {
		ip, _, err := r.probe(client, 4)
		last = fmt.Sprintf("%s %v", ip, err)
		return err == nil && ip == e.egress4
	})
	if ip, _, err := r.probe(client, 6); err == nil {
		r.t.Errorf("the client's IPv6 left by %s while the tunnel is %s's (last IPv4: %s)", ip, e.provider, last)
	}
}

// leakFree requires the internet's leak counter at zero: nothing from the
// client has reached the internet by the exit's host path, outside
// WireGuard.
func (r *systemRig) leakFree(when string) {
	r.t.Helper()
	if n := r.counted("leak"); n != 0 {
		r.t.Errorf("%s: %d packets from the client reached the internet by the host path", when, n)
	}
}

// endpoints is what `wg show vpn endpoints` lists in the exit: "" with no
// link.
func (r *systemRig) endpoints() string {
	out, err := r.exit.Exec("wg", "show", "vpn", "endpoints")
	if err != nil {
		return ""
	}
	return out
}

// tunnelProvider is the provider tunnel-provider.json names.
func (r *systemRig) tunnelProvider() string {
	raw, err := os.ReadFile(filepath.Join(r.stateDir, "applier", "tunnel-provider.json"))
	if err != nil {
		return ""
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	id, _ := m["provider"].(string)
	return id
}

// onTunnel checks that the exit's tunnel is e's: tunnel-provider.json and
// the link's peer.
func (r *systemRig) onTunnel(e rigExit) {
	r.t.Helper()
	if got := r.tunnelProvider(); got != e.provider {
		raw, _ := os.ReadFile(filepath.Join(r.stateDir, "applier", "tunnel-provider.json"))
		r.t.Errorf("tunnel-provider.json on %s: %s", e, raw)
	}
	if out := r.endpoints(); !strings.Contains(out, e.endpoint+":") {
		r.t.Errorf("the exit's tunnel on %s: %q", e, out)
	}
}

// switchTo asks the exit for to and waits until the change is verified with
// to's provider's own check, the client's traffic follows it and nothing of
// it reached the internet outside WireGuard. It returns the request id and
// how long verification took.
func (r *systemRig) switchTo(p *exitProc, from, to rigExit) (string, time.Duration) {
	t := r.t
	t.Helper()
	at := time.Now()
	id := r.request(to.provider, to.server)
	r.waitOn(p, to, id, 150*time.Second)
	took := time.Since(at)
	r.clientOn(to, 30*time.Second)
	r.onTunnel(to)
	if from.provider == "pia" && to.provider != "pia" {
		// Leaving PIA forgets its registration and its forwarded port.
		if _, err := os.Stat(filepath.Join(r.stateDir, "applier", "tunnel.json")); !os.IsNotExist(err) {
			t.Errorf("PIA's registration outlived it on %s: %v", to, err)
		}
		if res := r.result(); res["forwarded_port"] != nil || res["port_forward_error"] != nil {
			t.Errorf("PIA's port forwarding outlived it on %s: %s", to, jsonText(res))
		}
	}
	r.leakFree(from.String() + " -> " + to.String())
	t.Logf("%s -> %s: verified %v after the request; selection %s", from, to, took.Round(time.Millisecond), jsonText(r.result()["selection"]))
	return id, took
}

// The routing-repair drill on each provider: a subset of the drift table
// (internal/drill/drift_drill_test.go, tools/check-routing.sh) applied to a
// running multi-provider exit with that provider's tunnel up. That table's
// own rig has no providers, so the faults are applied again here: each of
// the contract's rules deleted, the tunnel's default route deleted, and the
// exit table flushed, in each family where the exit has them. Each must be
// repaired back to the routing the exit had before it, with nothing from the
// client reaching the internet outside WireGuard meanwhile.

// rigRepairPriorities are the rules deleted one at a time.
var rigRepairPriorities = []string{"1", "90", "94", "95", "96", "97", "98"}

// routing is the exit's rules and exit-table routes, both families, one
// sorted line each.
func (r *systemRig) routing() string {
	var lines []string
	for _, args := range [][]string{
		{"-4", "rule", "show"}, {"-6", "rule", "show"},
		{"-4", "route", "show", "table", "51821"}, {"-6", "route", "show", "table", "51821"},
	} {
		out, err := r.exit.Exec("ip", args...)
		if err != nil {
			r.t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		for _, l := range strings.Split(out, "\n") {
			if l = strings.TrimSpace(l); l != "" {
				lines = append(lines, args[0]+" "+args[1]+" "+strings.Join(strings.Fields(l), " "))
			}
		}
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// hasRule is whether the exit has a rule at priority in family.
func (r *systemRig) hasRule(family, priority string) bool {
	out, _ := r.exit.Exec("ip", family, "rule", "show")
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), priority+":") {
			return true
		}
	}
	return false
}

// repairs runs the repair drill on e's tunnel.
func (r *systemRig) repairs(p *exitProc, e rigExit) {
	t := r.t
	t.Helper()
	// A settled baseline: the same twice, a second apart.
	var before string
	r.waitFor(30*time.Second, "the exit's routing to settle on "+e.String(), func() bool {
		a := r.routing()
		time.Sleep(time.Second)
		before = r.routing()
		return a == before
	})
	type fault struct {
		name string
		args []string
		has  func(family string) bool
	}
	var faults []fault
	for _, prio := range rigRepairPriorities {
		prio := prio
		faults = append(faults, fault{"rule " + prio + " deleted", []string{"rule", "del", "priority", prio},
			func(f string) bool { return r.hasRule(f, prio) }})
	}
	faults = append(faults,
		fault{"tunnel route deleted", []string{"route", "del", "default", "dev", "vpn", "table", "51821"},
			func(f string) bool {
				out, _ := r.exit.Exec("ip", f, "route", "show", "default", "dev", "vpn", "table", "51821")
				return strings.TrimSpace(out) != ""
			}},
		fault{"exit table flushed", []string{"route", "flush", "table", "51821"}, func(string) bool { return true }},
	)
	var slowest time.Duration
	var slowestName string
	n := 0
	for _, family := range []string{"-4", "-6"} {
		for _, f := range faults {
			if !f.has(family) {
				continue
			}
			name := f.name + " (" + map[string]string{"-4": "IPv4", "-6": "IPv6"}[family] + ")"
			at := time.Now()
			if out, err := r.exit.Exec("ip", append([]string{family}, f.args...)...); err != nil {
				t.Fatalf("%s on %s: %v\n%s", name, e, err, out)
			}
			var now string
			deadline := time.Now().Add(30 * time.Second)
			for {
				if now = r.routing(); now == before {
					break
				}
				if !p.running() {
					t.Fatalf("the exit stopped (%d):\n%s", p.code, p.out.String())
				}
				if time.Now().After(deadline) {
					t.Fatalf("%s on %s was not repaired within 30s;\nbefore:\n%s\nnow:\n%s", name, e, before, now)
				}
				time.Sleep(20 * time.Millisecond)
			}
			if took := time.Since(at); took > slowest {
				slowest, slowestName = took, name
			}
			n++
			r.leakFree(name + " on " + e.String())
		}
	}
	r.clientOn(e, 30*time.Second)
	r.leakFree("the repairs on " + e.String())
	t.Logf("repairs on %s: %d faults repaired, the slowest %s in %v", e, n, slowestName, slowest.Round(time.Millisecond))
}

// TestSystemRigMultiProviderSwitch: an exit with all three providers changes
// its tunnel between every pair of them in both directions (Mullvad ->
// NordVPN -> PIA -> Mullvad -> PIA -> NordVPN -> Mullvad), each change
// verified with its provider's own check, the client's traffic following,
// and nothing from the client reaching the internet by the exit's host path
// at any point. The repair drill runs on each provider's tunnel the first
// time it is up.
func TestSystemRigMultiProviderSwitch(t *testing.T) {
	t.Parallel()
	r := newSystemRig(t)
	a, b := r.relays[0], r.relays[1]
	r.addNord()
	r.addPIA()
	r.multiProvider("mullvad,nordvpn,pia")
	p := r.start()
	r.waitReady(p)
	r.connectOverlay()
	A, B, N, P := mullvadExit(a), mullvadExit(b), nordExit(), piaExit()
	r.waitOn(p, A, "", 120*time.Second)
	if res := r.result(); res["schema"] != float64(2) || jsonText(res["providers"]) != `["mullvad","nordvpn","pia"]` || res["provider"] != "mullvad" {
		t.Fatalf("the multi-provider record: %s", jsonText(res))
	}
	r.clientOn(A, 30*time.Second)
	r.leakFree("on " + A.String())

	// The other providers' catalogues are refreshed while Mullvad is active.
	for _, name := range []string{"relays-nordvpn.json", "relays-pia.json"} {
		r.waitFor(60*time.Second, name, func() bool {
			_, err := os.Stat(filepath.Join(r.stateDir, "applier", name))
			return err == nil
		})
	}

	stop := make(chan struct{})
	samples := r.probeLoop(stop)
	r.repairs(p, A)
	repaired := map[string]bool{"mullvad": true}
	from := A
	var total time.Duration
	for _, to := range []rigExit{N, P, B, P, N, A} {
		_, took := r.switchTo(p, from, to)
		total += took
		if !repaired[to.provider] {
			r.repairs(p, to)
			repaired[to.provider] = true
		}
		from = to
	}
	close(stop)
	byVia := map[string]int{}
	allowed := map[string]bool{"": true, A.via(): true, B.via(): true, N.via(): true, P.via(): true}
	for _, s := range <-samples {
		byVia[s.via]++
		if !allowed[s.via] {
			t.Errorf("a client probe at %s left by %s", s.at.Format(time.RFC3339Nano), s.via)
		}
	}
	t.Logf("six changes verified in %v in all; client probes: %d by %s, %d by %s, %d by NordVPN, %d by PIA, %d failed",
		total.Round(time.Millisecond), byVia[A.via()], a.host, byVia[B.via()], b.host, byVia[N.via()], byVia[P.via()], byVia[""])

	r.leakFree("at the end")
	var counts []string
	for _, e := range []rigExit{A, B, N, P} {
		n := r.counted("via_" + e.link)
		if n == 0 {
			t.Errorf("no client probe arrived by %s", e)
		}
		counts = append(counts, fmt.Sprintf("%d by %s", n, e))
	}
	t.Logf("client probe packets at the internet: %s, 0 by the host path", strings.Join(counts, ", "))
	if !p.running() {
		t.Fatalf("the exit stopped (%d):\n%s", p.code, p.out.String())
	}
}
