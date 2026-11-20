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
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/nstest"
	"github.com/irashack/molebridge/internal/providers"
)

// The multi-provider drill (docs/design/multi-provider.md, piece 6): one
// exit with PROVIDERS=mullvad,nordvpn, on the drill build (the release build
// refuses PROVIDERS until multi-provider exits are switched on), changes its tunnel from the rig's
// Mullvad relay A to a fake NordVPN server and back to Mullvad relay B,
// without a restart, while a client behind the overlay keeps probing. The
// fake NordVPN network is shaped like NordVPN's: a catalogue in the shape of
// GET /v2/servers (tools/fixtures/nordvpn), one WireGuard server on port
// 51820 that knows the exit's nordvpn.conf key and its tunnel address
// 10.5.0.2, IPv4 only, an SNAT to the server's own egress address, and the
// ips/insights check, which says protected only for that address.
//
//	client ──▶ exit (wt0 … vpn) ──▶ relayA | nord | relayB ──SNAT──▶ internet

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
	r.mu.Lock()
	r.nordAPI = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
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

// nordVerified is whether result.json is ok on the fake NordVPN server for
// requestID, with NordVPN's insights passing from its egress address.
func (r *systemRig) nordVerified(requestID string) bool {
	res := r.result()
	if res == nil || res["status"] != "ok" || res["provider"] != "nordvpn" || res["server"] != rigNordHost {
		return false
	}
	sel, _ := res["selection"].(map[string]any)
	if res["request_id"] != requestID || sel["outcome"] != "verified" || sel["target_provider"] != "nordvpn" {
		return false
	}
	checks, _ := res["checks"].(map[string]any)
	eg, _ := checks["egress"].(map[string]any)
	ips, _ := res["egress_ips"].(map[string]any)
	return eg["state"] == "pass" && ips["4"] == rigNordEgress && ips["6"] == nil
}

// clientViaNord waits until the client's IPv4 leaves by the fake NordVPN
// server; its IPv6 then has no way out (NordLynx carries none).
func (r *systemRig) clientViaNord(d time.Duration) {
	r.t.Helper()
	client := nsClient(r.client, r.roots, "echo.example.net", 3*time.Second)
	var last string
	r.waitFor(d, "the client's IPv4 to leave by "+rigNordHost, func() bool {
		ip, _, err := r.probe(client, 4)
		last = fmt.Sprintf("%s %v", ip, err)
		return err == nil && ip == rigNordEgress
	})
	if ip, _, err := r.probe(client, 6); err == nil {
		r.t.Errorf("the client's IPv6 left by %s while the tunnel is NordVPN's (last IPv4: %s)", ip, last)
	}
}

// TestSystemRigMultiProviderSwitch: Mullvad relay A, then NordVPN, then
// Mullvad relay B, each change verified with its provider's own check, the
// client's traffic following, and nothing from the client reaching the
// internet by the exit's host path at any point.
func TestSystemRigMultiProviderSwitch(t *testing.T) {
	t.Parallel()
	r := newSystemRig(t)
	a, b := r.relays[0], r.relays[1]
	r.addNord()
	r.exitExtra = []string{"PROVIDERS=mullvad,nordvpn", "EXIT_IF=vpn", "NB_EXTRA_IFACE_BLACKLIST=vpn"}
	// The drill build: the release build refuses PROVIDERS until
	// multi-provider exits are switched on (multi_available.go).
	r.bin = filepath.Join(filepath.Dir(r.bin), "molebridge-drill")
	p := r.start()
	r.waitReady(p)
	r.connectOverlay()
	r.waitVerified(p, a, "", 120*time.Second)
	if res := r.result(); res["schema"] != float64(2) || jsonText(res["providers"]) != `["mullvad","nordvpn"]` || res["provider"] != "mullvad" {
		t.Fatalf("the multi-provider record: %s", jsonText(res))
	}
	r.clientVia(a, 30*time.Second)
	leakFree := func(when string) {
		t.Helper()
		if n := r.counted("leak"); n != 0 {
			t.Errorf("%s: %d packets from the client reached the internet by the host path", when, n)
		}
	}
	leakFree("on " + a.host)

	// NordVPN's catalogue is refreshed while Mullvad is active.
	r.waitFor(60*time.Second, "relays-nordvpn.json", func() bool {
		_, err := os.Stat(filepath.Join(r.stateDir, "applier", "relays-nordvpn.json"))
		return err == nil
	})

	stop := make(chan struct{})
	samples := r.probeLoop(stop)

	// Mullvad A -> NordVPN.
	at := time.Now()
	id := r.request("nordvpn", rigNordHost)
	r.waitFor(150*time.Second, "result.json verified on "+rigNordHost+" (request "+id+")", func() bool {
		if !p.running() {
			t.Fatalf("the exit stopped (%d):\n%s", p.code, p.out.String())
		}
		return r.nordVerified(id)
	})
	toNord := time.Since(at)
	r.clientViaNord(30 * time.Second)
	if raw, err := os.ReadFile(filepath.Join(r.stateDir, "applier", "tunnel-provider.json")); err != nil ||
		!strings.Contains(string(raw), `"nordvpn"`) {
		t.Errorf("tunnel-provider.json: %s %v", raw, err)
	}
	if out, err := r.exit.Exec("wg", "show", "vpn", "endpoints"); err != nil || !strings.Contains(out, rigNordEndpoint+":") {
		t.Errorf("the exit's tunnel after the change: %s %v", out, err)
	}
	leakFree("on " + rigNordHost)
	t.Logf("%s -> %s: verified %v after the request; selection %s", a.host, rigNordHost, toNord.Round(time.Millisecond), jsonText(r.result()["selection"]))

	// NordVPN -> Mullvad B.
	at = time.Now()
	id = r.request("mullvad", b.host)
	r.waitVerified(p, b, id, 150*time.Second)
	toB := time.Since(at)
	if res := r.result(); res["provider"] != "mullvad" {
		t.Errorf("the record after the change back: %s", jsonText(res))
	}
	r.clientVia(b, 30*time.Second)
	leakFree("on " + b.host)
	t.Logf("%s -> %s: verified %v after the request; selection %s", rigNordHost, b.host, toB.Round(time.Millisecond), jsonText(r.result()["selection"]))

	close(stop)
	byVia := map[string]int{}
	nord := "other:" + rigNordEgress
	for _, s := range <-samples {
		byVia[s.via]++
		if s.via != "" && s.via != a.host && s.via != b.host && s.via != nord {
			t.Errorf("a client probe at %s left by %s", s.at.Format(time.RFC3339Nano), s.via)
		}
	}
	t.Logf("client probes during the changes: %d by %s, %d by %s, %d by %s, %d failed",
		byVia[a.host], a.host, byVia[nord], rigNordHost, byVia[b.host], b.host, byVia[""])

	leakFree("at the end")
	viaA, viaNord, viaB := r.counted("via_"+a.link), r.counted("via_"+rigNordLink), r.counted("via_"+b.link)
	if viaA == 0 || viaNord == 0 || viaB == 0 {
		t.Errorf("the client's probes should have arrived by all three servers: %d by %s, %d by %s, %d by %s",
			viaA, a.host, viaNord, rigNordHost, viaB, b.host)
	}
	t.Logf("client probe packets at the internet: %d by %s, %d by %s, %d by %s, 0 by the host path",
		viaA, a.host, viaNord, rigNordHost, viaB, b.host)
	if !p.running() {
		t.Fatalf("the exit stopped (%d):\n%s", p.code, p.out.String())
	}
}
