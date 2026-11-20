//go:build drill && systemrig && linux

package exit

// The system rig in the gluetun form: the exit joins gluetun's namespace, as
// compose.gluetun.yaml runs it (`network_mode: service:gluetun`), and no
// gluetun runs. The test stands in for it:
//
//   - the namespace as gluetun leaves it: its rules 98 (the host subnet), 100
//     (inbound, table 200) and 101 (`not fwmark 51820 lookup 51820`), table
//     51820 through wg0, and wg0 itself, a kernel WireGuard interface with
//     gluetun's fwmark 51820, keyed to one of the rig's relays;
//   - its control server on 127.0.0.1:8000 in that namespace, with an API key
//     file: GET /v1/vpn/status, PUT /v1/vpn/settings, GET /v1/publicip/ip and
//     GET/PUT /v1/updater/status. A settings PUT does what gluetun's VPN loop
//     does on a restart: rule 101 goes, wg0 is deleted (and the kernel drops
//     its routes), then wg0 is created with the new server's peer, its
//     addresses, its table 51820 routes and rule 101 again, in that order;
//   - its server list, servers.json in gluetun's storage format, listing the
//     rig's two relays and a server of another city with nothing behind it.
//     A server is retired by rewriting the file, which the exit polls.
//
// The client's underlay reaches the exit through "internet", by the host
// interface, as a NetBird peer would: in gluetun's namespace NetBird's
// marked WireGuard traffic has the host table only (rule 88).
//
// Not covered: real gluetun's own reconnection (its timing, its firewall and
// the rewrite of it, its updater, a stale built-in server list).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/tunnel/wgnl"
)

const (
	rigGluetunIf      = "wg0"
	rigGluetunControl = "127.0.0.1:8000"
	// rigGluetunAPIKey is the fake control server's key: fictitious, the
	// shape gluetun's role tool writes.
	rigGluetunAPIKey = "systemrigGluetunKey00000000000000000000"
	// rigGluetunMark is gluetun's WireGuard fwmark (0xca6c in v3.41.3).
	rigGluetunMark = 51820
	// rigOtherCity is a server of another city in servers.json, sorted
	// between the rig's relays: a move that ignored the city would pick it.
	rigOtherCity     = "zz-tst-wg-0011"
	rigOtherCityName = "Other City"
)

// gluetunReconnect is one settings PUT as the fake gluetun carried it out.
type gluetunReconnect struct {
	server   string
	put      time.Time
	down, up time.Duration // since the PUT: wg0 deleted, wg0 back with rule 101
	err      error
}

type gluetunRig struct {
	*systemRig
	serversPath, keyPath string
	otherKey             wgtypes.Key

	gmu        sync.Mutex
	status     string // the VPN loop's status
	updater    string
	current    *rigRelay
	reconnects []gluetunReconnect
	// reconnecting serializes the PUTs' restarts, as gluetun's loop does.
	reconnecting sync.Mutex
}

// newGluetunRig is the system rig with the exit's namespace made gluetun's:
// gluetun connected to relay A, its control server answering and its server
// list written.
func newGluetunRig(t *testing.T) *gluetunRig {
	t.Helper()
	r := newSystemRig(t)
	g := &gluetunRig{systemRig: r, otherKey: rigKey(t), status: "running", updater: "stopped"}

	// The client's underlay by the host interface: off the exit's own link
	// and onto one to "internet".
	r.exit.IP("link", "del", "under0")
	r.client.Veth("under0", r.internet, "client0")
	addrUp(r.client, "under0", "198.51.100.14/30")
	addrUp(r.internet, "client0", "198.51.100.13/30")
	r.client.IP("route", "add", "198.51.100.0/30", "via", "198.51.100.13")

	// gluetun's own rules besides 101: the host subnet by the main table, and
	// what comes from the host address by table 200.
	r.exit.IP("-4", "rule", "add", "to", "198.51.100.0/30", "lookup", "main", "priority", "98")
	r.exit.IP("-6", "rule", "add", "to", "2001:db8:2::/64", "lookup", "main", "priority", "98")
	r.exit.IP("-4", "rule", "add", "from", rigHost4, "lookup", "200", "priority", "100")
	r.exit.IP("-6", "rule", "add", "from", "2001:db8:2::1", "lookup", "200", "priority", "100")
	r.exit.IP("-4", "route", "add", "default", "via", "198.51.100.2", "dev", "eth0", "table", "200")
	r.exit.IP("-6", "route", "add", "default", "via", "2001:db8:2::2", "dev", "eth0", "table", "200")
	if err := g.tunnelUp(r.relays[0]); err != nil {
		t.Fatalf("gluetun's tunnel: %v", err)
	}
	g.current = r.relays[0]

	dir := r.path("gluetun-servers")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	g.serversPath = filepath.Join(dir, "servers.json")
	g.writeServers()
	g.keyPath = r.path("gluetun-api-key")
	if err := os.WriteFile(g.keyPath, []byte(rigGluetunAPIKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	g.serveControl()

	r.exitExtra = append(r.exitExtra,
		"TUNNEL_BACKEND=gluetun", "PROVIDER=gluetun-mullvad", "EXIT_IF="+rigGluetunIf, "NB_EXTRA_IFACE_BLACKLIST="+rigGluetunIf,
		"HOST_IF=eth0", "HOST_TABLE=51822", "EXIT_TABLE=51821", "CONTROL_MARK=0x1bd00", "NB_FWMARK_BASE=0x1bd00", "NB_FAKE_FWMARK=0x1bd00",
		"GLUETUN_CONTROL_URL=http://"+rigGluetunControl, "GLUETUN_API_KEY_FILE="+g.keyPath,
		"GLUETUN_SERVERS_FILE="+g.serversPath, "GLUETUN_UPDATER_PERIOD=0")
	r.panelEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "STATE_DIR=" + r.stateDir, "PROVIDER=gluetun-mullvad",
		"EXIT_KIND=overlay", "TZ=UTC"}
	t.Cleanup(func() {
		if t.Failed() {
			g.gmu.Lock()
			defer g.gmu.Unlock()
			for _, rc := range g.reconnects {
				t.Logf("gluetun PUT %s at %s: wg0 down %v, up %v, err %v", rc.server, rc.put.UTC().Format("15:04:05.000"), rc.down, rc.up, rc.err)
			}
			for _, f := range []string{"-4", "-6"} {
				out, _ := r.exit.TryIP(f, "rule", "show")
				t.Logf("exit %s rules:\n%s", f, out)
				out, _ = r.exit.TryIP(f, "route", "show", "table", "all")
				t.Logf("exit %s routes:\n%s", f, out)
			}
		}
	})
	return g
}

// wgConfigure is wgSet for a goroutine: the error is returned.
func wgConfigure(fd int, name string, cfg wgtypes.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := wgnl.Dial(ctx, fd)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Configure(ctx, name, cfg)
}

// tunnelUp is gluetun's WireGuard setup: the interface with its key, fwmark
// and the server's peer, its addresses, up, the table 51820 defaults, and
// rule 101 last.
func (g *gluetunRig) tunnelUp(rl *rigRelay) error {
	ns := g.exit
	if out, err := ns.TryIP("link", "add", rigGluetunIf, "type", "wireguard"); err != nil {
		return fmt.Errorf("link add: %v: %s", err, out)
	}
	mark := rigGluetunMark
	_, all4, _ := net.ParseCIDR("0.0.0.0/0")
	_, all6, _ := net.ParseCIDR("::/0")
	if err := wgConfigure(ns.Fd(), rigGluetunIf, wgtypes.Config{PrivateKey: &g.exitKey, FirewallMark: &mark, ReplacePeers: true,
		Peers: []wgtypes.PeerConfig{{PublicKey: rl.key.PublicKey(), Endpoint: &net.UDPAddr{IP: net.ParseIP(rl.endpoint), Port: 51820},
			ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{*all4, *all6}}}}); err != nil {
		return fmt.Errorf("configure: %v", err)
	}
	for _, args := range [][]string{
		{"addr", "add", rigTunnel4 + "/32", "dev", rigGluetunIf},
		{"-6", "addr", "add", rigTunnel6 + "/128", "dev", rigGluetunIf, "nodad"},
		{"link", "set", rigGluetunIf, "mtu", "1420", "up"},
		{"-4", "route", "replace", "default", "dev", rigGluetunIf, "table", fmt.Sprint(rigGluetunMark)},
		{"-6", "route", "replace", "default", "dev", rigGluetunIf, "table", fmt.Sprint(rigGluetunMark)},
		{"-4", "rule", "add", "not", "fwmark", fmt.Sprint(rigGluetunMark), "lookup", fmt.Sprint(rigGluetunMark), "priority", "101"},
		{"-6", "rule", "add", "not", "fwmark", fmt.Sprint(rigGluetunMark), "lookup", fmt.Sprint(rigGluetunMark), "priority", "101"},
	} {
		if out, err := ns.TryIP(args...); err != nil {
			return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

// tunnelDown is gluetun's teardown: rule 101, then the interface, whose
// routes the kernel drops with it.
func (g *gluetunRig) tunnelDown() error {
	ns := g.exit
	for _, f := range []string{"-4", "-6"} {
		if out, err := ns.TryIP(f, "rule", "del", "priority", "101"); err != nil {
			return fmt.Errorf("rule del %s 101: %v: %s", f, err, out)
		}
	}
	if out, err := ns.TryIP("link", "del", rigGluetunIf); err != nil {
		return fmt.Errorf("link del: %v: %s", err, out)
	}
	return nil
}

func (g *gluetunRig) setStatus(s string) {
	g.gmu.Lock()
	g.status = s
	g.gmu.Unlock()
}

// reconnect is gluetun's VPN loop restarting on new settings.
func (g *gluetunRig) reconnect(rl *rigRelay, put time.Time) {
	g.reconnecting.Lock()
	defer g.reconnecting.Unlock()
	rc := gluetunReconnect{server: rl.host, put: put}
	defer func() {
		g.gmu.Lock()
		g.reconnects = append(g.reconnects, rc)
		g.gmu.Unlock()
		if rc.err != nil {
			g.t.Errorf("the fake gluetun's reconnect to %s: %v", rl.host, rc.err)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	g.setStatus("stopping")
	if rc.err = g.tunnelDown(); rc.err != nil {
		g.setStatus("crashed")
		return
	}
	rc.down = time.Since(put)
	g.setStatus("stopped")
	time.Sleep(time.Second)
	g.setStatus("starting")
	if rc.err = g.tunnelUp(rl); rc.err != nil {
		g.setStatus("crashed")
		return
	}
	rc.up = time.Since(put)
	g.gmu.Lock()
	g.current, g.status = rl, "running"
	g.gmu.Unlock()
	g.logServed("gluetun reconnected to %s: wg0 down %v, up %v after the PUT", rl.host, rc.down.Round(time.Millisecond), rc.up.Round(time.Millisecond))
}

// writeServers writes servers.json, as gluetun's storage holds it, without
// the retired servers, by a rename as gluetun's own write is atomic for the
// reader that waits for a complete file.
func (g *gluetunRig) writeServers(retired ...string) {
	t := g.t
	t.Helper()
	entry := func(host, city, endpoint string, key wgtypes.Key) map[string]any {
		return map[string]any{"vpn": "wireguard", "country": rigCountry, "city": city, "isp": "Example Hosting", "owned": true,
			"hostname": host, "wgpubkey": key.PublicKey().String(), "ips": []any{endpoint}}
	}
	var servers []any
	for _, rl := range g.relays {
		if !slices.Contains(retired, rl.host) {
			servers = append(servers, entry(rl.host, rigCity, rl.endpoint, rl.key))
		}
	}
	servers = append(servers, entry(rigOtherCity, rigOtherCityName, "198.51.100.200", g.otherKey))
	raw, err := json.Marshal(map[string]any{"version": 1, "mullvad": map[string]any{"version": 1,
		"timestamp": time.Now().Unix() - 3600, "servers": servers}})
	if err != nil {
		t.Fatal(err)
	}
	tmp := g.serversPath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, g.serversPath); err != nil {
		t.Fatal(err)
	}
}

// putCount is how many settings PUTs named host.
func (g *gluetunRig) putCount(host string) int {
	g.gmu.Lock()
	defer g.gmu.Unlock()
	n := 0
	for _, rc := range g.reconnects {
		if rc.server == host {
			n++
		}
	}
	return n
}

// serveControl runs the fake control server in the test process on a
// listener opened on the exit namespace's loopback.
func (g *gluetunRig) serveControl() {
	t := g.t
	var ln net.Listener
	if err := g.exit.Do(func() error {
		var err error
		ln, err = net.Listen("tcp", rigGluetunControl)
		return err
	}); err != nil {
		t.Fatalf("listen %s: %v", rigGluetunControl, err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(g.control), ReadHeaderTimeout: 10 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// control answers the five routes the exit's role allows, as gluetun
// v3.41.3 does.
func (g *gluetunRig) control(w http.ResponseWriter, req *http.Request) {
	g.logServed("gluetun %s %s", req.Method, req.URL.Path)
	if req.Header.Get("X-API-Key") != rigGluetunAPIKey {
		g.t.Errorf("a control request without the API key: %s %s", req.Method, req.URL.Path)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<16))
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	g.gmu.Lock()
	status, updater, current := g.status, g.updater, g.current
	g.gmu.Unlock()
	switch req.Method + " " + req.URL.Path {
	case "GET /v1/vpn/status":
		writeJSON(w, map[string]any{"status": status})
	case "GET /v1/publicip/ip":
		if status != "running" || current == nil {
			writeJSON(w, map[string]any{"public_ip": ""})
			return
		}
		writeJSON(w, map[string]any{"public_ip": current.egress4, "city": rigCity, "country": rigCountry})
	case "GET /v1/updater/status":
		writeJSON(w, map[string]any{"status": updater})
	case "PUT /v1/updater/status":
		var asked struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(body, &asked) != nil || asked.Status != "running" {
			http.Error(w, "bad updater status", http.StatusBadRequest)
			return
		}
		g.gmu.Lock()
		g.updater = "completed"
		g.gmu.Unlock()
		writeJSON(w, map[string]any{"outcome": "running"})
	case "PUT /v1/vpn/settings":
		rl, why := g.selected(body)
		if rl == nil {
			g.t.Errorf("a settings PUT the fake gluetun refused (%s): %s", why, body)
			http.Error(w, why, http.StatusBadRequest)
			return
		}
		put := time.Now()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "settings updated")
		go g.reconnect(rl, put)
	default:
		http.NotFound(w, req)
	}
}

// selected is the relay a settings PUT selects: exactly one hostname and
// every other filter cleared, as the exit's client sends it.
func (g *gluetunRig) selected(body []byte) (*rigRelay, string) {
	var settings struct {
		Provider struct {
			ServerSelection map[string]any `json:"server_selection"`
		} `json:"provider"`
	}
	if err := json.Unmarshal(body, &settings); err != nil || len(settings.Provider.ServerSelection) == 0 {
		return nil, "no server selection"
	}
	var host string
	for field, value := range settings.Provider.ServerSelection {
		switch v := value.(type) {
		case bool:
			if v {
				return nil, field + " is set"
			}
		case []any:
			if field == "hostnames" && len(v) == 1 {
				host, _ = v[0].(string)
			} else if len(v) != 0 {
				return nil, field + " is not cleared"
			}
		default:
			return nil, field + " is not a list or a flag"
		}
	}
	for _, rl := range g.relays {
		if rl.host == host {
			return rl, ""
		}
	}
	return nil, "no relay " + host
}

// keyGluetunOverlay keys the overlay as keyOverlay does, with the client's
// underlay reached by the host interface.
func (g *gluetunRig) keyGluetunOverlay() {
	t := g.t
	exitPort, clientPort, keepalive := 51830, 51831, 5*time.Second
	wgSet(t, g.exit, dOverlay, wgtypes.Config{PrivateKey: &g.wt0Key, ListenPort: &exitPort, ReplacePeers: true, Peers: []wgtypes.PeerConfig{{
		PublicKey: g.clientKey.PublicKey(), Endpoint: &net.UDPAddr{IP: net.ParseIP("198.51.100.14"), Port: clientPort},
		ReplaceAllowedIPs: true, AllowedIPs: rigPrefixes(t, rigClient4+"/32", rigClient6+"/128"), PersistentKeepaliveInterval: &keepalive,
	}}})
	g.exit.IP("addr", "add", "192.0.2.1/24", "dev", dOverlay)
	g.exit.IP("-6", "addr", "add", "2001:db8:1::1/64", "dev", dOverlay, "nodad")
	g.exit.IP("link", "set", dOverlay, "up")
}

// connectGluetunOverlay is connectOverlay for the gluetun rig.
func (g *gluetunRig) connectGluetunOverlay() {
	t := g.t
	g.wt0Key, g.clientKey = rigKey(t), rigKey(t)
	clientPort, keepalive := 51831, 5*time.Second
	g.keyGluetunOverlay()
	c := g.client
	c.IP("link", "add", "wgc", "type", "wireguard")
	wgSet(t, c, "wgc", wgtypes.Config{PrivateKey: &g.clientKey, ListenPort: &clientPort, ReplacePeers: true, Peers: []wgtypes.PeerConfig{{
		PublicKey: g.wt0Key.PublicKey(), Endpoint: &net.UDPAddr{IP: net.ParseIP(rigHost4), Port: 51830},
		ReplaceAllowedIPs: true, AllowedIPs: rigPrefixes(t, "0.0.0.0/0", "::/0"), PersistentKeepaliveInterval: &keepalive,
	}}})
	addrUp(c, "wgc", rigClient4+"/24", rigClient6+"/64")
	c.IP("route", "add", "default", "dev", "wgc")
	c.IP("-6", "route", "add", "default", "dev", "wgc")
}

// bringUp starts the exit in gluetun's namespace, keys the overlay, starts
// the panel and waits for the exit to be verified on relay A, where gluetun
// started.
func (g *gluetunRig) bringUp() *exitProc {
	p := g.start()
	g.waitReady(p)
	g.connectGluetunOverlay()
	g.startPanel()
	started := time.Now()
	g.waitVerified(p, g.relays[0], "", 120*time.Second)
	g.t.Logf("verified on %s %v after NetBird was up; selection %s", g.relays[0].host, time.Since(started).Round(time.Millisecond), jsonText(g.result()["selection"]))
	return p
}

// TestSystemRigGluetunRetiredServer is the retired-server move in the gluetun
// form (docs/verification.md, a retired server): the requested server leaves
// gluetun's servers.json, the exit moves to the next server of its city
// through gluetun's control server, and returns once the server is listed
// again. The client keeps probing throughout; every answer must come by a
// relay, and nothing of the client's may leave by the host path.
func TestSystemRigGluetunRetiredServer(t *testing.T) {
	t.Parallel()
	g := newGluetunRig(t)
	a, b := g.relays[0], g.relays[1]
	p := g.bringUp()
	g.clientVia(a, 30*time.Second)

	stop := make(chan struct{})
	samples := g.probeLoop(stop)

	// Ask for relay A by name, so the exit records where it is.
	id, at := g.panelSwitch(a.host)
	g.waitVerified(p, a, id, 120*time.Second)
	t.Logf("request for %s verified %v after the panel's answer", a.host, time.Since(at).Round(time.Millisecond))
	if l := g.location(); l["server"] != a.host || l["city"] != rigCity || l["country"] != rigCountry || l["replacement"] != nil {
		t.Fatalf("location.json after the request: %s", jsonText(l))
	}

	// A leaves gluetun's list; the exit sees it at its next poll.
	g.writeServers(a.host)
	retired := time.Now()
	wantMoved := map[string]any{"from": a.host, "to": b.host, "reason": "left-catalogue"}
	g.waitFor(150*time.Second, "the exit to move to "+b.host, func() bool {
		if !p.running() {
			t.Fatalf("the exit stopped:\n%s", p.out.String())
		}
		res := g.result()
		moved, _ := res["moved"].(map[string]any)
		return g.verified(b, "") && res["requested_server"] == a.host && res["request_id"] == id && jsonText(moved) == jsonText(wantMoved)
	})
	movedAfter := time.Since(retired)
	res := g.result()
	if n := strings.Count(p.out.String(), logMoving); n != 1 {
		t.Errorf("%q is in the log %d times, want once:\n%s", logMoving, n, p.out.String())
	}
	if g.putCount(b.host) == 0 {
		t.Errorf("the exit moved to %s without a settings PUT", b.host)
	}
	if l := g.location(); l["server"] != a.host || l["replacement"] != b.host {
		t.Errorf("location.json after the move: %s", jsonText(l))
	}
	var v map[string]any
	g.waitFor(15*time.Second, "the panel to show the move", func() bool {
		v = g.panelStatus()
		reasons, _ := v["reasons"].([]any)
		return v["state"] == "ok" && v["label"] == "connected" && slices.Contains(reasons, any("server-moved"))
	})
	wantNote := a.host + " is no longer in the provider's server list. Connected through " + b.host + ", in the same city, instead."
	if note := g.movedNote(); note != wantNote {
		t.Errorf("the panel's note: %q, want %q", note, wantNote)
	}
	clientOnB := g.clientVia(b, 30*time.Second).Sub(retired)
	t.Logf("retired %s in servers.json: ok and verified on %s %v after the rewrite, the client's traffic by %s %v after it; moved %s, selection %s; panel %s %v",
		a.host, b.host, movedAfter.Round(time.Millisecond), b.host, clientOnB.Round(time.Millisecond), jsonText(res["moved"]), jsonText(res["selection"]), v["label"], v["reasons"])
	if n := g.counted("leak"); n != 0 {
		t.Errorf("after the move: %d client packets by the host path", n)
	}

	// A is listed again: the exit returns to it.
	g.writeServers()
	restored := time.Now()
	g.waitFor(150*time.Second, "the exit to return to "+a.host, func() bool {
		if !p.running() {
			t.Fatalf("the exit stopped:\n%s", p.out.String())
		}
		res := g.result()
		_, hasMoved := res["moved"]
		return g.verified(a, "") && res["request_id"] == id && (!hasMoved || res["moved"] == nil)
	})
	backAfter := time.Since(restored)
	res = g.result()
	if n := strings.Count(p.out.String(), logReturning); n != 1 {
		t.Errorf("%q is in the log %d times, want once:\n%s", logReturning, n, p.out.String())
	}
	if n := strings.Count(p.out.String(), logMoving); n != 1 {
		t.Errorf("%q is in the log %d times after the return, want once", logMoving, n)
	}
	if l := g.location(); l["server"] != a.host || l["replacement"] != nil {
		t.Errorf("location.json after the return: %s", jsonText(l))
	}
	g.waitFor(15*time.Second, "the panel to show "+a.host+" with no move", func() bool {
		v = g.panelStatus()
		reasons, _ := v["reasons"].([]any)
		return v["state"] == "ok" && !slices.Contains(reasons, any("server-moved"))
	})
	if note := g.movedNote(); note != "" {
		t.Errorf("the panel still notes a move: %q", note)
	}
	clientOnA := g.clientVia(a, 30*time.Second).Sub(restored)
	close(stop)
	all := <-samples
	t.Logf("%s listed again: ok on %s %v after the rewrite, the client's traffic by %s %v after it, no moved; selection %s; panel %s %v",
		a.host, a.host, backAfter.Round(time.Millisecond), a.host, clientOnA.Round(time.Millisecond), jsonText(res["selection"]), v["label"], v["reasons"])

	// What the client saw throughout: every answer came by a relay or failed.
	byVia := map[string]int{}
	var failed []string
	for _, s := range all {
		byVia[s.via]++
		if s.via == "" {
			failed = append(failed, s.at.UTC().Format("15:04:05.000"))
		}
		if s.via != "" && s.via != a.host && s.via != b.host {
			t.Errorf("a client probe at %s left by %s", s.at.Format(time.RFC3339Nano), s.via)
		}
	}
	t.Logf("client probes during the move and the return: %d by %s, %d by %s, %d failed %v", byVia[a.host], a.host, byVia[b.host], b.host, byVia[""], failed)
	if byVia[b.host] == 0 {
		t.Errorf("no client probe came by %s during the move", b.host)
	}
	if n := g.counted("leak"); n != 0 {
		t.Errorf("%d packets from the client reached the internet by the exit's host path", n)
	}
	viaA, viaB := g.counted("via_"+a.link), g.counted("via_"+b.link)
	t.Logf("client probe packets at the internet: %d by %s, %d by %s, 0 by the host path; %d of the client's by a relay without its SNAT",
		viaA, a.host, viaB, b.host, g.counted("unnat"))
	g.gmu.Lock()
	for _, rc := range g.reconnects {
		t.Logf("gluetun settings PUT for %s at %s: wg0 deleted %v and back %v after it", rc.server, rc.put.UTC().Format("15:04:05.000"),
			rc.down.Round(time.Millisecond), rc.up.Round(time.Millisecond))
	}
	g.gmu.Unlock()
	if !p.running() {
		t.Fatalf("the exit stopped (%d):\n%s", p.code, p.out.String())
	}
}
