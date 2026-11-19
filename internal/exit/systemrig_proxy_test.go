//go:build drill && systemrig && linux

package exit

// The proxy drill on the system rig (docs/design/menu.md, "Testing"): the
// release build's `molebridge proxy` in the exit's namespace, as uid
// rigProxyUID with no capabilities and the exit's applier directory
// read-only, as Compose runs it (network_mode: service:exit), against fake
// Mullvad relay proxies.
//
//	exit ──WireGuard──▶ relayA | relayB ──SNAT──▶ "mullvad" ──▶ 10.124.0.x:1080 (one fake relay proxy per catalogue relay)
//	                     10.64.0.1:53 (fake DNS)                    │ dials from its own egress address
//	                                                                ▼
//	                                                  "internet": the echo on rigProxyPort
//
// The relay proxies' addresses are in a namespace of their own, reachable
// only from the relays (as Mullvad's are only inside its network), so a
// connection to one has gone through the tunnel. Each relay answers DNS on
// 10.64.0.1:53 with the relay proxies' 10.124.0.0/16 addresses. Each fake
// relay proxy resolves only echo.example.net, dials the echo from an address
// of its own and records which relay's tunnel the connection came by; the
// echo names the relay proxy by that address, so a client learns which
// server its traffic left by. An nftables counter in the exit's namespace
// counts every packet of the proxy's uid on any interface but the tunnel
// (its answers to clients on loopback aside), and must stay at zero.

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/nstest"
)

const (
	rigProxyUID      = 65532
	rigProxyListen   = "127.0.0.1:1080"
	rigProxyPassword = "rig-proxy-password"
	// rigProxyPort is the echo's port that only the relay proxies dial.
	rigProxyPort = "8444"
	rigEchoName  = "echo.example.net"
	rigMullvadNS = "10.64.0.1"
)

// rigRelayProxy is one fake Mullvad relay proxy.
type rigRelayProxy struct {
	relay  string // the catalogue's relay, such as "yy-one-wg-004"
	name   string // its proxy's name, "yy-one-wg-socks5-004.relays.mullvad.net"
	addr   string // in 10.124.0.0/16
	egress string // the address it dials the echo from

	mu       sync.Mutex
	broken   bool
	attempts int            // CONNECT requests received
	served   int            // connections opened
	via      map[string]int // the relay whose tunnel brought each request
	targets  map[string]int // the hosts asked for, as received
}

func (p *rigRelayProxy) setBroken(b bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.broken = b
}

func (p *rigRelayProxy) counts() (attempts, served int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.attempts, p.served
}

type proxyRig struct {
	*systemRig
	mullvad *nstest.NS // the relay proxies' network
	proxies []*rigRelayProxy
	byRelay map[string]*rigRelayProxy
	// byEgress names the relay proxy an echo request came from.
	byEgress map[string]*rigRelayProxy
	// bySNAT names the relay whose tunnel a relay proxy's connection came by.
	bySNAT map[string]string

	out  *syncBuf
	cmd  *exec.Cmd
	done chan struct{}
}

// The catalogue the proxy drill uses: the rig's two WireGuard relays (city
// zz-tst) and three more without WireGuard, in another city of country zz
// and in a second country.
var rigProxyExtra = []struct{ host, location, city, country, endpoint string }{
	{"zz-alt-wg-003", "zz-alt", "Other City", rigCountry, "198.51.100.203"},
	{"yy-one-wg-004", "yy-one", "Far City", "Elsewhere", "198.51.100.204"},
	{"yy-one-wg-005", "yy-one", "Far City", "Elsewhere", "198.51.100.205"},
}

// newProxyRig builds the system rig with the relay proxies' network, the
// fake DNS on each relay, the fake relay proxies, the echo and the uid
// counters. Nothing runs yet.
func newProxyRig(t *testing.T) *proxyRig {
	t.Helper()
	sr := newSystemRig(t)
	r := &proxyRig{systemRig: sr, byRelay: map[string]*rigRelayProxy{}, byEgress: map[string]*rigRelayProxy{}, bySNAT: map[string]string{}}
	sr.mu.Lock()
	for _, x := range rigProxyExtra {
		sr.catalogExtra = append(sr.catalogExtra, rigCatalogRelay{host: x.host, location: x.location, city: x.city,
			country: x.country, endpoint: x.endpoint, key: rigKey(t)})
	}
	sr.mu.Unlock()

	hosts := []string{sr.relays[0].host, sr.relays[1].host}
	for _, x := range rigProxyExtra {
		hosts = append(hosts, x.host)
	}
	for i, h := range hosts {
		name, ok := mullvadSocksName(h)
		if !ok {
			t.Fatalf("no relay proxy name for %s", h)
		}
		p := &rigRelayProxy{relay: h, name: name, addr: fmt.Sprintf("10.124.0.%d", 10+i),
			egress: fmt.Sprintf("203.0.113.%d", 41+i), via: map[string]int{}, targets: map[string]int{}}
		r.proxies = append(r.proxies, p)
		r.byRelay[h] = p
		r.byEgress[p.egress] = p
	}

	// The relay proxies' network: reached from each relay over a link of its
	// own, with the relay's address on it as the source.
	mv := nstest.New(t, "mullvad")
	r.mullvad = mv
	rigSysctls(mv)
	for i, rl := range sr.relays {
		relayEnd, mvEnd := fmt.Sprintf("198.51.100.%d", 33+4*i), fmt.Sprintf("198.51.100.%d", 34+4*i)
		rl.ns.Veth("mv0", mv, fmt.Sprintf("relay%d", i))
		addrUp(rl.ns, "mv0", relayEnd+"/30")
		addrUp(mv, fmt.Sprintf("relay%d", i), mvEnd+"/30")
		rl.ns.IP("route", "add", "10.124.0.0/16", "via", mvEnd)
		r.bySNAT[relayEnd] = rl.host
		nat := "table ip proxyrig {\n  chain post {\n    type nat hook postrouting priority srcnat; policy accept;\n" +
			"    oifname \"mv0\" snat to " + relayEnd + "\n  }\n}\n"
		if out, err := rl.ns.ExecInput(nat, "nft", "-f", "-"); err != nil {
			t.Fatalf("nft in %s: %v\n%s", rl.host, err, out)
		}
		// Mullvad's resolver inside the tunnel.
		addrUp(rl.ns, "lo", rigMullvadNS+"/32")
		r.serveDNS(rl)
	}
	for _, p := range r.proxies {
		addrUp(mv, "lo", p.addr+"/32")
		addrUp(sr.internet, "lo", p.egress+"/32")
		r.serveRelayProxy(p)
	}
	sr.serve(net.JoinHostPort(rigCheck4, rigProxyPort), http.HandlerFunc(r.echo))

	// Every packet of the proxy's uid that leaves by anything but the
	// tunnel, its answers on its own listener over loopback aside; and the
	// ones by the tunnel, which show the counter matches the uid at all.
	_, listenPort, _ := net.SplitHostPort(rigProxyListen)
	counters := fmt.Sprintf(`table inet proxyrig {
  counter leak {}
  counter tunnel {}
  chain out {
    type filter hook output priority raw; policy accept;
    meta skuid %d oifname %q counter name tunnel
    meta skuid %d oifname "lo" tcp sport %s accept
    meta skuid %d counter name leak
  }
}
`, rigProxyUID, dExit, rigProxyUID, listenPort, rigProxyUID)
	if out, err := sr.exit.ExecInput(counters, "nft", "-f", "-"); err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if t.Failed() {
			if r.out != nil {
				t.Logf("proxy output:\n%s", r.out.String())
			}
			raw, _ := os.ReadFile(r.statusPath())
			t.Logf("proxy.json: %s", raw)
			t.Logf("relay proxies: %s", r.summary())
		}
	})
	return r
}

// mullvadSocksName is Mullvad's relay proxy name for a WireGuard relay, as
// the design states it: <cc>-<city>-wg-<n> has <cc>-<city>-wg-socks5-<n>.
func mullvadSocksName(relay string) (string, bool) {
	i := strings.LastIndex(relay, "-wg-")
	if i < 0 {
		return "", false
	}
	return relay[:i] + "-wg-socks5-" + relay[i+len("-wg-"):] + ".relays.mullvad.net", true
}

// summary is what each relay proxy saw, for a log line.
func (r *proxyRig) summary() string {
	var parts []string
	for _, p := range r.proxies {
		p.mu.Lock()
		parts = append(parts, fmt.Sprintf("%s: %d asked, %d served, via %v, targets %v, broken %v", p.relay, p.attempts, p.served, p.via, p.targets, p.broken))
		p.mu.Unlock()
	}
	return strings.Join(parts, "; ")
}

// serveDNS answers DNS on 10.64.0.1:53 in rl's namespace: A records for the
// relay proxies' names, no record of another type for them, and NXDOMAIN
// for anything else.
func (r *proxyRig) serveDNS(rl *rigRelay) {
	t := r.t
	var pc net.PacketConn
	if err := rl.ns.Do(func() error {
		var err error
		pc, err = net.ListenPacket("udp4", net.JoinHostPort(rigMullvadNS, "53"))
		return err
	}); err != nil {
		t.Fatalf("DNS on %s: %v", rl.host, err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	addrs := map[string]string{}
	for _, p := range r.proxies {
		addrs[p.name] = p.addr
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if answer := dnsAnswer(buf[:n], addrs); answer != nil {
				r.logServed("dns via %s", rl.host)
				_, _ = pc.WriteTo(answer, from)
			}
		}
	}()
}

// dnsAnswer is the answer to one query, or nil for something that is not a
// single plain query.
func dnsAnswer(q []byte, addrs map[string]string) []byte {
	if len(q) < 12 || q[2]&0x80 != 0 || binary.BigEndian.Uint16(q[4:]) != 1 {
		return nil
	}
	var labels []string
	off := 12
	for {
		if off >= len(q) {
			return nil
		}
		n := int(q[off])
		if n == 0 {
			off++
			break
		}
		if n > 63 || off+1+n > len(q) {
			return nil
		}
		labels = append(labels, strings.ToLower(string(q[off+1:off+1+n])))
		off += 1 + n
	}
	if off+4 > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[off:])
	question := q[12 : off+4]
	addr, known := addrs[strings.Join(labels, ".")]
	msg := make([]byte, 12, 64)
	copy(msg, q[:2])
	flags := uint16(0x8180) // a response, recursion desired and available
	if !known {
		flags |= 3 // NXDOMAIN
	}
	binary.BigEndian.PutUint16(msg[2:], flags)
	binary.BigEndian.PutUint16(msg[4:], 1)
	msg = append(msg, question...)
	if known && qtype == 1 {
		binary.BigEndian.PutUint16(msg[6:], 1)
		msg = append(msg, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
		msg = append(msg, net.ParseIP(addr).To4()...)
	}
	return msg
}

// serveRelayProxy runs p: a SOCKS5 server without authentication on
// p.addr:1080 in the relay proxies' network, answering CONNECT for
// echo.example.net (or an address) by dialing it from p.egress in
// "internet". While p is broken it answers "general failure".
func (r *proxyRig) serveRelayProxy(p *rigRelayProxy) {
	t := r.t
	var ln net.Listener
	if err := r.mullvad.Do(func() error {
		var err error
		ln, err = net.Listen("tcp4", net.JoinHostPort(p.addr, "1080"))
		return err
	}); err != nil {
		t.Fatalf("relay proxy %s: %v", p.relay, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go r.relayProxyConn(p, c)
		}
	}()
}

func (r *proxyRig) relayProxyConn(p *rigRelayProxy, c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil || !slices.Contains(methods, 0) {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil || req[0] != 5 || req[1] != 1 {
		return
	}
	var host string
	switch req[3] {
	case 1:
		a := make([]byte, 4)
		if _, err := io.ReadFull(c, a); err != nil {
			return
		}
		host = net.IP(a).String()
	case 3:
		n := make([]byte, 1)
		if _, err := io.ReadFull(c, n); err != nil {
			return
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return
		}
		host = string(name)
	default:
		_, _ = c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(c, port); err != nil {
		return
	}
	src, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	p.mu.Lock()
	p.attempts++
	p.via[r.bySNAT[src]]++
	if len(p.targets) < 50 {
		p.targets[host]++
	}
	broken := p.broken
	p.mu.Unlock()
	r.logServed("relay proxy %s: CONNECT %s via %s (broken %v)", p.relay, host, r.bySNAT[src], broken)
	if broken {
		_, _ = c.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	target := host
	if host == rigEchoName {
		target = rigCheck4
	} else if net.ParseIP(host) == nil {
		_, _ = c.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var up net.Conn
	d := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(p.egress)}}
	if err := r.internet.Do(func() error {
		var err error
		up, err = d.Dial("tcp4", net.JoinHostPort(target, fmt.Sprint(binary.BigEndian.Uint16(port))))
		return err
	}); err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	if _, err := c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	p.mu.Lock()
	p.served++
	p.mu.Unlock()
	_ = c.SetDeadline(time.Time{})
	go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
	_, _ = io.Copy(c, up)
}

// echo answers as am.i.mullvad.net would, for the relay proxies: the
// caller's address and the relay whose proxy it is.
func (r *proxyRig) echo(w http.ResponseWriter, req *http.Request) {
	host, _, _ := net.SplitHostPort(req.RemoteAddr)
	p := r.byEgress[host]
	answer := map[string]any{"ip": host, "mullvad_exit_ip": p != nil}
	if p != nil {
		answer["mullvad_exit_ip_hostname"] = p.relay
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(answer)
}

// tunnelServer is the exit's server as proxy.json states it.
func tunnelServer(status map[string]any) any {
	tunnel, _ := status["tunnel"].(map[string]any)
	return tunnel["server"]
}

func (r *proxyRig) statusPath() string { return filepath.Join(r.stateDir, "proxy", "proxy.json") }

// proxyStatus is proxy.json, or nil.
func (r *proxyRig) proxyStatus() map[string]any {
	raw, err := os.ReadFile(r.statusPath())
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// benched is the servers proxy.json lists as benched, with their until.
func (r *proxyRig) benched() map[string]string {
	out := map[string]string{}
	servers, _ := r.proxyStatus()["servers"].(map[string]any)
	list, _ := servers["benched"].([]any)
	for _, b := range list {
		if m, ok := b.(map[string]any); ok {
			s, _ := m["server"].(string)
			u, _ := m["until"].(string)
			out[s] = u
		}
	}
	return out
}

// startProxy runs `molebridge proxy` in the exit's namespace as Compose
// runs it: uid rigProxyUID, no capabilities, no new privileges, the exit's
// applier directory bind-mounted read-only over itself, its own state
// directory and password file owned by that uid. It waits for proxy.json to
// say it serves.
func (r *proxyRig) startProxy() {
	t := r.t
	own := filepath.Join(r.stateDir, "proxy")
	secrets := r.path("secrets")
	pw := filepath.Join(secrets, "password")
	for _, d := range []string{own, secrets} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(pw, []byte(rigProxyPassword+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{own, pw} {
		if err := os.Chown(p, rigProxyUID, rigProxyUID); err != nil {
			t.Fatal(err)
		}
	}
	script := `mount --bind "$1" "$1" && mount -o remount,bind,ro "$1" &&
exec setpriv --reuid=` + fmt.Sprint(rigProxyUID) + ` --regid=` + fmt.Sprint(rigProxyUID) +
		` --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs "$2" proxy`
	cmd := exec.Command("ip", "netns", "exec", r.exit.Name, "sh", "-c", script, "sh", filepath.Join(r.stateDir, "applier"), r.bin)
	// The proxy service's environment in compose.proxy.yaml, PROXY_DNS empty
	// (Mullvad's own resolver, 10.64.0.1:53).
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "TZ=UTC", "STATE_DIR=" + r.stateDir, "PROVIDER=mullvad",
		"TUNNEL_INTERFACE=" + dExit, "PROXY_LISTEN=" + rigProxyListen, "OVERLAY_IF=" + dOverlay, "PROXY_MAX_CONNS=512",
		"PROXY_PASSWORD_FILE=" + pw, "PROXY_DNS="}
	r.out = &syncBuf{}
	cmd.Stdout, cmd.Stderr = r.out, r.out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r.cmd, r.done = cmd, make(chan struct{})
	go func() { _ = cmd.Wait(); close(r.done) }()
	t.Cleanup(func() {
		select {
		case <-r.done:
		default:
			_ = cmd.Process.Kill()
			<-r.done
		}
	})
	r.waitFor(30*time.Second, "proxy.json to say the proxy serves", func() bool {
		r.proxyRunning()
		return r.proxyStatus()["status"] == "ok"
	})
}

// proxyRunning fails the test when the proxy has stopped.
func (r *proxyRig) proxyRunning() {
	select {
	case <-r.done:
		r.t.Fatalf("the proxy stopped:\n%s", r.out.String())
	default:
	}
}

// proxyConn is a client's connection through the proxy to the echo, kept
// open for more requests.
type proxyConn struct {
	tls *tls.Conn
	br  *bufio.Reader
}

func (c *proxyConn) Close() { _ = c.tls.Close() }

// ask sends one request to the echo and returns the relay it names.
func (c *proxyConn) ask(d time.Duration) (string, error) {
	_ = c.tls.SetDeadline(time.Now().Add(d))
	if _, err := io.WriteString(c.tls, "GET /json HTTP/1.1\r\nHost: "+rigEchoName+"\r\n\r\n"); err != nil {
		return "", err
	}
	resp, err := http.ReadResponse(c.br, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var answer struct {
		Exit bool   `json:"mullvad_exit_ip"`
		Host string `json:"mullvad_exit_ip_hostname"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&answer); err != nil {
		return "", err
	}
	if !answer.Exit {
		return "", errors.New("the echo saw no relay proxy")
	}
	return answer.Host, nil
}

// refusal is the proxy's answer when it did not open the connection: the
// SOCKS reply code or the HTTP status, and whether authentication failed.
type refusal struct {
	socks    byte
	http     int
	authFail bool
}

func (e *refusal) Error() string {
	if e.authFail {
		return "authentication refused"
	}
	if e.http != 0 {
		return fmt.Sprintf("HTTP %d", e.http)
	}
	return fmt.Sprintf("SOCKS reply %d", e.socks)
}

// dialProxy connects to the proxy's listener from the exit's namespace, as
// a program sharing it would.
func (r *proxyRig) dialProxy() (net.Conn, error) {
	var c net.Conn
	err := r.exit.Do(func() error {
		var err error
		c, err = net.DialTimeout("tcp4", rigProxyListen, 5*time.Second)
		return err
	})
	return c, err
}

// open opens a connection to the echo through the proxy, by SOCKS5 or HTTP
// CONNECT, with user and password, and finishes TLS with it. A refusal is
// a *refusal.
func (r *proxyRig) open(viaHTTP bool, user, password string) (*proxyConn, error) {
	c, err := r.dialProxy()
	if err != nil {
		return nil, err
	}
	_ = c.SetDeadline(time.Now().Add(45 * time.Second))
	target := net.JoinHostPort(rigEchoName, rigProxyPort)
	br := bufio.NewReader(c)
	if viaHTTP {
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, auth)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			c.Close()
			return nil, err
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			c.Close()
			return nil, &refusal{http: resp.StatusCode, authFail: resp.StatusCode == http.StatusProxyAuthRequired}
		}
	} else {
		msg := []byte{5, 1, 2}
		msg = append(msg, 1, byte(len(user)))
		msg = append(msg, user...)
		msg = append(msg, byte(len(password)))
		msg = append(msg, password...)
		req := append([]byte{5, 1, 0, 3, byte(len(rigEchoName))}, rigEchoName...)
		var port uint16
		fmt.Sscan(rigProxyPort, &port)
		req = binary.BigEndian.AppendUint16(req, port)
		if _, err := c.Write(msg); err != nil {
			c.Close()
			return nil, err
		}
		var choice, status [2]byte
		if _, err := io.ReadFull(br, choice[:]); err != nil || choice != [2]byte{5, 2} {
			c.Close()
			return nil, fmt.Errorf("SOCKS greeting: %v %v", choice, err)
		}
		if _, err := io.ReadFull(br, status[:]); err != nil {
			c.Close()
			return nil, err
		}
		if status[1] != 0 {
			c.Close()
			return nil, &refusal{authFail: true}
		}
		if _, err := c.Write(req); err != nil {
			c.Close()
			return nil, err
		}
		reply := make([]byte, 10)
		if _, err := io.ReadFull(br, reply[:2]); err != nil {
			c.Close()
			return nil, err
		}
		if reply[1] != 0 {
			c.Close()
			return nil, &refusal{socks: reply[1]}
		}
		if _, err := io.ReadFull(br, reply[2:]); err != nil || reply[3] != 1 {
			c.Close()
			return nil, fmt.Errorf("SOCKS reply: %v %v", reply, err)
		}
	}
	_ = c.SetDeadline(time.Time{})
	tc := tls.Client(&bufConn{Conn: c, r: br}, &tls.Config{RootCAs: r.roots, ServerName: rigEchoName, MinVersion: tls.VersionTLS12})
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		c.Close()
		return nil, fmt.Errorf("TLS through the proxy: %w", err)
	}
	return &proxyConn{tls: tc, br: bufio.NewReader(tc)}, nil
}

// bufConn reads what a bufio.Reader holds before the connection.
type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// via opens a connection as user, asks the echo once and closes it: the
// relay its traffic left by.
func (r *proxyRig) via(viaHTTP bool, user string) (string, error) {
	c, err := r.open(viaHTTP, user, rigProxyPassword)
	if err != nil {
		return "", err
	}
	defer c.Close()
	return c.ask(10 * time.Second)
}

// mustVia is via that fails the test on an error.
func (r *proxyRig) mustVia(viaHTTP bool, user string) string {
	r.t.Helper()
	got, err := r.via(viaHTTP, user)
	if err != nil {
		r.t.Fatalf("%s as %q: %v", protocol(viaHTTP), user, err)
	}
	return got
}

func protocol(viaHTTP bool) string {
	if viaHTTP {
		return "HTTP CONNECT"
	}
	return "SOCKS5"
}

// attempts is every CONNECT the relay proxies have received.
func (r *proxyRig) attempts() int {
	n := 0
	for _, p := range r.proxies {
		a, _ := p.counts()
		n += a
	}
	return n
}

// cameVia requires every relay proxy connection so far to have come through
// the tunnel to one of relays.
func (r *proxyRig) cameVia(relays ...string) {
	r.t.Helper()
	for _, p := range r.proxies {
		p.mu.Lock()
		for via, n := range p.via {
			if !slices.Contains(relays, via) {
				r.t.Errorf("%d connections to %s's proxy came by %q, want %v", n, p.relay, via, relays)
			}
		}
		p.mu.Unlock()
	}
}

// uidCounted reads one of the exit namespace's uid counters.
func (r *proxyRig) uidCounted(name string) int {
	r.t.Helper()
	out, err := r.exit.Exec("nft", "list", "counter", "inet", "proxyrig", name)
	if err != nil {
		r.t.Fatalf("nft: %v\n%s", err, out)
	}
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "packets" && i+1 < len(fields) {
			var n int
			fmt.Sscan(fields[i+1], &n)
			return n
		}
	}
	return 0
}

// noLeak requires no packet of the proxy's uid by anything but the tunnel,
// some by the tunnel, and none of the client's by the host path.
func (r *proxyRig) noLeak(when string) {
	r.t.Helper()
	leak, tunnel := r.uidCounted("leak"), r.uidCounted("tunnel")
	if leak != 0 {
		r.t.Errorf("%s: %d packets of the proxy's uid left by an interface other than %s", when, leak, dExit)
	}
	if tunnel == 0 {
		r.t.Errorf("%s: no packet of the proxy's uid counted by %s: the counter does not see it", when, dExit)
	}
	if n := r.counted("leak"); n != 0 {
		r.t.Errorf("%s: %d client packets by the host path", when, n)
	}
	r.t.Logf("%s: %d packets of the proxy's uid by %s, 0 by any other interface", when, tunnel, dExit)
}

// waitRefused waits until a new connection is refused because of the
// exit's verdict: HTTP 503 and SOCKS reply 1, with no relay proxy asked.
func (r *proxyRig) waitRefused(d time.Duration, what string) {
	r.t.Helper()
	r.waitFor(d, "the proxy to refuse new connections ("+what+")", func() bool {
		r.proxyRunning()
		if r.proxyStatus()["status"] != "refusing" {
			time.Sleep(200 * time.Millisecond)
			return false
		}
		before := r.attempts()
		_, herr := r.via(true, "any")
		_, serr := r.via(false, "any")
		var h, s *refusal
		if !errors.As(herr, &h) || h.http != http.StatusServiceUnavailable || !errors.As(serr, &s) || s.socks != 1 {
			r.t.Logf("%s: refusing, but HTTP %v, SOCKS %v", what, herr, serr)
			time.Sleep(200 * time.Millisecond)
			return false
		}
		if n := r.attempts() - before; n != 0 {
			r.t.Errorf("%s: a refused connection asked %d relay proxies", what, n)
		}
		return true
	})
}

// waitServing waits until the proxy serves again and a connection by
// location leaves by a relay proxy.
func (r *proxyRig) waitServing(d time.Duration, location string) string {
	r.t.Helper()
	var got string
	r.waitFor(d, "the proxy to serve again", func() bool {
		r.proxyRunning()
		if r.proxyStatus()["status"] != "ok" {
			time.Sleep(200 * time.Millisecond)
			return false
		}
		var err error
		if got, err = r.via(false, location); err != nil {
			time.Sleep(time.Second)
			return false
		}
		return true
	})
	return got
}

// TestSystemRigProxy is the proxy's drill on the system rig, each part on a
// rig of its own, in parallel with each other and the other rig drills.
func TestSystemRigProxy(t *testing.T) {
	t.Parallel()
	t.Run("Locations", func(t *testing.T) {
		t.Parallel()
		r := newProxyRig(t)
		a, b := r.relays[0].host, r.relays[1].host
		r.bringUp()
		r.startProxy()
		if s := r.proxyStatus(); tunnelServer(s) != a || s["guarantee"] != "opt-in" {
			t.Errorf("proxy.json after the start: %s", jsonText(s))
		}

		// Every kind of location, both ways in.
		for _, c := range []struct {
			location string
			want     []string
		}{
			{"any", []string{a, b, "zz-alt-wg-003", "yy-one-wg-004", "yy-one-wg-005"}},
			{"zz", []string{a, b, "zz-alt-wg-003"}},
			{"yy", []string{"yy-one-wg-004", "yy-one-wg-005"}},
			{"zz-tst", []string{a, b}},
			{"zz-alt", []string{"zz-alt-wg-003"}},
			{"yy-one-wg-005", []string{"yy-one-wg-005"}},
			{b, []string{b}},
		} {
			for _, viaHTTP := range []bool{false, true} {
				seen := map[string]int{}
				for i := 0; i < 4; i++ {
					got := r.mustVia(viaHTTP, c.location)
					if !slices.Contains(c.want, got) {
						t.Errorf("%s as %q left by %s, want one of %v", protocol(viaHTTP), c.location, got, c.want)
					}
					seen[got]++
				}
				t.Logf("%s as %q: %v", protocol(viaHTTP), c.location, seen)
			}
		}
		// The target's name went to the relay proxies, never an address
		// resolved here.
		for _, p := range r.proxies {
			p.mu.Lock()
			for host := range p.targets {
				if host != rigEchoName {
					t.Errorf("%s's proxy was asked for %q, want the name %s", p.relay, host, rigEchoName)
				}
			}
			p.mu.Unlock()
		}
		r.cameVia(a)

		// A wrong password, both ways in: refused before any relay proxy is
		// asked.
		before := r.attempts()
		for _, viaHTTP := range []bool{false, true} {
			var ref *refusal
			if _, err := r.open(viaHTTP, "any", "wrong-password"); !errors.As(err, &ref) || !ref.authFail {
				t.Errorf("%s with a wrong password: %v, want an authentication refusal", protocol(viaHTTP), err)
			}
		}
		if _, err := r.open(false, "", rigProxyPassword); err == nil {
			t.Errorf("SOCKS5 with an empty username was served")
		}
		if n := r.attempts() - before; n != 0 {
			t.Errorf("refused clients reached %d relay proxies", n)
		}

		// A session keeps its server across connections.
		x := r.mustVia(false, "yy-one.s1")
		for i := 0; i < 5; i++ {
			if got := r.mustVia(i%2 == 1, "yy-one.s1"); got != x {
				t.Fatalf("session s1 moved from %s to %s while %s worked", x, got, x)
			}
		}
		y := "yy-one-wg-004"
		if x == y {
			y = "yy-one-wg-005"
		}
		// x's proxy fails: the session moves to y and stays there, and x is
		// benched.
		r.byRelay[x].setBroken(true)
		broken := time.Now()
		if got := r.mustVia(false, "yy-one.s1"); got != y {
			t.Fatalf("session s1 after %s failed: %s, want %s", x, got, y)
		}
		for i := 0; i < 3; i++ {
			if got := r.mustVia(true, "yy-one.s1"); got != y {
				t.Fatalf("session s1 moved again, to %s", got)
			}
		}
		r.waitFor(15*time.Second, "proxy.json to list "+x+" benched", func() bool { return r.benched()[x] != "" })
		until, err := time.Parse(time.RFC3339, r.benched()[x])
		if err != nil {
			t.Fatalf("benched until %q: %v", r.benched()[x], err)
		}
		// While benched, x is skipped: its city goes to y, and x by name is
		// refused without x's proxy being asked.
		xAsked, _ := r.byRelay[x].counts()
		for i := 0; i < 4; i++ {
			if got := r.mustVia(i%2 == 1, "yy-one"); got != y {
				t.Errorf("yy-one while %s is benched left by %s", x, got)
			}
		}
		if _, err := r.via(false, x); err == nil {
			t.Errorf("%s by name was served while benched", x)
		}
		if n, _ := r.byRelay[x].counts(); n != xAsked {
			t.Errorf("%s's proxy was asked %d times while benched", x, n-xAsked)
		}
		t.Logf("%s benched until %s (%v after its failure); session s1 moved to %s", x, until.Format(time.RFC3339), until.Sub(broken).Round(time.Second), y)

		// x works again; once its bench ends it is chosen and cleared.
		r.byRelay[x].setBroken(false)
		time.Sleep(time.Until(until) + time.Second)
		r.waitFor(30*time.Second, x+" to be served again by name", func() bool {
			got, err := r.via(false, x)
			if err != nil {
				time.Sleep(time.Second)
				return false
			}
			if got != x {
				t.Fatalf("%s by name left by %s", x, got)
			}
			return true
		})
		recovered := time.Since(broken)
		r.waitFor(15*time.Second, "proxy.json to clear "+x+"'s bench", func() bool { return r.benched()[x] == "" })
		if got := r.mustVia(false, "yy-one.s1"); got != y {
			t.Errorf("session s1 after %s recovered: %s, want %s still", x, got, y)
		}
		t.Logf("%s served again %v after its failure", x, recovered.Round(time.Second))
		r.cameVia(a)
		if s := r.proxyStatus(); s["sessions"] == nil || s["status"] != "ok" {
			t.Errorf("proxy.json at the end: %s", jsonText(s))
		}
		t.Logf("relay proxies: %s", r.summary())
		r.noLeak("locations, sessions and benching")
	})

	t.Run("ExitSwitch", func(t *testing.T) {
		t.Parallel()
		r := newProxyRig(t)
		a, b := r.relays[0], r.relays[1]
		p := r.bringUp()
		r.startProxy()
		r.mustVia(false, "any")
		r.cameVia(a.host)
		open, err := r.open(true, "yy", rigProxyPassword)
		if err != nil {
			t.Fatal(err)
		}
		defer open.Close()
		if _, err := open.ask(10 * time.Second); err != nil {
			t.Fatalf("the open connection: %v", err)
		}

		// The switch to B, held applying: new connections are refused.
		release := r.holdChecks()
		defer release()
		id, at := r.panelSwitch(b.host)
		r.waitFor(30*time.Second, "result.json applying for "+b.host, func() bool {
			res := r.result()
			return res["status"] == "applying" && res["request_id"] == id
		})
		r.waitRefused(30*time.Second, "the exit applying a switch")
		refusedAfter := time.Since(at)
		release()
		r.waitVerified(p, b, id, 120*time.Second)
		verified := time.Since(at)
		got := r.waitServing(30*time.Second, "zz-tst")
		servingAfter := time.Since(at)
		_, oerr := open.ask(5 * time.Second)
		// Every relay proxy connection since the switch came by B.
		for _, rp := range r.proxies {
			rp.mu.Lock()
			rp.via = map[string]int{}
			rp.mu.Unlock()
		}
		for i := 0; i < 4; i++ {
			r.mustVia(i%2 == 1, "any")
		}
		r.cameVia(b.host)
		if s := r.proxyStatus(); tunnelServer(s) != b.host {
			t.Errorf("proxy.json after the switch: %s", jsonText(s["tunnel"]))
		}
		t.Logf("exit switch %s -> %s: refused %v after the panel's answer, verified %v, the proxy serving again (by %s) %v; the connection open across it: %v",
			a.host, b.host, refusedAfter.Round(time.Millisecond), verified.Round(time.Millisecond), got, servingAfter.Round(time.Millisecond), oerr)
		r.noLeak("the exit switch")
	})

	t.Run("TunnelLoss", func(t *testing.T) {
		t.Parallel()
		r := newProxyRig(t)
		a := r.relays[0]
		r.bringUp()
		r.startProxy()
		r.mustVia(false, "zz")
		open, err := r.open(false, "zz-tst", rigProxyPassword)
		if err != nil {
			t.Fatal(err)
		}
		defer open.Close()
		if _, err := open.ask(10 * time.Second); err != nil {
			t.Fatalf("the open connection: %v", err)
		}

		// The tunnel stops: relay A drops its WireGuard traffic. The
		// client's probes give the exit traffic to notice the silence by.
		drop := "table inet drill {\n  chain in {\n    type filter hook input priority 0; policy accept;\n    udp dport 51820 drop\n  }\n}\n"
		if out, err := a.ns.ExecInput(drop, "nft", "-f", "-"); err != nil {
			t.Fatalf("nft: %v\n%s", err, out)
		}
		lost := time.Now()
		stop := make(chan struct{})
		samples := r.probeLoop(stop)
		defer func() {
			select {
			case <-stop:
			default:
				close(stop)
				<-samples
			}
		}()
		// The open connection and a new one fail: nothing goes another way.
		if got, err := open.ask(5 * time.Second); err == nil {
			t.Errorf("the open connection answered by %s after the tunnel stopped", got)
		}
		if got, err := r.via(false, "zz-alt-wg-003"); err == nil {
			t.Errorf("a new connection was served by %s after the tunnel stopped", got)
		} else {
			t.Logf("a new connection while the tunnel is silent: %v", err)
		}
		// The exit's verdict leaves ok: new connections are refused.
		r.waitRefused(150*time.Second, "the tunnel stopped")
		refusedAfter := time.Since(lost)
		res := r.result()
		t.Logf("the tunnel stopped: refused %v after, the exit's record %s; proxy.json tunnel %s",
			refusedAfter.Round(time.Millisecond), fmtStatus(res), jsonText(r.proxyStatus()["tunnel"]))

		// The tunnel comes back: the exit is ok again, and so is the proxy.
		if out, err := a.ns.Exec("nft", "delete", "table", "inet", "drill"); err != nil {
			t.Fatalf("nft: %v\n%s", err, out)
		}
		back := time.Now()
		var current string
		r.waitFor(150*time.Second, "result.json ok again", func() bool {
			res := r.result()
			current, _ = res["server"].(string)
			return res["status"] == "ok" && (r.verified(a, "") || r.verified(r.relays[1], ""))
		})
		got := r.waitServing(60*time.Second, "zz-tst")
		close(stop)
		all := <-samples
		for _, s := range all {
			if s.via != "" && s.via != a.host && s.via != r.relays[1].host {
				t.Errorf("a client probe at %s left by %s", s.at.Format(time.RFC3339Nano), s.via)
			}
		}
		t.Logf("the tunnel back: the exit ok on %s and the proxy serving (by %s) %v after", current, got, time.Since(back).Round(time.Millisecond))
		r.cameVia(a.host, r.relays[1].host)
		r.noLeak("tunnel loss")
	})
}
