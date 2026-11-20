package main

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

// proxyEnv is a complete, valid set of the proxy's settings.
func proxyEnv() map[string]string {
	return map[string]string{
		"PROVIDER":            "mullvad",
		"TUNNEL_INTERFACE":    "mullvad",
		"PROXY_PASSWORD_FILE": "/run/secrets/proxy/password",
	}
}

func TestProxySettingsDefaults(t *testing.T) {
	s, err := proxySettingsFrom(proxyEnv())
	if err != nil {
		t.Fatal(err)
	}
	want := proxySettings{StateDir: "/state", Provider: "mullvad", TunnelInterface: "mullvad",
		Listen: "127.0.0.1:1080", MaxConns: 512, PasswordFile: "/run/secrets/proxy/password",
		OverlayIf: "wt0", DNS: "10.64.0.1:53"}
	if s != want {
		t.Fatalf("got %+v\nwant %+v", s, want)
	}
	for provider, dns := range map[string]string{"pia": "10.0.0.243:53", "nordvpn": "103.86.96.100:53"} {
		env := proxyEnv()
		env["PROVIDER"] = provider
		s, err := proxySettingsFrom(env)
		if err != nil || s.DNS != dns {
			t.Fatalf("%s: %+v %v", provider, s, err)
		}
	}
	// Empty is unset, as Compose's ${NAME:-} passes it.
	env := proxyEnv()
	for _, k := range []string{"STATE_DIR", "PROXY_LISTEN", "PROXY_MAX_CONNS", "OVERLAY_IF", "PROXY_DNS"} {
		env[k] = ""
	}
	if s, err := proxySettingsFrom(env); err != nil || s != want {
		t.Fatalf("empty values: %+v %v", s, err)
	}
}

func TestProxySettingsSet(t *testing.T) {
	env := proxyEnv()
	env["STATE_DIR"] = "/srv/state"
	env["PROVIDER"] = "pia"
	env["TUNNEL_INTERFACE"] = "pia0"
	env["PROXY_LISTEN"] = "192.0.2.10:1081"
	env["PROXY_MAX_CONNS"] = "64"
	env["OVERLAY_IF"] = "mesh0"
	env["PROXY_DNS"] = "192.0.2.53"
	s, err := proxySettingsFrom(env)
	if err != nil {
		t.Fatal(err)
	}
	want := proxySettings{StateDir: "/srv/state", Provider: "pia", TunnelInterface: "pia0",
		Listen: "192.0.2.10:1081", MaxConns: 64, PasswordFile: "/run/secrets/proxy/password",
		OverlayIf: "mesh0", DNS: "192.0.2.53:53"}
	if s != want {
		t.Fatalf("got %+v\nwant %+v", s, want)
	}
	for in, out := range map[string]string{
		"192.0.2.53:5353":        "192.0.2.53:5353",
		"[2001:db8::53]:53":      "[2001:db8::53]:53",
		"2001:db8::53":           "[2001:db8::53]:53",
		"::ffff:192.0.2.53":      "192.0.2.53:53",
		"[::ffff:192.0.2.53]:53": "192.0.2.53:53",
	} {
		env["PROXY_DNS"] = in
		if s, err := proxySettingsFrom(env); err != nil || s.DNS != out {
			t.Fatalf("PROXY_DNS %q: %q %v", in, s.DNS, err)
		}
	}
}

func TestProxySettingsRefusals(t *testing.T) {
	cases := []struct {
		key, value, want string
	}{
		{"PROVIDER", "", "PROVIDER is required"},
		{"PROVIDER", "gluetun-nordvpn", "supports mullvad, pia and nordvpn"},
		{"PROVIDER", "Mullvad", "supports mullvad, pia and nordvpn"},
		{"PROVIDER", "ivpn", "supports mullvad, pia and nordvpn"},
		{"PROVIDERS", "mullvad,pia", "not supported on a multi-provider exit"},
		{"TUNNEL_INTERFACE", "", "TUNNEL_INTERFACE is required"},
		{"TUNNEL_INTERFACE", "a/b", "TUNNEL_INTERFACE is not a valid"},
		{"TUNNEL_INTERFACE", "sixteen-letters0", "TUNNEL_INTERFACE is not a valid"},
		{"TUNNEL_INTERFACE", "wt0", "name the same interface"},
		{"OVERLAY_IF", "wt 0", "OVERLAY_IF is not a valid"},
		{"OVERLAY_IF", "mullvad", "name the same interface"},
		{"STATE_DIR", "state", "STATE_DIR must be a clean absolute path"},
		{"STATE_DIR", "/state/../etc", "STATE_DIR must be a clean absolute path"},
		{"STATE_DIR", "/state/", "STATE_DIR must be a clean absolute path"},
		{"PROXY_MAX_CONNS", "0", "PROXY_MAX_CONNS"},
		{"PROXY_MAX_CONNS", "-1", "PROXY_MAX_CONNS"},
		{"PROXY_MAX_CONNS", "65536", "PROXY_MAX_CONNS"},
		{"PROXY_MAX_CONNS", "12x", "PROXY_MAX_CONNS"},
		{"PROXY_MAX_CONNS", "+5", "PROXY_MAX_CONNS"},
		{"PROXY_MAX_CONNS", "05", "PROXY_MAX_CONNS"},
		{"PROXY_MAX_CONNS", " 5", "PROXY_MAX_CONNS"},
		{"PROXY_PASSWORD_FILE", "", "PROXY_PASSWORD_FILE is required"},
		{"PROXY_PASSWORD_FILE", "secrets/password", "PROXY_PASSWORD_FILE must be an absolute path"},
		{"PROXY_DNS", "dns.example.net", "PROXY_DNS must be an IP address"},
		{"PROXY_DNS", "dns.example.net:53", "PROXY_DNS must be an IP address"},
		{"PROXY_DNS", "192.0.2.53:0", "PROXY_DNS must be an IP address"},
		{"PROXY_DNS", "192.0.2.53:70000", "PROXY_DNS must be an IP address"},
		{"PROXY_DNS", "fe80::1%eth0", "PROXY_DNS must be an IP address"},
		{"PROXY_DNS", "[fe80::1%eth0]:53", "PROXY_DNS must be an IP address"},
		{"PROXY_DNS", "192.0.2.53:53,198.51.100.53:53", "PROXY_DNS must be an IP address"},
	}
	for _, c := range cases {
		env := proxyEnv()
		env[c.key] = c.value
		if _, err := proxySettingsFrom(env); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s=%q: got %v, want %q", c.key, c.value, err, c.want)
		}
	}
}

func TestProxySettingsRefuseEveryBadSettingAtOnce(t *testing.T) {
	env := map[string]string{
		"STATE_DIR":           "state",
		"PROVIDER":            "ivpn",
		"TUNNEL_INTERFACE":    "a/b",
		"OVERLAY_IF":          "wt 0",
		"PROXY_LISTEN":        "localhost:1080",
		"PROXY_MAX_CONNS":     "0",
		"PROXY_PASSWORD_FILE": "secrets/password",
		"PROXY_DNS":           "dns.example.net",
	}
	_, err := proxySettingsFrom(env)
	if err == nil {
		t.Fatal("accepted")
	}
	want := []string{
		"STATE_DIR must be a clean absolute path",
		`PROVIDER "ivpn": the proxy supports mullvad, pia and nordvpn`,
		"TUNNEL_INTERFACE is not a valid interface name",
		"OVERLAY_IF is not a valid interface name",
		"PROXY_LISTEN: the host must be an IP address (for example 127.0.0.1:1080)",
		"PROXY_MAX_CONNS must be a whole number from 1 to 65535",
		"PROXY_PASSWORD_FILE must be an absolute path",
		"PROXY_DNS must be an IP address",
	}
	got := proxyStartRefusals(proxySettings{}, err, nil)
	if len(got) != len(want) {
		t.Fatalf("got %d refusals, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
	for i, w := range want {
		if !strings.HasPrefix(got[i], w) {
			t.Errorf("refusal %d: got %q, want %q", i, got[i], w)
		}
	}
}

func TestProxyStartRefusalsIncludeThePasswordFileAndTheListenAddress(t *testing.T) {
	dir := t.TempDir()
	password := filepath.Join(dir, "password")
	if err := os.WriteFile(password, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := proxyEnv()
	env["PROXY_PASSWORD_FILE"] = password
	env["PROXY_LISTEN"] = "192.0.2.10:1080"
	env["OVERLAY_IF"] = "eth0"
	env["PROXY_MAX_CONNS"] = "x"
	s, err := proxySettingsFrom(env)
	addrs := func(string) ([]net.Addr, error) {
		return []net.Addr{&net.IPNet{IP: net.ParseIP("203.0.113.7").To4(), Mask: net.CIDRMask(32, 32)}}, nil
	}
	got := proxyStartRefusals(s, err, addrs)
	want := []string{"PROXY_MAX_CONNS", "the password file is readable by others",
		`listen address "192.0.2.10:1080" is neither loopback nor an address of eth0`}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i, w := range want {
		if !strings.HasPrefix(got[i], w) {
			t.Errorf("refusal %d: got %q, want %q", i, got[i], w)
		}
	}
	// The pod's own address on a cluster interface is accepted.
	if err := os.Chmod(password, 0o600); err != nil {
		t.Fatal(err)
	}
	delete(env, "PROXY_MAX_CONNS")
	env["PROXY_LISTEN"] = "203.0.113.7:1080"
	s, err = proxySettingsFrom(env)
	if got := proxyStartRefusals(s, err, addrs); len(got) != 0 {
		t.Fatalf("refused: %q", got)
	}
}

func TestProxyIsolation(t *testing.T) {
	ok := identity{UID: 1000, EUID: 1000, CapKnown: true}
	if r := checkProxyIsolation(ok, ""); len(r) != 0 {
		t.Fatalf("a non-root process with no capabilities refused: %v", r)
	}
	root := identity{UID: 0, EUID: 0, CapKnown: true}
	cases := []struct {
		name      string
		id        identity
		allowRoot string
		want      []string
	}{
		{"root", root, "", []string{refuseProxyRoot}},
		{"effective root", identity{UID: 1000, EUID: 0, CapKnown: true}, "", []string{refuseProxyRoot}},
		{"root with PANEL_ALLOW_ROOT=1", root, "1", nil},
		{"effective root with PANEL_ALLOW_ROOT=1", identity{UID: 1000, EUID: 0, CapKnown: true}, "1", nil},
		{"root with PANEL_ALLOW_ROOT=true", root, "true", []string{refuseProxyRoot}},
		{"root with PANEL_ALLOW_ROOT=yes", root, "yes", []string{refuseProxyRoot}},
		{"root with PANEL_ALLOW_ROOT=0", root, "0", []string{refuseProxyRoot}},
		{"root with PANEL_ALLOW_ROOT=' 1'", root, " 1", []string{refuseProxyRoot}},
		{"one capability", identity{UID: 1000, EUID: 1000, CapEff: 1 << 12, CapKnown: true}, "", []string{refuseProxyCaps}},
		{"capabilities unknown", identity{UID: 1000, EUID: 1000}, "", []string{refuseProxyCapUnknown}},
		{"root with every capability", identity{CapEff: 0x1ffffffffff, CapKnown: true}, "", []string{refuseProxyRoot, refuseProxyCaps}},
		{"allowed root still needs no capabilities", identity{CapEff: 0x1ffffffffff, CapKnown: true}, "1", []string{refuseProxyCaps}},
		{"allowed root, capabilities unknown", identity{}, "1", []string{refuseProxyCapUnknown}},
	}
	for _, c := range cases {
		got := checkProxyIsolation(c.id, c.allowRoot)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	// The isolation is checked before the settings are read.
	var stderr bytes.Buffer
	if code := proxyMain(context.Background(), map[string]string{}, identity{CapKnown: true}, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "must not run as root") || strings.Contains(stderr.String(), "PROVIDER") {
		t.Fatalf("%d %q", code, stderr.String())
	}
	// With PANEL_ALLOW_ROOT=1 the root check passes and the settings are read.
	stderr.Reset()
	if code := proxyMain(context.Background(), map[string]string{"PANEL_ALLOW_ROOT": "1", "PROVIDER": "gluetun-ivpn"}, identity{CapKnown: true}, &stderr); code != 1 ||
		strings.Contains(stderr.String(), "must not run as root") || !strings.Contains(stderr.String(), "refusing to start: PROVIDER") {
		t.Fatalf("%d %q", code, stderr.String())
	}
	stderr.Reset()
	if code := proxyMain(context.Background(), map[string]string{"PROVIDER": "gluetun-ivpn"}, ok, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "refusing to start: PROVIDER") {
		t.Fatalf("%d %q", code, stderr.String())
	}
}

// freeLoopback is a loopback address no one listens on.
func freeLoopback(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// The role end to end, in this process and without a tunnel: it listens,
// refuses new connections while the exit has no record, publishes proxy.json
// (which status --proxy and health --proxy read), and stops cleanly when its
// context ends, as on SIGTERM.
func TestProxyRoleServesAndStops(t *testing.T) {
	dir := t.TempDir()
	password := filepath.Join(dir, "password")
	if err := os.WriteFile(password, []byte("correct horse\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "state", "applier"), 0o755); err != nil {
		t.Fatal(err)
	}
	address := freeLoopback(t)
	env := proxyEnv()
	env["STATE_DIR"] = filepath.Join(dir, "state")
	env["TUNNEL_INTERFACE"] = "mb-test0"
	env["PROXY_PASSWORD_FILE"] = password
	env["PROXY_LISTEN"] = address

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stderr syncBuffer
	done := make(chan int, 1)
	go func() { done <- proxyMain(ctx, env, identity{UID: 1000, EUID: 1000, CapKnown: true}, &stderr) }()

	var conn net.Conn
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.Dial("tcp", address)
		if err == nil {
			conn = c
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the proxy never listened: %v\n%s", err, stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	// No result.json: the exit's verdict is unknown, so CONNECT is refused
	// before any upstream is asked.
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := "CONNECT example.net:443 HTTP/1.1\r\nHost: example.net:443\r\n" +
		"Proxy-Authorization: Basic " + "YW55OmNvcnJlY3QgaG9yc2U=" + "\r\n\r\n" // any:correct horse
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("CONNECT with no exit record: %d", resp.StatusCode)
	}

	// proxy.json says it refuses; status and health agree.
	statusPath := proxyStatusPath(env["STATE_DIR"])
	for {
		if v := verdict.AssessProxy(verdict.ReadProxy(statusPath), "mullvad", time.Time{}); v.State == "refusing" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no refusing proxy.json\n%s", stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	var out, errOut bytes.Buffer
	if code := statusMain([]string{"--proxy"}, env, nil, time.Now, &out, &errOut); code != 1 ||
		!strings.Contains(out.String(), "state: refusing (refusing)") || !strings.Contains(out.String(), "exit verdict: unknown") {
		t.Fatalf("status --proxy: %d %q %q", code, out.String(), errOut.String())
	}
	out.Reset()
	if code := healthMain([]string{"--proxy"}, env, &out, &errOut); code != 1 || !strings.HasPrefix(out.String(), "unhealthy: proxy refusing (tunnel-not-ok)") {
		t.Fatalf("health --proxy: %d %q", code, out.String())
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit status %d after a clean stop\n%s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the proxy did not stop")
	}
	if !strings.Contains(stderr.String(), "leaves through mb-test0, or fails") || strings.Contains(stderr.String(), "correct horse") {
		t.Fatalf("log: %q", stderr.String())
	}
	if v := verdict.AssessProxy(verdict.ReadProxy(statusPath), "mullvad", time.Time{}); v.State != "failed" {
		t.Fatalf("after a stop proxy.json says %s", v.State)
	}
}

// A refused start: an unreadable password file stops the role with status 1.
func TestProxyRoleRefusesABadPasswordFile(t *testing.T) {
	dir := t.TempDir()
	password := filepath.Join(dir, "password")
	if err := os.WriteFile(password, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env := proxyEnv()
	env["STATE_DIR"] = dir
	env["PROXY_PASSWORD_FILE"] = password
	env["PROXY_LISTEN"] = freeLoopback(t)
	var stderr bytes.Buffer
	if code := proxyMain(context.Background(), env, identity{UID: 1000, EUID: 1000, CapKnown: true}, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "readable by others") {
		t.Fatalf("%d %q", code, stderr.String())
	}
	env["PROXY_LISTEN"] = "0.0.0.0:1080"
	stderr.Reset()
	os.Chmod(password, 0o600)
	if code := proxyMain(context.Background(), env, identity{UID: 1000, EUID: 1000, CapKnown: true}, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "neither loopback nor an address of wt0") && !strings.Contains(stderr.String(), "addresses of wt0") {
		t.Fatalf("%d %q", code, stderr.String())
	}
}

func writeProxyRecord(t *testing.T, stateDir, status string, at time.Time) {
	t.Helper()
	record := `{"schema": 1, "kind": "proxy", "provider": "mullvad", "guarantee": "opt-in",
  "status": "` + status + `", "message": "Serving.", "checked_at": "` + validate.FormatTime(at) + `",
  "listen": "127.0.0.1:1080",
  "tunnel": {"verdict": "ok", "server": "se-got-wg-001", "checked_at": "` + validate.FormatTime(at) + `"},
  "servers": {"known": 3, "benched": [{"server": "de-fra-wg-003", "until": "` + validate.FormatTime(at.Add(time.Minute)) + `", "reason": "handshake timed out"}]},
  "sessions": 2, "connections": {"open": 7, "total": 9, "failed": 1}}`
	if err := os.MkdirAll(filepath.Join(stateDir, "proxy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proxyStatusPath(stateDir), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestProxyStatusAndHealth(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	env := map[string]string{"STATE_DIR": dir, "PROVIDER": "mullvad"}
	writeProxyRecord(t, dir, "ok", now.Add(-5*time.Second))
	var out, errOut bytes.Buffer
	if code := statusMain([]string{"--proxy"}, env, nil, func() time.Time { return now }, &out, &errOut); code != 0 {
		t.Fatalf("%d %q %q", code, out.String(), errOut.String())
	}
	for _, line := range []string{"guarantee: every connection the proxy opens leaves through the tunnel, or fails",
		"state: ok (serving)", "reasons: none", "message: Serving.", "exit verdict: ok",
		"benched servers: 1", "sessions: 2", "open connections: 7", "version: "} {
		if !strings.Contains(out.String(), line) {
			t.Errorf("status --proxy lacks %q:\n%s", line, out.String())
		}
	}
	if code := healthMain([]string{"--proxy"}, env, &out, &errOut); code != 0 {
		t.Fatalf("health --proxy on a fresh ok record: %d", code)
	}
	// Another provider's record, a stale one, a missing one: unknown, 1.
	out.Reset()
	if code := statusMain([]string{"--proxy"}, map[string]string{"STATE_DIR": dir, "PROVIDER": "pia"}, nil, time.Now, &out, &errOut); code != 1 ||
		!strings.Contains(out.String(), "provider-mismatch") {
		t.Fatalf("%d %q", code, out.String())
	}
	writeProxyRecord(t, dir, "ok", now.Add(-time.Minute))
	out.Reset()
	if code := statusMain([]string{"--proxy"}, env, nil, time.Now, &out, &errOut); code != 1 || !strings.Contains(out.String(), "status-stale") {
		t.Fatalf("%d %q", code, out.String())
	}
	out.Reset()
	if code := healthMain([]string{"--proxy"}, env, &out, &errOut); code != 1 || !strings.Contains(out.String(), "status-stale") {
		t.Fatalf("health --proxy on a stale record: %d %q", code, out.String())
	}
	os.Remove(proxyStatusPath(dir))
	out.Reset()
	if code := statusMain([]string{"--proxy"}, env, nil, time.Now, &out, &errOut); code != 1 || !strings.Contains(out.String(), "no-status") {
		t.Fatalf("%d %q", code, out.String())
	}
	if code := statusMain([]string{"--proxy"}, map[string]string{"PROVIDER": "gluetun-ivpn"}, nil, time.Now, &out, &errOut); code != 1 {
		t.Fatalf("a gluetun provider: %d", code)
	}
	if code := statusMain([]string{"--proxy", "x"}, env, nil, time.Now, &out, &errOut); code != 2 {
		t.Fatalf("usage: %d", code)
	}
	if code := healthMain([]string{"--proxy", "--guarded"}, env, &out, &errOut); code != 2 {
		t.Fatalf("usage: %d", code)
	}
}

// syncBuffer is a bytes.Buffer the proxy's goroutines may log to while the
// test reads it.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
