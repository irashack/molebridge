package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const testPassword = "correct horse"

// fakeUpstream dials an echo server on loopback for every target and records
// what it was asked.
type fakeUpstream struct {
	echo string

	mu      sync.Mutex
	calls   []dialCall
	server  string // the server it uses; "" for pinned, or else "se-got-wg-001"
	err     error
	delay   time.Duration
	servers []ServerState
}

type dialCall struct{ location, pinned, target string }

func (f *fakeUpstream) Dial(ctx context.Context, location, pinned, target string) (net.Conn, string, error) {
	f.mu.Lock()
	f.calls = append(f.calls, dialCall{location, pinned, target})
	server, err, delay := f.server, f.err, f.delay
	f.mu.Unlock()
	time.Sleep(delay)
	if server == "" {
		server = pinned
	}
	if server == "" {
		server = "se-got-wg-001"
	}
	if err != nil {
		return nil, server, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", f.echo)
	return conn, server, err
}

func (f *fakeUpstream) Servers() []ServerState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ServerState(nil), f.servers...)
}

func (f *fakeUpstream) lastCall(t *testing.T) dialCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("the upstream was not asked")
	}
	return f.calls[len(f.calls)-1]
}

func (f *fakeUpstream) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// echoServer echoes until the client's end, then half-closes.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
				c.(*net.TCPConn).CloseWrite()
				io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func writePassword(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeClock is a settable wall clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type rig struct {
	addr     string
	up       *fakeUpstream
	clock    *fakeClock
	tunnel   atomic.Value // string
	srv      *server
	cancel   context.CancelFunc
	done     chan error
	status   string
	lnClosed func()
}

// startRig runs a proxy on an ephemeral loopback port with a fake upstream.
func startRig(t *testing.T, edit func(*Config)) *rig {
	t.Helper()
	r := &rig{up: &fakeUpstream{echo: echoServer(t)}, clock: &fakeClock{t: time.Date(2026, 11, 19, 18, 0, 0, 0, time.UTC)}}
	r.tunnel.Store("ok")
	r.status = filepath.Join(t.TempDir(), "proxy.json")
	cfg := Config{
		Listen:       DefaultListen,
		PasswordFile: writePassword(t, testPassword+"\n", 0o600),
		Upstream:     r.up,
		Tunnel: func() TunnelState {
			return TunnelState{Verdict: r.tunnel.Load().(string), Server: "se-got-wg-001", CheckedAt: "2026-11-19T17:59:30Z"}
		},
		Provider:   "mullvad",
		StatusPath: r.status,
		Now:        r.clock.now,
	}
	if edit != nil {
		edit(&cfg)
	}
	srv, err := newServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.srv = srv
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	r.lnClosed = func() { ln.Close() }
	r.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan error, 1)
	go func() { r.done <- srv.run(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
			t.Error("the proxy did not stop")
		}
	})
	return r
}

func (r *rig) dial(t *testing.T) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

// -- SOCKS5 -------------------------------------------------------------------

func socksGreet(t *testing.T, c net.Conn, user, pass string) byte {
	t.Helper()
	c.Write([]byte{5, 2, 0, 2})
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil || sel != [2]byte{5, 2} {
		t.Fatalf("method selection %v %v", sel, err)
	}
	msg := []byte{1, byte(len(user))}
	msg = append(msg, user...)
	msg = append(msg, byte(len(pass)))
	msg = append(msg, pass...)
	c.Write(msg)
	var st [2]byte
	if _, err := io.ReadFull(c, st[:]); err != nil || st[0] != 1 {
		t.Fatalf("auth status %v %v", st, err)
	}
	return st[1]
}

func socksRequest(cmd, atyp byte, addr []byte, port uint16) []byte {
	msg := []byte{5, cmd, 0, atyp}
	if atyp == atypDomain {
		msg = append(msg, byte(len(addr)))
	}
	msg = append(msg, addr...)
	return binary.BigEndian.AppendUint16(msg, port)
}

func socksReply(t *testing.T, c net.Conn) byte {
	t.Helper()
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if rep[0] != 5 || rep[2] != 0 || rep[3] != atypIPv4 || string(rep[4:]) != "\x00\x00\x00\x00\x00\x00" {
		t.Fatalf("reply %v", rep)
	}
	return rep[1]
}

func roundTrip(t *testing.T, c net.Conn) {
	t.Helper()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "ping" {
		t.Fatalf("echo %q %v", got, err)
	}
}

func TestSOCKSConnectEveryAddressType(t *testing.T) {
	r := startRig(t, nil)
	cases := []struct {
		atyp   byte
		addr   []byte
		target string
	}{
		{atypIPv4, []byte{192, 0, 2, 1}, "192.0.2.1:443"},
		{atypIPv6, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "[2001:db8::1]:443"},
		// The name is passed on as it is: resolved at the far end, never here.
		{atypDomain, []byte("Host.example.net"), "Host.example.net:443"},
	}
	for _, tc := range cases {
		c := r.dial(t)
		if st := socksGreet(t, c, "se-got", testPassword); st != 0 {
			t.Fatalf("auth status %d", st)
		}
		c.Write(socksRequest(cmdConnect, tc.atyp, tc.addr, 443))
		if rep := socksReply(t, c); rep != replySucceeded {
			t.Fatalf("%s: reply %d", tc.target, rep)
		}
		roundTrip(t, c)
		if call := r.up.lastCall(t); call != (dialCall{"se-got", "", tc.target}) {
			t.Fatalf("dial %+v, want target %s", call, tc.target)
		}
	}
}

func TestSOCKSRefusesWithoutUsernamePassword(t *testing.T) {
	r := startRig(t, nil)
	c := r.dial(t)
	c.Write([]byte{5, 1, 0})
	var sel [2]byte
	if _, err := io.ReadFull(c, sel[:]); err != nil || sel != [2]byte{5, 0xff} {
		t.Fatalf("selection %v %v", sel, err)
	}
	if _, err := c.Read(sel[:]); err == nil {
		t.Fatal("connection still open")
	}
}

func TestSOCKSAuthFailures(t *testing.T) {
	r := startRig(t, nil)
	for _, tc := range []struct{ user, pass string }{
		{"se-got", "wrong"},
		{"se-got", ""},
		{"SE", testPassword},
		{"se.too.many", testPassword},
		{"se.", testPassword},
		{"", testPassword},
	} {
		c := r.dial(t)
		if st := socksGreet(t, c, tc.user, tc.pass); st == 0 {
			t.Fatalf("%q/%q accepted", tc.user, tc.pass)
		}
		var b [1]byte
		if _, err := c.Read(b[:]); err == nil {
			t.Fatal("connection still open after a failed authentication")
		}
	}
	if r.up.callCount() != 0 {
		t.Fatal("the upstream was asked")
	}
}

func TestSOCKSReplyCodes(t *testing.T) {
	r := startRig(t, nil)
	ask := func(msg []byte) byte {
		c := r.dial(t)
		socksGreet(t, c, "any", testPassword)
		c.Write(msg)
		return socksReply(t, c)
	}
	if rep := ask(socksRequest(0x02, atypIPv4, []byte{192, 0, 2, 1}, 80)); rep != replyCommandUnsupported {
		t.Fatalf("BIND: %d", rep)
	}
	if rep := ask(socksRequest(0x03, atypIPv4, []byte{192, 0, 2, 1}, 80)); rep != replyCommandUnsupported {
		t.Fatalf("UDP ASSOCIATE: %d", rep)
	}
	if rep := ask([]byte{5, 1, 0, 0x05, 1, 2, 3, 4, 0, 80}); rep != replyAddressUnsupported {
		t.Fatalf("address type 5: %d", rep)
	}
	if rep := ask(socksRequest(cmdConnect, atypDomain, []byte("bad name"), 80)); rep != replyAddressUnsupported {
		t.Fatalf("bad name: %d", rep)
	}
	if rep := ask(socksRequest(cmdConnect, atypIPv4, []byte{192, 0, 2, 1}, 0)); rep != replyAddressUnsupported {
		t.Fatalf("port 0: %d", rep)
	}

	for _, tc := range []struct {
		err  error
		want byte
	}{
		{fmt.Errorf("relay: %w", syscall.ECONNREFUSED), replyConnectionRefused},
		{fmt.Errorf("relay: %w", syscall.EHOSTUNREACH), replyHostUnreachable},
		{fmt.Errorf("relay: %w", syscall.ENETUNREACH), replyNetworkUnreachable},
		{context.DeadlineExceeded, replyHostUnreachable},
		{errors.New("no server in location"), replyGeneralFailure},
	} {
		r.up.mu.Lock()
		r.up.err = tc.err
		r.up.mu.Unlock()
		if rep := ask(socksRequest(cmdConnect, atypIPv4, []byte{192, 0, 2, 1}, 80)); rep != tc.want {
			t.Fatalf("%v: reply %d, want %d", tc.err, rep, tc.want)
		}
	}
}

func TestTunnelNotOKRefusesNewConnectionsOnly(t *testing.T) {
	r := startRig(t, nil)
	// One connection opened while the tunnel is ok...
	open := r.dial(t)
	socksGreet(t, open, "any", testPassword)
	open.Write(socksRequest(cmdConnect, atypIPv4, []byte{192, 0, 2, 1}, 80))
	if rep := socksReply(t, open); rep != replySucceeded {
		t.Fatal(rep)
	}
	r.tunnel.Store("failed")
	calls := r.up.callCount()

	c := r.dial(t)
	socksGreet(t, c, "any", testPassword)
	c.Write(socksRequest(cmdConnect, atypIPv4, []byte{192, 0, 2, 1}, 80))
	if rep := socksReply(t, c); rep != replyGeneralFailure {
		t.Fatalf("SOCKS reply %d while the tunnel is failed", rep)
	}
	h := r.dial(t)
	fmt.Fprintf(h, "CONNECT example.net:443 HTTP/1.1\r\nHost: example.net:443\r\nProxy-Authorization: %s\r\n\r\n", basic("any", testPassword))
	if code := httpStatus(t, h); code != 503 {
		t.Fatalf("HTTP %d while the tunnel is failed", code)
	}
	if r.up.callCount() != calls {
		t.Fatal("the upstream was asked while the tunnel is failed")
	}
	// ...is left alone.
	roundTrip(t, open)
}

// -- HTTP CONNECT -------------------------------------------------------------

func basic(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func httpStatus(t *testing.T, c net.Conn) int {
	t.Helper()
	resp, _ := readResponse(t, c)
	return resp
}

func readResponse(t *testing.T, c net.Conn) (int, string) {
	t.Helper()
	br := bufio.NewReader(c)
	var head strings.Builder
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("response: %q %v", head.String(), err)
		}
		head.WriteString(line)
		if line == "\r\n" {
			break
		}
	}
	var code int
	fmt.Sscanf(head.String(), "HTTP/1.1 %d", &code)
	return code, head.String()
}

func TestHTTPConnect(t *testing.T) {
	r := startRig(t, nil)
	c := r.dial(t)
	// The first bytes of the connection come right behind the request.
	fmt.Fprintf(c, "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\nProxy-Authorization: %s\r\n\r\nearly", basic("se.s1", testPassword))
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil || line != "HTTP/1.1 200 Connection established\r\n" {
		t.Fatalf("%q %v", line, err)
	}
	if blank, _ := br.ReadString('\n'); blank != "\r\n" {
		t.Fatalf("%q", blank)
	}
	c.(*net.TCPConn).CloseWrite()
	got, _ := io.ReadAll(br)
	if string(got) != "early" {
		t.Fatalf("echo %q", got)
	}
	if call := r.up.lastCall(t); call != (dialCall{"se", "", "[2001:db8::1]:8443"}) {
		t.Fatalf("%+v", call)
	}
}

func TestHTTPRefusals(t *testing.T) {
	r := startRig(t, nil)
	auth := "Proxy-Authorization: " + basic("any", testPassword) + "\r\n"
	cases := []struct {
		name, request string
		code          int
		header        string
	}{
		{"no credentials", "CONNECT example.net:443 HTTP/1.1\r\nHost: example.net:443\r\n\r\n", 407, `Proxy-Authenticate: Basic realm="molebridge"`},
		{"wrong password", "CONNECT example.net:443 HTTP/1.1\r\nProxy-Authorization: " + basic("any", "nope") + "\r\n\r\n", 407, "Proxy-Authenticate: Basic"},
		{"bad username", "CONNECT example.net:443 HTTP/1.1\r\nProxy-Authorization: " + basic("Any", testPassword) + "\r\n\r\n", 407, "Proxy-Authenticate: Basic"},
		{"other scheme", "CONNECT example.net:443 HTTP/1.1\r\nProxy-Authorization: Bearer abc\r\n\r\n", 407, "Proxy-Authenticate: Basic"},
		{"two credentials", "CONNECT example.net:443 HTTP/1.1\r\n" + auth + auth + "\r\n", 407, "Proxy-Authenticate: Basic"},
		{"plain GET", "GET http://example.net/ HTTP/1.1\r\nHost: example.net\r\n" + auth + "\r\n", 405, "Allow: CONNECT"},
		{"no port", "CONNECT example.net HTTP/1.1\r\n" + auth + "\r\n", 400, ""},
		{"port 0", "CONNECT example.net:0 HTTP/1.1\r\n" + auth + "\r\n", 400, ""},
		{"bad host", "CONNECT exa%mple.net:443 HTTP/1.1\r\n" + auth + "\r\n", 400, ""},
		{"a body", "CONNECT example.net:443 HTTP/1.1\r\nContent-Length: 4\r\n" + auth + "\r\nbody", 400, ""},
		{"garbage", "HELLO\r\n\r\n", 400, ""},
		{"headers too long", "CONNECT example.net:443 HTTP/1.1\r\nX-Long: " + strings.Repeat("a", maxHandshakeBytes) + "\r\n" + auth + "\r\n", 400, ""},
	}
	for _, tc := range cases {
		c := r.dial(t)
		io.WriteString(c, tc.request)
		code, head := readResponse(t, c)
		if code != tc.code || !strings.Contains(head, tc.header) {
			t.Fatalf("%s: %d %q", tc.name, code, head)
		}
	}
	if r.up.callCount() != 0 {
		t.Fatal("the upstream was asked")
	}
	r.up.mu.Lock()
	r.up.err = errors.New("benched")
	r.up.mu.Unlock()
	c := r.dial(t)
	io.WriteString(c, "CONNECT example.net:443 HTTP/1.1\r\n"+auth+"\r\n")
	if code := httpStatus(t, c); code != 502 {
		t.Fatalf("upstream failure: %d", code)
	}
	r.up.mu.Lock()
	r.up.err = context.DeadlineExceeded
	r.up.mu.Unlock()
	c = r.dial(t)
	io.WriteString(c, "CONNECT example.net:443 HTTP/1.1\r\n"+auth+"\r\n")
	if code := httpStatus(t, c); code != 504 {
		t.Fatalf("upstream timeout: %d", code)
	}
}

// -- the listener --------------------------------------------------------------

func expectClosed(t *testing.T, c net.Conn, within time.Duration) {
	t.Helper()
	c.SetDeadline(time.Now().Add(within))
	var b [1]byte
	_, err := c.Read(b[:])
	var ne net.Error
	if err == nil || errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("connection not closed by the proxy: %v", err)
	}
}

func TestUnknownProtocolIsClosed(t *testing.T) {
	r := startRig(t, nil)
	c := r.dial(t)
	c.Write([]byte{0x04, 0x01})
	expectClosed(t, c, 2*time.Second)
}

func TestHandshakeDeadline(t *testing.T) {
	r := startRig(t, func(c *Config) { c.HandshakeTimeout = 200 * time.Millisecond })
	c := r.dial(t)
	c.Write([]byte{5}) // the first byte only
	expectClosed(t, c, 3*time.Second)
	h := r.dial(t)
	io.WriteString(h, "CONNECT example.net:443 HTTP/1.1\r\n")
	expectClosed(t, h, 3*time.Second)
}

func TestSlowDialOutlastsTheHandshakeDeadline(t *testing.T) {
	r := startRig(t, func(c *Config) { c.HandshakeTimeout = 200 * time.Millisecond })
	r.up.delay = 500 * time.Millisecond
	c := r.dial(t)
	socksGreet(t, c, "any", testPassword)
	c.Write(socksRequest(cmdConnect, atypIPv4, []byte{192, 0, 2, 1}, 80))
	if rep := socksReply(t, c); rep != replySucceeded {
		t.Fatal(rep)
	}
	roundTrip(t, c)
}

func TestMaxConns(t *testing.T) {
	r := startRig(t, func(c *Config) { c.MaxConns = 1 })
	first := r.dial(t)
	socksGreet(t, first, "any", testPassword)
	first.Write(socksRequest(cmdConnect, atypIPv4, []byte{192, 0, 2, 1}, 80))
	if rep := socksReply(t, first); rep != replySucceeded {
		t.Fatal(rep)
	}
	second := r.dial(t)
	expectClosed(t, second, 2*time.Second)
	roundTrip(t, first) // the open one is unaffected
	// Once the first is done its slot is free again.
	deadline := time.Now().Add(3 * time.Second)
	for r.srv.open.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	third := r.dial(t)
	if st := socksGreet(t, third, "any", testPassword); st != 0 {
		t.Fatal(st)
	}
}

func openSOCKS(t *testing.T, r *rig) net.Conn {
	t.Helper()
	c := r.dial(t)
	socksGreet(t, c, "any", testPassword)
	c.Write(socksRequest(cmdConnect, atypIPv4, []byte{192, 0, 2, 1}, 80))
	if rep := socksReply(t, c); rep != replySucceeded {
		t.Fatal(rep)
	}
	return c
}

func waitOpen(t *testing.T, r *rig, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for r.srv.open.Load() != want {
		if time.Now().After(deadline) {
			t.Fatalf("open %d, want %d", r.srv.open.Load(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMaxConnsPerClient(t *testing.T) {
	// Every test client connects from 127.0.0.1: one client address.
	r := startRig(t, func(c *Config) { c.MaxConns = 10; c.MaxConnsPerClient = 2 })
	first, second := openSOCKS(t, r), openSOCKS(t, r)
	third := r.dial(t)
	expectClosed(t, third, 2*time.Second)
	if n := r.srv.overClient.Load(); n != 1 {
		t.Fatalf("over_client_limit %d", n)
	}
	if n := r.srv.clients(); n != 1 {
		t.Fatalf("clients %d", n)
	}
	// The refused one took no shared slot: the open count is the two.
	if n := r.srv.open.Load(); n != 2 {
		t.Fatalf("open %d", n)
	}
	roundTrip(t, first) // the open ones are unaffected
	waitOpen(t, r, 1)
	// The first's place is free again for the same client.
	openSOCKS(t, r)
	roundTrip(t, second)
	waitOpen(t, r, 1)
	if n := r.srv.overClient.Load(); n != 1 {
		t.Fatalf("over_client_limit %d", n)
	}
}

func TestMaxConnsPerClientReleasedWhenTheSharedBoundRefuses(t *testing.T) {
	r := startRig(t, func(c *Config) { c.MaxConns = 1; c.MaxConnsPerClient = 5 })
	first := openSOCKS(t, r)
	for i := 0; i < 3; i++ {
		expectClosed(t, r.dial(t), 2*time.Second)
	}
	if n := r.srv.overClient.Load(); n != 0 {
		t.Fatalf("over_client_limit %d: the shared bound refused these", n)
	}
	r.srv.mu.Lock()
	held := r.srv.perClient["127.0.0.1"]
	r.srv.mu.Unlock()
	if held != 1 {
		t.Fatalf("counted %d for the client, want 1", held)
	}
	roundTrip(t, first)
	waitOpen(t, r, 0)
	if n := r.srv.clients(); n != 0 {
		t.Fatalf("clients %d after every connection closed", n)
	}
}

func TestClientKey(t *testing.T) {
	for addr, want := range map[net.Addr]string{
		&net.TCPAddr{IP: net.ParseIP("192.0.2.7"), Port: 4000}:   "192.0.2.7",
		&net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 4000}: "2001:db8::1",
	} {
		if got := clientKey(addr); got != want {
			t.Errorf("%v: %q", addr, got)
		}
	}
	if got := clientKey(nil); got != "" {
		t.Errorf("nil: %q", got)
	}
}

func TestIdleTimeoutClosesAnIdleConnection(t *testing.T) {
	r := startRig(t, func(c *Config) { c.IdleTimeout = 300 * time.Millisecond })
	c := openSOCKS(t, r)
	start := time.Now()
	expectClosed(t, c, 3*time.Second)
	if took := time.Since(start); took < 250*time.Millisecond {
		t.Fatalf("closed after %v, before the idle timeout", took)
	}
	waitOpen(t, r, 0)
	if n := r.srv.idleClosed.Load(); n != 1 {
		t.Fatalf("idle_closed %d", n)
	}
}

func TestIdleTimeoutSparesAnActiveConnection(t *testing.T) {
	r := startRig(t, func(c *Config) { c.IdleTimeout = 300 * time.Millisecond })
	c := openSOCKS(t, r)
	// Traffic every 100 ms for three idle timeouts keeps it open.
	for i := 0; i < 9; i++ {
		if _, err := c.Write([]byte("x")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "xxxxxxxxx" {
		t.Fatalf("echo %q %v", got, err)
	}
	if n := r.srv.idleClosed.Load(); n != 0 {
		t.Fatalf("idle_closed %d", n)
	}
}

func TestNoIdleTimeoutByDefault(t *testing.T) {
	r := startRig(t, nil)
	c := openSOCKS(t, r)
	time.Sleep(400 * time.Millisecond)
	roundTrip(t, c)
}

func TestHalfClose(t *testing.T) {
	r := startRig(t, nil)
	c := r.dial(t)
	socksGreet(t, c, "any", testPassword)
	c.Write(socksRequest(cmdConnect, atypDomain, []byte("example.net"), 80))
	if rep := socksReply(t, c); rep != replySucceeded {
		t.Fatal(rep)
	}
	// The echo server answers only after it has seen the client's end; the
	// answer still arrives, so each direction closed on its own.
	c.Write([]byte("one "))
	c.Write([]byte("two"))
	c.(*net.TCPConn).CloseWrite()
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "one two" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestStopClosesOpenConnections(t *testing.T) {
	r := startRig(t, nil)
	c := r.dial(t)
	socksGreet(t, c, "any", testPassword)
	c.Write(socksRequest(cmdConnect, atypIPv4, []byte{192, 0, 2, 1}, 80))
	socksReply(t, c)
	r.cancel()
	if err := <-r.done; err != nil {
		t.Fatal(err)
	}
	r.done <- nil // for the cleanup
	expectClosed(t, c, 2*time.Second)
}

// -- sessions -----------------------------------------------------------------

func TestSessionsPinTheirServer(t *testing.T) {
	r := startRig(t, nil)
	connect := func(user string) dialCall {
		c := r.dial(t)
		socksGreet(t, c, user, testPassword)
		c.Write(socksRequest(cmdConnect, atypDomain, []byte("example.net"), 443))
		socksReply(t, c)
		c.Close()
		return r.up.lastCall(t)
	}
	if call := connect("se.alpha"); call.pinned != "" {
		t.Fatalf("a new session has a pin: %+v", call)
	}
	if call := connect("se.alpha"); call.pinned != "se-got-wg-001" {
		t.Fatalf("the session lost its server: %+v", call)
	}
	// Without a session, and for the same session name in another location,
	// the server is chosen again.
	if call := connect("se"); call.pinned != "" {
		t.Fatalf("%+v", call)
	}
	if call := connect("de.alpha"); call.pinned != "" {
		t.Fatalf("%+v", call)
	}
	// The Upstream moves the session (its server was benched): the pin follows.
	r.up.mu.Lock()
	r.up.server = "se-sto-wg-002"
	r.up.mu.Unlock()
	if call := connect("se.alpha"); call.pinned != "se-got-wg-001" {
		t.Fatalf("%+v", call)
	}
	r.up.mu.Lock()
	r.up.server = ""
	r.up.mu.Unlock()
	if call := connect("se.alpha"); call.pinned != "se-sto-wg-002" {
		t.Fatalf("the pin did not follow the Upstream: %+v", call)
	}
	// Used within 30 minutes: kept. Idle for longer: gone.
	r.clock.advance(29 * time.Minute)
	if call := connect("se.alpha"); call.pinned != "se-sto-wg-002" {
		t.Fatalf("%+v", call)
	}
	r.clock.advance(31 * time.Minute)
	if call := connect("se.alpha"); call.pinned != "" {
		t.Fatalf("an idle session kept its server: %+v", call)
	}
}

func TestSessionTable(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 11, 19, 18, 0, 0, 0, time.UTC)}
	s := newSessions(clock.now)
	s.update("se", "", "se-got-wg-001")
	if s.active() != 0 || s.pinned("se", "") != "" {
		t.Fatal("a connection without a session was pinned")
	}
	s.update("se", "a", "se-got-wg-001")
	s.update("se", "a", "") // a failed dial that named no server keeps the pin
	if got := s.pinned("se", "a"); got != "se-got-wg-001" {
		t.Fatal(got)
	}
	s.update("se", "b", "se-got-wg-002")
	if s.active() != 2 {
		t.Fatal(s.active())
	}
	clock.advance(SessionTTL + time.Second)
	if s.pinned("se", "a") != "" || s.active() != 0 {
		t.Fatal("expired sessions remain")
	}
	// An expired session that is used again starts afresh.
	s.m[sessionKey("se", "c")] = pin{server: "old", lastUsed: clock.now().Add(-SessionTTL - time.Second)}
	s.update("se", "c", "")
	if got := s.pinned("se", "c"); got != "" {
		t.Fatalf("an expired pin came back: %q", got)
	}
	// The table is bounded.
	for i := 0; i < maxSessions+10; i++ {
		s.update("se", fmt.Sprintf("s%d", i), "se-got-wg-001")
	}
	if len(s.m) > maxSessions {
		t.Fatal(len(s.m))
	}
}

// -- configuration -----------------------------------------------------------

func TestCheckListen(t *testing.T) {
	addrs := func(name string) ([]net.Addr, error) {
		if name != "wt0" {
			return nil, errors.New("no such interface")
		}
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("198.51.100.0").To4(), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("198.51.100.5").To4(), Mask: net.CIDRMask(16, 32)},
			&net.IPAddr{IP: net.ParseIP("2001:db8::5")},
		}, nil
	}
	ok := []struct{ addr, iface string }{
		{"127.0.0.1:1080", ""},
		{"127.0.0.2:1080", ""},
		{"[::1]:1080", ""},
		{"[::ffff:127.0.0.1]:1080", ""},
		{"198.51.100.5:1080", "wt0"},
		{"[2001:db8::5]:1080", "wt0"},
	}
	for _, tc := range ok {
		if err := CheckListen(tc.addr, tc.iface, addrs); err != nil {
			t.Errorf("%s on %q: %v", tc.addr, tc.iface, err)
		}
	}
	refused := []struct{ addr, iface string }{
		{"0.0.0.0:1080", "wt0"},
		{"[::]:1080", "wt0"},
		{"192.0.2.10:1080", "wt0"},
		{"198.51.100.5:1080", ""},
		{"198.51.100.5:1080", "eth9"},
		{"localhost:1080", ""},
		{"127.0.0.1:0", ""},
		{"127.0.0.1:65536", ""},
		{"127.0.0.1", ""},
		{"[fe80::1%wt0]:1080", "wt0"},
		{"", ""},
	}
	for _, tc := range refused {
		if err := CheckListen(tc.addr, tc.iface, addrs); err == nil {
			t.Errorf("%s on %q accepted", tc.addr, tc.iface)
		}
	}
	// OVERLAY_IF may be a cluster interface: on Kubernetes, eth0 and the
	// pod's own address.
	pod := func(name string) ([]net.Addr, error) {
		if name != "eth0" {
			return nil, errors.New("no such interface")
		}
		return []net.Addr{&net.IPNet{IP: net.ParseIP("203.0.113.7").To4(), Mask: net.CIDRMask(32, 32)}}, nil
	}
	if err := CheckListen("203.0.113.7:1080", "eth0", pod); err != nil {
		t.Errorf("the pod's address on eth0: %v", err)
	}
	if err := CheckListen("203.0.113.8:1080", "eth0", pod); err == nil {
		t.Error("another address accepted on eth0")
	}
}

func TestReadPassword(t *testing.T) {
	if got, err := ReadPassword(writePassword(t, "secret\r\n", 0o400)); err != nil || string(got) != "secret" {
		t.Fatalf("%q %v", got, err)
	}
	if got, err := ReadPassword(writePassword(t, " spaced \n\n", 0o600)); err != nil || string(got) != " spaced \n" {
		t.Fatalf("only one newline is trimmed: %q %v", got, err)
	}
	for name, path := range map[string]string{
		"unset":          "",
		"missing":        filepath.Join(t.TempDir(), "none"),
		"empty":          writePassword(t, "", 0o600),
		"newline only":   writePassword(t, "\n", 0o600),
		"world-readable": writePassword(t, "secret", 0o604),
		"too long":       writePassword(t, strings.Repeat("a", 256), 0o600),
		"a directory":    t.TempDir(),
	} {
		if _, err := ReadPassword(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A group may read it: the proxy's user often gets the file by its group.
	if _, err := ReadPassword(writePassword(t, "secret", 0o640)); err != nil {
		t.Errorf("group-readable: %v", err)
	}
	// Serve refuses to start without it.
	err := Serve(context.Background(), Config{Listen: DefaultListen, Upstream: &fakeUpstream{},
		Tunnel: func() TunnelState { return TunnelState{} }, PasswordFile: writePassword(t, "x", 0o644)})
	if err == nil || !strings.Contains(err.Error(), "readable by others") {
		t.Fatal(err)
	}
}

func TestServeRefusesABadListenAddress(t *testing.T) {
	err := Serve(context.Background(), Config{Listen: "0.0.0.0:1080", Upstream: &fakeUpstream{},
		Tunnel: func() TunnelState { return TunnelState{} }, PasswordFile: writePassword(t, "x", 0o600)})
	if err == nil {
		t.Fatal("accepted 0.0.0.0")
	}
	// A bad listen address and a bad password file are refused together.
	err = Serve(context.Background(), Config{Listen: "0.0.0.0:1080", Upstream: &fakeUpstream{},
		Tunnel: func() TunnelState { return TunnelState{} }, PasswordFile: writePassword(t, "x", 0o644)})
	if err == nil || !strings.Contains(err.Error(), "0.0.0.0:1080") || !strings.Contains(err.Error(), "readable by others") {
		t.Fatalf("want both refusals: %v", err)
	}
}

func TestParseUsername(t *testing.T) {
	good := map[string][2]string{
		"any":                            {"any", ""},
		"se":                             {"se", ""},
		"se-got":                         {"se-got", ""},
		"se-got-wg-001":                  {"se-got-wg-001", ""},
		"us_california":                  {"us_california", ""},
		"se.a":                           {"se", "a"},
		"se-got.my_session_1":            {"se-got", "my_session_1"},
		"any." + strings.Repeat("s", 32): {"any", strings.Repeat("s", 32)},
		strings.Repeat("a", 63):          {strings.Repeat("a", 63), ""},
	}
	for in, want := range good {
		loc, ses, ok := ParseUsername(in)
		if !ok || loc != want[0] || ses != want[1] {
			t.Errorf("%q: %q %q %v", in, loc, ses, ok)
		}
	}
	for _, in := range []string{"", "SE", "-se", "_se", "se.", ".s", "se.a.b", "se.A", "se.a-b",
		"any." + strings.Repeat("s", 33), strings.Repeat("a", 64), "se got", "se\x00", "sé", "se:1"} {
		if _, _, ok := ParseUsername(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestPasswordMatches(t *testing.T) {
	want := []byte("secret")
	long := []byte(strings.Repeat("a", maxPasswordBytes))
	for _, c := range []struct {
		want, got []byte
		ok        bool
	}{
		{want, []byte("secret"), true},
		{want, []byte("secre"), false},
		{want, []byte("secret\x00"), false},
		{want, []byte("Secret"), false},
		{want, nil, false},
		{long, long, true},
		{long, append(append([]byte{}, long...), 'a'), false},
	} {
		if got := passwordMatches(c.want, c.got); got != c.ok {
			t.Errorf("passwordMatches(%q, %q) = %v", c.want, c.got, got)
		}
	}
}

// Connections that start together on a new session share the first one's
// server: the others wait for its choice instead of choosing their own.
func TestSessionFirstBurstSharesOneServer(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 11, 26, 18, 0, 0, 0, time.UTC)}
	s := newSessions(clock.now)
	pinned, done := s.acquire(context.Background(), "se", "a")
	if pinned != "" {
		t.Fatalf("a new session has a server: %q", pinned)
	}
	got := make(chan string, 1)
	go func() {
		p, d := s.acquire(context.Background(), "se", "a")
		d(p)
		got <- p
	}()
	select {
	case p := <-got:
		t.Fatalf("the second connection chose (%q) before the first had", p)
	case <-time.After(50 * time.Millisecond):
	}
	done("se-got-wg-001")
	select {
	case p := <-got:
		if p != "se-got-wg-001" {
			t.Fatalf("the second connection got %q, not the first's server", p)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the second connection never got the first's server")
	}
	// A first dial that named no server lets the next connection choose.
	_, done = s.acquire(context.Background(), "se", "b")
	go func() {
		p, d := s.acquire(context.Background(), "se", "b")
		d("se-got-wg-002")
		got <- p
	}()
	done("")
	if p := <-got; p != "" {
		t.Fatalf("a failed first dial left a server: %q", p)
	}
	if p := s.pinned("se", "b"); p != "se-got-wg-002" {
		t.Fatal(p)
	}
	// A wait ends with its context; that connection dials without a pin.
	_, done = s.acquire(context.Background(), "se", "c")
	defer done("")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if p, _ := s.acquire(ctx, "se", "c"); p != "" {
		t.Fatal(p)
	}
	// Without a session nothing waits.
	if p, d := s.acquire(context.Background(), "se", ""); p != "" {
		t.Fatal(p)
	} else {
		d("se-got-wg-003")
	}
}

// A FIFO as the password file is refused at once, not waited on.
func TestReadPasswordRefusesFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadPassword(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadPassword blocked on a FIFO")
	}
}
