package relayproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const zeroKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// mullvadEntry is a relay as relays.json stores it.
func mullvadEntry(name, code string) string {
	return `"` + name + `": {"hostname": "` + name + `", "public_key": "` + zeroKey +
		`", "ipv4_addr_in": "198.51.100.10", "city": "Example City", "country": "Example", "location_code": "` + code + `"}`
}

// writeSnapshot writes a Mullvad relays.json holding entries.
func writeSnapshot(t *testing.T, dir string, entries ...string) string {
	t.Helper()
	path := filepath.Join(dir, "relays.json")
	body := `{"fetched_at": "2026-11-19T18:00:00Z", "provider": "mullvad", "relays": {` + strings.Join(entries, ", ") + `}}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// clock is a settable clock.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock { return &clock{now: time.Date(2026, 11, 19, 18, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeResolver answers from a table; a missing name is not found.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	calls   []string
}

var errNotFound = errors.New("no such host")

func (f *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, network+" "+host)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a, ok := f.answers[host]
	if !ok {
		return nil, errNotFound
	}
	return a, nil
}

func addrs(list ...string) []netip.Addr {
	out := make([]netip.Addr, len(list))
	for i, s := range list {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// fakeDialer serves each dialled address with its handler over net.Pipe; an
// address without one is refused.
type fakeDialer struct {
	mu       sync.Mutex
	handlers map[string]func(net.Conn)
	dialed   []string
}

var errRefused = errors.New("connection refused")

func (f *fakeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, network+" "+address)
	h := f.handlers[address]
	f.mu.Unlock()
	if network != "tcp" {
		return nil, errors.New("unexpected network")
	}
	if h == nil {
		return nil, errRefused
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		h(server)
	}()
	return client, nil
}

func (f *fakeDialer) handle(address string, h func(net.Conn)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.handlers == nil {
		f.handlers = map[string]func(net.Conn){}
	}
	f.handlers[address] = h
}

func (f *fakeDialer) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dialed...)
}

// socksServer is a fake relay proxy: it checks the greeting, reads the
// CONNECT request into got, and replies with code; after a success it echoes.
type socksServer struct {
	code byte
	mu   sync.Mutex
	got  [][]byte
}

func (s *socksServer) serve(c net.Conn) {
	var greet [3]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil || greet != [3]byte{5, 1, 0} {
		return
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(c, head); err != nil {
		return
	}
	var addr []byte
	switch head[3] {
	case 1:
		addr = make([]byte, 4+2)
	case 4:
		addr = make([]byte, 16+2)
	case 3:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		head = append(head, n[0])
		addr = make([]byte, int(n[0])+2)
	}
	if _, err := io.ReadFull(c, addr); err != nil {
		return
	}
	s.mu.Lock()
	s.got = append(s.got, append(head, addr...))
	s.mu.Unlock()
	reply := []byte{5, s.code, 0, 1, 10, 124, 0, 1, 0x30, 0x39}
	if _, err := c.Write(reply); err != nil || s.code != 0 {
		return
	}
	_, _ = io.Copy(c, c)
}

func (s *socksServer) requests() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.got...)
}

// domainRequest is the CONNECT request a domain target should produce.
func domainRequest(host string, port uint16) []byte {
	b := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	return binary.BigEndian.AppendUint16(b, port)
}

// rig is a Mullvad Relays over fakes, with the named relays' proxies at
// 10.124.0.<i+1> serving s.
type rig struct {
	relays   *Relays
	dialer   *fakeDialer
	resolver *fakeResolver
	clock    *clock
	picks    []int // the n of every uniform choice
	dir      string
}

func newRig(t *testing.T, names ...string) *rig {
	t.Helper()
	r := &rig{dialer: &fakeDialer{}, resolver: &fakeResolver{answers: map[string][]netip.Addr{}}, clock: newClock(), dir: t.TempDir()}
	var entries []string
	for i, name := range names {
		entries = append(entries, mullvadEntry(name, name[:6]))
		socks, ok := MullvadSocksName(name)
		if !ok {
			t.Fatalf("no proxy name for %s", name)
		}
		r.resolver.answers[socks] = addrs("10.124.0." + itoa(i+1))
	}
	path := writeSnapshot(t, r.dir, entries...)
	var err error
	r.relays, err = New(Config{Provider: "mullvad", CatalogPath: path, Dialer: r.dialer, Resolver: r.resolver,
		HandshakeTimeout: time.Second, Now: r.clock.Now,
		Intn: func(n int) int { r.picks = append(r.picks, n); return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func itoa(i int) string { return strconv.Itoa(i) }

// serve makes relay i's proxy (10.124.0.<i+1>:1080) serve s.
func (r *rig) serve(i int, s *socksServer) {
	r.dialer.handle("10.124.0."+itoa(i+1)+":1080", s.serve)
}

func (r *rig) state(name string) ServerState {
	for _, s := range r.relays.Servers() {
		if s.Server == name {
			return s
		}
	}
	return ServerState{}
}
