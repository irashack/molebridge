// Package relayproxy is the proxy's upstream (docs/design/menu.md, "Relay
// proxies"): the servers a connection can leave by, chosen for a location,
// with failed ones benched for a while.
//
// For Mullvad, each WireGuard relay in the exit's catalogue snapshot
// (state/applier/relays.json, read through providers.ReadSnapshot so its
// validation is the catalogue's) has a SOCKS5 proxy, reached inside the
// tunnel. Its name is resolved through the tunnel resolver and only an answer
// in 10.124.0.0/16 is used; the connection goes through the tunnel dialer,
// then a SOCKS5 handshake sends the target's host name to the relay proxy.
//
// For PIA and NordVPN no proxy per server is known: only the exit's current
// server (result.json's "server") is offered, and the target is dialed
// directly through the tunnel dialer, its name resolved through the tunnel
// resolver.
//
// Nothing here opens a socket itself: the Dialer and Resolver it is given
// are the tunnel's (internal/tunneldial), so every connection leaves through
// the tunnel or fails. The role `molebridge proxy` uses it.
package relayproxy

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/irashack/molebridge/internal/providers"
)

// Upstream is the interface the proxy uses (as in the design).
type Upstream interface {
	// Dial opens a connection to target ("host:port") through a server in
	// location, preferring pinned when it is set and not benched. It returns
	// the server used.
	Dial(ctx context.Context, location, pinned, target string) (conn net.Conn, server string, err error)
	Servers() []ServerState // for the status record
}

// ServerState is one server's state, for the status record.
type ServerState struct {
	Server       string
	Benched      bool
	BenchedUntil time.Time
	Reason       string
	LastOK       time.Time
}

// Dialer opens connections; the proxy gives it *tunneldial.Dialer.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Resolver resolves names; the proxy gives it *tunneldial.Resolver.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Benching: a failed relay proxy is benched for BenchFirst, doubling with each
// further failure up to BenchMax, until a success clears it.
const (
	BenchFirst = time.Minute
	BenchMax   = time.Hour
)

// DefaultHandshakeTimeout bounds one attempt at a relay proxy: resolving its
// name, connecting and the SOCKS5 handshake.
const DefaultHandshakeTimeout = 10 * time.Second

// attempts is how many relay proxies one Dial tries before giving up.
const attempts = 3

// relayRange is where Mullvad's relay proxies answer, inside the tunnel.
var relayRange = netip.MustParsePrefix("10.124.0.0/16")

// The refusals. They never carry a name, address or anything received.
var (
	ErrProvider    = errors.New("relayproxy: the proxy supports mullvad, pia and nordvpn")
	ErrConfig      = errors.New("relayproxy: a Dialer, a Resolver and the catalogue path are required")
	ErrAllBenched  = errors.New("relayproxy: every server for the location is benched")
	ErrNoCurrent   = errors.New("relayproxy: the exit has no current server")
	ErrOutOfRange  = errors.New("relayproxy: relay proxy address outside 10.124.0.0/16")
	ErrUnreachable = errors.New("relayproxy: no address of the target answered")
)

// Config is what New needs.
type Config struct {
	Provider    string // "mullvad", "pia" or "nordvpn"
	CatalogPath string // the exit's state/applier/relays.json
	ResultPath  string // the exit's state/applier/result.json (PIA and NordVPN)
	Dialer      Dialer
	Resolver    Resolver
	// HandshakeTimeout bounds one attempt; DefaultHandshakeTimeout when zero.
	HandshakeTimeout time.Duration
	// Now is the clock and Intn the uniform choice (tests); time.Now and
	// math/rand/v2 when nil.
	Now  func() time.Time
	Intn func(n int) int
}

// bench is a server's failure record.
type bench struct {
	failures int
	until    time.Time
	reason   string
}

// Relays implements Upstream.
type Relays struct {
	cfg  Config
	ipv6 bool

	mu      sync.Mutex
	catalog catalog
	benches map[string]*bench
	lastOK  map[string]time.Time
}

var _ Upstream = (*Relays)(nil)

// New checks cfg and reads the catalogue.
func New(cfg Config) (*Relays, error) {
	switch cfg.Provider {
	case "mullvad", "pia", "nordvpn":
	default:
		return nil, ErrProvider
	}
	if cfg.Dialer == nil || cfg.Resolver == nil || cfg.CatalogPath == "" || cfg.Provider != "mullvad" && cfg.ResultPath == "" {
		return nil, ErrConfig
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Intn == nil {
		cfg.Intn = rand.IntN
	}
	p, _ := providers.Lookup(cfg.Provider)
	r := &Relays{cfg: cfg, ipv6: p != nil && p.IPv6, benches: map[string]*bench{}, lastOK: map[string]time.Time{}}
	r.catalog = loadCatalog(cfg.CatalogPath, cfg.Provider)
	return r, nil
}

// refresh rereads the catalogue when its file has changed. Called with mu
// held.
func (r *Relays) refresh() {
	if r.catalog.stale(r.cfg.CatalogPath) {
		r.catalog = loadCatalog(r.cfg.CatalogPath, r.cfg.Provider)
	}
}

// Known is the number of servers in the catalogue the proxy can use.
func (r *Relays) Known() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh()
	return len(r.catalog.servers)
}

// Servers is every usable server's state, sorted by name: for Mullvad the
// catalogue's, for PIA and NordVPN the exit's current server.
func (r *Relays) Servers() []ServerState {
	if r.cfg.Provider != "mullvad" {
		current := currentServer(r.cfg.ResultPath, r.cfg.Provider)
		if current == "" {
			return nil
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		return []ServerState{{Server: current, LastOK: r.lastOK[current]}}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh()
	now := r.cfg.Now()
	out := make([]ServerState, 0, len(r.catalog.servers))
	for _, s := range r.catalog.servers {
		st := ServerState{Server: s.name, LastOK: r.lastOK[s.name]}
		if b := r.benches[s.name]; b != nil && b.until.After(now) {
			st.Benched, st.BenchedUntil, st.Reason = true, b.until, b.reason
		}
		out = append(out, st)
	}
	return out
}

// Dial implements Upstream.
func (r *Relays) Dial(ctx context.Context, location, pinned, target string) (net.Conn, string, error) {
	host, port, err := ParseTarget(target)
	if err != nil {
		return nil, "", err
	}
	loc, err := parseLocation(location)
	if err != nil {
		return nil, "", err
	}
	if r.cfg.Provider != "mullvad" {
		return r.dialDirect(ctx, loc, host, port)
	}
	tried := map[string]bool{}
	var last error
	for i := 0; i < attempts; i++ {
		s, err := r.choose(loc, pinned, tried)
		if err != nil {
			if last != nil {
				return nil, "", last
			}
			return nil, "", err
		}
		tried[s.name] = true
		conn, err := r.dialRelay(ctx, s, host, port)
		if err == nil {
			r.succeeded(s.name)
			return conn, s.name, nil
		}
		if ctx.Err() != nil {
			// The caller gave up: no fault of the relay proxy.
			return nil, "", ctx.Err()
		}
		var reply *ReplyError
		if errors.As(err, &reply) && reply.Target() {
			// The relay proxy works; the target does not.
			r.succeeded(s.name)
			return nil, s.name, err
		}
		r.failed(s.name, reason(err))
		last = err
	}
	return nil, "", last
}

// choose picks pinned when it is in the location, untried and not benched,
// else uniformly among the location's untried servers that aren't benched.
func (r *Relays) choose(loc location, pinned string, tried map[string]bool) (server, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refresh()
	now := r.cfg.Now()
	var free []server
	matched := false
	for _, s := range r.catalog.servers {
		if !loc.matches(s) {
			continue
		}
		matched = true
		if tried[s.name] {
			continue
		}
		if b := r.benches[s.name]; b != nil && b.until.After(now) {
			continue
		}
		if s.name == pinned {
			return s, nil
		}
		free = append(free, s)
	}
	if !matched {
		return server{}, ErrNoServer
	}
	if len(free) == 0 {
		return server{}, ErrAllBenched
	}
	return free[r.cfg.Intn(len(free))], nil
}

func (r *Relays) succeeded(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.benches, name)
	r.lastOK[name] = r.cfg.Now()
}

func (r *Relays) failed(name, why string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.benches[name]
	if b == nil {
		b = &bench{}
		r.benches[name] = b
	}
	if b.failures < 16 {
		b.failures++
	}
	d := BenchFirst << (b.failures - 1)
	if d > BenchMax || d <= 0 {
		d = BenchMax
	}
	b.until, b.reason = r.cfg.Now().Add(d), why
}

// stepError marks which step of an attempt failed, for the bench reason.
type stepError struct {
	step string
	err  error
}

func (e *stepError) Error() string { return e.err.Error() }
func (e *stepError) Unwrap() error { return e.err }

// reason is the bench reason for an attempt's error: fixed text, never
// anything received.
func reason(err error) string {
	var reply *ReplyError
	if errors.As(err, &reply) {
		if text, ok := replyText[reply.Code]; ok {
			return "relay proxy replied " + text
		}
		return "relay proxy replied an unknown code"
	}
	if errors.Is(err, ErrOutOfRange) {
		return "relay proxy address outside 10.124.0.0/16"
	}
	if errors.Is(err, ErrNoAuth) {
		return "relay proxy wants authentication"
	}
	step := "connection"
	var se *stepError
	if errors.As(err, &se) {
		step = se.step
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		return step + " timed out"
	}
	return step + " failed"
}

// dialRelay resolves s's relay proxy, connects through the dialer and runs
// the handshake, all within the handshake timeout.
func (r *Relays) dialRelay(ctx context.Context, s server, host string, port uint16) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, r.cfg.HandshakeTimeout)
	defer cancel()
	addrs, err := r.cfg.Resolver.LookupNetIP(ctx, "ip4", s.socks)
	if err != nil {
		return nil, &stepError{"name lookup", err}
	}
	addr, err := relayAddress(addrs)
	if err != nil {
		return nil, err
	}
	conn, err := r.cfg.Dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, SocksPort).String())
	if err != nil {
		return nil, &stepError{"connection", err}
	}
	if err := handshake(ctx, conn, host, port); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// relayAddress is the first answer, when every answer is in 10.124.0.0/16:
// an answer elsewhere means the name is not the relay proxy's.
func relayAddress(addrs []netip.Addr) (netip.Addr, error) {
	if len(addrs) == 0 {
		return netip.Addr{}, &stepError{"name lookup", ErrOutOfRange}
	}
	for _, a := range addrs {
		if !relayRange.Contains(a.Unmap()) {
			return netip.Addr{}, ErrOutOfRange
		}
	}
	return addrs[0].Unmap(), nil
}

// handshake runs socksConnect under ctx: its deadline, and closing the
// connection if ctx ends first. The deadline is cleared on success.
func handshake(ctx context.Context, conn net.Conn, host string, port uint16) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	err := socksConnect(conn, host, port)
	if !stop() && err == nil {
		err = ctx.Err()
	}
	if err != nil {
		var reply *ReplyError
		if errors.As(err, &reply) {
			return err
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		return &stepError{"handshake", err}
	}
	_ = conn.SetDeadline(time.Time{})
	return nil
}

// dialDirect is PIA's and NordVPN's way: the exit's current server, when it
// is in the location, and the target dialed through the dialer, its name
// resolved through the resolver (IPv4 only where the provider's tunnel
// carries no IPv6). Nothing is benched: a failure here is the target's or
// the tunnel's, and there is no other server to choose.
func (r *Relays) dialDirect(ctx context.Context, loc location, host string, port uint16) (net.Conn, string, error) {
	current := currentServer(r.cfg.ResultPath, r.cfg.Provider)
	if current == "" {
		return nil, "", ErrNoCurrent
	}
	if !loc.any {
		r.mu.Lock()
		r.refresh()
		i, ok := r.catalog.byName[current]
		var s server
		if ok {
			s = r.catalog.servers[i]
		}
		r.mu.Unlock()
		if !ok || !loc.matches(s) {
			return nil, "", ErrNoServer
		}
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		network := "ip4"
		if r.ipv6 {
			network = "ip"
		}
		if addrs, err = r.cfg.Resolver.LookupNetIP(ctx, network, host); err != nil {
			return nil, current, err
		}
	}
	var last error = ErrUnreachable
	for _, a := range addrs {
		if a.Is6() && !a.Is4In6() && !r.ipv6 {
			continue
		}
		conn, err := r.cfg.Dialer.DialContext(ctx, "tcp", netip.AddrPortFrom(a.Unmap(), port).String())
		if err == nil {
			r.mu.Lock()
			r.lastOK[current] = r.cfg.Now()
			r.mu.Unlock()
			return conn, current, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, current, ctx.Err()
		}
	}
	return nil, current, last
}
