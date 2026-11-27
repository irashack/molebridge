// Package proxy is the core of `molebridge proxy` (docs/design/menu.md, "The
// proxy"): one listener that takes SOCKS5 (RFC 1928 CONNECT, RFC 1929
// username and password) and HTTP CONNECT from programs that opt in, and
// opens each connection through an Upstream.
//
// Its guarantee: every connection the proxy opens leaves through the tunnel,
// or fails. It promises nothing about traffic not sent to it. This package
// opens no outbound connection itself: every one goes through
// Config.Upstream (internal/relayproxy, over the tunnel dialer), and while
// the exit's verdict is not "ok" new connections are refused before the
// Upstream is asked.
//
// The package offers Serve and Config, the Upstream interface and
// ServerState it is built against, CheckListen, ReadPassword, ParseUsername,
// TunnelState with ResultGate (the exit's verdict from its result.json) and
// the status record, proxy.json (status.go), which internal/verdict judges
// with AssessProxy. The role `molebridge proxy` (cmd/molebridge/role_proxy.go)
// runs it over internal/relayproxy and internal/tunneldial.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/irashack/molebridge/internal/relayproxy"
)

// Upstream opens the proxy's connections (internal/relayproxy implements it).
type Upstream interface {
	// Dial opens a connection to target ("host:port") through a server in
	// location, preferring pinned when it is set and not benched. It returns
	// the server used.
	Dial(ctx context.Context, location, pinned, target string) (conn net.Conn, server string, err error)
	Servers() []ServerState // for the status record
}

// ServerState is one server as the Upstream knows it: relayproxy's own type,
// so that *relayproxy.Relays is an Upstream as it is (relayproxy imports
// nothing of this package).
type ServerState = relayproxy.ServerState

// Defaults.
const (
	DefaultListen           = "127.0.0.1:1080"
	DefaultMaxConns         = 512
	DefaultHandshakeTimeout = 10 * time.Second
	DefaultStatusInterval   = 10 * time.Second
	// SessionTTL: a session keeps its server while it has been used within
	// this long.
	SessionTTL = 30 * time.Minute
	// maxHandshakeBytes bounds what is read from a client before its
	// connection is open: the HTTP request with its headers, or the SOCKS5
	// greeting, authentication and request (at most about 1.1 KiB).
	maxHandshakeBytes = 8192
	// dialTimeout bounds one Upstream.Dial, whatever the Upstream's own
	// timeouts are.
	dialTimeout = 30 * time.Second
)

// Config is what Serve needs. Listen, PasswordFile, Upstream and Tunnel are
// required; the rest have defaults.
type Config struct {
	// Listen is the address to listen on (PROXY_LISTEN): an IP literal and a
	// port, the IP loopback or one of Interface's addresses.
	Listen string
	// Interface is the NetBird interface whose addresses may be listened on;
	// empty allows loopback only.
	Interface string
	// InterfaceAddrs returns an interface's addresses; nil uses the system's.
	InterfaceAddrs func(name string) ([]net.Addr, error)
	// PasswordFile holds the password (PROXY_PASSWORD_FILE).
	PasswordFile string
	// MaxConns bounds the open client connections (PROXY_MAX_CONNS).
	MaxConns int
	// MaxConnsPerClient bounds the open connections from one client address
	// (PROXY_MAX_CONNS_PER_CLIENT); zero is no bound beyond MaxConns.
	MaxConnsPerClient int
	// IdleTimeout closes an open connection that has carried nothing either
	// way for this long (PROXY_IDLE_TIMEOUT); zero never does.
	IdleTimeout time.Duration
	// HandshakeTimeout bounds a client's handshake, from accept to the
	// request read.
	HandshakeTimeout time.Duration
	Upstream         Upstream
	// Tunnel is the exit's verdict now (ResultGate); new connections are
	// refused while its Verdict is not "ok".
	Tunnel func() TunnelState
	// Provider is the exit's provider, for the status record.
	Provider string
	// StatusPath is where proxy.json is written; empty writes none.
	StatusPath string
	// StatusInterval is how often proxy.json is rewritten.
	StatusInterval time.Duration
	// Now is the wall clock; nil is time.Now.
	Now func() time.Time
	// Logf logs one line; nil logs nothing. Nothing logged carries a
	// password, a username or a target.
	Logf func(format string, args ...any)
}

func (c *Config) defaults() {
	if c.MaxConns <= 0 {
		c.MaxConns = DefaultMaxConns
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if c.StatusInterval <= 0 {
		c.StatusInterval = DefaultStatusInterval
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
}

// server is one running proxy.
type server struct {
	cfg      Config
	password []byte
	sessions *sessions
	slots    chan struct{}
	kick     chan struct{} // asks the status loop to look for a bench change

	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	perClient map[string]int // open connections by client address, with MaxConnsPerClient
	wg        sync.WaitGroup

	open, total, failed atomic.Int64
	// overClient counts connections closed at accept for their client's
	// bound; idleClosed, open connections closed by IdleTimeout.
	overClient, idleClosed atomic.Int64
}

// Serve checks cfg (the listen address and the password file), listens and
// serves until ctx ends or the listener fails. It returns nil when ctx ended,
// and otherwise the reason it could not start or stopped. While it runs it
// publishes proxy.json; when it returns the record says "failed".
func Serve(ctx context.Context, cfg Config) error {
	s, err := newServer(cfg)
	if err != nil {
		return err
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.cfg.Listen)
	if err != nil {
		s.publish("failed", "The listener is down.")
		return fmt.Errorf("proxy: listen: %w", err)
	}
	s.cfg.Logf("proxy: listening on %s", ln.Addr())
	return s.run(ctx, ln)
}

// newServer checks cfg (the listen address and the password file) and fills
// in its defaults.
func newServer(cfg Config) (*server, error) {
	cfg.defaults()
	if cfg.Upstream == nil || cfg.Tunnel == nil {
		return nil, errors.New("proxy: no upstream or tunnel state configured")
	}
	// Both are checked, so a refusal names every problem at once.
	listenErr := CheckListen(cfg.Listen, cfg.Interface, cfg.InterfaceAddrs)
	password, err := ReadPassword(cfg.PasswordFile)
	if err := errors.Join(listenErr, err); err != nil {
		return nil, err
	}
	return &server{
		cfg:       cfg,
		password:  password,
		sessions:  newSessions(cfg.Now),
		slots:     make(chan struct{}, cfg.MaxConns),
		kick:      make(chan struct{}, 1),
		conns:     map[net.Conn]struct{}{},
		perClient: map[string]int{},
	}, nil
}

// run serves ln until ctx ends or Accept fails for good.
func (s *server) run(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	statusDone := make(chan struct{})
	go func() {
		defer close(statusDone)
		s.statusLoop(ctx)
	}()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	var acceptErr error
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			acceptErr = fmt.Errorf("proxy: accept: %w", err)
			break
		}
		s.total.Add(1)
		client := clientKey(conn.RemoteAddr())
		if !s.admitClient(client) {
			// Over PROXY_MAX_CONNS_PER_CLIENT: closed before anything is
			// read, and without taking one of the shared slots.
			s.failed.Add(1)
			s.overClient.Add(1)
			conn.Close()
			continue
		}
		select {
		case s.slots <- struct{}{}:
		default:
			// Over PROXY_MAX_CONNS: closed before anything is read.
			s.releaseClient(client)
			s.failed.Add(1)
			conn.Close()
			continue
		}
		s.track(conn, true)
		s.open.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.releaseClient(client)
			defer func() { <-s.slots }()
			defer s.open.Add(-1)
			defer s.track(conn, false)
			s.handle(ctx, conn)
		}()
	}
	cancel()
	ln.Close()
	// Open connections end with the proxy.
	s.mu.Lock()
	for c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	<-statusDone
	if acceptErr != nil {
		s.cfg.Logf("proxy: %v", acceptErr)
		s.publish("failed", "The listener is down.")
		return acceptErr
	}
	s.publish("failed", "The proxy stopped.")
	return nil
}

// track keeps the connections the proxy closes when it stops; a connection
// is closed when it is dropped.
func (s *server) track(c net.Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
		c.Close()
	}
}

// clientKey is the client a connection is counted against for
// MaxConnsPerClient: its IP address, without the port. Programs on one host
// share an address, so they share its bound.
func clientKey(addr net.Addr) string {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		return tcp.IP.String()
	}
	if addr == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

// admitClient counts one more open connection for client, or reports false
// when that would pass MaxConnsPerClient.
func (s *server) admitClient(client string) bool {
	if s.cfg.MaxConnsPerClient <= 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perClient[client] >= s.cfg.MaxConnsPerClient {
		return false
	}
	s.perClient[client]++
	return true
}

// releaseClient counts one connection of client's as closed.
func (s *server) releaseClient(client string) {
	if s.cfg.MaxConnsPerClient <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perClient[client] <= 1 {
		delete(s.perClient, client)
		return
	}
	s.perClient[client]--
}

// clients is the number of client addresses with an open connection
// (counted only while MaxConnsPerClient is set).
func (s *server) clients() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.perClient)
}

// request is a client's handshake, read and authenticated.
type request struct {
	location, session, target string
}

// handshake is one protocol's side of a connection.
type handshake interface {
	// read reads and authenticates the request. A false result means the
	// connection is done (the reply, if any, has been written).
	read() (request, bool)
	// refuse answers a request the proxy will not open: the tunnel is not
	// ok, or the Upstream failed with err (nil for the tunnel).
	refuse(err error)
	// ready answers that the connection is open.
	ready() error
}

// handle serves one client connection.
func (s *server) handle(ctx context.Context, conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout)) // a socket deadline: the real clock
	br := bufio.NewReaderSize(&io.LimitedReader{R: conn, N: maxHandshakeBytes}, 4096)
	first, err := br.Peek(1)
	if err != nil {
		s.failed.Add(1)
		return
	}
	var h handshake
	switch {
	case first[0] == socksVersion:
		h = &socksConn{conn: conn, br: br, s: s}
	case first[0] >= 'A' && first[0] <= 'Z':
		h = &httpConn{conn: conn, br: br, s: s}
	default:
		s.failed.Add(1)
		return
	}
	req, ok := h.read()
	if !ok {
		s.failed.Add(1)
		return
	}
	// The handshake's deadline ends with the request; the dial has its own,
	// and the reply gets a fresh one.
	_ = conn.SetDeadline(time.Time{})
	replyDeadline := func() { _ = conn.SetWriteDeadline(time.Now().Add(s.cfg.HandshakeTimeout)) }
	if t := s.cfg.Tunnel(); t.Verdict != "ok" {
		replyDeadline()
		h.refuse(nil)
		s.failed.Add(1)
		return
	}
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	pinned, chosen := s.sessions.acquire(dctx, req.location, req.session)
	up, used, err := s.cfg.Upstream.Dial(dctx, req.location, pinned, req.target)
	cancel()
	chosen(used)
	s.kickStatus()
	replyDeadline()
	if err != nil {
		h.refuse(err)
		s.failed.Add(1)
		return
	}
	defer up.Close()
	if err := h.ready(); err != nil {
		s.failed.Add(1)
		return
	}
	_ = conn.SetWriteDeadline(time.Time{})
	// Whatever the client sent after its request is the connection's first
	// bytes.
	if n := br.Buffered(); n > 0 {
		pending, _ := br.Peek(n)
		if _, err := up.Write(pending); err != nil {
			return
		}
	}
	s.track(up, true)
	defer s.track(up, false)
	if pipe(conn, up, s.cfg.IdleTimeout) {
		s.idleClosed.Add(1)
	}
}

// pipe copies both ways until both are done. A clean end of one direction
// is passed on as a half-close; an error closes both. With idle above zero,
// both are closed once nothing has been read either way for that long, and
// pipe reports true.
func pipe(client, upstream net.Conn, idle time.Duration) (idled bool) {
	var watch *idleWatch
	if idle > 0 {
		watch = newIdleWatch(idle, func() {
			client.Close()
			upstream.Close()
		})
		defer watch.stop()
	}
	var wg sync.WaitGroup
	wg.Add(2)
	one := func(dst, src net.Conn) {
		defer wg.Done()
		var r io.Reader = src
		if watch != nil {
			r = watch.reader(src)
		}
		if _, err := io.Copy(dst, r); err != nil {
			client.Close()
			upstream.Close()
			return
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			if cw.CloseWrite() == nil {
				return
			}
		}
		client.Close()
		upstream.Close()
	}
	go one(upstream, client)
	go one(client, upstream)
	wg.Wait()
	return watch != nil && watch.fired()
}

// idleWatch closes a connection that has been idle too long: every read
// through one of its readers is activity, and a timer looks again when the
// last activity is idle old.
type idleWatch struct {
	idle    time.Duration
	last    atomic.Int64 // unix nanoseconds of the last read (the real clock: socket time)
	idled   atomic.Bool
	timer   *time.Timer
	onIdle  func()
	stopped atomic.Bool
}

func newIdleWatch(idle time.Duration, onIdle func()) *idleWatch {
	w := &idleWatch{idle: idle, onIdle: onIdle}
	w.last.Store(time.Now().UnixNano())
	w.timer = time.AfterFunc(idle, w.check)
	return w
}

func (w *idleWatch) check() {
	if w.stopped.Load() {
		return
	}
	since := time.Since(time.Unix(0, w.last.Load()))
	if since >= w.idle {
		w.idled.Store(true)
		w.onIdle()
		return
	}
	w.timer.Reset(w.idle - since)
}

func (w *idleWatch) stop() {
	w.stopped.Store(true)
	w.timer.Stop()
}

func (w *idleWatch) fired() bool { return w.idled.Load() }

// reader is r with every read that returns bytes counted as activity. (It
// hides r's own fast paths from io.Copy, which is why it is used only with
// an idle timeout.)
func (w *idleWatch) reader(r io.Reader) io.Reader { return activityReader{r: r, w: w} }

type activityReader struct {
	r io.Reader
	w *idleWatch
}

func (a activityReader) Read(p []byte) (int, error) {
	n, err := a.r.Read(p)
	if n > 0 {
		a.w.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func (s *server) kickStatus() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}
