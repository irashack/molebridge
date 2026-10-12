//go:build linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/tunnel/wgnl"
	"github.com/irashack/molebridge/internal/tunnelconf"
)

// Timeout bounds each kernel request made through a Manager that is not
// given an operation deadline of its own.
const Timeout = 10 * time.Second

// DefaultBudget bounds a whole call (Up, Down, Cleanup) made without a context
// that has a deadline.
const DefaultBudget = 20 * time.Second

// SampleBudget bounds a firewall-mark read: it must fit the two-second sample
// the gluetun backend's monitor takes.
const SampleBudget = 2 * time.Second

// cleanupBudget is what removing a half-built link may take even after the
// call's own deadline has passed: leaving the link behind is worse.
const cleanupBudget = 3 * time.Second

// Options say where a Manager operates.
type Options struct {
	// NetNS is a file descriptor of the network namespace to operate in; zero
	// is the calling thread's namespace.
	NetNS int
}

// routeAPI is the part of *rtnl.Conn the Manager uses.
type routeAPI interface {
	LinkByName(name string) (rtnl.Link, error)
	AddLink(name, kind string) error
	DelLink(index uint32) error
	SetLinkMTU(index, mtu uint32) error
	SetLinkUp(index uint32) error
	AddAddr(a rtnl.Addr) error
	ReplaceRoute(r rtnl.Route) error
	DelRoute(r rtnl.Route) error
	SetDeadline(t time.Time)
	Interrupt()
	Close() error
}

// wgAPI is the part of *wgnl.Conn the Manager uses.
type wgAPI interface {
	Device(ctx context.Context, name string) (*wgtypes.Device, error)
	Configure(ctx context.Context, name string, cfg wgtypes.Config) error
	Broken() bool
	Close() error
}

// Manager changes links, addresses, routes and WireGuard devices.
//
// Bounded I/O. Every kernel conversation is on a socket this package owns:
// the route socket (an *rtnl.Conn: links, addresses and MTU as rtnetlink
// requests, routes) and the WireGuard generic netlink socket (a *wgnl.Conn).
// Each call carries the operation's absolute deadline, set on the socket
// before the request is sent; if the context ends first the socket is
// closed, which unblocks a pending read, and the next call opens a fresh one.
// A reply cut off that way may mean the change was applied or not; the
// caller reads the state back. A call that does not return even after its
// socket is closed (a kernel stuck in the system call) is reported as
// rtnl.ErrStuck and its socket is abandoned for a new one.
//
// No library opens a socket the Manager cannot reach: wgctrl and
// vishvananda/netlink are not used by any of the operations above. The
// deprecated Wg, WgDo, LinkDo and Netlink accessors (legacy_linux.go) are the
// only places they remain.
type Manager struct {
	opts   Options
	dialRT func() (routeAPI, error)
	dialWG func(ctx context.Context) (wgAPI, error)

	opMu sync.Mutex // one route-socket operation at a time
	wgMu sync.Mutex // one WireGuard call at a time

	cmu    sync.Mutex // guards rt, wg, closed
	rt     routeAPI
	wg     wgAPI
	closed bool

	legacy
}

// Open opens the sockets.
func Open(o Options) (*Manager, error) {
	m := &Manager{opts: o}
	m.dialRT = func() (routeAPI, error) {
		c, err := rtnl.Dial(rtnl.Options{NetNS: o.NetNS})
		if err != nil {
			return nil, err
		}
		return c, nil
	}
	m.dialWG = func(ctx context.Context) (wgAPI, error) {
		c, err := wgnl.Dial(ctx, o.NetNS)
		if err != nil {
			if errors.Is(err, wgnl.ErrNoWireGuard) {
				return nil, fmt.Errorf("tunnel: the kernel has no WireGuard: %w", os.ErrNotExist)
			}
			return nil, fmt.Errorf("tunnel: open WireGuard netlink: %w", err)
		}
		return c, nil
	}
	// Fail early if the route socket or WireGuard netlink is unavailable.
	ctx, cancel := context.WithTimeout(context.Background(), DefaultBudget)
	defer cancel()
	if _, err := m.route(); err != nil {
		_ = m.Close()
		return nil, err
	}
	if err := m.wgCall(ctx, func(wgAPI) error { return nil }); err != nil {
		_ = m.Close()
		return nil, err
	}
	return m, nil
}

// Close closes the sockets, unblocking any call in flight.
func (m *Manager) Close() error {
	m.cmu.Lock()
	m.closed = true
	rt, wg := m.rt, m.wg
	m.rt, m.wg = nil, nil
	m.cmu.Unlock()
	var err error
	if wg != nil {
		err = wg.Close()
	}
	if rt != nil {
		if e := rt.Close(); err == nil {
			err = e
		}
	}
	if e := m.closeLegacy(); err == nil {
		err = e
	}
	return err
}

var errClosed = errors.New("tunnel: closed")

// route returns the live route socket, opening one if the last was abandoned.
func (m *Manager) route() (routeAPI, error) {
	m.cmu.Lock()
	defer m.cmu.Unlock()
	if m.closed {
		return nil, errClosed
	}
	if m.rt == nil {
		rt, err := m.dialRT()
		if err != nil {
			return nil, err
		}
		m.rt = rt
	}
	return m.rt, nil
}

func (m *Manager) dropRoute(rt routeAPI) {
	m.cmu.Lock()
	if m.rt == rt {
		m.rt = nil
	}
	m.cmu.Unlock()
	_ = rt.Close()
}

// budgeted gives ctx the default budget if it has no deadline.
func budgeted(ctx context.Context) (context.Context, context.CancelFunc) {
	return budgetedWith(ctx, DefaultBudget)
}

func budgetedWith(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}

func ctxErr(ctx context.Context) error {
	err := ctx.Err()
	if errors.Is(err, context.DeadlineExceeded) {
		return rtnl.ErrDeadline
	}
	return err
}

// rtDo runs a group of route-socket calls under ctx's absolute deadline,
// which is put on the socket before the first request. If ctx ends first the
// socket is closed under the call, which then fails; the next call finds a
// fresh socket. Callers hold opMu.
func (m *Manager) rtDo(ctx context.Context, fn func(routeAPI) error) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	rt, err := m.route()
	if err != nil {
		return err
	}
	dl, _ := ctx.Deadline() // zero clears it
	rt.SetDeadline(dl)
	err = rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, rt.Interrupt, func() error { return fn(rt) })
	if errors.Is(err, rtnl.ErrStuck) {
		m.dropRoute(rt)
	}
	return err
}

// RouteDo runs fn with the route socket under ctx's deadline (DefaultBudget
// if it has none). If the deadline passes first the socket is closed under
// the call and replaced for the next. fn must not keep the connection.
func (m *Manager) RouteDo(ctx context.Context, fn func(*rtnl.Conn) error) error {
	ctx, cancel := budgeted(ctx)
	defer cancel()
	m.opMu.Lock()
	defer m.opMu.Unlock()
	return m.rtDo(ctx, func(r routeAPI) error {
		c, ok := r.(*rtnl.Conn)
		if !ok {
			return errors.New("tunnel: the route socket is not an rtnl connection")
		}
		return fn(c)
	})
}

// wgFor returns the live WireGuard connection, dialling one under ctx if the
// last was closed at a deadline or after a failure.
func (m *Manager) wgFor(ctx context.Context) (wgAPI, error) {
	m.cmu.Lock()
	if m.closed {
		m.cmu.Unlock()
		return nil, errClosed
	}
	c := m.wg
	if c != nil && c.Broken() {
		m.wg = nil
		m.cmu.Unlock()
		_ = c.Close()
		c = nil
	} else {
		m.cmu.Unlock()
	}
	if c != nil {
		return c, nil
	}
	c, err := m.dialWG(ctx)
	if err != nil {
		return nil, err
	}
	m.cmu.Lock()
	defer m.cmu.Unlock()
	if m.closed {
		_ = c.Close()
		return nil, errClosed
	}
	m.wg = c
	return c, nil
}

func (m *Manager) dropWG(c wgAPI) {
	m.cmu.Lock()
	if m.wg == c {
		m.wg = nil
	}
	m.cmu.Unlock()
	_ = c.Close()
}

// wgCall runs a call on the WireGuard socket under ctx's deadline; the
// connection carries the deadline itself, and a call that outlasts it anyway
// (a kernel stuck in the system call) is abandoned with its socket.
func (m *Manager) wgCall(ctx context.Context, fn func(wgAPI) error) error {
	m.wgMu.Lock()
	defer m.wgMu.Unlock()
	if err := ctxErr(ctx); err != nil {
		return err
	}
	c, err := m.wgFor(ctx)
	if err != nil {
		return err
	}
	err = rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, func() { _ = c.Close() }, func() error { return fn(c) })
	if c.Broken() || ctx.Err() != nil {
		m.dropWG(c)
	}
	return err
}

// Device reads a WireGuard device under ctx's deadline (SampleBudget if it has
// none). A missing interface is an error for which errors.Is(err,
// os.ErrNotExist) holds.
func (m *Manager) Device(ctx context.Context, name string) (*wgtypes.Device, error) {
	ctx, cancel := budgetedWith(ctx, SampleBudget)
	defer cancel()
	var d *wgtypes.Device
	err := m.wgCall(ctx, func(c wgAPI) (e error) { d, e = c.Device(ctx, name); return })
	return d, err
}

// Configure applies a WireGuard configuration under ctx's deadline
// (DefaultBudget if it has none). A cut-off call may or may not have taken
// effect: read the device back.
func (m *Manager) Configure(ctx context.Context, name string, cfg wgtypes.Config) error {
	ctx, cancel := budgeted(ctx)
	defer cancel()
	return m.wgCall(ctx, func(c wgAPI) error { return c.Configure(ctx, name, cfg) })
}

// Params describe the tunnel to bring up.
type Params struct {
	ExitIf string
	Conf   *tunnelconf.Conf
}

func notFound(err error) bool {
	return rtnl.IsNotExist(err) || errors.Is(err, syscall.ENODEV) || errors.Is(err, os.ErrNotExist)
}

// Up makes one attempt to bring the tunnel up; see UpContext.
func (m *Manager) Up(p Params) error { return m.UpContext(context.Background(), p) }

// UpContext makes one attempt to bring the tunnel up: a leftover link of the
// same name is removed, a wireguard link is created and configured, and the
// exit table's default route goes in. Every call ends by ctx's deadline
// (DefaultBudget if it has none), and ctx is checked between calls. On any
// failure the half-built link is removed, even if the deadline has passed, so
// the next attempt starts clean; the exit table keeps its unreachable fallback
// throughout. No error carries key material.
func (m *Manager) UpContext(ctx context.Context, p Params) (err error) {
	if p.Conf == nil {
		return errors.New("tunnel: no config")
	}
	ctx, cancel := budgeted(ctx)
	defer cancel()
	m.opMu.Lock()
	defer m.opMu.Unlock()
	var link rtnl.Link
	defer func() {
		if err != nil {
			// Whatever the deadline says, the half-built link comes out.
			rctx, rcancel := context.WithTimeout(context.Background(), cleanupBudget)
			defer rcancel()
			_ = m.rtDo(rctx, func(r routeAPI) error {
				if l, lerr := r.LinkByName(p.ExitIf); lerr == nil {
					return r.DelLink(l.Index)
				}
				return nil
			})
		}
	}()
	err = m.rtDo(ctx, func(r routeAPI) error {
		if old, lerr := r.LinkByName(p.ExitIf); lerr == nil {
			if derr := r.DelLink(old.Index); derr != nil && !notFound(derr) {
				return fmt.Errorf("tunnel: remove the old %s link: %w", p.ExitIf, derr)
			}
		} else if !notFound(lerr) {
			return fmt.Errorf("tunnel: look up %s: %w", p.ExitIf, lerr)
		}
		if err := r.AddLink(p.ExitIf, "wireguard"); err != nil {
			return fmt.Errorf("tunnel: create the wireguard link %s: %w", p.ExitIf, err)
		}
		var lerr error
		if link, lerr = r.LinkByName(p.ExitIf); lerr != nil {
			return fmt.Errorf("tunnel: look up %s: %w", p.ExitIf, lerr)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err = m.configure(ctx, p); err != nil {
		return err
	}
	err = m.rtDo(ctx, func(r routeAPI) error {
		for _, a := range []netip.Addr{p.Conf.Addr4, p.Conf.Addr6} {
			if !a.IsValid() {
				continue
			}
			if err := r.AddAddr(rtnl.HostAddr(link.Index, a)); err != nil {
				return fmt.Errorf("tunnel: assign an address to %s: %w", p.ExitIf, err)
			}
		}
		if err := r.SetLinkMTU(link.Index, uint32(p.Conf.MTU)); err != nil {
			return fmt.Errorf("tunnel: set the MTU of %s: %w", p.ExitIf, err)
		}
		if err := r.SetLinkUp(link.Index); err != nil {
			return fmt.Errorf("tunnel: bring %s up: %w", p.ExitIf, err)
		}
		// The PostUp hook: `ip route replace default dev %i table N`, per family.
		for _, op := range p.Conf.UpRoutes() {
			if err := r.ReplaceRoute(contract.TunnelRoute(op.Family, op.Table, link.Index)); err != nil {
				return fmt.Errorf("tunnel: route %s through %s: %w", op.Family, p.ExitIf, err)
			}
		}
		return nil
	})
	return err
}

// configure sets the private key and, for a config that carries one, the peer.
func (m *Manager) configure(ctx context.Context, p Params) error {
	key := wgtypes.Key(p.Conf.PrivateKey)
	cfg := wgtypes.Config{PrivateKey: &key, ReplacePeers: true}
	if peer := p.Conf.Peer; peer != nil {
		pc := wgtypes.PeerConfig{
			PublicKey:         wgtypes.Key(peer.PublicKey),
			Endpoint:          net.UDPAddrFromAddrPort(peer.Endpoint),
			ReplaceAllowedIPs: true,
		}
		for _, pref := range peer.AllowedIPs {
			_, n, err := net.ParseCIDR(pref.String())
			if err != nil {
				return fmt.Errorf("tunnel: peer allowed IPs: %w", err)
			}
			pc.AllowedIPs = append(pc.AllowedIPs, *n)
		}
		if peer.Keepalive > 0 {
			d := time.Duration(peer.Keepalive) * time.Second
			pc.PersistentKeepaliveInterval = &d
		}
		cfg.Peers = []wgtypes.PeerConfig{pc}
	}
	if err := m.wgCall(ctx, func(c wgAPI) error { return c.Configure(ctx, p.ExitIf, cfg) }); err != nil {
		return fmt.Errorf("tunnel: configure %s: %w", p.ExitIf, err)
	}
	return nil
}

// Down is `wg-quick down`; see DownContext.
func (m *Manager) Down(p Params) error { return m.DownContext(context.Background(), p) }

// DownContext is `wg-quick down`: the PreDown routes come out, then the link.
// A missing link or route is not an error. The rules and the unreachable
// fallback stay: the namespace stays fail-closed whatever happens to the
// tunnel.
func (m *Manager) DownContext(ctx context.Context, p Params) error {
	ctx, cancel := budgeted(ctx)
	defer cancel()
	m.opMu.Lock()
	defer m.opMu.Unlock()
	err := m.rtDo(ctx, func(r routeAPI) error {
		link, err := r.LinkByName(p.ExitIf)
		if err != nil {
			if notFound(err) {
				return nil
			}
			return fmt.Errorf("tunnel: look up %s: %w", p.ExitIf, err)
		}
		if p.Conf != nil {
			for _, op := range p.Conf.DownRoutes() {
				err := r.DelRoute(rtnl.Route{Family: op.Family, Dst: defaultPrefix(op.Family), Table: op.Table, Type: rtnl.RTNUnicast,
					Oif: rtnl.Some(link.Index)})
				if err != nil && !rtnl.IsNotExist(err) {
					return fmt.Errorf("tunnel: remove the %s route through %s: %w", op.Family, p.ExitIf, err)
				}
			}
		}
		if err := r.DelLink(link.Index); err != nil && !notFound(err) {
			return fmt.Errorf("tunnel: delete %s: %w", p.ExitIf, err)
		}
		return nil
	})
	return err
}

func defaultPrefix(f rtnl.Family) netip.Prefix {
	if f == rtnl.V6 {
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
}

// Cleanup is the independent cleanup; see CleanupContext.
func (m *Manager) Cleanup(backend contract.Backend, exitIf, overlayIf string) error {
	return m.CleanupContext(context.Background(), backend, exitIf, overlayIf)
}

// CleanupContext is the independent cleanup the supervisor runs after the
// worker is gone: the native backend deletes Molebridge's tunnel link and
// NetBird's overlay link (a kernel WireGuard interface can keep forwarding in
// a namespace another container holds); the gluetun backend deletes only the
// overlay link and never touches gluetun's tunnel, which is not ours. Every
// rule and the unreachable fallback stay in place. A link that is not there
// is fine; one that is still there afterwards is an error. Every call ends by
// ctx's deadline (DefaultBudget if it has none).
func (m *Manager) CleanupContext(ctx context.Context, backend contract.Backend, exitIf, overlayIf string) error {
	ctx, cancel := budgeted(ctx)
	defer cancel()
	m.opMu.Lock()
	defer m.opMu.Unlock()
	names := []string{overlayIf}
	if backend == contract.Native {
		names = []string{exitIf, overlayIf}
	}
	var failed []string
	for _, name := range names {
		err := m.rtDo(ctx, func(r routeAPI) error {
			l, err := r.LinkByName(name)
			if err != nil {
				if notFound(err) {
					return nil
				}
				return err
			}
			if err := r.DelLink(l.Index); err != nil && !notFound(err) {
				return err
			}
			if _, err := r.LinkByName(name); err == nil {
				return fmt.Errorf("%s remains", name)
			}
			return nil
		})
		if err != nil {
			failed = append(failed, name)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("tunnel: cleanup incomplete: the %v interface(s) remain", failed)
	}
	return nil
}

// ErrNoDevice says the WireGuard interface does not exist.
var ErrNoDevice = errors.New("tunnel: no such WireGuard interface")

// Fwmark reads a WireGuard interface's firewall mark within SampleBudget; see
// FwmarkContext.
func (m *Manager) Fwmark(name string) (uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), SampleBudget)
	defer cancel()
	return m.FwmarkContext(ctx, name)
}

// FwmarkContext reads a WireGuard interface's firewall mark, which is what the
// gluetun backend checks NetBird's overlay interface for (the control mark).
// A missing interface is ErrNoDevice. The read ends by ctx's deadline
// (SampleBudget if it has none) even if the kernel never answers: the socket
// is closed and replaced.
func (m *Manager) FwmarkContext(ctx context.Context, name string) (uint32, error) {
	d, err := m.Device(ctx, name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && ctx.Err() == nil {
			return 0, ErrNoDevice
		}
		return 0, fmt.Errorf("tunnel: read %s: %w", name, err)
	}
	return uint32(d.FirewallMark), nil
}
