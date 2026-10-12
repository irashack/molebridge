//go:build linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
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

// wgClient is the part of *wgctrl.Client the Manager uses.
type wgClient interface {
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Device(name string) (*wgtypes.Device, error)
	Close() error
}

// Manager holds the netlink sockets the tunnel operations use.
//
// Bounded I/O. The link handle and the route socket take deadlines and get
// the operation's. The WireGuard connection has none, so every call on it runs
// under rtnl.RunBounded: at the deadline the connection is closed, which
// unblocks its read, and is discarded; the next call opens a fresh one. A
// reply cut off that way may mean the change was applied or not; the caller
// reads the state back.
type Manager struct {
	h  *netlink.Handle
	rt *rtnl.Conn

	open   func() (wgClient, error)
	callMu sync.Mutex // one WireGuard call at a time
	cmu    sync.Mutex // guards wg
	wg     wgClient
	closed bool
}

// Open opens the sockets.
func Open(o Options) (*Manager, error) {
	var (
		h   *netlink.Handle
		err error
	)
	if o.NetNS != 0 {
		h, err = netlink.NewHandleAt(netns.NsHandle(o.NetNS))
	} else {
		h, err = netlink.NewHandle()
	}
	if err != nil {
		return nil, fmt.Errorf("tunnel: open netlink: %w", err)
	}
	_ = h.SetSocketTimeout(Timeout)
	rt, err := rtnl.Dial(rtnl.Options{NetNS: o.NetNS})
	if err != nil {
		h.Close()
		return nil, err
	}
	m := &Manager{h: h, rt: rt, open: func() (wgClient, error) {
		// A generic netlink socket belongs to the namespace of the thread that
		// opens it.
		var c *wgctrl.Client
		err := inNamespace(o.NetNS, func() error {
			var err error
			c, err = wgctrl.New()
			return err
		})
		if err != nil {
			return nil, fmt.Errorf("tunnel: open WireGuard netlink: %w", err)
		}
		return c, nil
	}}
	// Fail early if WireGuard netlink is unavailable.
	ctx, cancel := context.WithTimeout(context.Background(), DefaultBudget)
	defer cancel()
	if err := m.wgDo(ctx, func(wgClient) error { return nil }); err != nil {
		_ = m.Close()
		return nil, err
	}
	return m, nil
}

// inNamespace runs fn on a thread that is in the namespace (when fd is set).
func inNamespace(fd int, fn func() error) error {
	if fd == 0 {
		return fn()
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		return err
	}
	defer orig.Close()
	if err := netns.Set(netns.NsHandle(fd)); err != nil {
		return err
	}
	defer func() { _ = netns.Set(orig) }()
	return fn()
}

// Close closes the sockets, unblocking any call in flight.
func (m *Manager) Close() error {
	m.cmu.Lock()
	m.closed = true
	c := m.wg
	m.wg = nil
	m.cmu.Unlock()
	if m.h != nil {
		m.h.Close()
	}
	var err error
	if c != nil {
		err = c.Close()
	}
	if m.rt != nil {
		if e := m.rt.Close(); err == nil {
			err = e
		}
	}
	return err
}

// discard drops a WireGuard connection that was cut off.
func (m *Manager) discard(c wgClient) {
	m.cmu.Lock()
	if m.wg == c {
		m.wg = nil
	}
	m.cmu.Unlock()
	_ = c.Close()
}

// wgDo runs a call on the WireGuard connection, opening one if needed, under
// the context's deadline.
func (m *Manager) wgDo(ctx context.Context, fn func(wgClient) error) error {
	m.callMu.Lock()
	defer m.callMu.Unlock()
	m.cmu.Lock()
	if m.closed {
		m.cmu.Unlock()
		return errors.New("tunnel: closed")
	}
	c := m.wg
	m.cmu.Unlock()
	if c == nil {
		var opened wgClient
		err := rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, func() {}, func() error {
			var err error
			opened, err = m.open()
			return err
		})
		if err != nil {
			return err
		}
		m.cmu.Lock()
		if m.closed {
			m.cmu.Unlock()
			_ = opened.Close()
			return errors.New("tunnel: closed")
		}
		m.wg, c = opened, opened
		m.cmu.Unlock()
	}
	err := rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, func() { m.discard(c) }, func() error { return fn(c) })
	if ctx.Err() != nil {
		m.discard(c)
	}
	return err
}

// budgeted gives ctx the default budget if it has no deadline.
func budgeted(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, DefaultBudget)
}

// begin readies the netlink sockets for an operation under ctx: one absolute
// deadline for the route socket, and the time left for the link handle.
func (m *Manager) begin(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return rtnl.ErrDeadline
		}
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		m.rt.SetDeadline(dl)
		left := time.Until(dl)
		if left > Timeout {
			left = Timeout
		}
		if left < time.Millisecond {
			left = time.Millisecond
		}
		_ = m.h.SetSocketTimeout(left)
	}
	return nil
}

// Params describe the tunnel to bring up.
type Params struct {
	ExitIf string
	Conf   *tunnelconf.Conf
}

func prefixOf(a netip.Addr) *net.IPNet {
	return &net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(a.BitLen(), a.BitLen())}
}

func notFound(err error) bool {
	var nf netlink.LinkNotFoundError
	return errors.As(err, &nf) || errors.Is(err, syscall.ENODEV) || errors.Is(err, os.ErrNotExist)
}

// Up makes one attempt to bring the tunnel up; see UpContext.
func (m *Manager) Up(p Params) error { return m.UpContext(context.Background(), p) }

// UpContext makes one attempt to bring the tunnel up: a leftover link of the
// same name is removed, a wireguard link is created and configured, and the
// exit table's default route goes in. Every request ends by ctx's deadline
// (DefaultBudget if it has none) and ctx is checked between requests. On any
// failure the half-built link is removed, even if the deadline has passed, so
// the next attempt starts clean; the exit table keeps its unreachable
// fallback throughout. No error carries key material.
func (m *Manager) UpContext(ctx context.Context, p Params) (err error) {
	if p.Conf == nil {
		return errors.New("tunnel: no config")
	}
	ctx, cancel := budgeted(ctx)
	defer cancel()
	defer m.rt.SetDeadline(time.Time{})
	step := func() error { return m.begin(ctx) }
	if err := step(); err != nil {
		return err
	}
	if old, lerr := m.h.LinkByName(p.ExitIf); lerr == nil {
		if derr := m.h.LinkDel(old); derr != nil && !notFound(derr) {
			return fmt.Errorf("tunnel: remove the old %s link: %w", p.ExitIf, derr)
		}
	} else if !notFound(lerr) {
		return fmt.Errorf("tunnel: look up %s: %w", p.ExitIf, lerr)
	}
	if err := step(); err != nil {
		return err
	}
	if err := m.h.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: p.ExitIf}}); err != nil {
		return fmt.Errorf("tunnel: create the wireguard link %s: %w", p.ExitIf, err)
	}
	defer func() {
		if err != nil {
			// Whatever the deadline says, the half-built link comes out.
			rctx, rcancel := context.WithTimeout(context.Background(), cleanupBudget)
			defer rcancel()
			_ = m.begin(rctx)
			if l, lerr := m.h.LinkByName(p.ExitIf); lerr == nil {
				_ = m.h.LinkDel(l)
			}
		}
	}()
	link, err := m.h.LinkByName(p.ExitIf)
	if err != nil {
		return fmt.Errorf("tunnel: look up %s: %w", p.ExitIf, err)
	}
	if err = step(); err != nil {
		return err
	}
	if err = m.configure(ctx, p); err != nil {
		return err
	}
	for _, a := range []netip.Addr{p.Conf.Addr4, p.Conf.Addr6} {
		if !a.IsValid() {
			continue
		}
		if err = step(); err != nil {
			return err
		}
		if err = m.h.AddrAdd(link, &netlink.Addr{IPNet: prefixOf(a)}); err != nil {
			return fmt.Errorf("tunnel: assign an address to %s: %w", p.ExitIf, err)
		}
	}
	if err = step(); err != nil {
		return err
	}
	if err = m.h.LinkSetMTU(link, p.Conf.MTU); err != nil {
		return fmt.Errorf("tunnel: set the MTU of %s: %w", p.ExitIf, err)
	}
	if err = step(); err != nil {
		return err
	}
	if err = m.h.LinkSetUp(link); err != nil {
		return fmt.Errorf("tunnel: bring %s up: %w", p.ExitIf, err)
	}
	// The PostUp hook: `ip route replace default dev %i table N`, per family.
	for _, op := range p.Conf.UpRoutes() {
		if err = step(); err != nil {
			return err
		}
		if err = m.rt.ReplaceRoute(contract.TunnelRoute(op.Family, op.Table, uint32(link.Attrs().Index))); err != nil {
			return fmt.Errorf("tunnel: route %s through %s: %w", op.Family, p.ExitIf, err)
		}
	}
	return nil
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
	err := m.wgDo(ctx, func(c wgClient) error { return c.ConfigureDevice(p.ExitIf, cfg) })
	if err != nil {
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
	defer m.rt.SetDeadline(time.Time{})
	if err := m.begin(ctx); err != nil {
		return err
	}
	link, err := m.h.LinkByName(p.ExitIf)
	if err != nil {
		if notFound(err) {
			return nil
		}
		return fmt.Errorf("tunnel: look up %s: %w", p.ExitIf, err)
	}
	if p.Conf != nil {
		for _, op := range p.Conf.DownRoutes() {
			if err := m.begin(ctx); err != nil {
				return err
			}
			err := m.rt.DelRoute(rtnl.Route{Family: op.Family, Dst: defaultPrefix(op.Family), Table: op.Table, Type: rtnl.RTNUnicast,
				Oif: rtnl.Some(uint32(link.Attrs().Index))})
			if err != nil && !rtnl.IsNotExist(err) {
				return fmt.Errorf("tunnel: remove the %s route through %s: %w", op.Family, p.ExitIf, err)
			}
		}
	}
	if err := m.begin(ctx); err != nil {
		return err
	}
	if err := m.h.LinkDel(link); err != nil && !notFound(err) {
		return fmt.Errorf("tunnel: delete %s: %w", p.ExitIf, err)
	}
	return nil
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
// is fine; one that is still there afterwards is an error. Every request ends
// by ctx's deadline (DefaultBudget if it has none).
func (m *Manager) CleanupContext(ctx context.Context, backend contract.Backend, exitIf, overlayIf string) error {
	ctx, cancel := budgeted(ctx)
	defer cancel()
	names := []string{overlayIf}
	if backend == contract.Native {
		names = []string{exitIf, overlayIf}
	}
	var failed []string
	for _, name := range names {
		if err := m.begin(ctx); err != nil {
			failed = append(failed, name)
			continue
		}
		l, err := m.h.LinkByName(name)
		if err != nil {
			if !notFound(err) {
				failed = append(failed, name)
			}
			continue
		}
		if err := m.h.LinkDel(l); err != nil && !notFound(err) {
			failed = append(failed, name)
			continue
		}
		if _, err := m.h.LinkByName(name); err == nil {
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
// A missing interface is ErrNoDevice. The read ends by ctx's deadline even if
// the kernel never answers: the connection is closed, discarded and replaced.
func (m *Manager) FwmarkContext(ctx context.Context, name string) (uint32, error) {
	var mark uint32
	err := m.wgDo(ctx, func(c wgClient) error {
		d, err := c.Device(name)
		if err != nil {
			return err
		}
		mark = uint32(d.FirewallMark)
		return nil
	})
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && ctx.Err() == nil {
			return 0, ErrNoDevice
		}
		return 0, fmt.Errorf("tunnel: read %s: %w", name, err)
	}
	return mark, nil
}

// Wg returns a WireGuard client for the peer changes and handshake reads of
// the provider code. Its calls have no deadline of their own: prefer WgDo.
func (m *Manager) Wg() *wgctrl.Client {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultBudget)
	defer cancel()
	var out *wgctrl.Client
	_ = m.wgDo(ctx, func(c wgClient) error { out, _ = c.(*wgctrl.Client); return nil })
	return out
}

// WgDo runs fn with the WireGuard client under ctx's deadline (DefaultBudget
// if it has none). If the deadline passes first the connection is closed and
// replaced, fn's call fails, and WgDo returns a deadline error; the caller
// reads the device back to learn whether a mutation took effect.
func (m *Manager) WgDo(ctx context.Context, fn func(*wgctrl.Client) error) error {
	ctx, cancel := budgeted(ctx)
	defer cancel()
	return m.wgDo(ctx, func(c wgClient) error {
		real, ok := c.(*wgctrl.Client)
		if !ok {
			return errors.New("tunnel: not a wgctrl client")
		}
		return fn(real)
	})
}

// Netlink returns the link handle.
func (m *Manager) Netlink() *netlink.Handle { return m.h }
