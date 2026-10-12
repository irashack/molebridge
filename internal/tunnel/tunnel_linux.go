//go:build linux

package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/mdlayher/netlink"
	vnetlink "github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
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

// openGrace is how long a call waits for a connection that is still being
// opened after its deadline.
const openGrace = 50 * time.Millisecond

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

// linkAPI is the part of *vishvananda/netlink.Handle the Manager uses.
type linkAPI interface {
	LinkByName(name string) (vnetlink.Link, error)
	LinkAdd(l vnetlink.Link) error
	LinkDel(l vnetlink.Link) error
	LinkSetMTU(l vnetlink.Link, mtu int) error
	LinkSetUp(l vnetlink.Link) error
	AddrAdd(l vnetlink.Link, a *vnetlink.Addr) error
	Close()
}

// Manager holds the netlink sockets the tunnel operations use.
//
// Bounded I/O. The route socket takes an absolute deadline, and it is set. The
// link handle's library restarts a relative timeout at every receive, and the
// WireGuard library takes none: both are used only under rtnl.RunBounded. At
// the context's deadline the connection under the call is closed, which
// unblocks its read, and is discarded; the next call opens a fresh one. A
// connection that is delivered after its call gave up is closed. A reply cut
// off that way may mean the change was applied or not; the caller reads the
// state back.
type Manager struct {
	rt *rtnl.Conn

	openWG func(ctx context.Context) (wgClient, error)
	wgMu   sync.Mutex // one WireGuard call at a time
	openLK func() (linkAPI, error)
	lkMu   sync.Mutex // one link call at a time

	cmu    sync.Mutex // guards wg, lk, closed
	wg     wgClient
	lk     linkAPI
	closed bool
}

// Open opens the sockets.
func Open(o Options) (*Manager, error) {
	rt, err := rtnl.Dial(rtnl.Options{NetNS: o.NetNS})
	if err != nil {
		return nil, err
	}
	m := &Manager{rt: rt}
	m.openLK = func() (linkAPI, error) {
		var h *vnetlink.Handle
		var err error
		if o.NetNS != 0 {
			h, err = vnetlink.NewHandleAt(netns.NsHandle(o.NetNS))
		} else {
			h, err = vnetlink.NewHandle()
		}
		if err != nil {
			return nil, fmt.Errorf("tunnel: open netlink: %w", err)
		}
		_ = h.SetSocketTimeout(Timeout)
		return h, nil
	}
	m.openWG = func(ctx context.Context) (wgClient, error) {
		// wgctrl.New looks the WireGuard family up on a socket it opens
		// itself and never lets go of until the kernel answers. Prove the
		// kernel answers, on a socket we own and close, before handing it the
		// job.
		if err := probeWireGuardFamily(ctx, o.NetNS); err != nil {
			return nil, err
		}
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
	}
	// Fail early if WireGuard netlink or the link socket is unavailable.
	ctx, cancel := context.WithTimeout(context.Background(), DefaultBudget)
	defer cancel()
	if err := m.wgDo(ctx, func(wgClient) error { return nil }); err != nil {
		_ = m.Close()
		return nil, err
	}
	if err := m.linkDo(ctx, func(linkAPI) error { return nil }); err != nil {
		_ = m.Close()
		return nil, err
	}
	return m, nil
}

// probeWireGuardFamily asks the kernel for the "wireguard" generic netlink
// family on a socket of its own, with the context's deadline on it and closed
// on return, so that a kernel that does not answer family lookups is found
// out before wgctrl opens a socket we cannot reach.
func probeWireGuardFamily(ctx context.Context, netnsFd int) error {
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("tunnel: look up the WireGuard family: %w", rtnl.ErrDeadline)
		}
		return err
	}
	c, err := netlink.Dial(unix.NETLINK_GENERIC, &netlink.Config{NetNS: netnsFd})
	if err != nil {
		return fmt.Errorf("tunnel: open generic netlink: %w", err)
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		if err := c.SetDeadline(dl); err != nil {
			return err
		}
	}
	// Close the socket when the context ends, which unblocks the request
	// even if the deadline option could not.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = c.Close()
		case <-stop:
		}
	}()
	const ctrlCmdGetFamily, ctrlAttrFamilyName = 3, 2
	req := []byte{ctrlCmdGetFamily, 1, 0, 0}
	name := append([]byte("wireguard"), 0)
	attr := make([]byte, 4, 4+len(name)+3)
	nativeEnd.PutUint16(attr[0:2], uint16(4+len(name)))
	nativeEnd.PutUint16(attr[2:4], ctrlAttrFamilyName)
	attr = append(attr, name...)
	for len(attr)%4 != 0 {
		attr = append(attr, 0)
	}
	_, err = c.Execute(netlink.Message{
		Header: netlink.Header{Type: unix.GENL_ID_CTRL, Flags: netlink.Request},
		Data:   append(req, attr...),
	})
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("tunnel: look up the WireGuard family: %w", rtnl.ErrDeadline)
		}
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("tunnel: the kernel has no WireGuard: %w", os.ErrNotExist)
		}
		return fmt.Errorf("tunnel: look up the WireGuard family: %w", err)
	}
	return nil
}

var nativeEnd = binary.NativeEndian

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
	c, l := m.wg, m.lk
	m.wg, m.lk = nil, nil
	m.cmu.Unlock()
	var err error
	if l != nil {
		l.Close()
	}
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

var errClosed = errors.New("tunnel: closed")

// discardWG and discardLK drop a connection that was cut off.
func (m *Manager) discardWG(c wgClient) {
	m.cmu.Lock()
	if m.wg == c {
		m.wg = nil
	}
	m.cmu.Unlock()
	_ = c.Close()
}

func (m *Manager) discardLK(l linkAPI) {
	m.cmu.Lock()
	if m.lk == l {
		m.lk = nil
	}
	m.cmu.Unlock()
	l.Close()
}

// opened runs an open function under the context's deadline and hands its
// connection over under a lock: one that arrives after the call gave up is
// closed by the goroutine that made it, so nothing is left open.
func opened[T any](ctx context.Context, open func() (T, error), closeIt func(T)) (T, error) {
	var mu sync.Mutex
	var got T
	var have, abandoned bool
	// Nothing can be closed to hurry an open along (the connection does not
	// exist yet), so the wait after the deadline is short: the handoff below
	// makes a late arrival harmless.
	err := rtnl.RunBounded(ctx, openGrace, func() {
		mu.Lock()
		abandoned = true
		mu.Unlock()
	}, func() error {
		c, err := open()
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		if abandoned {
			closeIt(c)
			return rtnl.ErrDeadline
		}
		got, have = c, true
		return nil
	})
	mu.Lock()
	defer mu.Unlock()
	if err != nil {
		if have {
			closeIt(got) // finished during the abort grace, but the call failed anyway
			have = false
		}
		var zero T
		return zero, err
	}
	if !have {
		var zero T
		return zero, rtnl.ErrDeadline
	}
	return got, nil
}

// wgDo runs a call on the WireGuard connection, opening one if needed, under
// the context's deadline.
func (m *Manager) wgDo(ctx context.Context, fn func(wgClient) error) error {
	m.wgMu.Lock()
	defer m.wgMu.Unlock()
	m.cmu.Lock()
	if m.closed {
		m.cmu.Unlock()
		return errClosed
	}
	c := m.wg
	m.cmu.Unlock()
	if c == nil {
		var err error
		c, err = opened(ctx, func() (wgClient, error) { return m.openWG(ctx) }, func(c wgClient) { _ = c.Close() })
		if err != nil {
			return err
		}
		m.cmu.Lock()
		if m.closed {
			m.cmu.Unlock()
			_ = c.Close()
			return errClosed
		}
		m.wg = c
		m.cmu.Unlock()
	}
	err := rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, func() { m.discardWG(c) }, func() error { return fn(c) })
	if ctx.Err() != nil {
		m.discardWG(c)
	}
	return err
}

// linkDo runs a group of link calls on the link handle under the context's
// absolute deadline: whatever the library does with its own timeouts, at the
// deadline the handle's sockets are closed, which unblocks a pending receive.
func (m *Manager) linkDo(ctx context.Context, fn func(linkAPI) error) error {
	m.lkMu.Lock()
	defer m.lkMu.Unlock()
	m.cmu.Lock()
	if m.closed {
		m.cmu.Unlock()
		return errClosed
	}
	l := m.lk
	m.cmu.Unlock()
	if l == nil {
		var err error
		l, err = opened(ctx, m.openLK, func(l linkAPI) { l.Close() })
		if err != nil {
			return err
		}
		m.cmu.Lock()
		if m.closed {
			m.cmu.Unlock()
			l.Close()
			return errClosed
		}
		m.lk = l
		m.cmu.Unlock()
	}
	err := rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, func() { m.discardLK(l) }, func() error { return fn(l) })
	if ctx.Err() != nil {
		m.discardLK(l)
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

// begin readies the route socket for an operation under ctx: one absolute
// deadline.
func (m *Manager) begin(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return rtnl.ErrDeadline
		}
		return err
	}
	if dl, ok := ctx.Deadline(); ok && m.rt != nil {
		m.rt.SetDeadline(dl)
	}
	return nil
}

func (m *Manager) clearDeadline() {
	if m.rt != nil {
		m.rt.SetDeadline(time.Time{})
	}
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
	var nf vnetlink.LinkNotFoundError
	return errors.As(err, &nf) || errors.Is(err, syscall.ENODEV) || errors.Is(err, os.ErrNotExist)
}

// Up makes one attempt to bring the tunnel up; see UpContext.
func (m *Manager) Up(p Params) error { return m.UpContext(context.Background(), p) }

// UpContext makes one attempt to bring the tunnel up: a leftover link of the
// same name is removed, a wireguard link is created and configured, and the
// exit table's default route goes in. Every call ends by ctx's deadline
// (DefaultBudget if it has none), including every receive of the link
// handle, and ctx is checked between calls. On any failure the half-built link
// is removed, even if the deadline has passed, so the next attempt starts
// clean; the exit table keeps its unreachable fallback throughout. No error
// carries key material.
func (m *Manager) UpContext(ctx context.Context, p Params) (err error) {
	if p.Conf == nil {
		return errors.New("tunnel: no config")
	}
	ctx, cancel := budgeted(ctx)
	defer cancel()
	defer m.clearDeadline()
	if err := m.begin(ctx); err != nil {
		return err
	}
	var link vnetlink.Link
	err = m.linkDo(ctx, func(h linkAPI) error {
		if old, lerr := h.LinkByName(p.ExitIf); lerr == nil {
			if derr := h.LinkDel(old); derr != nil && !notFound(derr) {
				return fmt.Errorf("tunnel: remove the old %s link: %w", p.ExitIf, derr)
			}
		} else if !notFound(lerr) {
			return fmt.Errorf("tunnel: look up %s: %w", p.ExitIf, lerr)
		}
		if err := h.LinkAdd(&vnetlink.Wireguard{LinkAttrs: vnetlink.LinkAttrs{Name: p.ExitIf}}); err != nil {
			return fmt.Errorf("tunnel: create the wireguard link %s: %w", p.ExitIf, err)
		}
		var lerr error
		if link, lerr = h.LinkByName(p.ExitIf); lerr != nil {
			return fmt.Errorf("tunnel: look up %s: %w", p.ExitIf, lerr)
		}
		return nil
	})
	defer func() {
		if err != nil {
			// Whatever the deadline says, the half-built link comes out.
			rctx, rcancel := context.WithTimeout(context.Background(), cleanupBudget)
			defer rcancel()
			_ = m.linkDo(rctx, func(h linkAPI) error {
				if l, lerr := h.LinkByName(p.ExitIf); lerr == nil {
					return h.LinkDel(l)
				}
				return nil
			})
		}
	}()
	if err != nil {
		return err
	}
	if err = m.configure(ctx, p); err != nil {
		return err
	}
	err = m.linkDo(ctx, func(h linkAPI) error {
		for _, a := range []netip.Addr{p.Conf.Addr4, p.Conf.Addr6} {
			if !a.IsValid() {
				continue
			}
			if err := h.AddrAdd(link, &vnetlink.Addr{IPNet: prefixOf(a)}); err != nil {
				return fmt.Errorf("tunnel: assign an address to %s: %w", p.ExitIf, err)
			}
		}
		if err := h.LinkSetMTU(link, p.Conf.MTU); err != nil {
			return fmt.Errorf("tunnel: set the MTU of %s: %w", p.ExitIf, err)
		}
		if err := h.LinkSetUp(link); err != nil {
			return fmt.Errorf("tunnel: bring %s up: %w", p.ExitIf, err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// The PostUp hook: `ip route replace default dev %i table N`, per family.
	for _, op := range p.Conf.UpRoutes() {
		if err = m.begin(ctx); err != nil {
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
	defer m.clearDeadline()
	if err := m.begin(ctx); err != nil {
		return err
	}
	var link vnetlink.Link
	err := m.linkDo(ctx, func(h linkAPI) error {
		var err error
		link, err = h.LinkByName(p.ExitIf)
		return err
	})
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
	err = m.linkDo(ctx, func(h linkAPI) error { return h.LinkDel(link) })
	if err != nil && !notFound(err) {
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
// is fine; one that is still there afterwards is an error. Every call ends by
// ctx's deadline (DefaultBudget if it has none).
func (m *Manager) CleanupContext(ctx context.Context, backend contract.Backend, exitIf, overlayIf string) error {
	ctx, cancel := budgeted(ctx)
	defer cancel()
	names := []string{overlayIf}
	if backend == contract.Native {
		names = []string{exitIf, overlayIf}
	}
	var failed []string
	for _, name := range names {
		err := m.linkDo(ctx, func(h linkAPI) error {
			l, err := h.LinkByName(name)
			if err != nil {
				if notFound(err) {
					return nil
				}
				return err
			}
			if err := h.LinkDel(l); err != nil && !notFound(err) {
				return err
			}
			if _, err := h.LinkByName(name); err == nil {
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

// LinkDo runs fn with the link handle under ctx's deadline (DefaultBudget if
// it has none), closing the handle's sockets if it passes.
func (m *Manager) LinkDo(ctx context.Context, fn func(*vnetlink.Handle) error) error {
	ctx, cancel := budgeted(ctx)
	defer cancel()
	return m.linkDo(ctx, func(l linkAPI) error {
		h, ok := l.(*vnetlink.Handle)
		if !ok {
			return errors.New("tunnel: not a netlink handle")
		}
		return fn(h)
	})
}

// Netlink returns the link handle. Its calls are bounded only by a relative
// per-receive timeout: prefer LinkDo.
func (m *Manager) Netlink() *vnetlink.Handle {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultBudget)
	defer cancel()
	var out *vnetlink.Handle
	_ = m.linkDo(ctx, func(l linkAPI) error { out, _ = l.(*vnetlink.Handle); return nil })
	return out
}
