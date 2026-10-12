//go:build linux

package tunnel

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	vnetlink "github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/tunnel/wgnl"
)

// Deprecated library handles.
//
// The Manager's own operations (Up, Down, Cleanup, Device, Configure,
// FwmarkContext) use nothing in this file: they run on a route socket and a
// WireGuard generic netlink socket the package owns and puts an absolute
// deadline on. Wg, WgDo, LinkDo and Netlink remain only for callers that still
// want a wgctrl client or a vishvananda handle. Those libraries open sockets
// of their own, so a call is bounded only by closing the whole handle at the
// deadline (rtnl.RunBounded), and the handle is opened on first use, never by
// Open. New code uses Device, Configure and RouteDo.

// openGrace is how long a call waits for a connection that is still being
// opened after its deadline.
const openGrace = 50 * time.Millisecond

// wgClient is the part of *wgctrl.Client the legacy accessors use.
type wgClient interface {
	ConfigureDevice(name string, cfg wgtypes.Config) error
	Device(name string) (*wgtypes.Device, error)
	Close() error
}

// linkAPI is the part of *vishvananda/netlink.Handle the legacy accessors use.
type linkAPI interface {
	Close()
}

type legacy struct {
	openWG func(ctx context.Context) (wgClient, error) // tests replace it
	openLK func() (linkAPI, error)                     // tests replace it
	lwgMu  sync.Mutex                                  // one wgctrl call at a time
	lkMu   sync.Mutex                                  // one link call at a time

	lmu     sync.Mutex // guards lwg, llk, lclosed
	lwg     wgClient
	llk     linkAPI
	lclosed bool
}

func (m *Manager) openLegacyWG(ctx context.Context) (wgClient, error) {
	if m.openWG != nil {
		return m.openWG(ctx)
	}
	// wgctrl.New looks the WireGuard family up on a socket it opens itself
	// and never lets go of until the kernel answers. Prove the kernel
	// answers, on a socket we own and close, before handing it the job.
	probe, err := wgnl.Dial(ctx, m.opts.NetNS)
	if err != nil {
		return nil, fmt.Errorf("tunnel: look up the WireGuard family: %w", err)
	}
	_ = probe.Close()
	// A generic netlink socket belongs to the namespace of the thread that
	// opens it.
	var c *wgctrl.Client
	err = inNamespace(m.opts.NetNS, func() error {
		var err error
		c, err = wgctrl.New()
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("tunnel: open WireGuard netlink: %w", err)
	}
	return c, nil
}

func (m *Manager) openLegacyLK() (linkAPI, error) {
	if m.openLK != nil {
		return m.openLK()
	}
	var h *vnetlink.Handle
	var err error
	if m.opts.NetNS != 0 {
		h, err = vnetlink.NewHandleAt(netns.NsHandle(m.opts.NetNS))
	} else {
		h, err = vnetlink.NewHandle()
	}
	if err != nil {
		return nil, fmt.Errorf("tunnel: open netlink: %w", err)
	}
	_ = h.SetSocketTimeout(Timeout)
	return h, nil
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

// closeLegacy closes the handles, unblocking any call in flight.
func (m *Manager) closeLegacy() error {
	m.lmu.Lock()
	m.lclosed = true
	c, l := m.lwg, m.llk
	m.lwg, m.llk = nil, nil
	m.lmu.Unlock()
	if l != nil {
		l.Close()
	}
	if c != nil {
		return c.Close()
	}
	return nil
}

func (m *Manager) discardLegacyWG(c wgClient) {
	m.lmu.Lock()
	if m.lwg == c {
		m.lwg = nil
	}
	m.lmu.Unlock()
	_ = c.Close()
}

func (m *Manager) discardLegacyLK(l linkAPI) {
	m.lmu.Lock()
	if m.llk == l {
		m.llk = nil
	}
	m.lmu.Unlock()
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

// legacyWgDo runs a call on the wgctrl client, opening one if needed, under
// the context's deadline.
func (m *Manager) legacyWgDo(ctx context.Context, fn func(wgClient) error) error {
	m.lwgMu.Lock()
	defer m.lwgMu.Unlock()
	m.lmu.Lock()
	if m.lclosed {
		m.lmu.Unlock()
		return errClosed
	}
	c := m.lwg
	m.lmu.Unlock()
	if c == nil {
		var err error
		c, err = opened(ctx, func() (wgClient, error) { return m.openLegacyWG(ctx) }, func(c wgClient) { _ = c.Close() })
		if err != nil {
			return err
		}
		m.lmu.Lock()
		if m.lclosed {
			m.lmu.Unlock()
			_ = c.Close()
			return errClosed
		}
		m.lwg = c
		m.lmu.Unlock()
	}
	err := rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, func() { m.discardLegacyWG(c) }, func() error { return fn(c) })
	if ctx.Err() != nil {
		m.discardLegacyWG(c)
	}
	return err
}

// legacyLinkDo runs a group of calls on the vishvananda handle under the
// context's absolute deadline: whatever the library does with its own
// timeouts, at the deadline the handle's sockets are closed, which unblocks a
// pending receive.
func (m *Manager) legacyLinkDo(ctx context.Context, fn func(linkAPI) error) error {
	m.lkMu.Lock()
	defer m.lkMu.Unlock()
	m.lmu.Lock()
	if m.lclosed {
		m.lmu.Unlock()
		return errClosed
	}
	l := m.llk
	m.lmu.Unlock()
	if l == nil {
		var err error
		l, err = opened(ctx, m.openLegacyLK, func(l linkAPI) { l.Close() })
		if err != nil {
			return err
		}
		m.lmu.Lock()
		if m.lclosed {
			m.lmu.Unlock()
			l.Close()
			return errClosed
		}
		m.llk = l
		m.lmu.Unlock()
	}
	err := rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, func() { m.discardLegacyLK(l) }, func() error { return fn(l) })
	if ctx.Err() != nil {
		m.discardLegacyLK(l)
	}
	return err
}

var errNoLegacy = errors.New("tunnel: not a library handle")

// Wg returns a wgctrl client for callers that still want one. Its calls have
// no deadline of their own: use WgDo, or better Device and Configure.
//
// Deprecated: wgctrl opens a socket it does not let the caller bound.
func (m *Manager) Wg() *wgctrl.Client {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultBudget)
	defer cancel()
	var out *wgctrl.Client
	_ = m.legacyWgDo(ctx, func(c wgClient) error { out, _ = c.(*wgctrl.Client); return nil })
	return out
}

// WgDo runs fn with the wgctrl client under ctx's deadline (DefaultBudget if
// it has none). If the deadline passes first the connection is closed and
// replaced, fn's call fails, and WgDo returns a deadline error; the caller
// reads the device back to learn whether a mutation took effect.
//
// Deprecated: use Device and Configure, which run on the package's own
// WireGuard socket under an absolute deadline.
func (m *Manager) WgDo(ctx context.Context, fn func(*wgctrl.Client) error) error {
	ctx, cancel := budgeted(ctx)
	defer cancel()
	return m.legacyWgDo(ctx, func(c wgClient) error {
		real, ok := c.(*wgctrl.Client)
		if !ok {
			return errNoLegacy
		}
		return fn(real)
	})
}

// LinkDo runs fn with a vishvananda handle under ctx's deadline (DefaultBudget
// if it has none), closing the handle's sockets if it passes.
//
// Deprecated: use RouteDo, which runs on the package's own route socket.
func (m *Manager) LinkDo(ctx context.Context, fn func(*vnetlink.Handle) error) error {
	ctx, cancel := budgeted(ctx)
	defer cancel()
	return m.legacyLinkDo(ctx, func(l linkAPI) error {
		h, ok := l.(*vnetlink.Handle)
		if !ok {
			return errNoLegacy
		}
		return fn(h)
	})
}

// Netlink returns a vishvananda handle. Its calls are bounded only by a
// relative per-receive timeout: use RouteDo.
//
// Deprecated: see LinkDo.
func (m *Manager) Netlink() *vnetlink.Handle {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultBudget)
	defer cancel()
	var out *vnetlink.Handle
	_ = m.legacyLinkDo(ctx, func(l linkAPI) error { out, _ = l.(*vnetlink.Handle); return nil })
	return out
}
