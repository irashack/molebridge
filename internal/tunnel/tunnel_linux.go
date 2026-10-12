//go:build linux

package tunnel

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
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

// Timeout bounds each kernel request.
const Timeout = 10 * time.Second

// Options say where a Manager operates.
type Options struct {
	// NetNS is a file descriptor of the network namespace to operate in; zero
	// is the calling thread's namespace.
	NetNS int
}

// Manager holds the netlink sockets the tunnel operations use.
type Manager struct {
	h  *netlink.Handle
	wg *wgctrl.Client
	rt *rtnl.Conn
}

// Open opens the sockets.
func Open(o Options) (*Manager, error) {
	var (
		h   *netlink.Handle
		wg  *wgctrl.Client
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
	// A generic netlink socket belongs to the namespace of the thread that
	// opens it.
	err = inNamespace(o.NetNS, func() error {
		var err error
		wg, err = wgctrl.New()
		return err
	})
	if err != nil {
		h.Close()
		return nil, fmt.Errorf("tunnel: open WireGuard netlink: %w", err)
	}
	rt, err := rtnl.Dial(rtnl.Options{NetNS: o.NetNS})
	if err != nil {
		h.Close()
		_ = wg.Close()
		return nil, err
	}
	return &Manager{h: h, wg: wg, rt: rt}, nil
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

// Close closes the sockets.
func (m *Manager) Close() error {
	m.h.Close()
	err := m.wg.Close()
	if e := m.rt.Close(); err == nil {
		err = e
	}
	return err
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

// Up makes one attempt to bring the tunnel up: a leftover link of the same
// name is removed, a wireguard link is created and configured, and the exit
// table's default route goes in. On any failure the half-built link is
// removed, so the next attempt starts clean; the exit table keeps its
// unreachable fallback throughout. No error carries key material.
func (m *Manager) Up(p Params) (err error) {
	if p.Conf == nil {
		return errors.New("tunnel: no config")
	}
	if old, lerr := m.h.LinkByName(p.ExitIf); lerr == nil {
		if derr := m.h.LinkDel(old); derr != nil && !notFound(derr) {
			return fmt.Errorf("tunnel: remove the old %s link: %w", p.ExitIf, derr)
		}
	} else if !notFound(lerr) {
		return fmt.Errorf("tunnel: look up %s: %w", p.ExitIf, lerr)
	}
	if err := m.h.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: p.ExitIf}}); err != nil {
		return fmt.Errorf("tunnel: create the wireguard link %s: %w", p.ExitIf, err)
	}
	defer func() {
		if err != nil {
			if l, lerr := m.h.LinkByName(p.ExitIf); lerr == nil {
				_ = m.h.LinkDel(l)
			}
		}
	}()
	link, err := m.h.LinkByName(p.ExitIf)
	if err != nil {
		return fmt.Errorf("tunnel: look up %s: %w", p.ExitIf, err)
	}
	if err := m.configure(p); err != nil {
		return err
	}
	for _, a := range []netip.Addr{p.Conf.Addr4, p.Conf.Addr6} {
		if !a.IsValid() {
			continue
		}
		if err := m.h.AddrAdd(link, &netlink.Addr{IPNet: prefixOf(a)}); err != nil {
			return fmt.Errorf("tunnel: assign an address to %s: %w", p.ExitIf, err)
		}
	}
	if err := m.h.LinkSetMTU(link, p.Conf.MTU); err != nil {
		return fmt.Errorf("tunnel: set the MTU of %s: %w", p.ExitIf, err)
	}
	if err := m.h.LinkSetUp(link); err != nil {
		return fmt.Errorf("tunnel: bring %s up: %w", p.ExitIf, err)
	}
	// The PostUp hook: `ip route replace default dev %i table N`, per family.
	for _, op := range p.Conf.UpRoutes() {
		if err := m.rt.ReplaceRoute(contract.TunnelRoute(op.Family, op.Table, uint32(link.Attrs().Index))); err != nil {
			return fmt.Errorf("tunnel: route %s through %s: %w", op.Family, p.ExitIf, err)
		}
	}
	return nil
}

// configure sets the private key and, for a config that carries one, the peer.
func (m *Manager) configure(p Params) error {
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
	if err := m.wg.ConfigureDevice(p.ExitIf, cfg); err != nil {
		return fmt.Errorf("tunnel: configure %s: %w", p.ExitIf, err)
	}
	return nil
}

// Down is `wg-quick down`: the PreDown routes come out, then the link. A
// missing link or route is not an error. The rules and the unreachable
// fallback stay: the namespace stays fail-closed whatever happens to the
// tunnel.
func (m *Manager) Down(p Params) error {
	link, err := m.h.LinkByName(p.ExitIf)
	if err != nil {
		if notFound(err) {
			return nil
		}
		return fmt.Errorf("tunnel: look up %s: %w", p.ExitIf, err)
	}
	if p.Conf != nil {
		for _, op := range p.Conf.DownRoutes() {
			err := m.rt.DelRoute(rtnl.Route{Family: op.Family, Dst: defaultPrefix(op.Family), Table: op.Table, Type: rtnl.RTNUnicast,
				Oif: rtnl.Some(uint32(link.Attrs().Index))})
			if err != nil && !rtnl.IsNotExist(err) {
				return fmt.Errorf("tunnel: remove the %s route through %s: %w", op.Family, p.ExitIf, err)
			}
		}
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

// Cleanup is the independent cleanup the supervisor runs after the worker is
// gone: the native backend deletes Molebridge's tunnel link and NetBird's
// overlay link (a kernel WireGuard interface can keep forwarding in a
// namespace another container holds); the gluetun backend deletes only the
// overlay link and never touches gluetun's tunnel, which is not ours. Every
// rule and the unreachable fallback stay in place. A link that is not there
// is fine; one that is still there afterwards is an error.
func (m *Manager) Cleanup(backend contract.Backend, exitIf, overlayIf string) error {
	names := []string{overlayIf}
	if backend == contract.Native {
		names = []string{exitIf, overlayIf}
	}
	var failed []string
	for _, name := range names {
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

// Fwmark reads a WireGuard interface's firewall mark, which is what the
// gluetun backend checks NetBird's overlay interface for (the control mark).
// A missing interface is ErrNoDevice.
func (m *Manager) Fwmark(name string) (uint32, error) {
	d, err := m.wg.Device(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, ErrNoDevice
		}
		return 0, fmt.Errorf("tunnel: read %s: %w", name, err)
	}
	return uint32(d.FirewallMark), nil
}

// Wg returns the WireGuard client, for the peer changes and handshake reads
// of the provider code.
func (m *Manager) Wg() *wgctrl.Client { return m.wg }

// Netlink returns the link handle.
func (m *Manager) Netlink() *netlink.Handle { return m.h }
