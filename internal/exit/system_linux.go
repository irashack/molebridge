//go:build linux

package exit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/applier"
	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/nft"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/tunnel"
)

// KernelSystem is the worker's implementation of applier.System: every call
// the Python applier made through `ip`, `wg`, `nft` and `curl` is one method,
// answered through netlink, WireGuard's generic netlink and nftables. Reads go
// over a request socket of their own (the mutation owner's socket carries a
// per-operation deadline); every kernel change is one queued job on the
// mutation owner.
type KernelSystem struct {
	netx.Client

	S    *Settings
	Spec contract.Spec
	Obs  *rtnl.Conn
	Mut  *mutator.Mutator
	Tun  *tunnel.Manager
	// Generation is the launch generation: the native exit's owner generation.
	Generation string
	// NetNS is a file descriptor of the namespace the exit lives in; zero (the
	// process's own) in production, set by tests that look from outside.
	NetNS int

	snapMu sync.Mutex
	snap   *rtnl.Snapshot
	snapAt time.Time
}

var (
	_ applier.System        = (*KernelSystem)(nil)
	_ applier.GluetunSystem = (*KernelSystem)(nil)
)

func (k *KernelSystem) exitIf() string    { return k.S.Routing.ExitIf }
func (k *KernelSystem) overlayIf() string { return k.S.Routing.OverlayIf }

// LinkExists is nil when the interface exists.
func (k *KernelSystem) LinkExists(_ context.Context, name string) error {
	snap, err := k.readSnapshot()
	if err != nil {
		return err
	}
	if _, ok := snap.Link(name); ok {
		return nil
	}
	return fmt.Errorf("interface %s does not exist", name)
}

func familyOf(n int) (rtnl.Family, error) {
	switch n {
	case 4:
		return rtnl.V4, nil
	case 6:
		return rtnl.V6, nil
	}
	return 0, errors.New("the address family is 4 or 6")
}

// RoutingStatus is contract.FamilyStatus over one snapshot: the strict judgment
// of rules and exit table for one family.
func (k *KernelSystem) RoutingStatus(_ context.Context, family int, tunnelAddress string) (bool, bool, error) {
	f, err := familyOf(family)
	if err != nil {
		return false, false, err
	}
	var addr netip.Addr
	if tunnelAddress != "" {
		if addr, err = netip.ParseAddr(tunnelAddress); err != nil {
			return false, false, errors.New("invalid tunnel address")
		}
	}
	snap, err := k.readSnapshot()
	if err != nil {
		return false, false, err
	}
	link, _ := snap.Link(k.exitIf())
	protected, fallback := contract.FamilyStatus(k.Spec, f, snap.Rules[f], snap.RoutesInTable(f, k.Spec.Config.Table),
		contract.StatusOptions{TunnelAddress: addr, ExitIfIndex: link.Index})
	return protected, fallback, nil
}

// ReadSysctl returns the text of a /proc/sys file.
func (k *KernelSystem) ReadSysctl(_ context.Context, path string) (string, error) {
	if !strings.HasPrefix(path, "/proc/sys/") || strings.Contains(path, "..") {
		return "", errors.New("not a sysctl file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return "", err
	}
	return string(buf[:n]), nil
}

// OverlayKernelWireGuard is whether the overlay interface is a kernel
// WireGuard link.
func (k *KernelSystem) OverlayKernelWireGuard(_ context.Context) (bool, error) {
	snap, err := k.readSnapshot()
	if err != nil {
		return false, err
	}
	return contract.OverlayIsKernelWireguard(snap.Links, k.overlayIf()), nil
}

// NetbirdFirewallPresent is whether NetBird's nftables table or chains exist.
func (k *KernelSystem) NetbirdFirewallPresent(ctx context.Context) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	chains, err := nft.ListChainsContext(ctx, k.NetNS)
	if err != nil {
		return false, err
	}
	return contract.NetbirdFirewallPresent(chains), nil
}

var routeTypeNames = map[uint8]string{
	rtnl.RTNUnicast: "unicast", rtnl.RTNLocal: "local", rtnl.RTNBroadcast: "broadcast", rtnl.RTNAnycast: "anycast",
	rtnl.RTNMulticast: "multicast", rtnl.RTNBlackhole: "blackhole", rtnl.RTNUnreachable: "unreachable",
	rtnl.RTNProhibit: "prohibit", rtnl.RTNThrow: "throw",
}

// IPv6Evidence is `ip -j -6 route show table all` and `ip -j -6 address show
// scope global` in the shape the egress code reads.
func (k *KernelSystem) IPv6Evidence(_ context.Context) (any, any, error) {
	links, err := k.Obs.Links()
	if err != nil {
		return nil, nil, err
	}
	names := map[uint32]string{}
	for _, l := range links {
		names[l.Index] = l.Name
	}
	routes, err := k.Obs.Routes(rtnl.V6, nil)
	if err != nil {
		return nil, nil, err
	}
	routeList := []any{}
	for _, r := range routes {
		m := map[string]any{"type": routeTypeNames[r.Type]}
		if r.IsDefault() {
			m["dst"] = "default"
		} else {
			m["dst"] = r.Dst.String()
		}
		if r.Oif.OK {
			m["dev"] = names[r.Oif.V]
		}
		if r.Gateway.IsValid() {
			m["gateway"] = r.Gateway.String()
		}
		if r.MultiPath {
			m["nexthops"] = []any{}
		}
		routeList = append(routeList, m)
	}
	addrs, err := k.Obs.Addrs(rtnl.V6)
	if err != nil {
		return nil, nil, err
	}
	byLink := map[uint32][]any{}
	for _, a := range addrs {
		if !a.Global() {
			continue
		}
		byLink[a.Index] = append(byLink[a.Index], map[string]any{
			"family": "inet6", "local": a.Local.Addr().String(), "prefixlen": int64(a.Local.Bits()), "scope": "global"})
	}
	linkList := []any{}
	for _, l := range links {
		if info := byLink[l.Index]; len(info) > 0 {
			linkList = append(linkList, map[string]any{"ifname": l.Name, "addr_info": info})
		}
	}
	return routeList, linkList, nil
}

// OwnerGeneration is the native exit's launch generation, "" for the others.
func (k *KernelSystem) OwnerGeneration(_ context.Context) string {
	if k.S.Native() {
		return k.Generation
	}
	return ""
}

func (k *KernelSystem) device(ctx context.Context) (*wgtypes.Device, error) {
	d, err := k.Tun.Device(ctx, k.exitIf())
	if err != nil {
		return nil, fmt.Errorf("WireGuard interface %s: %w", k.exitIf(), err)
	}
	return d, nil
}

// Peers are the tunnel's peer public keys.
func (k *KernelSystem) Peers(ctx context.Context) ([]string, error) {
	d, err := k.device(ctx)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(d.Peers))
	for _, p := range d.Peers {
		keys = append(keys, p.PublicKey.String())
	}
	return keys, nil
}

// LatestHandshakes are the peers' last handshake times in Unix seconds.
func (k *KernelSystem) LatestHandshakes(ctx context.Context) (map[string]int64, error) {
	d, err := k.device(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	for _, p := range d.Peers {
		var at int64
		if !p.LastHandshakeTime.IsZero() {
			at = p.LastHandshakeTime.Unix()
		}
		out[p.PublicKey.String()] = at
	}
	return out, nil
}

// Endpoints are the peers' endpoints, "(none)" for a peer without one.
func (k *KernelSystem) Endpoints(ctx context.Context) (map[string]string, error) {
	d, err := k.device(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, p := range d.Peers {
		if p.Endpoint == nil {
			out[p.PublicKey.String()] = "(none)"
			continue
		}
		out[p.PublicKey.String()] = p.Endpoint.AddrPort().String()
	}
	return out, nil
}

// PublicKey is the interface's own public key; the private key is not read.
func (k *KernelSystem) PublicKey(ctx context.Context) (string, error) {
	d, err := k.device(ctx)
	if err != nil {
		return "", err
	}
	return d.PublicKey.String(), nil
}

// ReplacePeer removes the peers in remove, one after another, then sets add.
// An empty public key in add means remove only.
func (k *KernelSystem) ReplacePeer(ctx context.Context, remove []string, add applier.PeerConfig) error {
	defer k.invalidate()
	return k.Mut.Do(ctx, "change the tunnel peer", func(tx *mutator.Tx) error {
		configure := func(cfg wgtypes.Config) error {
			return k.Tun.Configure(tx.Context(), k.exitIf(), cfg)
		}
		for _, r := range remove {
			key, err := wgtypes.ParseKey(r)
			if err != nil {
				return errors.New("invalid peer key")
			}
			if err := configure(wgtypes.Config{Peers: []wgtypes.PeerConfig{{PublicKey: key, Remove: true}}}); err != nil {
				return fmt.Errorf("remove a peer: %w", err)
			}
		}
		if add.PublicKey == "" {
			return nil
		}
		key, err := wgtypes.ParseKey(add.PublicKey)
		if err != nil {
			return errors.New("invalid peer key")
		}
		pc := wgtypes.PeerConfig{PublicKey: key, ReplaceAllowedIPs: true}
		if add.Endpoint != "" {
			ap, err := netip.ParseAddrPort(add.Endpoint)
			if err != nil {
				return errors.New("invalid peer endpoint")
			}
			pc.Endpoint = net.UDPAddrFromAddrPort(ap)
		}
		for _, c := range add.AllowedIPs {
			_, n, err := net.ParseCIDR(c)
			if err != nil {
				return errors.New("invalid allowed IPs")
			}
			pc.AllowedIPs = append(pc.AllowedIPs, *n)
		}
		if add.KeepaliveSec > 0 {
			d := time.Duration(add.KeepaliveSec) * time.Second
			pc.PersistentKeepaliveInterval = &d
		}
		if err := configure(wgtypes.Config{Peers: []wgtypes.PeerConfig{pc}}); err != nil {
			return fmt.Errorf("set the peer: %w", err)
		}
		return nil
	})
}

// NamespaceIPv4Prefixes are the IPv4 prefixes on every interface but exclude.
func (k *KernelSystem) NamespaceIPv4Prefixes(_ context.Context, exclude string) ([]netip.Prefix, error) {
	links, err := k.Obs.Links()
	if err != nil {
		return nil, err
	}
	names := map[uint32]string{}
	for _, l := range links {
		names[l.Index] = l.Name
	}
	addrs, err := k.Obs.Addrs(rtnl.V4)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		if names[a.Index] == exclude {
			continue
		}
		out = append(out, a.Local.Masked())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

// -- PIA's kernel calls ------------------------------------------------------

// piaOnTx is applier.PIAKernel over one operation of the mutation owner.
type piaOnTx struct {
	k  *KernelSystem
	tx *mutator.Tx
}

func (p piaOnTx) exitLink() (rtnl.Link, error) {
	snap, err := p.tx.Snapshot()
	if err != nil {
		return rtnl.Link{}, err
	}
	l, ok := snap.Link(p.k.exitIf())
	if !ok {
		return rtnl.Link{}, fmt.Errorf("interface %s does not exist", p.k.exitIf())
	}
	return l, nil
}

func (p piaOnTx) IPv4Rules(_ context.Context, priority int) ([]applier.Rule, error) {
	snap, err := p.tx.Snapshot()
	if err != nil {
		return nil, err
	}
	return ipv4RulesAt(snap, priority), nil
}

func ipv4RulesAt(snap *rtnl.Snapshot, priority int) []applier.Rule {
	var out []applier.Rule
	for _, r := range snap.Rules[rtnl.V4] {
		if int(r.Priority) != priority {
			continue
		}
		rule := applier.Rule{Priority: priority, SrcLen: -1}
		if r.Src.IsValid() {
			rule.Src, rule.SrcLen = r.Src.Addr().String(), r.Src.Bits()
		}
		if r.IPProto.OK {
			rule.IPProto = int(r.IPProto.V)
		}
		switch r.Action {
		case rtnl.FRActToTbl:
			rule.Table = int(r.Table)
		case rtnl.FRActUnreachable:
			rule.Action = "unreachable"
		}
		rule.Other = r.IifName != "" || r.OifName != "" || r.FwMark.OK || r.FwMask.OK || r.Dst.IsValid() || r.Invert() ||
			r.Tos != 0 || r.SuppressPrefixLen.OK || r.Goto.OK || len(r.Unknown) > 0 || r.Bad
		out = append(out, rule)
	}
	return out
}

func (p piaOnTx) TunnelAddresses(_ context.Context) ([]netip.Addr, error) {
	snap, err := p.tx.Snapshot()
	if err != nil {
		return nil, err
	}
	return tunnelAddressesIn(snap, p.k.exitIf())
}

func tunnelAddressesIn(snap *rtnl.Snapshot, exitIf string) ([]netip.Addr, error) {
	l, ok := snap.Link(exitIf)
	if !ok {
		return nil, fmt.Errorf("interface %s does not exist", exitIf)
	}
	var out []netip.Addr
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		for _, a := range snap.Addrs[f] {
			if a.Index == l.Index && a.Global() {
				out = append(out, a.Local.Addr())
			}
		}
	}
	return out, nil
}

// returnPathRule is the expected rule 94 or 98 for an address.
func (p piaOnTx) returnPathRule(priority int, addr netip.Addr) (rtnl.Rule, error) {
	if priority != contract.PrioReturnPath && priority != contract.PrioBackstop {
		return rtnl.Rule{}, errors.New("not a return-path priority")
	}
	sp := p.k.Spec.Clone()
	sp.ReturnPath = map[rtnl.Family][]netip.Addr{rtnl.V4: {addr}}
	sp.LeaveReturnPath = map[rtnl.Family]bool{}
	rules := sp.RulesAt(rtnl.V4, uint32(priority))
	if len(rules) != 1 {
		return rtnl.Rule{}, errors.New("no return-path rule is expected at that priority")
	}
	return rules[0], nil
}

func (p piaOnTx) AddReturnPathRule(_ context.Context, priority int, addr netip.Addr) error {
	r, err := p.returnPathRule(priority, addr)
	if err != nil {
		return err
	}
	return p.tx.AddRule(r)
}

func (p piaOnTx) DeleteReturnPathRule(_ context.Context, priority int, src netip.Addr) error {
	if !src.IsValid() {
		_, err := p.tx.DelRulePriority(rtnl.V4, uint32(priority))
		return err
	}
	r, err := p.returnPathRule(priority, src)
	if err != nil {
		return err
	}
	return p.tx.DelRule(r)
}

// ReplaceTunnelAddress is `ip -4 address replace <addr>/32 dev <exit>`: the
// address is added, and already being there is the same outcome. It runs on the
// tunnel manager's route socket under the operation's deadline.
func (p piaOnTx) ReplaceTunnelAddress(_ context.Context, addr netip.Addr) error {
	return p.k.Tun.RouteDo(p.tx.Context(), func(c *rtnl.Conn) error {
		l, err := c.LinkByName(p.k.exitIf())
		if err != nil {
			return err
		}
		if err := c.AddAddr(rtnl.HostAddr(l.Index, addr)); err != nil && !rtnl.IsExist(err) {
			return err
		}
		return nil
	})
}

// DeleteTunnelAddress is `ip -4 address del <addr>/32 dev <exit>`.
func (p piaOnTx) DeleteTunnelAddress(_ context.Context, addr netip.Addr) error {
	return p.k.Tun.RouteDo(p.tx.Context(), func(c *rtnl.Conn) error {
		l, err := c.LinkByName(p.k.exitIf())
		if err != nil {
			return err
		}
		if err := c.DelAddr(rtnl.HostAddr(l.Index, addr)); err != nil && !rtnl.IsNotExist(err) {
			return err
		}
		return nil
	})
}

func (p piaOnTx) ReplaceExitDefaultRoute(_ context.Context) error {
	l, err := p.exitLink()
	if err != nil {
		return err
	}
	return p.tx.ReplaceRoute(contract.TunnelRoute(rtnl.V4, p.k.Spec.Config.Table, l.Index))
}

// The standalone primitives are each one job on the owner.

func (k *KernelSystem) onOwner(ctx context.Context, name string, fn func(piaOnTx) error) error {
	defer k.invalidate()
	return k.Mut.Do(ctx, name, func(tx *mutator.Tx) error { return fn(piaOnTx{k, tx}) })
}

// invalidate drops the shared snapshot: after a change, the next read looks at
// the kernel again.
func (k *KernelSystem) invalidate() {
	k.snapMu.Lock()
	k.snap = nil
	k.snapMu.Unlock()
}

// IPv4Rules lists the IPv4 rules at a priority (a read: no job on the owner).
func (k *KernelSystem) IPv4Rules(_ context.Context, priority int) ([]applier.Rule, error) {
	snap, err := k.Obs.Take(k.Spec.Interest())
	if err != nil {
		return nil, err
	}
	return ipv4RulesAt(snap, priority), nil
}

// TunnelAddresses are the exit interface's global-scope addresses (a read).
func (k *KernelSystem) TunnelAddresses(_ context.Context) ([]netip.Addr, error) {
	snap, err := k.readSnapshot()
	if err != nil {
		return nil, err
	}
	return tunnelAddressesIn(snap, k.exitIf())
}

// AddReturnPathRule installs rule 94 or 98 for addr.
func (k *KernelSystem) AddReturnPathRule(ctx context.Context, priority int, addr netip.Addr) error {
	return k.onOwner(ctx, "add a return-path rule", func(p piaOnTx) error { return p.AddReturnPathRule(ctx, priority, addr) })
}

// DeleteReturnPathRule removes the rule at priority from src.
func (k *KernelSystem) DeleteReturnPathRule(ctx context.Context, priority int, src netip.Addr) error {
	return k.onOwner(ctx, "remove a return-path rule", func(p piaOnTx) error { return p.DeleteReturnPathRule(ctx, priority, src) })
}

// ReplaceTunnelAddress is `ip -4 address replace <addr>/32 dev <exit>`.
func (k *KernelSystem) ReplaceTunnelAddress(ctx context.Context, addr netip.Addr) error {
	return k.onOwner(ctx, "set the tunnel address", func(p piaOnTx) error { return p.ReplaceTunnelAddress(ctx, addr) })
}

// DeleteTunnelAddress is `ip -4 address del <addr>/32 dev <exit>`.
func (k *KernelSystem) DeleteTunnelAddress(ctx context.Context, addr netip.Addr) error {
	return k.onOwner(ctx, "remove a tunnel address", func(p piaOnTx) error { return p.DeleteTunnelAddress(ctx, addr) })
}

// ReplaceExitDefaultRoute restores the exit table's default route.
func (k *KernelSystem) ReplaceExitDefaultRoute(ctx context.Context) error {
	return k.onOwner(ctx, "restore the exit route", func(p piaOnTx) error { return p.ReplaceExitDefaultRoute(ctx) })
}

// ChangePIAAddress is PIA's address change as one job on the mutation owner:
// the owner installs and confirms the new 94/98 pair (the expected state
// carries both pairs meanwhile), the applier's ordering changes the address
// and removes the old pair's leftovers, the owner restores the exit table's
// default route and drops the old pair from the expected state.
func (k *KernelSystem) ChangePIAAddress(ctx context.Context, old, next netip.Addr) error {
	defer k.invalidate()
	return k.Mut.ChangeReturnPath(ctx, rtnl.V4, old, next, func(tx *mutator.Tx) error {
		return applier.ChangePIAAddress(tx.Context(), piaOnTx{k, tx}, old, next)
	})
}

// -- nftables ----------------------------------------------------------------

// The nftables changes are jobs of the mutation owner like any other kernel
// change: serialized with the repairer, counted against the owner's progress
// (a wedged flush stops the lease's renewals instead of hiding behind an idle
// owner), and bounded by the operation's one absolute deadline, which every
// nftables socket carries.

// InstallIngressGuard installs the forward-path guard (never removed).
func (k *KernelSystem) InstallIngressGuard(ctx context.Context) error {
	return k.Mut.Do(ctx, "install the ingress guard", func(tx *mutator.Tx) error {
		return nft.InstallIngressGuard(tx.Context(), k.NetNS, k.exitIf(), k.overlayIf())
	})
}

// ApplyForwardRules atomically replaces the port-forwarding table.
func (k *KernelSystem) ApplyForwardRules(ctx context.Context, port int, target netip.Addr) error {
	return k.Mut.Do(ctx, "apply the forward rules", func(tx *mutator.Tx) error {
		return nft.ApplyForwardRules(tx.Context(), k.NetNS, k.exitIf(), k.overlayIf(), port, target)
	})
}

// RemoveForwardRules deletes the port-forwarding table.
func (k *KernelSystem) RemoveForwardRules(ctx context.Context) error {
	return k.Mut.Do(ctx, "remove the forward rules", func(tx *mutator.Tx) error {
		return nft.RemoveForwardRules(tx.Context(), k.NetNS)
	})
}

// -- the gluetun backend's reads -------------------------------------------------

// GluetunLinks reads the tunnel interface and the host interface from one
// dump. A missing tunnel is routine (gluetun recreates it on every
// reconnect) and not an error.
func (k *KernelSystem) GluetunLinks(_ context.Context) (applier.GluetunLinks, error) {
	snap, err := k.gluetunSnapshot()
	if err != nil {
		return applier.GluetunLinks{}, err
	}
	var out applier.GluetunLinks
	if l, ok := snap.Link(k.exitIf()); ok {
		out.Tunnel = applier.TunnelLink{Present: true, Up: l.Up(), Index: l.Index}
	}
	if k.Spec.Config.HostIf != "" {
		if l, ok := snap.Link(k.Spec.Config.HostIf); ok {
			out.HostIndex = l.Index
		}
	}
	return out, nil
}

// GluetunTables reads one family's rules and the exit, host and main tables.
// The links and the tables of one reading come from one snapshot: calls within
// 100 ms of each other share it, so the tunnel route's interface index is the
// tunnel link's index the previous call reported.
func (k *KernelSystem) GluetunTables(_ context.Context, family int) (applier.GluetunTables, error) {
	f, err := familyOf(family)
	if err != nil {
		return applier.GluetunTables{}, err
	}
	snap, err := k.gluetunSnapshot()
	if err != nil {
		return applier.GluetunTables{}, err
	}
	c := k.Spec.Config
	return applier.GluetunTables{
		Rules: snap.Rules[f], Exit: snap.RoutesInTable(f, c.Table), Host: snap.RoutesInTable(f, c.HostTable),
		Main: snap.RoutesInTable(f, rtnl.TableMain),
	}, nil
}

// snapshotAge is how long a read-only snapshot is shared between the calls
// that read the namespace (a health check and a tick make a dozen within
// milliseconds of each other).
const snapshotAge = 100 * time.Millisecond

// gluetunSnapshot is the shared read-only snapshot.
func (k *KernelSystem) gluetunSnapshot() (*rtnl.Snapshot, error) { return k.readSnapshot() }

func (k *KernelSystem) readSnapshot() (*rtnl.Snapshot, error) {
	k.snapMu.Lock()
	defer k.snapMu.Unlock()
	if k.snap != nil && time.Since(k.snapAt) < snapshotAge {
		return k.snap, nil
	}
	// The reads behind the status record change nothing, so one look will do:
	// the full stable snapshot (two looks behind a barrier) is for the
	// mutation owner's decisions.
	snap, err := k.Obs.TakeReadOnly(context.Background(), k.Spec.Interest())
	if err != nil {
		return nil, err
	}
	k.snap, k.snapAt = snap, time.Now()
	return snap, nil
}
