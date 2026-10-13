package contract

import (
	"net/netip"

	"github.com/irashack/molebridge/internal/rtnl"
)

// StatusOptions are family_status's keyword arguments.
type StatusOptions struct {
	// TunnelAddress is the family's global address on the exit interface; the
	// zero Addr when the tunnel does not carry the family. With one, the
	// family must also have its tunnel default route and the priority-94
	// return-path rule for exactly that address and ICMP alone, and, natively,
	// the priority-98 backstop for the same packets.
	TunnelAddress netip.Addr
	// NoTunnelRoute allows the tunnel default to be missing (gluetun's
	// interface exists with its address but is down; the guard removes the
	// route then), though never replaced by another route.
	NoTunnelRoute bool
	// ExitIfIndex is the exit interface's index, 0 when it is absent.
	ExitIfIndex uint32
}

// LocalRuleAdmitsOverlay is local_rule_admits_overlay: true when the rule
// looks up the local table and could match a packet that arrives on the
// overlay interface. Only two shapes cannot: the local-delivery guard itself
// (inverted, with the overlay interface as its only selector) and a rule
// whose positive iif names another interface. The kernel's default
// priority-0 rule matches everything.
func LocalRuleAdmitsOverlay(r rtnl.Rule, overlayIf string) bool {
	if r.Action != rtnl.FRActToTbl || r.Table != rtnl.TableLocal {
		return false
	}
	if r.Invert() {
		// Anything beyond the interface narrows the inversion into a rule
		// that is not the guard.
		return !guardShape(r, overlayIf)
	}
	return r.IifName == "" || r.IifName == overlayIf
}

// guardShape: inverted, the overlay interface the only selector.
func guardShape(r rtnl.Rule, overlayIf string) bool {
	if r.IifName != overlayIf || r.Src.IsValid() || r.Dst.IsValid() || r.OifName != "" || r.Tos != 0 ||
		r.FwMark.OK || r.FwMask.OK || r.IPProto.OK || r.SuppressPrefixLen.OK || r.SuppressIfGroup.OK ||
		r.Goto.OK || r.L3Mdev.OK || len(r.Unknown) > 0 || r.ExtraFlags() != 0 || r.Bad {
		return false
	}
	return true
}

func exactRule(r rtnl.Rule, want rtnl.Rule) bool {
	return !r.IifDetached() && !r.OifDetached() && equalItems(r.Items(), want.Items())
}

// FamilyStatus is family_status: whether one family holds the whole contract
// exactly — exact selectors, no extra rules in Molebridge's range, the
// terminal guard, safe table routes — and, separately, whether the exit
// table's unreachable fallback is in place. rules are all of the family's
// rules; routes the family's routes in the exit table.
func FamilyStatus(spec Spec, f rtnl.Family, rules []rtnl.Rule, routes []rtnl.Route, opt StatusOptions) (ready, fallback bool) {
	c := spec.Config
	st := spec.Clone()
	st.ReturnPath = map[rtnl.Family][]netip.Addr{}
	st.LeaveReturnPath = map[rtnl.Family]bool{}
	st.TempGuard = map[rtnl.Family]bool{}
	if opt.TunnelAddress.IsValid() {
		if (f == rtnl.V4) != opt.TunnelAddress.Is4() {
			return false, false
		}
		st.ReturnPath[f] = []netip.Addr{opt.TunnelAddress}
	}
	expected := map[uint32]rtnl.Rule{}
	for _, r := range st.Rules(f) {
		expected[r.Priority] = r
	}
	found := map[uint32]bool{}
	rulesOK := true
	for _, r := range rules {
		if LocalRuleAdmitsOverlay(r, c.OverlayIf) {
			rulesOK = false
		}
		// Past 97, only the priorities Molebridge owns are judged: 98 natively,
		// 102-104 with gluetun. gluetun's own rules (98-101) and NetBird's
		// (105, 110) are not.
		if r.Priority > PrioIngressReject && !st.Owned(r.Priority) {
			continue
		}
		want, ok := expected[r.Priority]
		if !ok || found[r.Priority] {
			rulesOK = false
			continue
		}
		found[r.Priority] = true
		if !exactRule(r, want) {
			rulesOK = false
		}
	}
	rulesOK = rulesOK && len(found) == len(expected)

	routesOK, tunnelDefault := true, false
	for _, r := range routes {
		switch {
		case isFallback(r):
			fallback = true
		case r.Type == rtnl.RTNUnicast && opt.ExitIfIndex != 0 && r.Oif.OK && r.Oif.V == opt.ExitIfIndex && plainDeviceRoute(r):
			// Only the default route counts as the tunnel route, and only an
			// unconditional one (see isTunnelRoute); another route out of the
			// tunnel interface is tolerated here (and removed by the repair
			// pass).
			if isTunnelRoute(r, opt.ExitIfIndex) && !r.LinkDown() {
				tunnelDefault = true
			}
		default:
			routesOK = false
		}
	}
	tunnelOK := tunnelDefault || !opt.TunnelAddress.IsValid() || opt.NoTunnelRoute
	return rulesOK && routesOK && fallback && tunnelOK, fallback
}

// TransitionOptions are gluetun_transition_status's keyword arguments.
type TransitionOptions struct {
	TunnelAddress   netip.Addr
	PreviousAddress netip.Addr
	// InterfacePresent and InterfaceUp describe the tunnel interface.
	InterfacePresent, InterfaceUp bool
	ExitIfIndex                   uint32
}

// GluetunTransitionStatus is gluetun_transition_status: (safe, ready) for
// one family of the gluetun backend while a switch is being verified.
//
// A PUT makes gluetun drop and recreate its tunnel interface, and the guard
// repairs the routing behind it, asynchronously. ready is FamilyStatus
// itself. safe (the protective predicate) is the same validation with exactly
// these reconnection states tolerated, any other deviation being unsafe:
//
//   - the exit table's tunnel default route missing (the unreachable fallback
//     must stay, and any other route is still unsafe);
//   - rules 90 and 96, which name the exit interface, in the kernel's detached
//     form while that interface is absent;
//   - the address present before its rule 94 is recreated;
//   - rule 94 for the previous address and for the current one at once, as
//     the guard adds before it deletes, each at most once and in its exact
//     form. Rule 94 for any other address is unsafe.
func GluetunTransitionStatus(spec Spec, f rtnl.Family, rules []rtnl.Rule, routes []rtnl.Route, opt TransitionOptions) (safe, ready bool) {
	ready, _ = FamilyStatus(spec, f, rules, routes, StatusOptions{
		TunnelAddress: opt.TunnelAddress, NoTunnelRoute: !opt.InterfaceUp, ExitIfIndex: opt.ExitIfIndex})
	if ready {
		return true, true
	}
	var adjusted, returnPaths []rtnl.Rule
	for _, r := range rules {
		if r.Priority == PrioReturnPath {
			returnPaths = append(returnPaths, r)
			continue
		}
		if (r.Priority == PrioFromTunnel || r.Priority == PrioEgress) && !opt.InterfacePresent {
			r.Flags &^= rtnl.FIBRuleIifDetached | rtnl.FIBRuleOifDetached
		}
		adjusted = append(adjusted, r)
	}
	var allowed []netip.Addr
	for _, a := range []netip.Addr{opt.PreviousAddress, opt.TunnelAddress} {
		if !a.IsValid() || containsAddr(allowed, a) {
			continue
		}
		if (f == rtnl.V4) != a.Is4() {
			return false, false
		}
		allowed = append(allowed, a)
	}
	matched := map[netip.Addr]bool{}
	for _, r := range returnPaths {
		var hit netip.Addr
		for _, a := range allowed {
			s := spec.Clone()
			s.ReturnPath = map[rtnl.Family][]netip.Addr{f: {a}}
			for _, e := range s.Rules(f) {
				if e.Priority == PrioReturnPath && exactRule(r, e) {
					hit = a
				}
			}
		}
		if !hit.IsValid() || matched[hit] {
			return false, false
		}
		matched[hit] = true
	}
	safe, _ = FamilyStatus(spec, f, adjusted, routes, StatusOptions{ExitIfIndex: opt.ExitIfIndex})
	return safe, false
}

func containsAddr(s []netip.Addr, a netip.Addr) bool {
	for _, x := range s {
		if x == a {
			return true
		}
	}
	return false
}

// HostTableStatus is host_table_status: the gluetun backend's host table
// holds only default and on-link routes through the host interface, never the
// tunnel or the overlay, and for IPv4 a default route. NetBird's control
// traffic depends on it; the IPv6 table may be empty when the host has no
// IPv6 route. With main (the main table's routes) and haveMain, the host
// table must hold the same destinations as main's default and on-link host
// routes.
func HostTableStatus(routes []rtnl.Route, hostIf uint32, f rtnl.Family, main []rtnl.Route, haveMain bool) bool {
	found, ok := hostDestinations(routes, hostIf)
	if !ok {
		return false
	}
	if haveMain {
		wanted := map[netip.Prefix]bool{}
		for _, r := range main {
			if r.Type == rtnl.RTNUnicast && r.Oif.OK && hostIf != 0 && r.Oif.V == hostIf && !r.Encap && !r.MultiPath &&
				!r.NHID.OK && (!r.Gateway.IsValid() || r.IsDefault()) {
				wanted[r.Dst] = true
			}
		}
		if len(wanted) != len(found) {
			return false
		}
		for d := range wanted {
			if !found[d] {
				return false
			}
		}
	}
	for d := range found {
		if d.Bits() == 0 {
			return true
		}
	}
	return f == rtnl.V6
}

// hostDestinations is _host_routes: the destinations of the default and
// on-link unicast routes through the host interface, or false if any route
// is something else.
func hostDestinations(routes []rtnl.Route, hostIf uint32) (map[netip.Prefix]bool, bool) {
	found := map[netip.Prefix]bool{}
	for _, r := range routes {
		if r.Type != rtnl.RTNUnicast || !r.Oif.OK || hostIf == 0 || r.Oif.V != hostIf || r.MultiPath || r.Encap || r.NHID.OK || !r.Unconditional() {
			return nil, false
		}
		if r.Gateway.IsValid() && !r.IsDefault() {
			return nil, false
		}
		found[r.Dst] = true
	}
	return found, true
}

// OverlayIsKernelWireguard is overlay_is_kernel_wireguard: the overlay
// interface exists and is of kind wireguard, as Molebridge requires. A
// userspace bind (a tun device) or netstack mode is not wireguard or has no
// link.
func OverlayIsKernelWireguard(links []rtnl.Link, overlayIf string) bool {
	for _, l := range links {
		if l.Name == overlayIf {
			return l.Kind == "wireguard"
		}
	}
	return false
}

// NftChain is a chain of the nftables ruleset.
type NftChain struct {
	// Family is the table's family as nft names it: "ip", "ip6", "inet".
	Family string
	Table  string
	Name   string
}

// NetBird's own netfilter objects in the pinned release (0.80.0): the
// nftables backend creates table `netbird`; the iptables backend creates
// chains such as NETBIRD-RT-FWD-IN. NetBird picks iptables whenever its
// iptables lists filter chains. The chains are visible here when that
// iptables uses the nftables backend, Alpine's default, which the pinned
// Alpine-based image is expected to use; legacy iptables would fail this
// check, closed.
const (
	NetBirdNftTable       = "netbird"
	NetBirdIptablesPrefix = "NETBIRD-"
)

// NetbirdFirewallPresent is netbird_firewall_present: NetBird's kernel
// firewall has its IPv4 table or chains in place. With kernel WireGuard
// NetBird's engine does not start without that firewall.
func NetbirdFirewallPresent(chains []NftChain) bool {
	for _, c := range chains {
		if c.Family != "ip" {
			continue
		}
		if c.Table == NetBirdNftTable || len(c.Name) >= len(NetBirdIptablesPrefix) && c.Name[:len(NetBirdIptablesPrefix)] == NetBirdIptablesPrefix {
			return true
		}
	}
	return false
}

// ReturnPathEnabled is return_path_enabled: the sysctl file content says the
// kernel sources ICMP errors from the inbound interface address.
func ReturnPathEnabled(value string) bool {
	for len(value) > 0 && (value[len(value)-1] == '\n' || value[len(value)-1] == ' ' || value[len(value)-1] == '\t' || value[len(value)-1] == '\r') {
		value = value[:len(value)-1]
	}
	for len(value) > 0 && (value[0] == '\n' || value[0] == ' ' || value[0] == '\t' || value[0] == '\r') {
		value = value[1:]
	}
	return value == "1"
}

// ReturnPathSysctl is the file ReturnPathEnabled reads: with the sysctl the
// kernel sources the exit's own ICMP errors (fragmentation needed, packet too
// big) from the tunnel address, and the priority-94 rule routes that address
// through the exit table.
const ReturnPathSysctl = "/proc/sys/net/ipv4/icmp_errors_use_inbound_ifaddr"

// RoutingOptions are the conditions beyond the snapshot that routing_status
// (applier/apply.py) judged.
type RoutingOptions struct {
	// RequireAddress: the exit interface must have a global IPv4 address.
	// Without it an interface with no address yet passes when its guards are
	// intact: a provider that assigns the address per server installs rules
	// 94 and 98 with it.
	RequireAddress bool
	// ReturnPath: the kernel sources the exit's own ICMP errors from the
	// inbound interface address (ReturnPathEnabled of the sysctl file).
	ReturnPath bool
}

// RoutingStatus is routing_status: (protected, fallback) for both families
// of the native backend, from one snapshot. The overlay interface and the
// tunnel interface must exist; the tunnel addresses are read from the
// interface, never its routes, and exactly one global address per family is
// supported (the return-path rule and the kernel's ICMP source selection
// both assume a single address). The owner record (the exit's liveness) is
// the supervisor's to judge, not this function's.
func RoutingStatus(spec Spec, snap *rtnl.Snapshot, opt RoutingOptions) (protected, fallback bool) {
	c := spec.Config
	if _, ok := snap.Link(c.OverlayIf); !ok {
		return false, false
	}
	link, ok := snap.Link(c.ExitIf)
	if !ok {
		return false, false
	}
	addresses := map[rtnl.Family]netip.Addr{}
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		for _, a := range snap.Addrs[f] {
			if a.Index != link.Index || !a.Global() {
				continue
			}
			if _, dup := addresses[f]; dup {
				return false, false
			}
			addresses[f] = a.Local.Addr()
		}
	}
	if !addresses[rtnl.V4].IsValid() && opt.RequireAddress {
		return false, false
	}
	protected, fallback = opt.ReturnPath, true
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		ready, fb := FamilyStatus(spec, f, snap.Rules[f], snap.RoutesInTable(f, c.Table),
			StatusOptions{TunnelAddress: addresses[f], ExitIfIndex: link.Index})
		protected = protected && ready
		fallback = fallback && fb
	}
	return protected, fallback
}
