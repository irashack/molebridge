package contract

import (
	"net/netip"
	"sort"

	"github.com/irashack/molebridge/internal/rtnl"
)

// FallbackMetric is the metric of the exit table's permanent
// `unreachable default`, which keeps the table fail-closed whatever happens
// to the tunnel route.
const FallbackMetric = 4096

// TunnelMode is exit_table_actions' tunnel argument.
type TunnelMode uint8

const (
	// TunnelNone: no tunnel default route belongs in the table.
	TunnelNone TunnelMode = 0
	// TunnelRequired: the tunnel is up and carries the family; its default
	// route belongs in the table.
	TunnelRequired TunnelMode = 1
	// TunnelMaybe: the tunnel is coming up; a default route through it is
	// allowed but not required.
	TunnelMaybe TunnelMode = 2
)

// RouteActionKind is a step in repairing a routing table.
type RouteActionKind uint8

const (
	// AddFallback restores `unreachable default metric 4096`.
	AddFallback RouteActionKind = iota + 1
	// AddTunnel restores `default dev <tunnel>`.
	AddTunnel
	// DelRoute removes a route that does not belong.
	DelRoute
)

// RouteAction is one step of an exit-table repair.
type RouteAction struct {
	Kind RouteActionKind
	// Route is the route to install, or the route found to remove.
	Route rtnl.Route
}

func defaultPrefix(f rtnl.Family) netip.Prefix {
	if f == rtnl.V6 {
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
}

// FallbackRoute is the route AddFallback installs.
func FallbackRoute(f rtnl.Family, table uint32) rtnl.Route {
	return rtnl.Route{Family: f, Dst: defaultPrefix(f), Table: table, Type: rtnl.RTNUnreachable,
		Metric: FallbackMetric, Protocol: rtnl.RTProtoBoot, Scope: rtnl.RTScopeUniverse}
}

// TunnelRoute is the route AddTunnel installs: a default route out of the
// tunnel interface, no gateway.
func TunnelRoute(f rtnl.Family, table uint32, ifIndex uint32) rtnl.Route {
	return rtnl.Route{Family: f, Dst: defaultPrefix(f), Table: table, Type: rtnl.RTNUnicast,
		Oif: rtnl.Some(ifIndex), Protocol: rtnl.RTProtoBoot, Scope: rtnl.RTScopeLink}
}

func plainDeviceRoute(r rtnl.Route) bool {
	return !r.Gateway.IsValid() && !r.Via && !r.MultiPath && !r.NHID.OK
}

// ExitTableActions compares the routes of the exit table in one family with
// the contract: `unreachable default metric 4096` always, `default dev
// <tunnel>` as the mode says, nothing else (exit_table_actions). routes must
// be the family's routes in the exit table; exitIf is the tunnel interface's
// index, 0 when it does not exist.
func ExitTableActions(routes []rtnl.Route, f rtnl.Family, table uint32, exitIf uint32, mode TunnelMode) []RouteAction {
	var del []RouteAction
	fallback, found := false, false
	for _, r := range routes {
		switch {
		case r.Type == rtnl.RTNUnreachable && r.IsDefault() && r.Metric == FallbackMetric && !fallback:
			fallback = true
		case r.Type == rtnl.RTNUnicast && r.IsDefault() && exitIf != 0 && r.Oif.OK && r.Oif.V == exitIf &&
			plainDeviceRoute(r) && (mode == TunnelRequired || mode == TunnelMaybe) && !found:
			found = true
		default:
			del = append(del, RouteAction{Kind: DelRoute, Route: r})
		}
	}
	var out []RouteAction
	if !fallback {
		out = append(out, RouteAction{Kind: AddFallback, Route: FallbackRoute(f, table)})
	}
	if mode == TunnelRequired && !found && exitIf != 0 {
		out = append(out, RouteAction{Kind: AddTunnel, Route: TunnelRoute(f, table, exitIf)})
	}
	return append(out, del...)
}

// HostRoute is one route of the host table: a default or on-link route
// through the namespace's host interface.
type HostRoute struct {
	Dst    netip.Prefix
	Via    netip.Addr
	Src    netip.Addr
	Metric uint32
	OnLink bool
}

func (h HostRoute) kind() int {
	if h.Via.IsValid() {
		return 1
	}
	return 0
}

// HostRoutes extracts the default and on-link unicast routes through the host
// interface, on-link first so a gateway is reachable when its default route
// goes in (host_routes). With check, any other route in the table is
// reported in odd; without it, other routes are ignored, as for the main
// table.
func HostRoutes(routes []rtnl.Route, hostIf uint32, check bool) (list []HostRoute, odd bool) {
	for _, r := range routes {
		switch r.Type {
		case rtnl.RTNUnicast:
		case rtnl.RTNUnreachable, rtnl.RTNBlackhole, rtnl.RTNProhibit, rtnl.RTNThrow, rtnl.RTNLocal,
			rtnl.RTNBroadcast, rtnl.RTNMulticast, rtnl.RTNAnycast, rtnl.RTNNAT:
			odd = odd || check
			continue
		default:
			odd = odd || check
			continue
		}
		unusual := r.Via || r.NHID.OK || r.Encap || r.MultiPath
		if !r.Oif.OK || r.Oif.V != hostIf || hostIf == 0 || unusual || (r.Gateway.IsValid() && !r.IsDefault()) {
			odd = odd || check
			continue
		}
		list = append(list, HostRoute{Dst: r.Dst, Via: r.Gateway, Src: r.PrefSrc, Metric: r.Metric, OnLink: r.OnLink()})
	}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if a.kind() != b.kind() {
			return a.kind() < b.kind()
		}
		if a.Dst != b.Dst {
			return a.Dst.String() < b.Dst.String()
		}
		if a.Via != b.Via {
			return a.Via.Less(b.Via)
		}
		if a.Src != b.Src {
			return a.Src.Less(b.Src)
		}
		if a.Metric != b.Metric {
			return a.Metric < b.Metric
		}
		return !a.OnLink && b.OnLink
	})
	return list, odd
}

// HostTableMatches reports whether the host table holds exactly the main
// table's host routes.
func HostTableMatches(main, host []HostRoute, hostOdd bool) bool {
	if hostOdd || len(main) != len(host) {
		return false
	}
	for i := range main {
		if main[i] != host[i] {
			return false
		}
	}
	return true
}

// HostRoute returns the route that copies h into the host table.
func (h HostRoute) Route(f rtnl.Family, table, hostIf uint32) rtnl.Route {
	r := rtnl.Route{Family: f, Dst: h.Dst, Table: table, Type: rtnl.RTNUnicast, Oif: rtnl.Some(hostIf),
		Gateway: h.Via, PrefSrc: h.Src, Metric: h.Metric, Protocol: rtnl.RTProtoBoot, Scope: rtnl.RTScopeLink}
	if h.Via.IsValid() {
		r.Scope = rtnl.RTScopeUniverse
	}
	if h.OnLink {
		r.Flags = rtnl.RTNHFOnlink
	}
	return r
}

// HasIPv4Default reports a default route among the host routes.
func HasIPv4Default(list []HostRoute) bool {
	for _, h := range list {
		if h.Dst.Bits() == 0 {
			return true
		}
	}
	return false
}
