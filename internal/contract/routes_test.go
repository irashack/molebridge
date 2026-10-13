package contract

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/irashack/molebridge/internal/rtnl"
)

func routeKinds(actions []RouteAction) []RouteActionKind {
	var out []RouteActionKind
	for _, a := range actions {
		out = append(out, a.Kind)
	}
	return out
}

func TestExitTableActions(t *testing.T) {
	foreign := rtnl.Route{Family: 4, Dst: netip.MustParsePrefix("203.0.113.99/32"), Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2))}
	viaGateway := tunnelRoute(4)
	viaGateway.Gateway = netip.MustParseAddr("203.0.113.2")
	nexthops := tunnelRoute(4)
	nexthops.MultiPath = true
	otherMetric := fallbackRoute(4)
	otherMetric.Metric = 100
	toOtherDevice := tunnelRoute(4)
	toOtherDevice.Oif = rtnl.Some(uint32(2))
	cases := []struct {
		name   string
		routes []rtnl.Route
		mode   TunnelMode
		want   []RouteActionKind
	}{
		{"tunnel up, all in place", []rtnl.Route{fallbackRoute(4), tunnelRoute(4)}, TunnelRequired, nil},
		{"order does not matter", []rtnl.Route{tunnelRoute(4), fallbackRoute(4)}, TunnelRequired, nil},
		{"empty table", nil, TunnelRequired, []RouteActionKind{AddFallback, AddTunnel}},
		{"empty table, tunnel down", nil, TunnelNone, []RouteActionKind{AddFallback}},
		{"fallback lost with the tunnel route", []rtnl.Route{tunnelRoute(4)}, TunnelRequired, []RouteActionKind{AddFallback}},
		{"tunnel route missing", []rtnl.Route{fallbackRoute(4)}, TunnelRequired, []RouteActionKind{AddTunnel}},
		{"tunnel route while the tunnel is down", []rtnl.Route{fallbackRoute(4), tunnelRoute(4)}, TunnelNone, []RouteActionKind{DelRoute}},
		{"tunnel coming up: route allowed", []rtnl.Route{fallbackRoute(4), tunnelRoute(4)}, TunnelMaybe, nil},
		{"tunnel coming up: route not required", []rtnl.Route{fallbackRoute(4)}, TunnelMaybe, nil},
		{"foreign route", []rtnl.Route{fallbackRoute(4), tunnelRoute(4), foreign}, TunnelRequired, []RouteActionKind{DelRoute}},
		{"duplicate fallback", []rtnl.Route{fallbackRoute(4), fallbackRoute(4), tunnelRoute(4)}, TunnelRequired, []RouteActionKind{DelRoute}},
		{"duplicate tunnel route", []rtnl.Route{fallbackRoute(4), tunnelRoute(4), tunnelRoute(4)}, TunnelRequired, []RouteActionKind{DelRoute}},
		{"default through a gateway is not the tunnel route", []rtnl.Route{fallbackRoute(4), viaGateway}, TunnelRequired, []RouteActionKind{AddTunnel, DelRoute}},
		{"multipath default", []rtnl.Route{fallbackRoute(4), nexthops}, TunnelRequired, []RouteActionKind{AddTunnel, DelRoute}},
		{"fallback with another metric", []rtnl.Route{otherMetric, tunnelRoute(4)}, TunnelRequired, []RouteActionKind{AddFallback, DelRoute}},
		{"default through another device", []rtnl.Route{fallbackRoute(4), toOtherDevice}, TunnelRequired, []RouteActionKind{AddTunnel, DelRoute}},
	}
	for _, c := range cases {
		got := ExitTableActions(c.routes, rtnl.V4, 51821, exitIfIndex, c.mode)
		if !reflect.DeepEqual(routeKinds(got), c.want) && !(len(got) == 0 && len(c.want) == 0) {
			t.Errorf("%s: %v, want %v", c.name, routeKinds(got), c.want)
		}
	}
	// With the interface absent nothing can be the tunnel route and none is added.
	got := ExitTableActions([]rtnl.Route{fallbackRoute(4)}, rtnl.V4, 51821, 0, TunnelRequired)
	if len(got) != 0 {
		t.Errorf("no interface: %v", routeKinds(got))
	}
	// The routes it installs are the documented ones.
	got = ExitTableActions(nil, rtnl.V6, 51821, exitIfIndex, TunnelRequired)
	if got[0].Route.Type != rtnl.RTNUnreachable || got[0].Route.Metric != 4096 || !got[0].Route.IsDefault() || got[0].Route.Table != 51821 {
		t.Errorf("%+v", got[0].Route)
	}
	if got[1].Route.Type != rtnl.RTNUnicast || got[1].Route.Oif.V != exitIfIndex || got[1].Route.Gateway.IsValid() || got[1].Route.Scope != rtnl.RTScopeLink {
		t.Errorf("%+v", got[1].Route)
	}
}

func main(dst, gw, src string, metric uint32, dev uint32) rtnl.Route {
	r := rtnl.Route{Family: 4, Table: 254, Type: rtnl.RTNUnicast, Oif: rtnl.Some(dev), Metric: metric}
	if dst == "default" {
		r.Dst = zero(4)
	} else {
		r.Dst = netip.MustParsePrefix(dst)
	}
	if gw != "" {
		r.Gateway = netip.MustParseAddr(gw)
	}
	if src != "" {
		r.PrefSrc = netip.MustParseAddr(src)
	}
	return r
}

func TestHostRoutes(t *testing.T) {
	onlinkHost := main("198.51.100.77/32", "", "", 0, 2)
	onlinkHost.Flags = rtnl.RTNHFOnlink
	routes := []rtnl.Route{
		main("default", "198.51.100.2", "", 0, 2),
		main("198.51.100.0/28", "", "198.51.100.1", 0, 2),
		main("192.0.2.0/24", "", "192.0.2.1", 0, 3),    // the overlay
		main("10.64.0.0/10", "198.51.100.3", "", 0, 2), // a gateway route that is not the default
		{Family: 4, Table: 254, Type: rtnl.RTNUnreachable, Dst: netip.MustParsePrefix("203.0.113.0/24")},
		onlinkHost,
	}
	// The main table: other routes are ignored, on-link first.
	list, odd := HostRoutes(routes, 2, false)
	if odd {
		t.Error("odd without check")
	}
	if len(list) != 3 || list[0].Via.IsValid() || list[1].Via.IsValid() || !list[2].Via.IsValid() {
		t.Fatalf("%+v", list)
	}
	if list[0].Dst.String() != "198.51.100.0/28" || list[0].Src.String() != "198.51.100.1" || !list[1].OnLink {
		t.Errorf("%+v", list)
	}
	// The host table: anything else is odd.
	if _, odd := HostRoutes(routes, 2, true); !odd {
		t.Error("the host table must report the extra routes")
	}
	table := []rtnl.Route{main("default", "198.51.100.2", "", 0, 2), main("198.51.100.0/28", "", "198.51.100.1", 0, 2), onlinkHost}
	copyList, odd := HostRoutes(table, 2, true)
	if odd || !HostTableMatches(list, copyList, odd) {
		t.Errorf("a faithful copy should match: odd=%v %+v", odd, copyList)
	}
	// A different source address or metric is a difference.
	other := append([]rtnl.Route{}, table...)
	other[1].PrefSrc = netip.MustParseAddr("198.51.100.9")
	otherList, _ := HostRoutes(other, 2, true)
	if HostTableMatches(list, otherList, false) {
		t.Error("a different src matched")
	}
	if !HasIPv4Default(list) || HasIPv4Default(list[:2]) {
		t.Error("HasIPv4Default")
	}
	// Re-installing a copy reproduces the route.
	r := list[2].Route(rtnl.V4, 51822, 2)
	if r.Table != 51822 || r.Gateway.String() != "198.51.100.2" || r.Scope != rtnl.RTScopeUniverse || !r.Dst.IsValid() {
		t.Errorf("%+v", r)
	}
	r = list[1].Route(rtnl.V4, 51822, 2)
	if r.Flags&rtnl.RTNHFOnlink == 0 || r.Scope != rtnl.RTScopeLink {
		t.Errorf("%+v", r)
	}
	// Odd shapes.
	for name, mod := range map[string]func(*rtnl.Route){
		"encap": func(r *rtnl.Route) { r.Encap = true }, "nhid": func(r *rtnl.Route) { r.NHID = rtnl.Some(uint32(1)) },
		"via": func(r *rtnl.Route) { r.Via = true }, "multipath": func(r *rtnl.Route) { r.MultiPath = true },
	} {
		odd := main("default", "198.51.100.2", "", 0, 2)
		mod(&odd)
		if l, o := HostRoutes([]rtnl.Route{odd}, 2, true); len(l) != 0 || !o {
			t.Errorf("%s: %v %v", name, l, o)
		}
	}
	if l, _ := HostRoutes(routes, 0, false); len(l) != 0 {
		t.Error("an absent host interface must match nothing")
	}
}

// A route is the contract's route only if every selector matches: a TOS, a
// source selector or an input interface narrows it to other traffic, and a
// scope or metric that differs changes whether and when it is chosen. The
// reviewer's case: with both IPv4 routes at TOS 16 the pass verified with no
// mutation.
func TestRoutesThatOnlyLookLikeTheContractsAreNotTheContractsRoutes(t *testing.T) {
	with := func(r rtnl.Route, edit func(*rtnl.Route)) rtnl.Route { edit(&r); return r }
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		fb, tun := fallbackRoute(f), tunnelRoute(f)
		src := netip.PrefixFrom(netip.MustParseAddr(map[rtnl.Family]string{rtnl.V4: "203.0.113.5", rtnl.V6: "2001:db8:3::5"}[f]), map[rtnl.Family]int{rtnl.V4: 32, rtnl.V6: 128}[f])
		cases := []struct {
			name   string
			routes []rtnl.Route
			want   []RouteActionKind
		}{
			{"both with a TOS", []rtnl.Route{with(fb, func(r *rtnl.Route) { r.Tos = 16 }), with(tun, func(r *rtnl.Route) { r.Tos = 16 })}, []RouteActionKind{AddFallback, AddTunnel, DelRoute, DelRoute}},
			{"the fallback with a TOS", []rtnl.Route{with(fb, func(r *rtnl.Route) { r.Tos = 16 }), tun}, []RouteActionKind{AddFallback, DelRoute}},
			{"the tunnel route with a TOS", []rtnl.Route{fb, with(tun, func(r *rtnl.Route) { r.Tos = 16 })}, []RouteActionKind{AddTunnel, DelRoute}},
			{"the tunnel route from a source", []rtnl.Route{fb, with(tun, func(r *rtnl.Route) { r.Src = src })}, []RouteActionKind{AddTunnel, DelRoute}},
			{"the fallback from a source", []rtnl.Route{with(fb, func(r *rtnl.Route) { r.Src = src }), tun}, []RouteActionKind{AddFallback, DelRoute}},
			{"the tunnel route for an input interface", []rtnl.Route{fb, with(tun, func(r *rtnl.Route) { r.Iif = rtnl.Some(uint32(2)) })}, []RouteActionKind{AddTunnel, DelRoute}},
			{"the tunnel route with a metric above the fallback's", []rtnl.Route{fb, with(tun, func(r *rtnl.Route) { r.Metric = 5000 })}, []RouteActionKind{AddTunnel, DelRoute}},
			{"a dead tunnel route", []rtnl.Route{fb, with(tun, func(r *rtnl.Route) { r.Flags = rtnl.RTNHFDead })}, []RouteActionKind{AddTunnel, DelRoute}},
		}
		if f == rtnl.V4 {
			cases = append(cases,
				struct {
					name   string
					routes []rtnl.Route
					want   []RouteActionKind
				}{"the tunnel route with universe scope", []rtnl.Route{fb, with(tun, func(r *rtnl.Route) { r.Scope = rtnl.RTScopeUniverse })}, []RouteActionKind{AddTunnel, DelRoute}},
				struct {
					name   string
					routes []rtnl.Route
					want   []RouteActionKind
				}{"the fallback with link scope", []rtnl.Route{with(fb, func(r *rtnl.Route) { r.Scope = rtnl.RTScopeLink }), tun}, []RouteActionKind{AddFallback, DelRoute}})
		}
		for _, tc := range cases {
			got := routeKinds(ExitTableActions(tc.routes, f, 51821, exitIfIndex, TunnelRequired))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("%s %s: %v, want %v", f, tc.name, got, tc.want)
			}
			// The readiness judgment agrees: not ready, whatever the rules say.
			if ready, _ := nativeStatus(nativeRules(f), tc.routes, f, true); ready {
				t.Errorf("%s %s: ready", f, tc.name)
			}
		}
	}
}

func TestAHostRouteWithATOSIsNotAHostRoute(t *testing.T) {
	r := rtnl.Route{Family: rtnl.V4, Dst: netip.PrefixFrom(netip.IPv4Unspecified(), 0), Table: 254, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2)),
		Gateway: netip.MustParseAddr("198.51.100.2")}
	if list, odd := HostRoutes([]rtnl.Route{r}, 2, true); len(list) != 1 || odd {
		t.Fatalf("%v %v", list, odd)
	}
	r.Tos = 16
	if list, odd := HostRoutes([]rtnl.Route{r}, 2, true); len(list) != 0 || !odd {
		t.Errorf("a TOS route was taken for a host route: %v %v", list, odd)
	}
	if _, ok := hostDestinations([]rtnl.Route{r}, 2); ok {
		t.Error("the status judgment accepted a TOS route in the host table")
	}
}
