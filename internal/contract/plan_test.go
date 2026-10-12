package contract

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/irashack/molebridge/internal/rtnl"
)

func nativeSnapshot() *rtnl.Snapshot {
	s := rtnl.NewSnapshot()
	s.Links = []rtnl.Link{{Index: 1, Name: "lo", Flags: rtnl.IFFUp}, {Index: 2, Name: "eth0", Flags: rtnl.IFFUp},
		{Index: 3, Name: "wt0", Flags: rtnl.IFFUp, Kind: "wireguard"}, {Index: exitIfIndex, Name: "mullvad", Flags: rtnl.IFFUp, Kind: "wireguard"}}
	for _, f := range families {
		for _, r := range nativeRules(f) {
			if r.Priority <= 98 {
				s.Rules[f] = append(s.Rules[f], r)
			}
		}
		s.Routes[f] = nativeRoutes(f)
	}
	return s
}

func TestNativePlanOfAHealthyNamespaceIsClean(t *testing.T) {
	for _, f := range families {
		p := nativeSpec().PlanFamily(nativeSnapshot(), f, PlanInput{})
		if !p.Clean() || p.Tunnel != TunnelRequired {
			t.Errorf("%s: %+v", f, p)
		}
	}
}

func TestNativePlanNamesWhatIsWrong(t *testing.T) {
	s := nativeSnapshot()
	s.Rules[4] = without(s.Rules[4], 95)
	s.Routes[4] = s.Routes[4][1:]
	p := nativeSpec().PlanFamily(s, rtnl.V4, PlanInput{})
	if !reflect.DeepEqual(p.Problems, []Problem{ProblemRules, ProblemExit}) {
		t.Fatalf("%v", p.Problems)
	}
	if p.Clean() || p.Rules[0].Priority != 95 || p.Routes[0].Kind != AddTunnel {
		t.Fatalf("%+v", p)
	}
}

func TestNativePlanTunnelModes(t *testing.T) {
	s := nativeSnapshot()
	// The tunnel link is down: no tunnel route belongs.
	s.Links[3].Flags = 0
	p := nativeSpec().PlanFamily(s, rtnl.V4, PlanInput{})
	if p.Tunnel != TunnelNone || len(p.Routes) != 1 || p.Routes[0].Kind != DelRoute {
		t.Errorf("down: %+v", p)
	}
	// Absent: the same.
	s = nativeSnapshot()
	s.Links = s.Links[:3]
	p = nativeSpec().PlanFamily(s, rtnl.V4, PlanInput{})
	if p.Tunnel != TunnelNone || len(p.Routes) != 1 || p.Routes[0].Kind != DelRoute {
		t.Errorf("absent: %+v", p)
	}
	// Starting: a route is allowed, not required.
	p = nativeSpec().PlanFamily(nativeSnapshot(), rtnl.V4, PlanInput{TunnelStarting: true})
	if p.Tunnel != TunnelMaybe || !p.Clean() {
		t.Errorf("starting: %+v", p)
	}
	s = nativeSnapshot()
	s.Routes[4] = s.Routes[4][1:]
	if p = nativeSpec().PlanFamily(s, rtnl.V4, PlanInput{TunnelStarting: true}); !p.Clean() {
		t.Errorf("starting without the route: %+v", p)
	}
	// An IPv4-only tunnel: IPv6 gets the fallback only, and a stray default
	// route through the tunnel is removed.
	spec := nativeSpec()
	spec.ReturnPath = map[rtnl.Family][]netip.Addr{rtnl.V4: {netip.MustParseAddr(tunnel4)}}
	s = nativeSnapshot()
	s.Rules[6] = without(s.Rules[6], 94, 98)
	p = spec.PlanFamily(s, rtnl.V6, PlanInput{})
	if p.Tunnel != TunnelNone || len(p.Routes) != 1 || p.Routes[0].Kind != DelRoute || len(p.Rules) != 0 {
		t.Errorf("IPv4-only tunnel, IPv6: %+v", p)
	}
	// A PIA config: IPv4 always carries, IPv6 never.
	pia := Spec{Config: nativeConfig(), LeaveReturnPath: map[rtnl.Family]bool{rtnl.V4: true, rtnl.V6: true}}
	s = nativeSnapshot()
	s.Rules[4], s.Rules[6] = without(s.Rules[4], 94, 98), without(s.Rules[6], 94, 98)
	if p = pia.PlanFamily(s, rtnl.V4, PlanInput{}); p.Tunnel != TunnelRequired || !p.Clean() {
		t.Errorf("PIA IPv4: %+v", p)
	}
	s.Routes[6] = s.Routes[6][1:]
	if p = pia.PlanFamily(s, rtnl.V6, PlanInput{}); p.Tunnel != TunnelNone || !p.Clean() {
		t.Errorf("PIA IPv6: %+v", p)
	}
}

func glSnapshot() *rtnl.Snapshot {
	s := rtnl.NewSnapshot()
	s.Links = []rtnl.Link{{Index: 1, Name: "lo", Flags: rtnl.IFFUp}, {Index: 2, Name: "eth0", Flags: rtnl.IFFUp},
		{Index: 3, Name: "wt0", Flags: rtnl.IFFUp, Kind: "wireguard"}, {Index: exitIfIndex, Name: "wg0", Flags: rtnl.IFFUp}}
	s.Addrs[4] = []rtnl.Addr{{Family: 4, Index: exitIfIndex, Local: netip.MustParsePrefix(tunnel4 + "/32")}}
	s.Addrs[6] = []rtnl.Addr{{Family: 6, Index: exitIfIndex, Local: netip.MustParsePrefix(tunnel6 + "/128")}}
	for _, f := range families {
		for _, r := range glRules(f) {
			if r.Priority <= 97 || r.Priority >= 102 && r.Priority <= 104 || r.Priority == 98 || r.Priority == 101 {
				s.Rules[f] = append(s.Rules[f], r)
			}
		}
		s.Routes[f] = []rtnl.Route{
			{Family: f, Dst: zero(f), Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(exitIfIndex))},
			fallbackRoute(f),
		}
	}
	gw4 := rtnl.Route{Family: 4, Dst: zero(4), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2)), Gateway: netip.MustParseAddr("198.51.100.2")}
	onlink := rtnl.Route{Family: 4, Dst: netip.MustParsePrefix("198.51.100.0/28"), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2)), PrefSrc: netip.MustParseAddr("198.51.100.1")}
	for _, r := range []rtnl.Route{onlink, gw4} {
		m, h := r, r
		m.Table, h.Table = rtnl.TableMain, 51822
		s.Routes[4] = append(s.Routes[4], m, h)
	}
	return s
}

func TestGluetunPlanOfAHealthyNamespaceIsClean(t *testing.T) {
	for _, f := range families {
		p := glSpec().PlanFamily(glSnapshot(), f, PlanInput{})
		if !p.Clean() || p.Address != netip.MustParseAddr(addrOf(f)) || p.Tunnel != TunnelRequired {
			t.Errorf("%s: %+v", f, p)
		}
	}
}

func TestGluetunPlanRefreshesAndHoldsTheKillSwitch(t *testing.T) {
	s := glSnapshot()
	var kept []rtnl.Route
	for _, r := range s.Routes[4] {
		if r.Table != 51822 {
			kept = append(kept, r)
		}
	}
	s.Routes[4] = kept // the host table is empty
	s.Rules[4] = without(s.Rules[4], 104)
	p := glSpec().PlanFamily(s, rtnl.V4, PlanInput{})
	if !p.HostRefresh || !p.HoldKillSwitch || len(p.HostWant) != 2 || len(p.HostFlush) != 0 {
		t.Fatalf("%+v", p)
	}
	for _, a := range p.Rules {
		if a.Priority == 104 {
			t.Error("rule 104 planned while the host table is empty")
		}
	}
	if !reflect.DeepEqual(p.Problems, []Problem{ProblemHost}) {
		t.Errorf("%v", p.Problems)
	}
	// A stale route in the host table is flushed.
	s = glSnapshot()
	s.Routes[4] = append(s.Routes[4], rtnl.Route{Family: 4, Table: 51822, Dst: netip.MustParsePrefix("10.0.0.0/8"), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(9))})
	p = glSpec().PlanFamily(s, rtnl.V4, PlanInput{})
	if !p.HostRefresh || len(p.HostFlush) != 3 {
		t.Fatalf("%+v", p)
	}
}

func TestGluetunPlanReportsMissingDefault(t *testing.T) {
	s := glSnapshot()
	var kept []rtnl.Route
	for _, r := range s.Routes[4] {
		if !r.IsDefault() || r.Table == 51821 {
			kept = append(kept, r)
		}
	}
	s.Routes[4] = kept
	p := glSpec().PlanFamily(s, rtnl.V4, PlanInput{})
	if p.HostRefresh || !reflect.DeepEqual(p.Problems, []Problem{ProblemNoDefault}) || !p.Clean() || p.Healthy() {
		t.Fatalf("%+v", p)
	}
	// IPv6 may have no default.
	if p := glSpec().PlanFamily(glSnapshot(), rtnl.V6, PlanInput{}); !p.Healthy() {
		t.Fatalf("%+v", p)
	}
}

func TestGluetunPlanFollowsTheObservedAddress(t *testing.T) {
	s := glSnapshot()
	s.Addrs[4][0].Local = netip.MustParsePrefix("10.64.0.9/32")
	p := glSpec().PlanFamily(s, rtnl.V4, PlanInput{})
	// The old rule 94 is stale, the new one missing: add first, then remove.
	if len(p.Rules) != 2 || p.Rules[0].Kind != Add || p.Rules[0].Priority != 94 || p.Rules[1].Kind != Del {
		t.Fatalf("%v", kinds(p.Rules))
	}
	// The interface up without an address: no tunnel route required, and the
	// fallback must stay.
	s = glSnapshot()
	s.Addrs[4] = nil
	s.Routes[4] = append([]rtnl.Route{}, s.Routes[4][1:]...)
	p = glSpec().PlanFamily(s, rtnl.V4, PlanInput{})
	if p.Tunnel != TunnelNone || len(p.Routes) != 0 {
		t.Fatalf("%+v", p)
	}
}

func TestInterestListsTheTablesToDump(t *testing.T) {
	if got := nativeSpec().Interest().Tables; !reflect.DeepEqual(got, []uint32{51821}) {
		t.Error(got)
	}
	if got := glSpec().Interest().Tables; !reflect.DeepEqual(got, []uint32{51821, 51822, 254}) {
		t.Error(got)
	}
}
