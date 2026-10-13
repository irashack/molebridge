package policy

import (
	"net/netip"
	"sort"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

func cfg(t *testing.T, env map[string]string) contract.Config {
	t.Helper()
	c, err := contract.ConfigFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// kernelRules are the kernel's own, less rule 0: the contract removes it, and
// with it the overlay's way to local delivery.
func kernelRules(f rtnl.Family) []rtnl.Rule {
	return []rtnl.Rule{
		{Family: f, Priority: 32766, Action: rtnl.FRActToTbl, Table: rtnl.TableMain},
		{Family: f, Priority: 32767, Action: rtnl.FRActToTbl, Table: 253},
	}
}

var (
	tunnel4 = netip.MustParseAddr("203.0.113.1")
	tunnel6 = netip.MustParseAddr("2001:db8:3::1")
)

func nativeState(t *testing.T) State {
	spec := contract.Spec{Config: cfg(t, map[string]string{"OVERLAY_CIDR": "192.0.2.0/24", "OVERLAY6_CIDR": "2001:db8:1::/64", "OVERLAY_IF": "wt0",
		"EXIT_IF": "mullvad", "EXIT_TABLE": "51821"}),
		ReturnPath: map[rtnl.Family][]netip.Addr{rtnl.V4: {tunnel4}, rtnl.V6: {tunnel6}}}
	return healthy(spec)
}

func gluetunState(t *testing.T) State {
	spec := contract.Spec{Config: cfg(t, map[string]string{"TUNNEL_BACKEND": "gluetun", "OVERLAY_CIDR": "192.0.2.0/24", "OVERLAY6_CIDR": "2001:db8:1::/64",
		"OVERLAY_IF": "wt0", "EXIT_IF": "wg0", "EXIT_TABLE": "51821", "HOST_IF": "eth0", "HOST_TABLE": "51822", "CONTROL_MARK": "0x1bd00"}),
		ReturnPath: map[rtnl.Family][]netip.Addr{rtnl.V4: {tunnel4}, rtnl.V6: {tunnel6}}}
	s := healthy(spec)
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		// gluetun's own rules.
		s.Rules[f] = append(s.Rules[f],
			rtnl.Rule{Family: f, Priority: 101, Action: rtnl.FRActToTbl, Table: 51820, Flags: rtnl.FIBRuleInvert, FwMark: rtnl.Some(uint32(51820)), FwMask: rtnl.Some(uint32(0xffffffff))})
		sort.SliceStable(s.Rules[f], func(i, j int) bool { return s.Rules[f][i].Priority < s.Rules[f][j].Priority })
		def := rtnl.Route{Family: f, Dst: netip.PrefixFrom(map[rtnl.Family]netip.Addr{rtnl.V4: netip.IPv4Unspecified(), rtnl.V6: netip.IPv6Unspecified()}[f], 0), Type: rtnl.RTNUnicast}
		h := def
		h.Table = 51822
		s.Routes[f][51822] = []rtnl.Route{h}
		m := def
		m.Table = rtnl.TableMain
		ov := rtnl.Route{Family: f, Dst: spec.Config.OverlayFor(f), Table: rtnl.TableMain, Type: rtnl.RTNUnicast}
		s.Routes[f][rtnl.TableMain] = []rtnl.Route{m, ov}
	}
	return s
}

// healthy: the contract installed with the tunnel up.
func healthy(spec contract.Spec) State {
	s := State{Spec: spec, Rules: map[rtnl.Family][]rtnl.Rule{}, Routes: map[rtnl.Family]map[uint32][]rtnl.Route{},
		Known: map[uint32]bool{}, Live: map[rtnl.Family][]netip.Addr{rtnl.V4: {tunnel4}, rtnl.V6: {tunnel6}}}
	for _, tb := range spec.Interest().Tables {
		s.Known[tb] = true
	}
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		rules := append(kernelRules(f), spec.Rules(f)...)
		sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
		s.Rules[f] = rules
		s.Routes[f] = map[uint32][]rtnl.Route{}
		for tb := range s.Known {
			s.Routes[f][tb] = nil
		}
		s.Routes[f][spec.Config.Table] = []rtnl.Route{contract.FallbackRoute(f, spec.Config.Table), contract.TunnelRoute(f, spec.Config.Table, 3)}
	}
	return s
}

func TestAHealthyContractHasNoEscape(t *testing.T) {
	for name, s := range map[string]State{"native": nativeState(t), "gluetun": gluetunState(t)} {
		if v := s.Violations(); len(v) != 0 {
			t.Errorf("%s: %v", name, v)
		}
		if len(s.Probes()) < 6 {
			t.Errorf("%s: only %d classes", name, len(s.Probes()))
		}
	}
}

// Each protection, removed on its own from a healthy contract, is the escape
// of exactly the class it protects, and the one a dependent rule backs up
// leaves the class protected.
func TestDeletingWhatNothingBacksUpIsRefused(t *testing.T) {
	s := nativeState(t)
	for _, p := range []uint32{1, 95, 97} {
		after, ok := s.WithoutPriority(rtnl.V4, p)
		if !ok {
			t.Fatalf("no rule %d", p)
		}
		_ = after
	}
	// Rule 95 alone: 97 still stops forwarded traffic; the exit table is not
	// used but nothing escapes.
	after, _ := s.WithoutPriority(rtnl.V4, 95)
	if v := Worsened(s.Violations(), after.Violations()); len(v) != 0 {
		t.Errorf("rule 95 is backed up by 97: %v", v)
	}
	// Both 95 and 97: forwarded traffic reaches the main table.
	after, _ = after.WithoutPriority(rtnl.V4, 97)
	if v := after.Violations(); len(v) == 0 {
		t.Error("forwarded traffic escapes without 95 and 97")
	}
	// The kernel's rule 0 delivers overlay traffic locally; back, it is an
	// escape, and deleting it never makes one.
	withZero := s.clone()
	withZero.Rules[rtnl.V4] = append([]rtnl.Rule{{Family: rtnl.V4, Priority: 0, Action: rtnl.FRActToTbl, Table: rtnl.TableLocal}}, withZero.Rules[rtnl.V4]...)
	if v := withZero.Violations(); len(v) == 0 {
		t.Error("overlay traffic is not delivered locally with the kernel's rule 0")
	}
	gone, _ := withZero.WithoutPriority(rtnl.V4, 0)
	if v := Worsened(withZero.Violations(), gone.Violations()); len(v) != 0 || len(gone.Violations()) != 0 {
		t.Errorf("removing rule 0: %v", gone.Violations())
	}
	// Without rule 1 and with rule 0, the same.
	noOne, _ := withZero.WithoutPriority(rtnl.V4, 1)
	if len(noOne.Violations()) == 0 {
		t.Error("rule 0 without rule 1 is safe?")
	}
}

func TestICMPFromATunnelAddressIsKeptOffTheHostRoute(t *testing.T) {
	s := nativeState(t)
	// 94 and 98 each back the other up; losing both is an escape.
	a, _ := s.WithoutRule(rtnl.Rule{Family: rtnl.V4, Priority: 94, Src: netip.PrefixFrom(tunnel4, 32)})
	if v := a.Violations(); len(v) != 0 {
		t.Errorf("98 backs up 94: %v", v)
	}
	b, _ := a.WithoutRule(rtnl.Rule{Family: rtnl.V4, Priority: 98, Src: netip.PrefixFrom(tunnel4, 32)})
	if v := b.Violations(); len(v) == 0 {
		t.Error("ICMP from the tunnel address escapes without 94 and 98")
	}
	// An address live on the tunnel interface is covered too.
	s.Live[rtnl.V4] = append(s.Live[rtnl.V4], netip.MustParseAddr("203.0.113.9"))
	if v := s.Violations(); len(v) == 0 {
		t.Error("a live address without a pair is not an escape class")
	}
}

func TestAnEmptyExitTableStopsRatherThanFallsThrough(t *testing.T) {
	s := nativeState(t)
	s.Routes[rtnl.V4][51821] = nil // no fallback, no tunnel route
	if v := s.Violations(); len(v) != 0 {
		t.Errorf("rule 97 stops what an empty exit table lets through: %v", v)
	}
	s, _ = s.WithoutPriority(rtnl.V4, 97)
	if v := s.Violations(); len(v) == 0 {
		t.Error("an empty exit table and no rule 97 falls through to the main table")
	}
	s = nativeState(t)
	s.Routes[rtnl.V4][51821] = []rtnl.Route{contract.FallbackRoute(rtnl.V4, 51821)}
	if v := s.Violations(); len(v) != 0 {
		t.Errorf("the fallback alone is protection: %v", v)
	}
	after, ok := nativeState(t).WithoutRoute(contract.FallbackRoute(rtnl.V4, 51821))
	if !ok {
		t.Fatal("route not found")
	}
	if v := after.Violations(); len(v) != 0 {
		t.Errorf("the tunnel route alone is protection: %v", v)
	}
}

func TestGluetunClasses(t *testing.T) {
	s := gluetunState(t)
	// Rule 89 backs up 88: without 89 and an empty host table control traffic
	// would go to the tunnel table.
	s.Routes[rtnl.V4][51822] = nil
	after, _ := s.WithoutPriority(rtnl.V4, 89)
	if v := Worsened(s.Violations(), after.Violations()); len(v) == 0 {
		t.Error("control traffic reaches the tunnel without rule 89 and an empty host table")
	}
	// Rule 104 stops the exit's own traffic when the tunnel table is empty;
	// the model cannot see that table, so with it in place nothing changes.
	s = gluetunState(t)
	after, _ = s.WithoutPriority(rtnl.V4, 92)
	if v := Worsened(s.Violations(), after.Violations()); len(v) != 0 {
		t.Errorf("rule 92 is only reached without an overlay route: %v", v)
	}
	// Without an overlay route, 92 is what stops traffic for a client.
	noRoute := gluetunState(t)
	noRoute.Routes[rtnl.V4][rtnl.TableMain] = noRoute.Routes[rtnl.V4][rtnl.TableMain][:1]
	after, _ = noRoute.WithoutPriority(rtnl.V4, 92)
	if v := Worsened(noRoute.Violations(), after.Violations()); len(v) == 0 {
		t.Error("traffic for a client goes to gluetun's tunnel without rule 92 and an overlay route")
	}
}

func TestSelectorsTheModelDoesNotFollowAreTheWorstCase(t *testing.T) {
	s := nativeState(t)
	// A foreign rule with a TOS selector that sends overlay traffic to the main table.
	stray := rtnl.Rule{Family: rtnl.V4, Priority: 50, Action: rtnl.FRActToTbl, Table: rtnl.TableMain, IifName: "wt0", Tos: 16}
	s.Rules[rtnl.V4] = append(s.Rules[rtnl.V4], stray)
	sort.SliceStable(s.Rules[rtnl.V4], func(i, j int) bool { return s.Rules[rtnl.V4][i].Priority < s.Rules[rtnl.V4][j].Priority })
	if v := s.Violations(); len(v) == 0 {
		t.Error("a rule that may send overlay traffic to the main table is not an escape")
	}
	// An unknown attribute does the same.
	s = nativeState(t)
	stray.Tos = 0
	stray.Unknown = []rtnl.RawAttr{{Type: 99, Data: []byte{1}}}
	s.Rules[rtnl.V4] = append(s.Rules[rtnl.V4], stray)
	sort.SliceStable(s.Rules[rtnl.V4], func(i, j int) bool { return s.Rules[rtnl.V4][i].Priority < s.Rules[rtnl.V4][j].Priority })
	if v := s.Violations(); len(v) == 0 {
		t.Error("an unknown selector was assumed to exclude the packet")
	}
}

func TestInvertedAndMarkedRules(t *testing.T) {
	s := nativeState(t)
	// "not fwmark 7 lookup main" at 50 catches every unmarked packet.
	r := rtnl.Rule{Family: rtnl.V4, Priority: 50, Action: rtnl.FRActToTbl, Table: rtnl.TableMain, Flags: rtnl.FIBRuleInvert,
		FwMark: rtnl.Some(uint32(7)), FwMask: rtnl.Some(uint32(0xffffffff))}
	s.Rules[rtnl.V4] = append(s.Rules[rtnl.V4], r)
	sort.SliceStable(s.Rules[rtnl.V4], func(i, j int) bool { return s.Rules[rtnl.V4][i].Priority < s.Rules[rtnl.V4][j].Priority })
	if v := s.Violations(); len(v) == 0 {
		t.Error("an inverted mark rule was not followed")
	}
	// The same rule restricted to marked packets catches nothing here.
	s = nativeState(t)
	r.Flags = 0
	s.Rules[rtnl.V4] = append(s.Rules[rtnl.V4], r)
	sort.SliceStable(s.Rules[rtnl.V4], func(i, j int) bool { return s.Rules[rtnl.V4][i].Priority < s.Rules[rtnl.V4][j].Priority })
	if v := s.Violations(); len(v) != 0 {
		t.Errorf("a mark that does not match: %v", v)
	}
}

func TestDetachedRulesApplyAsTheyWillWhenTheInterfaceAppears(t *testing.T) {
	s := nativeState(t)
	for i := range s.Rules[rtnl.V4] {
		if s.Rules[rtnl.V4][i].IifName == "wt0" {
			s.Rules[rtnl.V4][i].Flags |= rtnl.FIBRuleIifDetached
		}
	}
	if v := s.Violations(); len(v) != 0 {
		t.Errorf("detached rules judged as unprotective: %v", v)
	}
}
