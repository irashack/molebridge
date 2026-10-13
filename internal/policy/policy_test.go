package policy

import (
	"math/rand"
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

const (
	exitIdx    = 3
	overlayIdx = 4
	hostIdx    = 2
)

func cfg(t *testing.T, env map[string]string) contract.Config {
	t.Helper()
	c, err := contract.ConfigFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

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

func zero(f rtnl.Family) netip.Prefix {
	if f == rtnl.V6 {
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
}

func sortRules(s *State, f rtnl.Family) {
	sort.SliceStable(s.Rules[f], func(i, j int) bool { return s.Rules[f][i].Priority < s.Rules[f][j].Priority })
}

func nativeEnv() map[string]string {
	return map[string]string{"OVERLAY_CIDR": "192.0.2.0/24", "OVERLAY6_CIDR": "2001:db8:1::/64", "OVERLAY_IF": "wt0", "EXIT_IF": "mullvad", "EXIT_TABLE": "51821"}
}

func gluetunEnv() map[string]string {
	return map[string]string{"TUNNEL_BACKEND": "gluetun", "OVERLAY_CIDR": "192.0.2.0/24", "OVERLAY6_CIDR": "2001:db8:1::/64",
		"OVERLAY_IF": "wt0", "EXIT_IF": "wg0", "EXIT_TABLE": "51821", "HOST_IF": "eth0", "HOST_TABLE": "51822", "CONTROL_MARK": "0x1bd00"}
}

func nativeState(t *testing.T) State {
	spec := contract.Spec{Config: cfg(t, nativeEnv()), ReturnPath: map[rtnl.Family][]netip.Addr{rtnl.V4: {tunnel4}, rtnl.V6: {tunnel6}}}
	return healthy(spec)
}

func gluetunState(t *testing.T) State {
	spec := contract.Spec{Config: cfg(t, gluetunEnv()), ReturnPath: map[rtnl.Family][]netip.Addr{rtnl.V4: {tunnel4}, rtnl.V6: {tunnel6}}}
	s := healthy(spec)
	for _, f := range families {
		// gluetun's own rules and NetBird's, and the tables the guard reads.
		s.Rules[f] = append(s.Rules[f],
			rtnl.Rule{Family: f, Priority: 98, Action: rtnl.FRActToTbl, Table: rtnl.TableMain, Dst: map[rtnl.Family]netip.Prefix{rtnl.V4: netip.MustParsePrefix("198.51.100.0/28"), rtnl.V6: netip.MustParsePrefix("2001:db8:2::/64")}[f]},
			rtnl.Rule{Family: f, Priority: 100, Action: rtnl.FRActToTbl, Table: 200, Src: map[rtnl.Family]netip.Prefix{rtnl.V4: netip.MustParsePrefix("198.51.100.1/32"), rtnl.V6: netip.MustParsePrefix("2001:db8:2::1/128")}[f]},
			rtnl.Rule{Family: f, Priority: 101, Action: rtnl.FRActToTbl, Table: 51820, Flags: rtnl.FIBRuleInvert, FwMark: rtnl.Some(uint32(51820)), FwMask: rtnl.Some(uint32(0xffffffff))},
			rtnl.Rule{Family: f, Priority: 105, Action: rtnl.FRActToTbl, Table: rtnl.TableMain, SuppressPrefixLen: rtnl.Some(uint32(0))},
			rtnl.Rule{Family: f, Priority: 110, Action: rtnl.FRActToTbl, Table: 7120, Flags: rtnl.FIBRuleInvert, FwMark: rtnl.Some(uint32(0x1bd00)), FwMask: rtnl.Some(uint32(0xffffffff))})
		sortRules(&s, f)
		host := rtnl.Route{Family: f, Dst: zero(f), Table: 51822, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(hostIdx))}
		lan := rtnl.Route{Family: f, Dst: map[rtnl.Family]netip.Prefix{rtnl.V4: netip.MustParsePrefix("198.51.100.0/28"), rtnl.V6: netip.MustParsePrefix("2001:db8:2::/64")}[f],
			Table: 51822, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(hostIdx))}
		s.Routes[f][51822] = []rtnl.Route{host, lan}
		main := host
		main.Table = rtnl.TableMain
		ov := rtnl.Route{Family: f, Dst: spec.Config.OverlayFor(f), Table: rtnl.TableMain, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(overlayIdx))}
		lanMain := lan
		lanMain.Table = rtnl.TableMain
		s.Routes[f][rtnl.TableMain] = []rtnl.Route{main, ov, lanMain}
	}
	return s
}

// healthy: the contract installed, the tunnel up, the kernel's rule 0 gone.
func healthy(spec contract.Spec) State {
	s := State{Spec: spec, Rules: map[rtnl.Family][]rtnl.Rule{}, Routes: map[rtnl.Family]map[uint32][]rtnl.Route{},
		Known: map[uint32]bool{}, Live: map[rtnl.Family][]netip.Addr{rtnl.V4: {tunnel4}, rtnl.V6: {tunnel6}},
		Locals: map[rtnl.Family][]netip.Addr{
			rtnl.V4: {tunnel4, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")},
			rtnl.V6: {tunnel6, netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:2::1")}},
		ExitIdx: exitIdx, HostIdx: hostIdx, OverlayIdx: overlayIdx}
	for _, tb := range spec.Interest().Tables {
		s.Known[tb] = true
	}
	for _, f := range families {
		rules := append(kernelRules(f), spec.Rules(f)...)
		s.Rules[f] = rules
		sortRules(&s, f)
		s.Routes[f] = map[uint32][]rtnl.Route{}
		for tb := range s.Known {
			s.Routes[f][tb] = nil
		}
		tun := contract.TunnelRoute(f, spec.Config.Table, exitIdx)
		s.Routes[f][spec.Config.Table] = []rtnl.Route{contract.FallbackRoute(f, spec.Config.Table), tun}
	}
	return s
}

func (s State) set(f rtnl.Family, edit func(rules []rtnl.Rule) []rtnl.Rule) State {
	out := s.clone()
	out.Rules[f] = edit(out.Rules[f])
	sortRules(&out, f)
	return out
}

func (s State) without(f rtnl.Family, priority uint32) State {
	out, _ := s.WithoutPriority(f, priority)
	return out
}

func TestAHealthyContractHasNoEscape(t *testing.T) {
	for name, s := range map[string]State{"native": nativeState(t), "gluetun": gluetunState(t)} {
		if v := s.Violations(); len(v) != 0 {
			t.Errorf("%s: %v", name, v)
		}
		pts := allPoints(s)
		if len(pts) < 100 {
			t.Errorf("%s: only %d points", name, len(pts))
		}
		t.Logf("%s: %d points", name, len(pts))
	}
}

func TestDeletingWhatNothingBacksUpIsAnEscape(t *testing.T) {
	s := nativeState(t)
	// 95 alone: 97 still stops overlay traffic.
	a := s.without(rtnl.V4, 95)
	if v := Worsens(s, a); len(v) != 0 {
		t.Errorf("rule 95 is backed up by 97: %v", v)
	}
	// Both: overlay traffic reaches a table that is not read.
	b := a.without(rtnl.V4, 97)
	if v := Worsens(a, b); len(v) == 0 {
		t.Error("overlay traffic escapes without 95 and 97")
	}
	// 94 and 98 back each other up for ICMP from the tunnel address.
	c := s.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule { return filter(r, func(x rtnl.Rule) bool { return x.Priority != 94 }) })
	if v := Worsens(s, c); len(v) != 0 {
		t.Errorf("98 backs up 94: %v", v)
	}
	d := c.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule { return filter(r, func(x rtnl.Rule) bool { return x.Priority != 98 }) })
	if v := Worsens(c, d); len(v) == 0 {
		t.Error("ICMP from the tunnel address escapes without 94 and 98")
	}
}

func filter(r []rtnl.Rule, keep func(rtnl.Rule) bool) []rtnl.Rule {
	var out []rtnl.Rule
	for _, x := range r {
		if keep(x) {
			out = append(out, x)
		}
	}
	return out
}

func TestTheKernelsRuleZeroAndRuleOne(t *testing.T) {
	s := nativeState(t)
	withZero := s.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule {
		return append(r, rtnl.Rule{Family: rtnl.V4, Priority: 0, Action: rtnl.FRActToTbl, Table: rtnl.TableLocal})
	})
	if v := withZero.Violations(); len(v) == 0 {
		t.Error("overlay traffic for the exit's own address is not delivered locally with the kernel's rule 0")
	}
	gone := withZero.without(rtnl.V4, 0)
	if v := Worsens(withZero, gone); len(v) != 0 || len(gone.Violations()) != 0 {
		t.Errorf("removing rule 0: %v", gone.Violations())
	}
}

// The reviewer's counterexamples of round 6.

// 1. An explicit zero fwmark in a delete is a wildcard: the request that names
// the unmarked rule removes the marked protection in front of it.
func TestAZeroMarkDeleteTakesTheMarkedRuleInFrontOfIt(t *testing.T) {
	s := gluetunState(t)
	marked := rtnl.Rule{Family: rtnl.V4, Priority: 95, Action: rtnl.FRActToTbl, Table: 51821, IifName: "wt0", FwMark: rtnl.Some(uint32(contract.GluetunMark)), FwMask: rtnl.Some(uint32(0xffffffff))}
	zeroMark := rtnl.Rule{Family: rtnl.V4, Priority: 95, Action: rtnl.FRActToTbl, Table: 51821, IifName: "wt0", FwMark: rtnl.Some(uint32(0)), FwMask: rtnl.Some(uint32(0xffffffff))}
	// Everything else is routed by a rule that excludes that one mark on the
	// overlay ("not (iif wt0 and fwmark 51820)"), so the marked rule is that
	// mark's only protection.
	others := rtnl.Rule{Family: rtnl.V4, Priority: 96, Action: rtnl.FRActToTbl, Table: 51821, IifName: "wt0", Flags: rtnl.FIBRuleInvert,
		FwMark: rtnl.Some(uint32(contract.GluetunMark)), FwMask: rtnl.Some(uint32(0xffffffff))}
	s = s.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule {
		r = filter(r, func(x rtnl.Rule) bool { return x.Priority != 95 && x.Priority != 97 })
		return append(r, marked, zeroMark, others)
	})
	if v := s.Violations(); len(v) != 0 {
		t.Fatalf("the starting point escapes: %v", v)
	}
	after, ok := s.WithoutRule(zeroMark)
	if !ok {
		t.Fatal("nothing deleted")
	}
	if v := Worsens(s, after); len(v) == 0 {
		t.Error("deleting the zero-mark rule removed the marked rule, and that was approved")
	}
	// And the rule that was removed is the marked one.
	for _, r := range after.Rules[rtnl.V4] {
		if r.Priority == 95 && r.FwMark.V == contract.GluetunMark {
			t.Error("the marked rule is still there")
		}
	}
}

// 2. Classes, not samples: a remaining rule that protects ICMP only to one
// address does not make deleting the general barrier safe; and forwarding in
// both families is a class whatever overlay prefixes are configured.
func TestAClassIsEveryPacketItsSelectorsDefine(t *testing.T) {
	s := nativeState(t)
	// 94 is gone and 98 is the barrier; a narrow rule protects ICMP to 8.8.8.8.
	narrow := rtnl.Rule{Family: rtnl.V4, Priority: 96, Action: rtnl.FRActUnreachable, IPProto: rtnl.Some(uint8(1)), Dst: netip.MustParsePrefix("8.8.8.8/32")}
	a := s.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule {
		return append(filter(r, func(x rtnl.Rule) bool { return x.Priority != 94 }), narrow)
	})
	b := a.without(rtnl.V4, 98)
	v := Worsens(a, b)
	if len(v) == 0 {
		t.Fatal("ICMP to another address than 8.8.8.8 escapes once the general barrier is gone")
	}
	t.Log(v[0])

	// No overlay prefixes at all: the overlay interface still carries both families.
	env := nativeEnv()
	delete(env, "OVERLAY6_CIDR")
	spec := contract.Spec{Config: cfg(t, env), ReturnPath: map[rtnl.Family][]netip.Addr{rtnl.V4: {tunnel4}, rtnl.V6: {tunnel6}}}
	n := healthy(spec)
	if v := n.Violations(); len(v) != 0 {
		t.Fatalf("%v", v)
	}
	// Without 95 and 97 in IPv6 forwarded packets escape.
	broken := n.without(rtnl.V6, 95)
	broken = broken.without(rtnl.V6, 97)
	if v := Worsens(n, broken); len(v) == 0 {
		t.Error("forwarded IPv6 is not a class when OVERLAY6_CIDR is unset")
	}
}

// 3. Route lookups: a TOS route does not answer an ordinary packet, so with
// only a TOS fallback rule 94 is not a barrier.
func TestAConditionalRouteIsNotAnAnswerForEveryPacket(t *testing.T) {
	s := nativeState(t)
	tos := contract.FallbackRoute(rtnl.V4, 51821)
	tos.Tos = 16
	s.Routes[rtnl.V4][51821] = []rtnl.Route{tos}
	// Rule 98 keeps ICMP from the tunnel address stopped; without 98 rule 94
	// finds no route for ordinary packets and the lookup falls through.
	b := s.without(rtnl.V4, 98)
	if v := Worsens(s, b); len(v) == 0 {
		t.Error("rule 94 was taken for a barrier although only a TOS route is in its table")
	}
}

// 4. A route out of another device is no protection, whatever table it is in.
func TestARouteThroughTheHostInterfaceIsNotSafeEgress(t *testing.T) {
	s := nativeState(t)
	s.Routes[rtnl.V4][51821] = []rtnl.Route{contract.FallbackRoute(rtnl.V4, 51821),
		{Family: rtnl.V4, Dst: zero(rtnl.V4), Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(hostIdx)), Gateway: netip.MustParseAddr("198.51.100.2")}}
	if v := s.Violations(); len(v) == 0 {
		t.Error("a default route through eth0 in the exit table is safe egress")
	}
	// An earlier barrier stops ICMP from the tunnel address; 94 would send it
	// into that table, out of eth0. Deleting the barrier first opens it.
	barrier := rtnl.Rule{Family: rtnl.V4, Priority: 50, Action: rtnl.FRActUnreachable, IPProto: rtnl.Some(uint8(1)), Src: netip.PrefixFrom(tunnel4, 32)}
	with := s.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule { return append(r, barrier) })
	with = with.without(rtnl.V4, 95).without(rtnl.V4, 90) // only ICMP matters here
	gone, _ := with.WithoutRule(barrier)
	if v := Worsens(with, gone); len(v) == 0 {
		t.Error("the barrier was deleted although the table it falls to sends ICMP out of eth0")
	}
}

// 5. A conditional goto: both the jump and the fall-through are followed.
func TestAConditionalGotoIsFollowedBothWays(t *testing.T) {
	s := nativeState(t)
	jump := rtnl.Rule{Family: rtnl.V4, Priority: 40, Action: rtnl.FRActGoto, Goto: rtnl.Some(uint32(150)), Tos: 16}
	target := rtnl.Rule{Family: rtnl.V4, Priority: 150, Action: rtnl.FRActToTbl, Table: rtnl.TableMain}
	a := s.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule { return append(r, jump, target) })
	// The TOS-qualified goto can bypass everything: it already escapes.
	if v := a.Violations(); len(v) == 0 {
		t.Error("a TOS-qualified goto to the main table is not an escape")
	}
}

// 6. The kernel resolves a goto to the rule at exactly the target priority; with
// that rule gone the goto does nothing.
func TestDeletingAGotoTargetFallsThrough(t *testing.T) {
	s := nativeState(t)
	// 40 goto 60; 50 escapes; 60 rejects. Overlay traffic: the goto jumps over 50.
	rules := []rtnl.Rule{
		{Family: rtnl.V4, Priority: 40, Action: rtnl.FRActGoto, Goto: rtnl.Some(uint32(60)), IifName: "wt0"},
		{Family: rtnl.V4, Priority: 50, Action: rtnl.FRActToTbl, Table: rtnl.TableMain, IifName: "wt0"},
		{Family: rtnl.V4, Priority: 60, Action: rtnl.FRActUnreachable, IifName: "wt0"},
	}
	a := s.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule { return append(r, rules...) })
	if v := a.Violations(); len(v) != 0 {
		t.Fatalf("the goto should skip the escape: %v", v)
	}
	b := a.without(rtnl.V4, 60)
	if v := Worsens(a, b); len(v) == 0 {
		t.Error("deleting the goto's target was approved although the goto then falls through to the escape at 50")
	}
}

func TestSelectorsTheModelDoesNotFollowAreFollowedBothWays(t *testing.T) {
	s := nativeState(t)
	stray := rtnl.Rule{Family: rtnl.V4, Priority: 50, Action: rtnl.FRActToTbl, Table: rtnl.TableMain, IifName: "wt0", Tos: 16}
	a := s.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule { return append(r, stray) })
	if v := a.Violations(); len(v) == 0 {
		t.Error("a rule that may send overlay traffic to the main table is not an escape")
	}
	stray.Tos = 0
	stray.Unknown = []rtnl.RawAttr{{Type: 99, Data: []byte{1}}}
	b := s.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule { return append(r, stray) })
	if v := b.Violations(); len(v) == 0 {
		t.Error("an unknown selector was assumed to exclude the packet")
	}
	stray.Unknown = nil
	stray.L3Mdev = rtnl.Some(uint8(1))
	c := s.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule { return append(r, stray) })
	if v := c.Violations(); len(v) == 0 {
		t.Error("an l3mdev rule was assumed not to apply")
	}
}

func TestInvertedAndMarkedRules(t *testing.T) {
	s := nativeState(t)
	r := rtnl.Rule{Family: rtnl.V4, Priority: 50, Action: rtnl.FRActToTbl, Table: rtnl.TableMain, Flags: rtnl.FIBRuleInvert,
		FwMark: rtnl.Some(uint32(7)), FwMask: rtnl.Some(uint32(0xffffffff))}
	a := s.set(rtnl.V4, func(x []rtnl.Rule) []rtnl.Rule { return append(x, r) })
	if v := a.Violations(); len(v) == 0 {
		t.Error("an inverted mark rule was not followed")
	}
	r.Flags = 0
	b := s.set(rtnl.V4, func(x []rtnl.Rule) []rtnl.Rule { return append(x, r) })
	if v := b.Violations(); len(v) == 0 {
		t.Error("mark 7 traffic reaches the main table")
	} else {
		for _, x := range v {
			if !strings.Contains(x.Packet, "mark 0x7 ") {
				t.Errorf("a mark rule for mark 7 caught other traffic: %v", x)
			}
		}
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

func TestAnEmptyExitTableStopsAndRule97BacksItUp(t *testing.T) {
	s := nativeState(t)
	s.Routes[rtnl.V4][51821] = nil
	if v := s.Violations(); len(v) != 0 {
		t.Errorf("rule 97 stops what an empty exit table lets through: %v", v)
	}
	if v := s.without(rtnl.V4, 97).Violations(); len(v) == 0 {
		t.Error("an empty exit table and no rule 97 falls through")
	}
	// The fallback alone, the tunnel route alone: both are protection.
	for i := 0; i < 2; i++ {
		s := nativeState(t)
		s.Routes[rtnl.V4][51821] = s.Routes[rtnl.V4][51821][i : i+1]
		if v := s.Violations(); len(v) != 0 {
			t.Errorf("route %d alone: %v", i, v)
		}
	}
}

func TestGluetunClasses(t *testing.T) {
	s := gluetunState(t)
	// Rule 89 backs up 88 when the host table is empty.
	s.Routes[rtnl.V4][51822] = nil
	if v := s.Violations(); len(v) != 0 {
		t.Fatalf("%v", v)
	}
	if v := Worsens(s, s.without(rtnl.V4, 89)); len(v) == 0 {
		t.Error("control traffic reaches the tunnel without rule 89 and an empty host table")
	}
	// Without an overlay route, 92 is what stops traffic for a client.
	n := gluetunState(t)
	n.Routes[rtnl.V4][rtnl.TableMain] = filterRoutes(n.Routes[rtnl.V4][rtnl.TableMain], func(r rtnl.Route) bool { return r.Dst.Bits() != 24 || r.Dst.Addr() != netip.MustParseAddr("192.0.2.0") })
	if v := n.Violations(); len(v) != 0 {
		t.Fatalf("%v", v)
	}
	if v := Worsens(n, n.without(rtnl.V4, 92)); len(v) == 0 {
		t.Error("traffic for a client goes to gluetun's tunnel without rule 92 and an overlay route")
	}
	// Rule 104 stops the exit's own traffic when gluetun's table has nothing.
	if v := Worsens(gluetunState(t), gluetunState(t).without(rtnl.V4, 104)); len(v) != 0 {
		t.Logf("without 104: %v", v)
	}
}

func filterRoutes(r []rtnl.Route, keep func(rtnl.Route) bool) []rtnl.Route {
	var out []rtnl.Route
	for _, x := range r {
		if keep(x) {
			out = append(out, x)
		}
	}
	return out
}

func BenchmarkWorsensGluetun(b *testing.B) {
	t := &testing.T{}
	s := gluetunState(t)
	after := s.without(rtnl.V4, 95)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Worsens(s, after)
	}
}

// Round 7: a rule the kernel dumps as "fwmark 0/0xffffffff" carries a mask and
// no mark. It selects only unmarked packets. The reviewer's case: with it as
// rule 95 and 95/97 gone, the rule before it is the protection of every other mark,
// and deleting that rule lets forwarded traffic marked 0xca6c reach main/eth0.
func TestADumpedZeroMarkRuleDoesNotProtectMarkedTraffic(t *testing.T) {
	for name, build := range map[string]func(t *testing.T) State{"native": nativeState, "gluetun": gluetunState} {
		s := build(t)
		zeroMark, err := rtnl.DecodeRule(rtnl.Rule{Family: rtnl.V4, Priority: 95, Action: rtnl.FRActToTbl, Table: 51821, IifName: "wt0",
			FwMask: rtnl.Some(uint32(0xffffffff))}.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		everything := rtnl.Rule{Family: rtnl.V4, Priority: 93, Action: rtnl.FRActToTbl, Table: 51821, IifName: "wt0"}
		s = s.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule {
			r = filter(r, func(x rtnl.Rule) bool { return x.Priority != 95 && x.Priority != 97 })
			return append(r, zeroMark, everything)
		})
		if v := s.Violations(); len(v) != 0 {
			t.Fatalf("%s: the starting point escapes: %v", name, v)
		}
		after, ok := s.WithoutPriority(rtnl.V4, 93)
		if !ok {
			t.Fatal("no rule 93")
		}
		v := Worsens(s, after)
		if len(v) == 0 {
			t.Fatalf("%s: forwarded traffic marked 0xca6c escapes once the rule in front is gone, and the deletion was approved", name)
		}
		found := false
		for _, x := range v {
			if strings.Contains(x.Packet, "mark 0xca6c") {
				found = true
			}
		}
		if name == "gluetun" && !found {
			t.Errorf("the 0xca6c packets were not among the escapes: %v", v)
		}
	}
}

// Round 7: a point that might escape one way must not excuse a deletion that
// makes it escape another. An interrupted repair left the ICMP copy at
// priority 97; the restore of 94 and 98 fails; the exit table has a route out
// of the wrong device; and rule 96's oif keeps the unbound ICMP's outcome
// uncertain (it escapes by the wrong route if a socket is bound to the tunnel
// interface). Clearing priority 97 removes the copy that really stops the
// ICMP of the sockets that are not.
func TestAnUncertainEscapeDoesNotExcuseARealOne(t *testing.T) {
	s := nativeState(t)
	copy97 := rtnl.Rule{Family: rtnl.V4, Priority: 97, Action: rtnl.FRActUnreachable, IPProto: rtnl.Some(uint8(1)), Src: netip.PrefixFrom(tunnel4, 32)}
	guard := rtnl.Rule{Family: rtnl.V4, Priority: 80, Action: rtnl.FRActUnreachable, IifName: "wt0"}
	s = s.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule {
		r = filter(r, func(x rtnl.Rule) bool { return x.Priority != 94 && x.Priority != 98 })
		// The copy is the first rule at 97, where a delete by priority finds it.
		out := []rtnl.Rule{}
		for _, x := range r {
			if x.Priority == 97 {
				out = append(out, copy97)
			}
			out = append(out, x)
		}
		return append(out, guard)
	})
	s.Routes[rtnl.V4][51821] = []rtnl.Route{contract.FallbackRoute(rtnl.V4, 51821),
		{Family: rtnl.V4, Dst: zero(rtnl.V4), Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(hostIdx)), Gateway: netip.MustParseAddr("198.51.100.2")}}
	sortRules(&s, rtnl.V4)
	after, ok := s.WithoutPriority(rtnl.V4, 97)
	if !ok {
		t.Fatal("nothing at 97")
	}
	// The concrete evaluator: an unbound socket's ICMP from the tunnel address.
	q := concrete{packet: packet{f: rtnl.V4, iif: "lo", proto: 1, src: tunnel4, dst: netip.MustParseAddr("8.8.8.8")}}
	rng := rand.New(rand.NewSource(1))
	unbound := coins{1000 + indexOf(s.Rules[rtnl.V4], 96): false, 2000 + indexOf(s.Rules[rtnl.V4], 32766): true} // rule 96's oif does not apply
	cl := s.classifier()(q.packet)
	if o := oracle(s, q, rng, unbound); !cl.allows(o) {
		t.Fatalf("the starting point already lets the unbound ICMP out: %v", o)
	}
	// The main table (not read by the model) answers, as it does on a host.
	afterUnbound := coins{1000 + indexOf(after.Rules[rtnl.V4], 96): false, 2000 + indexOf(after.Rules[rtnl.V4], 32766): true}
	if o := oracle(after, q, rng, afterUnbound); cl.allows(o) {
		t.Fatalf("the concrete evaluator finds nothing wrong after the deletion (%v)", o)
	}
	// The starting point has an escape for the bound socket, which is what hid
	// the real one.
	if v := s.Violations(); len(v) == 0 {
		t.Fatal("the premise: some ICMP can escape by the wrong-device route")
	}
	if v := Worsens(s, after); len(v) == 0 {
		t.Error("the deletion was approved: the point's earlier, uncertain escape excused the real one")
	}
}

func indexOf(rs []rtnl.Rule, priority uint32) int {
	for i, r := range rs {
		if r.Priority == priority {
			return i
		}
	}
	return -1
}
