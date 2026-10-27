package contract

// The behavior of rule_actions (routing/contract-rules), exercised through
// the scenarios tools/check-routing.sh and tools/test_host_and_routing.py
// drive: single deletions, insertions, wrong actions, extra selectors,
// duplicates, the applier-owned pair, the held kill switch.

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/irashack/molebridge/internal/rtnl"
)

func kinds(actions []Action) []string {
	var out []string
	for _, a := range actions {
		out = append(out, a.Kind.String()+" "+itoa(a.Priority))
	}
	return out
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func expectActions(t *testing.T, name string, got []Action, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(kinds(got), want) && !(len(got) == 0 && len(want) == 0) {
		t.Errorf("%s:\n got  %q\n want %q", name, kinds(got), want)
	}
}

func glSpecWithAddresses() Spec {
	spec := glSpec()
	spec.ReturnPath = map[rtnl.Family][]netip.Addr{
		rtnl.V4: {netip.MustParseAddr(tunnel4)}, rtnl.V6: {netip.MustParseAddr(tunnel6)}}
	return spec
}

func TestExactRulesNeedNothing(t *testing.T) {
	for _, f := range families {
		expectActions(t, "native "+f.String(), Diff(nativeSpec(), f, nativeRules(f), DiffOptions{}))
		expectActions(t, "gluetun "+f.String(), Diff(glSpecWithAddresses(), f, glRules(f), DiffOptions{}))
	}
}

// Spec.Rules agrees with the hand-written rule sets, rule for rule.
func TestSpecRulesAgreeWithTheFixtures(t *testing.T) {
	check := func(name string, got, all []rtnl.Rule, owned func(uint32) bool) {
		var want []rtnl.Rule
		for _, r := range all {
			if owned(r.Priority) {
				want = append(want, r)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("%s: %d rules, want %d", name, len(got), len(want))
		}
		for i := range got {
			if got[i].Priority != want[i].Priority || !reflect.DeepEqual(got[i].Items(), want[i].Items()) {
				t.Errorf("%s priority %d: %q vs %q", name, got[i].Priority, got[i].Items(), want[i].Items())
			}
		}
	}
	for _, f := range families {
		check("native "+f.String(), nativeSpec().Rules(f), nativeRules(f), func(p uint32) bool { return p <= 98 })
		check("gluetun "+f.String(), glSpecWithAddresses().Rules(f), glRules(f), func(p uint32) bool {
			return p <= 97 || p >= 102 && p <= 104
		})
	}
}

func TestSingleDeletionIsAddedBack(t *testing.T) {
	for _, f := range families {
		for _, p := range []uint32{1, 90, 94, 95, 96, 97, 98} {
			got := Diff(nativeSpec(), f, without(nativeRules(f), p), DiffOptions{})
			expectActions(t, f.String()+" without "+itoa(p), got, "add "+itoa(p))
			if got[0].Rule.Priority != p || got[0].Rule.Family != f {
				t.Errorf("%+v", got[0])
			}
		}
	}
}

func TestMissingRulesGoInTerminalFirst(t *testing.T) {
	got := Diff(nativeSpec(), rtnl.V4, nil, DiffOptions{})
	// 97 and 98 before everything; rule 1 before the rest of the guards.
	expectActions(t, "native, nothing present", got, "add 97", "add 98", "add 1", "add 90", "add 94", "add 95", "add 96")
	got = Diff(glSpec(), rtnl.V4, nil, DiffOptions{})
	expectActions(t, "gluetun, nothing present", got, "add 97", "add 89", "add 92", "add 102", "add 103", "add 104", "add 1", "add 88", "add 90", "add 91", "add 95", "add 96")
	got = Diff(glSpec(), rtnl.V4, nil, DiffOptions{HoldKillSwitch: true})
	for _, a := range got {
		if a.Priority == 104 {
			t.Error("the kill switch was added while held")
		}
	}
}

func TestGluetunReturnPathComesFromTheObservedAddress(t *testing.T) {
	spec := glSpec()
	spec.ReturnPath = map[rtnl.Family][]netip.Addr{rtnl.V4: {netip.MustParseAddr(tunnel4)}}
	expectActions(t, "no 94 present", Diff(spec, rtnl.V4, without(glRules(rtnl.V4), 94), DiffOptions{}), "add 94")
	expectActions(t, "94 present", Diff(spec, rtnl.V4, glRules(rtnl.V4), DiffOptions{}))
	// Without an address in the family, a rule 94 is not expected.
	expectActions(t, "94 without an address", Diff(glSpec(), rtnl.V4, glRules(rtnl.V4), DiffOptions{}), "del 94")
}

func TestInsertedRulesAreRemoved(t *testing.T) {
	// check-routing.sh: lookup main at 50 and the kernel's lookup local at 0.
	for _, f := range families {
		rules := append([]rtnl.Rule{rule(f, 0, table(rtnl.TableLocal))}, nativeRules(f)...)
		rules = append(rules, rule(f, 50, table(rtnl.TableMain)))
		got := Diff(nativeSpec(), f, rules, DiffOptions{})
		expectActions(t, f.String(), got, "del 0", "del 50")
	}
}

func TestRulesOutsideTheRangeAreLeftAlone(t *testing.T) {
	native := append(nativeRules(rtnl.V4), rule(4, 99, table(1)), rule(4, 110, not(), mark(0x1bd00), table(7120)), rule(4, 32766, table(rtnl.TableMain)))
	expectActions(t, "native", Diff(nativeSpec(), rtnl.V4, native, DiffOptions{}))
	// gluetun's own 98-101 and NetBird's 105 and 110 are not Molebridge's.
	gl := append(glRules(rtnl.V4), rule(4, 99, table(1)), rule(4, 100, table(2)))
	spec := glSpec()
	spec.ReturnPath = map[rtnl.Family][]netip.Addr{rtnl.V4: {netip.MustParseAddr(tunnel4)}}
	expectActions(t, "gluetun", Diff(spec, rtnl.V4, gl, DiffOptions{}))
	// 98 is Molebridge's natively but gluetun's own with gluetun.
	native98 := append(without(nativeRules(rtnl.V4), 98), rule(4, 98, to("198.51.100.0/28"), table(rtnl.TableMain)))
	expectActions(t, "98 natively", Diff(nativeSpec(), rtnl.V4, native98, DiffOptions{}), "add 98", "del 98")
	// 102-104 are Molebridge's with gluetun and nobody's natively.
	expectActions(t, "104 natively", Diff(nativeSpec(), rtnl.V4, append(nativeRules(rtnl.V4), rule(4, 104, unreachable())), DiffOptions{}))
}

func TestWrongActionIsReplacedBehindTheRightOne(t *testing.T) {
	rules := nativeRules(rtnl.V4)
	at(t, rules, 97).Action = rtnl.FRActProhibit
	got := Diff(nativeSpec(), rtnl.V4, rules, DiffOptions{})
	// The expected rule goes in before the wrong one comes out.
	expectActions(t, "prohibit instead of unreachable", got, "add 97", "del 97")
	if got[1].Rule.Action != rtnl.FRActProhibit {
		t.Errorf("the rule to delete should be the wrong one: %+v", got[1].Rule)
	}
}

func TestExtraSelectorRuleIsDeletedAndTheExactOneKept(t *testing.T) {
	rules := append(nativeRules(rtnl.V4), rule(4, 95, iif("wt0"), mark(5), table(51821)))
	got := Diff(nativeSpec(), rtnl.V4, rules, DiffOptions{})
	expectActions(t, "fwmark added to a copy of 95", got, "del 95")
	// The same selectors but narrower than expected: a subset, rebuilt.
	wide := append(without(nativeRules(rtnl.V4), 95), rule(4, 95, table(51821)))
	got = Diff(nativeSpec(), rtnl.V4, wide, DiffOptions{})
	expectActions(t, "95 without its iif", got, "add 95", "sub 95")
}

func TestDuplicateRuleIsRebuilt(t *testing.T) {
	rules := append(nativeRules(rtnl.V4), rule(4, 96, oif("mullvad"), table(51821)))
	expectActions(t, "second rule 96", Diff(nativeSpec(), rtnl.V4, rules, DiffOptions{}), "sub 96")
	// Three at once: one rebuild.
	rules = append(rules, rule(4, 96, oif("mullvad"), table(51821)))
	expectActions(t, "third rule 96", Diff(nativeSpec(), rtnl.V4, rules, DiffOptions{}), "sub 96")
}

func TestInversionFlagMakesADifferentRule(t *testing.T) {
	for name, shown := range map[string]rtnl.Rule{
		"not inverted":    rule(4, 1, iif("wt0"), table(rtnl.TableLocal)),
		"other interface": rule(4, 1, not(), iif("wt1"), table(rtnl.TableLocal)),
		"extra fwmark":    rule(4, 1, not(), iif("wt0"), mark(1), table(rtnl.TableLocal)),
		"kernel rule 0":   rule(4, 0, table(rtnl.TableLocal)),
	} {
		rules := append([]rtnl.Rule{shown}, without(nativeRules(4), 1)...)
		got := Diff(nativeSpec(), rtnl.V4, rules, DiffOptions{})
		if len(got) < 2 || got[0].Kind != Add || got[0].Priority != 1 {
			t.Errorf("%s: rule 1 must be added first, got %q", name, kinds(got))
		}
	}
	// The exact rule, detached as before NetBird creates the interface, is
	// left alone (test_routing_rerun_keeps_the_local_delivery_rule).
	rules := nativeRules(rtnl.V4)
	at(t, rules, 1).Flags |= rtnl.FIBRuleIifDetached
	at(t, rules, 95).Flags |= rtnl.FIBRuleIifDetached
	expectActions(t, "detached", Diff(nativeSpec(), rtnl.V4, rules, DiffOptions{}))
}

func TestForeignAttributesNeverMatch(t *testing.T) {
	rules := nativeRules(rtnl.V4)
	at(t, rules, 97).Unknown = []rtnl.RawAttr{{Type: 20, Data: []byte{1, 0, 0, 0, 2, 0, 0, 0}}}
	expectActions(t, "uid range on 97", Diff(nativeSpec(), rtnl.V4, rules, DiffOptions{}), "add 97", "del 97")
	rules = nativeRules(rtnl.V4)
	at(t, rules, 96).Tos = 8
	expectActions(t, "tos on 96", Diff(nativeSpec(), rtnl.V4, rules, DiffOptions{}), "add 96", "del 96")
	rules = nativeRules(rtnl.V4)
	at(t, rules, 90).Flags |= 0x100
	expectActions(t, "unknown flag on 90", Diff(nativeSpec(), rtnl.V4, rules, DiffOptions{}), "add 90", "del 90")
	// Protocol (who installed the rule) is not a selector.
	rules = nativeRules(rtnl.V4)
	at(t, rules, 97).Protocol = rtnl.Some(uint8(3))
	expectActions(t, "installed by boot", Diff(nativeSpec(), rtnl.V4, rules, DiffOptions{}))
}

func TestLeftReturnPathIsNotCompared(t *testing.T) {
	// An addressless config (PIA): 94 and 98 belong to the transaction that
	// sets the address, and are not compared at all.
	spec := Spec{Config: nativeConfig(), LeaveReturnPath: map[rtnl.Family]bool{rtnl.V4: true, rtnl.V6: true}}
	bare := without(nativeRules(rtnl.V4), 94, 98)
	expectActions(t, "neither present", Diff(spec, rtnl.V4, bare, DiffOptions{}))
	for round := 0; round < 3; round++ {
		withPair := append(bare, rule(4, 94, from("203.0.113.5/32"), proto(1), table(51821)), rule(4, 98, from("203.0.113.5/32"), proto(1), unreachable()),
			rule(4, 94, from("203.0.113.6/32"), proto(1), table(51821)))
		expectActions(t, "pairs of any address", Diff(spec, rtnl.V4, withPair, DiffOptions{}))
	}
	// Anything else there is still a stray: only the return-path shape is
	// left to the transaction.
	pair := []rtnl.Rule{rule(4, 94, from("203.0.113.5/32"), proto(1), table(51821)), rule(4, 98, from("203.0.113.5/32"), proto(1), unreachable())}
	for name, c := range map[string]struct {
		stray rtnl.Rule
		want  string
	}{
		"lookup main at 94":       {rule(4, 94, table(rtnl.TableMain)), "del 94"},
		"unreachable at 98":       {rule(4, 98, unreachable()), "del 98"},
		"94 into another table":   {rule(4, 94, from("203.0.113.5/32"), proto(1), table(rtnl.TableMain)), "del 94"},
		"98 with an iif":          {rule(4, 98, iif("wt0"), from("203.0.113.5/32"), proto(1), unreachable()), "del 98"},
		"94 for a whole prefix":   {rule(4, 94, from("203.0.113.0/24"), proto(1), table(51821)), "del 94"},
		"94 without its protocol": {rule(4, 94, from("203.0.113.5/32"), table(51821)), "sub 94"},
	} {
		rules := append(append(append([]rtnl.Rule{}, bare...), pair...), c.stray)
		expectActions(t, name, Diff(spec, rtnl.V4, rules, DiffOptions{}), c.want)
	}
	if left := LeftReturnPath(spec, rtnl.V4, append(append(append([]rtnl.Rule{}, bare...), pair...), pair[0])); len(left[94]) != 1 || len(left[98]) != 1 {
		t.Errorf("left: %v", left)
	}
}

// A protective copy of rule 102 left at gluetun's 101 (a rebuild that did not
// complete) is removed; gluetun's own rule 101 is not Molebridge's.
func TestALeftoverCopyBelowTheOwnedRangeIsRemoved(t *testing.T) {
	spec := glSpecWithAddresses()
	own101 := rule(4, 101, not(), mark(0xca6c), table(51820))
	rules := append(glRules(rtnl.V4), own101)
	expectActions(t, "gluetun's 101", Diff(spec, rtnl.V4, rules, DiffOptions{}))
	cp := spec.RulesAt(rtnl.V4, PrioGluetunMark)[0]
	cp.Priority = 101
	expectActions(t, "a copy of 102 at 101", Diff(spec, rtnl.V4, append(rules, cp), DiffOptions{}), "del 101")
	// Natively 101 is nobody's, and 102 nothing of Molebridge's.
	expectActions(t, "natively", Diff(nativeSpec(), rtnl.V4, append(nativeRules(rtnl.V4), cp), DiffOptions{}))
}

func TestTwoReturnPathPairsDuringAnAddressChange(t *testing.T) {
	spec := nativeSpec()
	spec.ReturnPath = map[rtnl.Family][]netip.Addr{rtnl.V4: {netip.MustParseAddr("203.0.113.5"), netip.MustParseAddr("203.0.113.6")}}
	bare := without(nativeRules(rtnl.V4), 94, 98)
	pair := func(a string) []rtnl.Rule {
		return []rtnl.Rule{rule(4, 94, from(a+"/32"), proto(1), table(51821)), rule(4, 98, from(a+"/32"), proto(1), unreachable())}
	}
	full := append(append(append([]rtnl.Rule{}, bare...), pair("203.0.113.5")...), pair("203.0.113.6")...)
	expectActions(t, "both pairs present", Diff(spec, rtnl.V4, full, DiffOptions{}))
	// The new pair not yet installed: its rules are added, the old pair kept.
	only := append(append([]rtnl.Rule{}, bare...), pair("203.0.113.5")...)
	expectActions(t, "new pair missing", Diff(spec, rtnl.V4, only, DiffOptions{}), "add 98", "add 94")
	// A pair for an address no longer expected is removed.
	spec.ReturnPath = map[rtnl.Family][]netip.Addr{rtnl.V4: {netip.MustParseAddr("203.0.113.6")}}
	expectActions(t, "old pair stale", Diff(spec, rtnl.V4, full, DiffOptions{}), "del 94", "del 98")
}

func TestTemporaryGuardIsExpectedOnlyWhenHeld(t *testing.T) {
	guard := rule(4, 80, iif("wt0"), unreachable())
	rules := append(nativeRules(rtnl.V4), guard)
	expectActions(t, "guard unexpected", Diff(nativeSpec(), rtnl.V4, rules, DiffOptions{}), "del 80")
	spec := nativeSpec()
	spec.TempGuard = map[rtnl.Family]bool{rtnl.V4: true}
	expectActions(t, "guard expected", Diff(spec, rtnl.V4, rules, DiffOptions{}))
	expectActions(t, "guard expected, absent", Diff(spec, rtnl.V4, nativeRules(rtnl.V4), DiffOptions{}), "add 80")
}

func TestTouchesGuards(t *testing.T) {
	cases := map[string]bool{"add 1": false, "add 98": false, "del 0": false, "add 90": true, "sub 95": true, "del 97": true, "add 80": false}
	for in, want := range cases {
		var a Action
		var p uint32
		for i := 0; i < len(in); i++ {
			if in[i] >= '0' && in[i] <= '9' {
				p = p*10 + uint32(in[i]-'0')
			}
		}
		a.Priority = p
		if got := TouchesGuards([]Action{a}); got != want {
			t.Errorf("%s: %v", in, got)
		}
	}
	if !reflect.DeepEqual(Priorities([]Action{{Priority: 95}, {Priority: 90}, {Priority: 95}}), []uint32{90, 95}) {
		t.Error("Priorities")
	}
}
