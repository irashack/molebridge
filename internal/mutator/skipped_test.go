package mutator

// The priorities left to a transaction (rules 94 and 98 of an addressless
// config) and the protective copy a gluetun rebuild puts below the owned
// range: neither is a place a stray can stay.

import (
	"context"
	"net/netip"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

func rulesAt(k *fakeKernel, f rtnl.Family, p uint32) []rtnl.Rule {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []rtnl.Rule
	for _, r := range k.rules[f] {
		if r.Priority == p {
			out = append(out, r)
		}
	}
	return out
}

func hasRule(k *fakeKernel, want rtnl.Rule) bool {
	for _, r := range rulesAt(k, want.Family, want.Priority) {
		if equalStrings(r.Items(), want.Items()) {
			return true
		}
	}
	return false
}

// While rules 94 and 98 are left to PIA's registration, a rule there that is
// not return-path shaped is a stray like any other: removed, and the pass not
// verified until it is. The pair a transaction left, for whatever address,
// stays.
func TestAStrayAtALeftPriorityIsRemoved(t *testing.T) {
	a := netip.MustParseAddr("203.0.113.11")
	pair := contract.Spec{Config: nativeConfig(), ReturnPath: map[rtnl.Family][]netip.Addr{rtnl.V4: {a}}}
	left := append(pair.RulesAt(rtnl.V4, contract.PrioReturnPath), pair.RulesAt(rtnl.V4, contract.PrioBackstop)...)
	for name, stray := range map[string]rtnl.Rule{
		"lookup main at 94":   {Family: rtnl.V4, Priority: 94, Action: rtnl.FRActToTbl, Table: rtnl.TableMain},
		"lookup main at 98":   {Family: rtnl.V4, Priority: 98, Action: rtnl.FRActToTbl, Table: rtnl.TableMain},
		"94 with an iif":      {Family: rtnl.V4, Priority: 94, Action: rtnl.FRActToTbl, Table: 51821, IifName: "wt0", Src: netip.MustParsePrefix("203.0.113.11/32"), IPProto: rtnl.Some(uint8(1))},
		"98 that is a lookup": {Family: rtnl.V4, Priority: 98, Action: rtnl.FRActToTbl, Table: rtnl.TableMain, Src: netip.MustParsePrefix("203.0.113.11/32"), IPProto: rtnl.Some(uint8(1))},
		// A subset of the pair's rule 94: deleting it by its attributes could
		// take the rule that stays, so the priority is rebuilt around it.
		"94 without its protocol": {Family: rtnl.V4, Priority: 94, Action: rtnl.FRActToTbl, Table: 51821, Src: netip.MustParsePrefix("203.0.113.11/32")},
	} {
		t.Run(name, func(t *testing.T) {
			h := newPIAHarness(t, piaScenario{name: name, old: a, leave: true})
			h.k.mu.Lock()
			h.k.rules[rtnl.V4] = append(h.k.rules[rtnl.V4], stray)
			sortRules(h.k.rules[rtnl.V4])
			h.k.mu.Unlock()
			res, err := h.m.ReconcileNow(context.Background(), "a stray at a left priority")
			if err != nil || !res.Verified {
				t.Fatalf("%+v %v", res, err)
			}
			if hasRule(h.k, stray) {
				t.Errorf("the stray stayed: %v", h.k.ruleSummary(rtnl.V4))
			}
			for _, r := range left {
				if !hasRule(h.k, r) {
					t.Errorf("the left rule %s went: %v", r, h.k.ruleSummary(rtnl.V4))
				}
			}
			for _, p := range []uint32{93, 97} {
				if n := len(rulesAt(h.k, rtnl.V4, p)); n > 1 || p == 93 && n > 0 {
					t.Errorf("a copy stayed at %d: %v", p, h.k.ruleSummary(rtnl.V4))
				}
			}
		})
	}
}

// The protective copy of rule 102 lands at gluetun's 101, which Molebridge
// does not own. A rebuild that cannot confirm its result leaves the copy; the
// next pass that reads rule 102 back removes it, and gluetun's own rule 101
// stays.
func TestAGluetunCopyAt101IsRemovedOnceRule102IsBack(t *testing.T) {
	k := gluetunKernel()
	m := start(t, k, glSpec())
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	gl101 := rtnl.Rule{Family: rtnl.V4, Priority: 101, Action: rtnl.FRActToTbl, Table: 51820, Flags: rtnl.FIBRuleInvert,
		FwMark: rtnl.Some(uint32(0xca6c)), FwMask: rtnl.Some(uint32(0xffffffff))}
	want := glSpec().RulesAt(rtnl.V4, contract.PrioGluetunMark)[0]
	k.mu.Lock()
	k.rules[rtnl.V4] = append(k.rules[rtnl.V4], gl101)
	// A subset of rule 102 (no iif), so 102 is rebuilt behind a copy at 101.
	sub := want
	sub.IifName = ""
	k.rules[rtnl.V4] = append(k.rules[rtnl.V4], sub)
	sortRules(k.rules[rtnl.V4])
	// The refill of 102 "succeeds" and installs nothing.
	k.lie = func(op string) bool { return op == "add 2 102" }
	k.mu.Unlock()
	if res, err := m.ReconcileNow(context.Background(), "rebuild 102"); err == nil && res.Verified {
		t.Fatalf("verified with rule 102 missing: %+v", res)
	}
	copyAt101 := want
	copyAt101.Priority = 101
	if !hasRule(k, copyAt101) {
		t.Fatalf("no copy at 101 to test with: %v", k.ruleSummary(rtnl.V4))
	}
	k.mu.Lock()
	k.lie = nil
	k.mu.Unlock()
	res, err := m.ReconcileNow(context.Background(), "again")
	if err != nil || !res.Verified {
		t.Fatalf("%+v %v", res, err)
	}
	if hasRule(k, copyAt101) {
		t.Errorf("the copy at 101 stayed: %v", k.ruleSummary(rtnl.V4))
	}
	if !hasRule(k, gl101) || !hasRule(k, want) {
		t.Errorf("gluetun's 101 or rule 102 went: %v", k.ruleSummary(rtnl.V4))
	}
}
