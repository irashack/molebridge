package mutator

// No deletion without a confirmed replacement. Every sequence in the mutator
// that removes a rule after adding what stands in for it is failed at the add
// (persistently, once, by a request that "succeeds" and installs nothing, and
// by a kernel that will not hold still for the read-back), with the exit's
// own ICMP errors from every tunnel address followed through the rules at
// every instant, the temporary guard at priority 80 in place or not.

import (
	"context"
	"errors"
	"fmt"
	"github.com/irashack/molebridge/internal/contract"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/rtnl"
)

var (
	gateA11 = netip.MustParseAddr("203.0.113.11")
	gateA12 = netip.MustParseAddr("203.0.113.12")
)

// duplicatesHarness: two live protected addresses, each pair's rules at 94 and
// 98 repeated, so that both priorities must be rebuilt.
func duplicatesHarness(t *testing.T, guard bool) *piaHarness {
	t.Helper()
	h := newPIAHarness(t, piaScenario{name: "A named, B live", old: gateA11, next: gateA11})
	h.m.Close()
	h.m = startWith(t, h.k, h.spec, func(o *Options) { o.GuardRepairs = guard })
	h.k.setAddr(rtnl.V4, "mullvad", gateA12, true)
	pair := h.spec.Clone()
	pair.ReturnPath = map[rtnl.Family][]netip.Addr{rtnl.V4: {gateA12}}
	for _, r := range pair.Rules(rtnl.V4) {
		if r.Priority == 94 || r.Priority == 98 {
			h.k.rules[rtnl.V4] = append(h.k.rules[rtnl.V4], r)
		}
	}
	for _, r := range append([]rtnl.Rule(nil), h.k.rules[rtnl.V4]...) {
		if r.Priority == 94 || r.Priority == 98 {
			h.k.rules[rtnl.V4] = append(h.k.rules[rtnl.V4], r)
		}
	}
	sortRules(h.k.rules[rtnl.V4])
	h.k.hook = h.observe
	h.observe("start")
	return h
}

func (h *piaHarness) countAt(p uint32) int {
	h.k.mu.Lock()
	defer h.k.mu.Unlock()
	n := 0
	for _, r := range h.k.rules[rtnl.V4] {
		if r.Priority == p {
			n++
		}
	}
	return n
}

func (h *piaHarness) deletions() []string {
	var out []string
	h.k.mu.Lock()
	defer h.k.mu.Unlock()
	for _, op := range h.k.log {
		if strings.HasPrefix(op, "del") {
			out = append(out, op)
		}
	}
	return out
}

func TestAFailedProtectiveCopyNeverCostsTheOriginals(t *testing.T) { // the blocker of round 4
	modes := []struct {
		name string
		fail func(op string, n *int) error
	}{
		{"persistently, copies only", func(op string, n *int) error {
			if op == "add 2 93" || op == "add 2 97" {
				return syscall.ENOMEM
			}
			return nil
		}},
		{"persistently, copies and the rules themselves", func(op string, n *int) error {
			switch op {
			case "add 2 93", "add 2 97", "add 2 94", "add 2 98":
				return syscall.ENOMEM
			}
			return nil
		}},
		{"once, the first copy", func(op string, n *int) error {
			if op == "add 2 93" {
				*n++
				if *n == 1 {
					return syscall.ENOMEM
				}
			}
			return nil
		}},
		{"once, the second copy", func(op string, n *int) error {
			if op == "add 2 97" {
				*n++
				if *n == 1 {
					return syscall.ENOMEM
				}
			}
			return nil
		}},
		{"a copy the kernel acknowledges and does not install", nil},
	}
	for _, guard := range []bool{false, true} {
		for _, md := range modes {
			t.Run(fmtName(guard, md.name), func(t *testing.T) {
				h := duplicatesHarness(t, guard)
				before94, before98 := h.countAt(94), h.countAt(98)
				if before94 < 4 || before98 < 4 {
					t.Fatalf("setup: %d at 94, %d at 98", before94, before98)
				}
				n := 0
				persistent := strings.HasPrefix(md.name, "persistently")
				if md.fail != nil {
					h.k.fail = func(op string) error { return md.fail(op, &n) }
				} else {
					h.k.lie = func(op string) bool { return op == "add 2 93" || op == "add 2 97" }
				}
				res, err := h.m.ReconcileNow(context.Background(), "x")
				if h.violation != "" {
					t.Fatal(h.violation)
				}
				if persistent || md.fail == nil {
					// Without its copies a priority is not rebuilt: the rules
					// found are all still there, and the pass says it is not
					// verified.
					if res.Verified || err == nil {
						t.Errorf("verified without being able to rebuild: %+v %v", res, err)
					}
					for _, p := range []uint32{94, 98} {
						if h.countAt(p) < 4 {
							t.Errorf("rules at %d were deleted without a protective copy: %d left of 4", p, h.countAt(p))
						}
					}
					if d := h.deletions(); len(d) > 0 && !onlyCopyCleanup(d) {
						t.Errorf("deletions %v", d)
					}
				}
				if h.m.Ready() && res.Verified == false {
					t.Error("ready without a verified pass")
				}
				// Once the kernel cooperates the contract is restored.
				h.k.fail, h.k.lie = nil, nil
				res, err = h.m.ReconcileNow(context.Background(), "again")
				if err != nil || !res.Verified {
					t.Fatalf("%+v %v", res, err)
				}
				if h.violation != "" {
					t.Fatal(h.violation)
				}
				for _, a := range []netip.Addr{gateA11, gateA12} {
					got := 0
					for _, r := range h.k.rules[rtnl.V4] {
						if (r.Priority == 94 || r.Priority == 98) && r.Src.Addr() == a {
							got++
						}
					}
					if got != 2 {
						t.Errorf("%s has %d of its 2 rules", a, got)
					}
				}
			})
		}
	}
}

func fmtName(guard bool, s string) string {
	if guard {
		return "guard/" + s
	}
	return "noguard/" + s
}

// Only the removal of copies this pass installed (none, when they failed) or
// of strays the plan itself calls for.
func onlyCopyCleanup(ops []string) bool {
	for _, op := range ops {
		if op != "del 2 93" && op != "del 2 97" {
			return false
		}
	}
	return true
}

// The refilled rules are read back before the copies go; if the kernel keeps
// changing, nothing is confirmed and the copies stay, the originals having
// been rebuilt behind them.
func TestACopyIsNotRemovedUntilWhatItProtectsIsReadBack(t *testing.T) {
	h := duplicatesHarness(t, true)
	// The re-adds "succeed" but install nothing: the rebuild cleared the
	// priority and nothing came back.
	h.k.lie = func(op string) bool { return op == "add 2 94" || op == "add 2 98" }
	res, err := h.m.ReconcileNow(context.Background(), "x")
	if h.violation != "" {
		t.Fatal(h.violation)
	}
	if res.Verified || err == nil {
		t.Errorf("verified: %+v %v", res, err)
	}
	copies := 0
	for _, r := range h.k.rules[rtnl.V4] {
		if r.Priority == 93 || r.Priority == 97 {
			copies++
		}
	}
	if copies == 0 {
		t.Errorf("the copies were removed while the rules they stand in for are not there: %v", h.k.ruleSummary(rtnl.V4))
	}
	h.k.lie = nil
	if res, err = h.m.ReconcileNow(context.Background(), "again"); err != nil || !res.Verified {
		t.Fatalf("%+v %v", res, err)
	}
	if h.violation != "" {
		t.Fatal(h.violation)
	}
}

// A kernel that does not hold still cannot confirm the copies: the rebuild
// does not start.
func TestACopyThatCannotBeReadBackOnAStableLookEndsTheRebuild(t *testing.T) {
	h := duplicatesHarness(t, false)
	copied := false
	prev := h.k.hook
	h.k.hook = func(op string) {
		prev(op)
		if op == "add 2 93" {
			copied = true
		}
	}
	h.k.unstableFn = func(int) bool { return copied }
	before94, before98 := h.countAt(94), h.countAt(98)
	res, err := h.m.ReconcileNow(context.Background(), "x")
	if h.violation != "" {
		t.Fatal(h.violation)
	}
	if res.Verified || err == nil {
		t.Errorf("verified: %+v %v", res, err)
	}
	if h.countAt(94) < before94 || h.countAt(98) < before98 {
		t.Errorf("rules were deleted on evidence that was not stable: 94 %d->%d, 98 %d->%d", before94, h.countAt(94), before98, h.countAt(98))
	}
	h.k.unstableFn = nil
	if res, err = h.m.ReconcileNow(context.Background(), "again"); err != nil || !res.Verified {
		t.Fatalf("%+v %v", res, err)
	}
}

// The kernel's priority-0 rule gives local delivery until rule 1 replaces it.
func TestThePriorityZeroRuleStaysUntilRuleOneIsReadBack(t *testing.T) {
	for _, mode := range []string{"fails", "lies"} {
		t.Run(mode, func(t *testing.T) {
			m, k, spec := healthyNamespace(t)
			// Back to a fresh namespace: rule 0 present, rule 1 absent.
			_ = k.DelRulePriority(rtnl.V4, 1)
			k.mu.Lock()
			k.rules[rtnl.V4] = append([]rtnl.Rule{{Family: rtnl.V4, Priority: 0, Action: rtnl.FRActToTbl, Table: rtnl.TableLocal, Protocol: rtnl.Some(uint8(2))}}, k.rules[rtnl.V4]...)
			k.mu.Unlock()
			if mode == "fails" {
				k.fail = func(op string) error {
					if op == "add 2 1" {
						return syscall.ENOMEM
					}
					return nil
				}
			} else {
				k.lie = func(op string) bool { return op == "add 2 1" }
			}
			res, err := m.ReconcileNow(context.Background(), "x")
			if res.Verified || err == nil {
				t.Errorf("verified: %+v %v", res, err)
			}
			has0 := false
			for _, r := range k.rules[rtnl.V4] {
				if r.Priority == 0 {
					has0 = true
				}
			}
			if !has0 {
				t.Error("rule 0 was removed while rule 1 is not installed")
			}
			k.fail, k.lie = nil, nil
			repairs(t, m, k, spec)
		})
	}
}

// A repair of 90-97 is behind the guard only if the guard is in the kernel.
func TestRulesBetweenNinetyAndNinetySevenAreLeftAloneWhenTheGuardIsNotInPlace(t *testing.T) {
	m, k, spec := healthyNamespace(t)
	// A stray rule among the guards: removing it is a repair of 90-97.
	k.mu.Lock()
	k.rules[rtnl.V4] = append(k.rules[rtnl.V4], rtnl.Rule{Family: rtnl.V4, Priority: 93, Action: rtnl.FRActUnreachable, IifName: "eth0"})
	k.mu.Unlock()
	sortRules(k.rules[rtnl.V4])
	k.fail = func(op string) error {
		if op == "add 2 80" {
			return syscall.ENOMEM
		}
		return nil
	}
	res, err := m.ReconcileNow(context.Background(), "x")
	if res.Verified || err == nil {
		t.Errorf("verified: %+v %v", res, err)
	}
	for _, op := range k.log {
		if strings.HasPrefix(op, "del 2 93") || strings.HasPrefix(op, "delprio 2 93") {
			t.Errorf("a rule among the guards was removed without the temporary guard: %v", k.log)
		}
	}
	k.fail = nil
	repairs(t, m, k, spec)
}

// The reviewer's scenario of round 5. An earlier failed refill left the
// protective copies at 93 and 97 in place of the originals at 94 and 98, and
// additions at 94 and 98 keep failing. An exact delete of the copy at 93 fails
// too, and the fallback deletes by priority; then the rebuild of 97 (its rule
// is repeated) would clear the remaining copy of the ICMP backstop. No single
// step is wrong on its own: what is wrong is that the exit's ICMP errors from
// the tunnel address would reach the host route. The owner asks the policy
// model before every deletion, and refuses the one that opens that.
func TestNoDeletionTakesTheLastProtectionOfATrafficClass(t *testing.T) {
	for _, guard := range []bool{false, true} {
		t.Run(fmtName(guard, "reviewer scenario"), func(t *testing.T) {
			m, k, spec := healthyNamespace(t, func(o *Options) { o.GuardRepairs = guard })
			a := spec.ReturnPath[rtnl.V4][0]
			var orig94, orig98 rtnl.Rule
			for _, r := range spec.Rules(rtnl.V4) {
				switch {
				case r.Priority == 94 && r.Src.Addr() == a:
					orig94 = r
				case r.Priority == 98 && r.Src.Addr() == a:
					orig98 = r
				}
			}
			_ = k.DelRulePriority(rtnl.V4, 94)
			_ = k.DelRulePriority(rtnl.V4, 98)
			copy93, copy97 := orig94, orig98
			copy93.Priority, copy97.Priority = 93, 97
			dup97 := rtnl.Rule{Family: rtnl.V4, Priority: 97, Action: rtnl.FRActUnreachable, IifName: spec.Config.OverlayIf}
			for _, r := range []rtnl.Rule{copy93, copy97} {
				if err := k.AddRule(r); err != nil {
					t.Fatal(err)
				}
			}
			// The kernel refuses an exact repeat; one that arrived some other
			// way is put in directly.
			k.mu.Lock()
			k.rules[rtnl.V4] = append(k.rules[rtnl.V4], dup97)
			k.mu.Unlock()
			sortRules(k.rules[rtnl.V4])
			k.log = nil
			guardLeaks(t, k, spec)
			if v := k.escapes(spec); len(v) != 0 {
				t.Fatalf("the starting point is not protected: %v", v)
			}
			k.fail = func(op string) error {
				switch op {
				case "add 2 94", "add 2 98":
					return syscall.ENOMEM
				case "del 2 93":
					return syscall.EIO
				}
				return nil
			}
			res, err := m.ReconcileNow(context.Background(), "x")
			if res.Verified || err == nil {
				t.Errorf("verified: %+v %v", res, err)
			}
			if v := k.escapes(spec); len(v) != 0 {
				t.Errorf("the policy model sees an escape at the end: %v", v)
			}
			// The ICMP protection is still there, in one form or the other.
			kept := false
			for _, r := range k.rules[rtnl.V4] {
				if r.Src.IsValid() && r.Src.Addr() == a {
					kept = true
				}
			}
			if !kept {
				t.Errorf("every rule for %s went: %v", a, k.ruleSummary(rtnl.V4))
			}
			k.fail = nil
			repairs(t, m, k, spec)
		})
	}
}

// A deletion the owner cannot judge is not made: a snapshot that never holds
// still gives no evidence, and nothing is removed on it.
func TestADeletionIsNotMadeOnEvidenceThatIsNotStable(t *testing.T) {
	m, k, spec := healthyNamespace(t)
	k.mu.Lock()
	k.rules[rtnl.V4] = append(k.rules[rtnl.V4], rtnl.Rule{Family: rtnl.V4, Priority: 93, Action: rtnl.FRActUnreachable, IifName: "eth0"})
	k.mu.Unlock()
	sortRules(k.rules[rtnl.V4])
	err := m.Do(context.Background(), "delete", func(tx *Tx) error {
		k.unstable = true
		defer func() { k.unstable = false }()
		return tx.DelRule(rtnl.Rule{Family: rtnl.V4, Priority: 93, Action: rtnl.FRActUnreachable, IifName: "eth0"})
	})
	if !errors.Is(err, ErrUnsafeDeletion) {
		t.Fatalf("%v", err)
	}
	if index(k.log, "del 2 93") >= 0 {
		t.Error("the rule was deleted on an unstable look")
	}
	repairs(t, m, k, spec)
}

// What the case-by-case gates cannot know: a rule of no priority the contract
// expects can be the only thing between a class of traffic and the host's
// route, because the rules that should be there cannot be added. It is not
// deleted, whatever the plan calls it.
func TestAForeignRuleThatIsTheOnlyProtectionIsNotDeleted(t *testing.T) {
	cases := []struct {
		name  string
		setup func(spec contract.Spec, k *fakeKernel) (stray rtnl.Rule)
		fail  func(op string) error
	}{
		{"ICMP from the tunnel address", func(spec contract.Spec, k *fakeKernel) rtnl.Rule {
			a := spec.ReturnPath[rtnl.V4][0]
			_ = k.DelRulePriority(rtnl.V4, 94)
			_ = k.DelRulePriority(rtnl.V4, 98)
			r := rtnl.Rule{Family: rtnl.V4, Priority: 50, Action: rtnl.FRActUnreachable, Src: netip.PrefixFrom(a, 32), IPProto: rtnl.Some(uint8(1))}
			if err := k.AddRule(r); err != nil {
				panic(err)
			}
			return r
		}, func(op string) error {
			if op == "add 2 94" || op == "add 2 98" {
				return syscall.ENOMEM
			}
			return nil
		}},
		{"forwarded traffic from the overlay", func(spec contract.Spec, k *fakeKernel) rtnl.Rule {
			_ = k.DelRulePriority(rtnl.V4, 95)
			_ = k.DelRulePriority(rtnl.V4, 97)
			r := rtnl.Rule{Family: rtnl.V4, Priority: 60, Action: rtnl.FRActUnreachable, IifName: spec.Config.OverlayIf}
			if err := k.AddRule(r); err != nil {
				panic(err)
			}
			return r
		}, func(op string) error {
			if op == "add 2 95" || op == "add 2 97" || op == "add 2 80" { // the temporary guard is another protection
				return syscall.ENOMEM
			}
			return nil
		}},
	}
	for _, guard := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(fmtName(guard, tc.name), func(t *testing.T) {
				m, k, spec := healthyNamespace(t, func(o *Options) { o.GuardRepairs = guard })
				stray := tc.setup(spec, k)
				k.log = nil
				guardLeaks(t, k, spec)
				if v := k.escapes(spec); len(v) != 0 {
					t.Fatalf("the starting point is not protected: %v", v)
				}
				k.fail = tc.fail
				res, err := m.ReconcileNow(context.Background(), "x")
				if res.Verified || err == nil {
					t.Errorf("verified: %+v %v", res, err)
				}
				if v := k.escapes(spec); len(v) != 0 {
					t.Errorf("the policy model sees an escape: %v", v)
				}
				still := false
				for _, r := range k.rules[rtnl.V4] {
					if r.Priority == stray.Priority {
						still = true
					}
				}
				if !still {
					t.Errorf("the only protection, rule %d, was deleted: %v", stray.Priority, k.ruleSummary(rtnl.V4))
				}
				// Once the kernel cooperates the contract is restored and the
				// foreign rule goes.
				k.fail = nil
				repairs(t, m, k, spec)
			})
		}
	}
}

// Routes that carry a TOS are not the contract's: the reviewer found both IPv4
// routes of the exit table re-marked TOS 16 and the pass verified with no
// mutation. They are replaced, and nothing leaks while they are.
func TestTOSRoutesAreReplacedNotAccepted(t *testing.T) {
	m, k, spec := healthyNamespace(t)
	k.mu.Lock()
	for i := range k.routes[rtnl.V4] {
		k.routes[rtnl.V4][i].Tos = 16
	}
	k.mu.Unlock()
	guardLeaks(t, k, spec)
	res := repairs(t, m, k, spec)
	if !res.Repaired {
		t.Error("nothing was repaired")
	}
	for _, r := range k.routes[rtnl.V4] {
		if r.Tos != 0 {
			t.Errorf("a TOS route is still there: %+v", r)
		}
	}
}

// A change moves away from the old address, and its own steps may remove the old
// pair once the address is gone; while the address is live the pair is still
// protected, and the deletion is refused.
func TestAChangeMayRetireTheOldPairOnlyOnceTheAddressIsGone(t *testing.T) {
	a11, a12 := netip.MustParseAddr("203.0.113.11"), netip.MustParseAddr("203.0.113.12")
	pairRule := func(spec contract.Spec, prio uint32, a netip.Addr) rtnl.Rule {
		s := spec.Clone()
		s.ReturnPath = map[rtnl.Family][]netip.Addr{rtnl.V4: {a}}
		for _, r := range s.Rules(rtnl.V4) {
			if r.Priority == prio {
				return r
			}
		}
		t.Fatal("no rule")
		return rtnl.Rule{}
	}
	h := newPIAHarness(t, piaScenario{name: "x", old: a11, next: a12})
	h.k.hook = h.observe
	var whileLive, afterGone error
	err := h.m.ChangeReturnPath(context.Background(), rtnl.V4, a11, a12, func(tx *Tx) error {
		h.k.setAddr(rtnl.V4, "mullvad", a12, true)
		if err := tx.DelRule(pairRule(h.spec, 94, a11)); err != nil { // the backstop still stops it
			return err
		}
		whileLive = tx.DelRule(pairRule(h.spec, 98, a11)) // a11 is still on the interface: its last protection
		h.k.setAddr(rtnl.V4, "mullvad", a11, false)
		afterGone = tx.DelRule(pairRule(h.spec, 98, a11))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(whileLive, ErrUnsafeDeletion) {
		t.Errorf("the pair of a live address was deleted: %v", whileLive)
	}
	if afterGone != nil {
		t.Errorf("the pair of an address that left was refused: %v", afterGone)
	}
	if h.violation != "" {
		t.Error(h.violation)
	}
}

// Round 8: the reviewer's TOS-16 protection at priority 50, with 94 and 98
// missing and failing to come back. ICMP of every other TOS value already
// escapes to main; the pass must still not delete the rule that stops TOS 16.
func TestATOSQualifiedProtectionIsNotDeletedWhileTheContractCannotBeRestored(t *testing.T) {
	m, k, spec := healthyNamespace(t)
	a := spec.ReturnPath[rtnl.V4][0]
	_ = k.DelRulePriority(rtnl.V4, 94)
	_ = k.DelRulePriority(rtnl.V4, 98)
	protect := rtnl.Rule{Family: rtnl.V4, Priority: 50, Action: rtnl.FRActUnreachable, IPProto: rtnl.Some(uint8(1)), Src: netip.PrefixFrom(a, 32), Tos: 16}
	if err := k.AddRule(protect); err != nil {
		t.Fatal(err)
	}
	k.fail = func(op string) error {
		if op == "add 2 94" || op == "add 2 98" {
			return syscall.ENOMEM
		}
		return nil
	}
	res, err := m.ReconcileNow(context.Background(), "x")
	if res.Verified || err == nil {
		t.Errorf("verified: %+v %v", res, err)
	}
	found := false
	for _, r := range k.rules[rtnl.V4] {
		if r.Priority == 50 {
			found = true
		}
	}
	if !found {
		t.Errorf("the TOS-16 protection was deleted: %v", k.ruleSummary(rtnl.V4))
	}
	k.fail = nil
	repairs(t, m, k, spec)
}

// One stable snapshot per pass: the deletions of a pass are judged against the
// model of the snapshot with the pass's own changes applied, and only a change
// somebody else made sends the owner back to the kernel.
func TestADeletionIsJudgedAgainstThePassesModelNotANewSnapshot(t *testing.T) {
	m, k, spec := healthyNamespace(t)
	k.mu.Lock()
	for p := uint32(20); p < 28; p++ {
		k.rules[rtnl.V4] = append(k.rules[rtnl.V4], rtnl.Rule{Family: rtnl.V4, Priority: p, Action: rtnl.FRActUnreachable, IifName: "eth0"})
	}
	k.mu.Unlock()
	sortRules(k.rules[rtnl.V4])
	k.mu.Lock()
	k.takes = 0
	k.mu.Unlock()
	repairs(t, m, k, spec)
	k.mu.Lock()
	takes := k.takes
	k.mu.Unlock()
	// The plan's look, the look that verifies, and the checks of the end.
	if takes > 4 {
		t.Errorf("%d snapshots for the removal of eight strays: a deletion took a snapshot of its own", takes)
	}
}

func TestAChangeBySomebodyElseSendsTheOwnerBackToTheKernel(t *testing.T) {
	m, k, spec := healthyNamespace(t)
	k.mu.Lock()
	for p := uint32(20); p < 24; p++ {
		k.rules[rtnl.V4] = append(k.rules[rtnl.V4], rtnl.Rule{Family: rtnl.V4, Priority: p, Action: rtnl.FRActUnreachable, IifName: "eth0"})
	}
	k.mu.Unlock()
	sortRules(k.rules[rtnl.V4])
	// Somebody else puts a rule in after the first deletion.
	var once sync.Once
	k.hook = func(op string) {
		if strings.HasPrefix(op, "del 2 2") {
			once.Do(func() {
				k.mu.Lock()
				k.rules[rtnl.V4] = append(k.rules[rtnl.V4], rtnl.Rule{Family: rtnl.V4, Priority: 70, Action: rtnl.FRActUnreachable, IifName: "eth0"})
				k.mu.Unlock()
				sortRules(k.rules[rtnl.V4])
			})
		}
	}
	k.mu.Lock()
	k.takes = 0
	k.mu.Unlock()
	repairs(t, m, k, spec)
	k.mu.Lock()
	takes := k.takes
	k.mu.Unlock()
	if takes < 3 {
		t.Errorf("%d snapshots: the foreign change did not make the owner look again", takes)
	}
	for _, r := range k.rules[rtnl.V4] {
		if r.Priority == 70 {
			t.Error("the stray somebody else added was not removed")
		}
	}
}

// A refusal that persists is logged once, not on every pass, and again once
// RefusalRelog has passed.
func TestARefusalThatPersistsIsLoggedOncePerRelog(t *testing.T) {
	var mu sync.Mutex
	var logged []string
	var now atomic.Int64
	now.Store(int64(time.Hour))
	m, k, _ := healthyNamespace(t, func(o *Options) {
		o.Clock = func() time.Duration { return time.Duration(now.Load()) }
		o.Logf = func(format string, a ...any) {
			mu.Lock()
			defer mu.Unlock()
			logged = append(logged, fmt.Sprintf(format, a...))
		}
	})
	stray := rtnl.Rule{Family: rtnl.V4, Priority: 93, Action: rtnl.FRActUnreachable, IifName: "eth0"}
	k.mu.Lock()
	k.rules[rtnl.V4] = append(k.rules[rtnl.V4], stray)
	k.mu.Unlock()
	sortRules(k.rules[rtnl.V4])
	refuse := func() {
		t.Helper()
		err := m.Do(context.Background(), "delete", func(tx *Tx) error {
			k.unstable = true
			defer func() { k.unstable = false }()
			return tx.DelRule(stray)
		})
		if !errors.Is(err, ErrUnsafeDeletion) {
			t.Fatalf("%v", err)
		}
	}
	count := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, line := range logged {
			if strings.Contains(line, "kept IPv4 rule 93") {
				n++
			}
		}
		return n
	}
	for i := 0; i < 3; i++ {
		refuse()
	}
	if n := count(); n != 1 {
		t.Fatalf("logged %d times in three passes: %q", n, logged)
	}
	now.Add(int64(RefusalRelog))
	refuse()
	if n := count(); n != 2 {
		t.Fatalf("not logged again after RefusalRelog: %d: %q", n, logged)
	}
}
