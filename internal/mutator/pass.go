package mutator

import (
	"errors"
	"fmt"
	"time"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// PassResult is what one reconcile pass found and did.
type PassResult struct {
	Reason string
	// Repaired: the pass changed the kernel.
	Repaired  bool
	Mutations int
	// ContractHolds: on the final snapshot the rules, the exit table and the
	// host table are as expected and the temporary guard is out again.
	ContractHolds bool
	// Verified is ContractHolds and nothing outside the owner's reach is
	// wrong (the gluetun backend without an IPv4 default route through the
	// host interface). The worker's routing check is Verified.
	Verified bool
	// Problems that remain, per family, when not Verified.
	Problems map[rtnl.Family][]contract.Problem
	// Err is the first snapshot or kernel failure of the pass, or says the
	// contract could not be verified.
	Err error
	// At is the boot-clock time the pass ended.
	At time.Duration
}

// maxRounds bounds the repair rounds of one pass: a repair, a verification,
// and a repair of what the verification found, then the guard's removal.
const maxRounds = 4

var families = []rtnl.Family{rtnl.V4, rtnl.V6}

// guardRule is the temporary priority-80 rule: forwarded traffic is
// unreachable while the guards at 90-97 are rebuilt.
func guardRule(spec contract.Spec, f rtnl.Family) rtnl.Rule {
	s := spec.Clone()
	s.TempGuard = map[rtnl.Family]bool{f: true}
	for _, r := range s.Rules(f) {
		if r.Priority == contract.PrioTempGuard {
			return r
		}
	}
	return rtnl.Rule{}
}

// hasGuard reports an exact priority-80 guard among the rules.
func hasGuard(spec contract.Spec, f rtnl.Family, rules []rtnl.Rule) bool {
	want := guardRule(spec, f).Items()
	for _, r := range rules {
		if r.Priority == contract.PrioTempGuard && equalStrings(r.Items(), want) {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func planAll(spec contract.Spec, snap *rtnl.Snapshot) map[rtnl.Family]contract.Plan {
	out := map[rtnl.Family]contract.Plan{}
	for _, f := range families {
		out[f] = spec.PlanFamily(snap, f, contract.PlanInput{})
	}
	return out
}

func allClean(plans map[rtnl.Family]contract.Plan) bool {
	for _, p := range plans {
		if !p.Clean() {
			return false
		}
	}
	return true
}

func allHealthy(plans map[rtnl.Family]contract.Plan) bool {
	for _, p := range plans {
		if !p.Healthy() {
			return false
		}
	}
	return true
}

func guardsHeld(spec contract.Spec) bool {
	for _, f := range families {
		if spec.TempGuard[f] {
			return true
		}
	}
	return false
}

// reconcile is the repair pass: look at the kernel, compare it with the
// expected state, apply the ordered actions, look again, and go on until the
// contract verifies or the rounds are spent. A gluetun sidecar has no contract.
//
// A repair that changes rules 90-97 happens behind the temporary guard at
// priority 80 (natively), which comes out once the result verifies; while it
// cannot be verified the guard stays, and a later pass that finds everything
// else right takes it out.
func (tx *Tx) reconcile(reason string) (res PassResult) {
	m := tx.m
	res.Reason = reason
	res.Problems = map[rtnl.Family][]contract.Problem{}
	defer func() {
		res.At = m.o.Clock()
		m.recordPass(res)
	}()
	fail := func(err error) {
		if res.Err == nil {
			res.Err = err
		}
	}
	if m.Expected().Config.IsGluetunSidecar() {
		res.ContractHolds, res.Verified = true, true
		return
	}
	snap, err := tx.Snapshot()
	if err != nil {
		fail(opErr("look at the kernel", err))
		return
	}
	for round := 0; ; round++ {
		spec := m.Expected()
		// A guard left by an earlier pass is expected until a pass verifies.
		for _, f := range families {
			if !spec.Config.IsNativeSidecar() && !spec.TempGuard[f] && hasGuard(spec, f, snap.Rules[f]) {
				spec.TempGuard[f] = true
				tx.SetSpec(spec)
			}
		}
		plans := planAll(spec, snap)
		if allClean(plans) && snap.Unstable {
			// Nothing to repair on this look, but the kernel kept changing
			// while it was taken: no verdict, no release of a guard.
			if round >= maxRounds {
				fail(errors.New("the kernel kept changing; the routing contract could not be verified"))
				break
			}
			if snap, err = tx.Snapshot(); err != nil {
				fail(opErr("look at the kernel", err))
				return
			}
			continue
		}
		if allClean(plans) {
			if !guardsHeld(spec) {
				res.ContractHolds = true
				res.Verified = allHealthy(plans)
				for _, f := range families {
					res.Problems[f] = plans[f].Problems
				}
				res.Err = nil
				return
			}
			// Verified behind the guard: take it out, then look again.
			for _, f := range families {
				if !spec.TempGuard[f] {
					continue
				}
				g := guardRule(spec, f)
				spec.TempGuard[f] = false
				tx.SetSpec(spec)
				changed, err := tx.delRule(g)
				if err != nil {
					fail(opErr(fmt.Sprintf("remove the %s temporary guard", f), err))
				}
				if changed {
					res.Repaired = true
					res.Mutations++
				}
			}
			if snap, err = tx.Snapshot(); err != nil {
				fail(opErr("look at the kernel", err))
				return
			}
			if round >= maxRounds {
				break
			}
			continue
		}
		if round >= maxRounds {
			break
		}
		// Behind the guard first, when a repair would change rules 90-97.
		if m.o.GuardRepairs {
			for _, f := range families {
				if !contract.TouchesGuards(plans[f].Rules) || spec.TempGuard[f] {
					continue
				}
				spec.TempGuard[f] = true
				tx.SetSpec(spec)
				g := guardRule(spec, f)
				changed, err := tx.addRule(g)
				if err != nil {
					fail(opErr(fmt.Sprintf("add the %s temporary guard", f), err))
				}
				if changed {
					res.Repaired = true
					res.Mutations++
					tx.Logf("molebridge: added the %s temporary guard", f)
					snap = withRule(snap, f, g)
				}
				plans[f] = spec.PlanFamily(snap, f, contract.PlanInput{})
			}
		}
		for _, f := range families {
			n, errs := tx.apply(plans[f], !snap.Unstable)
			if n > 0 {
				res.Repaired = true
				res.Mutations += n
			}
			for _, e := range errs {
				fail(e)
			}
		}
		if snap, err = tx.Snapshot(); err != nil {
			fail(opErr("look at the kernel", err))
			return
		}
	}
	// Not verified: say what is still wrong.
	spec := m.Expected()
	for _, f := range families {
		res.Problems[f] = spec.PlanFamily(snap, f, contract.PlanInput{}).Problems
	}
	res.Verified = false
	if res.Err == nil {
		res.Err = errors.New("the routing contract could not be verified after repair")
	}
	return
}

// withRule returns a copy of the snapshot with a rule added to a family, so a
// plan can be recomputed after an addition without another dump.
func withRule(snap *rtnl.Snapshot, f rtnl.Family, r rtnl.Rule) *rtnl.Snapshot {
	cp := *snap
	cp.Rules = map[rtnl.Family][]rtnl.Rule{}
	for k, v := range snap.Rules {
		cp.Rules[k] = v
	}
	rules := append([]rtnl.Rule(nil), snap.Rules[f]...)
	i := len(rules)
	for j, x := range rules {
		if x.Priority > r.Priority {
			i = j
			break
		}
	}
	rules = append(rules[:i], append([]rtnl.Rule{r}, rules[i:]...)...)
	cp.Rules[f] = rules
	return &cp
}
