package mutator

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// faults the drills and the field produce, applied to a healthy namespace.
func randomFault(rng *rand.Rand, k *fakeKernel, spec contract.Spec) string {
	f := families[rng.Intn(2)]
	owned := []uint32{1, 90, 94, 95, 96, 97, 98}
	p := owned[rng.Intn(len(owned))]
	switch rng.Intn(12) {
	case 0, 1:
		_ = k.DelRulePriority(f, p)
		return fmt.Sprintf("delete %s %d", f, p)
	case 2: // a foreign rule anywhere in the owned range
		prio := uint32(rng.Intn(99))
		act := []uint8{rtnl.FRActToTbl, rtnl.FRActUnreachable, rtnl.FRActProhibit}[rng.Intn(3)]
		r := rtnl.Rule{Family: f, Priority: prio, Action: act}
		if act == rtnl.FRActToTbl {
			r.Table = []uint32{rtnl.TableMain, rtnl.TableLocal, 51821, 12345}[rng.Intn(4)]
		}
		if rng.Intn(2) == 0 {
			r.IifName = []string{"wt0", "mullvad", "eth0", "lo"}[rng.Intn(4)]
		}
		if rng.Intn(3) == 0 {
			r.FwMark, r.FwMask = rtnl.Some(uint32(rng.Intn(9))+1), rtnl.Some(uint32(0xffffffff))
		}
		if rng.Intn(4) == 0 {
			r.Flags |= rtnl.FIBRuleInvert
		}
		_ = k.AddRule(r)
		return fmt.Sprintf("insert %v", r)
	case 3: // the kernel's rule 0 comes back
		_ = k.AddRule(rtnl.Rule{Family: f, Priority: 0, Action: rtnl.FRActToTbl, Table: rtnl.TableLocal})
		return fmt.Sprintf("rule 0 back %s", f)
	case 4: // wrong action
		for i, r := range k.rules[f] {
			if r.Priority == p {
				if r.Action == rtnl.FRActUnreachable {
					k.rules[f][i].Action = rtnl.FRActProhibit
				} else {
					k.rules[f][i].Action, k.rules[f][i].Table = rtnl.FRActUnreachable, 0
				}
				return fmt.Sprintf("wrong action %s %d", f, p)
			}
		}
	case 5: // an extra selector on a copy
		for _, r := range k.rules[f] {
			if r.Priority == p {
				r.FwMark, r.FwMask = rtnl.Some(uint32(7)), rtnl.Some(uint32(0xffffffff))
				_ = k.AddRule(r)
				return fmt.Sprintf("extra selector copy %s %d", f, p)
			}
		}
	case 6: // a subset: the rule without one selector
		for i, r := range k.rules[f] {
			if r.Priority == p {
				switch {
				case r.IifName != "":
					k.rules[f][i].IifName = ""
				case r.OifName != "":
					k.rules[f][i].OifName = ""
				case r.Src.IsValid():
					k.rules[f][i].Src = netip.Prefix{}
				case r.Dst.IsValid():
					k.rules[f][i].Dst = netip.Prefix{}
				default:
					continue
				}
				return fmt.Sprintf("narrower %s %d", f, p)
			}
		}
	case 7: // a duplicate
		for _, r := range k.rules[f] {
			if r.Priority == p {
				k.rules[f] = append(k.rules[f], r)
				return fmt.Sprintf("duplicate %s %d", f, p)
			}
		}
	case 8: // an inversion flipped
		for i, r := range k.rules[f] {
			if r.Priority == p {
				k.rules[f][i].Flags ^= rtnl.FIBRuleInvert
				return fmt.Sprintf("invert %s %d", f, p)
			}
		}
	case 9: // the exit table loses a route
		if n := len(k.routes[f]); n > 0 {
			i := rng.Intn(n)
			k.routes[f] = append(k.routes[f][:i:i], k.routes[f][i+1:]...)
			return fmt.Sprintf("route %d lost %s", i, f)
		}
	case 10: // a foreign route in the exit table
		k.routes[f] = append(k.routes[f], rtnl.Route{Family: f, Dst: netip.MustParsePrefix(map[rtnl.Family]string{4: "203.0.113.99/32", 6: "2001:db8:99::1/128"}[f]),
			Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2))})
		return fmt.Sprintf("foreign route %s", f)
	case 11: // a leftover guard
		_ = k.AddRule(guardRule(spec, f))
		return fmt.Sprintf("leftover guard %s", f)
	}
	return "nothing"
}

// Whatever combination of these faults is injected into a healthy namespace,
// one pass restores the exact contract, and no step of the repair opens a
// namespace that was closed before the step.
func TestRandomFaultsAreRepairedWithoutOpeningTheNamespace(t *testing.T) {
	// With the temporary guard (the native practice) and without it: the
	// ordering and the rebuild must close every gap on their own.
	for _, guard := range []bool{true, false} {
		t.Run(fmt.Sprintf("guard=%v", guard), func(t *testing.T) { randomFaults(t, guard) })
	}
}

func randomFaults(t *testing.T, guard bool) {
	rng := rand.New(rand.NewSource(20261012))
	n := draws(1500)
	var withFault, repaired, leakedAtStart int
	defer func() {
		t.Logf("%d cases, %d with a repairable fault, %d starting open", n, repaired, leakedAtStart)
		_ = withFault
	}()
	for i := 0; i < n; i++ {
		k := newFakeKernel()
		spec := nativeSpec()
		k.installNative(spec, true)
		m := New(Options{Kernel: k, Spec: spec, GuardRepairs: guard, OpTimeout: 5e9, IdleStep: 1e9})
		m.Start()
		var faults []string
		for n := 1 + rng.Intn(3); n > 0; n-- {
			faults = append(faults, randomFault(rng, k, spec))
		}
		startLeak := leaking(k, spec)
		if startLeak {
			leakedAtStart++
		}
		var wasSafe = !startLeak
		bad := ""
		k.hook = func(op string) {
			l := leaking(k, spec)
			if !l {
				wasSafe = true
			} else if wasSafe && bad == "" {
				bad = op
			}
		}
		res, err := m.ReconcileNow(context.Background(), "random")
		if err != nil || !res.Verified {
			t.Fatalf("case %d, faults %v: %v %+v\n%v", i, faults, err, res, k.log)
		}
		if res.Repaired {
			repaired++
		}
		snap, _ := k.Take(spec.Interest())
		for _, f := range families {
			p := spec.PlanFamily(snap, f, contract.PlanInput{})
			if !p.Healthy() {
				t.Fatalf("case %d, faults %v: %s unhealthy after repair: %v %v\n%v", i, faults, f, p.Rules, p.Routes, k.ruleSummary(f))
			}
			if _, ok := priorities(k, f)[80]; ok {
				t.Fatalf("case %d, faults %v: guard left", i, faults)
			}
		}
		if bad != "" {
			t.Fatalf("case %d, faults %v: the namespace leaked after %q\n%v", i, faults, bad, k.log)
		}
		if leaking(k, spec) {
			t.Fatalf("case %d, faults %v: leaks after repair", i, faults)
		}
		// And the repair is stable: a second pass has nothing to do.
		mark := len(k.log)
		res, err = m.ReconcileNow(context.Background(), "again")
		if err != nil || !res.Verified || len(k.log) != mark {
			t.Fatalf("case %d, faults %v: not stable: %v %+v %v", i, faults, err, res, k.log[mark:])
		}
		m.Close()
	}
}
