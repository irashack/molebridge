package mutator

// The property the owner's deletion check exists for, tried against random
// failures: from a state in which every protected class of traffic is safe, no
// mutation the owner makes - whatever requests the kernel refuses, whenever its
// snapshots are unstable or unreadable - lets the policy model see one escape,
// and once the kernel cooperates the contract is restored.

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"syscall"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// kernelState is a copy of the fake's rules and routes, to undo a fault.
type kernelState struct {
	rules  map[rtnl.Family][]rtnl.Rule
	routes map[rtnl.Family][]rtnl.Route
}

func saveState(k *fakeKernel) kernelState {
	s := kernelState{rules: map[rtnl.Family][]rtnl.Rule{}, routes: map[rtnl.Family][]rtnl.Route{}}
	for _, f := range families {
		s.rules[f] = append([]rtnl.Rule(nil), k.rules[f]...)
		s.routes[f] = append([]rtnl.Route(nil), k.routes[f]...)
	}
	return s
}

func (s kernelState) restore(k *fakeKernel) {
	for _, f := range families {
		k.rules[f] = append([]rtnl.Rule(nil), s.rules[f]...)
		k.routes[f] = append([]rtnl.Route(nil), s.routes[f]...)
	}
}

func TestNoFailureSequenceEverOpensAProtectedClass(t *testing.T) {
	for _, guard := range []bool{true, false} {
		t.Run(fmt.Sprintf("guard=%v", guard), func(t *testing.T) { failureSequences(t, guard) })
	}
}

func failureSequences(t *testing.T, guard bool) {
	rng := rand.New(rand.NewSource(20261013))
	var cases, refused, withFailures int
	for i := 0; i < 1500; i++ {
		k := newFakeKernel()
		spec := nativeSpec()
		k.installNative(spec, true)
		var logged []string
		m := New(Options{Kernel: k, Spec: spec, GuardRepairs: guard, OpTimeout: 5e9, IdleStep: 1e9,
			Logf: func(format string, a ...any) { logged = append(logged, fmt.Sprintf(format, a...)) }})
		m.Start()
		// A starting point with some faults in it, every class still safe.
		var faults []string
		for n := 1 + rng.Intn(4); n > 0; n-- {
			before := saveState(k)
			f := randomFault(rng, k, spec)
			for _, fam := range families {
				sortRules(k.rules[fam]) // the kernel keeps rules in priority order
			}
			if len(k.escapes(spec)) > 0 {
				before.restore(k)
				continue
			}
			faults = append(faults, f)
		}
		if len(faults) == 0 {
			m.Close()
			continue
		}
		cases++
		// Failures: a rate for every request, and requests that never succeed.
		rate := []float64{0, 0.15, 0.4, 0.8}[rng.Intn(4)]
		persistent := map[string]bool{}
		for n := rng.Intn(4); n > 0; n-- {
			persistent[fmt.Sprintf("add %d %d", 2+4*rng.Intn(2), []int{80, 93, 94, 95, 96, 97, 98, 1}[rng.Intn(8)])] = true
		}
		failed := 0
		k.fail = func(op string) error {
			if persistent[op] || rng.Float64() < rate {
				failed++
				return []error{syscall.ENOMEM, syscall.EIO, syscall.EBUSY}[rng.Intn(3)]
			}
			return nil
		}
		unstableRate := []float64{0, 0.2, 0.5}[rng.Intn(3)]
		k.unstableFn = func(int) bool { return rng.Float64() < unstableRate }
		if rng.Intn(4) == 0 {
			k.takeFail = func(int) error {
				if rng.Float64() < 0.2 {
					return errors.New("the dump failed")
				}
				return nil
			}
		}
		bad := ""
		k.hook = func(op string) {
			if v := k.escapes(spec); len(v) > 0 && bad == "" {
				bad = fmt.Sprintf("after %q: %v", op, v)
			}
		}
		for pass := 0; pass < 4; pass++ {
			_, _ = m.ReconcileNow(context.Background(), "random")
		}
		if failed > 0 {
			withFailures++
		}
		for _, l := range logged {
			if len(l) > 15 && l[:15] == "molebridge: kep" {
				refused++
				break
			}
		}
		if bad != "" {
			t.Fatalf("case %d, faults %v, rate %v, persistent %v, unstable %v: %s\n%v", i, faults, rate, persistent, unstableRate, bad, k.log)
		}
		// The kernel cooperates again: the contract comes back.
		k.fail, k.unstableFn, k.takeFail = nil, nil, nil
		var res PassResult
		var err error
		for pass := 0; pass < 3; pass++ {
			if res, err = m.ReconcileNow(context.Background(), "cooperating"); err == nil && res.Verified {
				break
			}
		}
		if err != nil || !res.Verified {
			t.Fatalf("case %d, faults %v, rate %v, persistent %v: not restored: %v %+v\n%v\n%v\n%v", i, faults, rate, persistent, err, res, k.ruleSummary(rtnl.V4), k.ruleSummary(rtnl.V6), logged)
		}
		snap, _ := k.Take(spec.Interest())
		for _, f := range families {
			if p := spec.PlanFamily(snap, f, contract.PlanInput{}); !p.Healthy() {
				t.Fatalf("case %d, faults %v: %s unhealthy after the kernel cooperated: %v %v\n%v", i, faults, f, p.Rules, p.Routes, k.ruleSummary(f))
			}
		}
		m.Close()
	}
	t.Logf("%d cases, %d with refused requests, %d where the owner kept a rule it judged unsafe to delete", cases, withFailures, refused)
}
