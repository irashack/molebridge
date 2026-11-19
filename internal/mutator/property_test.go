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
	"net/netip"
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

// extraFault adds what the round-6 review found the model must handle: routes
// out of the wrong device, TOS routes, gotos, explicit zero marks and rules
// with selectors that cannot be followed.
func extraFault(rng *rand.Rand, k *fakeKernel, spec contract.Spec) string {
	f := families[rng.Intn(2)]
	owned := []uint32{1, 90, 94, 95, 96, 97, 98}
	p := owned[rng.Intn(len(owned))]
	switch rng.Intn(6) {
	case 0: // a default route out of the host interface in the exit table
		k.routes[f] = append(k.routes[f], rtnl.Route{Family: f, Dst: netip.PrefixFrom(map[rtnl.Family]netip.Addr{4: netip.IPv4Unspecified(), 6: netip.IPv6Unspecified()}[f], 0),
			Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2)), Metric: uint32([]int{0, 100, 5000}[rng.Intn(3)])})
		return fmt.Sprintf("host default in the exit table %s", f)
	case 1: // the fallback with a TOS
		for _, r := range k.routes[f] {
			if r.Type == rtnl.RTNUnreachable {
				r.Tos = 16
				k.routes[f] = append(k.routes[f], r)
				return fmt.Sprintf("TOS fallback %s", f)
			}
		}
	case 2: // a goto
		prio := uint32(rng.Intn(99))
		_ = k.AddRule(rtnl.Rule{Family: f, Priority: prio, Action: rtnl.FRActGoto, Goto: rtnl.Some(prio + 1 + uint32(rng.Intn(60)))})
		return fmt.Sprintf("goto at %d", prio)
	case 3: // an explicit zero mark on a copy
		for _, r := range k.rules[f] {
			if r.Priority == p {
				r.FwMark, r.FwMask = rtnl.Some(uint32(0)), rtnl.Some(uint32(0xffffffff))
				k.rules[f] = append(k.rules[f], r)
				return fmt.Sprintf("zero-mark copy %s %d", f, p)
			}
		}
	case 4: // a TOS copy of a protective rule
		for _, r := range k.rules[f] {
			if r.Priority == p {
				r.Tos = 16
				k.rules[f] = append(k.rules[f], r)
				return fmt.Sprintf("TOS copy %s %d", f, p)
			}
		}
	case 5: // a rule with a selector nothing can follow
		for _, r := range k.rules[f] {
			if r.Priority == p {
				r.Unknown = []rtnl.RawAttr{{Type: 99, Data: []byte{1}}}
				k.rules[f] = append(k.rules[f], r)
				return fmt.Sprintf("unknown-selector copy %s %d", f, p)
			}
		}
	}
	return "nothing"
}

// draws scales a property test's number of random cases: the full count in
// the default run, a tenth with -short or under the race detector, which
// runs these tests about ten times slower and would otherwise come close to
// go test's 10-minute timeout. The seeds are fixed, so the shorter run
// checks the first cases of the full one.
func draws(full int) int {
	if testing.Short() || raceEnabled {
		return full / 10
	}
	return full
}

func TestNoFailureSequenceEverOpensAProtectedClass(t *testing.T) {
	for _, guard := range []bool{true, false} {
		t.Run(fmt.Sprintf("guard=%v", guard), func(t *testing.T) { failureSequences(t, guard) })
	}
}

func failureSequences(t *testing.T, guard bool) {
	rng := rand.New(rand.NewSource(20261013))
	var cases, refused, withFailures int
	for i := 0; i < draws(1500); i++ {
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
			var f string
			if rng.Intn(3) == 0 {
				f = extraFault(rng, k, spec)
			} else {
				f = randomFault(rng, k, spec)
			}
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

// The same property for the whole-tunnel replacement: from a safe state with
// some faults in it, a replacement between random tunnels under random
// request failures, unstable and unreadable snapshots, never lets the policy
// model see an escape at any instant (the live tunnel addresses being the only
// return-path addresses it protects), and once the kernel cooperates the new
// tunnel comes up with the contract verified: by recovery after a failure
// that removed the link, by the caller's retry after one that could not.
func TestNoFailureDuringAReplacementOpensAProtectedClass(t *testing.T) {
	rng := rand.New(rand.NewSource(20261119))
	pool := addrs(tunnel4, tunnel6, "203.0.113.5", "2001:db8:3::9")
	pick := func() []netip.Addr {
		var out []netip.Addr
		for _, a := range pool {
			if rng.Intn(2) == 0 {
				out = append(out, a)
			}
		}
		return out
	}
	var cases, failedCases, retried int
	for i := 0; i < draws(600); i++ {
		sc := tunnelScenario{name: fmt.Sprintf("case %d", i), old: pick(), next: pick()}
		h := newTunnelHarness(t, sc)
		spec := h.m.Expected()
		var faults []string
		for n := rng.Intn(3); n > 0; n-- {
			before := saveState(h.k)
			f := randomFault(rng, h.k, spec)
			for _, fam := range families {
				sortRules(h.k.rules[fam])
			}
			if len(h.k.escapes(spec)) > 0 {
				before.restore(h.k)
				continue
			}
			faults = append(faults, f)
		}
		if rng.Intn(5) == 0 {
			// The old tunnel was lost before the replacement.
			_ = h.k.delTunnelLink("mullvad")
			faults = append(faults, "tunnel lost")
		}
		cases++
		rate := []float64{0, 0.1, 0.3, 0.7}[rng.Intn(4)]
		h.k.fail = func(string) error {
			if rng.Float64() < rate {
				return []error{syscall.ENOMEM, syscall.EIO, syscall.EBUSY}[rng.Intn(3)]
			}
			return nil
		}
		unstableRate := []float64{0, 0.2, 0.5}[rng.Intn(3)]
		h.k.unstableFn = func(int) bool { return rng.Float64() < unstableRate }
		if rng.Intn(4) == 0 {
			h.k.takeFail = func(int) error {
				if rng.Float64() < 0.2 {
					return errors.New("the dump failed")
				}
				return nil
			}
		}
		err := h.replace()
		h.k.hook = nil
		h.k.fail, h.k.unstableFn, h.k.takeFail = nil, nil, nil
		if h.violation != "" {
			t.Fatalf("%s %v -> %v, faults %v, rate %v, unstable %v: %s\n%v", sc.name, sc.old, sc.next, faults, rate, unstableRate, h.violation, h.k.log)
		}
		if err == nil {
			h.newTunnelChecks(sc.name, false)
			continue
		}
		failedCases++
		h.k.mu.Lock()
		hasLink := h.k.hasLink("mullvad")
		h.k.mu.Unlock()
		h.k.hook = h.observe
		if hasLink {
			retried++
			if err := h.m.ReplaceTunnel(context.Background(), h.change()); err != nil {
				t.Fatalf("%s %v -> %v, faults %v: the retry failed: %v", sc.name, sc.old, sc.next, faults, err)
			}
		} else {
			if res, err := h.m.ReconcileNow(context.Background(), "event"); err != nil || !res.ContractHolds {
				t.Fatalf("%s: the pass after the failure: %v %+v", sc.name, err, res)
			}
			if err := h.k.newTunnelLink("mullvad", 51821, sc.next); err != nil {
				t.Fatal(err)
			}
			if res, err := h.m.ReconcileNow(context.Background(), "tunnel up"); err != nil || !res.Verified {
				t.Fatalf("%s %v -> %v, faults %v: recovery did not verify: %v %+v", sc.name, sc.old, sc.next, faults, err, res)
			}
		}
		h.k.hook = nil
		h.newTunnelChecks(sc.name+" after recovery", false)
	}
	t.Logf("%d replacements, %d failed (%d retried by the caller, the rest recovered)", cases, failedCases, retried)
}
