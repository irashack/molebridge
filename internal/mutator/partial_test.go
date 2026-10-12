package mutator

// Fail-closed under partial failure. A multi-step transaction (PIA's address
// change) is failed at every step in turn: each micro-step of the address
// change, each request the transaction makes (once, and from then on), each
// snapshot it takes. After every kernel change and every address change the
// exit's own ICMP errors from every live tunnel address are followed through
// the rules and must never reach the host's route; and what the transaction
// leaves behind is judged from the kernel's addresses, not from what the
// callback was supposed to do.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

type piaStep struct {
	name string
	do   func(k *fakeKernel)
}

type piaScenario struct {
	name      string
	old, next netip.Addr
	// leave: the PIA initial state, rules 94 and 98 left to the transaction.
	leave bool
	steps []piaStep
}

func piaScenarios() []piaScenario {
	a11, a12 := netip.MustParseAddr("203.0.113.11"), netip.MustParseAddr("203.0.113.12")
	add := func(a netip.Addr) piaStep {
		return piaStep{"add " + a.String(), func(k *fakeKernel) { k.setAddr(rtnl.V4, "mullvad", a, true) }}
	}
	del := func(a netip.Addr) piaStep {
		return piaStep{"remove " + a.String(), func(k *fakeKernel) { k.setAddr(rtnl.V4, "mullvad", a, false) }}
	}
	dropRoutes := piaStep{"the kernel drops the routes through the interface", func(k *fakeKernel) {
		k.mu.Lock()
		var keep []rtnl.Route
		for _, r := range k.routes[rtnl.V4] {
			if r.Type == rtnl.RTNUnreachable {
				keep = append(keep, r)
			}
		}
		k.routes[rtnl.V4] = keep
		k.mu.Unlock()
	}}
	return []piaScenario{
		{name: "a new address replaces the old one", old: a11, next: a12, steps: []piaStep{add(a12), del(a11), dropRoutes}},
		{name: "the old address goes first", old: a11, next: a12, steps: []piaStep{del(a11), add(a12), dropRoutes}},
		{name: "a first registration", next: a12, leave: true, steps: []piaStep{add(a12), dropRoutes}},
		{name: "the same address again", old: a11, next: a11, steps: nil},
		{name: "both addresses at once", old: a11, next: a12, steps: []piaStep{add(a12)}},
	}
}

// harness builds a healthy PIA namespace with the old address live and
// protected.
type piaHarness struct {
	k    *fakeKernel
	m    *Mutator
	spec contract.Spec
	sc   piaScenario
	t    *testing.T
	// observed: the first violation seen at an observation point.
	violation string
}

func newPIAHarness(t *testing.T, sc piaScenario) *piaHarness {
	h := &piaHarness{t: t, sc: sc, k: newFakeKernel()}
	h.spec = contract.Spec{Config: nativeConfig()}
	if sc.leave {
		h.spec.LeaveReturnPath = map[rtnl.Family]bool{rtnl.V4: true, rtnl.V6: true}
	} else {
		h.spec.ReturnPath = map[rtnl.Family][]netip.Addr{rtnl.V4: {sc.old}}
	}
	h.k.installNative(h.spec, true)
	if sc.old.IsValid() {
		h.k.setAddr(rtnl.V4, "mullvad", sc.old, true)
		if sc.leave {
			// The pair a transaction before left, uncompared.
			pair := h.spec.Clone()
			pair.LeaveReturnPath = map[rtnl.Family]bool{}
			pair.ReturnPath = map[rtnl.Family][]netip.Addr{rtnl.V4: {sc.old}}
			for _, r := range pair.Rules(rtnl.V4) {
				if r.Priority == contract.PrioReturnPath || r.Priority == contract.PrioBackstop {
					h.k.rules[rtnl.V4] = append(h.k.rules[rtnl.V4], r)
				}
			}
			sortRules(h.k.rules[rtnl.V4])
		}
	}
	h.m = start(t, h.k, h.spec)
	return h
}

func sortRules(rs []rtnl.Rule) {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && rs[j-1].Priority > rs[j].Priority; j-- {
			rs[j-1], rs[j] = rs[j], rs[j-1]
		}
	}
}

// observe checks every live tunnel address.
func (h *piaHarness) observe(where string) {
	for _, a := range h.k.liveAddrs(rtnl.V4, "mullvad") {
		if h.k.icmpWhere(rtnl.V4, a, 51821) == escaped && h.violation == "" {
			h.violation = fmt.Sprintf("an ICMP error from %s reaches the host route after %s", a, where)
		}
	}
}

func (h *piaHarness) run(failStep int, failMutation int, persistent bool, failTake int) (steps int, err error) {
	h.k.hook = h.observe
	h.k.mutations = 0
	h.k.takes = 0
	h.k.fail = func(op string) error {
		if failMutation > 0 && (h.k.mutations == failMutation || persistent && h.k.mutations > failMutation) {
			return syscall.EIO
		}
		return nil
	}
	h.k.takeFail = func(n int) error {
		if failTake > 0 && n >= failTake {
			return errors.New("injected snapshot failure")
		}
		return nil
	}
	h.observe("start")
	err = h.m.ChangeReturnPath(context.Background(), rtnl.V4, h.sc.old, h.sc.next, func(tx *Tx) error {
		for i, st := range h.sc.steps {
			if i == failStep {
				return fmt.Errorf("injected failure before %q", st.name)
			}
			st.do(h.k)
			steps++
			h.observe(st.name)
		}
		if failStep == len(h.sc.steps) {
			return errors.New("injected failure after the last step")
		}
		return nil
	})
	return steps, err
}

// finalChecks: whatever the transaction returned, the kernel protects every
// live address, and a success is the completed change.
func (h *piaHarness) finalChecks(label string, err error) {
	t := h.t
	t.Helper()
	h.k.hook = nil
	h.k.fail, h.k.takeFail = nil, nil
	if h.violation != "" {
		t.Errorf("%s: %s", label, h.violation)
	}
	rules := h.k.rules[rtnl.V4]
	for _, a := range h.k.liveAddrs(rtnl.V4, "mullvad") {
		if h.k.icmpWhere(rtnl.V4, a, 51821) == escaped {
			t.Errorf("%s: live address %s is unprotected after the transaction (error: %v)", label, a, err)
		}
		if err != nil {
			continue
		}
		has94, has98 := false, false
		for _, r := range rules {
			if r.Src.IsValid() && r.Src.Addr() == a {
				has94 = has94 || r.Priority == 94
				has98 = has98 || r.Priority == 98
			}
		}
		if !has94 || !has98 {
			t.Errorf("%s: live address %s lacks its pair (94 %v, 98 %v) after a successful transaction", label, a, has94, has98)
		}
	}
	if err == nil {
		// Success is the whole change: the new address's pair is expected, the
		// old pair is gone with the old address.
		exp := h.m.Expected()
		if !containsAddr(exp.ReturnPath[rtnl.V4], h.sc.next) || exp.LeaveReturnPath[rtnl.V4] {
			t.Errorf("%s: expected state %+v", label, exp.ReturnPath)
		}
		if h.sc.old.IsValid() && h.sc.old != h.sc.next && !containsAddr(h.k.liveAddrs(rtnl.V4, "mullvad"), h.sc.old) {
			for _, r := range rules {
				if r.Src.IsValid() && r.Src.Addr() == h.sc.old {
					t.Errorf("%s: the old pair stayed after the old address left: %v", label, r)
				}
			}
		}
	}
}

func TestEveryFailurePointOfAnAddressChangeLeavesLiveAddressesProtected(t *testing.T) {
	for _, sc := range piaScenarios() {
		sc := sc
		// How many requests and snapshots a clean run makes.
		clean := newPIAHarness(t, sc)
		if _, err := clean.run(-1, 0, false, 0); err != nil {
			t.Fatalf("%s: a clean run failed: %v", sc.name, err)
		}
		clean.finalChecks(sc.name+" (clean)", nil)
		mutations, takes := clean.k.mutations, clean.k.takes
		t.Logf("%s: %d requests, %d snapshots, %d steps", sc.name, mutations, takes, len(sc.steps))

		for step := 0; step <= len(sc.steps); step++ {
			h := newPIAHarness(t, sc)
			_, err := h.run(step, 0, false, 0)
			h.finalChecks(fmt.Sprintf("%s, callback fails at step %d", sc.name, step), err)
			if step < len(sc.steps) || len(sc.steps) > 0 {
				if err == nil {
					t.Errorf("%s: an injected callback failure at step %d was not reported", sc.name, step)
				}
			}
		}
		for n := 1; n <= mutations+2; n++ {
			for _, persistent := range []bool{false, true} {
				h := newPIAHarness(t, sc)
				_, err := h.run(-1, n, persistent, 0)
				h.finalChecks(fmt.Sprintf("%s, request %d fails (persistent=%v)", sc.name, n, persistent), err)
				// And the same together with a callback failure.
				for step := 0; step <= len(sc.steps); step++ {
					h := newPIAHarness(t, sc)
					_, err := h.run(step, n, persistent, 0)
					h.finalChecks(fmt.Sprintf("%s, request %d fails (persistent=%v) and the callback at step %d", sc.name, n, persistent, step), err)
				}
			}
		}
		for n := 1; n <= takes+1; n++ {
			h := newPIAHarness(t, sc)
			_, err := h.run(-1, 0, false, n)
			h.finalChecks(fmt.Sprintf("%s, snapshots fail from the %d-th", sc.name, n), err)
			for step := 0; step <= len(sc.steps); step++ {
				h := newPIAHarness(t, sc)
				_, err := h.run(step, 0, false, n)
				h.finalChecks(fmt.Sprintf("%s, snapshots fail from the %d-th and the callback at step %d", sc.name, n, step), err)
			}
		}
	}
}

// old == next must not take anything away, not even for a moment.
func TestTheSameAddressNeverLosesItsPair(t *testing.T) {
	sc := piaScenarios()[3]
	h := newPIAHarness(t, sc)
	var removals []string
	h.k.hook = func(op string) {
		if strings.HasPrefix(op, "del ") || strings.HasPrefix(op, "delprio") {
			removals = append(removals, op)
		}
		h.observe(op)
	}
	for _, failure := range []error{nil, errors.New("the registration failed")} {
		err := h.m.ChangeReturnPath(context.Background(), rtnl.V4, sc.old, sc.next, func(tx *Tx) error { return failure })
		if (err == nil) != (failure == nil) {
			t.Fatalf("%v for %v", err, failure)
		}
	}
	if len(removals) != 0 || h.violation != "" {
		t.Fatalf("removals %v, %s", removals, h.violation)
	}
}

// The failure the review reproduced: the address was added, a later step
// failed, and the callback's error reached the transaction.
func TestAnAddressThatArrivedKeepsItsPairWhenALaterStepFails(t *testing.T) {
	sc := piaScenarios()[0]
	h := newPIAHarness(t, sc)
	err := h.m.ChangeReturnPath(context.Background(), rtnl.V4, sc.old, sc.next, func(tx *Tx) error {
		h.k.setAddr(rtnl.V4, "mullvad", sc.next, true)
		return errors.New("setting the peer failed")
	})
	if err == nil {
		t.Fatal("no error")
	}
	for _, a := range []netip.Addr{sc.old, sc.next} {
		if h.k.icmpWhere(rtnl.V4, a, 51821) == escaped {
			t.Errorf("%s is unprotected", a)
		}
	}
	if !h.m.Ready() && h.m.LastPass().Err != nil && strings.Contains(h.m.LastPass().Err.Error(), "never") {
		t.Log("not ready")
	}
}

// A rebuild whose re-add fails keeps its copies, which are what protects.
func TestARebuildThatCannotRestoreKeepsItsCopies(t *testing.T) {
	m, k, spec := healthyNamespace(t, func(o *Options) { o.GuardRepairs = false })
	for i, r := range k.rules[4] {
		if r.Priority == 95 {
			k.rules[4][i].IifName = "" // a subset: rebuilt
		}
	}
	_ = k.DelRulePriority(4, 97) // nothing else holds the overlay
	k.fail = func(op string) error {
		if op == "add 2 95" {
			return syscall.EIO // the plain add and the rebuild's re-add both fail
		}
		return nil
	}
	guardLeaks(t, k, spec)
	_, _ = m.ReconcileNow(context.Background(), "x")
	if leaking(k, spec) {
		t.Fatal("leaks")
	}
	copyKept := false
	for _, r := range k.rules[4] {
		if r.Priority == 94 && r.IifName == "wt0" {
			copyKept = true
		}
	}
	if !copyKept {
		t.Errorf("the copy at priority 94 was removed while rule 95 could not be restored: %v", k.ruleSummary(4))
	}
	// Once the kernel cooperates, the missing rule goes back before the copy,
	// which is then a stray, comes out.
	k.fail = nil
	repairs(t, m, k, spec)
}
