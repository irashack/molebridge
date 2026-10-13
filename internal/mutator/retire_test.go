package mutator

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// The documentation range stands in for the provider's addresses.
const (
	piaA = "203.0.113.11"
	piaB = "203.0.113.12"
)

func piaSpec() contract.Spec {
	return contract.Spec{Config: nativeConfig(), LeaveReturnPath: map[rtnl.Family]bool{rtnl.V4: true, rtnl.V6: true}}
}

func pairOf(k *fakeKernel) (sources []string) {
	for _, r := range k.rules[4] {
		if r.Priority == 94 || r.Priority == 98 {
			sources = append(sources, r.String())
		}
	}
	return
}

func countPairs(k *fakeKernel) int { return len(pairOf(k)) }

// registered is a PIA exit that registered address a: the address on the
// tunnel, its pair, installed by the address transaction.
func registered(t *testing.T, a string) (*Mutator, *fakeKernel) {
	t.Helper()
	k := newFakeKernel()
	spec := piaSpec()
	k.installNative(spec, true)
	m := start(t, k, spec)
	addr := netip.MustParseAddr(a)
	err := m.ChangeReturnPath(context.Background(), rtnl.V4, netip.Addr{}, addr, func(tx *Tx) error {
		k.setAddr(rtnl.V4, spec.Config.ExitIf, addr, true)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if countPairs(k) != 2 {
		t.Fatalf("the registration left %v", pairOf(k))
	}
	return m, k
}

// losePIATunnel is `ip link del` and the worker's recreation: the interface is
// back, up, with its default route in the exit table, and no address.
func losePIATunnel(k *fakeKernel, spec contract.Spec) {
	exit := spec.Config.ExitIf
	k.mu.Lock()
	var links []rtnl.Link
	for _, l := range k.links {
		if l.Name != exit {
			links = append(links, l)
		}
	}
	k.links = links
	k.addrs[4] = nil
	var routes []rtnl.Route
	for _, r := range k.routes[4] {
		if r.Type == rtnl.RTNUnreachable {
			routes = append(routes, r)
		}
	}
	k.routes[4] = routes
	k.mu.Unlock()
	k.addLink(exit)
	k.routes[4] = append(k.routes[4], contract.TunnelRoute(4, spec.Config.Table, k.linkIndex(exit)))
}

// The reproduction of the live defect. The provider (as 0.7.0's Python did)
// deletes the pair of an address the tunnel no longer has, directly; the owner
// still expects that address and puts the pair back, on every pass: the two
// fight for ever. This is why the retirement has to be the owner's job.
func TestWithoutARetirementTheOwnerAndTheProviderFight(t *testing.T) {
	m, k := registered(t, piaA)
	losePIATunnel(k, piaSpec())
	ctx := context.Background()
	mark := k.mutations
	for i := 0; i < 5; i++ {
		// the provider's tick: delete the stray pair by source
		_ = k.DelRulePriority(4, 94)
		_ = k.DelRulePriority(4, 98)
		if _, err := m.ReconcileNow(ctx, "tick"); err != nil {
			t.Fatal(err)
		}
	}
	if k.mutations-mark < 10 {
		t.Fatalf("expected the fight to show as repeated mutations, got %d", k.mutations-mark)
	}
}

func TestRetiringALostAddressEndsTheFight(t *testing.T) {
	m, k := registered(t, piaA)
	spec := piaSpec()
	losePIATunnel(k, spec)
	ctx := context.Background()
	addr := netip.MustParseAddr(piaA)

	if err := m.RetireReturnPath(ctx, rtnl.V4, addr); err != nil {
		t.Fatalf("%v\n%v", err, k.log)
	}
	if n := countPairs(k); n != 0 {
		t.Fatalf("the pair of a retired address is still there: %v", pairOf(k))
	}
	got := m.Expected()
	if len(got.ReturnPath[rtnl.V4]) != 0 || !got.LeaveReturnPath[rtnl.V4] {
		t.Fatalf("expected state after the retirement: %v leave=%v", got.ReturnPath[rtnl.V4], got.LeaveReturnPath[rtnl.V4])
	}
	// N ticks of the provider's reconcile (it asks again every tick) and of the
	// repairer: no mutation at all, no oscillation.
	mark := k.mutations
	for i := 0; i < 20; i++ {
		if err := m.RetireReturnPath(ctx, rtnl.V4, addr); err != nil {
			t.Fatalf("tick %d: %v", i, err)
		}
		res, err := m.ReconcileNow(ctx, "tick")
		if err != nil || !res.Verified {
			t.Fatalf("tick %d: %+v %v", i, res, err)
		}
	}
	if d := k.mutations - mark; d != 0 {
		t.Errorf("%d mutations over 20 ticks after the retirement: %v", d, k.log[len(k.log)-d:])
	}
	// The addressless exit is judged by the contract minus 94 and 98: with the
	// pair gone, a pass finds the contract whole and verifies it. (The strict
	// per-family status is checked against a real kernel in the drill.)
	if res, err := m.ReconcileNow(ctx, "intact"); err != nil || !res.Verified || res.Repaired {
		t.Errorf("not intact without an address: %+v %v", res, err)
	}
	// And the next registration installs its pair by the address transaction.
	next := netip.MustParseAddr(piaB)
	err := m.ChangeReturnPath(ctx, rtnl.V4, netip.Addr{}, next, func(tx *Tx) error {
		k.setAddr(rtnl.V4, spec.Config.ExitIf, next, true)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if countPairs(k) != 2 || len(m.Expected().ReturnPath[rtnl.V4]) != 1 || m.Expected().ReturnPath[rtnl.V4][0] != next {
		t.Errorf("after the new registration: %v expected %v", pairOf(k), m.Expected().ReturnPath[rtnl.V4])
	}
	if res, err := m.ReconcileNow(ctx, "after"); err != nil || !res.Verified || res.Repaired {
		t.Errorf("%+v %v", res, err)
	}
}

// A live address is never retired: its pair and its protection stay.
func TestALiveAddressIsNotRetired(t *testing.T) {
	m, k := registered(t, piaA)
	before := append([]string(nil), pairOf(k)...)
	mark := k.mutations
	err := m.RetireReturnPath(context.Background(), rtnl.V4, netip.MustParseAddr(piaA))
	if !errors.Is(err, ErrReturnPathLive) {
		t.Fatalf("%v", err)
	}
	if k.mutations != mark || len(pairOf(k)) != len(before) {
		t.Errorf("a live address's pair was touched: %v", k.log[mark:])
	}
	if got := m.Expected().ReturnPath[rtnl.V4]; len(got) != 1 {
		t.Errorf("expected %v", got)
	}
}

func TestAnAddressLiveOnAnyInterfaceIsNotRetired(t *testing.T) {
	m, k := registered(t, piaA)
	losePIATunnel(k, piaSpec())
	k.setAddr(rtnl.V4, "eth0", netip.MustParseAddr(piaA), true) // the address moved elsewhere
	if err := m.RetireReturnPath(context.Background(), rtnl.V4, netip.MustParseAddr(piaA)); !errors.Is(err, ErrReturnPathLive) {
		t.Fatalf("%v", err)
	}
	if countPairs(k) != 2 {
		t.Errorf("the pair of a live address went: %v", pairOf(k))
	}
}

// A snapshot the kernel could not hold still decides nothing: nothing is
// deleted, the caller retries.
func TestAnUnstableLookRetiresNothing(t *testing.T) {
	m, k := registered(t, piaA)
	losePIATunnel(k, piaSpec())
	k.unstable = true
	mark := k.mutations
	if err := m.RetireReturnPath(context.Background(), rtnl.V4, netip.MustParseAddr(piaA)); err == nil {
		t.Fatal("an unstable look must not retire")
	}
	if k.mutations != mark || countPairs(k) != 2 || len(m.Expected().ReturnPath[rtnl.V4]) != 1 {
		t.Errorf("state changed: %v", k.log[mark:])
	}
	k.unstable = false
	if err := m.RetireReturnPath(context.Background(), rtnl.V4, netip.MustParseAddr(piaA)); err != nil {
		t.Fatal(err)
	}
	if countPairs(k) != 0 {
		t.Errorf("%v", pairOf(k))
	}
}

// Retiring a dead address leaves every live one protected.
func TestRetiringOneAddressKeepsTheLiveOne(t *testing.T) {
	k := newFakeKernel()
	spec := piaSpec()
	k.installNative(spec, true)
	m := start(t, k, spec)
	a, b := netip.MustParseAddr(piaA), netip.MustParseAddr(piaB)
	ctx := context.Background()
	if err := m.ChangeReturnPath(ctx, rtnl.V4, netip.Addr{}, a, func(tx *Tx) error { k.setAddr(rtnl.V4, spec.Config.ExitIf, a, true); return nil }); err != nil {
		t.Fatal(err)
	}
	// An interrupted switch left both pairs and both expected.
	if err := m.ChangeReturnPath(ctx, rtnl.V4, a, b, func(tx *Tx) error {
		k.setAddr(rtnl.V4, spec.Config.ExitIf, b, true) // the new address went on, then the switch failed
		return errors.New("interrupted")
	}); err == nil {
		t.Fatal("the change should have failed")
	}
	if got := m.Expected().ReturnPath[rtnl.V4]; len(got) != 2 {
		t.Fatalf("an interrupted switch leaves both expected: %v", got)
	}
	k.setAddr(rtnl.V4, spec.Config.ExitIf, a, false)
	if err := m.RetireReturnPath(ctx, rtnl.V4, a); err != nil {
		t.Fatal(err)
	}
	for _, r := range k.rules[4] {
		if (r.Priority == 94 || r.Priority == 98) && r.Src.Addr() == a {
			t.Errorf("a retired address's rule is still there: %v", r)
		}
	}
	if got := m.Expected().ReturnPath[rtnl.V4]; len(got) != 1 || got[0] != b {
		t.Errorf("expected %v, want only the live %v", got, b)
	}
	if n := countPairs(k); n != 2 {
		t.Errorf("the live address lost its pair: %v", pairOf(k))
	}
	if res, err := m.ReconcileNow(ctx, "x"); err != nil || !res.Verified {
		t.Errorf("%+v %v", res, err)
	}
}

func TestRetiringWhatIsNotThereIsNothing(t *testing.T) {
	m, k := registered(t, piaA)
	mark := k.mutations
	if err := m.RetireReturnPath(context.Background(), rtnl.V4, netip.MustParseAddr(piaB)); err != nil {
		t.Fatal(err)
	}
	if k.mutations != mark {
		t.Errorf("%v", k.log[mark:])
	}
	if err := m.RetireReturnPath(context.Background(), rtnl.V4, netip.MustParseAddr("2001:db8::1")); err == nil {
		t.Error("an address of the wrong family")
	}
}

// A refused deletion changes nothing and is not a fight: the expectation stays
// and the repairer has nothing to undo.
func TestARefusedRetirementLeavesTheExpectationAlone(t *testing.T) {
	m, k := registered(t, piaA)
	losePIATunnel(k, piaSpec())
	k.fail = func(op string) error {
		if op == "del 2 94" || op == "del 2 98" {
			return errors.New("refused by the kernel")
		}
		return nil
	}
	if err := m.RetireReturnPath(context.Background(), rtnl.V4, netip.MustParseAddr(piaA)); err == nil {
		t.Fatal("the failure must be reported")
	}
	if len(m.Expected().ReturnPath[rtnl.V4]) != 1 {
		t.Errorf("the expectation went although the pair did not: %v", m.Expected().ReturnPath[rtnl.V4])
	}
	k.fail = nil
	if err := m.RetireReturnPath(context.Background(), rtnl.V4, netip.MustParseAddr(piaA)); err != nil {
		t.Fatalf("the next tick: %v", err)
	}
	if countPairs(k) != 0 {
		t.Errorf("%v", pairOf(k))
	}
}

// The gluetun backend tracks the tunnel's own address on every pass: when
// gluetun recreates its interface without one (or with another), the old
// address's rule 94 goes and nothing oscillates.
func TestGluetunRetiresTheOldAddressesRule94(t *testing.T) {
	k := gluetunKernel()
	m := start(t, k, glSpec())
	ctx := context.Background()
	if err := m.Install(ctx); err != nil {
		t.Fatal(err)
	}
	sources := func() (out []netip.Addr) {
		for _, r := range k.rules[4] {
			if r.Priority == 94 {
				out = append(out, r.Src.Addr())
			}
		}
		return
	}
	if len(sources()) != 1 {
		t.Fatalf("%v", sources())
	}
	// Recreated with no address yet.
	k.addrs[4] = nil
	if res, err := m.ReconcileNow(ctx, "x"); err != nil || !res.Verified {
		t.Fatalf("%+v %v", res, err)
	}
	if len(sources()) != 0 {
		t.Errorf("the lost address kept its rule 94: %v", sources())
	}
	mark := k.mutations
	for i := 0; i < 10; i++ {
		if res, err := m.ReconcileNow(ctx, "tick"); err != nil || !res.Verified {
			t.Fatalf("%+v %v", res, err)
		}
	}
	if k.mutations != mark {
		t.Errorf("oscillation without an address: %v", k.log[mark:])
	}
	// Then another address.
	k.addrs[4] = []rtnl.Addr{{Family: 4, Index: 7, Local: netip.MustParsePrefix("10.64.0.77/32")}}
	if res, err := m.ReconcileNow(ctx, "x"); err != nil || !res.Verified {
		t.Fatalf("%+v %v", res, err)
	}
	if s := sources(); len(s) != 1 || s[0] != netip.MustParseAddr("10.64.0.77") {
		t.Errorf("%v", s)
	}
	mark = k.mutations
	for i := 0; i < 10; i++ {
		_, _ = m.ReconcileNow(ctx, "tick")
	}
	if k.mutations != mark {
		t.Errorf("oscillation: %v", k.log[mark:])
	}
}
