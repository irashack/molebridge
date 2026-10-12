package mutator

// The mutation owner against a fake kernel. Ported from
// tools/test_host_and_routing.py (the routing-initialization tests of
// routing/10-exit-routing --install: test_routing_initialization_blocks_before_replacing_rules,
// test_routing_rerun_keeps_the_local_delivery_rule,
// test_routing_installs_the_exact_local_delivery_rule,
// test_failed_local_delivery_rule_keeps_the_kernel_rule,
// test_ipv4_only_tunnel_gets_no_ipv6_return_path_rule,
// test_failed_routing_init_leaves_guard_and_never_marks_ready) and from the
// reconcile rows of tools/check-routing.sh.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

const (
	tunnel4 = "203.0.113.1"
	tunnel6 = "2001:db8:3::1"
)

func nativeConfig() contract.Config {
	return contract.Config{Kind: contract.Overlay, Backend: contract.Native, Overlay: netip.MustParsePrefix("192.0.2.0/24"),
		Overlay6: netip.MustParsePrefix("2001:db8:1::/64"), OverlayIf: "wt0", ExitIf: "mullvad", Table: 51821}
}

func nativeSpec() contract.Spec {
	return contract.Spec{Config: nativeConfig(), ReturnPath: map[rtnl.Family][]netip.Addr{
		rtnl.V4: {netip.MustParseAddr(tunnel4)}, rtnl.V6: {netip.MustParseAddr(tunnel6)}}}
}

type logCollector struct {
	mu    sync.Mutex
	lines []string
}

func (l *logCollector) logf(format string, a ...any) {
	l.mu.Lock()
	l.lines = append(l.lines, fmt.Sprintf(format, a...))
	l.mu.Unlock()
}

func start(t *testing.T, k *fakeKernel, spec contract.Spec, mod ...func(*Options)) *Mutator {
	t.Helper()
	return startWith(t, k, spec, mod...)
}

func startWith(t *testing.T, k Kernel, spec contract.Spec, mod ...func(*Options)) *Mutator {
	t.Helper()
	o := Options{Kernel: k, Spec: spec, GuardRepairs: !spec.Config.IsGluetun(), OpTimeout: 2 * time.Second, IdleStep: 10 * time.Millisecond}
	for _, f := range mod {
		f(&o)
	}
	m := New(o)
	m.Start()
	t.Cleanup(m.Close)
	return m
}

// guardLeaks fails the test if the namespace leaks after it has once not
// leaked: no repair step may open what it found closed.
func guardLeaks(t *testing.T, k *fakeKernel, spec contract.Spec) *atomic.Bool {
	t.Helper()
	var wasSafe atomic.Bool
	check := func(op string) {
		leaking := false
		for _, f := range families {
			if k.leaks(f, spec.Config.OverlayIf, spec.Config.Table) {
				leaking = true
			}
		}
		if !leaking {
			wasSafe.Store(true)
		} else if wasSafe.Load() {
			t.Errorf("the namespace leaked after %q", op)
		}
	}
	k.hook = check
	check("start")
	return &wasSafe
}

func leaking(k *fakeKernel, spec contract.Spec) bool {
	for _, f := range families {
		if k.leaks(f, spec.Config.OverlayIf, spec.Config.Table) {
			return true
		}
	}
	return false
}

func priorities(k *fakeKernel, f rtnl.Family) map[uint32]int {
	out := map[uint32]int{}
	for _, p := range k.prioritiesPresent(f) {
		out[p] = 1
	}
	return out
}

func index(log []string, op string) int {
	for i, l := range log {
		if l == op {
			return i
		}
	}
	return -1
}

// expectHealthy checks the kernel against the expected rules, exactly.
func expectHealthy(t *testing.T, k *fakeKernel, spec contract.Spec) {
	t.Helper()
	snap, _ := k.Take(spec.Interest())
	for _, f := range families {
		p := spec.PlanFamily(snap, f, contract.PlanInput{})
		if !p.Healthy() {
			t.Errorf("%s still unhealthy: rules %v routes %v problems %v\n%s", f, p.Rules, p.Routes, p.Problems, strings.Join(k.ruleSummary(f), "\n"))
		}
		if _, ok := priorities(k, f)[contract.PrioTempGuard]; ok {
			t.Errorf("%s: the temporary guard is still in", f)
		}
	}
}

// ---- Install (tools/test_host_and_routing.py's routing-initialization tests) ----

func TestInstallBlocksBeforeReplacingRules(t *testing.T) { // test_routing_initialization_blocks_before_replacing_rules
	k := newFakeKernel()
	spec := nativeSpec()
	guardLeaks(t, k, spec)
	m := start(t, k, spec)
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	expectHealthy(t, k, spec)
	if leaking(k, spec) {
		t.Fatal("leaks after install")
	}
	for _, f := range families {
		af := f.AF()
		at := func(op string) int {
			i := index(k.log, fmt.Sprintf(op, af))
			if i < 0 {
				t.Fatalf("%s: %q never happened in %v", f, op, k.log)
			}
			return i
		}
		local := at("add %d 1")
		kernelRule := at("del %d 0")
		guard := at("add %d 80")
		fallback := at("route replace %d 51821")
		first := at("add %d 90")
		last := at("add %d 97")
		unblock := at("del %d 80")
		// The local-delivery rule goes in before the kernel's rule 0 comes out.
		if !(local < kernelRule) {
			t.Errorf("%s: rule 1 at %d, rule 0 removed at %d", f, local, kernelRule)
		}
		// The guard and the fallback are in before any of rules 90-97.
		if !(guard < first && fallback < first && guard < last && fallback < last) {
			t.Errorf("%s: guard %d fallback %d first %d last %d", f, guard, fallback, first, last)
		}
		if !(last < unblock && first < unblock) {
			t.Errorf("%s: the guard came out at %d before the rules (%d, %d)", f, unblock, first, last)
		}
		// Terminal rules before the rules that route.
		if !(at("add %d 97") < at("add %d 95")) {
			t.Errorf("%s: rule 97 must precede rule 95", f)
		}
	}
	// No temporary guard remains and nothing is left of the kernel's rule 0.
	for _, f := range families {
		if _, ok := priorities(k, f)[0]; ok {
			t.Errorf("%s: kernel rule 0 still present", f)
		}
	}
	if st := m.LastPass(); !st.Verified || !m.Ready() {
		t.Errorf("%+v", st)
	}
}

func TestInstallOfAnInstalledNamespaceChangesNothing(t *testing.T) { // test_routing_rerun_keeps_the_local_delivery_rule
	k := newFakeKernel()
	spec := nativeSpec()
	k.installNative(spec, true)
	m := start(t, k, spec)
	before := len(k.log)
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(k.log) != before {
		t.Fatalf("a rerun changed the kernel: %v", k.log[before:])
	}
}

func TestInstallKeepsTheExactLocalDeliveryRuleAndReplacesInexactOnes(t *testing.T) { // test_routing_installs_the_exact_local_delivery_rule
	for name, wrong := range map[string]rtnl.Rule{
		"kernel rule 0 only": {},
		"another interface":  {Family: rtnl.V4, Priority: 1, Action: rtnl.FRActToTbl, Table: rtnl.TableLocal, Flags: rtnl.FIBRuleInvert, IifName: "wt1"},
		"extra fwmark": {Family: rtnl.V4, Priority: 1, Action: rtnl.FRActToTbl, Table: rtnl.TableLocal, Flags: rtnl.FIBRuleInvert, IifName: "wt0",
			FwMark: rtnl.Some(uint32(1)), FwMask: rtnl.Some(uint32(0xffffffff))},
		"not inverted": {Family: rtnl.V4, Priority: 1, Action: rtnl.FRActToTbl, Table: rtnl.TableLocal, IifName: "wt0"},
	} {
		k := newFakeKernel()
		if wrong.Priority != 0 {
			k.rules[4] = append([]rtnl.Rule{k.rules[4][0], wrong}, k.rules[4][1:]...)
		}
		spec := nativeSpec()
		m := start(t, k, spec)
		if err := m.Install(context.Background()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		expectHealthy(t, k, spec)
	}
}

func TestFailedLocalDeliveryRuleKeepsTheKernelRule(t *testing.T) { // test_failed_local_delivery_rule_keeps_the_kernel_rule
	k := newFakeKernel()
	k.fail = func(op string) error {
		if op == "add 2 1" {
			return syscall.EPERM
		}
		return nil
	}
	spec := nativeSpec()
	m := start(t, k, spec)
	err := m.Install(context.Background())
	if err == nil {
		t.Fatal("install succeeded")
	}
	for _, op := range k.log {
		if strings.HasPrefix(op, "del ") || strings.HasPrefix(op, "delprio") {
			t.Errorf("%q: nothing may be removed when rule 1 cannot be installed", op)
		}
	}
	if _, ok := priorities(k, rtnl.V4)[0]; !ok {
		t.Error("kernel rule 0 was removed")
	}
	if m.Ready() {
		t.Error("ready")
	}
}

func TestIPv4OnlyTunnelGetsNoIPv6ReturnPathRule(t *testing.T) { // test_ipv4_only_tunnel_gets_no_ipv6_return_path_rule
	k := newFakeKernel()
	spec := nativeSpec()
	spec.ReturnPath = map[rtnl.Family][]netip.Addr{rtnl.V4: {netip.MustParseAddr(tunnel4)}}
	m := start(t, k, spec)
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := priorities(k, rtnl.V6)[94]; ok {
		t.Error("IPv6 return-path rule installed")
	}
	if _, ok := priorities(k, rtnl.V4)[94]; !ok {
		t.Error("IPv4 return-path rule missing")
	}
	expectHealthy(t, k, spec)
}

func TestAddresslessConfigLeavesRules94And98(t *testing.T) { // PIA's initialization
	k := newFakeKernel()
	spec := contract.Spec{Config: nativeConfig(), LeaveReturnPath: map[rtnl.Family]bool{rtnl.V4: true, rtnl.V6: true}}
	m := start(t, k, spec)
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		p := priorities(k, f)
		if _, ok := p[94]; ok {
			t.Errorf("%s: 94 installed", f)
		}
		if _, ok := p[98]; ok {
			t.Errorf("%s: 98 installed", f)
		}
	}
}

func TestFailedInstallLeavesTheGuardAndNeverReady(t *testing.T) { // test_failed_routing_init_leaves_guard_and_never_marks_ready
	k := newFakeKernel()
	k.fail = func(op string) error {
		if op == "add 10 95" {
			return syscall.EPERM
		}
		return nil
	}
	spec := nativeSpec()
	m := start(t, k, spec)
	err := m.Install(context.Background())
	var ie *InstallError
	if !errors.As(err, &ie) {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(err.Error(), "the temporary guard (priority 80) stays") {
		t.Errorf("%v", err)
	}
	for _, f := range families {
		if _, ok := priorities(k, f)[80]; !ok {
			t.Errorf("%s: the guard is gone", f)
		}
	}
	if m.Ready() {
		t.Error("ready")
	}
	// The overlay stays blocked in both families.
	if leaking(k, spec) {
		t.Error("the namespace leaks with the guard in")
	}
	// A later pass that finds everything right takes the guard out.
	k.fail = nil
	res, err := m.ReconcileNow(context.Background(), "later")
	if err != nil || !res.Verified {
		t.Fatalf("%+v %v", res, err)
	}
	expectHealthy(t, k, spec)
}

func TestSidecarHasNoContract(t *testing.T) {
	k := newFakeKernel()
	spec := contract.Spec{Config: contract.Config{Kind: contract.Sidecar, Backend: contract.Gluetun, ExitIf: "wg0"}}
	m := start(t, k, spec)
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	res, err := m.ReconcileNow(context.Background(), "x")
	if err != nil || !res.Verified || len(k.log) != 0 {
		t.Fatalf("%+v %v %v", res, err, k.log)
	}
}

// ---- repair: check-routing.sh's drift table ----

func healthyNamespace(t *testing.T, mod ...func(*Options)) (*Mutator, *fakeKernel, contract.Spec) {
	t.Helper()
	k := newFakeKernel()
	spec := nativeSpec()
	k.installNative(spec, true)
	m := start(t, k, spec, mod...)
	return m, k, spec
}

func repairs(t *testing.T, m *Mutator, k *fakeKernel, spec contract.Spec) PassResult {
	t.Helper()
	res, err := m.ReconcileNow(context.Background(), "test")
	if err != nil {
		t.Fatalf("%v (%+v)", err, res)
	}
	if !res.Verified {
		t.Fatalf("%+v", res)
	}
	expectHealthy(t, k, spec)
	return res
}

func TestSingleDeletionIsRepairedWithoutALeak(t *testing.T) { // each of rules 1, 90, 95, 96, 97 and 98 deleted
	for _, f := range families {
		for _, p := range []uint32{1, 90, 94, 95, 96, 97, 98} {
			m, k, spec := healthyNamespace(t)
			guardLeaks(t, k, spec)
			if err := k.DelRulePriority(f, p); err != nil {
				t.Fatal(err)
			}
			res := repairs(t, m, k, spec)
			if !res.Repaired {
				t.Errorf("%s %d: nothing repaired", f, p)
			}
			if len(k.log) == 0 {
				t.Fatal("no log")
			}
		}
	}
}

func TestDeletionOfBothTerminalRulesIsRepairedTerminalFirst(t *testing.T) {
	m, k, spec := healthyNamespace(t)
	for _, p := range []uint32{97, 95} {
		_ = k.DelRulePriority(rtnl.V4, p)
	}
	// 97 and 95 both gone: the overlay is no longer held.
	mark := len(k.log)
	repairs(t, m, k, spec)
	var seen []string
	for _, l := range k.log[mark:] {
		if strings.HasPrefix(l, "add 2 ") {
			seen = append(seen, l)
		}
	}
	// The guard first, then 97 before 95.
	if len(seen) < 3 || seen[0] != "add 2 80" || seen[1] != "add 2 97" || seen[2] != "add 2 95" {
		t.Errorf("%v", seen)
	}
}

func TestInsertedRulesAreRemoved(t *testing.T) { // inserted rules (lookup main at 50, lookup local at 0) and a foreign exit-table route
	m, k, spec := healthyNamespace(t)
	for _, f := range families {
		k.rules[f] = append([]rtnl.Rule{{Family: f, Priority: 0, Action: rtnl.FRActToTbl, Table: rtnl.TableLocal},
			{Family: f, Priority: 50, Action: rtnl.FRActToTbl, Table: rtnl.TableMain}}, k.rules[f]...)
	}
	k.routes[4] = append(k.routes[4], rtnl.Route{Family: 4, Dst: netip.MustParsePrefix("203.0.113.99/32"), Table: 51821,
		Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2))})
	if !leaking(k, spec) {
		t.Fatal("the fixture should leak")
	}
	guardLeaks(t, k, spec)
	res := repairs(t, m, k, spec)
	if !res.Repaired || leaking(k, spec) {
		t.Fatalf("%+v", res)
	}
	for _, f := range families {
		p := priorities(k, f)
		if _, ok := p[0]; ok {
			t.Errorf("%s: rule 0", f)
		}
		if _, ok := p[50]; ok {
			t.Errorf("%s: rule 50", f)
		}
	}
	if n := len(k.routes[4]); n != 2 {
		t.Errorf("exit table has %d routes", n)
	}
}

func TestWrongActionIsReplacedWithoutALeak(t *testing.T) {
	for _, p := range []uint32{97, 98, 95, 96, 90} {
		m, k, spec := healthyNamespace(t)
		guardLeaks(t, k, spec)
		for i, r := range k.rules[4] {
			if r.Priority != p {
				continue
			}
			if p == 97 || p == 98 {
				k.rules[4][i].Action = rtnl.FRActProhibit
			} else {
				k.rules[4][i].Action, k.rules[4][i].Table = rtnl.FRActUnreachable, 0
			}
		}
		repairs(t, m, k, spec)
	}
}

func TestExtraSelectorRuleIsRemovedAndTheExactOneNeverTouched(t *testing.T) {
	m, k, spec := healthyNamespace(t)
	guardLeaks(t, k, spec)
	k.rules[4] = append(k.rules[4], rtnl.Rule{Family: 4, Priority: 95, Action: rtnl.FRActToTbl, Table: 51821, IifName: "wt0",
		FwMark: rtnl.Some(uint32(5)), FwMask: rtnl.Some(uint32(0xffffffff))})
	mark := len(k.log)
	repairs(t, m, k, spec)
	for _, l := range k.log[mark:] {
		if l == "delprio 2 95" {
			t.Errorf("the exact rule 95 was rebuilt for an unrelated extra rule: %v", k.log[mark:])
		}
	}
}

func TestNarrowerSelectorsRuleIsRebuiltBehindACopy(t *testing.T) {
	// Rule 95 without its iif: its selectors are a subset of the expected
	// rule's, so deleting it by selectors would take the expected rule.
	m, k, spec := healthyNamespace(t)
	guardLeaks(t, k, spec)
	for i, r := range k.rules[4] {
		if r.Priority == 95 {
			k.rules[4][i].IifName = ""
		}
	}
	mark := len(k.log)
	repairs(t, m, k, spec)
	log := k.log[mark:]
	if index(log, "add 2 94") < 0 {
		t.Errorf("no copy at priority 94 in %v", log)
	}
}

func TestDuplicateRuleIsRebuilt(t *testing.T) {
	m, k, spec := healthyNamespace(t)
	guardLeaks(t, k, spec)
	k.rules[4] = append(k.rules[4], k.rules[4][4]) // a second rule at the same priority, same selectors
	_ = priorities
	repairs(t, m, k, spec)
}

func TestExitTableRepairs(t *testing.T) {
	cases := map[string]func(*fakeKernel){
		"tunnel route deleted": func(k *fakeKernel) { k.routes[4] = k.routes[4][:1] },
		"fallback deleted":     func(k *fakeKernel) { k.routes[4] = k.routes[4][1:] },
		"whole table flushed":  func(k *fakeKernel) { k.routes[4], k.routes[6] = nil, nil },
		"both families":        func(k *fakeKernel) { k.routes[4], k.routes[6] = k.routes[4][1:], k.routes[6][1:] },
		"default through a gw": func(k *fakeKernel) { k.routes[4][1].Gateway = netip.MustParseAddr("203.0.113.2") },
	}
	for name, fault := range cases {
		m, k, spec := healthyNamespace(t)
		fault(k)
		res := repairs(t, m, k, spec)
		if !res.Repaired {
			t.Errorf("%s: nothing repaired", name)
		}
	}
}

func TestTunnelLossAndRecreation(t *testing.T) {
	m, k, spec := healthyNamespace(t)
	// The tunnel interface goes away: its route goes with it, and nothing may
	// be left in the exit table beyond the fallback.
	k.links = k.links[:3]
	k.routes[4], k.routes[6] = k.routes[4][:1], k.routes[6][:1]
	repairs(t, m, k, spec)
	for _, f := range families {
		if len(k.routes[f]) != 1 || k.routes[f][0].Type != rtnl.RTNUnreachable {
			t.Errorf("%s: %+v", f, k.routes[f])
		}
	}
	// It comes back (a new bring-up) and the pass puts the default route in.
	k.addLink("mullvad")
	repairs(t, m, k, spec)
	for _, f := range families {
		if len(k.routes[f]) != 2 {
			t.Errorf("%s after recreation: %+v", f, k.routes[f])
		}
	}
	// Linkdown: the interface is administratively down; the route comes out.
	for i := range k.links {
		if k.links[i].Name == "mullvad" {
			k.links[i].Flags = 0
		}
	}
	repairs(t, m, k, spec)
	if len(k.routes[4]) != 1 {
		t.Errorf("a tunnel route with the interface down: %+v", k.routes[4])
	}
}

func TestAStrayGuardIsAdoptedAndRemovedOnceVerified(t *testing.T) { // a temporary guard left from an unverified pass comes out
	m, k, spec := healthyNamespace(t)
	for _, f := range families {
		g := guardRuleFor(spec, f)
		k.rules[f] = append(k.rules[f][:2:2], append([]rtnl.Rule{g}, k.rules[f][2:]...)...)
	}
	for i, r := range k.rules[4] {
		if r.Priority == 95 {
			k.rules[4] = append(k.rules[4][:i:i], k.rules[4][i+1:]...)
			break
		}
	}
	guardLeaks(t, k, spec)
	repairs(t, m, k, spec)
}

func guardRuleFor(spec contract.Spec, f rtnl.Family) rtnl.Rule { return guardRule(spec, f) }

func TestRepairNeverRemovesAnUnrelatedRuleOutsideTheRange(t *testing.T) {
	m, k, spec := healthyNamespace(t)
	other := rtnl.Rule{Family: 4, Priority: 105, Action: rtnl.FRActToTbl, Table: 7120}
	k.rules[4] = append(k.rules[4], other, rtnl.Rule{Family: 4, Priority: 110, Action: rtnl.FRActToTbl, Table: 7120, Flags: rtnl.FIBRuleInvert,
		FwMark: rtnl.Some(uint32(0x1bd00)), FwMask: rtnl.Some(uint32(0xffffffff))})
	_ = k.DelRulePriority(4, 96)
	repairs(t, m, k, spec)
	n := 0
	for _, r := range k.rules[4] {
		if r.Priority == 105 || r.Priority == 110 {
			n++
		}
	}
	if n != 2 {
		t.Errorf("NetBird's rules went: %d left", n)
	}
}

// A pass that cannot restore a rule reports it, keeps the guard in and is
// not ready; the namespace does not leak meanwhile.
func TestUnrepairableContractIsReportedAndFailsClosed(t *testing.T) {
	m, k, spec := healthyNamespace(t)
	_ = k.DelRulePriority(4, 96)
	k.fail = func(op string) error {
		if op == "add 2 96" {
			return syscall.EPERM
		}
		return nil
	}
	res, err := m.ReconcileNow(context.Background(), "x")
	if err == nil || res.Verified || m.Ready() {
		t.Fatalf("%+v %v", res, err)
	}
	if !contains(res.Problems[rtnl.V4], contract.ProblemRules) {
		t.Errorf("%v", res.Problems)
	}
	if _, ok := priorities(k, rtnl.V4)[80]; !ok {
		t.Error("the guard must stay while the contract cannot be verified")
	}
	if leaking(k, spec) {
		t.Error("leaks")
	}
	k.fail = nil
	res, err = m.ReconcileNow(context.Background(), "later")
	if err != nil || !res.Verified {
		t.Fatalf("%+v %v", res, err)
	}
	expectHealthy(t, k, spec)
}

func contains(s []contract.Problem, p contract.Problem) bool {
	for _, x := range s {
		if x == p {
			return true
		}
	}
	return false
}

// ---- PIA's address change as one transaction ----

func TestChangeReturnPathHoldsBothPairsMeanwhile(t *testing.T) {
	k := newFakeKernel()
	spec := contract.Spec{Config: nativeConfig(), LeaveReturnPath: map[rtnl.Family]bool{rtnl.V4: true, rtnl.V6: true}}
	k.installNative(spec, true)
	guardLeaks(t, k, spec)
	m := start(t, k, spec)
	old := netip.Addr{}
	for round := 1; round <= 3; round++ {
		next := netip.MustParseAddr(fmt.Sprintf("203.0.113.%d", 10+round))
		var during []string
		var expectedDuring []netip.Addr
		err := m.ChangeReturnPath(context.Background(), rtnl.V4, old, next, func(tx *Tx) error {
			// The new pair is in, confirmed, before the address changes.
			snap, err := tx.Snapshot()
			if err != nil {
				return err
			}
			for _, r := range snap.Rules[rtnl.V4] {
				if r.Priority == 94 || r.Priority == 98 {
					during = append(during, r.String())
				}
			}
			expectedDuring = tx.Spec().ReturnPath[rtnl.V4]
			// Changing the address removes the routes through the interface.
			k.routes[4] = k.routes[4][:1]
			// A repair requested meanwhile queues behind this operation.
			m.Reconcile("event during the transaction")
			return nil
		})
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		want := 2
		if old.IsValid() {
			want = 4
		}
		if len(during) != want {
			t.Errorf("round %d: %d return-path rules during the change, want %d: %v", round, len(during), want, during)
		}
		if len(expectedDuring) != want/2 {
			t.Errorf("round %d: expected state holds %v during the change", round, expectedDuring)
		}
		// Afterwards: the new pair alone, the exit route back, compared again.
		n94, n98 := 0, 0
		for _, r := range k.rules[4] {
			switch r.Priority {
			case 94:
				n94++
				if r.Src.Addr() != next {
					t.Errorf("round %d: stale rule 94 %v", round, r)
				}
			case 98:
				n98++
			}
		}
		if n94 != 1 || n98 != 1 {
			t.Errorf("round %d: %d x 94, %d x 98", round, n94, n98)
		}
		if len(k.routes[4]) != 2 {
			t.Errorf("round %d: the exit route did not come back: %+v", round, k.routes[4])
		}
		got := m.Expected()
		if got.LeaveReturnPath[rtnl.V4] || len(got.ReturnPath[rtnl.V4]) != 1 || got.ReturnPath[rtnl.V4][0] != next {
			t.Errorf("round %d: expected %+v", round, got)
		}
		old = next
	}
	// The queued event pass found nothing to undo.
	time.Sleep(50 * time.Millisecond)
	expectHealthy(t, k, m.Expected())
	if leaking(k, spec) {
		t.Error("leaks")
	}
}

func TestChangeReturnPathBacksOutWhenTheChangeFails(t *testing.T) {
	k := newFakeKernel()
	spec := contract.Spec{Config: nativeConfig(), LeaveReturnPath: map[rtnl.Family]bool{rtnl.V4: true, rtnl.V6: true}}
	k.installNative(spec, true)
	m := start(t, k, spec)
	boom := errors.New("address change refused")
	err := m.ChangeReturnPath(context.Background(), rtnl.V4, netip.Addr{}, netip.MustParseAddr("203.0.113.5"), func(tx *Tx) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
	for _, r := range k.rules[4] {
		if r.Priority == 94 || r.Priority == 98 {
			t.Errorf("the new pair was left behind: %v", r)
		}
	}
	got := m.Expected()
	if !got.LeaveReturnPath[rtnl.V4] || len(got.ReturnPath[rtnl.V4]) != 0 {
		t.Errorf("expected state not restored: %+v", got)
	}
}

// ---- the owner itself ----

func TestOperationsRunOneAtATimeInOrder(t *testing.T) {
	k := newFakeKernel()
	m := start(t, k, nativeSpec())
	var order []int
	var running atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = m.Do(context.Background(), "op", func(tx *Tx) error {
				if running.Add(1) != 1 {
					t.Error("two operations at once")
				}
				order = append(order, i)
				time.Sleep(time.Millisecond)
				running.Add(-1)
				return nil
			})
		}()
	}
	wg.Wait()
	if len(order) != 20 {
		t.Fatalf("%v", order)
	}
	// Submission order from one goroutine is preserved.
	var seq []int
	for i := 0; i < 10; i++ {
		i := i
		_ = m.Do(context.Background(), "ordered", func(tx *Tx) error { seq = append(seq, i); return nil })
	}
	for i, v := range seq {
		if v != i {
			t.Fatalf("%v", seq)
		}
	}
}

func TestReconcileRequestsCoalesce(t *testing.T) {
	m, k, _ := healthyNamespace(t)
	gate := make(chan struct{})
	started := make(chan struct{})
	go func() {
		_ = m.Do(context.Background(), "block", func(tx *Tx) error { close(started); <-gate; return nil })
	}()
	<-started
	for i := 0; i < 1000; i++ {
		m.Reconcile("event")
	}
	before := k.dumps
	close(gate)
	// Wait for the pass to run and the owner to go idle.
	deadline := time.Now().Add(2 * time.Second)
	for m.LastPass().Reason == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if passes := k.dumps - before; passes > 3 {
		t.Fatalf("1000 requests became %d dumps", passes)
	}
	if m.LastPass().Reason != "event" {
		t.Fatalf("%+v", m.LastPass())
	}
}

func TestProgressAdvancesWhenIdleAndStallsWhenWedged(t *testing.T) {
	var now atomic.Int64
	clock := bootclock.Clock(func() time.Duration { return time.Duration(now.Load()) })
	k := newFakeKernel()
	m := start(t, k, nativeSpec(), func(o *Options) { o.Clock = clock })
	wait := func(cond func() bool) bool {
		for i := 0; i < 400; i++ {
			if cond() {
				return true
			}
			time.Sleep(5 * time.Millisecond)
		}
		return false
	}
	now.Store(int64(5 * time.Second))
	if !wait(func() bool { return m.Progress() == 5*time.Second }) {
		t.Fatalf("an idle owner reports no step: %v", m.Progress())
	}
	// A wedged operation: the owner reports nothing until it returns.
	gate := make(chan struct{})
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = m.Do(context.Background(), "wedge", func(tx *Tx) error { close(started); <-gate; return nil })
	}()
	<-started
	now.Store(int64(30 * time.Second))
	time.Sleep(100 * time.Millisecond)
	if m.Progress() != 5*time.Second {
		t.Fatalf("a wedged owner reported progress: %v", m.Progress())
	}
	close(gate)
	<-done
	if !wait(func() bool { return m.Progress() == 30*time.Second }) {
		t.Fatalf("no step after the operation: %v", m.Progress())
	}
	if m.Bound() != 2*time.Second {
		t.Errorf("bound %v", m.Bound())
	}
}

func TestOperationBudget(t *testing.T) {
	k := newFakeKernel()
	m := start(t, k, nativeSpec(), func(o *Options) { o.OpTimeout = 80 * time.Millisecond })
	err := m.Do(context.Background(), "slow", func(tx *Tx) error {
		time.Sleep(120 * time.Millisecond)
		return tx.AddRule(rtnl.Rule{Family: 4, Priority: 5000, Action: rtnl.FRActUnreachable})
	})
	if !errors.Is(err, ErrOpTimeout) {
		t.Fatalf("%v", err)
	}
	for _, l := range k.log {
		if l == "add 2 5000" {
			t.Error("a kernel request went out after the budget")
		}
	}
	// A request carries what is left of the budget as its deadline.
	k.timeouts = nil
	_ = m.Do(context.Background(), "fast", func(tx *Tx) error {
		return tx.AddRule(rtnl.Rule{Family: 4, Priority: 5000, Action: rtnl.FRActUnreachable})
	})
	if len(k.timeouts) == 0 || k.timeouts[0] > 80*time.Millisecond || k.timeouts[0] <= 0 {
		t.Errorf("deadlines %v", k.timeouts)
	}
	// An operation that takes no time at all still completes.
	if err := m.Do(context.Background(), "noop", func(tx *Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestPanicInAnOperationIsAnError(t *testing.T) {
	m := start(t, newFakeKernel(), nativeSpec())
	err := m.Do(context.Background(), "boom", func(tx *Tx) error { panic("oops") })
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("%v", err)
	}
	if err := m.Do(context.Background(), "after", func(tx *Tx) error { return nil }); err != nil {
		t.Fatalf("the owner died: %v", err)
	}
}

func TestClosedOwnerRefusesWork(t *testing.T) {
	k := newFakeKernel()
	m := New(Options{Kernel: k, Spec: nativeSpec(), IdleStep: 5 * time.Millisecond})
	m.Start()
	gate := make(chan struct{})
	started := make(chan struct{})
	res := make(chan error, 3)
	go func() {
		res <- m.Do(context.Background(), "inflight", func(tx *Tx) error { close(started); <-gate; return nil })
	}()
	<-started
	for i := 0; i < 2; i++ {
		go func() { res <- m.Do(context.Background(), "queued", func(tx *Tx) error { return nil }) }()
	}
	time.Sleep(20 * time.Millisecond)
	go func() { time.Sleep(30 * time.Millisecond); close(gate) }()
	m.Close()
	var closed, ok int
	for i := 0; i < 3; i++ {
		switch err := <-res; {
		case err == nil:
			ok++
		case errors.Is(err, ErrClosed):
			closed++
		}
	}
	if ok != 1 || closed != 2 {
		t.Errorf("in flight finished %d, queued failed with ErrClosed %d", ok, closed)
	}
	if err := m.Do(context.Background(), "late", func(tx *Tx) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Errorf("%v", err)
	}
	m.Reconcile("late") // no panic, no effect
}

func TestStatsCountRepairs(t *testing.T) {
	var now atomic.Int64
	now.Store(int64(100 * time.Second))
	m, k, spec := healthyNamespace(t, func(o *Options) { o.Clock = func() time.Duration { return time.Duration(now.Load()) } })
	if s := m.Stats(); s.Repairs != 0 || s.HasLast {
		t.Fatalf("%+v", s)
	}
	repairs(t, m, k, spec) // nothing to repair
	if s := m.Stats(); s.Repairs != 0 {
		t.Fatalf("a clean pass counted: %+v", s)
	}
	_ = k.DelRulePriority(4, 95)
	now.Store(int64(130 * time.Second))
	repairs(t, m, k, spec)
	if s := m.Stats(); s.Repairs != 1 || !s.HasLast || s.LastRepair != 130 {
		t.Fatalf("%+v", s)
	}
}

func TestOnPassIsCalled(t *testing.T) {
	var got []PassResult
	var mu sync.Mutex
	m, k, spec := healthyNamespace(t, func(o *Options) {
		o.OnPass = func(r PassResult) { mu.Lock(); got = append(got, r); mu.Unlock() }
	})
	_ = k.DelRulePriority(4, 96)
	repairs(t, m, k, spec)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || !got[0].Repaired || !got[0].Verified || got[0].Reason != "test" {
		t.Fatalf("%+v", got)
	}
}

func TestRepairLogsWhatItDoes(t *testing.T) {
	var lc logCollector
	m, k, spec := healthyNamespace(t, func(o *Options) { o.Logf = lc.logf })
	_ = k.DelRulePriority(4, 96)
	repairs(t, m, k, spec)
	lc.mu.Lock()
	defer lc.mu.Unlock()
	joined := strings.Join(lc.lines, "\n")
	if !strings.Contains(joined, "added IPv4 rule 96") || !strings.Contains(joined, "temporary guard") {
		t.Errorf("%s", joined)
	}
}

func TestSnapshotFailureFailsThePass(t *testing.T) {
	m, k, _ := healthyNamespace(t)
	_ = k
	bad := &failingKernel{fakeKernel: k}
	m2 := New(Options{Kernel: bad, Spec: nativeSpec(), IdleStep: 5 * time.Millisecond})
	m2.Start()
	defer m2.Close()
	res, err := m2.ReconcileNow(context.Background(), "x")
	if err == nil || res.Verified || m2.Ready() {
		t.Fatalf("%+v %v", res, err)
	}
	_ = m
}

type failingKernel struct{ *fakeKernel }

func (f *failingKernel) Take(rtnl.Interest) (*rtnl.Snapshot, error) {
	return nil, errors.New("dump failed")
}

// The leak model the tests rely on has to see the leaks the contract exists
// to stop; otherwise "no leak at any step" would prove nothing.
func TestTheLeakModelSeesTheLeaks(t *testing.T) {
	spec := nativeSpec()
	k := newFakeKernel()
	if !k.leaks(4, "wt0", 51821) {
		t.Fatal("a namespace with only the kernel's rules must leak")
	}
	k.installNative(spec, true)
	if k.leaks(4, "wt0", 51821) || k.leaks(6, "wt0", 51821) {
		t.Fatal("the installed contract must not leak")
	}
	if k.where(4, forwarded, "wt0", 51821) != viaExitTable {
		t.Fatal("forwarded traffic should be routed by the exit table")
	}
	try := func(name string, mutate func(*fakeKernel), want bool) {
		kk := newFakeKernel()
		kk.installNative(spec, true)
		mutate(kk)
		if got := kk.leaks(4, "wt0", 51821); got != want {
			t.Errorf("%s: leaks = %v, want %v", name, got, want)
		}
	}
	try("kernel rule 0 back", func(kk *fakeKernel) {
		kk.rules[4] = append([]rtnl.Rule{{Family: 4, Priority: 0, Action: rtnl.FRActToTbl, Table: rtnl.TableLocal}}, kk.rules[4]...)
	}, true)
	try("lookup main at 50", func(kk *fakeKernel) {
		kk.rules[4] = append([]rtnl.Rule{{Family: 4, Priority: 50, Action: rtnl.FRActToTbl, Table: rtnl.TableMain}}, kk.rules[4]...)
	}, true)
	try("95 and 97 gone", func(kk *fakeKernel) {
		_ = kk.DelRulePriority(4, 95)
		_ = kk.DelRulePriority(4, 97)
	}, true)
	try("95 gone alone", func(kk *fakeKernel) { _ = kk.DelRulePriority(4, 95) }, false)
	try("97 gone alone", func(kk *fakeKernel) { _ = kk.DelRulePriority(4, 97) }, false)
	try("exit table empty and 97 gone", func(kk *fakeKernel) { kk.routes[4] = nil; _ = kk.DelRulePriority(4, 97) }, true)
	try("tunnel route gone", func(kk *fakeKernel) { kk.routes[4] = kk.routes[4][:1] }, false)
	try("whole exit table gone", func(kk *fakeKernel) { kk.routes[4] = nil }, false) // rule 97 holds it
}

// The rebuild of a priority leaves no gap even when nothing else holds the
// namespace: rule 97 is missing and cannot be restored, so rule 95 and the
// exit table alone carry the overlay, and replacing rule 95 must not open it.
func TestRebuildLeavesNoGapWhenItIsTheOnlyGuard(t *testing.T) {
	for _, guard := range []bool{false, true} {
		m, k, spec := healthyNamespace(t, func(o *Options) { o.GuardRepairs = guard })
		_ = k.DelRulePriority(4, 97)
		for i, r := range k.rules[4] {
			if r.Priority == 95 {
				k.rules[4][i].IifName = "" // narrower selectors: a subset of the expected rule
			}
		}
		k.fail = func(op string) error {
			if op == "add 2 97" {
				return syscall.EPERM
			}
			return nil
		}
		if leaking(k, spec) {
			t.Fatal("the fixture should be closed")
		}
		guardLeaks(t, k, spec)
		mark := len(k.log)
		res, _ := m.ReconcileNow(context.Background(), "x")
		if res.Verified {
			t.Fatal("verified without rule 97")
		}
		if index(k.log[mark:], "add 2 94") < 0 {
			t.Errorf("guard=%v: rule 95 was replaced without a copy: %v", guard, k.log[mark:])
		}
		// Rule 95 is restored in full.
		found := false
		for _, r := range k.rules[4] {
			if r.Priority == 95 && r.IifName == "wt0" {
				found = true
			}
		}
		if !found {
			t.Errorf("guard=%v: rule 95 not restored", guard)
		}
	}
}

// Rules 94 and 98 are replaced one at a time and never both missing for the
// tunnel address.
func TestReturnPathPairIsNeverBothGone(t *testing.T) {
	m, k, spec := healthyNamespace(t, func(o *Options) { o.GuardRepairs = false })
	// Both rules 94 and 98 are wrong (narrower selectors): both are rebuilt.
	for i, r := range k.rules[4] {
		if r.Priority == 94 || r.Priority == 98 {
			k.rules[4][i].IPProto = rtnl.Opt[uint8]{}
		}
	}
	covered := func() bool {
		have := map[uint32]bool{}
		for _, r := range k.rules[4] {
			if (r.Priority == 94 || r.Priority == 98) && r.Src.Addr() == netip.MustParseAddr(tunnel4) {
				have[r.Priority] = true
			}
		}
		return have[94] || have[98]
	}
	var gone atomic.Bool
	k.hook = func(op string) {
		if !covered() {
			gone.Store(true)
		}
	}
	repairs(t, m, k, spec)
	if gone.Load() {
		t.Fatal("at some step neither rule 94 nor rule 98 covered the tunnel address")
	}
}

func TestAnOperationThatEndsItsGoroutineDoesNotEndTheOwner(t *testing.T) {
	m := start(t, newFakeKernel(), nativeSpec())
	err := m.Do(context.Background(), "goexit", func(tx *Tx) error {
		runtime.Goexit() // what t.Fatal does
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "ended its goroutine") {
		t.Fatalf("%v", err)
	}
	if err := m.Do(context.Background(), "after", func(tx *Tx) error { return nil }); err != nil {
		t.Fatalf("the owner died: %v", err)
	}
}
