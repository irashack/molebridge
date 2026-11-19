package mutator

// The whole-tunnel replacement (ReplaceTunnel) against the fake kernel: the
// order of its four steps, the expected state at each, a failure at every
// point leaving no link, the fallback in place and the expected state naming
// what the kernel has, and recovery bringing up the new tunnel. After every
// change the fake makes, the policy model (internal/policy) judges the kernel
// with the live tunnel addresses as the only return-path addresses it
// protects: no intermediate state may let a protected class escape.

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

// delTunnelLink is `ip link del` through another socket than the owner's: the
// link, its addresses and its routes go together.
func (k *fakeKernel) delTunnelLink(name string) error {
	k.mu.Lock()
	if err := k.record("link del"); err != nil {
		k.mu.Unlock()
		return err
	}
	idx := uint32(0)
	var links []rtnl.Link
	for _, l := range k.links {
		if l.Name == name {
			idx = l.Index
			continue
		}
		links = append(links, l)
	}
	if idx == 0 {
		k.mu.Unlock()
		return nil
	}
	k.links = links
	for _, f := range families {
		var addrs []rtnl.Addr
		for _, a := range k.addrs[f] {
			if a.Index != idx {
				addrs = append(addrs, a)
			}
		}
		k.addrs[f] = addrs
		var routes []rtnl.Route
		for _, r := range k.routes[f] {
			if !(r.Oif.OK && r.Oif.V == idx) {
				routes = append(routes, r)
			}
		}
		k.routes[f] = routes
	}
	k.mu.Unlock()
	k.after("link del")
	return nil
}

// newTunnelLink is the tunnel package's bring-up against the fake, step by
// step through another socket: the link, each address, then the default
// route per family (IPv6 only with an IPv6 address, as a config's PostUp
// says). A failure removes the half-built link.
func (k *fakeKernel) newTunnelLink(name string, table uint32, addrs []netip.Addr) (err error) {
	defer func() {
		if err != nil {
			k.mu.Lock()
			fail := k.fail
			k.fail = nil
			k.mu.Unlock()
			_ = k.delTunnelLink(name)
			k.mu.Lock()
			k.fail = fail
			k.mu.Unlock()
		}
	}()
	step := func(op string, do func()) error {
		k.mu.Lock()
		if err := k.record(op); err != nil {
			k.mu.Unlock()
			return err
		}
		do()
		k.mu.Unlock()
		k.after(op)
		return nil
	}
	if err := step("link add", func() {
		k.links = append(k.links, rtnl.Link{Index: uint32(len(k.links) + 10 + k.mutations), Name: name, Flags: rtnl.IFFUp, Kind: "wireguard"})
	}); err != nil {
		return err
	}
	idx := k.linkIndexLocked(name)
	v6 := false
	for _, a := range addrs {
		f := rtnl.V4
		if a.Is6() {
			f, v6 = rtnl.V6, true
		}
		a := a
		if err := step(fmt.Sprintf("addr add %d", f.AF()), func() {
			k.addrs[f] = append(k.addrs[f], rtnl.Addr{Family: f, Index: idx, Local: netip.PrefixFrom(a, a.BitLen())})
		}); err != nil {
			return err
		}
	}
	for _, f := range families {
		if f == rtnl.V6 && !v6 {
			continue
		}
		f := f
		if err := step(fmt.Sprintf("tunnel route %d", f.AF()), func() {
			k.routes[f] = append(k.routes[f], contract.TunnelRoute(f, table, idx))
		}); err != nil {
			return err
		}
	}
	return nil
}

func (k *fakeKernel) linkIndexLocked(name string) uint32 {
	for _, l := range k.links {
		if l.Name == name {
			return l.Index
		}
	}
	return 0
}

// tunnelScenario is a replacement from one tunnel to another.
type tunnelScenario struct {
	name string
	// old are the old tunnel's addresses (none: PIA before it registers,
	// with the pair left to the applier); next the new tunnel's.
	old, next []netip.Addr
}

func addrs(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func tunnelScenarios() []tunnelScenario {
	return []tunnelScenario{
		{"Mullvad to NordVPN: other addresses", addrs(tunnel4, tunnel6), addrs("203.0.113.5")},
		{"the same addresses", addrs(tunnel4, tunnel6), addrs(tunnel4, tunnel6)},
		{"IPv4 only to both families", addrs("203.0.113.5"), addrs(tunnel4, tunnel6)},
		{"to a config without an address", addrs(tunnel4, tunnel6), nil},
		{"from a config without an address", nil, addrs(tunnel4)},
		{"one address kept, one replaced", addrs(tunnel4, tunnel6), addrs(tunnel4, "2001:db8:3::9")},
	}
}

func pathsOf(as []netip.Addr) (map[rtnl.Family][]netip.Addr, map[rtnl.Family]bool) {
	rp, leave := map[rtnl.Family][]netip.Addr{}, map[rtnl.Family]bool{}
	for _, a := range as {
		f := rtnl.V4
		if a.Is6() {
			f = rtnl.V6
		}
		rp[f] = append(rp[f], a)
	}
	if len(as) == 0 {
		leave[rtnl.V4], leave[rtnl.V6] = true, true
	}
	return rp, leave
}

type tunnelHarness struct {
	t         *testing.T
	k         *fakeKernel
	m         *Mutator
	spec      contract.Spec
	sc        tunnelScenario
	violation string
	// failCreate and failRemove fail the callbacks before they touch the
	// kernel; the fake's own fail hook fails single requests.
	failCreate, failRemove bool
	// oldExtra are old addresses the scenario does not name (a PIA
	// registration's).
	oldExtra map[netip.Addr]bool
}

func newTunnelHarness(t *testing.T, sc tunnelScenario) *tunnelHarness {
	t.Helper()
	h := &tunnelHarness{t: t, sc: sc, k: newFakeKernel()}
	rp, leave := pathsOf(sc.old)
	h.spec = contract.Spec{Config: nativeConfig(), ReturnPath: rp, LeaveReturnPath: leave}
	h.k.installNative(h.spec, true)
	if len(rp[rtnl.V6]) == 0 {
		// No IPv6 route through a tunnel without an IPv6 address.
		h.k.routes[rtnl.V6] = []rtnl.Route{contract.FallbackRoute(rtnl.V6, 51821)}
	}
	for _, a := range sc.old {
		f := rtnl.V4
		if a.Is6() {
			f = rtnl.V6
		}
		h.k.setAddr(f, "mullvad", a, true)
	}
	h.m = start(t, h.k, h.spec)
	if res, err := h.m.ReconcileNow(context.Background(), "start"); err != nil || !res.Verified {
		t.Fatalf("%s: the starting namespace does not verify: %v %+v\n%v\n%v", sc.name, err, res, h.k.ruleSummary(4), h.k.ruleSummary(6))
	}
	return h
}

// observe judges the kernel as it is now, protecting the live addresses only.
func (h *tunnelHarness) observe(where string) {
	if h.violation != "" {
		return
	}
	if v := h.k.escapes(h.m.Expected()); len(v) > 0 {
		h.violation = fmt.Sprintf("the policy model sees an escape after %s: %v", where, v)
		return
	}
	for _, f := range families {
		for _, a := range h.k.liveAddrs(f, "mullvad") {
			if h.k.icmpWhere(f, a, 51821) == escaped {
				h.violation = fmt.Sprintf("an ICMP error from %s reaches the host route after %s", a, where)
				return
			}
		}
	}
}

func (h *tunnelHarness) change() TunnelChange {
	rp, leave := pathsOf(h.sc.next)
	return TunnelChange{ReturnPath: rp, LeaveReturnPath: leave, Old: h.sc.old,
		RemoveLink: func(*Tx) error {
			if h.failRemove {
				return errors.New("injected: the link could not be deleted")
			}
			return h.k.delTunnelLink("mullvad")
		},
		CreateLink: func(*Tx) error {
			if h.failCreate {
				return errors.New("injected: the link could not be created")
			}
			return h.k.newTunnelLink("mullvad", 51821, h.sc.next)
		},
	}
}

func (h *tunnelHarness) replace() error {
	h.k.hook = h.observe
	h.observe("start")
	return h.m.ReplaceTunnel(context.Background(), h.change())
}

func (h *tunnelHarness) pairSources(f rtnl.Family) []netip.Addr {
	h.k.mu.Lock()
	defer h.k.mu.Unlock()
	var out []netip.Addr
	for _, r := range h.k.rules[f] {
		if (r.Priority == contract.PrioReturnPath || r.Priority == contract.PrioBackstop) && r.Src.IsValid() && !containsAddr(out, r.Src.Addr()) {
			out = append(out, r.Src.Addr())
		}
	}
	return out
}

func sameSet(a, b []netip.Addr) bool {
	if len(dedupe(a...)) != len(dedupe(b...)) {
		return false
	}
	for _, x := range a {
		if !containsAddr(b, x) {
			return false
		}
	}
	return true
}

// failedChecks: a failed replacement leaves no link, the fallback, the new
// return path expected and every live address protected; recovery then brings
// up the new tunnel and the contract verifies with exactly its pairs.
func (h *tunnelHarness) failedChecks(label string, err error) {
	t := h.t
	t.Helper()
	h.k.hook = nil
	h.k.fail, h.k.takeFail, h.k.unstableFn = nil, nil, nil
	if h.violation != "" {
		t.Errorf("%s: %s\n%v", label, h.violation, h.k.log)
	}
	if err == nil {
		t.Errorf("%s: no error", label)
	}
	h.k.mu.Lock()
	hasLink := h.k.hasLink("mullvad")
	h.k.mu.Unlock()
	if hasLink && (err == nil || !strings.Contains(err.Error(), "remove the tunnel link after the failure")) {
		t.Errorf("%s: a tunnel link survived the failure, and the error does not say so (%v)", label, err)
	}
	for _, f := range families {
		fallback := false
		for _, r := range h.k.routes[f] {
			fallback = fallback || r.Type == rtnl.RTNUnreachable && r.IsDefault()
		}
		if !fallback {
			t.Errorf("%s: the %s fallback is gone", label, f)
		}
	}
	exp := h.m.Expected()
	rp, _ := pathsOf(h.sc.next)
	for _, f := range families {
		for _, a := range rp[f] {
			if !containsAddr(exp.ReturnPath[f], a) {
				t.Errorf("%s: the new %s address %s is not expected after the failure: %v", label, f, a, exp.ReturnPath[f])
			}
		}
	}
	if hasLink {
		// The kernel refused even the removal: the error says so, and the
		// caller's retry, once the kernel cooperates, completes the change.
		h.failRemove = false
		h.k.hook = h.observe
		if err := h.m.ReplaceTunnel(context.Background(), h.change()); err != nil {
			t.Fatalf("%s: the retry failed: %v", label, err)
		}
		h.k.hook = nil
		h.newTunnelChecks(label+", retried", true)
		return
	}
	// Recovery: the repairer's next pass (the link's deletion is an event it
	// answers), then the tunnel loop brings up the new configuration, then
	// the pass after "tunnel up".
	h.k.hook = h.observe
	if res, err := h.m.ReconcileNow(context.Background(), "event"); err != nil || !res.ContractHolds {
		t.Fatalf("%s: the pass after the failure: %v %+v", label, err, res)
	}
	if err := h.k.newTunnelLink("mullvad", 51821, h.sc.next); err != nil {
		t.Fatal(err)
	}
	var res PassResult
	for i := 0; i < 2; i++ {
		if res, err = h.m.ReconcileNow(context.Background(), "tunnel up"); err == nil && res.Verified {
			break
		}
	}
	h.k.hook = nil
	if err != nil || !res.Verified {
		t.Fatalf("%s: recovery did not verify: %v %+v\n%v", label, err, res, h.k.ruleSummary(4))
	}
	h.newTunnelChecks(label+", recovered", false)
}

// newTunnelChecks: the new tunnel is in place with its pairs. exact asks for
// exactly its pairs; otherwise the old addresses may still be expected (a
// failure that could not read the kernel back keeps every pair until the
// next replacement), and nothing else may be.
func (h *tunnelHarness) newTunnelChecks(label string, exact bool) {
	t := h.t
	t.Helper()
	if h.violation != "" {
		t.Errorf("%s: %s", label, h.violation)
	}
	rp, leave := pathsOf(h.sc.next)
	exp := h.m.Expected()
	snap, _ := h.k.Take(exp.Interest())
	for _, f := range families {
		oldRP, _ := pathsOf(h.sc.old)
		ok := sameSet(exp.ReturnPath[f], rp[f]) && exp.LeaveReturnPath[f] == leave[f]
		if !exact {
			ok = true
			for _, a := range rp[f] {
				ok = ok && containsAddr(exp.ReturnPath[f], a)
			}
			for _, a := range exp.ReturnPath[f] {
				ok = ok && (containsAddr(rp[f], a) || containsAddr(oldRP[f], a) || h.oldExtra[a])
			}
		}
		if !ok {
			t.Errorf("%s: %s expected %v leave=%v, want %v leave=%v", label, f, exp.ReturnPath[f], exp.LeaveReturnPath[f], rp[f], leave[f])
		}
		if got := h.pairSources(f); !sameSet(got, exp.ReturnPath[f]) && (exact || !sameSet(got, rp[f])) {
			t.Errorf("%s: %s pairs for %v, expected %v", label, f, got, exp.ReturnPath[f])
		}
		if p := exp.PlanFamily(snap, f, contract.PlanInput{}); !p.Healthy() {
			t.Errorf("%s: %s unhealthy: %v %v", label, f, p.Rules, p.Routes)
		}
	}
}

func TestAReplacementRunsItsStepsInOrder(t *testing.T) {
	for _, sc := range tunnelScenarios() {
		h := newTunnelHarness(t, sc)
		mark := len(h.k.log)
		var specAtLinkDel, specAtLinkAdd contract.Spec
		h.k.hook = func(op string) {
			h.observe(op)
			switch op {
			case "link del":
				specAtLinkDel = h.m.Expected()
			case "link add":
				specAtLinkAdd = h.m.Expected()
			}
		}
		h.observe("start")
		if err := h.m.ReplaceTunnel(context.Background(), h.change()); err != nil {
			t.Fatalf("%s: %v\n%v", sc.name, err, h.k.log[mark:])
		}
		h.newTunnelChecks(sc.name, true)
		ops := h.k.log[mark:]
		pos := func(want func(string) bool) []int {
			var out []int
			for i, op := range ops {
				if want(op) {
					out = append(out, i)
				}
			}
			return out
		}
		linkDel := pos(func(op string) bool { return op == "link del" })
		linkAdd := pos(func(op string) bool { return op == "link add" })
		if len(linkDel) != 1 || len(linkAdd) != 1 || linkDel[0] > linkAdd[0] {
			t.Fatalf("%s: link del at %v, link add at %v: %v", sc.name, linkDel, linkAdd, ops)
		}
		// Every rule deletion but the temporary guard's (a pass takes it out
		// once its repair verifies) is a removal of an old pair, after the
		// link went and before the new one came.
		isGuard := func(op string) bool { return strings.HasSuffix(op, " 80") }
		for _, i := range pos(func(op string) bool {
			return (strings.HasPrefix(op, "del ") || strings.HasPrefix(op, "delprio")) && !isGuard(op)
		}) {
			if i < linkDel[0] || i > linkAdd[0] {
				t.Errorf("%s: %q at %d, outside the gap between the links (%d, %d): %v", sc.name, ops[i], i, linkDel[0], linkAdd[0], ops)
			}
		}
		// Every rule addition (the new pairs) comes before the old link goes.
		for _, i := range pos(func(op string) bool { return strings.HasPrefix(op, "add ") && !strings.HasPrefix(op, "addr") }) {
			if i > linkDel[0] && !isGuard(ops[i]) {
				t.Errorf("%s: %q at %d, after the old link went (%d): %v", sc.name, ops[i], i, linkDel[0], ops)
			}
		}
		// The route through the old link was deleted (approved) before the link.
		if r := pos(func(op string) bool { return strings.HasPrefix(op, "route del 2 51821") }); len(sc.old) > 0 && (len(r) == 0 || r[0] > linkDel[0]) {
			t.Errorf("%s: the old route's deletion at %v, the link's at %d: %v", sc.name, r, linkDel[0], ops)
		}
		// The expected state: both return paths when the old link goes, the
		// new one alone when the new link comes.
		oldRP, _ := pathsOf(sc.old)
		newRP, newLeave := pathsOf(sc.next)
		for _, f := range families {
			for _, a := range append(append([]netip.Addr(nil), oldRP[f]...), newRP[f]...) {
				if !containsAddr(specAtLinkDel.ReturnPath[f], a) {
					t.Errorf("%s: %s %s not expected when the old link went: %v", sc.name, f, a, specAtLinkDel.ReturnPath[f])
				}
			}
			if !sameSet(specAtLinkAdd.ReturnPath[f], newRP[f]) || specAtLinkAdd.LeaveReturnPath[f] != newLeave[f] {
				t.Errorf("%s: %s expected %v leave=%v when the new link came", sc.name, f, specAtLinkAdd.ReturnPath[f], specAtLinkAdd.LeaveReturnPath[f])
			}
		}
	}
}

// The same addresses never lose their pair, not even for a moment.
func TestAReplacementKeepsThePairsOfAddressesItKeeps(t *testing.T) {
	sc := tunnelScenarios()[1]
	h := newTunnelHarness(t, sc)
	var removals []string
	h.k.hook = func(op string) {
		h.observe(op)
		if strings.HasPrefix(op, "del ") || strings.HasPrefix(op, "delprio") {
			removals = append(removals, op)
		}
	}
	if err := h.m.ReplaceTunnel(context.Background(), h.change()); err != nil {
		t.Fatal(err)
	}
	if len(removals) != 0 || h.violation != "" {
		t.Fatalf("removals %v, %s", removals, h.violation)
	}
}

func TestEveryFailurePointOfAReplacementFailsClosed(t *testing.T) {
	for _, sc := range tunnelScenarios() {
		clean := newTunnelHarness(t, sc)
		mark, takes := clean.k.mutations, clean.k.takes
		if err := clean.replace(); err != nil {
			t.Fatalf("%s: a clean run failed: %v", sc.name, err)
		}
		mutations, snapshots := clean.k.mutations-mark, clean.k.takes-takes
		t.Logf("%s: %d requests, %d snapshots", sc.name, mutations, snapshots)

		// Each callback failing.
		for _, which := range []string{"create", "remove"} {
			h := newTunnelHarness(t, sc)
			h.failCreate, h.failRemove = which == "create", which == "remove"
			err := h.replace()
			h.failedChecks(fmt.Sprintf("%s, %s fails", sc.name, which), err)
		}
		// Each request failing, once and from then on.
		for n := 1; n <= mutations; n++ {
			for _, persistent := range []bool{false, true} {
				h := newTunnelHarness(t, sc)
				base := h.k.mutations
				h.k.fail = func(string) error {
					if at := h.k.mutations - base; at == n || persistent && at > n {
						return syscall.EIO
					}
					return nil
				}
				err := h.replace()
				label := fmt.Sprintf("%s, request %d fails (persistent=%v)", sc.name, n, persistent)
				if err == nil {
					// A failed request the transaction did not need (an
					// idempotent retry inside a pass) may not fail it; the
					// result must then be the whole change.
					h.k.fail = nil
					h.newTunnelChecks(label, true)
					continue
				}
				h.failedChecks(label, err)
			}
		}
		// Each snapshot failing, and the kernel unstable from some look on.
		for n := 1; n <= snapshots; n++ {
			for _, mode := range []string{"fails", "unstable"} {
				h := newTunnelHarness(t, sc)
				base := h.k.takes
				if mode == "fails" {
					h.k.takeFail = func(i int) error {
						if i-base >= n {
							return errors.New("injected snapshot failure")
						}
						return nil
					}
				} else {
					h.k.unstableFn = func(i int) bool { return i-base >= n }
				}
				err := h.replace()
				label := fmt.Sprintf("%s, snapshots %s from the %d-th", sc.name, mode, n)
				if err == nil {
					h.newTunnelChecks(label, true)
					continue
				}
				h.failedChecks(label, err)
			}
		}
	}
}

func TestAReplacementOnGluetunOrWithoutCallbacksChangesNothing(t *testing.T) {
	k := newFakeKernel()
	spec := nativeSpec()
	k.installNative(spec, true)
	m := start(t, k, spec)
	mark := k.mutations
	if err := m.ReplaceTunnel(context.Background(), TunnelChange{}); !errors.Is(err, ErrNoTunnelChange) {
		t.Fatalf("%v", err)
	}
	bad := TunnelChange{ReturnPath: map[rtnl.Family][]netip.Addr{rtnl.V4: addrs(tunnel6)},
		RemoveLink: func(*Tx) error { return nil }, CreateLink: func(*Tx) error { return nil }}
	if err := m.ReplaceTunnel(context.Background(), bad); !errors.Is(err, ErrNoTunnelChange) {
		t.Fatalf("%v", err)
	}
	if k.mutations != mark {
		t.Fatalf("a refused change made %d requests", k.mutations-mark)
	}

	gk := newFakeKernel()
	gspec := contract.Spec{Config: nativeConfig()}
	gspec.Config.Backend = contract.Gluetun
	gm := start(t, gk, gspec)
	called := false
	ch := TunnelChange{RemoveLink: func(*Tx) error { called = true; return nil }, CreateLink: func(*Tx) error { called = true; return nil }}
	if err := gm.ReplaceTunnel(context.Background(), ch); !errors.Is(err, ErrNoTunnelChange) || called {
		t.Fatalf("%v called=%v", err, called)
	}
}

// A replacement after PIA's address transaction: the registered address,
// expected by the transaction and not by the config, is the old tunnel's.
func TestAReplacementAfterPIAsAddressTransaction(t *testing.T) {
	m, k := registered(t, piaA)
	h := &tunnelHarness{t: t, k: k, m: m, sc: tunnelScenario{name: "PIA to Mullvad", next: addrs(tunnel4, tunnel6)}}
	if err := h.replace(); err != nil {
		t.Fatalf("%v\n%v", err, k.log)
	}
	h.newTunnelChecks(h.sc.name, true)
	for _, a := range h.pairSources(rtnl.V4) {
		if a.String() == piaA {
			t.Fatalf("the registration's pair stayed")
		}
	}
}
