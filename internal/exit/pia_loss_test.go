//go:build linux

package exit

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/applier"
	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/rtnl"
)

// nsKernel is a small kernel for the mutation owner and the System's reads:
// rules, routes, links and addresses of one namespace, with the FIB's
// semantics that matter here (a rule identical to one there is EEXIST, a
// delete matches the first rule that has the given attributes, and a rule's
// interface is detached while the interface is not there).
type nsKernel struct {
	mu        sync.Mutex
	rules     map[rtnl.Family][]rtnl.Rule
	routes    map[rtnl.Family][]rtnl.Route
	links     []rtnl.Link
	addrs     map[rtnl.Family][]rtnl.Addr
	mutations int
	log       []string
}

func newNSKernel() *nsKernel {
	k := &nsKernel{rules: map[rtnl.Family][]rtnl.Rule{}, routes: map[rtnl.Family][]rtnl.Route{}, addrs: map[rtnl.Family][]rtnl.Addr{}}
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		k.rules[f] = []rtnl.Rule{
			{Family: f, Priority: 0, Action: rtnl.FRActToTbl, Table: rtnl.TableLocal},
			{Family: f, Priority: 32766, Action: rtnl.FRActToTbl, Table: rtnl.TableMain},
		}
	}
	k.links = []rtnl.Link{{Index: 1, Name: "lo", Flags: rtnl.IFFUp}, {Index: 2, Name: "eth0", Flags: rtnl.IFFUp},
		{Index: 3, Name: "wt0", Flags: rtnl.IFFUp, Kind: "wireguard"}}
	return k
}

func (k *nsKernel) has(name string) bool {
	for _, l := range k.links {
		if l.Name == name {
			return true
		}
	}
	return false
}

func (k *nsKernel) record(op string) {
	k.mutations++
	k.log = append(k.log, op)
}

func (k *nsKernel) AddRule(r rtnl.Rule) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, x := range k.rules[r.Family] {
		if x.Priority == r.Priority && fmt.Sprint(x.Items()) == fmt.Sprint(r.Items()) {
			return syscall.EEXIST
		}
	}
	k.record(fmt.Sprintf("add %v %d", r.Family, r.Priority))
	rules := k.rules[r.Family]
	i := len(rules)
	for j, x := range rules {
		if x.Priority > r.Priority {
			i = j
			break
		}
	}
	k.rules[r.Family] = append(rules[:i], append([]rtnl.Rule{r}, rules[i:]...)...)
	return nil
}

func (k *nsKernel) DelRule(r rtnl.Rule) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i, x := range k.rules[r.Family] {
		if rtnl.DeleteMatches(r, x) {
			k.record(fmt.Sprintf("del %v %d", r.Family, r.Priority))
			k.rules[r.Family] = append(k.rules[r.Family][:i:i], k.rules[r.Family][i+1:]...)
			return nil
		}
	}
	return syscall.ENOENT
}

func (k *nsKernel) DelRulePriority(f rtnl.Family, priority uint32) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i, x := range k.rules[f] {
		if x.Priority == priority {
			k.record(fmt.Sprintf("delprio %v %d", f, priority))
			k.rules[f] = append(k.rules[f][:i:i], k.rules[f][i+1:]...)
			return nil
		}
	}
	return syscall.ENOENT
}

func routeID(r rtnl.Route) string { return fmt.Sprintf("%d %v %d", r.Table, r.Dst, r.Metric) }

func (k *nsKernel) ReplaceRoute(r rtnl.Route) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i, x := range k.routes[r.Family] {
		if routeID(x) == routeID(r) {
			k.routes[r.Family][i] = r
			return nil
		}
	}
	k.record(fmt.Sprintf("route %v %d", r.Family, r.Table))
	k.routes[r.Family] = append(k.routes[r.Family], r)
	return nil
}

func (k *nsKernel) DelRoute(r rtnl.Route) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i, x := range k.routes[r.Family] {
		if routeID(x) == routeID(r) {
			k.record(fmt.Sprintf("route del %v %d", r.Family, r.Table))
			k.routes[r.Family] = append(k.routes[r.Family][:i:i], k.routes[r.Family][i+1:]...)
			return nil
		}
	}
	return syscall.ENOENT
}

func (k *nsKernel) snapshot(in rtnl.Interest) *rtnl.Snapshot {
	k.mu.Lock()
	defer k.mu.Unlock()
	s := rtnl.NewSnapshot()
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		for _, r := range k.rules[f] {
			r.Flags &^= rtnl.FIBRuleIifDetached | rtnl.FIBRuleOifDetached
			if r.IifName != "" && !k.has(r.IifName) {
				r.Flags |= rtnl.FIBRuleIifDetached
			}
			if r.OifName != "" && !k.has(r.OifName) {
				r.Flags |= rtnl.FIBRuleOifDetached
			}
			s.Rules[f] = append(s.Rules[f], r)
		}
		for _, r := range k.routes[f] {
			for _, t := range in.Tables {
				if r.Table == t {
					s.Routes[f] = append(s.Routes[f], r)
				}
			}
		}
		s.Addrs[f] = append([]rtnl.Addr(nil), k.addrs[f]...)
	}
	s.Links = append([]rtnl.Link(nil), k.links...)
	return s
}

func (k *nsKernel) Take(in rtnl.Interest) (*rtnl.Snapshot, error) { return k.snapshot(in), nil }
func (k *nsKernel) TakeReadOnly(_ context.Context, in rtnl.Interest) (*rtnl.Snapshot, error) {
	return k.snapshot(in), nil
}
func (k *nsKernel) Links() ([]rtnl.Link, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]rtnl.Link(nil), k.links...), nil
}
func (k *nsKernel) Routes(f rtnl.Family, _ func(uint32) bool) ([]rtnl.Route, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]rtnl.Route(nil), k.routes[f]...), nil
}
func (k *nsKernel) Addrs(f rtnl.Family) ([]rtnl.Addr, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]rtnl.Addr(nil), k.addrs[f]...), nil
}

// The test seams of the kernel itself: addresses and the tunnel interface as
// the engine and the worker leave them.
func (k *nsKernel) setAddr(name string, a netip.Addr, present bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	var idx uint32
	for _, l := range k.links {
		if l.Name == name {
			idx = l.Index
		}
	}
	var kept []rtnl.Addr
	for _, x := range k.addrs[rtnl.V4] {
		if !(x.Index == idx && x.Local.Addr() == a) {
			kept = append(kept, x)
		}
	}
	if present {
		kept = append(kept, rtnl.HostAddr(idx, a))
	}
	k.addrs[rtnl.V4] = kept
}

func (k *nsKernel) pair() (out []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, r := range k.rules[rtnl.V4] {
		if r.Priority == 94 || r.Priority == 98 {
			out = append(out, fmt.Sprintf("%d from %v", r.Priority, r.Src.Addr()))
		}
	}
	return
}

func (k *nsKernel) mutationCount() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.mutations
}

// piaFakeSystem is the exit's System over the fake kernel, offline, with the
// namespace's sysctl as the exit's would be.
type piaFakeSystem struct{ *KernelSystem }

func (piaFakeSystem) Fetch(context.Context, netx.Request) (netx.Response, error) {
	return netx.Response{}, errors.New("offline")
}
func (piaFakeSystem) ReadSysctl(context.Context, string) (string, error) { return "1\n", nil }

// The tunnel has no peer yet (an addressless config).
func (piaFakeSystem) Peers(context.Context) ([]string, error) { return []string{}, nil }
func (piaFakeSystem) LatestHandshakes(context.Context) (map[string]int64, error) {
	return map[string]int64{}, nil
}
func (piaFakeSystem) Endpoints(context.Context) (map[string]string, error) {
	return map[string]string{}, nil
}
func (piaFakeSystem) PublicKey(context.Context) (string, error) { return "", errors.New("no device") }

// The live defect, end to end over a fake kernel: a PIA exit registered an
// address; the tunnel interface is deleted and recreated without one. The
// provider's reconcile (every tick, through the real pipeline) and the mutation
// owner must settle: the pair goes once, the owner stops expecting the lost
// address, nothing is added or deleted over ten more ticks, the exit is judged
// intact for an addressless config so the pipeline goes on, and the next
// registration gets its pair through the address transaction.
func TestPIATunnelLossSettlesInsteadOfFighting(t *testing.T) {
	k := newNSKernel()
	cfg, err := contract.ConfigFromEnv(func(n string) string {
		return map[string]string{"OVERLAY_CIDR": "192.0.2.0/24", "OVERLAY_IF": "wt0", "EXIT_IF": "pia", "EXIT_TABLE": "51821"}[n]
	})
	if err != nil {
		t.Fatal(err)
	}
	k.links = append(k.links, rtnl.Link{Index: 10, Name: "pia", Flags: rtnl.IFFUp, Kind: "wireguard"})
	spec := contract.Spec{Config: cfg, LeaveReturnPath: map[rtnl.Family]bool{rtnl.V4: true, rtnl.V6: true}}
	m := mutator.New(mutator.Options{Kernel: k, Spec: spec, GuardRepairs: true, OpTimeout: 2 * time.Second, IdleStep: 10 * time.Millisecond})
	m.Start()
	t.Cleanup(m.Close)
	ctx := context.Background()
	if err := m.Install(ctx); err != nil {
		t.Fatal(err)
	}
	s := &Settings{Routing: cfg, Provider: "pia", Env: map[string]string{}}
	ks := &KernelSystem{S: s, Spec: spec, Obs: k, Mut: m}
	lost, fresh := netip.MustParseAddr("203.0.113.11"), netip.MustParseAddr("203.0.113.12")

	exit := applier.Exit{ExitIf: "pia", OverlayIf: "wt0", Table: "51821", Overlay: "192.0.2.0/24", Kind: "overlay"}
	prov, err := applier.NewPIAFromEnv(exit, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	a, err := applier.New(applier.Config{StateDir: t.TempDir(), Exit: exit, Provider: prov, System: piaFakeSystem{ks},
		Publish: func(*applier.Record) error { return nil }, Log: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}

	// The registration: the address and its pair, by the owner's transaction.
	if err := m.ChangeReturnPath(ctx, rtnl.V4, netip.Addr{}, lost, func(tx *mutator.Tx) error {
		k.setAddr("pia", lost, true)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := k.pair(); len(got) != 2 {
		t.Fatalf("the registration's pair: %v", got)
	}
	if p, _ := a.DefaultRoutingStatus(ctx, true); !p {
		t.Fatal("a registered exit is not intact")
	}

	// `ip link del pia`, and the worker's recreation: up, no address, and the
	// default route in the exit table.
	k.mu.Lock()
	var links []rtnl.Link
	for _, l := range k.links {
		if l.Name != "pia" {
			links = append(links, l)
		}
	}
	k.links = append(links, rtnl.Link{Index: 11, Name: "pia", Flags: rtnl.IFFUp, Kind: "wireguard"})
	k.addrs[rtnl.V4] = nil
	k.routes[rtnl.V4] = []rtnl.Route{contract.FallbackRoute(rtnl.V4, 51821), contract.TunnelRoute(rtnl.V4, 51821, 11)}
	k.mu.Unlock()
	ks.invalidate() // the shared 100 ms look predates the deletion

	if _, err := a.Tick(ctx); err != nil {
		t.Logf("tick: %v", err)
	}
	if got := k.pair(); len(got) != 0 {
		t.Fatalf("the lost address's pair survived a tick: %v", got)
	}
	if got := m.Expected().ReturnPath[rtnl.V4]; len(got) != 0 {
		t.Fatalf("the owner still expects %v", got)
	}
	if !m.Expected().LeaveReturnPath[rtnl.V4] {
		t.Error("an addressless config leaves 94 and 98 to the provider again")
	}
	mark := k.mutationCount()
	for i := 0; i < 10; i++ {
		if _, err := a.Tick(ctx); err != nil {
			t.Logf("tick: %v", err)
		}
		if res, err := m.ReconcileNow(ctx, "tick"); err != nil || !res.Verified {
			t.Fatalf("pass %d: %+v %v", i, res, err)
		}
	}
	if d := k.mutationCount() - mark; d != 0 {
		k.mu.Lock()
		t.Errorf("%d mutations over ten ticks after the retirement: %v", d, k.log[len(k.log)-d:])
		k.mu.Unlock()
	}
	if got := k.pair(); len(got) != 0 {
		t.Errorf("a pair came back: %v", got)
	}
	// The gate judges an addressless config with no address required (as
	// 0.7.0's routing_status(require_address=False) did), so the pipeline goes
	// on to register.
	if p, f := a.DefaultRoutingStatus(ctx, false); !p || !f {
		t.Errorf("the addressless exit is not intact: %v %v", p, f)
	}
	if p, _ := a.DefaultRoutingStatus(ctx, true); p {
		t.Error("with an address required there is none")
	}
	// A live address is never retired by the provider's tick.
	if err := m.ChangeReturnPath(ctx, rtnl.V4, netip.Addr{}, fresh, func(tx *mutator.Tx) error {
		k.setAddr("pia", fresh, true)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got := k.pair(); len(got) != 2 || got[0] != "94 from 203.0.113.12" {
		t.Fatalf("the new registration's pair: %v", got)
	}
	mark = k.mutationCount()
	for i := 0; i < 5; i++ {
		_, _ = a.Tick(ctx)
	}
	if k.mutationCount() != mark || len(k.pair()) != 2 {
		t.Errorf("a live address's pair was touched by the ticks: %v %v", k.pair(), k.log[mark:])
	}
	if p, _ := a.DefaultRoutingStatus(ctx, true); !p {
		t.Error("the re-registered exit is not intact")
	}
}

// The retirement is refused while the address is live somewhere else, and the
// provider is told it is unverified.
func TestRetirementOfALiveAddressIsRefusedNotForced(t *testing.T) {
	k := newNSKernel()
	cfg, _ := contract.ConfigFromEnv(func(n string) string {
		return map[string]string{"OVERLAY_CIDR": "192.0.2.0/24", "EXIT_IF": "pia", "EXIT_TABLE": "51821"}[n]
	})
	k.links = append(k.links, rtnl.Link{Index: 10, Name: "pia", Flags: rtnl.IFFUp, Kind: "wireguard"})
	spec := contract.Spec{Config: cfg, LeaveReturnPath: map[rtnl.Family]bool{rtnl.V4: true, rtnl.V6: true}}
	m := mutator.New(mutator.Options{Kernel: k, Spec: spec, GuardRepairs: true, OpTimeout: 2 * time.Second, IdleStep: 10 * time.Millisecond})
	m.Start()
	t.Cleanup(m.Close)
	ctx := context.Background()
	if err := m.Install(ctx); err != nil {
		t.Fatal(err)
	}
	ks := &KernelSystem{S: &Settings{Routing: cfg, Provider: "pia", Env: map[string]string{}}, Spec: spec, Obs: k, Mut: m}
	addr := netip.MustParseAddr("203.0.113.11")
	if err := m.ChangeReturnPath(ctx, rtnl.V4, netip.Addr{}, addr, func(tx *mutator.Tx) error { k.setAddr("pia", addr, true); return nil }); err != nil {
		t.Fatal(err)
	}
	mark := k.mutationCount()
	err := ks.DeleteReturnPathRule(ctx, 94, addr)
	if !errors.Is(err, mutator.ErrReturnPathLive) {
		t.Fatalf("%v", err)
	}
	if k.mutationCount() != mark || len(k.pair()) != 2 {
		t.Errorf("a live address's pair was touched: %v", k.log[mark:])
	}
	if err := ks.DeleteReturnPathRule(ctx, 77, addr); err == nil {
		t.Error("not a return-path priority")
	}
}
