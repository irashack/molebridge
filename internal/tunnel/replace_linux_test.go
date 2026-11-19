//go:build linux

package tunnel

// Replace against one fake namespace that is both the Manager's route socket
// and the mutation owner's kernel: the four steps in order, the policy model
// (internal/policy) judging every state the namespace passes through, a
// failure leaving no link, the fallback and the new return path expected, and
// recovery bringing up the new configuration.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/policy"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/tunnelconf"
)

// nsFake is a namespace as the route socket and the owner see it. Rules
// follow the kernel where the contract depends on it (EEXIST for an identical
// rule, delete by the first rule that has every given attribute); deleting a
// link takes its addresses and routes with it.
type nsFake struct {
	mu     sync.Mutex
	links  []rtnl.Link
	next   uint32
	addrs  map[rtnl.Family][]rtnl.Addr
	rules  map[rtnl.Family][]rtnl.Rule
	routes map[rtnl.Family][]rtnl.Route
	ops    []string
	// fail fails the request named, e.g. "AddAddr 10" or "DelLink".
	fail func(op string) error
	hook func(op string)
}

func newNSFake() *nsFake {
	k := &nsFake{next: 10, addrs: map[rtnl.Family][]rtnl.Addr{}, rules: map[rtnl.Family][]rtnl.Rule{}, routes: map[rtnl.Family][]rtnl.Route{}}
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		k.rules[f] = []rtnl.Rule{
			{Family: f, Priority: 0, Action: rtnl.FRActToTbl, Table: rtnl.TableLocal},
			{Family: f, Priority: 32766, Action: rtnl.FRActToTbl, Table: rtnl.TableMain},
			{Family: f, Priority: 32767, Action: rtnl.FRActToTbl, Table: 253},
		}
	}
	k.links = []rtnl.Link{{Index: 1, Name: "lo", Flags: rtnl.IFFUp}, {Index: 2, Name: "eth0", Flags: rtnl.IFFUp},
		{Index: 3, Name: "wt0", Flags: rtnl.IFFUp, Kind: "wireguard"}}
	return k
}

// do records a request, fails it if told to, applies it and calls the hook.
func (k *nsFake) do(op string, apply func() error) error {
	k.mu.Lock()
	k.ops = append(k.ops, op)
	if k.fail != nil {
		if err := k.fail(op); err != nil {
			k.mu.Unlock()
			return err
		}
	}
	err := apply()
	k.mu.Unlock()
	if err == nil && k.hook != nil {
		k.hook(op)
	}
	return err
}

func (k *nsFake) linkLocked(name string) (rtnl.Link, bool) {
	for _, l := range k.links {
		if l.Name == name {
			return l, true
		}
	}
	return rtnl.Link{}, false
}

// ---- the route socket ----

func (k *nsFake) LinkByName(name string) (rtnl.Link, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if l, ok := k.linkLocked(name); ok {
		return l, nil
	}
	return rtnl.Link{}, syscall.ENODEV
}

func (k *nsFake) AddLink(name, kind string) error {
	return k.do("AddLink", func() error {
		if _, ok := k.linkLocked(name); ok {
			return syscall.EEXIST
		}
		k.next++
		k.links = append(k.links, rtnl.Link{Index: k.next, Name: name, Kind: kind})
		return nil
	})
}

func (k *nsFake) DelLink(index uint32) error {
	return k.do("DelLink", func() error {
		var links []rtnl.Link
		for _, l := range k.links {
			if l.Index != index {
				links = append(links, l)
			}
		}
		if len(links) == len(k.links) {
			return syscall.ENODEV
		}
		k.links = links
		for f := range k.addrs {
			var keep []rtnl.Addr
			for _, a := range k.addrs[f] {
				if a.Index != index {
					keep = append(keep, a)
				}
			}
			k.addrs[f] = keep
		}
		for f := range k.routes {
			var keep []rtnl.Route
			for _, r := range k.routes[f] {
				if !(r.Oif.OK && r.Oif.V == index) {
					keep = append(keep, r)
				}
			}
			k.routes[f] = keep
		}
		return nil
	})
}

func (k *nsFake) SetLinkMTU(_, _ uint32) error {
	return k.do("SetLinkMTU", func() error { return nil })
}

func (k *nsFake) SetLinkUp(index uint32) error {
	return k.do("SetLinkUp", func() error {
		for i := range k.links {
			if k.links[i].Index == index {
				k.links[i].Flags |= rtnl.IFFUp
			}
		}
		return nil
	})
}

func (k *nsFake) AddAddr(a rtnl.Addr) error {
	return k.do(fmt.Sprintf("AddAddr %d", a.Family.AF()), func() error {
		k.addrs[a.Family] = append(k.addrs[a.Family], a)
		return nil
	})
}

func (k *nsFake) ReplaceRoute(r rtnl.Route) error {
	return k.do(fmt.Sprintf("ReplaceRoute %d", r.Family.AF()), func() error {
		for i, x := range k.routes[r.Family] {
			if x.Table == r.Table && x.Dst == r.Dst && x.Metric == r.Metric && x.Tos == r.Tos {
				k.routes[r.Family][i] = r
				return nil
			}
		}
		k.routes[r.Family] = append(k.routes[r.Family], r)
		return nil
	})
}

func (k *nsFake) DelRoute(r rtnl.Route) error {
	return k.do(fmt.Sprintf("DelRoute %d", r.Family.AF()), func() error {
		for i, x := range k.routes[r.Family] {
			if x.Table != r.Table || x.Dst != r.Dst || r.Type != 0 && r.Type != x.Type || r.Oif.OK && r.Oif != x.Oif ||
				r.Metric != 0 && r.Metric != x.Metric {
				continue
			}
			k.routes[r.Family] = append(k.routes[r.Family][:i:i], k.routes[r.Family][i+1:]...)
			return nil
		}
		return syscall.ESRCH
	})
}

func (k *nsFake) SetDeadline(time.Time) {}
func (k *nsFake) Interrupt()            {}
func (k *nsFake) Close() error          { return nil }

// ---- the owner's kernel ----

func (k *nsFake) Take(in rtnl.Interest) (*rtnl.Snapshot, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s := rtnl.NewSnapshot()
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		s.Rules[f] = append([]rtnl.Rule(nil), k.rules[f]...)
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
	return s, nil
}

func ruleIdentity(r rtnl.Rule) string {
	var items []string
	for _, it := range r.Items() {
		if it != "not" {
			items = append(items, it)
		}
	}
	return fmt.Sprintf("%d %v", r.Priority, items)
}

func (k *nsFake) AddRule(r rtnl.Rule) error {
	return k.do(fmt.Sprintf("AddRule %d %d", r.Family.AF(), r.Priority), func() error {
		for _, x := range k.rules[r.Family] {
			if ruleIdentity(x) == ruleIdentity(r) {
				return syscall.EEXIST
			}
		}
		r.Flags &^= rtnl.FIBRuleIifDetached | rtnl.FIBRuleOifDetached
		if _, ok := k.linkLocked(r.IifName); r.IifName != "" && !ok {
			r.Flags |= rtnl.FIBRuleIifDetached
		}
		if _, ok := k.linkLocked(r.OifName); r.OifName != "" && !ok {
			r.Flags |= rtnl.FIBRuleOifDetached
		}
		rules := k.rules[r.Family]
		i := len(rules)
		for j, x := range rules {
			if x.Priority > r.Priority {
				i = j
				break
			}
		}
		k.rules[r.Family] = append(rules[:i:i], append([]rtnl.Rule{r}, rules[i:]...)...)
		return nil
	})
}

func (k *nsFake) DelRule(r rtnl.Rule) error {
	return k.do(fmt.Sprintf("DelRule %d %d", r.Family.AF(), r.Priority), func() error {
		for i, x := range k.rules[r.Family] {
			if rtnl.DeleteMatches(r, x) {
				k.rules[r.Family] = append(k.rules[r.Family][:i:i], k.rules[r.Family][i+1:]...)
				return nil
			}
		}
		return syscall.ENOENT
	})
}

func (k *nsFake) DelRulePriority(f rtnl.Family, priority uint32) error {
	return k.do(fmt.Sprintf("DelRule %d %d", f.AF(), priority), func() error {
		for i, x := range k.rules[f] {
			if x.Priority == priority {
				k.rules[f] = append(k.rules[f][:i:i], k.rules[f][i+1:]...)
				return nil
			}
		}
		return syscall.ENOENT
	})
}

// ---- the harness ----

// replaceConf is a config for provider; only Mullvad's carries its peer (the
// others' peer is set from the provider's API).

func replaceConf(t *testing.T, provider tunnelconf.Provider, addresses, endpoint string) *tunnelconf.Conf {
	t.Helper()
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	post := "ip route replace default dev %i table 51821"
	pre := "ip route del default dev %i table 51821"
	if strings.Contains(addresses, ":") {
		post += "; ip -6 route replace default dev %i table 51821"
		pre += "; ip -6 route del default dev %i table 51821"
	}
	text := "[Interface]\nPrivateKey = " + key + "\n"
	if addresses != "" {
		text += "Address = " + addresses + "\n"
	}
	text += "MTU = 1420\nTable = off\nPostUp = " + post + "\nPreDown = " + pre + "\n"
	if provider == tunnelconf.Mullvad {
		allowed := "0.0.0.0/0"
		if strings.Contains(addresses, ":") {
			allowed += ", ::/0"
		}
		text += "\n[Peer]\nPublicKey = " + key + "\nEndpoint = " + endpoint + "\nAllowedIPs = " + allowed + "\n"
	}
	c, err := tunnelconf.Parse(text, provider, 51821)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type replaceRig struct {
	t         *testing.T
	k         *nsFake
	m         *Manager
	mut       *mutator.Mutator
	from      Params
	violation string
}

func newReplaceRig(t *testing.T, from *tunnelconf.Conf) *replaceRig {
	t.Helper()
	k := newNSFake()
	r := &replaceRig{t: t, k: k, from: Params{ExitIf: "vpn", Conf: from}}
	r.m = &Manager{dialRT: func() (routeAPI, error) { return k, nil }, dialWG: (&wgFactory{}).dial}
	cfg := contract.Config{Kind: contract.Overlay, Backend: contract.Native, Overlay: netip.MustParsePrefix("192.0.2.0/24"),
		Overlay6: netip.MustParsePrefix("2001:db8:1::/64"), OverlayIf: "wt0", ExitIf: "vpn", Table: 51821}
	spec := contract.Spec{Config: cfg, TempGuard: map[rtnl.Family]bool{}}
	spec.ReturnPath, spec.LeaveReturnPath = ReturnPathOf(from)
	r.mut = mutator.New(mutator.Options{Kernel: k, Spec: spec, GuardRepairs: true, OpTimeout: 5 * time.Second, IdleStep: time.Second})
	r.mut.Start()
	t.Cleanup(r.mut.Close)
	ctx := context.Background()
	if err := r.mut.Install(ctx); err != nil {
		t.Fatal(err)
	}
	r.up(r.from)
	return r
}

// up is the tunnel loop's bring-up and the pass after it.
func (r *replaceRig) up(p Params) {
	r.t.Helper()
	ctx := context.Background()
	if err := r.mut.Do(ctx, "bring the tunnel up", func(tx *mutator.Tx) error { return r.m.UpContext(tx.Context(), p) }); err != nil {
		r.t.Fatal(err)
	}
	if res, err := r.mut.ReconcileNow(ctx, "tunnel up"); err != nil || !res.Verified {
		r.t.Fatalf("not verified with the tunnel up: %v %+v", err, res)
	}
}

// observe judges the namespace with its live tunnel addresses as the only
// protected return-path addresses.
func (r *replaceRig) observe(op string) {
	if r.violation != "" {
		return
	}
	spec := r.mut.Expected()
	spec.ReturnPath = map[rtnl.Family][]netip.Addr{}
	snap, _ := r.k.Take(spec.Interest())
	if v := policy.FromSnapshot(spec, snap).Violations(); len(v) > 0 {
		r.violation = fmt.Sprintf("after %s: %v", op, v)
	}
}

func (r *replaceRig) replace(to Params) error {
	r.k.hook = r.observe
	defer func() { r.k.hook = nil }()
	return r.m.Replace(context.Background(), r.mut, r.from, to)
}

// pairs lists the addresses with a rule 94 or 98.
func (r *replaceRig) pairs() []string {
	r.k.mu.Lock()
	defer r.k.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		for _, x := range r.k.rules[f] {
			if (x.Priority == 94 || x.Priority == 98) && x.Src.IsValid() && !seen[x.Src.Addr().String()] {
				seen[x.Src.Addr().String()] = true
				out = append(out, x.Src.Addr().String())
			}
		}
	}
	return out
}

func (r *replaceRig) liveOn() (idx uint32, addrs []string) {
	r.k.mu.Lock()
	defer r.k.mu.Unlock()
	l, ok := r.k.linkLocked("vpn")
	if !ok {
		return 0, nil
	}
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		for _, a := range r.k.addrs[f] {
			if a.Index == l.Index {
				addrs = append(addrs, a.Local.Addr().String())
			}
		}
	}
	return l.Index, addrs
}

func TestReplaceSwapsTheWholeTunnelInOrder(t *testing.T) {
	r := newReplaceRig(t, replaceConf(t, tunnelconf.Mullvad, "203.0.113.2/32, 2001:db8:3::2/128", "198.51.100.10:51820"))
	oldIdx, _ := r.liveOn()
	mark := len(r.k.ops)
	to := Params{ExitIf: "vpn", Conf: replaceConf(t, tunnelconf.NordVPN, "203.0.113.7/32", "")}
	if err := r.replace(to); err != nil {
		t.Fatal(err)
	}
	if r.violation != "" {
		t.Fatal(r.violation)
	}
	idx, live := r.liveOn()
	if idx == 0 || idx == oldIdx || strings.Join(live, " ") != "203.0.113.7" {
		t.Fatalf("link %d (old %d), addresses %v", idx, oldIdx, live)
	}
	if got := strings.Join(r.pairs(), " "); got != "203.0.113.7" {
		t.Fatalf("pairs for %s", got)
	}
	exp := r.mut.Expected()
	if fmt.Sprint(exp.ReturnPath[rtnl.V4]) != "[203.0.113.7]" || len(exp.ReturnPath[rtnl.V6]) != 0 || exp.LeaveReturnPath[rtnl.V4] {
		t.Fatalf("expected %v leave %v", exp.ReturnPath, exp.LeaveReturnPath)
	}
	if !r.mut.LastPass().Verified {
		t.Fatalf("not verified: %+v", r.mut.LastPass())
	}
	ops := r.k.ops[mark:]
	at := func(op string) int {
		for i, x := range ops {
			if x == op {
				return i
			}
		}
		return -1
	}
	newPair, delLink, oldPair, addLink, newAddr := at("AddRule 2 94"), at("DelLink"), at("DelRule 10 94"), at("AddLink"), at("AddAddr 2")
	if newPair < 0 || delLink < 0 || oldPair < 0 || addLink < 0 || newAddr < 0 ||
		!(newPair < delLink && delLink < oldPair && oldPair < addLink && addLink < newAddr) {
		t.Fatalf("order: new pair %d, link deleted %d, old pair removed %d, link added %d, address %d\n%v", newPair, delLink, oldPair, addLink, newAddr, ops)
	}
	if routeDel := at("DelRoute 2"); routeDel < 0 || routeDel > delLink {
		t.Fatalf("the old route's deletion at %d, the link's at %d", routeDel, delLink)
	}
}

func TestAFailedReplaceLeavesNoLinkAndRecoveryBringsUpTheNewConfig(t *testing.T) {
	r := newReplaceRig(t, replaceConf(t, tunnelconf.NordVPN, "203.0.113.2/32", ""))
	to := Params{ExitIf: "vpn", Conf: replaceConf(t, tunnelconf.Mullvad, "203.0.113.7/32, 2001:db8:3::7/128", "198.51.100.20:51820")}
	r.k.fail = func(op string) error {
		if op == "AddAddr 10" {
			return syscall.EACCES // as on an interface with IPv6 disabled
		}
		return nil
	}
	err := r.replace(to)
	if err == nil {
		t.Fatal("no error")
	}
	if strings.Contains(err.Error(), "AAAAAAAA") {
		t.Fatal("key material in the error")
	}
	if r.violation != "" {
		t.Fatal(r.violation)
	}
	if idx, _ := r.liveOn(); idx != 0 {
		t.Fatal("a link survived the failure")
	}
	snap, _ := r.k.Take(r.mut.Expected().Interest())
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		fallback := false
		for _, rt := range snap.RoutesInTable(f, 51821) {
			fallback = fallback || rt.Type == rtnl.RTNUnreachable
			if rt.Type != rtnl.RTNUnreachable {
				t.Errorf("%s: a route other than the fallback: %v", f, rt)
			}
		}
		if !fallback {
			t.Errorf("%s: no fallback", f)
		}
	}
	exp := r.mut.Expected()
	if fmt.Sprint(exp.ReturnPath[rtnl.V4]) != "[203.0.113.7]" || fmt.Sprint(exp.ReturnPath[rtnl.V6]) != "[2001:db8:3::7]" {
		t.Fatalf("expected after the failure: %v", exp.ReturnPath)
	}
	if got := strings.Join(r.pairs(), " "); got != "203.0.113.7 2001:db8:3::7" {
		t.Fatalf("pairs after the failure: %s", got)
	}
	// Recovery, with the fault gone, brings up the new configuration (what
	// the tunnel source names once the applier has updated it).
	r.k.fail = nil
	r.k.hook = r.observe
	r.up(to)
	if r.violation != "" {
		t.Fatal(r.violation)
	}
	if _, live := r.liveOn(); strings.Join(live, " ") != "203.0.113.7 2001:db8:3::7" {
		t.Fatalf("recovered with %v", live)
	}
}

func TestReplaceToAndFromAConfigWithoutAnAddress(t *testing.T) {
	r := newReplaceRig(t, replaceConf(t, tunnelconf.Mullvad, "203.0.113.2/32", "198.51.100.10:51820"))
	pia := Params{ExitIf: "vpn", Conf: replaceConf(t, tunnelconf.PIA, "", "")}
	if err := r.replace(pia); err != nil || r.violation != "" {
		t.Fatalf("%v %s", err, r.violation)
	}
	exp := r.mut.Expected()
	if len(exp.ReturnPath[rtnl.V4]) != 0 || !exp.LeaveReturnPath[rtnl.V4] || !exp.LeaveReturnPath[rtnl.V6] || len(r.pairs()) != 0 {
		t.Fatalf("to PIA: expected %v leave %v, pairs %v", exp.ReturnPath, exp.LeaveReturnPath, r.pairs())
	}
	r.from = pia
	back := Params{ExitIf: "vpn", Conf: replaceConf(t, tunnelconf.Mullvad, "203.0.113.2/32", "198.51.100.10:51820")}
	if err := r.replace(back); err != nil || r.violation != "" {
		t.Fatalf("%v %s", err, r.violation)
	}
	if got := strings.Join(r.pairs(), " "); got != "203.0.113.2" || r.mut.Expected().LeaveReturnPath[rtnl.V4] {
		t.Fatalf("back to Mullvad: pairs %s, expected %+v", got, r.mut.Expected())
	}
}

func TestReplaceRefusesAnotherInterfaceOrNoConfig(t *testing.T) {
	r := newReplaceRig(t, replaceConf(t, tunnelconf.Mullvad, "203.0.113.2/32", "198.51.100.10:51820"))
	mark := len(r.k.ops)
	for name, to := range map[string]Params{
		"another name": {ExitIf: "other", Conf: r.from.Conf},
		"no config":    {ExitIf: "vpn"},
	} {
		if err := r.m.Replace(context.Background(), r.mut, r.from, to); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := r.m.Replace(context.Background(), nil, r.from, r.from); err == nil {
		t.Error("no owner: accepted")
	}
	if len(r.k.ops) != mark {
		t.Fatalf("a refused replacement made requests: %v", r.k.ops[mark:])
	}
}

// The observer the tests above rely on does see a live tunnel address
// without its return-path rules.
func TestTheReplaceObserverSeesAnAddressWithoutItsRule(t *testing.T) {
	r := newReplaceRig(t, replaceConf(t, tunnelconf.Mullvad, "203.0.113.2/32", "198.51.100.10:51820"))
	r.observe("bring-up")
	if r.violation != "" {
		t.Fatal(r.violation)
	}
	for _, prio := range []uint32{94, 98} {
		if err := r.k.DelRulePriority(rtnl.V4, prio); err != nil {
			t.Fatal(err)
		}
	}
	r.observe("deleting rules 94 and 98")
	if r.violation == "" {
		t.Fatal("no violation with rules 94 and 98 gone and their address live")
	}
}

func TestReturnPathOfFollowsTheConfig(t *testing.T) {
	rp, leave := ReturnPathOf(replaceConf(t, tunnelconf.Mullvad, "203.0.113.2/32, 2001:db8:3::2/128", "198.51.100.10:51820"))
	if fmt.Sprint(rp[rtnl.V4], rp[rtnl.V6]) != "[203.0.113.2] [2001:db8:3::2]" || leave[rtnl.V4] || leave[rtnl.V6] {
		t.Fatalf("%v %v", rp, leave)
	}
	rp, leave = ReturnPathOf(replaceConf(t, tunnelconf.PIA, "", ""))
	if len(rp) != 0 || !leave[rtnl.V4] || !leave[rtnl.V6] {
		t.Fatalf("%v %v", rp, leave)
	}
	if rp, leave = ReturnPathOf(nil); len(rp) != 0 || len(leave) != 0 {
		t.Fatalf("%v %v", rp, leave)
	}
}
