package mutator

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// fakeKernel behaves as the Linux FIB does where the contract depends on it,
// as established by experiment with iproute2 in a throwaway namespace:
//
//   - a rule is added after the rules of the same priority, and adding a rule
//     identical to an existing one (everything but the invert flag, which the
//     kernel does not compare) is EEXIST;
//   - a rule is deleted by giving some of its attributes: the first rule at
//     the priority that has every attribute given goes, so a delete by a
//     subset of an expected rule's selectors removes the expected rule;
//   - a delete by priority alone removes the first rule at that priority;
//   - kernel rules 0, 32766 and 32767 exist at the start.
//
// Every mutation calls the hook after it is applied, which is where the tests
// look for a leak at each instant of a repair.
type fakeKernel struct {
	mu     sync.Mutex
	rules  map[rtnl.Family][]rtnl.Rule
	routes map[rtnl.Family][]rtnl.Route
	links  []rtnl.Link
	addrs  map[rtnl.Family][]rtnl.Addr

	log  []string
	hook func(op string)
	// fail returns an error for an operation; op is e.g. "add 4 95".
	fail func(op string) error
	// delay makes every request take this long.
	delay time.Duration

	timeouts []time.Duration
	dumps    int
	// unstableFn marks the n-th snapshot (1-based) as one taken while the
	// kernel kept changing: it is flagged Unstable and, like a real one can,
	// leaves out the interface addresses.
	unstableFn func(n int) bool
	// takeFail returns an error for the n-th snapshot (1-based).
	takeFail func(n int) error
	takes    int
	// unstable marks every snapshot as taken while the kernel kept changing.
	unstable bool
	// mutations counts requests that change something, in order.
	mutations int
}

func newFakeKernel() *fakeKernel {
	k := &fakeKernel{rules: map[rtnl.Family][]rtnl.Rule{}, routes: map[rtnl.Family][]rtnl.Route{}, addrs: map[rtnl.Family][]rtnl.Addr{}}
	for _, f := range families {
		k.rules[f] = []rtnl.Rule{
			{Family: f, Priority: 0, Action: rtnl.FRActToTbl, Table: rtnl.TableLocal, Protocol: rtnl.Some(uint8(2))},
			{Family: f, Priority: 32766, Action: rtnl.FRActToTbl, Table: rtnl.TableMain, Protocol: rtnl.Some(uint8(2))},
			{Family: f, Priority: 32767, Action: rtnl.FRActToTbl, Table: 253, Protocol: rtnl.Some(uint8(2))},
		}
	}
	k.links = []rtnl.Link{{Index: 1, Name: "lo", Flags: rtnl.IFFUp}, {Index: 2, Name: "eth0", Flags: rtnl.IFFUp},
		{Index: 3, Name: "wt0", Flags: rtnl.IFFUp, Kind: "wireguard"}}
	return k
}

func (k *fakeKernel) SetTimeout(d time.Duration) {
	k.mu.Lock()
	k.timeouts = append(k.timeouts, d)
	k.mu.Unlock()
}

func (k *fakeKernel) record(op string) error {
	k.log = append(k.log, op)
	k.mutations++
	if k.fail != nil {
		if err := k.fail(op); err != nil {
			return err
		}
	}
	return nil
}

func (k *fakeKernel) after(op string) {
	if k.hook != nil {
		k.hook(op)
	}
}

func (k *fakeKernel) wait() {
	if k.delay > 0 {
		time.Sleep(k.delay)
	}
}

func (k *fakeKernel) Take(in rtnl.Interest) (*rtnl.Snapshot, error) {
	k.wait()
	k.mu.Lock()
	defer k.mu.Unlock()
	k.dumps++
	k.takes++
	if k.takeFail != nil {
		if err := k.takeFail(k.takes); err != nil {
			return nil, err
		}
	}
	s := rtnl.NewSnapshot()
	s.Unstable = k.unstable
	omitAddrs := false
	if k.unstableFn != nil && k.unstableFn(k.takes) {
		s.Unstable, omitAddrs = true, true
	}
	for _, f := range families {
		s.Rules[f] = append([]rtnl.Rule(nil), k.rules[f]...)
		for _, r := range k.routes[f] {
			for _, t := range in.Tables {
				if r.Table == t {
					s.Routes[f] = append(s.Routes[f], r)
				}
			}
		}
		if !omitAddrs {
			s.Addrs[f] = append([]rtnl.Addr(nil), k.addrs[f]...)
		}
	}
	s.Links = append([]rtnl.Link(nil), k.links...)
	return s, nil
}

// withoutInvert is the rule's identity as the kernel compares it.
func withoutInvert(r rtnl.Rule) string {
	var items []string
	for _, it := range r.Items() {
		if it != "not" {
			items = append(items, it)
		}
	}
	return fmt.Sprintf("%d %v", r.Priority, items)
}

func (k *fakeKernel) AddRule(r rtnl.Rule) error {
	k.wait()
	k.mu.Lock()
	op := fmt.Sprintf("add %d %d", r.Family.AF(), r.Priority)
	if err := k.record(op); err != nil {
		k.mu.Unlock()
		return err
	}
	for _, x := range k.rules[r.Family] {
		if withoutInvert(x) == withoutInvert(r) {
			k.mu.Unlock()
			return syscall.EEXIST
		}
	}
	r.Flags &^= rtnl.FIBRulePermanent
	// Detachment follows the interface.
	r.Flags &^= rtnl.FIBRuleIifDetached | rtnl.FIBRuleOifDetached
	if r.IifName != "" && !k.hasLink(r.IifName) {
		r.Flags |= rtnl.FIBRuleIifDetached
	}
	if r.OifName != "" && !k.hasLink(r.OifName) {
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
	k.rules[r.Family] = append(rules[:i], append([]rtnl.Rule{r}, rules[i:]...)...)
	k.mu.Unlock()
	k.after(op)
	return nil
}

func (k *fakeKernel) hasLink(name string) bool {
	for _, l := range k.links {
		if l.Name == name {
			return true
		}
	}
	return false
}

// deleteMatches: every attribute r gives is the same on x. The invert flag is
// not compared.
func deleteMatches(req, x rtnl.Rule) bool {
	if req.Priority != x.Priority {
		return false
	}
	if req.Action != 0 && req.Action != x.Action {
		return false
	}
	if req.Table != 0 && req.Table != x.Table {
		return false
	}
	if req.IifName != "" && req.IifName != x.IifName {
		return false
	}
	if req.OifName != "" && req.OifName != x.OifName {
		return false
	}
	if req.FwMark.OK && req.FwMark != x.FwMark {
		return false
	}
	if req.FwMask.OK && req.FwMask != x.FwMask {
		return false
	}
	if req.SuppressPrefixLen.OK && req.SuppressPrefixLen != x.SuppressPrefixLen {
		return false
	}
	if req.IPProto.OK && req.IPProto != x.IPProto {
		return false
	}
	if req.Src.IsValid() && req.Src != x.Src {
		return false
	}
	if req.Dst.IsValid() && req.Dst != x.Dst {
		return false
	}
	if req.Tos != 0 && req.Tos != x.Tos {
		return false
	}
	for _, u := range req.Unknown {
		found := false
		for _, v := range x.Unknown {
			if u.Type == v.Type && string(u.Data) == string(v.Data) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (k *fakeKernel) DelRule(r rtnl.Rule) error {
	k.wait()
	k.mu.Lock()
	op := fmt.Sprintf("del %d %d", r.Family.AF(), r.Priority)
	if err := k.record(op); err != nil {
		k.mu.Unlock()
		return err
	}
	for i, x := range k.rules[r.Family] {
		if deleteMatches(r, x) {
			k.rules[r.Family] = append(k.rules[r.Family][:i:i], k.rules[r.Family][i+1:]...)
			k.mu.Unlock()
			k.after(op)
			return nil
		}
	}
	k.mu.Unlock()
	return syscall.ENOENT
}

func (k *fakeKernel) DelRulePriority(f rtnl.Family, priority uint32) error {
	k.wait()
	k.mu.Lock()
	op := fmt.Sprintf("delprio %d %d", f.AF(), priority)
	if err := k.record(op); err != nil {
		k.mu.Unlock()
		return err
	}
	for i, x := range k.rules[f] {
		if x.Priority == priority {
			k.rules[f] = append(k.rules[f][:i:i], k.rules[f][i+1:]...)
			k.mu.Unlock()
			k.after(op)
			return nil
		}
	}
	k.mu.Unlock()
	return syscall.ENOENT
}

func routeKey(r rtnl.Route) string {
	return fmt.Sprintf("%d %v %d %d", r.Table, r.Dst, r.Metric, r.Tos)
}

func (k *fakeKernel) ReplaceRoute(r rtnl.Route) error {
	k.wait()
	k.mu.Lock()
	op := fmt.Sprintf("route replace %d %d", r.Family.AF(), r.Table)
	if err := k.record(op); err != nil {
		k.mu.Unlock()
		return err
	}
	routes := k.routes[r.Family]
	for i, x := range routes {
		if routeKey(x) == routeKey(r) {
			routes[i] = r
			k.mu.Unlock()
			k.after(op)
			return nil
		}
	}
	k.routes[r.Family] = append(routes, r)
	k.mu.Unlock()
	k.after(op)
	return nil
}

func (k *fakeKernel) DelRoute(r rtnl.Route) error {
	k.wait()
	k.mu.Lock()
	op := fmt.Sprintf("route del %d %d", r.Family.AF(), r.Table)
	if err := k.record(op); err != nil {
		k.mu.Unlock()
		return err
	}
	for i, x := range k.routes[r.Family] {
		if x.Table != r.Table || x.Dst != r.Dst {
			continue
		}
		if r.Type != 0 && r.Type != x.Type {
			continue
		}
		if r.Oif.OK && r.Oif != x.Oif {
			continue
		}
		if r.Metric != 0 && r.Metric != x.Metric {
			continue
		}
		if r.Gateway.IsValid() && r.Gateway != x.Gateway {
			continue
		}
		k.routes[r.Family] = append(k.routes[r.Family][:i:i], k.routes[r.Family][i+1:]...)
		k.mu.Unlock()
		k.after(op)
		return nil
	}
	k.mu.Unlock()
	return syscall.ESRCH
}

// ---- where packets go ----

// A probe is a packet that arrived on the overlay interface. Forwarded is
// destined for the Internet; Local for the exit's own address, which only the
// local-delivery guard (rule 1) keeps from the exit's own stack.
type probe int

const (
	forwarded probe = iota
	local
)

func probeSrc(f rtnl.Family) netip.Addr {
	if f == rtnl.V6 {
		return netip.MustParseAddr("2001:db8:1::2")
	}
	return netip.MustParseAddr("192.0.2.2")
}

func probeDst(f rtnl.Family, p probe) netip.Addr {
	switch {
	case p == local && f == rtnl.V6:
		return netip.MustParseAddr("2001:db8:1::1")
	case p == local:
		return netip.MustParseAddr("192.0.2.1")
	case f == rtnl.V6:
		return netip.MustParseAddr("2001:db8:2::100")
	}
	return netip.MustParseAddr("198.51.100.100")
}

// matches evaluates the rule's selectors for the probe packet: arrived on
// overlayIf, TCP, mark 0, no output interface yet. A rule with selectors the
// codec does not model is assumed not to match.
func matches(r rtnl.Rule, f rtnl.Family, p probe, overlayIf string) bool {
	match := true
	if r.IifName != "" && r.IifName != overlayIf {
		match = false
	}
	if r.OifName != "" {
		match = false
	}
	if r.Src.IsValid() && !r.Src.Contains(probeSrc(f)) {
		match = false
	}
	if r.Dst.IsValid() && !r.Dst.Contains(probeDst(f, p)) {
		match = false
	}
	if r.FwMark.OK {
		mask := uint32(0xffffffff)
		if r.FwMask.OK {
			mask = r.FwMask.V
		}
		if 0&mask != r.FwMark.V {
			match = false
		}
	}
	if r.IPProto.OK && r.IPProto.V != 6 {
		match = false
	}
	if r.Tos != 0 || len(r.Unknown) > 0 {
		match = false
	}
	if r.Invert() {
		match = !match
	}
	return match
}

type verdict string

const (
	viaExitTable verdict = "the exit table"
	stopped      verdict = "stopped"
	escaped      verdict = "ESCAPED"
)

// where follows the probe through the FIB rules.
func (k *fakeKernel) where(f rtnl.Family, p probe, overlayIf string, exitTable uint32) verdict {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, r := range k.rules[f] {
		if !matches(r, f, p, overlayIf) {
			continue
		}
		switch r.Action {
		case rtnl.FRActUnreachable, rtnl.FRActProhibit, rtnl.FRActBlackhole:
			return stopped
		case rtnl.FRActToTbl:
			switch r.Table {
			case exitTable:
				// The default route with the lowest metric answers.
				var best *rtnl.Route
				for i, rt := range k.routes[f] {
					if rt.Table == exitTable && rt.IsDefault() && (best == nil || rt.Metric < best.Metric) {
						best = &k.routes[f][i]
					}
				}
				if best != nil {
					if best.Type == rtnl.RTNUnreachable {
						return stopped
					}
					return viaExitTable
				}
			case rtnl.TableLocal:
				if p == local {
					return escaped
				}
			case rtnl.TableMain:
				if p == forwarded && !r.SuppressPrefixLen.OK {
					return escaped
				}
			}
		}
	}
	return stopped
}

// leaks: some probe gets past the contract.
func (k *fakeKernel) leaks(f rtnl.Family, overlayIf string, exitTable uint32) bool {
	return k.where(f, forwarded, overlayIf, exitTable) == escaped || k.where(f, local, overlayIf, exitTable) == escaped
}

func (k *fakeKernel) ruleSummary(f rtnl.Family) []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var out []string
	for _, r := range k.rules[f] {
		out = append(out, r.String())
	}
	return out
}

func (k *fakeKernel) prioritiesPresent(f rtnl.Family) []uint32 {
	k.mu.Lock()
	defer k.mu.Unlock()
	seen := map[uint32]bool{}
	var out []uint32
	for _, r := range k.rules[f] {
		if !seen[r.Priority] {
			seen[r.Priority] = true
			out = append(out, r.Priority)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// install seeds a healthy native namespace the way a finished install leaves it.
func (k *fakeKernel) installNative(spec contract.Spec, tunnelUp bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, f := range families {
		rules := []rtnl.Rule{k.rules[f][1], k.rules[f][2]}
		for _, r := range spec.Rules(f) {
			rules = append(rules, withDetach(k, r))
		}
		sort.SliceStable(rules, func(i, j int) bool { return rules[i].Priority < rules[j].Priority })
		k.rules[f] = rules
		k.routes[f] = []rtnl.Route{contract.FallbackRoute(f, spec.Config.Table)}
	}
	if tunnelUp {
		k.addLink(spec.Config.ExitIf)
		idx := k.linkIndex(spec.Config.ExitIf)
		for _, f := range families {
			if f == rtnl.V6 && len(spec.ReturnPath[rtnl.V6]) == 0 {
				continue
			}
			k.routes[f] = append(k.routes[f], contract.TunnelRoute(f, spec.Config.Table, idx))
		}
	}
}

func withDetach(k *fakeKernel, r rtnl.Rule) rtnl.Rule {
	if r.IifName != "" && !k.hasLink(r.IifName) {
		r.Flags |= rtnl.FIBRuleIifDetached
	}
	if r.OifName != "" && !k.hasLink(r.OifName) {
		r.Flags |= rtnl.FIBRuleOifDetached
	}
	return r
}

func (k *fakeKernel) addLink(name string) {
	if k.hasLink(name) {
		return
	}
	k.links = append(k.links, rtnl.Link{Index: uint32(len(k.links) + 10), Name: name, Flags: rtnl.IFFUp, Kind: "wireguard"})
}

func (k *fakeKernel) linkIndex(name string) uint32 {
	for _, l := range k.links {
		if l.Name == name {
			return l.Index
		}
	}
	return 0
}

// ---- the exit's own ICMP errors ----

// icmpWhere follows an ICMP error the exit sends from a tunnel address: a
// locally generated packet (input interface lo), source the address, protocol
// ICMP, destined outside. It must never reach the main table, where the
// host's default route is.
func (k *fakeKernel) icmpWhere(f rtnl.Family, from netip.Addr, exitTable uint32) verdict {
	k.mu.Lock()
	defer k.mu.Unlock()
	proto := uint8(1)
	if f == rtnl.V6 {
		proto = 58
	}
	for _, r := range k.rules[f] {
		match := true
		if r.IifName != "" && r.IifName != "lo" {
			match = false
		}
		if r.OifName != "" {
			match = false
		}
		if r.Src.IsValid() && !r.Src.Contains(from) {
			match = false
		}
		if r.Dst.IsValid() && !r.Dst.Contains(probeDst(f, forwarded)) {
			match = false
		}
		if r.IPProto.OK && r.IPProto.V != proto {
			match = false
		}
		if r.FwMark.OK && r.FwMark.V != 0 || r.Tos != 0 || len(r.Unknown) > 0 {
			match = false
		}
		if r.Invert() {
			match = !match
		}
		if !match {
			continue
		}
		switch r.Action {
		case rtnl.FRActUnreachable, rtnl.FRActProhibit, rtnl.FRActBlackhole:
			return stopped
		case rtnl.FRActToTbl:
			switch r.Table {
			case exitTable:
				var best *rtnl.Route
				for i, rt := range k.routes[f] {
					if rt.Table == exitTable && rt.IsDefault() && (best == nil || rt.Metric < best.Metric) {
						best = &k.routes[f][i]
					}
				}
				if best != nil {
					if best.Type == rtnl.RTNUnreachable {
						return stopped
					}
					return viaExitTable
				}
			case rtnl.TableMain:
				if !r.SuppressPrefixLen.OK {
					return escaped
				}
			}
		}
	}
	return stopped
}

// liveAddrs are the global addresses on the tunnel interface.
func (k *fakeKernel) liveAddrs(f rtnl.Family, ifName string) []netip.Addr {
	k.mu.Lock()
	defer k.mu.Unlock()
	idx := uint32(0)
	for _, l := range k.links {
		if l.Name == ifName {
			idx = l.Index
		}
	}
	var out []netip.Addr
	for _, a := range k.addrs[f] {
		if a.Index == idx && a.Global() {
			out = append(out, a.Local.Addr())
		}
	}
	return out
}

func (k *fakeKernel) setAddr(f rtnl.Family, ifName string, a netip.Addr, present bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	idx := uint32(0)
	for _, l := range k.links {
		if l.Name == ifName {
			idx = l.Index
		}
	}
	var kept []rtnl.Addr
	for _, x := range k.addrs[f] {
		if !(x.Index == idx && x.Local.Addr() == a) {
			kept = append(kept, x)
		}
	}
	if present {
		kept = append(kept, rtnl.Addr{Family: f, Index: idx, Local: netip.PrefixFrom(a, a.BitLen())})
	}
	k.addrs[f] = kept
}
