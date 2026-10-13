package policy

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"sort"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// State is what the model judges: the contract, the rules of both families, the
// routes of the tables the snapshot read, the interfaces and the addresses.
type State struct {
	Spec  contract.Spec
	Rules map[rtnl.Family][]rtnl.Rule
	// Routes by family and table; only tables in Known are present. A table
	// that is not known may or may not answer a lookup, and through any device.
	Routes map[rtnl.Family]map[uint32][]rtnl.Route
	Known  map[uint32]bool
	// Live are the global addresses on the tunnel interface, per family.
	Live map[rtnl.Family][]netip.Addr
	// Locals are every address of the namespace (the local table answers for
	// them), per family.
	Locals map[rtnl.Family][]netip.Addr
	// ExitIdx, HostIdx and OverlayIdx are the interface indexes of the
	// contract's interfaces, 0 for one that does not exist.
	ExitIdx, HostIdx, OverlayIdx uint32
}

var families = []rtnl.Family{rtnl.V4, rtnl.V6}

// FromSnapshot builds the state from a snapshot taken for spec.Interest().
func FromSnapshot(spec contract.Spec, snap *rtnl.Snapshot) State {
	s := State{
		Spec:   spec,
		Rules:  map[rtnl.Family][]rtnl.Rule{},
		Routes: map[rtnl.Family]map[uint32][]rtnl.Route{},
		Known:  map[uint32]bool{},
		Live:   map[rtnl.Family][]netip.Addr{},
		Locals: map[rtnl.Family][]netip.Addr{},
	}
	c := spec.Config
	for _, t := range spec.Interest().Tables {
		s.Known[t] = true
	}
	link, haveLink := snap.Link(c.ExitIf)
	if haveLink {
		s.ExitIdx = link.Index
	}
	if l, ok := snap.Link(c.HostIf); ok && c.HostIf != "" {
		s.HostIdx = l.Index
	}
	if l, ok := snap.Link(c.OverlayIf); ok {
		s.OverlayIdx = l.Index
	}
	for _, f := range families {
		s.Rules[f] = sortedRules(snap.Rules[f])
		s.Routes[f] = map[uint32][]rtnl.Route{}
		for t := range s.Known {
			s.Routes[f][t] = snap.RoutesInTable(f, t)
		}
		for _, a := range snap.Addrs[f] {
			s.Locals[f] = append(s.Locals[f], a.Local.Addr())
			if haveLink && a.Index == link.Index && a.Global() {
				s.Live[f] = append(s.Live[f], a.Local.Addr())
			}
		}
	}
	return s
}

func sortedRules(in []rtnl.Rule) []rtnl.Rule {
	out := append([]rtnl.Rule(nil), in...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// clone copies the parts a deletion edits.
func (s State) clone() State {
	out := s
	out.Rules = map[rtnl.Family][]rtnl.Rule{}
	for f, r := range s.Rules {
		out.Rules[f] = append([]rtnl.Rule(nil), r...)
	}
	out.Routes = map[rtnl.Family]map[uint32][]rtnl.Route{}
	for f, m := range s.Routes {
		out.Routes[f] = map[uint32][]rtnl.Route{}
		for t, r := range m {
			out.Routes[f][t] = append([]rtnl.Route(nil), r...)
		}
	}
	return out
}

// WithoutRule returns the state after the kernel deletes the first rule (in
// priority order) that the request names, as rtnl.DeleteMatches defines it,
// and whether there was one.
func (s State) WithoutRule(req rtnl.Rule) (State, bool) {
	out := s.clone()
	rules := out.Rules[req.Family]
	for i, x := range rules {
		if rtnl.DeleteMatches(req, x) {
			out.Rules[req.Family] = append(rules[:i:i], rules[i+1:]...)
			return out, true
		}
	}
	return s, false
}

// WithoutPriority returns the state after the kernel deletes the first rule at
// a priority, whatever it selects.
func (s State) WithoutPriority(f rtnl.Family, priority uint32) (State, bool) {
	out := s.clone()
	rules := out.Rules[f]
	for i, x := range rules {
		if x.Priority == priority {
			out.Rules[f] = append(rules[:i:i], rules[i+1:]...)
			return out, true
		}
	}
	return s, false
}

// WithRule returns the state after the kernel adds a rule: after the rules of
// its priority already there.
func (s State) WithRule(r rtnl.Rule) State {
	out := s.clone()
	rules := out.Rules[r.Family]
	i := len(rules)
	for j, x := range rules {
		if x.Priority > r.Priority {
			i = j
			break
		}
	}
	out.Rules[r.Family] = append(rules[:i:i], append([]rtnl.Rule{r}, rules[i:]...)...)
	return out
}

// WithRoute returns the state after the kernel creates or replaces a route
// (NLM_F_CREATE|NLM_F_REPLACE): a route of the same destination, TOS and
// metric in the table is replaced, otherwise the route is added. A table the
// snapshot did not read is not tracked.
func (s State) WithRoute(r rtnl.Route) State {
	routes, known := s.Routes[r.Family][r.Table]
	if !known {
		return s
	}
	out := s.clone()
	routes = out.Routes[r.Family][r.Table]
	for i, x := range routes {
		if x.Dst == r.Dst && x.Tos == r.Tos && x.Metric == r.Metric && (r.Family == rtnl.V4 || x.Src == r.Src) {
			routes[i] = r
			return out
		}
	}
	out.Routes[r.Family][r.Table] = append(routes, r)
	return out
}

// WithoutRoute returns the state after the kernel deletes the first route of
// the request's table that it names: fib_table_delete for IPv4 (destination,
// TOS, type, metric, scope and protocol when the request gives them, then the
// nexthop's device and gateway) and ip6_route_del for IPv6 (destination,
// source, metric, then device and gateway).
func (s State) WithoutRoute(r rtnl.Route) (State, bool) {
	out := s.clone()
	routes, known := out.Routes[r.Family][r.Table]
	if !known {
		return s, false
	}
	for i, x := range routes {
		if x.Dst != r.Dst || (r.Metric != 0 && x.Metric != r.Metric) {
			continue
		}
		if r.Oif.OK && x.Oif != r.Oif || r.Gateway.IsValid() && x.Gateway != r.Gateway {
			continue
		}
		if r.Family == rtnl.V4 {
			if r.Tos != 0 && x.Tos != r.Tos || r.Type != 0 && x.Type != r.Type || x.Scope != r.Scope || r.Protocol != 0 && x.Protocol != r.Protocol {
				continue
			}
		} else if r.Src.IsValid() && r.Src.Bits() > 0 && x.Src != r.Src {
			continue
		}
		out.Routes[r.Family][r.Table] = append(routes[:i:i], routes[i+1:]...)
		return out, true
	}
	return s, false
}

// ---- outcomes ----

type outKind uint8

const (
	// stopped: the lookup is refused (an unreachable, blackhole or prohibit
	// rule or route, or no rule answered).
	stopped outKind = iota + 1
	// local: the local table answered.
	local
	// viaDev: a route in a table the snapshot read answered, out of a device.
	viaDev
	// viaTable: a table the snapshot did not read may have answered, out of
	// any device.
	viaTable
)

const unknownDev = ^uint32(0)

// Outcome is where a lookup can end: the selected route's disposition.
type Outcome struct {
	Kind  outKind
	Table uint32
	Dev   uint32
	// By identifies the rule whose action ended the walk (a hash of its
	// priority and selectors), so that two paths to the same place through
	// different rules are different outcomes when two states are compared.
	By uint64
	// Cond records the decisions the model could not make on the way (a rule
	// that may or may not apply, a lookup that may or may not answer), as a hash
	// of the sequence: the same place reached under another assumption is
	// another outcome.
	Cond uint64
}

// same ignores By and Cond: where the packet ends, not how it got there.
func (o Outcome) same(x Outcome) bool { o.By, x.By, o.Cond, x.Cond = 0, 0, 0, 0; return o == x }

func (o Outcome) String() string {
	switch o.Kind {
	case stopped:
		return "stopped"
	case local:
		return "local delivery"
	case viaTable:
		return fmt.Sprintf("table %d (not read)", o.Table)
	}
	if o.Dev == unknownDev {
		return fmt.Sprintf("a route of table %d out of an unknown device", o.Table)
	}
	return fmt.Sprintf("a route of table %d out of interface %d", o.Table, o.Dev)
}

// class says which outcomes are safe for a packet.
type class struct {
	name string
	// any: nothing is asked of this packet.
	any bool
	// devs are the devices a route may send it out of; tables the tables not
	// read that may answer it. Being stopped is always safe.
	devs, tables []uint32
}

func (c class) allows(o Outcome) bool {
	if c.any || o.Kind == stopped {
		return true
	}
	switch o.Kind {
	case viaDev:
		for _, d := range c.devs {
			if d == o.Dev && d != 0 && d != unknownDev {
				return true
			}
		}
	case viaTable:
		for _, t := range c.tables {
			if t == o.Table {
				return true
			}
		}
	}
	return false
}

// ---- packets ----

// packet is one point of a class of traffic: every attribute a rule or a route
// selects on that the model can evaluate. Attributes it cannot (a rule's
// unknown attributes, the output interface of the exit's own traffic) make the
// rule one that may or may not apply, and both are followed.
type packet struct {
	f        rtnl.Family
	iif      string
	mark     uint32
	proto    uint8
	src, dst netip.Addr
	// tos is the TOS byte (DSCP and ECN); sport and dport the transport ports;
	// uid the socket owner; l3 says the flow belongs to an l3mdev (VRF).
	tos          uint8
	sport, dport uint16
	uid          uint32
	l3           bool
}

func (p packet) String() string {
	src := "unbound"
	if p.src.IsValid() && !p.src.IsUnspecified() {
		src = p.src.String()
	}
	s := fmt.Sprintf("%s packet in on %s mark %#x ipproto %d from %s to %s", p.f, p.iif, p.mark, p.proto, src, p.dst)
	if p.tos != 0 {
		s += fmt.Sprintf(" tos %#x", p.tos)
	}
	if p.sport != 0 || p.dport != 0 {
		s += fmt.Sprintf(" ports %d>%d", p.sport, p.dport)
	}
	if p.uid != 0 {
		s += fmt.Sprintf(" uid %d", p.uid)
	}
	if p.l3 {
		s += " in a VRF"
	}
	return s
}

type tri uint8

const (
	no tri = iota
	yes
	maybe
)

// matches evaluates a rule's selectors for a packet: yes, no, or maybe when a
// selector the model cannot evaluate exactly (an attribute of a newer kernel, a
// rule that does not parse, the output interface of the exit's own traffic,
// unknown flag bits) decides it. TOS, DSCP, uid and port ranges and l3mdev are
// evaluated: the packet has a value of each.
func matches(r rtnl.Rule, p packet) tri {
	known := yes
	if r.IifName != "" && r.IifName != p.iif {
		known = no
	}
	if known != no && r.OifName != "" && p.iif != "lo" {
		known = no // a forwarded packet has no output interface at the lookup
	}
	if known != no && r.Src.IsValid() && r.Src.Bits() > 0 && (!p.src.IsValid() || !r.Src.Contains(p.src)) {
		known = no
	}
	if known != no && r.Dst.IsValid() && r.Dst.Bits() > 0 && !r.Dst.Contains(p.dst) {
		known = no
	}
	if known != no {
		// As fib_rule_match: (packet mark ^ rule mark) & mask; a dumped rule
		// can carry the mask alone (see EffectiveMark).
		if mark, mask := r.EffectiveMark(); (mark^p.mark)&mask != 0 {
			known = no
		}
	}
	if known != no && r.IPProto.OK && r.IPProto.V != 0 && r.IPProto.V != p.proto {
		known = no
	}
	if known != no && r.Tos != 0 && r.Tos != p.tos {
		known = no
	}
	if known != no && r.L3Mdev.OK && r.L3Mdev.V != 0 && !p.l3 {
		known = no
	}
	ext := r.Ext()
	if known != no && ext.UID != nil && (uint32(p.uid) < ext.UID[0] || uint32(p.uid) > ext.UID[1]) {
		known = no
	}
	if known != no && ext.Sport != nil && (uint32(p.sport) < ext.Sport[0] || uint32(p.sport) > ext.Sport[1]) {
		known = no
	}
	if known != no && ext.Dport != nil && (uint32(p.dport) < ext.Dport[0] || uint32(p.dport) > ext.Dport[1]) {
		known = no
	}
	if known != no && ext.DSCP != nil && p.tos>>2 != *ext.DSCP {
		known = no
	}
	res := known
	if known == yes && (ext.Other || r.Bad || r.ExtraFlags() != 0 || (r.OifName != "" && p.iif == "lo")) {
		res = maybe
	}
	if r.Invert() {
		switch res {
		case yes:
			res = no
		case no:
			res = yes
		}
	}
	return res
}

// ---- lookups ----

// disposition is what one route does with a packet.
func (s State) disposition(rt rtnl.Route) (o Outcome, fall bool) {
	switch rt.Type {
	case rtnl.RTNUnreachable, rtnl.RTNBlackhole, rtnl.RTNProhibit:
		return Outcome{Kind: stopped}, false
	case rtnl.RTNThrow:
		return Outcome{}, true
	case rtnl.RTNUnicast:
		if rt.Oif.OK && !rt.MultiPath && !rt.NHID.OK && !rt.Via && !rt.Encap {
			return Outcome{Kind: viaDev, Table: rt.Table, Dev: rt.Oif.V}, false
		}
	}
	// Multipath, nexthop objects, encapsulation, local and broadcast routes,
	// a gateway with no device: the device is not known.
	return Outcome{Kind: viaDev, Table: rt.Table, Dev: unknownDev}, false
}

// routeApplies says whether a route can answer the packet: its TOS, source and
// input-interface selectors are evaluated, and a route that is dead, down or
// unresolved may or may not be used.
func (s State) routeApplies(rt rtnl.Route, p packet) tri {
	if rt.Family == rtnl.V4 && rt.Tos != 0 && rt.Tos != p.tos {
		return no
	}
	if rt.Src.IsValid() && rt.Src.Bits() > 0 && (!p.src.IsValid() || !rt.Src.Contains(p.src)) {
		return no
	}
	if rt.Iif.OK {
		switch {
		case p.iif == s.Spec.Config.OverlayIf && s.OverlayIdx != 0:
			if rt.Iif.V != s.OverlayIdx {
				return no
			}
		case p.iif == "lo":
			if rt.Iif.V != 1 {
				return no
			}
		default:
			return maybe
		}
	}
	if rt.Flags&(rtnl.RTNHFDead|rtnl.RTNHFLinkdown|rtnl.RTNHFUnresolved) != 0 {
		return maybe
	}
	return yes
}

// lookup follows a rule that looks a table up: the outcomes it can end the
// search in, and whether the search can fall through to the next rule.
func (s State) lookup(r rtnl.Rule, p packet) (outs []Outcome, fall bool) {
	table := r.Table
	if table == rtnl.TableLocal {
		for _, a := range s.Locals[p.f] {
			if a == p.dst {
				return []Outcome{{Kind: local, Table: table}}, false
			}
		}
		if p.dst.IsLoopback() {
			return []Outcome{{Kind: local, Table: table}}, false
		}
		return nil, true
	}
	if !s.Known[table] {
		return []Outcome{{Kind: viaTable, Table: table}}, true
	}
	suppress := -1
	if r.SuppressPrefixLen.OK {
		suppress = int(r.SuppressPrefixLen.V)
	}
	ifgroup := r.SuppressIfGroup.OK
	// The routes that cover the destination, in the kernel's order: the longest
	// prefix first, then (IPv4) a route with a TOS before one without, then by
	// metric.
	var buf [16]rtnl.Route
	cands := buf[:0]
	for _, rt := range s.Routes[p.f][table] {
		if rt.Dst.IsValid() && rt.Dst.Contains(p.dst) {
			cands = append(cands, rt)
		}
	}
	v4 := p.f == rtnl.V4
	less := func(a, b rtnl.Route) bool {
		if a.Dst.Bits() != b.Dst.Bits() {
			return a.Dst.Bits() > b.Dst.Bits()
		}
		if v4 && (a.Tos != 0) != (b.Tos != 0) {
			return a.Tos != 0
		}
		return a.Metric < b.Metric
	}
	for i := 1; i < len(cands); i++ { // insertion sort: stable, and the lists are short
		for j := i; j > 0 && less(cands[j], cands[j-1]); j-- {
			cands[j], cands[j-1] = cands[j-1], cands[j]
		}
	}
	add := func(o Outcome, f bool, b int) {
		if f {
			fall = true
			return
		}
		if o.Kind == stopped { // an error, not a result: nothing suppresses it
			outs = append(outs, o)
			return
		}
		if suppress >= 0 && b <= suppress {
			fall = true // the result is thrown away; the next rule is tried
			return
		}
		outs = append(outs, o)
		if ifgroup {
			fall = true
		}
	}
	for _, rt := range cands {
		switch s.routeApplies(rt, p) {
		case no:
		case maybe:
			o, f := s.disposition(rt)
			add(o, f, rt.Dst.Bits())
		default:
			o, f := s.disposition(rt)
			add(o, f, rt.Dst.Bits())
			return outs, fall
		}
	}
	// No route answered: the lookup falls through.
	return outs, true
}

// ---- the rule walk ----

// walk follows a packet through the rules and returns every place it can end.
// Rules whose selectors the model cannot decide are followed both ways, a
// goto both to its target and past it, and a lookup that can fail both ways.
func (s State) walk(p packet) []Outcome { return s.walkWith(p, ruleHashes(s.Rules[p.f])) }

// walkWith is walk with the hashes of the family's rules (ruleHashes) already made.
func (s State) walkWith(p packet, hashes []uint64) []Outcome {
	rules := s.Rules[p.f]
	n := len(rules)
	// sets[i] are the outcomes of the walk that arrives at rule i.
	sets := make([][]Outcome, n+1)
	sets[n] = []Outcome{{Kind: stopped, By: endHash}} // no rule answered: the lookup fails
	union := func(a, b []Outcome) []Outcome {
		out := append([]Outcome(nil), a...)
		for _, o := range b {
			dup := false
			for _, x := range out {
				if x == o {
					dup = true
					break
				}
			}
			if !dup {
				out = append(out, o)
			}
		}
		return out
	}
	// tag records a decision the model could not make on the outcomes it led to.
	tag := func(set []Outcome, decision uint64) []Outcome {
		out := make([]Outcome, len(set))
		for k, o := range set {
			o.Cond = mix(decision, o.Cond)
			out[k] = o
		}
		return out
	}
	for i := n - 1; i >= 0; i-- {
		r := rules[i]
		m := matches(r, p)
		if m == no {
			sets[i] = sets[i+1]
			continue
		}
		var taken []Outcome
		by := hashes[i]
		switch r.Action {
		case rtnl.FRActToTbl:
			outs, fall := s.lookup(r, p)
			for k := range outs {
				outs[k].By = by
			}
			taken = outs
			if fall && len(outs) > 0 {
				// The table may answer or not: both are followed, and which
				// one is part of the outcome.
				taken = union(tag(outs, mix(by, 1)), tag(sets[i+1], mix(by, 2)))
			} else if fall {
				taken = sets[i+1]
			}
		case rtnl.FRActUnreachable, rtnl.FRActProhibit, rtnl.FRActBlackhole:
			taken = []Outcome{{Kind: stopped, By: by}}
		case rtnl.FRActGoto:
			taken = sets[i+1] // an unresolved goto falls through
			if r.Goto.OK {
				// The kernel resolves the target to the first rule after this
				// one with exactly that priority; with none (it was deleted)
				// the goto does nothing.
				for j := i + 1; j < n; j++ {
					if rules[j].Priority == r.Goto.V {
						taken = sets[j]
						break
					}
				}
			}
		default:
			taken = sets[i+1]
		}
		if m == maybe {
			taken = union(tag(taken, mix(by, 3)), tag(sets[i+1], mix(by, 4)))
		}
		sets[i] = taken
	}
	return sets[0]
}

// ruleKey names a rule by its priority and selectors.
func ruleKey(r rtnl.Rule) string { return fmt.Sprintf("%d %v", r.Priority, r.Items()) }

const endHash = 0x9e3779b97f4a7c15

// ruleHashes gives each rule a 64-bit name made from its priority and selectors:
// the identity outcomes carry. Computing it takes a rule's canonical form, so it
// is done once per state and family, not per packet.
func ruleHashes(rules []rtnl.Rule) []uint64 {
	out := make([]uint64, len(rules))
	for i, r := range rules {
		h := fnv.New64a()
		h.Write([]byte(ruleKey(r)))
		out[i] = h.Sum64() | 1
	}
	return out
}

// mix combines a decision into a sequence of decisions, order sensitive.
func mix(decision, seq uint64) uint64 {
	x := seq*0x9e3779b97f4a7c15 + decision + 0x7f4a7c15
	x ^= x >> 29
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 32
	return x
}
