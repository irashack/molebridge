package policy

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// State is what the model judges: the contract, the rules of both families, the
// routes of the tables the snapshot read, and the addresses live on the tunnel
// interface.
type State struct {
	Spec  contract.Spec
	Rules map[rtnl.Family][]rtnl.Rule
	// Routes by family and table; only tables in Known are present. A table
	// that is not known is assumed to answer every lookup (the worst case).
	Routes map[rtnl.Family]map[uint32][]rtnl.Route
	Known  map[uint32]bool
	// Live are the global addresses on the tunnel interface, per family.
	Live map[rtnl.Family][]netip.Addr
}

// FromSnapshot builds the state from a snapshot taken for spec.Interest().
func FromSnapshot(spec contract.Spec, snap *rtnl.Snapshot) State {
	s := State{
		Spec:   spec,
		Rules:  map[rtnl.Family][]rtnl.Rule{},
		Routes: map[rtnl.Family]map[uint32][]rtnl.Route{},
		Known:  map[uint32]bool{},
		Live:   map[rtnl.Family][]netip.Addr{},
	}
	for _, t := range spec.Interest().Tables {
		s.Known[t] = true
	}
	link, haveLink := snap.Link(spec.Config.ExitIf)
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		s.Rules[f] = append([]rtnl.Rule(nil), snap.Rules[f]...)
		sort.SliceStable(s.Rules[f], func(i, j int) bool { return s.Rules[f][i].Priority < s.Rules[f][j].Priority })
		s.Routes[f] = map[uint32][]rtnl.Route{}
		for t := range s.Known {
			s.Routes[f][t] = snap.RoutesInTable(f, t)
		}
		if haveLink {
			for _, a := range snap.Addrs[f] {
				if a.Index == link.Index && a.Global() {
					s.Live[f] = append(s.Live[f], a.Local.Addr())
				}
			}
		}
	}
	return s
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
// priority order) that has every attribute of req, and whether there was one.
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

// WithoutRoute returns the state after the kernel deletes the route r names:
// the first route of its table with the same destination, type, interface,
// gateway and, when it gives one, metric.
func (s State) WithoutRoute(r rtnl.Route) (State, bool) {
	out := s.clone()
	routes, known := out.Routes[r.Family][r.Table]
	if !known {
		return s, false
	}
	for i, x := range routes {
		if x.Dst == r.Dst && (r.Type == 0 || x.Type == r.Type) && (r.Metric == 0 || x.Metric == r.Metric) && (r.Tos == 0 || x.Tos == r.Tos) &&
			(!r.Oif.OK || x.Oif == r.Oif) && (!r.Gateway.IsValid() || x.Gateway == r.Gateway) {
			out.Routes[r.Family][r.Table] = append(routes[:i:i], routes[i+1:]...)
			return out, true
		}
	}
	return s, false
}

// Outcome is where a lookup ends.
type Outcome struct {
	// Unreachable: the lookup is refused (an unreachable, blackhole or
	// prohibit rule or route, or no rule answered).
	Unreachable bool
	// Table is the table whose route answered.
	Table uint32
}

func (o Outcome) String() string {
	if o.Unreachable {
		return "stopped"
	}
	switch o.Table {
	case rtnl.TableMain:
		return "the main table"
	case rtnl.TableLocal:
		return "local delivery"
	}
	return fmt.Sprintf("table %d", o.Table)
}

// Probe is one class of protected traffic.
type Probe struct {
	Name   string
	Family rtnl.Family
	// Iif is the input interface: the overlay for traffic arriving there, "lo"
	// for what the exit sends itself.
	Iif      string
	Mark     uint32
	Src, Dst netip.Addr
	Proto    uint8
	// DstLocal says Dst is an address of the exit (the local table answers).
	DstLocal bool
	// Allowed are the tables a lookup for the probe may end in; being stopped
	// is always allowed.
	Allowed []uint32
}

func (p Probe) allows(o Outcome) bool {
	if o.Unreachable {
		return true
	}
	for _, t := range p.Allowed {
		if t == o.Table {
			return true
		}
	}
	return false
}

// Violation is a probe that can reach a forbidden place.
type Violation struct {
	Probe   string
	Outcome string
}

func (v Violation) String() string { return fmt.Sprintf("%s reaches %s", v.Probe, v.Outcome) }

var (
	outside4 = netip.MustParseAddr("8.8.8.8")
	outside6 = netip.MustParseAddr("2001:4860:4860::8888")
)

func outside(f rtnl.Family) netip.Addr {
	if f == rtnl.V6 {
		return outside6
	}
	return outside4
}

func icmp(f rtnl.Family) uint8 {
	if f == rtnl.V6 {
		return 58
	}
	return 1
}

// clientAddr is an address inside the overlay, not the exit's own.
func clientAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().Next()
	if p.Bits() >= p.Addr().BitLen()-1 {
		return p.Addr()
	}
	return a.Next()
}

// exitAddr is the exit's own address in the overlay.
func exitAddr(p netip.Prefix) netip.Addr {
	if p.Bits() >= p.Addr().BitLen()-1 {
		return p.Addr()
	}
	return p.Masked().Addr().Next()
}

// Probes lists the classes of protected traffic for the state.
func (s State) Probes() []Probe {
	c := s.Spec.Config
	if c.IsSidecar() {
		return nil
	}
	var out []Probe
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		overlay := c.OverlayFor(f)
		var live []netip.Addr
		live = append(live, s.Live[f]...)
		live = append(live, s.Spec.ReturnPath[f]...)
		live = dedupe(live)
		marks := []uint32{0}
		if c.IsGluetun() {
			marks = []uint32{0, c.ControlMark, c.ControlMark | 0x21, contract.GluetunMark}
		}
		if overlay.IsValid() {
			client := clientAddr(overlay)
			for _, m := range marks {
				out = append(out, Probe{Name: fmt.Sprintf("%s traffic forwarded from %s (mark %#x)", f, c.OverlayIf, m), Family: f,
					Iif: c.OverlayIf, Mark: m, Src: client, Dst: outside(f), Proto: 6, Allowed: []uint32{c.Table}})
			}
			out = append(out, Probe{Name: fmt.Sprintf("%s traffic from %s to the exit's own address", f, c.OverlayIf), Family: f,
				Iif: c.OverlayIf, Src: client, Dst: exitAddr(overlay), Proto: 6, DstLocal: true, Allowed: []uint32{c.Table}})
			if c.IsGluetun() {
				out = append(out, Probe{Name: fmt.Sprintf("%s traffic the exit sends to a client of %s", f, c.OverlayIf), Family: f,
					Iif: "lo", Src: netip.Addr{}, Dst: client, Proto: 1, Allowed: []uint32{rtnl.TableMain}})
			}
		}
		for _, a := range live {
			out = append(out, Probe{Name: fmt.Sprintf("%s ICMP the exit sends from tunnel address %s", f, a), Family: f,
				Iif: "lo", Src: a, Dst: outside(f), Proto: icmp(f), Allowed: []uint32{c.Table}})
		}
		if c.IsGluetun() {
			out = append(out,
				Probe{Name: fmt.Sprintf("%s traffic the exit sends unmarked", f), Family: f,
					Iif: "lo", Dst: outside(f), Proto: 17, Allowed: []uint32{contract.GluetunMark}},
				Probe{Name: fmt.Sprintf("%s control-marked traffic the exit sends (%#x)", f, c.ControlMark), Family: f,
					Iif: "lo", Mark: c.ControlMark, Dst: outside(f), Proto: 17, Allowed: []uint32{c.HostTable}})
		}
	}
	return out
}

func dedupe(addrs []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	for _, a := range addrs {
		if a.IsValid() && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out
}

// Violations lists every class that can reach a place the contract forbids.
func (s State) Violations() []Violation {
	var out []Violation
	for _, p := range s.Probes() {
		for _, o := range s.outcomes(p) {
			if !p.allows(o) {
				out = append(out, Violation{Probe: p.Name, Outcome: o.String()})
				break
			}
		}
	}
	return out
}

// Worsened returns the violations of after that are not in before: classes a
// change turned from safe into an escape. A class that already escaped is not
// counted again.
func Worsened(before, after []Violation) []Violation {
	had := map[string]bool{}
	for _, v := range before {
		had[v.Probe] = true
	}
	var out []Violation
	for _, v := range after {
		if !had[v.Probe] {
			out = append(out, v)
		}
	}
	return out
}

type tri uint8

const (
	no tri = iota
	yes
	maybe
)

// matches evaluates a rule's selectors for a probe.
func matches(r rtnl.Rule, p Probe, overlay netip.Prefix) tri {
	res := yes
	if r.IifName != "" && r.IifName != p.Iif {
		res = no
	}
	if r.OifName != "" {
		res = no // no output interface is known at the lookups modeled
	}
	if res != no && r.Src.IsValid() && r.Src.Bits() > 0 {
		if !p.Src.IsValid() || !r.Src.Contains(p.Src) {
			res = no
		}
	}
	if res != no && r.Dst.IsValid() && r.Dst.Bits() > 0 && !r.Dst.Contains(p.Dst) {
		res = no
	}
	if res != no && r.FwMark.OK {
		mask := uint32(0xffffffff)
		if r.FwMask.OK {
			mask = r.FwMask.V
		}
		if (r.FwMark.V^p.Mark)&mask != 0 {
			res = no
		}
	}
	if res != no && r.IPProto.OK && r.IPProto.V != p.Proto {
		res = no
	}
	if res == yes && (len(r.Unknown) > 0 || r.Tos != 0 || r.L3Mdev.OK || r.Bad || r.SuppressIfGroup.OK) {
		// Selectors the model does not follow: they may exclude the packet.
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

// lookup follows a rule that looks a table up: it ends the search with an
// outcome, or falls through to the next rule.
func (s State) lookup(r rtnl.Rule, p Probe, overlay netip.Prefix) (Outcome, bool) {
	table := r.Table
	if table == rtnl.TableLocal {
		if p.DstLocal {
			return Outcome{Table: table}, true
		}
		return Outcome{}, false
	}
	suppress := -1
	if r.SuppressPrefixLen.OK && r.SuppressPrefixLen.V != 0xffffffff {
		suppress = int(r.SuppressPrefixLen.V)
	}
	if s.Known[table] {
		var best *rtnl.Route
		for i := range s.Routes[p.Family][table] {
			rt := &s.Routes[p.Family][table][i]
			if !rt.Dst.IsValid() || !rt.Dst.Contains(p.Dst) {
				continue
			}
			if best == nil || rt.Dst.Bits() > best.Dst.Bits() || rt.Dst.Bits() == best.Dst.Bits() && rt.Metric < best.Metric {
				best = rt
			}
		}
		if best == nil {
			return Outcome{}, false
		}
		switch best.Type {
		case rtnl.RTNUnreachable, rtnl.RTNBlackhole, rtnl.RTNProhibit:
			return Outcome{Unreachable: true}, true
		case rtnl.RTNThrow:
			return Outcome{}, false
		}
		if suppress >= 0 && best.Dst.Bits() <= suppress {
			return Outcome{}, false
		}
		return Outcome{Table: table}, true
	}
	// A table the snapshot did not read answers with a default route, and the
	// main table also with the overlay's connected route.
	bits := 0
	if table == rtnl.TableMain && overlay.IsValid() && overlay.Contains(p.Dst) {
		bits = overlay.Bits()
	}
	if suppress >= 0 && bits <= suppress {
		return Outcome{}, false
	}
	return Outcome{Table: table}, true
}

// outcomes follows the probe through the rules and returns every place it can
// end (more than one only through rules with selectors the model cannot
// decide).
func (s State) outcomes(p Probe) []Outcome {
	rules := s.Rules[p.Family]
	overlay := s.Spec.Config.OverlayFor(p.Family)
	var out []Outcome
	add := func(o Outcome) {
		for _, x := range out {
			if x == o {
				return
			}
		}
		out = append(out, o)
	}
	for i := 0; i < len(rules); i++ {
		r := rules[i]
		m := matches(r, p, overlay)
		if m == no {
			continue
		}
		var o Outcome
		stop := false
		jump := -1
		switch r.Action {
		case rtnl.FRActToTbl:
			o, stop = s.lookup(r, p, overlay)
		case rtnl.FRActUnreachable, rtnl.FRActProhibit, rtnl.FRActBlackhole:
			o, stop = Outcome{Unreachable: true}, true
		case rtnl.FRActGoto:
			if r.Goto.OK && r.Flags&rtnl.FIBRuleUnresolved == 0 {
				for j := i + 1; j < len(rules); j++ {
					if rules[j].Priority >= r.Goto.V {
						jump = j
						break
					}
				}
			}
		}
		if m == maybe {
			if stop {
				add(o)
			}
			continue
		}
		if stop {
			add(o)
			return out
		}
		if jump >= 0 {
			i = jump - 1
		}
	}
	// No rule answered: the lookup fails.
	add(Outcome{Unreachable: true})
	return out
}
