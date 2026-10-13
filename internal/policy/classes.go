package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// The classes of traffic the contract protects, as selector-defined sets of
// packets, not samples.
//
//   - Anything arriving on the overlay interface, in both families whatever
//     overlay prefixes are configured: only the tunnel (or nothing) may carry
//     it, and local delivery is never an answer.
//   - What the exit sends from a tunnel address (live, or expected by the
//     contract) in ICMP: the tunnel or nothing.
//   - With gluetun, what the exit itself sends: control-marked traffic leaves by
//     the host interface or not at all; traffic for a client by the overlay or
//     not at all; other traffic, unbound or from the tunnel address, by
//     gluetun's tunnel (its table is not read) or not at all. Traffic gluetun's
//     own socket marks, traffic for the namespace's own addresses, traffic for
//     the host's subnets and traffic from the host's own addresses is the host's.
//
// A class's points are found by partition refinement: every prefix boundary in
// any rule or route selector, every mark and protocol the rules select on, is
// a candidate; candidates the rules and the classes cannot tell apart are one
// point. The points are taken from all the states being compared together, so
// that a deletion is judged on the same packets before and after.

// classify says what is asked of a packet, and whether anything is.
func (s State) classify(p packet, prot map[netip.Addr]bool, hostSubnets []netip.Prefix) class {
	c := s.Spec.Config
	if p.iif == c.OverlayIf {
		return class{name: "traffic arriving on " + c.OverlayIf, devs: []uint32{s.ExitIdx}}
	}
	if p.iif != "lo" {
		return class{any: true}
	}
	// The exit's own traffic. What stays in the namespace is not asked of.
	for _, a := range s.Locals[p.f] {
		if a == p.dst {
			return class{any: true}
		}
	}
	if p.dst.IsLoopback() {
		return class{any: true}
	}
	icmp := p.proto == 1 && p.f == rtnl.V4 || p.proto == 58 && p.f == rtnl.V6
	fromTunnel := prot[p.src]
	if c.IsGluetun() {
		switch {
		case p.mark == c.ControlMark:
			return class{name: "control-marked traffic the exit sends", devs: []uint32{s.HostIdx}}
		case p.mark == contract.GluetunMark:
			return class{any: true} // gluetun's own socket
		}
		if ov := c.OverlayFor(p.f); ov.IsValid() && ov.Contains(p.dst) {
			return class{name: "traffic the exit sends to a client of " + c.OverlayIf, devs: []uint32{s.OverlayIdx}}
		}
		if fromTunnel && icmp {
			return class{name: "ICMP the exit sends from a tunnel address", devs: []uint32{s.ExitIdx}}
		}
		for _, h := range hostSubnets {
			if h.Contains(p.dst) {
				return class{any: true}
			}
		}
		if !p.src.IsValid() || p.src.IsUnspecified() || fromTunnel {
			return class{name: "unmarked traffic the exit sends", devs: []uint32{s.ExitIdx}, tables: []uint32{contract.GluetunMark}}
		}
		return class{any: true}
	}
	if fromTunnel && icmp {
		return class{name: "ICMP the exit sends from a tunnel address", devs: []uint32{s.ExitIdx}}
	}
	return class{any: true}
}

// protectedAddrs are the tunnel addresses whose ICMP is protected: the live
// ones and those the contract expects.
func (s State) protectedAddrs(f rtnl.Family) map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	for _, a := range s.Live[f] {
		out[a] = true
	}
	for _, a := range s.Spec.ReturnPath[f] {
		out[a] = true
	}
	return out
}

// hostSubnets are the host's own subnets: the destinations of the non-default
// routes through the host interface in the host table and in the main table.
// gluetun sends traffic for them to the host on purpose.
func (s State) hostSubnets(f rtnl.Family) []netip.Prefix {
	c := s.Spec.Config
	if !c.IsGluetun() {
		return nil
	}
	var out []netip.Prefix
	for _, table := range []uint32{c.HostTable, rtnl.TableMain} {
		for _, rt := range s.Routes[f][table] {
			if rt.Dst.IsValid() && rt.Dst.Bits() > 0 && rt.Oif.OK && rt.Oif.V == s.HostIdx && s.HostIdx != 0 {
				out = append(out, rt.Dst)
			}
		}
	}
	return out
}

// ---- points ----

func boundaryPoints(p netip.Prefix) []netip.Addr {
	if !p.IsValid() {
		return nil
	}
	p = p.Masked()
	first := p.Addr()
	last := first
	bits := first.BitLen()
	b := first.AsSlice()
	for i := p.Bits(); i < bits; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	last, _ = netip.AddrFromSlice(b)
	out := []netip.Addr{first, last}
	if prev := first.Prev(); prev.IsValid() {
		out = append(out, prev)
	}
	if next := last.Next(); next.IsValid() {
		out = append(out, next)
	}
	return out
}

func zeroAddr(f rtnl.Family) netip.Addr {
	if f == rtnl.V6 {
		return netip.IPv6Unspecified()
	}
	return netip.IPv4Unspecified()
}

func otherAddr(f rtnl.Family) netip.Addr {
	if f == rtnl.V6 {
		return netip.MustParseAddr("2001:4860:4860::8888")
	}
	return netip.MustParseAddr("8.8.8.8")
}

// sig builds a signature string from yes/no facts.
type sig struct{ b strings.Builder }

func (s *sig) add(v bool) {
	if v {
		s.b.WriteByte('1')
	} else {
		s.b.WriteByte('0')
	}
}

// points returns the packets to judge for a family, refined over every state.
func points(f rtnl.Family, states ...State) []packet {
	base := states[0]
	c := base.Spec.Config
	var rules []rtnl.Rule
	var routes []rtnl.Route
	prot := map[netip.Addr]bool{}
	locals := map[netip.Addr]bool{}
	var hostSubnets []netip.Prefix
	for _, st := range states {
		rules = append(rules, st.Rules[f]...)
		for _, rs := range st.Routes[f] {
			routes = append(routes, rs...)
		}
		for a := range st.protectedAddrs(f) {
			prot[a] = true
		}
		for _, a := range st.Locals[f] {
			locals[a] = true
		}
		hostSubnets = append(hostSubnets, st.hostSubnets(f)...)
	}
	// Candidate addresses.
	var prefixes []netip.Prefix
	for _, r := range rules {
		prefixes = append(prefixes, r.Src, r.Dst)
	}
	for _, r := range routes {
		prefixes = append(prefixes, r.Dst, r.Src)
	}
	prefixes = append(prefixes, c.OverlayFor(f))
	prefixes = append(prefixes, hostSubnets...)
	for a := range prot {
		prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
	}
	for a := range locals {
		prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
	}
	cand := map[netip.Addr]bool{zeroAddr(f): true, otherAddr(f): true}
	for _, p := range prefixes {
		if !p.IsValid() {
			continue
		}
		for _, a := range boundaryPoints(p) {
			if a.Is4() == (f == rtnl.V4) {
				cand[a] = true
			}
		}
	}
	addrs := make([]netip.Addr, 0, len(cand))
	for a := range cand {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	ov := c.OverlayFor(f)
	isLocal := func(a netip.Addr) bool { return locals[a] || a.IsLoopback() }
	// Source and destination addresses: one point for each set of candidates no
	// rule selector, route, or class can tell apart.
	srcSig := func(a netip.Addr) string {
		var g sig
		for _, r := range rules {
			g.add(r.Src.IsValid() && r.Src.Bits() > 0 && r.Src.Contains(a))
		}
		for _, r := range routes {
			g.add(r.Src.IsValid() && r.Src.Bits() > 0 && r.Src.Contains(a))
		}
		g.add(a.IsUnspecified())
		g.add(prot[a])
		g.add(isLocal(a))
		return g.b.String()
	}
	dstSig := func(a netip.Addr) string {
		var g sig
		for _, r := range rules {
			g.add(r.Dst.IsValid() && r.Dst.Bits() > 0 && r.Dst.Contains(a))
		}
		for _, r := range routes {
			g.add(r.Dst.IsValid() && r.Dst.Contains(a))
		}
		g.add(isLocal(a))
		g.add(ov.IsValid() && ov.Contains(a))
		for _, h := range hostSubnets {
			g.add(h.Contains(a))
		}
		return g.b.String()
	}
	pick := func(sigOf func(netip.Addr) string) []netip.Addr {
		seen := map[string]bool{}
		var out []netip.Addr
		for _, a := range addrs {
			k := sigOf(a)
			if !seen[k] {
				seen[k] = true
				out = append(out, a)
			}
		}
		return out
	}
	srcs := pick(srcSig)
	// A destination is never the unspecified address; it must not stand in for
	// the others it cannot be told apart from.
	dsts := pick(func(a netip.Addr) string {
		if a.IsUnspecified() {
			return "unspecified"
		}
		return dstSig(a)
	})
	// Marks: the values the rules select on, their complements within the mask,
	// the contract's, none and everything.
	markSet := map[uint32]bool{0: true, 0xffffffff: true, c.ControlMark: true, c.ControlMark | 0x21: true, contract.GluetunMark: true}
	for _, r := range rules {
		if mark, mask := r.EffectiveMark(); mask != 0 {
			markSet[mark] = true
			markSet[mark^mask] = true
			markSet[mark^(mask&-mask)] = true // differs in the lowest bit the rule looks at
		}
	}
	var marks []uint32
	for m := range markSet {
		marks = append(marks, m)
	}
	sort.Slice(marks, func(i, j int) bool { return marks[i] < marks[j] })
	markSigs := map[string]bool{}
	var mk []uint32
	for _, m := range marks {
		var g sig
		for _, r := range rules {
			mark, mask := r.EffectiveMark()
			g.add(mask != 0 && (mark^m)&mask == 0)
		}
		g.add(m == c.ControlMark)
		g.add(m == contract.GluetunMark)
		if k := g.b.String(); !markSigs[k] {
			markSigs[k] = true
			mk = append(mk, m)
		}
	}
	// Protocols: those rules select on, ICMP, TCP, UDP and another.
	icmp := uint8(1)
	if f == rtnl.V6 {
		icmp = 58
	}
	protoSet := map[uint8]bool{icmp: true, 6: true, 17: true, 253: true}
	for _, r := range rules {
		if r.IPProto.OK && r.IPProto.V != 0 {
			protoSet[r.IPProto.V] = true
		}
	}
	var protos []uint8
	for p := range protoSet {
		protos = append(protos, p)
	}
	sort.Slice(protos, func(i, j int) bool { return protos[i] < protos[j] })
	var out []packet
	for _, iif := range []string{c.OverlayIf, "lo"} {
		for _, m := range mk {
			for _, pr := range protos {
				for _, s := range srcs {
					for _, d := range dsts {
						if d.IsUnspecified() {
							continue
						}
						out = append(out, packet{f: f, iif: iif, mark: m, proto: pr, src: s, dst: d})
					}
				}
			}
		}
	}
	return out
}

// Violation is a packet that can reach a place the contract forbids.
type Violation struct {
	Class   string
	Packet  string
	Outcome string
}

func (v Violation) String() string {
	return fmt.Sprintf("%s: a %s can reach %s", v.Class, v.Packet, v.Outcome)
}

// judge returns the violations of one state over the given points.
func judge(s State, pts []packet) []Violation {
	var out []Violation
	cls := s.classifier()
	for _, p := range pts {
		cl := cls(p)
		if cl.any {
			continue
		}
		for _, o := range s.walk(p) {
			if !cl.allows(o) {
				out = append(out, Violation{Class: cl.name, Packet: p.String(), Outcome: o.String()})
				break
			}
		}
	}
	return out
}

// classifier returns the state's classification of a packet.
func (s State) classifier() func(packet) class {
	prot := map[rtnl.Family]map[netip.Addr]bool{}
	hosts := map[rtnl.Family][]netip.Prefix{}
	for _, f := range families {
		prot[f] = s.protectedAddrs(f)
		hosts[f] = s.hostSubnets(f)
	}
	return func(p packet) class { return s.classify(p, prot[p.f], hosts[p.f]) }
}

func allPoints(states ...State) []packet {
	var pts []packet
	for _, f := range families {
		pts = append(pts, points(f, states...)...)
	}
	return pts
}

// Violations lists every protected packet that can reach a forbidden place.
func (s State) Violations() []Violation {
	if s.Spec.Config.IsSidecar() {
		return nil
	}
	return judge(s, allPoints(s))
}

// Worsens returns what a change opens: for every point, every outcome that
// the walk can end in after the change, was not possible before it, and the
// class forbids. The comparison is point by point and path by path - an
// outcome includes the rule that produced it - and never collapses a point to
// "already escaping": a point that could escape one way before and gains
// another is refused, because an escape that was merely possible must not hide
// one that has become real. When the two walks differ in a way that cannot be
// told to be safe, the answer is to refuse.
func Worsens(before, after State) []Violation {
	if before.Spec.Config.IsSidecar() {
		return nil
	}
	clsAfter := after.classifier()
	var out []Violation
	for _, p := range allPoints(before, after) {
		cl := clsAfter(p)
		if cl.any {
			continue
		}
		prior := before.walk(p)
		for _, o := range after.walk(p) {
			if cl.allows(o) {
				continue
			}
			known := false
			for _, x := range prior {
				if x == o {
					known = true
					break
				}
			}
			if !known {
				out = append(out, Violation{Class: cl.name, Packet: p.String(), Outcome: o.String()})
			}
		}
	}
	return out
}
