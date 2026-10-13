package policy

import (
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// The model is conservative when it can name, for every concrete packet, a place
// the kernel could send it that the model also names. The oracle below is a
// second, plainly-written lookup for one concrete packet - with a concrete TOS,
// and with every selector the model does not follow decided by a coin per rule
// - and the properties hold it to the model over random rule sets and routes:
//
//   - whatever the oracle does with a point, the model's set of outcomes contains;
//   - whatever the oracle does with any concrete packet - not only the points -
//     that its class forbids, the model's Violations report.

type coins map[int]bool // per rule index (and route) decisions the model cannot make

func (c coins) flip(rng *rand.Rand, key int) bool {
	if v, ok := c[key]; ok {
		return v
	}
	c[key] = rng.Intn(2) == 0
	return c[key]
}

type concrete struct {
	packet
	tos uint8
}

func oracle(s State, q concrete, rng *rand.Rand, cn coins) Outcome {
	rules := s.Rules[q.f]
	for i := 0; i < len(rules); i++ {
		r := rules[i]
		m := true
		if r.IifName != "" && r.IifName != q.iif {
			m = false
		}
		if m && r.OifName != "" {
			m = q.iif == "lo" && cn.flip(rng, 1000+i)
		}
		if m && r.Src.IsValid() && r.Src.Bits() > 0 && (!q.src.IsValid() || !r.Src.Contains(q.src)) {
			m = false
		}
		if m && r.Dst.IsValid() && r.Dst.Bits() > 0 && !r.Dst.Contains(q.dst) {
			m = false
		}
		if m && r.FwMark.OK {
			mask := uint32(0xffffffff)
			if r.FwMask.OK {
				mask = r.FwMask.V
			}
			m = (r.FwMark.V^q.mark)&mask == 0
		}
		if m && r.IPProto.OK && r.IPProto.V != 0 && r.IPProto.V != q.proto {
			m = false
		}
		if m && r.Tos != 0 && r.Tos != q.tos {
			m = false
		}
		if m && (len(r.Unknown) > 0 || r.L3Mdev.OK && r.L3Mdev.V != 0 || r.Bad || r.ExtraFlags() != 0) {
			m = cn.flip(rng, i)
		}
		if r.Invert() {
			m = !m
		}
		if !m {
			continue
		}
		switch r.Action {
		case rtnl.FRActUnreachable, rtnl.FRActProhibit, rtnl.FRActBlackhole:
			return Outcome{Kind: stopped}
		case rtnl.FRActGoto:
			if r.Goto.OK {
				for j := i + 1; j < len(rules); j++ {
					if rules[j].Priority == r.Goto.V {
						i = j - 1
						break
					}
				}
			}
		case rtnl.FRActToTbl:
			if o, ok := oracleLookup(s, r, q, rng, cn, i); ok {
				return o
			}
		}
	}
	return Outcome{Kind: stopped}
}

func oracleLookup(s State, r rtnl.Rule, q concrete, rng *rand.Rand, cn coins, idx int) (Outcome, bool) {
	if r.Table == rtnl.TableLocal {
		for _, a := range s.Locals[q.f] {
			if a == q.dst {
				return Outcome{Kind: local, Table: r.Table}, true
			}
		}
		if q.dst.IsLoopback() {
			return Outcome{Kind: local, Table: r.Table}, true
		}
		return Outcome{}, false
	}
	if !s.Known[r.Table] {
		if cn.flip(rng, 2000+idx) {
			return Outcome{Kind: viaTable, Table: r.Table}, true
		}
		return Outcome{}, false
	}
	// The best route: longest prefix, then the TOS-specific, then lowest metric.
	var best *rtnl.Route
	routes := s.Routes[q.f][r.Table]
	for i := range routes {
		rt := routes[i]
		if !rt.Dst.IsValid() || !rt.Dst.Contains(q.dst) {
			continue
		}
		if rt.Tos != 0 && rt.Tos != q.tos {
			continue
		}
		if rt.Src.IsValid() && rt.Src.Bits() > 0 && (!q.src.IsValid() || !rt.Src.Contains(q.src)) {
			continue
		}
		if rt.Iif.OK && cn.flip(rng, 3000+i) == false {
			continue
		}
		if rt.Flags&(rtnl.RTNHFDead|rtnl.RTNHFLinkdown|rtnl.RTNHFUnresolved) != 0 && cn.flip(rng, 4000+i) {
			continue
		}
		better := best == nil || rt.Dst.Bits() > best.Dst.Bits() ||
			rt.Dst.Bits() == best.Dst.Bits() && (rt.Tos != 0 && best.Tos == 0 || (rt.Tos != 0) == (best.Tos != 0) && rt.Metric < best.Metric)
		if better {
			cp := rt
			best = &cp
		}
	}
	if best == nil {
		return Outcome{}, false
	}
	switch best.Type {
	case rtnl.RTNUnreachable, rtnl.RTNBlackhole, rtnl.RTNProhibit:
		return Outcome{Kind: stopped}, true
	case rtnl.RTNThrow:
		return Outcome{}, false
	}
	if r.SuppressPrefixLen.OK && best.Dst.Bits() <= int(r.SuppressPrefixLen.V) {
		return Outcome{}, false
	}
	if r.SuppressIfGroup.OK && cn.flip(rng, 5000+idx) {
		return Outcome{}, false
	}
	if best.Type == rtnl.RTNUnicast && best.Oif.OK && !best.MultiPath && !best.NHID.OK && !best.Via && !best.Encap {
		return Outcome{Kind: viaDev, Table: best.Table, Dev: best.Oif.V}, true
	}
	return Outcome{Kind: viaDev, Table: best.Table, Dev: unknownDev}, true
}

func has(set []Outcome, o Outcome) bool {
	for _, x := range set {
		if x.same(o) {
			return true
		}
	}
	return false
}

// randomState builds a native or gluetun state, healthy or damaged, with extra
// rules and routes drawn from a pool that includes every selector the model
// handles and those it cannot.
func randomState(rng *rand.Rand, t *testing.T) State {
	var s State
	if rng.Intn(2) == 0 {
		s = nativeState(t)
	} else {
		s = gluetunState(t)
	}
	f := families[rng.Intn(2)]
	s = s.clone()
	pool := []netip.Prefix{{}, zero(f)}
	if f == rtnl.V4 {
		pool = append(pool, netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("203.0.113.1/32"), netip.MustParsePrefix("8.8.8.8/32"),
			netip.MustParsePrefix("198.51.100.0/28"), netip.MustParsePrefix("198.51.100.9/32"))
	} else {
		pool = append(pool, netip.MustParsePrefix("2001:db8:1::/64"), netip.MustParsePrefix("2001:db8:3::1/128"), netip.MustParsePrefix("2001:4860:4860::8888/128"),
			netip.MustParsePrefix("2001:db8:2::/64"))
	}
	pick := func() netip.Prefix { return pool[rng.Intn(len(pool))] }
	for n := rng.Intn(5); n > 0; n-- {
		switch rng.Intn(3) {
		case 0: // delete a rule
			if rs := s.Rules[f]; len(rs) > 0 {
				i := rng.Intn(len(rs))
				s.Rules[f] = append(rs[:i:i], rs[i+1:]...)
			}
		default: // add a rule
			r := rtnl.Rule{Family: f, Priority: uint32(rng.Intn(120)), Action: []uint8{rtnl.FRActToTbl, rtnl.FRActToTbl, rtnl.FRActUnreachable, rtnl.FRActGoto, rtnl.FRActNop}[rng.Intn(5)]}
			if r.Action == rtnl.FRActToTbl {
				r.Table = []uint32{rtnl.TableMain, rtnl.TableLocal, 51821, 200, 51822, 51820}[rng.Intn(6)]
				if rng.Intn(4) == 0 {
					r.SuppressPrefixLen = rtnl.Some(uint32(rng.Intn(2)))
				}
				if rng.Intn(6) == 0 {
					r.SuppressIfGroup = rtnl.Some(uint32(1))
				}
			}
			if r.Action == rtnl.FRActGoto {
				r.Goto = rtnl.Some(uint32(r.Priority + 1 + uint32(rng.Intn(60))))
			}
			if rng.Intn(2) == 0 {
				r.IifName = []string{"wt0", "lo", s.Spec.Config.ExitIf}[rng.Intn(3)]
			}
			if rng.Intn(5) == 0 {
				r.OifName = s.Spec.Config.ExitIf
			}
			if rng.Intn(3) == 0 {
				r.Src = pick()
			}
			if rng.Intn(3) == 0 {
				r.Dst = pick()
			}
			if rng.Intn(3) == 0 {
				r.FwMark, r.FwMask = rtnl.Some(uint32([]uint32{0, 7, 0x1bd00, 51820}[rng.Intn(4)])), rtnl.Some(uint32(0xffffffff))
			}
			if rng.Intn(4) == 0 {
				r.IPProto = rtnl.Some(uint8([]uint8{0, 1, 6, 17, 58}[rng.Intn(5)]))
			}
			if rng.Intn(5) == 0 {
				r.Tos = 16
			}
			if rng.Intn(8) == 0 {
				r.Unknown = []rtnl.RawAttr{{Type: 99, Data: []byte{1}}}
			}
			if rng.Intn(8) == 0 {
				r.L3Mdev = rtnl.Some(uint8(1))
			}
			if rng.Intn(4) == 0 {
				r.Flags |= rtnl.FIBRuleInvert
			}
			s.Rules[f] = append(s.Rules[f], r)
		}
	}
	// Routes in the known tables.
	for tb := range s.Known {
		routes := s.Routes[f][tb]
		for n := rng.Intn(3); n > 0; n-- {
			switch rng.Intn(3) {
			case 0:
				if len(routes) > 0 {
					i := rng.Intn(len(routes))
					routes = append(routes[:i:i], routes[i+1:]...)
				}
			default:
				rt := rtnl.Route{Family: f, Dst: []netip.Prefix{zero(f), pick()}[rng.Intn(2)], Table: tb, Type: []uint8{rtnl.RTNUnicast, rtnl.RTNUnicast, rtnl.RTNUnreachable, rtnl.RTNThrow, rtnl.RTNBlackhole}[rng.Intn(5)],
					Metric: uint32(rng.Intn(3)) * 100, Oif: rtnl.Some([]uint32{exitIdx, hostIdx, overlayIdx}[rng.Intn(3)])}
				if !rt.Dst.IsValid() {
					rt.Dst = zero(f)
				}
				switch rng.Intn(8) {
				case 0:
					rt.Tos = 16
				case 1:
					rt.Src = pick()
				case 2:
					rt.Iif = rtnl.Some(uint32(overlayIdx))
				case 3:
					rt.Flags = rtnl.RTNHFLinkdown
				case 4:
					rt.MultiPath = true
				}
				routes = append(routes, rt)
			}
		}
		s.Routes[f][tb] = routes
	}
	sortRules(&s, f)
	return s
}

func TestTheModelContainsWhatTheOracleDoes(t *testing.T) {
	rng := rand.New(rand.NewSource(20261014))
	checked := 0
	for i := 0; i < 600; i++ {
		s := randomState(rng, t)
		pts := allPoints(s)
		for k := 0; k < 40; k++ {
			p := pts[rng.Intn(len(pts))]
			set := s.walk(p)
			for trial := 0; trial < 6; trial++ {
				q := concrete{packet: p, tos: []uint8{0, 16}[rng.Intn(2)]}
				got := oracle(s, q, rng, coins{})
				if !has(set, got) {
					t.Fatalf("state %d: the kernel can send %v to %v but the model says only %v (tos %d)\nrules %v\nroutes %+v", i, p, got, set, q.tos, ruleLines(s, p.f), s.Routes[p.f][51822])
				}
				checked++
			}
		}
	}
	t.Logf("%d concrete lookups contained", checked)
}

func ruleLines(s State, f rtnl.Family) []string {
	var out []string
	for _, r := range s.Rules[f] {
		out = append(out, fmt.Sprintf("%d: %s", r.Priority, r.String()))
	}
	return out
}

// Any concrete packet the oracle lets through a class's limits is reported by
// Violations, which only looks at the points.
func TestAnEscapeOfAnyConcretePacketIsAViolationOfSomePoint(t *testing.T) {
	rng := rand.New(rand.NewSource(20261015))
	addrs := func(f rtnl.Family) []netip.Addr {
		var out []netip.Addr
		for _, s := range []string{"192.0.2.1", "192.0.2.77", "193.0.2.1", "203.0.113.1", "203.0.113.2", "8.8.8.8", "8.8.4.4", "198.51.100.1", "198.51.100.9", "198.51.100.200", "0.0.0.0", "127.0.0.1"} {
			a := netip.MustParseAddr(s)
			if f == rtnl.V4 {
				out = append(out, a)
			}
		}
		for _, s := range []string{"2001:db8:1::1", "2001:db8:1::77", "2001:db8:3::1", "2001:db8:3::2", "2001:4860:4860::8888", "2001:4860:4860::8844", "2001:db8:2::1", "2001:db8:2::9", "::", "::1"} {
			a := netip.MustParseAddr(s)
			if f == rtnl.V6 {
				out = append(out, a)
			}
		}
		return out
	}
	found, escapes := 0, 0
	for i := 0; i < 1000; i++ {
		s := randomState(rng, t)
		violations := len(s.Violations()) > 0
		prot := map[rtnl.Family]map[netip.Addr]bool{4: s.protectedAddrs(4), 6: s.protectedAddrs(6)}
		hosts := map[rtnl.Family][]netip.Prefix{4: s.hostSubnets(4), 6: s.hostSubnets(6)}
		for k := 0; k < 200; k++ {
			f := families[rng.Intn(2)]
			as := addrs(f)
			q := concrete{packet: packet{f: f, iif: []string{s.Spec.Config.OverlayIf, "lo"}[rng.Intn(2)],
				mark: []uint32{0, 7, 0x1bd00, 0x1bd21, 51820}[rng.Intn(5)], proto: []uint8{1, 6, 17, 58, 253}[rng.Intn(5)],
				src: as[rng.Intn(len(as))], dst: as[rng.Intn(len(as))]}, tos: []uint8{0, 16}[rng.Intn(2)]}
			if q.dst.IsUnspecified() {
				continue
			}
			cl := s.classify(q.packet, prot[f], hosts[f])
			if cl.any {
				continue
			}
			found++
			if o := oracle(s, q, rng, coins{}); !cl.allows(o) {
				escapes++
				if !violations {
					t.Fatalf("state %d: %v can reach %v (class %q) and Violations is empty\nrules %v", i, q.packet, o, cl.name, ruleLines(s, f))
				}
			}
		}
	}
	t.Logf("%d classified packets, %d escapes found by the oracle, all reported", found, escapes)
	if escapes < 100 {
		t.Errorf("the draw produces too few escapes (%d) to test anything", escapes)
	}
}

// A deletion the model approves does not give the oracle a new escape: for a
// packet that was safe before (under the same coins) and escapes after, the
// model must have said so.
func TestAnApprovedDeletionOpensNothingTheOracleCanFind(t *testing.T) {
	rng := rand.New(rand.NewSource(20261016))
	approved := 0
	for i := 0; i < 600; i++ {
		s := randomState(rng, t)
		f := families[rng.Intn(2)]
		rs := s.Rules[f]
		if len(rs) == 0 {
			continue
		}
		del := rs[rng.Intn(len(rs))]
		after, ok := s.WithoutRule(del)
		if !ok {
			continue
		}
		worse := Worsens(s, after)
		if len(worse) > 0 {
			continue
		}
		approved++
		pts := allPoints(s, after)
		prot := map[rtnl.Family]map[netip.Addr]bool{4: s.protectedAddrs(4), 6: s.protectedAddrs(6)}
		hosts := map[rtnl.Family][]netip.Prefix{4: s.hostSubnets(4), 6: s.hostSubnets(6)}
		sort.Slice(pts, func(a, b int) bool { return pts[a].String() < pts[b].String() })
		for k := 0; k < 100; k++ {
			p := pts[rng.Intn(len(pts))]
			cl := s.classify(p, prot[p.f], hosts[p.f])
			if cl.any {
				continue
			}
			q := concrete{packet: p, tos: []uint8{0, 16}[rng.Intn(2)]}
			seed := rng.Int63()
			before := oracle(s, q, rand.New(rand.NewSource(seed)), coins{})
			afterO := oracle(after, q, rand.New(rand.NewSource(seed)), coins{})
			// The coins are drawn per rule index, and a deletion renumbers the
			// rules, so only compare when the same coins cannot differ: states
			// whose rules have no coin-dependent selector.
			if cl.allows(before) && !cl.allows(afterO) && !hasCoinRules(s, f) {
				t.Fatalf("state %d: deleting %s opened %v to %v (class %q) and the model approved", i, del.String(), p, afterO, cl.name)
			}
		}
	}
	t.Logf("%d deletions approved, none opened a packet the oracle could find", approved)
}

func hasCoinRules(s State, f rtnl.Family) bool {
	for _, r := range s.Rules[f] {
		if len(r.Unknown) > 0 || r.L3Mdev.OK || r.OifName != "" || r.SuppressIfGroup.OK || r.ExtraFlags() != 0 {
			return true
		}
	}
	for _, rs := range s.Routes[f] {
		for _, rt := range rs {
			if rt.Iif.OK || rt.Flags != 0 {
				return true
			}
		}
	}
	for _, r := range s.Rules[f] {
		if !s.Known[r.Table] && r.Action == rtnl.FRActToTbl && r.Table != rtnl.TableLocal {
			return true
		}
	}
	return false
}

var _ = contract.GluetunMark
