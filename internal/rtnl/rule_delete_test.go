package rtnl

import (
	"math/rand"
	"net/netip"
	"strings"
	"testing"
)

// kernelRule is a fib_rule as net/core/fib_rules.c holds it: integers, zero
// for "not set", and -1 for the suppressors' "not set".
type kernelRule struct {
	action, table                int
	pref                         uint32
	iif, oif                     string
	mark, markMask               uint32
	suppressIfgroup, suppressLen int64
	l3mdev, ipProto, proto       uint8
	srcLen, dstLen               uint8
	src, dst                     netip.Addr
	tos                          uint8
	unknown                      string
}

// toKernel is fib_nl2rule(): what the kernel makes of a request or a dump
// entry. An attribute that is absent and one that is zero come out the same.
func toKernel(r Rule) kernelRule {
	k := kernelRule{action: int(r.Action), table: int(r.Table), pref: r.Priority, iif: r.IifName, oif: r.OifName,
		suppressIfgroup: -1, suppressLen: -1, tos: r.Tos}
	if r.FwMark.OK {
		k.mark = r.FwMark.V
	}
	if r.FwMask.OK {
		k.markMask = r.FwMask.V
	}
	if r.SuppressIfGroup.OK {
		k.suppressIfgroup = int64(r.SuppressIfGroup.V)
	}
	if r.SuppressPrefixLen.OK {
		k.suppressLen = int64(r.SuppressPrefixLen.V)
	}
	if r.L3Mdev.OK {
		k.l3mdev = r.L3Mdev.V
	}
	if r.IPProto.OK {
		k.ipProto = r.IPProto.V
	}
	if r.Protocol.OK {
		k.proto = r.Protocol.V
	}
	if r.Src.IsValid() {
		k.srcLen, k.src = uint8(r.Src.Bits()), r.Src.Addr()
	}
	if r.Dst.IsValid() {
		k.dstLen, k.dst = uint8(r.Dst.Bits()), r.Dst.Addr()
	}
	for _, u := range r.Unknown {
		k.unknown += string(rune(u.Type)) + string(u.Data) + ";"
	}
	return k
}

// kernelRuleFind is rule_find() of net/core/fib_rules.c, Linux 6.12, with the
// ops->compare of net/ipv4/fib_rules.c (fib4_rule_compare) and
// net/ipv6/fib6_rules.c (fib6_rule_compare), transcribed line for line:
//
//	if (rule->action && r->action != rule->action) continue;
//	if (rule->table && r->table != rule->table) continue;
//	if (user_priority && r->pref != rule->pref) continue;
//	if (rule->iifname[0] && memcmp(r->iifname, rule->iifname, IFNAMSIZ)) continue;
//	if (rule->oifname[0] && memcmp(r->oifname, rule->oifname, IFNAMSIZ)) continue;
//	if (rule->mark && r->mark != rule->mark) continue;
//	if (rule->suppress_ifgroup != -1 && r->suppress_ifgroup != rule->suppress_ifgroup) continue;
//	if (rule->suppress_prefixlen != -1 && r->suppress_prefixlen != rule->suppress_prefixlen) continue;
//	if (rule->mark_mask && r->mark_mask != rule->mark_mask) continue;
//	if (rule->l3mdev && r->l3mdev != rule->l3mdev) continue;
//	if (rule->ip_proto && r->ip_proto != rule->ip_proto) continue;
//	if (rule->proto && r->proto != rule->proto) continue;
//	if (!ops->compare(r, frh, tb)) continue;
//
//	fib4_rule_compare / fib6_rule_compare:
//	if (frh->src_len && (rule->src_len != frh->src_len)) return 0;
//	if (frh->dst_len && (rule->dst_len != frh->dst_len)) return 0;
//	if (frh->tos && (rule->tos != frh->tos)) return 0;
//	if (frh->src_len && (rule->src != nla_get_in_addr(tb[FRA_SRC]))) return 0;
//	if (frh->dst_len && (rule->dst != nla_get_in_addr(tb[FRA_DST]))) return 0;
func kernelRuleFind(rule, r kernelRule) bool {
	if rule.action != 0 && r.action != rule.action {
		return false
	}
	if rule.table != 0 && r.table != rule.table {
		return false
	}
	if r.pref != rule.pref { // user_priority: Rule.Marshal always sends FRA_PRIORITY
		return false
	}
	if rule.iif != "" && r.iif != rule.iif {
		return false
	}
	if rule.oif != "" && r.oif != rule.oif {
		return false
	}
	if rule.mark != 0 && r.mark != rule.mark {
		return false
	}
	if rule.suppressIfgroup != -1 && r.suppressIfgroup != rule.suppressIfgroup {
		return false
	}
	if rule.suppressLen != -1 && r.suppressLen != rule.suppressLen {
		return false
	}
	if rule.markMask != 0 && r.markMask != rule.markMask {
		return false
	}
	if rule.l3mdev != 0 && r.l3mdev != rule.l3mdev {
		return false
	}
	if rule.ipProto != 0 && r.ipProto != rule.ipProto {
		return false
	}
	if rule.proto != 0 && r.proto != rule.proto {
		return false
	}
	if rule.srcLen != 0 && r.srcLen != rule.srcLen {
		return false
	}
	if rule.dstLen != 0 && r.dstLen != rule.dstLen {
		return false
	}
	if rule.tos != 0 && r.tos != rule.tos {
		return false
	}
	if rule.srcLen != 0 && r.src != rule.src {
		return false
	}
	if rule.dstLen != 0 && r.dst != rule.dst {
		return false
	}
	if rule.unknown != "" && r.unknown != rule.unknown {
		return false
	}
	return true
}

func TestDeleteMatchesFollowsTheKernelsPredicate(t *testing.T) {
	zero4 := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	marked := Rule{Family: V4, Priority: 95, Action: FRActToTbl, Table: 51821, IifName: "wt0", FwMark: Some(uint32(0x1bd00)), FwMask: Some(uint32(0xffffffff))}
	unmarked := Rule{Family: V4, Priority: 95, Action: FRActToTbl, Table: 51821, IifName: "wt0"}
	cases := []struct {
		name     string
		req, x   Rule
		wildcard bool
	}{
		{"explicit zero mark is a wildcard: it takes the marked rule", Rule{Family: V4, Priority: 95, Action: FRActToTbl, Table: 51821, IifName: "wt0", FwMark: Some(uint32(0))}, marked, true},
		{"an absent mark is the same", unmarked, marked, true},
		{"explicit zero mask is a wildcard", Rule{Family: V4, Priority: 95, FwMask: Some(uint32(0))}, marked, true},
		{"a mark that differs", Rule{Family: V4, Priority: 95, FwMark: Some(uint32(7))}, marked, false},
		{"explicit zero table and action", Rule{Family: V4, Priority: 95, Action: 0, Table: 0}, marked, true},
		{"the from-all prefix is a wildcard", Rule{Family: V4, Priority: 95, Src: zero4}, marked, true},
		{"explicit zero ip protocol", Rule{Family: V4, Priority: 95, IPProto: Some(uint8(0))}, Rule{Family: V4, Priority: 95, IPProto: Some(uint8(1))}, true},
		{"a different ip protocol", Rule{Family: V4, Priority: 95, IPProto: Some(uint8(6))}, Rule{Family: V4, Priority: 95, IPProto: Some(uint8(1))}, false},
		{"suppress 0 is not a wildcard", Rule{Family: V4, Priority: 91, SuppressPrefixLen: Some(uint32(0))}, Rule{Family: V4, Priority: 91}, false},
		{"suppress 0 against suppress 0", Rule{Family: V4, Priority: 91, SuppressPrefixLen: Some(uint32(0))}, Rule{Family: V4, Priority: 91, SuppressPrefixLen: Some(uint32(0))}, true},
		{"another priority", Rule{Family: V4, Priority: 94}, marked, false},
		{"a protocol that differs", Rule{Family: V4, Priority: 95, Protocol: Some(uint8(3))}, Rule{Family: V4, Priority: 95, Protocol: Some(uint8(2))}, false},
		{"explicit zero protocol", Rule{Family: V4, Priority: 95, Protocol: Some(uint8(0))}, Rule{Family: V4, Priority: 95, Protocol: Some(uint8(2))}, true},
	}
	for _, tc := range cases {
		if got := DeleteMatches(tc.req, tc.x); got != tc.wildcard {
			t.Errorf("%s: DeleteMatches = %v, want %v", tc.name, got, tc.wildcard)
		}
		if got := kernelRuleFind(toKernel(tc.req), toKernel(tc.x)); got != tc.wildcard {
			t.Errorf("%s: the transcribed kernel predicate = %v, want %v", tc.name, got, tc.wildcard)
		}
	}
}

// And against the transcription, over random pairs of rules drawn so that the
// attributes collide often: the two agree on every pair.
func TestDeleteMatchesAgreesWithTheTranscribedPredicate(t *testing.T) {
	rng := rand.New(rand.NewSource(612))
	opt32 := func(vals ...uint32) Opt[uint32] {
		if rng.Intn(3) == 0 {
			return Opt[uint32]{}
		}
		return Some(vals[rng.Intn(len(vals))])
	}
	opt8 := func(vals ...uint8) Opt[uint8] {
		if rng.Intn(3) == 0 {
			return Opt[uint8]{}
		}
		return Some(vals[rng.Intn(len(vals))])
	}
	prefixes := []netip.Prefix{{}, netip.PrefixFrom(netip.IPv4Unspecified(), 0), netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.0.2.9/32"), netip.MustParsePrefix("198.51.100.0/24")}
	random := func() Rule {
		r := Rule{Family: V4, Priority: uint32(94 + rng.Intn(2))}
		r.Action = []uint8{0, FRActToTbl, FRActUnreachable}[rng.Intn(3)]
		r.Table = []uint32{0, 254, 51821}[rng.Intn(3)]
		r.IifName = []string{"", "wt0", "lo"}[rng.Intn(3)]
		r.OifName = []string{"", "wg0"}[rng.Intn(2)]
		r.FwMark, r.FwMask = opt32(0, 1, 0x1bd00), opt32(0, 0xffffffff, 0xff)
		r.SuppressPrefixLen, r.SuppressIfGroup = opt32(0, 1), opt32(0, 1)
		r.L3Mdev, r.IPProto, r.Protocol = opt8(0, 1), opt8(0, 1, 6), opt8(0, 2)
		r.Src, r.Dst = prefixes[rng.Intn(len(prefixes))], prefixes[rng.Intn(len(prefixes))]
		r.Tos = []uint8{0, 0, 16}[rng.Intn(3)]
		if rng.Intn(6) == 0 {
			r.Unknown = []RawAttr{{Type: 99, Data: []byte{byte(rng.Intn(2))}}}
		}
		return r
	}
	// reduce makes a request from a rule by dropping or zeroing some attributes,
	// as a caller naming "the rule like this" does.
	reduce := func(x Rule) Rule {
		r := x
		r.Unknown = append([]RawAttr(nil), x.Unknown...)
		for _, f := range []func(){
			func() { r.Action = 0 }, func() { r.Table = 0 }, func() { r.IifName = "" }, func() { r.OifName = "" },
			func() { r.FwMark = Opt[uint32]{} }, func() { r.FwMark = Some(uint32(0)) }, func() { r.FwMask = Opt[uint32]{} },
			func() { r.FwMask = Some(uint32(0)) }, func() { r.SuppressPrefixLen = Opt[uint32]{} }, func() { r.SuppressIfGroup = Opt[uint32]{} },
			func() { r.L3Mdev = Opt[uint8]{} }, func() { r.IPProto = Opt[uint8]{} }, func() { r.IPProto = Some(uint8(0)) },
			func() { r.Protocol = Opt[uint8]{} }, func() { r.Src = netip.Prefix{} }, func() { r.Dst = netip.Prefix{} },
			func() { r.Tos = 0 }, func() { r.Unknown = nil },
		} {
			if rng.Intn(3) == 0 {
				f()
			}
		}
		return r
	}
	agree := 0
	for i := 0; i < 200000; i++ {
		x := random()
		req := random()
		if i%2 == 0 {
			req = reduce(x)
		}
		got, want := DeleteMatches(req, x), kernelRuleFind(toKernel(req), toKernel(x))
		if got != want {
			t.Fatalf("request %+v against %+v: DeleteMatches %v, kernel %v", req, x, got, want)
		}
		if want {
			agree++
		}
	}
	if agree < 1000 {
		t.Errorf("only %d matching pairs: the draw does not exercise the predicate", agree)
	}
}

// A dump describes "fwmark 0/0xffffffff" as a mask with no mark: the kernel
// puts FRA_FWMARK only when it is nonzero (fib_nl_fill_rule). The rule matches
// only unmarked packets; read as "no mark selector" it would match them all.
func TestAMaskWithoutAMarkIsAZeroMarkSelector(t *testing.T) {
	dumped, err := DecodeRule(Rule{Family: V4, Priority: 95, Action: FRActToTbl, Table: 51821, IifName: "wt0",
		FwMask: Some(uint32(0xffffffff))}.Marshal()) // no FRA_FWMARK attribute, as the kernel dumps it
	if err != nil {
		t.Fatal(err)
	}
	if dumped.FwMark.OK || !dumped.FwMask.OK {
		t.Fatalf("not the shape of a kernel dump: %+v", dumped)
	}
	mark, mask := dumped.EffectiveMark()
	if mark != 0 || mask != 0xffffffff {
		t.Errorf("effective mark %#x/%#x", mark, mask)
	}
	explicit := Rule{Family: V4, Priority: 95, Action: FRActToTbl, Table: 51821, IifName: "wt0", FwMark: Some(uint32(0)), FwMask: Some(uint32(0xffffffff))}
	if got, want := dumped.Items(), explicit.Items(); len(got) != len(want) || got[0] != want[0] {
		t.Errorf("the dumped rule and the one we install differ: %v vs %v", got, want)
	}
	// Defaults of a request: a nonzero mark without a mask gets all ones; no
	// mark and no mask selects nothing; a mask of zero selects nothing.
	for _, tc := range []struct {
		r          Rule
		mark, mask uint32
	}{
		{Rule{FwMark: Some(uint32(7))}, 7, 0xffffffff},
		{Rule{}, 0, 0},
		{Rule{FwMask: Some(uint32(0))}, 0, 0},
		{Rule{FwMark: Some(uint32(0x1bd00)), FwMask: Some(uint32(0xffffff00))}, 0x1bd00, 0xffffff00},
	} {
		if m, k := tc.r.EffectiveMark(); m != tc.mark || k != tc.mask {
			t.Errorf("%+v: %#x/%#x, want %#x/%#x", tc.r, m, k, tc.mark, tc.mask)
		}
	}
	for _, it := range (Rule{Family: V4}).Items() {
		if strings.HasPrefix(it, "fwmark") {
			t.Errorf("a rule without a mark selector has %q", it)
		}
	}
}
