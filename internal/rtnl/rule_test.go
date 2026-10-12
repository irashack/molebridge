package rtnl

import (
	"net/netip"
	"reflect"
	"testing"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// contractRules are the shapes the routing contract installs, as a kernel
// would report them after `ip rule add`.
func contractRules() map[string]Rule {
	return map[string]Rule{
		"local guard": {Family: V4, Priority: 1, Action: FRActToTbl, Table: TableLocal,
			Flags: FIBRuleInvert, IifName: "wt0"},
		"mark to host table": {Family: V4, Priority: 88, Action: FRActToTbl, Table: 51822,
			IifName: "lo", FwMark: Some(uint32(0x1bd00)), FwMask: Some(uint32(0xffffffff))},
		"mark unreachable": {Family: V4, Priority: 89, Action: FRActUnreachable,
			IifName: "lo", FwMark: Some(uint32(0x1bd00)), FwMask: Some(uint32(0xffffffff))},
		"tunnel replies": {Family: V6, Priority: 90, Action: FRActToTbl, Table: TableMain,
			IifName: "wg0", Dst: pfx("2001:db8:1::/64")},
		"suppress": {Family: V4, Priority: 91, Action: FRActToTbl, Table: TableMain,
			IifName: "lo", Dst: pfx("192.0.2.0/24"), SuppressPrefixLen: Some(uint32(0))},
		"icmp return": {Family: V6, Priority: 94, Action: FRActToTbl, Table: 51821,
			Src: pfx("2001:db8:3::1/128"), IPProto: Some(uint8(58))},
		"icmp backstop": {Family: V4, Priority: 98, Action: FRActUnreachable,
			Src: pfx("203.0.113.1/32"), IPProto: Some(uint8(1))},
		"big table":   {Family: V4, Priority: 95, Action: FRActToTbl, Table: 2147483647, IifName: "wt0"},
		"unreachable": {Family: V4, Priority: 97, Action: FRActUnreachable, IifName: "wt0"},
	}
}

func TestRuleRoundTrip(t *testing.T) {
	for name, want := range contractRules() {
		t.Run(name, func(t *testing.T) {
			got, err := DecodeRule(want.Marshal())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip\n got  %+v\n want %+v", got, want)
			}
			if got.Bad {
				t.Fatal("round trip flagged bad")
			}
		})
	}
}

func TestRuleTableAboveTheHeaderByte(t *testing.T) {
	r := contractRules()["big table"]
	b := r.Marshal()
	if b[4] != tableCompat {
		t.Fatalf("header table %d, want RT_TABLE_COMPAT", b[4])
	}
	got, err := DecodeRule(b)
	if err != nil || got.Table != 2147483647 {
		t.Fatalf("FRA_TABLE not preferred over the header: %+v %v", got, err)
	}
	// A kernel that sends no FRA_TABLE for a small table: the header decides.
	hdr := make([]byte, 12)
	hdr[0], hdr[4], hdr[7] = afInet, 254, FRActToTbl
	hdr = appendAttrU32(hdr, fraPriority, 32766)
	got, err = DecodeRule(hdr)
	if err != nil || got.Table != 254 || got.Priority != 32766 {
		t.Fatalf("header table: %+v %v", got, err)
	}
}

func TestDecodeKeepsEveryUnknownAttributeRaw(t *testing.T) {
	r := contractRules()["unreachable"]
	b := r.Marshal()
	// FRA_UID_RANGE (20), FRA_SPORT_RANGE (23) and a type nobody defined.
	b = appendAttr(b, 20, []byte{1, 0, 0, 0, 2, 0, 0, 0})
	b = appendAttr(b, 23, []byte{80, 0, 80, 0})
	b = appendAttr(b, 999, []byte{1, 2, 3})
	got, err := DecodeRule(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Unknown) != 3 || got.Unknown[0].Type != 20 || got.Unknown[2].Type != 999 {
		t.Fatalf("unknown attributes lost: %+v", got.Unknown)
	}
	if reflect.DeepEqual(got.Items(), r.Items()) {
		t.Fatal("a rule with extra selectors compares equal to the plain rule")
	}
	// The raw attributes go back out unchanged, so the rule can be deleted.
	again, err := DecodeRule(got.Marshal())
	if err != nil || !reflect.DeepEqual(again.Unknown, got.Unknown) {
		t.Fatalf("unknown attributes not preserved on re-encoding: %+v %v", again.Unknown, err)
	}
}

func TestWrongShapeAttributesAreKeptNotDropped(t *testing.T) {
	hdr := make([]byte, 12)
	hdr[0], hdr[7] = afInet, FRActUnreachable
	hdr = appendAttr(hdr, fraFwmark, []byte{1, 2}) // two bytes where four belong
	hdr = appendAttr(hdr, fraIPProto, []byte{1, 2})
	got, err := DecodeRule(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if got.FwMark.OK || got.IPProto.OK || len(got.Unknown) != 2 {
		t.Fatalf("%+v", got)
	}
}

func TestPrefixWithoutAddressIsBad(t *testing.T) {
	hdr := make([]byte, 12)
	hdr[0], hdr[1], hdr[7] = afInet, 24, FRActUnreachable
	got, err := DecodeRule(hdr)
	if err != nil || !got.Bad {
		t.Fatalf("dst_len without FRA_DST must be flagged: %+v %v", got, err)
	}
	if !contains(got.Items(), "bad") {
		t.Fatal("a bad rule must not compare equal to any expected rule")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestItems(t *testing.T) {
	cases := []struct {
		name string
		rule Rule
		want []string
	}{
		{"local guard", contractRules()["local guard"], []string{"from all", "iif wt0", "lookup 255", "not"}},
		{"mark exact", contractRules()["mark to host table"], []string{"from all", "fwmark 0x1bd00", "iif lo", "lookup 51822"}},
		{"mark with a partial mask", Rule{Family: V4, Action: FRActUnreachable, FwMark: Some(uint32(0x1bd00)),
			FwMask: Some(uint32(0xff00))}, []string{"from all", "fwmark 0x1bd00/0xff00", "unreachable"}},
		{"icmp", contractRules()["icmp return"], []string{"from 2001:db8:3::1/128", "ipproto ipv6-icmp", "lookup 51821"}},
		{"permanent default rule", Rule{Family: V4, Action: FRActToTbl, Table: TableLocal, Flags: FIBRulePermanent},
			[]string{"from all", "lookup 255"}},
		{"detached is not a selector", Rule{Family: V4, Action: FRActUnreachable, IifName: "x", Flags: FIBRuleIifDetached},
			[]string{"from all", "iif x", "unreachable"}},
		{"unknown flag", Rule{Family: V4, Action: FRActUnreachable, Flags: 0x100},
			[]string{"flags 0x100", "from all", "unreachable"}},
	}
	for _, c := range cases {
		if got := c.rule.Items(); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDecodeRejectsTruncatedAndOverlongInput(t *testing.T) {
	good := contractRules()["tunnel replies"].Marshal()
	for i := 0; i < len(good); i++ {
		// Every prefix either decodes or fails; none may panic.
		_, _ = DecodeRule(good[:i])
	}
	if _, err := DecodeRule(good[:11]); err == nil {
		t.Fatal("short header accepted")
	}
	bad := append([]byte(nil), good...)
	native.PutUint16(bad[12:14], 0xfff0) // attribute longer than the message
	if _, err := DecodeRule(bad); err == nil {
		t.Fatal("overlong attribute accepted")
	}
	bad[0] = 3
	if _, err := DecodeRule(bad); err == nil {
		t.Fatal("rule of an unknown family accepted")
	}
}

func TestPriorityOnly(t *testing.T) {
	b := PriorityOnly(V6, 94)
	got, err := DecodeRule(b)
	if err != nil || got.Family != V6 || got.Priority != 94 || got.Action != 0 || got.Table != 0 {
		t.Fatalf("%+v %v", got, err)
	}
}

func FuzzDecodeRule(f *testing.F) {
	for _, r := range contractRules() {
		f.Add(r.Marshal())
	}
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeRule(b)
		if err != nil || r.Bad {
			return
		}
		items := r.Items()
		again, err := DecodeRule(r.Marshal())
		if err != nil {
			t.Fatalf("re-encoding a decoded rule failed: %v", err)
		}
		if !reflect.DeepEqual(again.Items(), items) {
			t.Fatalf("round trip changed the rule\n%q\n%q", items, again.Items())
		}
	})
}

func TestUnsetSuppressorsAreAbsent(t *testing.T) {
	// A kernel reports -1 for a rule without suppress_prefixlength or
	// suppress_ifgroup.
	hdr := make([]byte, 12)
	hdr[0], hdr[7] = afInet, FRActUnreachable
	hdr = appendAttrU32(hdr, fraSuppressPrefix, 0xffffffff)
	hdr = appendAttrU32(hdr, fraSuppressIfgrp, 0xffffffff)
	got, err := DecodeRule(hdr)
	if err != nil || got.SuppressPrefixLen.OK || got.SuppressIfGroup.OK {
		t.Fatalf("%+v %v", got, err)
	}
	hdr = appendAttrU32(hdr[:12], fraSuppressPrefix, 0)
	got, _ = DecodeRule(hdr)
	if !got.SuppressPrefixLen.OK || got.SuppressPrefixLen.V != 0 {
		t.Fatalf("suppress_prefixlength 0 must be present: %+v", got)
	}
}

func TestEveryNonBookkeepingFlagIsSemantic(t *testing.T) {
	plain := Rule{Family: V6, Priority: 94, Action: FRActToTbl, Table: 100, Src: pfx("2001:db8::1/128")}
	for _, bit := range []uint32{FIBRuleFindSaddr, FIBRuleUnresolved, 0x20, 0x100, 0x80000000} {
		flagged := plain
		flagged.Flags |= bit
		if reflect.DeepEqual(flagged.Items(), plain.Items()) {
			t.Errorf("flag %#x compares equal to the rule without it", bit)
		}
		// And it is preserved when the rule is sent back (INVERT excepted: it
		// has its own item).
		got, err := DecodeRule(flagged.Marshal())
		if err != nil || got.Flags&bit != bit {
			t.Errorf("flag %#x lost on re-encoding: %#x %v", bit, got.Flags, err)
		}
	}
	for _, bit := range []uint32{FIBRulePermanent, FIBRuleIifDetached, FIBRuleOifDetached} {
		flagged := plain
		flagged.Flags |= bit
		if !reflect.DeepEqual(flagged.Items(), plain.Items()) {
			t.Errorf("bookkeeping flag %#x changes the comparison", bit)
		}
		if got, _ := DecodeRule(flagged.Marshal()); got.Flags&bit != 0 {
			t.Errorf("bookkeeping flag %#x is sent", bit)
		}
	}
	inv := plain
	inv.Flags |= FIBRuleInvert
	if reflect.DeepEqual(inv.Items(), plain.Items()) {
		t.Error("invert")
	}
}
