package rtnl

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestRouteRoundTrip(t *testing.T) {
	zero4 := netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	zero6 := netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	cases := map[string]Route{
		"unreachable fallback": {Family: V4, Dst: zero4, Table: 51821, Type: RTNUnreachable, Metric: 4096, Protocol: RTProtoBoot},
		"tunnel default":       {Family: V6, Dst: zero6, Table: 51821, Type: RTNUnicast, Oif: Some(uint32(7)), Protocol: RTProtoBoot},
		"host route":           {Family: V4, Dst: netip.MustParsePrefix("198.51.100.0/28"), Table: 51822, Type: RTNUnicast, Oif: Some(uint32(2)), PrefSrc: netip.MustParseAddr("198.51.100.1"), Protocol: RTProtoBoot, Scope: RTScopeLink},
		"gateway default":      {Family: V6, Dst: zero6, Table: 51822, Type: RTNUnicast, Oif: Some(uint32(2)), Gateway: netip.MustParseAddr("fe80::1"), Metric: 1024, Protocol: RTProtoBoot, Flags: RTNHFOnlink},
	}
	for name, want := range cases {
		got, err := DecodeRoute(want.Marshal())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		want.Flags &= RTNHFOnlink
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got  %+v\n want %+v", name, got, want)
		}
	}
}

func TestRouteTableAttributeWinsOverTheHeader(t *testing.T) {
	r := Route{Family: V4, Dst: netip.PrefixFrom(netip.IPv4Unspecified(), 0), Table: 1 << 20, Type: RTNUnicast, Oif: Some(uint32(1))}
	b := r.Marshal()
	if b[4] != tableCompat {
		t.Fatalf("header table %d", b[4])
	}
	got, err := DecodeRoute(b)
	if err != nil || got.Table != 1<<20 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestRouteOddities(t *testing.T) {
	base := Route{Family: V4, Dst: netip.PrefixFrom(netip.IPv4Unspecified(), 0), Table: 5, Type: RTNUnicast}.Marshal()
	for name, attrType := range map[string]uint16{"multipath": rtaMultipath, "via": rtaVia, "encap": rtaEncap, "encap type": rtaEncapType} {
		got, err := DecodeRoute(appendAttr(append([]byte(nil), base...), attrType, []byte{0, 0, 0, 0}))
		if err != nil {
			t.Fatal(err)
		}
		if !(got.MultiPath || got.Via || got.Encap) {
			t.Errorf("%s not recorded: %+v", name, got)
		}
	}
	got, err := DecodeRoute(appendAttrU32(append([]byte(nil), base...), rtaNHID, 9))
	if err != nil || !got.NHID.OK || got.NHID.V != 9 {
		t.Fatalf("nhid: %+v %v", got, err)
	}
	got, err = DecodeRoute(appendAttr(append([]byte(nil), base...), rtaMetrics, []byte{0, 0, 0, 0}))
	if err != nil || got.Other != 1 {
		t.Fatalf("ignored attributes should be counted: %+v %v", got, err)
	}
}

func TestRouteRejectsBrokenInput(t *testing.T) {
	if _, err := DecodeRoute(make([]byte, 11)); err == nil {
		t.Error("short header accepted")
	}
	hdr := make([]byte, 12)
	hdr[0], hdr[1] = afInet, 24
	if _, err := DecodeRoute(hdr); err == nil {
		t.Error("prefix length without a destination accepted")
	}
	hdr[1] = 33
	if _, err := DecodeRoute(hdr); err == nil {
		t.Error("prefix length 33 accepted for IPv4")
	}
	hdr[1] = 0
	if _, err := DecodeRoute(appendAttr(hdr, rtaGateway, []byte{1, 2, 3})); err == nil {
		t.Error("three-byte gateway accepted")
	}
}

func TestLinkAndAddrDecode(t *testing.T) {
	// ifinfomsg: family, pad, type, index, flags, change.
	b := make([]byte, 16)
	native.PutUint32(b[4:8], 7)
	native.PutUint32(b[8:12], IFFUp|IFFLowerUp|0x1000)
	b = appendAttrStr(b, iflaIfname, "wg0")
	b = appendAttrU32(b, iflaMTU, 1420)
	info := appendAttrStr(nil, iflaInfoKind, "wireguard")
	b = appendAttr(b, iflaLinkinfo|nlaFNested, info)
	l, err := DecodeLink(b)
	if err != nil {
		t.Fatal(err)
	}
	if l.Name != "wg0" || l.Index != 7 || l.MTU != 1420 || l.Kind != "wireguard" || !l.Up() {
		t.Fatalf("%+v", l)
	}
	if _, err := DecodeLink(make([]byte, 15)); err == nil {
		t.Error("short link header accepted")
	}

	a := make([]byte, 8)
	a[0], a[1], a[3] = afInet, 24, RTScopeUniverse
	native.PutUint32(a[4:8], 7)
	a = appendAttr(a, ifaAddress, []byte{203, 0, 113, 2}) // the peer
	a = appendAttr(a, ifaLocal, []byte{203, 0, 113, 1})
	addr, err := DecodeAddr(a)
	if err != nil {
		t.Fatal(err)
	}
	if addr.Local != netip.MustParsePrefix("203.0.113.1/24") || !addr.Global() || addr.Index != 7 {
		t.Fatalf("%+v", addr)
	}
	v6 := make([]byte, 8)
	v6[0], v6[1], v6[3] = afInet6, 64, RTScopeLink
	ip := netip.MustParseAddr("fe80::1").As16()
	v6 = appendAttr(v6, ifaAddress, ip[:])
	addr, err = DecodeAddr(v6)
	if err != nil || addr.Global() || addr.Local != netip.MustParsePrefix("fe80::1/64") {
		t.Fatalf("%+v %v", addr, err)
	}
	if _, err := DecodeAddr(make([]byte, 8)); err == nil {
		t.Error("an address message without an address accepted")
	}
}

func TestSnapshotHelpers(t *testing.T) {
	s := NewSnapshot()
	s.Links = []Link{{Index: 2, Name: "eth0"}, {Index: 7, Name: "wg0", Flags: IFFUp}}
	s.Addrs[V4] = []Addr{
		{Family: V4, Index: 2, Local: netip.MustParsePrefix("198.51.100.1/28")},
		{Family: V4, Index: 7, Local: netip.MustParsePrefix("203.0.113.1/32"), Scope: RTScopeLink},
		{Family: V4, Index: 7, Local: netip.MustParsePrefix("203.0.113.9/32")},
	}
	got, ok := s.GlobalAddr("wg0", V4)
	if !ok || got != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("%v %v", got, ok)
	}
	if _, ok := s.GlobalAddr("wg0", V6); ok {
		t.Error("an address in the other family")
	}
	if _, ok := s.GlobalAddr("nope", V4); ok {
		t.Error("an address on a missing link")
	}
}

func FuzzDecodeRoute(f *testing.F) {
	f.Add(Route{Family: V4, Dst: netip.PrefixFrom(netip.IPv4Unspecified(), 0), Table: 5, Type: RTNUnicast}.Marshal())
	f.Add(Route{Family: V6, Dst: netip.MustParsePrefix("2001:db8::/32"), Table: 5, Oif: Some(uint32(2)), Gateway: netip.MustParseAddr("fe80::1")}.Marshal())
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeRoute(b)
		_, _ = DecodeLink(b)
		_, _ = DecodeAddr(b)
	})
}
