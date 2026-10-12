package rtnl

import (
	"net/netip"
	"testing"
)

// The requests are the encoding half of the decoders: what is built reads
// back as what was asked for.
func TestLinkRequestsReadBackThroughTheDecoder(t *testing.T) {
	cases := []struct {
		name string
		data []byte
		want Link
	}{
		{"create", LinkCreateRequest("wt0", "wireguard"), Link{Name: "wt0", Kind: "wireguard"}},
		{"lookup", LinkLookupRequest("wt0"), Link{Name: "wt0"}},
		{"mtu", LinkMTURequest(7, 1380), Link{Index: 7, MTU: 1380}},
		{"up", LinkUpRequest(7), Link{Index: 7, Flags: IFFUp}},
		{"delete", LinkDeleteRequest(9), Link{Index: 9}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := DecodeLink(c.data)
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("%+v, want %+v", got, c.want)
			}
		})
	}
}

func TestLinkUpChangesOnlyTheUpFlag(t *testing.T) {
	b := LinkUpRequest(3)
	if native.Uint32(b[12:16]) != IFFUp || native.Uint32(b[8:12]) != IFFUp {
		t.Errorf("flags %#x change %#x", native.Uint32(b[8:12]), native.Uint32(b[12:16]))
	}
}

func TestAddrMarshalReadsBack(t *testing.T) {
	for _, s := range []string{"198.51.100.2", "2001:db8::2"} {
		a := HostAddr(7, netip.MustParseAddr(s))
		got, err := DecodeAddr(a.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		if got.Local != a.Local || got.Index != 7 || got.Family != a.Family || !got.Global() {
			t.Errorf("%s: %+v", s, got)
		}
		if got.Local.Bits() != got.Local.Addr().BitLen() {
			t.Errorf("%s is not a host address: %v", s, got.Local)
		}
	}
}
