package exit

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/netx"
)

func TestSidecarRequest(t *testing.T) {
	c := contract.Config{Kind: contract.Sidecar, Backend: contract.Native, ControlMark: 0x1bd00,
		HostResolvers: []netip.Addr{netip.MustParseAddr("10.129.0.10"), netip.MustParseAddr("2001:db8::53")}}
	got := sidecarRequest(c, netx.Request{URL: "https://example.test/"})
	if got.SocketMark != 0x1bd00 || !got.MarkResolver || !reflect.DeepEqual(got.Resolvers, []string{"10.129.0.10:53", "[2001:db8::53]:53"}) {
		t.Errorf("an unbound request: %+v", got)
	}
	// A request bound to the tunnel keeps the namespace's resolvers: its
	// lookup goes through the tunnel like the applications'.
	if got := sidecarRequest(c, netx.Request{BindInterface: "pia"}); got.SocketMark != 0 || got.MarkResolver || got.Resolvers != nil {
		t.Errorf("a bound request: %+v", got)
	}
	c.HostResolvers = nil
	if got := sidecarRequest(c, netx.Request{}); got.SocketMark != 0x1bd00 || !got.MarkResolver || got.Resolvers != nil {
		t.Errorf("without host resolvers: %+v", got)
	}
	c.Kind = contract.Overlay
	if got := sidecarRequest(c, netx.Request{}); got.SocketMark != 0 || got.MarkResolver {
		t.Errorf("an overlay exit: %+v", got)
	}
}
