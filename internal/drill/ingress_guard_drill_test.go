//go:build drill && linux

package drill

// The ingress guard on any native overlay exit (the rig is Mullvad-shaped):
// a packet that arrives from the tunnel addressed to something behind the
// host interface is dropped, in both families. Rule 95 matches only traffic
// from the overlay, so without the guard the main table forwards such a packet
// out of the host interface; the drill shows that first, so it can see the
// path it closes.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/nft"
)

func TestTheIngressGuardDropsTunnelTrafficForTheHostSide(t *testing.T) { // R2: a VPN server cannot reach the host's network through the exit
	r := newRig(t)
	if out, err := r.exit.Exec("nft", "list", "ruleset"); err != nil {
		t.Skipf("nft is unavailable here: %v %s", err, out)
	}
	// The tunnel's far side sends to the outside namespace's own addresses,
	// which only the exit's host interface reaches.
	r.tun.IP("route", "add", "198.51.100.2/32", "via", "203.0.113.1")
	r.tun.IP("-6", "route", "add", "2001:db8:2::2/128", "via", "2001:db8:3::1")
	script := `table inet ingress {
  counter tunnel {}
  chain pre {
    type filter hook prerouting priority raw; policy accept;
    ip saddr 203.0.113.0/24 counter name tunnel
    ip6 saddr 2001:db8:3::/64 counter name tunnel
  }
}
`
	if out, err := r.outside.ExecInput(script, "nft", "-f", "-"); err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}
	reached := func() bool {
		t.Helper()
		if out, err := r.outside.Exec("nft", "reset", "counter", "inet", "ingress", "tunnel"); err != nil {
			t.Fatalf("nft: %v\n%s", err, out)
		}
		_, _ = r.tun.Exec("ping", "-4", "-c", "1", "-W", "1", "-I", "203.0.113.2", "198.51.100.2")
		_, _ = r.tun.Exec("ping", "-6", "-c", "1", "-W", "1", "-I", "2001:db8:3::2", "2001:db8:2::2")
		out, err := r.outside.Exec("nft", "list", "counter", "inet", "ingress", "tunnel")
		if err != nil {
			t.Fatalf("nft: %v\n%s", err, out)
		}
		return !strings.Contains(out, "packets 0 ")
	}
	// Sensitivity: the routing contract alone forwards it.
	if !reached() {
		t.Fatal("the drill cannot see the path: without the guard nothing from the tunnel reached the host side")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := nft.InstallIngressGuard(ctx, r.exit.Fd(), exitIf, overlayIf); err != nil {
		t.Fatal(err)
	}
	if reached() {
		t.Error("with the ingress guard, a packet from the tunnel still reached the host side")
	}
	// Replies to clients still come back over the overlay.
	if !r.ping("-4") || !r.ping("-6") {
		t.Error("with the ingress guard, the overlay no longer reaches the tunnel")
	}
}
