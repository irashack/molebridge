//go:build drill && linux

package drill

// Rules 91 and 92 at packet level (check-routing.sh, gl_overlay_path and
// gl_too_big_reported): what the exit itself sends to a client's overlay
// address leaves over the overlay, never into gluetun's tunnel, where rule 101
// would otherwise take it. The ICMP errors the exit owes a client (fragmentation
// needed, packet too big) are such traffic.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/nstest"
)

const (
	glClient4 = "192.0.2.2"
	glClient6 = "2001:db8:1::2"
)

// overlayCounters: the client counts the probe datagrams (UDP port 9) that
// arrive over the overlay; the tunnel's far end counts those that leak into
// the tunnel. Only port 9 is counted, so the client's own ICMP answers, which
// take rule 95 into the tunnel like any client packet, are not a leak.
func (g *glRig) overlayCounters() {
	g.t.Helper()
	client := `table inet glo {
  counter arrived {}
  chain pre {
    type filter hook prerouting priority raw; policy accept;
    ip daddr 192.0.2.2 udp dport 9 counter name arrived
    ip6 daddr 2001:db8:1::2 udp dport 9 counter name arrived
  }
}
`
	tunnel := `table inet glo {
  counter leaked {}
  chain pre {
    type filter hook prerouting priority raw; policy accept;
    ip daddr 192.0.2.0/24 udp dport 9 counter name leaked
    ip6 daddr 2001:db8:1::/64 udp dport 9 counter name leaked
  }
}
`
	for ns, script := range map[*nstest.NS]string{g.client: client, g.tun: tunnel} {
		if out, err := ns.ExecInput(script, "nft", "-f", "-"); err != nil {
			g.t.Fatalf("nft: %v\n%s", err, out)
		}
	}
}

func overlayCount(t *testing.T, ns *nstest.NS, name string) int {
	t.Helper()
	out, err := ns.Exec("nft", "list", "counter", "inet", "glo", name)
	if err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "packets" && i+1 < len(fields) {
			var n int
			fmt.Sscan(fields[i+1], &n)
			return n
		}
	}
	return 0
}

// overlayPath says where an unmarked datagram from the exit to a client's
// overlay address goes: overlay, tunnel or none.
func (g *glRig) overlayPath(family string) string {
	g.t.Helper()
	for ns, c := range map[*nstest.NS]string{g.client: "arrived", g.tun: "leaked"} {
		if out, err := ns.Exec("nft", "reset", "counter", "inet", "glo", c); err != nil {
			g.t.Fatalf("nft: %v\n%s", err, out)
		}
	}
	dst := glClient4
	if family == "-6" {
		dst = glClient6
	}
	refused := g.send(family, "0", dst)
	time.Sleep(300 * time.Millisecond)
	arrived, leaked := overlayCount(g.t, g.client, "arrived"), overlayCount(g.t, g.tun, "leaked")
	switch {
	case arrived != 0 && leaked == 0:
		return "overlay"
	case leaked != 0 && arrived == 0:
		return "tunnel"
	case arrived == 0 && leaked == 0 && refused:
		return "none"
	}
	return fmt.Sprintf("mixed:%v:%d:%d", refused, arrived, leaked)
}

// tooBigReported: a client's oversized, don't-fragment packet toward the
// tunnel brings the exit's ICMP error back to it.
func (g *glRig) tooBigReported(family string) bool {
	g.t.Helper()
	dst, pattern := glTarget4, "Frag needed"
	if family == "-6" {
		dst, pattern = glTarget6, "Packet too big"
	}
	// A path MTU the client cached from an earlier answer would hide the
	// exit's; and ICMP errors are rate limited per destination.
	g.client.TryIP(family, "route", "flush", "cache")
	time.Sleep(time.Second)
	out, _ := g.client.Exec("ping", family, "-c", "1", "-W", "1", "-M", "do", "-s", "1300", dst)
	if strings.Contains(out, "local error") {
		g.t.Fatalf("the client answered from its own path MTU cache (%s)", family)
	}
	return strings.Contains(out, pattern)
}

func (g *glRig) overlayRoute(del bool) {
	g.t.Helper()
	if del {
		g.exit.IP("-4", "route", "del", "192.0.2.0/24", "dev", overlayIf)
		g.exit.IP("-6", "route", "del", "2001:db8:1::/64", "dev", overlayIf)
		return
	}
	g.exit.IP("-4", "route", "add", "192.0.2.0/24", "dev", overlayIf, "proto", "kernel", "scope", "link", "src", "192.0.2.1")
	g.exit.IP("-6", "route", "add", "2001:db8:1::/64", "dev", overlayIf, "proto", "kernel", "metric", "256")
}

func TestGluetunExitReachesClientsOnlyOverTheOverlay(t *testing.T) { // rules 91/92 at packet level
	g := newGluetunRig(t)
	g.overlayCounters()
	// Narrower than the client's link, so a full-size client packet needs the
	// exit's ICMP error.
	g.exit.IP("link", "set", glExitIf, "mtu", "1280")
	g.tun.IP("link", "set", "tunnel0", "mtu", "1280")
	families := []string{"-4", "-6"}
	for _, f := range families {
		if got := g.overlayPath(f); got != "overlay" {
			t.Errorf("%s: unmarked local traffic to the overlay: %s, want overlay", f, got)
		}
		if !g.tooBigReported(f) {
			t.Errorf("%s: the client got no ICMP error for an oversized packet", f)
		}
	}
	// With no overlay route the traffic is unreachable, never the tunnel.
	g.overlayRoute(true)
	for _, f := range families {
		if got := g.overlayPath(f); got != "none" {
			t.Errorf("%s: local traffic to the overlay without the overlay route: %s, want none", f, got)
		}
	}
	if ok, why := g.strict(); !ok {
		t.Errorf("the contract is not intact: %s", why)
	}

	// Sensitivity: without rule 92, and with no overlay route, the traffic
	// takes gluetun's rule 101 into the tunnel. The owner is held so that
	// nothing is repaired while the drill looks.
	resume := g.pause()
	defer resume()
	for _, f := range families {
		g.ipx(f, "rule", "del", "priority", "92")
	}
	for _, f := range families {
		if got := g.overlayPath(f); got != "tunnel" {
			t.Errorf("%s: the drill cannot see local overlay traffic reach the tunnel without rule 92: %s", f, got)
		}
	}
	g.overlayRoute(false)
	// Without rule 91 as well, the client's ICMP errors go into the tunnel.
	for _, f := range families {
		g.ipx(f, "rule", "del", "priority", "91")
	}
	for _, f := range families {
		if got := g.overlayPath(f); got != "tunnel" {
			t.Errorf("%s: the drill cannot see local overlay traffic reach the tunnel without rules 91/92: %s", f, got)
		}
		if g.tooBigReported(f) {
			t.Errorf("%s: the drill cannot see the client's ICMP error lost without rules 91/92", f)
		}
	}
	// One pass restores both.
	resume()
	g.waitStrict(2 * time.Second)
	for _, f := range families {
		if got := g.overlayPath(f); got != "overlay" {
			t.Errorf("%s: the repair did not restore rules 91/92: %s", f, got)
		}
		if !g.tooBigReported(f) {
			t.Errorf("%s: the repair did not restore the client's ICMP errors", f)
		}
	}
}
