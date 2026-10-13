//go:build drill && linux

package drill

// PIA port forwarding at packet level (check-routing.sh, the last section), with
// the nftables the exit installs (internal/nft, as the exit calls it): a
// connection from the tunnel side to the forwarded port reaches the overlay
// target and its replies return through the tunnel; the ingress guard stops
// the forwarded connection leaving any other way when the overlay route is
// gone; and the drill is shown sensitive by removing the guard.

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/nft"
	"github.com/irashack/molebridge/internal/nstest"
)

const forwardPort = 40000

// forwardTarget listens on the overlay client and answers "target".
func forwardTarget(t *testing.T, ns *nstest.NS) {
	t.Helper()
	var ln net.Listener
	if err := ns.Do(func() (err error) { ln, err = net.Listen("tcp4", "192.0.2.2:40000"); return }); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("target"))
			c.Close()
		}
	}()
}

// inbound connects from the tunnel's far side, as an Internet peer would, to
// the exit's tunnel address on the forwarded port and returns what it reads.
func inbound(t *testing.T, tun *nstest.NS) string {
	t.Helper()
	var got string
	_ = tun.Do(func() error {
		d := net.Dialer{Timeout: 2 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(target4)}}
		c, err := d.Dial("tcp4", tunnel4.String()+":40000")
		if err != nil {
			return nil
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(c)
		got = string(b)
		return nil
	})
	return got
}

func TestPIAForwardedPortReachesTheOverlayAndTheGuardKeepsItOnTheOverlay(t *testing.T) {
	r := newRig(t)
	if out, err := r.exit.Exec("nft", "list", "ruleset"); err != nil {
		t.Skipf("nft is unavailable here: %v %s", err, out)
	}
	forwardTarget(t, r.client)
	// A counter behind the exit's ordinary default route sees any forwarded
	// packet that leaks there.
	script := `table inet leak {
  counter seen {}
  chain pre {
    type filter hook prerouting priority raw; policy accept;
    ip daddr 192.0.2.2 tcp dport 40000 counter name seen
  }
}
`
	if out, err := r.outside.ExecInput(script, "nft", "-f", "-"); err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}
	leaked := func() bool {
		t.Helper()
		if out, err := r.outside.Exec("nft", "reset", "counter", "inet", "leak", "seen"); err != nil {
			t.Fatalf("nft: %v\n%s", err, out)
		}
		inbound(t, r.tun)
		out, err := r.outside.Exec("nft", "list", "counter", "inet", "leak", "seen")
		if err != nil {
			t.Fatalf("nft: %v\n%s", err, out)
		}
		return !strings.Contains(out, "packets 0 ")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	install := func() {
		t.Helper()
		if err := nft.InstallIngressGuard(ctx, r.exit.Fd(), exitIf, overlayIf); err != nil {
			t.Fatal(err)
		}
	}
	install()
	if err := nft.ApplyForwardRules(ctx, r.exit.Fd(), exitIf, overlayIf, forwardPort, netip.MustParseAddr("192.0.2.2")); err != nil {
		t.Fatal(err)
	}
	if got := inbound(t, r.tun); got != "target" {
		t.Fatalf("the forwarded port did not reach the overlay target (got %q)", got)
	}

	// The overlay route goes: the DNATed connection would leave by the exit's
	// ordinary default route. The guard drops it.
	r.exit.IP("route", "del", "192.0.2.0/24", "dev", overlayIf)
	if leaked() {
		t.Fatal("a forwarded connection left through the ordinary route")
	}
	// Sensitivity: without the guard the same connection leaks.
	r.exit.IP("-4", "route", "show")
	if out, err := r.exit.Exec("nft", "delete", "table", "inet", nft.GuardTable); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !leaked() {
		t.Fatal("the drill cannot see the unguarded path: without the guard nothing leaked")
	}
	install()
	if leaked() {
		t.Fatal("installing the guard again did not stop the leak")
	}
	// The overlay route comes back and the port works again.
	r.exit.IP("route", "add", "192.0.2.0/24", "dev", overlayIf, "proto", "kernel", "scope", "link", "src", "192.0.2.1")
	if got := inbound(t, r.tun); got != "target" {
		t.Errorf("after the overlay route returned: %q", got)
	}
}
