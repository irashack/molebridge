//go:build drill && linux

package drill

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// recreate rebuilds the tunnel interface the way the bring-up does: the
// interface, its addresses, its neighbors, then up.
func (r *rig) recreate(up bool) {
	r.t.Helper()
	r.exit.Veth(exitIf, r.tun, "tunnel0")
	r.tun.IP("link", "set", "tunnel0", "address", "02:00:00:00:03:02")
	r.tun.IP("addr", "add", "203.0.113.2/24", "dev", "tunnel0")
	r.tun.IP("-6", "addr", "add", "2001:db8:3::2/64", "dev", "tunnel0", "nodad")
	r.tun.IP("addr", "add", target4+"/32", "dev", "tunnel0")
	r.tun.IP("-6", "addr", "add", target6+"/128", "dev", "tunnel0", "nodad")
	r.tun.IP("link", "set", "tunnel0", "up")
	r.tun.IP("route", "replace", "192.0.2.0/24", "via", "203.0.113.1")
	r.tun.IP("-6", "route", "replace", "2001:db8:1::/64", "via", "2001:db8:3::1")
	r.exit.IP("addr", "add", "203.0.113.1/24", "dev", exitIf)
	r.exit.IP("-6", "addr", "add", "2001:db8:3::1/64", "dev", exitIf, "nodad")
	r.exit.IP("link", "set", exitIf, "mtu", "1420")
	pinNeighbors(r.exit)
	if up {
		r.exit.IP("link", "set", exitIf, "up")
	}
}

func (r *rig) exitTableHasTunnelRoutes() bool {
	for _, f := range []string{"-4", "-6"} {
		out, err := r.exit.TryIP(f, "route", "show", "table", fmt.Sprint(table))
		if err != nil || !strings.Contains(out, "default dev "+exitIf) {
			return false
		}
	}
	return true
}

// Tunnel loss and recreation (check-routing.sh's 'tunnel interface down' and
// the bring-up's retry): while the interface is gone the exit table keeps its
// unreachable fallback and nothing leaves; when it is back and up the default
// route returns within the repair budget.
func TestTunnelLossAndRecreation(t *testing.T) {
	r := newRig(t)
	r.flood()
	resetCounter(t, r.outside)

	r.exit.IP("link", "del", exitIf)
	r.waitHealthy(time.Second)
	if r.ping("-4") || r.ping("-6") {
		t.Error("the client reached the destination with the tunnel gone")
	}
	for _, f := range []string{"-4", "-6"} {
		out, _ := r.exit.TryIP(f, "route", "show", "table", fmt.Sprint(table))
		if !strings.Contains(out, "unreachable default") || strings.Contains(out, "default dev "+exitIf) {
			t.Errorf("%s exit table with the tunnel gone: %q", f, out)
		}
	}

	r.recreate(false)
	time.Sleep(60 * time.Millisecond)
	if r.exitTableHasTunnelRoutes() {
		t.Error("a tunnel route appeared while the interface is down")
	}
	r.exit.IP("link", "set", exitIf, "up")
	start := time.Now()
	for !r.exitTableHasTunnelRoutes() {
		if time.Since(start) > 2*time.Second {
			t.Fatalf("no tunnel route after the interface came up\n%s", r.logs.text())
		}
		time.Sleep(time.Millisecond)
	}
	if took := time.Since(start); took > repairBudget {
		t.Errorf("the tunnel route came back %v after the interface came up, budget %v", took, repairBudget)
	}
	r.waitHealthy(time.Second)
	if ok, f := r.connected(); !ok {
		t.Errorf("%s: not connected after the recreation", f)
	}
	r.held("tunnel loss and recreation")

	// The rules that name the interface are attached to the new one again.
	snap, _ := r.obs.Take(r.spec.Interest())
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		link, _ := snap.Link(exitIf)
		ready, fallback := contract.FamilyStatus(r.spec, f, snap.Rules[f], snap.RoutesInTable(f, table), contract.StatusOptions{
			TunnelAddress: tunnelAddr(f), ExitIfIndex: link.Index})
		if !ready || !fallback {
			t.Errorf("%s: the strict status is %v %v after the recreation\n%v", f, ready, fallback, snap.Rules[f])
		}
	}
}

func tunnelAddr(f rtnl.Family) netip.Addr {
	if f == rtnl.V4 {
		return tunnel4
	}
	return tunnel6
}

// The interface goes administratively down and up again.
func TestTunnelInterfaceDownAndUp(t *testing.T) { // 'tunnel interface down' in check-routing.sh
	r := newRig(t)
	r.flood()
	resetCounter(t, r.outside)
	r.exit.IP("link", "set", exitIf, "down")
	r.waitHealthy(time.Second)
	time.Sleep(50 * time.Millisecond)
	if r.ping("-4") || r.ping("-6") {
		t.Error("the client reached the destination with the tunnel down")
	}
	r.exit.IP("link", "set", exitIf, "up")
	// Linux removes the IPv6 address on link-down; the bring-up restores it.
	r.exit.IP("-6", "addr", "replace", "2001:db8:3::1/64", "dev", exitIf, "nodad")
	pinNeighbors(r.exit)
	start := time.Now()
	for !r.exitTableHasTunnelRoutes() {
		if time.Since(start) > 2*time.Second {
			t.Fatalf("no tunnel route after the interface came up\n%s", r.logs.text())
		}
		time.Sleep(time.Millisecond)
	}
	r.waitHealthy(time.Second)
	if ok, f := r.connected(); !ok {
		t.Errorf("%s: not connected", f)
	}
	r.held("tunnel interface down")
}
