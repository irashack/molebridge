//go:build drill && linux

package drill

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func (g *glRig) ipx(family string, args ...string) { g.exit.IP(append([]string{family}, args...)...) }

func TestGluetunInstallPutsEveryRuleInPlaceAndRoutesByMark(t *testing.T) {
	// Before the guard, gluetun's rule 101 takes NetBird's marked traffic into
	// the tunnel too: the reason for rules 88 and 89. The fixture shows it by
	// running the paths before the stack starts.
	g := newGluetunRig(t)
	if ok, why := g.strict(); !ok {
		t.Fatalf("not healthy after the install: %s", why)
	}
	for _, f := range []string{"-4", "-6"} {
		out, _ := g.exit.TryIP(f, "rule", "show")
		for _, want := range []string{"1:", "88:", "89:", "90:", "91:", "92:", "94:", "95:", "96:", "97:", "98:", "100:", "101:", "102:", "103:", "104:", "105:", "110:"} {
			if !strings.Contains(out, "\n"+want) && !strings.HasPrefix(out, want) {
				t.Errorf("%s: rule %s missing:\n%s", f, want, out)
			}
		}
	}
	g.forwarding("tunnel", "tunnel up")
	for _, f := range []string{"-4", "-6"} {
		if got := g.localPath(f, "0x1bd00"); got != "host" {
			t.Errorf("%s: control-marked local traffic: %s, want host", f, got)
		}
		if got := g.localPath(f, "0"); got != "tunnel" {
			t.Errorf("%s: unmarked local traffic: %s, want tunnel (gluetun's rule 101)", f, got)
		}
		if got := g.localPath(f, "0x1bd21"); got != "tunnel" {
			t.Errorf("%s: a data-plane mark matched the control-plane rules: %s", f, got)
		}
	}
	// Molebridge's repairs never touch gluetun's or NetBird's rules.
	g.ipx("-4", "rule", "del", "priority", "95")
	g.waitStrict(time.Second)
	for _, f := range []string{"-4", "-6"} {
		out, _ := g.exit.TryIP(f, "rule", "show")
		for _, own := range []string{"98:", "100:", "101:", "105:", "110:"} {
			if !strings.Contains(out, own) {
				t.Errorf("%s: %s went with a repair:\n%s", f, own, out)
			}
		}
	}
}

func TestGluetunHostTableEmptyMakesControlTrafficUnreachable(t *testing.T) { // 'with the host table empty, control traffic is unreachable, never the tunnel'
	g := newGluetunRig(t)
	resume := g.pause()
	defer resume()
	for _, f := range []string{"-4", "-6"} {
		g.ipx(f, "route", "flush", "table", "51822")
	}
	for _, f := range []string{"-4", "-6"} {
		if got := g.localPath(f, "0x1bd00"); got != "none" {
			t.Errorf("%s: control traffic without a host route: %s, want none", f, got)
		}
	}
	if ok, _ := g.strict(); ok {
		t.Error("the strict judgment accepts an empty host table")
	}
	// Sensitivity: without rule 89 the control traffic reaches the tunnel.
	for _, f := range []string{"-4", "-6"} {
		g.ipx(f, "rule", "del", "priority", "89")
	}
	for _, f := range []string{"-4", "-6"} {
		if got := g.localPath(f, "0x1bd00"); got != "tunnel" {
			t.Errorf("%s: the drill cannot see control traffic reaching the tunnel without rule 89: %s", f, got)
		}
	}
	resume()
	g.waitStrict(time.Second)
	for _, f := range []string{"-4", "-6"} {
		if got := g.localPath(f, "0x1bd00"); got != "host" {
			t.Errorf("%s: the repair did not restore the host route: %s", f, got)
		}
	}
}

func TestGluetunTunnelRecreatedWithANewAddress(t *testing.T) {
	g := newGluetunRig(t)
	g.flood()
	g.resetCounters()
	g.exit.IP("link", "del", glExitIf)
	g.waitStrictOrHealthy()
	g.forwarding("blocked", "tunnel interface deleted")
	// gluetun brings its interface back with a new address.
	glTunnelUp(g.rig, "203.0.113.9")
	start := time.Now()
	g.waitStrict(2 * time.Second)
	if took := time.Since(start); took > repairBudget {
		t.Errorf("repaired %v after the interface came back, budget %v", took, repairBudget)
	}
	g.forwarding("tunnel", "tunnel recreated and repaired")
	out, _ := g.exit.TryIP("-4", "rule", "show", "priority", "94")
	if !strings.Contains(out, "from 203.0.113.9 ") || strings.Contains(out, "from 203.0.113.1 ") {
		t.Errorf("rule 94 does not follow the new address:\n%s", out)
	}
}

// waitStrictOrHealthy: with the interface deleted the strict judgment fails
// (detached rules); the plan is what must hold.
func (g *glRig) waitStrictOrHealthy() {
	g.t.Helper()
	g.rig.waitHealthy(time.Second)
}

func TestGluetunSingleFaultsAreRepairedWithin250ms(t *testing.T) {
	type fl struct {
		name  string
		apply func(g *glRig, f string)
	}
	var faults []fl
	for _, p := range []string{"1", "88", "89", "90", "91", "92", "94", "95", "96", "97", "102", "103", "104"} {
		p := p
		faults = append(faults, fl{"rule " + p + " deleted", func(g *glRig, f string) { g.ipx(f, "rule", "del", "priority", p) }})
	}
	faults = append(faults,
		fl{"host table flushed", func(g *glRig, f string) { g.ipx(f, "route", "flush", "table", "51822") }},
		fl{"a stray host-table route", func(g *glRig, f string) {
			dst := "10.99.0.0/16"
			if f == "-6" {
				dst = "2001:db8:99::/64"
			}
			g.ipx(f, "route", "add", dst, "dev", glExitIf, "table", "51822")
		}},
		fl{"tunnel route deleted", func(g *glRig, f string) {
			g.ipx(f, "route", "del", "default", "dev", glExitIf, "table", fmt.Sprint(table))
		}},
		fl{"rule 88 without iif lo", func(g *glRig, f string) {
			g.ipx(f, "rule", "add", "fwmark", "0x1bd00/0xffffffff", "lookup", "51822", "priority", "88")
			g.ipx(f, "rule", "del", "iif", "lo", "fwmark", "0x1bd00/0xffffffff", "lookup", "51822", "priority", "88")
		}},
		fl{"rule 102 with the control mark", func(g *glRig, f string) {
			g.ipx(f, "rule", "add", "iif", "lo", "fwmark", "0x1bd00/0xffffffff", "lookup", "main", "priority", "102")
			g.ipx(f, "rule", "del", "iif", "lo", "fwmark", "0xca6c/0xffffffff", "lookup", "main", "priority", "102")
		}},
		fl{"rule 91 without its suppressor", func(g *glRig, f string) {
			ov := "192.0.2.0/24"
			if f == "-6" {
				ov = "2001:db8:1::/64"
			}
			g.ipx(f, "rule", "add", "iif", "lo", "to", ov, "lookup", "main", "priority", "91")
			g.ipx(f, "rule", "del", "iif", "lo", "to", ov, "lookup", "main", "suppress_prefixlength", "0", "priority", "91")
		}},
	)
	for _, fault := range faults {
		for _, family := range []string{"-4", "-6"} {
			fault, family := fault, family
			t.Run(fault.name+" "+family, func(t *testing.T) {
				g := newGluetunRig(t)
				before := g.mut.Stats().Repairs
				fault.apply(g, family)
				took := g.rig.waitHealthy(2 * time.Second)
				if took > repairBudget {
					t.Errorf("repaired %v after the change, budget %v", took, repairBudget)
				}
				for i := 0; i < 100 && g.mut.Stats().Repairs == before; i++ {
					time.Sleep(5 * time.Millisecond)
				}
				if g.mut.Stats().Repairs == before {
					t.Errorf("no repair was counted")
				}
				g.waitStrict(time.Second)
			})
		}
	}
}

// Sensitivity and containment of the forwarded-mark rules.
func TestGluetunForwardedLeaksAreSeenAndRepaired(t *testing.T) {
	g := newGluetunRig(t)
	resume := g.pause()
	defer resume()
	// Without 95 and 97, a forwarded packet marked 51820 skips gluetun's rule
	// 101 and NetBird's 105 and leaves by the main table.
	for _, f := range []string{"-4", "-6"} {
		g.ipx(f, "rule", "del", "priority", "95")
		g.ipx(f, "rule", "del", "priority", "97")
	}
	g.markForwarded("51820")
	for _, f := range []string{"-4", "-6"} {
		g.resetCounters()
		g.forward(f)
		if glCount(t, g.outside, "client") == 0 {
			t.Errorf("the drill cannot see a forwarded leak without rules 95 and 97 (%s)", f)
		}
	}
	resume()
	g.waitStrict(time.Second)
	g.forwarding("tunnel", "rules 95 and 97 restored")

	// Rule 88 without `iif lo` would hand forwarded packets that carry the
	// control mark to the host table.
	resume = g.pause()
	defer resume()
	for _, f := range []string{"-4", "-6"} {
		g.ipx(f, "rule", "del", "priority", "88")
		g.ipx(f, "rule", "add", "fwmark", "0x1bd00/0xffffffff", "lookup", "51822", "priority", "88")
	}
	g.markForwarded("0x1bd00")
	for _, f := range []string{"-4", "-6"} {
		g.resetCounters()
		g.forward(f)
		if glCount(t, g.outside, "client") == 0 {
			t.Errorf("the drill cannot see forwarded control-marked packets leak through rule 88 without iif lo (%s)", f)
		}
	}
	resume()
	g.waitStrict(time.Second)
	g.forwarding("tunnel", "rule 88 corrected")
}

// With gluetun's tunnel table empty, as during a reconnect, the exit's own
// unmarked traffic is unreachable, never the host side; gluetun's WireGuard
// socket and NetBird's control traffic still leave by the host.
func TestGluetunKillSwitchWithTheTunnelTableEmpty(t *testing.T) {
	g := newGluetunRig(t)
	empty := func() {
		for _, f := range []string{"-4", "-6"} {
			g.ipx(f, "route", "flush", "table", "51820")
		}
	}
	fill := func() {
		for _, f := range []string{"-4", "-6"} {
			g.ipx(f, "route", "replace", "default", "dev", glExitIf, "table", "51820")
		}
	}
	for _, f := range []string{"-4", "-6"} {
		if got := g.localPath(f, "0"); got != "tunnel" {
			t.Fatalf("%s: unmarked local traffic did not take the tunnel: %s", f, got)
		}
		if got := g.localPath(f, "51820"); got != "host" {
			t.Fatalf("%s: gluetun's WireGuard mark did not leave by the host interface: %s", f, got)
		}
	}
	empty()
	for _, f := range []string{"-4", "-6"} {
		if got := g.localPath(f, "0"); got != "none" {
			t.Errorf("%s: unmarked local UDP was not unreachable with the tunnel table empty: %s", f, got)
		}
		if got := g.localPath(f, "51820"); got != "host" {
			t.Errorf("%s: gluetun's WireGuard mark with the tunnel table empty: %s", f, got)
		}
		if got := g.localPath(f, "0x1bd00"); got != "host" {
			t.Errorf("%s: NetBird's control traffic with the tunnel table empty: %s", f, got)
		}
	}
	fill()
	// Sensitivity: without rule 104 the same traffic leaves by the host side;
	// without 102 gluetun's WireGuard socket can't reach its server.
	resume := g.pause()
	defer resume()
	empty()
	for _, f := range []string{"-4", "-6"} {
		g.ipx(f, "rule", "del", "priority", "104")
		if got := g.localPath(f, "0"); got != "host" {
			t.Errorf("%s: the drill cannot see unmarked local traffic leave by the host without rule 104: %s", f, got)
		}
		g.ipx(f, "rule", "add", "iif", "lo", "unreachable", "priority", "104")
		g.ipx(f, "rule", "del", "priority", "102")
		if got := g.localPath(f, "51820"); got != "none" {
			t.Errorf("%s: the drill cannot see gluetun's WireGuard socket cut off without rule 102: %s", f, got)
		}
	}
	resume()
	g.waitStrict(time.Second)
	for _, f := range []string{"-4", "-6"} {
		if got := g.localPath(f, "0"); got != "none" {
			t.Errorf("%s: rule 104 not restored: %s", f, got)
		}
		if got := g.localPath(f, "51820"); got != "host" {
			t.Errorf("%s: rule 102 not restored: %s", f, got)
		}
	}
	fill()
}

// gluetun's start-up, with the whole guard in place: it adds `default via
// <gateway> dev <host if> table 200` before its own rule 98 exists. The
// kernel checks the gateway with a lookup through the policy rules as local
// traffic; rule 103 must answer it before 104 does.
func TestGluetunTable200GatewayRouteIsAcceptedBecauseOfRule103(t *testing.T) {
	g := newGluetunRig(t)
	route200 := func(f string) error {
		gw := "198.51.100.2"
		if f == "-6" {
			gw = "2001:db8:2::2"
		}
		_, err := g.exit.TryIP(f, "route", "replace", "default", "via", gw, "dev", "eth0", "table", "200")
		return err
	}
	for _, f := range []string{"-4", "-6"} {
		g.ipx(f, "rule", "del", "priority", "98")
		g.ipx(f, "route", "flush", "table", "200")
		if err := route200(f); err != nil {
			t.Errorf("%s: gluetun's table-200 default route was refused with the guard in place: %v", f, err)
		}
	}
	// Sensitivity: without rule 103 the gateway check reaches 104 and the route
	// is refused (IPv4; IPv6 is only reported).
	resume := g.pause()
	defer resume()
	for _, f := range []string{"-4", "-6"} {
		g.ipx(f, "route", "flush", "table", "200")
		g.ipx(f, "rule", "del", "priority", "103")
	}
	if err := route200("-4"); err == nil {
		t.Error("the drill cannot see the IPv4 gateway check fail without rule 103")
	}
	if err := route200("-6"); err == nil {
		t.Logf("without rule 103 the IPv6 gateway check still passed (a global gateway on this kernel)")
	}
	resume()
	g.waitStrict(time.Second)
	for _, f := range []string{"-4", "-6"} {
		g.ipx(f, "route", "flush", "table", "200")
		if err := route200(f); err != nil {
			t.Errorf("%s: the repair did not restore rule 103: %v", f, err)
		}
	}
}
