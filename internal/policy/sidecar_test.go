package policy

import (
	"net/netip"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

func sidecarState(t *testing.T) State {
	c := cfg(t, map[string]string{"EXIT_KIND": "sidecar", "TUNNEL_BACKEND": "native", "SIDECAR_LAN_CIDRS": "192.0.2.0/24,2001:db8:1::/64"})
	s := healthy(contract.Spec{Config: c, ReturnPath: map[rtnl.Family][]netip.Addr{rtnl.V4: {tunnel4}, rtnl.V6: {tunnel6}}})
	for _, f := range families {
		s = s.WithRule(rtnl.Rule{Family: f, Priority: 0, Action: rtnl.FRActToTbl, Table: rtnl.TableLocal})
		s.Routes[f][rtnl.TableMain] = []rtnl.Route{{Family: f, Table: rtnl.TableMain, Dst: zero(f), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(hostIdx))}}
	}
	return s
}

func TestNativeSidecarClasses(t *testing.T) {
	s := sidecarState(t)
	if v := s.Violations(); len(v) != 0 {
		t.Fatal(v)
	}
	cls := s.classifier()
	for _, f := range families {
		dst := netip.MustParseAddr("198.51.100.100")
		loopback := netip.MustParseAddr("127.0.0.2")
		lan := netip.MustParseAddr("192.0.2.22")
		if f == rtnl.V6 {
			dst, loopback, lan = netip.MustParseAddr("2001:db8:2::100"), netip.IPv6Loopback(), netip.MustParseAddr("2001:db8:1::22")
		}
		p := packet{f: f, iif: "lo", dst: dst, proto: 17}
		for _, mark := range []uint32{0, s.Spec.Config.ControlMark | 1, s.Spec.Config.TunnelMark() | 2} {
			p.mark = mark
			cl := cls(p)
			if cl.any || !cl.allows(Outcome{Kind: viaDev, Dev: exitIdx}) || cl.allows(Outcome{Kind: viaDev, Dev: hostIdx}) || !cl.allows(Outcome{Kind: stopped}) {
				t.Fatalf("%s mark %x: %+v", f, mark, cl)
			}
		}
		p.mark = s.Spec.Config.ControlMark
		if cl := cls(p); cl.any || !cl.allows(Outcome{Kind: viaDev, Dev: hostIdx}) || cl.allows(Outcome{Kind: viaDev, Dev: exitIdx}) {
			t.Fatalf("control: %+v", cl)
		}
		p.dst = lan // control traffic stays restricted even for a LAN destination
		if cls(p).any {
			t.Fatal("control mark lost its host restriction on the LAN")
		}
		p.mark = s.Spec.Config.TunnelMark()
		if !cls(p).any {
			t.Fatal("WireGuard socket is protected as application traffic")
		}
		p.mark = 0
		for _, d := range []netip.Addr{lan, loopback, s.Locals[f][0]} {
			p.dst = d
			if !cls(p).any {
				t.Fatalf("local/LAN %s is restricted", d)
			}
		}
		p.dst, p.iif = dst, "eth0"
		if !cls(p).any {
			t.Fatal("sidecar classified forwarded traffic")
		}
		pts, tooMany := points(f, s)
		if tooMany || len(pts) == 0 {
			t.Fatal("no sidecar points")
		}
		for _, p := range pts {
			if p.iif != "lo" {
				t.Fatalf("sidecar point arrives on %q", p.iif)
			}
		}
	}
}

func TestNativeSidecarDeletionBackstops(t *testing.T) {
	for _, f := range families {
		s := sidecarState(t)
		without96 := s.without(f, 96)
		if v := Worsens(s, without96); len(v) != 0 {
			t.Fatalf("97 backs up 96: %v", v)
		}
		withoutBoth := without96.without(f, 97)
		if v := Worsens(s, withoutBoth); len(v) == 0 {
			t.Fatal("96 and 97 may not go together")
		}
		if v := Worsens(without96, withoutBoth); len(v) == 0 {
			t.Fatal("97 may not go after 96")
		}
		if v := Worsens(s, s.without(f, 88)); len(v) != 0 {
			t.Fatalf("89 backs up 88: %v", v)
		}
		// The host default is present even with no exit table: the terminal
		// rule must still refuse the applications' unmarked traffic.
		noTable := s.clone()
		noTable.Routes[f][s.Spec.Config.Table] = nil
		if v := noTable.Violations(); len(v) != 0 {
			t.Fatalf("97 protects an empty exit table: %v", v)
		}
	}
}

func TestNativeSidecarExitTableHostRouteIsAnEscape(t *testing.T) {
	for _, f := range families {
		s := sidecarState(t)
		bad := s.WithRoute(rtnl.Route{Family: f, Table: s.Spec.Config.Table, Dst: zero(f), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(hostIdx))})
		if v := bad.Violations(); len(v) == 0 {
			t.Fatal("a host route in the exit table escapes")
		}
		if v := Worsens(s, bad); len(v) == 0 {
			t.Fatal("adding the host route worsens protection")
		}
		for _, mark := range []uint32{0, s.Spec.Config.ControlMark} {
			p := packet{f: f, iif: "lo", mark: mark, dst: s.Spec.Config.LANFor(f)[0].Addr().Next().Next(), proto: 17}
			outs := s.walkWith(p, s.hashes()[f])
			if len(outs) != 1 || outs[0].Kind != viaDev || outs[0].Dev != hostIdx || outs[0].Table != rtnl.TableMain {
				t.Fatalf("LAN/control host path: %v", outs)
			}
		}
		// Control marked traffic is unsafe if main itself points at another device.
		bad = s.WithRoute(rtnl.Route{Family: f, Table: rtnl.TableMain, Dst: zero(f), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(exitIdx))})
		if v := bad.Violations(); len(v) == 0 {
			t.Fatal("control marked traffic may leave only through HOST_IF")
		}
	}
}

func TestNativeSidecarSnapshotFindsHostIndex(t *testing.T) {
	s := sidecarState(t)
	snap := rtnl.NewSnapshot()
	snap.Links = []rtnl.Link{{Name: "eth0", Index: hostIdx}, {Name: s.Spec.Config.ExitIf, Index: exitIdx}}
	for _, f := range families {
		snap.Rules[f] = s.Rules[f]
		for _, routes := range s.Routes[f] {
			snap.Routes[f] = append(snap.Routes[f], routes...)
		}
	}
	got := FromSnapshot(s.Spec, snap)
	if got.HostIdx != hostIdx || got.ExitIdx != exitIdx || !got.Known[rtnl.TableMain] {
		t.Fatalf("snapshot: %+v", got)
	}
	if v := got.Violations(); len(v) != 0 {
		t.Fatal(v)
	}
}
