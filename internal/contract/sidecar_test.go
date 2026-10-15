package contract

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/rtnl"
)

func sidecarEnv(extra map[string]string) func(string) string {
	m := map[string]string{"EXIT_KIND": "sidecar", "TUNNEL_BACKEND": "native"}
	for k, v := range extra {
		m[k] = v
	}
	return env(m)
}

func sidecarSpec() Spec {
	c := Config{Kind: Sidecar, Backend: Native, ExitIf: DefaultExitIf, Table: DefaultExitTable, HostIf: DefaultHostIf, ControlMark: 0x1bd00}
	return Spec{Config: c, ReturnPath: nativeSpec().ReturnPath}
}

func TestNativeSidecarConfig(t *testing.T) {
	for _, backend := range []string{"", "native", "wireguard"} {
		c, err := ConfigFromEnv(sidecarEnv(map[string]string{"TUNNEL_BACKEND": backend, "HOST_TABLE": "ignored", "NB_JUNK": "ignored"}))
		if err != nil || !reflect.DeepEqual(c, sidecarSpec().Config) {
			t.Fatalf("backend %q: %+v, %v", backend, c, err)
		}
		if !c.IsSidecar() || !c.IsNativeSidecar() || c.IsGluetunSidecar() || c.TunnelMark() != c.Table {
			t.Fatalf("kind/mark: %+v", c)
		}
	}
	for _, table := range []string{"51820", "7120", "256", "2147483647"} {
		if _, err := ConfigFromEnv(sidecarEnv(map[string]string{"EXIT_TABLE": table})); err != nil {
			t.Fatalf("table %s: %v", table, err)
		}
	}
	c, err := ConfigFromEnv(sidecarEnv(map[string]string{
		"EXIT_IF": "wg-1.2", "HOST_IF": "enp3s0", "CONTROL_MARK": "0x2000",
		"SIDECAR_LAN_CIDRS": " 192.0.2.0/24, 2001:DB8:1::/64 ,198.51.100.5/32,2001:db8:2::1/128 ",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.ExitIf != "wg-1.2" || c.HostIf != "enp3s0" || c.ControlMark != 0x2000 ||
		!reflect.DeepEqual(c.LANFor(rtnl.V4), []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.5/32")}) ||
		!reflect.DeepEqual(c.LANFor(rtnl.V6), []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/64"), netip.MustParsePrefix("2001:db8:2::1/128")}) {
		t.Fatalf("%+v", c)
	}
	var entries []string
	for i := 0; i < 16; i++ {
		entries = append(entries, fmt.Sprintf("192.0.2.%d/32", i))
	}
	if _, err := ConfigFromEnv(sidecarEnv(map[string]string{"SIDECAR_LAN_CIDRS": strings.Join(entries, ",")})); err != nil {
		t.Fatal(err)
	}
	// The gluetun sidecar still reads no routing settings, including LANs.
	c, err = ConfigFromEnv(sidecarEnv(map[string]string{"TUNNEL_BACKEND": "gluetun", "OVERLAY_IF": "../bad", "CONTROL_MARK": "bad", "SIDECAR_LAN_CIDRS": "bad"}))
	if err != nil || !c.IsGluetunSidecar() || c.IsNativeSidecar() || c.Table != 0 || c.LAN != nil {
		t.Fatalf("gluetun: %+v, %v", c, err)
	}
}

func TestNativeSidecarRefusals(t *testing.T) {
	for _, tc := range []struct{ name, value, want string }{
		{"TUNNEL_BACKEND", "other", "TUNNEL_BACKEND must be native or gluetun"},
		{"EXIT_IF", "../bad", "invalid interface name"},
		{"HOST_IF", "../bad", "invalid HOST_IF"},
		{"HOST_IF", "lo", "HOST_IF must name the namespace's host interface, not lo, the overlay or the tunnel"},
		{"HOST_IF", "mullvad", "HOST_IF must name the namespace's host interface, not lo, the overlay or the tunnel"},
		{"EXIT_TABLE", "x", "EXIT_TABLE must be numeric"},
		{"EXIT_TABLE", "0256", "EXIT_TABLE must be canonical decimal"},
		{"EXIT_TABLE", "255", "EXIT_TABLE must be 256..2147483647"},
		{"EXIT_TABLE", "2147483648", "EXIT_TABLE must be 256..2147483647"},
		{"CONTROL_MARK", "0x01bd00", "CONTROL_MARK must be lowercase hexadecimal like 0x1bd00"},
		{"CONTROL_MARK", "0x1bd01", "CONTROL_MARK must be lowercase hexadecimal like 0x1bd00, low byte zero"},
		{"EXIT_TABLE", "113920", "CONTROL_MARK and EXIT_TABLE must differ"},
		{"OVERLAY_CIDR", "192.0.2.0/24", "OVERLAY_CIDR is for the overlay kind; a sidecar has no overlay"},
		{"OVERLAY6_CIDR", "2001:db8::/32", "OVERLAY6_CIDR is for the overlay kind; a sidecar has no overlay"},
		{"OVERLAY_IF", "wt0", "OVERLAY_IF is for the overlay kind; a sidecar has no overlay"},
		{"SIDECAR_LAN_CIDRS", "192.0.2.1", "SIDECAR_LAN_CIDRS: 192.0.2.1 is not a network prefix"},
		{"SIDECAR_LAN_CIDRS", "192.0.2.0/33", "SIDECAR_LAN_CIDRS: 192.0.2.0/33 is not a network prefix"},
		{"SIDECAR_LAN_CIDRS", "2001:db8::/129", "SIDECAR_LAN_CIDRS: 2001:db8::/129 is not a network prefix"},
		{"SIDECAR_LAN_CIDRS", "::ffff:192.0.2.0/120", "SIDECAR_LAN_CIDRS: ::ffff:192.0.2.0/120 is not a network prefix"},
		{"SIDECAR_LAN_CIDRS", "0.0.0.0/0", "SIDECAR_LAN_CIDRS: 0.0.0.0/0 is a default route"},
		{"SIDECAR_LAN_CIDRS", "::/0", "SIDECAR_LAN_CIDRS: ::/0 is a default route"},
		{"SIDECAR_LAN_CIDRS", "192.0.2.1/24", "SIDECAR_LAN_CIDRS: 192.0.2.1/24 must use the network address"},
		{"SIDECAR_LAN_CIDRS", "2001:db8::1/64", "SIDECAR_LAN_CIDRS: 2001:db8::1/64 must use the network address"},
		{"SIDECAR_LAN_CIDRS", "192.0.2.0/24, 192.0.2.0/24", "SIDECAR_LAN_CIDRS: 192.0.2.0/24 is duplicated"},
		{"SIDECAR_LAN_CIDRS", "2001:db8::/64, 2001:DB8:0::/64", "SIDECAR_LAN_CIDRS: 2001:DB8:0::/64 is duplicated"},
		{"SIDECAR_LAN_CIDRS", "192.0.2.0/24,", "SIDECAR_LAN_CIDRS: empty entry is not a network prefix"},
		{"SIDECAR_LAN_CIDRS", " ", "SIDECAR_LAN_CIDRS: empty entry is not a network prefix"},
		{"SIDECAR_LAN_CIDRS", strings.Repeat("192.0.2.0/24,", 16) + "2001:db8::/64", "SIDECAR_LAN_CIDRS must have at most 16 entries"},
	} {
		t.Run(tc.name+"="+tc.value, func(t *testing.T) {
			_, err := ConfigFromEnv(sidecarEnv(map[string]string{tc.name: tc.value}))
			if err == nil || err.Error() != tc.want {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestNativeSidecarRulesAndDiff(t *testing.T) {
	for _, f := range families {
		for _, n := range []int{0, 1, 3} {
			t.Run(fmt.Sprintf("%s/%d LANs", f, n), func(t *testing.T) {
				spec := sidecarSpec()
				var lan []netip.Prefix
				for i := 1; i <= n; i++ {
					prefix := fmt.Sprintf("192.0.2.%d/32", i)
					if f == rtnl.V6 {
						prefix = fmt.Sprintf("2001:db8::%d/128", i)
					}
					lan = append(lan, netip.MustParsePrefix(prefix))
				}
				if f == rtnl.V4 {
					spec.Config.LAN = lan
				} else {
					spec.Config.LAN6 = lan
				}
				want := []rtnl.Rule{
					rule(f, 88, iif("lo"), mark(0x1bd00), table(rtnl.TableMain)),
					rule(f, 89, iif("lo"), mark(0x1bd00), unreachable()),
				}
				for _, p := range lan {
					want = append(want, rule(f, 90, iif("lo"), to(p.String()), table(rtnl.TableMain)))
				}
				want = append(want,
					rule(f, 93, iif("lo"), mark(51821), table(rtnl.TableMain)),
					rule(f, 94, from(hostOf(f)), proto(icmpOf(f)), table(51821)),
					rule(f, 96, iif("lo"), table(51821)),
					rule(f, 97, iif("lo"), unreachable()),
					rule(f, 98, from(hostOf(f)), proto(icmpOf(f)), unreachable()))
				// A stale TempGuard expectation never adds a sidecar guard.
				spec.TempGuard = map[rtnl.Family]bool{f: true}
				if got := spec.Rules(f); !reflect.DeepEqual(got, want) {
					t.Fatalf("rules: %v, want %v", got, want)
				}
				actual := append([]rtnl.Rule{rule(f, 0, table(rtnl.TableLocal))}, want...)
				if got := Diff(spec, f, actual, DiffOptions{}); len(got) != 0 {
					t.Fatalf("exact diff: %v", got)
				}
				if ready, fb := FamilyStatus(spec, f, actual, nativeRoutes(f), StatusOptions{TunnelAddress: netip.MustParseAddr(addrOf(f)), ExitIfIndex: exitIfIndex}); !ready || !fb {
					t.Fatalf("exact status: ready=%v fallback=%v", ready, fb)
				}
				missing := Diff(spec, f, nil, DiffOptions{})
				if len(missing) != len(want) || missing[0].Priority != 97 || missing[1].Priority != 96 {
					t.Fatalf("install order: %v", missing)
				}
				for _, bad := range [][]rtnl.Rule{append(actual, want[0]), append(actual, rule(f, 50, table(rtnl.TableMain))), without(actual, 96)} {
					if ready, _ := FamilyStatus(spec, f, bad, nativeRoutes(f), StatusOptions{TunnelAddress: netip.MustParseAddr(addrOf(f)), ExitIfIndex: exitIfIndex}); ready {
						t.Fatalf("accepted drift: %v", bad)
					}
				}
				if n > 1 {
					bad := append([]rtnl.Rule(nil), actual...)
					bad[3] = bad[4] // duplicate one LAN and lose another
					if ready, _ := FamilyStatus(spec, f, bad, nativeRoutes(f), StatusOptions{TunnelAddress: netip.MustParseAddr(addrOf(f)), ExitIfIndex: exitIfIndex}); ready {
						t.Fatal("accepted duplicate/missing LAN rule")
					}
				}
				spec.LeaveReturnPath = map[rtnl.Family]bool{f: true}
				if len(spec.RulesAt(f, 94)) != 0 || len(spec.RulesAt(f, 98)) != 0 {
					t.Fatal("return-path pair not left to its owner")
				}
			})
		}
	}
}

func TestNativeSidecarPlanAndRoutingStatus(t *testing.T) {
	spec := sidecarSpec()
	for p := uint32(0); p <= 105; p++ {
		if spec.Owned(p) != (p >= 1 && p <= 98) {
			t.Fatalf("owned %d", p)
		}
	}
	if !reflect.DeepEqual(spec.Interest().Tables, []uint32{51821, rtnl.TableMain}) {
		t.Fatal(spec.Interest())
	}
	snap := nativeSnapshot()
	snap.Links = []rtnl.Link{snap.Links[0], snap.Links[1], snap.Links[3]} // no overlay
	for _, f := range families {
		snap.Rules[f] = append([]rtnl.Rule{rule(f, 0, table(rtnl.TableLocal))}, spec.Rules(f)...)
		snap.Addrs[f] = []rtnl.Addr{{Family: f, Index: exitIfIndex, Local: netip.MustParsePrefix(hostOf(f))}}
		if p := spec.PlanFamily(snap, f, PlanInput{}); !p.Healthy() || p.HostRefresh || p.HostIf.Name != "eth0" {
			t.Fatalf("healthy plan: %+v", p)
		}
		bad := *snap
		bad.Rules = map[rtnl.Family][]rtnl.Rule{f: {rule(f, 0, table(rtnl.TableLocal)), rule(f, 50, table(rtnl.TableMain))}}
		bad.Routes = nil
		p := spec.PlanFamily(&bad, f, PlanInput{})
		if p.Rules[0].Priority != 97 || p.Rules[1].Priority != 96 || p.Rules[len(p.Rules)-1].Kind != Del || p.Routes[0].Kind != AddFallback || p.Routes[1].Kind != AddTunnel {
			t.Fatalf("repair plan: %+v", p)
		}
	}
	if protected, fallback := RoutingStatus(spec, snap, RoutingOptions{RequireAddress: true}); !protected || !fallback {
		t.Fatalf("sidecar without forwarding sysctl: %v %v", protected, fallback)
	}
	// A tunnel-less namespace holds the contract with only its fallbacks.
	snap.Links = snap.Links[:2]
	for _, f := range families {
		snap.Routes[f] = []rtnl.Route{FallbackRoute(f, spec.Config.Table)}
		snap.Addrs[f] = nil
		if p := spec.PlanFamily(snap, f, PlanInput{}); !p.Healthy() || p.Tunnel != TunnelNone {
			t.Fatalf("tunnel absent: %+v", p)
		}
	}
}

func TestSpecCloneCopiesSidecarLANs(t *testing.T) {
	spec := sidecarSpec()
	spec.Config.LAN = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	spec.Config.LAN6 = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}
	copy := spec.Clone()
	copy.Config.LAN[0], copy.Config.LAN6[0] = netip.Prefix{}, netip.Prefix{}
	if !spec.Config.LAN[0].IsValid() || !spec.Config.LAN6[0].IsValid() {
		t.Fatal("clone shares LAN slices")
	}
}
