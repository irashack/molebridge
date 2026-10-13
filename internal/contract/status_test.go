package contract

// Ported from tools/test_runtime.py (the family_status tests),
// tools/test_gluetun.py (the validator, host table and overlay tests) and
// tools/test_gluetun_transition.py (gluetun_transition_status). Where the
// Python fed `ip -j` JSON, these build decoded rules with the helpers in
// helpers_test.go; tests of JSON-only quirks (a prefix that is a string, an
// ipproto that is a list) have no typed counterpart: a decoded rule cannot be
// malformed that way.

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/irashack/molebridge/internal/rtnl"
)

var families = []rtnl.Family{rtnl.V4, rtnl.V6}

func TestHealthyNativeContract(t *testing.T) {
	for _, f := range families {
		ready, fallback := nativeStatus(nativeRules(f), nativeRoutes(f), f, true)
		if !ready || !fallback {
			t.Errorf("%s: %v %v", f, ready, fallback)
		}
	}
}

func TestDetachedRoutingSelectorsAreUnhealthy(t *testing.T) { // test_detached_routing_selectors_are_unhealthy
	for _, tc := range []struct {
		priority uint32
		flag     opt
	}{{95, iifDetached()}, {96, oifDetached()}} {
		rules := nativeRules(rtnl.V4)
		tc.flag(at(t, rules, tc.priority))
		ready, fallback := nativeStatus(rules, nativeRoutes(rtnl.V4), rtnl.V4, true)
		if ready || !fallback {
			t.Errorf("%d: %v %v", tc.priority, ready, fallback)
		}
	}
}

func TestNarrowedOrInvertedRuleIsNotHealthy(t *testing.T) { // test_narrowed_or_inverted_rule_is_not_healthy
	for name, extra := range map[string]opt{
		"fwmark": maskedMark(1, 0xffffffff), "src": from("192.0.2.5/32"), "not": not(), "suppress": suppress(0),
	} {
		rules := nativeRules(rtnl.V4)
		extra(at(t, rules, 95))
		if ready, _ := nativeStatus(rules, nativeRoutes(rtnl.V4), rtnl.V4, true); ready {
			t.Errorf("%s: healthy", name)
		}
	}
}

func TestKernelLocalRuleLeftInPlaceIsUnhealthy(t *testing.T) { // test_kernel_local_rule_left_in_place_is_unhealthy
	for _, f := range families {
		with := append([]rtnl.Rule{rule(f, 0, table(rtnl.TableLocal))}, nativeRules(f)...)
		if ready, fb := nativeStatus(with, nativeRoutes(f), f, true); ready || !fb {
			t.Errorf("%s: %v %v", f, ready, fb)
		}
		if ready, fb := nativeStatus(nativeRules(f), nativeRoutes(f), f, true); !ready || !fb {
			t.Errorf("%s: %v %v", f, ready, fb)
		}
	}
}

func TestLocalDeliveryRuleMustBeExact(t *testing.T) { // test_local_delivery_rule_must_be_exact
	changes := map[string]func(*rtnl.Rule){
		"inversion dropped":  func(r *rtnl.Rule) { r.Flags &^= rtnl.FIBRuleInvert },
		"other interface":    func(r *rtnl.Rule) { r.IifName = "eth0" },
		"the tunnel":         func(r *rtnl.Rule) { r.IifName = "mullvad" },
		"main table":         func(r *rtnl.Rule) { r.Table = rtnl.TableMain },
		"numeric main table": func(r *rtnl.Rule) { r.Table = 254 },
		"fwmark":             func(r *rtnl.Rule) { r.FwMark, r.FwMask = rtnl.Some(uint32(0x1bd00)), rtnl.Some(uint32(0xffffffff)) },
		"src":                func(r *rtnl.Rule) { r.Src = netip.MustParsePrefix("192.0.2.0/24") },
		"detached":           func(r *rtnl.Rule) { r.Flags |= rtnl.FIBRuleIifDetached },
		"unreachable":        func(r *rtnl.Rule) { r.Action, r.Table = rtnl.FRActUnreachable, 0 },
	}
	for name, change := range changes {
		rules := nativeRules(rtnl.V4)
		change(at(t, rules, 1))
		if ready, _ := nativeStatus(rules, nativeRoutes(rtnl.V4), rtnl.V4, true); ready {
			t.Errorf("%s: healthy", name)
		}
	}
}

func TestLocalDeliveryRuleMustBeInverted(t *testing.T) { // test_local_delivery_rule_must_be_inverted
	rules := nativeRules(rtnl.V4)
	at(t, rules, 1).Flags = 0
	if ready, _ := nativeStatus(rules, nativeRoutes(rtnl.V4), rtnl.V4, true); ready {
		t.Fatal("healthy")
	}
}

func TestNoLaterLocalRuleMayMatchTheOverlay(t *testing.T) { // test_no_later_local_rule_may_match_the_overlay
	cases := []struct {
		name    string
		rule    rtnl.Rule
		healthy bool
	}{
		{"kernel default", rule(rtnl.V4, 32765, table(rtnl.TableLocal)), false},
		{"numeric local", rule(rtnl.V4, 32765, table(255)), false},
		{"overlay interface", rule(rtnl.V4, 200, iif("wt0"), table(rtnl.TableLocal)), false},
		{"inverted for another interface", rule(rtnl.V4, 200, not(), iif("eth0"), table(rtnl.TableLocal)), false},
		{"narrowed inversion", rule(rtnl.V4, 200, not(), iif("wt0"), mark(1), table(rtnl.TableLocal)), false},
		{"oif only", rule(rtnl.V4, 200, oif("wt0"), table(rtnl.TableLocal)), false},
		{"loopback only", rule(rtnl.V4, 200, iif("lo"), table(rtnl.TableLocal)), true},
		{"another guard", rule(rtnl.V4, 200, not(), iif("wt0"), table(rtnl.TableLocal)), true},
		{"main table", rule(rtnl.V4, 200, table(rtnl.TableMain)), true},
	}
	for _, c := range cases {
		if got := LocalRuleAdmitsOverlay(c.rule, "wt0"); got == c.healthy {
			t.Errorf("%s: admits = %v", c.name, got)
		}
		rules := append(nativeRules(rtnl.V4), c.rule)
		if ready, _ := nativeStatus(rules, nativeRoutes(rtnl.V4), rtnl.V4, true); ready != c.healthy {
			t.Errorf("%s: healthy = %v", c.name, ready)
		}
	}
}

func TestOverlayMustBeKernelWireguard(t *testing.T) { // test_overlay_must_be_kernel_wireguard
	cases := []struct {
		name  string
		links []rtnl.Link
		want  bool
	}{
		{"wireguard", []rtnl.Link{{Name: "wt0", Kind: "wireguard"}}, true},
		{"tun", []rtnl.Link{{Name: "wt0", Kind: "tun"}}, false},
		{"no linkinfo", []rtnl.Link{{Name: "wt0"}}, false},
		{"another name", []rtnl.Link{{Name: "wt1", Kind: "wireguard"}}, false},
		{"none", nil, false},
		{"among others", []rtnl.Link{{Name: "lo"}, {Name: "eth0", Kind: "veth"}, {Name: "wt0", Kind: "wireguard"}}, true},
	}
	for _, c := range cases {
		if got := OverlayIsKernelWireguard(c.links, "wt0"); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestNetbirdKernelFirewallDetection(t *testing.T) { // test_netbird_kernel_firewall_detection
	cases := []struct {
		name   string
		chains []NftChain
		want   bool
	}{
		{"iptables backend", []NftChain{{"ip", "filter", "INPUT"}, {"ip", "filter", "NETBIRD-RT-FWD-IN"}}, true},
		{"nftables backend", []NftChain{{"ip", "netbird", "netbird-acl-input-rules"}}, true},
		{"nat chain", []NftChain{{"ip", "nat", "NETBIRD-RT-NAT"}}, true},
		{"other tables only", []NftChain{{"ip", "filter", "INPUT"}, {"inet", "molebridge_guard", "prerouting"}}, false},
		{"IPv6 table only", []NftChain{{"ip6", "netbird", "netbird-acl-input-rules"}}, false},
		{"empty", nil, false},
	}
	for _, c := range cases {
		if got := NetbirdFirewallPresent(c.chains); got != c.want {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestEarlierRuleAndUnsafeTableRouteRejected(t *testing.T) { // test_earlier_rule_and_unsafe_table_route_rejected
	early := append([]rtnl.Rule{rule(rtnl.V4, 50, table(rtnl.TableMain))}, nativeRules(rtnl.V4)...)
	if ready, _ := nativeStatus(early, nativeRoutes(rtnl.V4), rtnl.V4, true); ready {
		t.Error("an earlier rule accepted")
	}
	extra := append(nativeRoutes(rtnl.V4), rtnl.Route{Family: rtnl.V4, Dst: netip.MustParsePrefix("192.0.2.0/24"),
		Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2))})
	if ready, _ := nativeStatus(nativeRules(rtnl.V4), extra, rtnl.V4, true); ready {
		t.Error("an unsafe table route accepted")
	}
}

func TestWrongOrMissingOverlayPrefixRejected(t *testing.T) { // test_wrong_or_malformed_rule_prefix_rejected
	for _, dst := range []string{"192.0.2.0/23", "192.0.2.0/25", "192.0.2.0/32", ""} {
		rules := nativeRules(rtnl.V4)
		r := at(t, rules, 90)
		r.Dst = netip.Prefix{}
		if dst != "" {
			r.Dst = netip.MustParsePrefix(dst)
		}
		if ready, _ := nativeStatus(rules, nativeRoutes(rtnl.V4), rtnl.V4, true); ready {
			t.Errorf("%q accepted", dst)
		}
	}
}

func TestHostOverlayRangeIsAccepted(t *testing.T) { // test_host_rule_prefix_omits_dstlen
	rules := nativeRules(rtnl.V4)
	at(t, rules, 90).Dst = netip.MustParsePrefix("192.0.2.0/32")
	spec := nativeSpec()
	spec.Config.Overlay = netip.MustParsePrefix("192.0.2.0/32")
	ready, fb := FamilyStatus(spec, rtnl.V4, rules, nativeRoutes(rtnl.V4),
		StatusOptions{TunnelAddress: netip.MustParseAddr(tunnel4), ExitIfIndex: exitIfIndex})
	if !ready || !fb {
		t.Fatalf("%v %v", ready, fb)
	}
}

func TestReturnPathRuleMustMatchTheTunnelAddressAndIcmpOnly(t *testing.T) {
	// test_return_path_rule_must_match_the_tunnel_address_and_icmp_only
	for _, f := range families {
		other := "203.0.113.9/32"
		wide := "203.0.113.0/24"
		otherProto := uint8(58)
		if f == rtnl.V6 {
			other, wide, otherProto = "2001:db8:3::9/128", "2001:db8:3::/64", 1
		}
		changes := map[string]func(rules *[]rtnl.Rule){
			"other address": func(r *[]rtnl.Rule) { at(t, *r, 94).Src = netip.MustParsePrefix(other) },
			"prefix":        func(r *[]rtnl.Rule) { at(t, *r, 94).Src = netip.MustParsePrefix(wide) },
			"iif":           func(r *[]rtnl.Rule) { at(t, *r, 94).IifName = "mullvad" },
			"oif":           func(r *[]rtnl.Rule) { at(t, *r, 94).OifName = "mullvad" },
			"main":          func(r *[]rtnl.Rule) { at(t, *r, 94).Table = rtnl.TableMain },
			"missing":       func(r *[]rtnl.Rule) { *r = without(*r, 94) },
			// The pre-qualifier rule: every protocol from the tunnel address.
			"any protocol":     func(r *[]rtnl.Rule) { at(t, *r, 94).IPProto = rtnl.Opt[uint8]{} },
			"other protocol":   func(r *[]rtnl.Rule) { at(t, *r, 94).IPProto = rtnl.Some(otherProto) },
			"unknown protocol": func(r *[]rtnl.Rule) { at(t, *r, 94).IPProto = rtnl.Some(uint8(99)) },
		}
		for name, change := range changes {
			rules := nativeRules(f)
			change(&rules)
			ready, fb := nativeStatus(rules, nativeRoutes(f), f, true)
			if ready || !fb {
				t.Errorf("%s %s: %v %v", f, name, ready, fb)
			}
		}
		if ready, fb := nativeStatus(nativeRules(f), nativeRoutes(f), f, true); !ready || !fb {
			t.Errorf("%s: unchanged %v %v", f, ready, fb)
		}
	}
}

func TestNumericProtocolSelectorMeansTheSameRule(t *testing.T) { // test_numeric_protocol_selector_means_the_same_rule
	// The kernel reports the number; the name is only how iproute2 prints it.
	for _, f := range families {
		rules := nativeRules(f)
		n := uint8(1)
		if f == rtnl.V6 {
			n = 58
		}
		at(t, rules, 94).IPProto = rtnl.Some(n)
		if ready, fb := nativeStatus(rules, nativeRoutes(f), f, true); !ready || !fb {
			t.Errorf("%s: %v %v", f, ready, fb)
		}
	}
}

func TestNoOtherRuleMayCarryAProtocolSelector(t *testing.T) { // test_no_other_rule_may_carry_a_protocol_selector
	for _, p := range []uint32{90, 95, 96, 97} {
		rules := nativeRules(rtnl.V4)
		at(t, rules, p).IPProto = rtnl.Some(uint8(1))
		if ready, fb := nativeStatus(rules, nativeRoutes(rtnl.V4), rtnl.V4, true); ready || !fb {
			t.Errorf("%d: %v %v", p, ready, fb)
		}
	}
}

func TestTunnelWithoutAFamilyExpectsNoReturnPathRule(t *testing.T) { // test_tunnel_without_a_family_expects_no_return_path_rule
	fallbackOnly := nativeRoutes(rtnl.V6)[1:]
	if ready, fb := nativeStatus(nativeRules(rtnl.V6), fallbackOnly, rtnl.V6, false); ready || !fb {
		t.Errorf("with 94 and 98 present: %v %v", ready, fb)
	}
	if ready, fb := nativeStatus(without(nativeRules(rtnl.V6), 94, 98), fallbackOnly, rtnl.V6, false); !ready || !fb {
		t.Errorf("without them: %v %v", ready, fb)
	}
	// The backstop alone is as unexpected as the return-path rule alone.
	if ready, fb := nativeStatus(without(nativeRules(rtnl.V6), 94), fallbackOnly, rtnl.V6, false); ready || !fb {
		t.Errorf("backstop alone: %v %v", ready, fb)
	}
}

func TestMissingRulePreventsSuccess(t *testing.T) { // test_missing_rule_prevents_success_and_switch
	for _, f := range families {
		for _, p := range []uint32{1, 90, 94, 95, 96, 97, 98} {
			if ready, _ := nativeStatus(without(nativeRules(f), p), nativeRoutes(f), f, true); ready {
				t.Errorf("%s rule %d: healthy", f, p)
			}
		}
	}
}

func TestMissingFallbackPreventsSuccess(t *testing.T) { // test_missing_fallback_prevents_switch_success
	routes := nativeRoutes(rtnl.V6)[:1]
	if ready, fb := nativeStatus(nativeRules(rtnl.V6), routes, rtnl.V6, true); ready || fb {
		t.Errorf("%v %v", ready, fb)
	}
}

func TestSingleFamilyRouteLossIsUnhealthy(t *testing.T) { // test_single_family_route_loss_is_unhealthy_and_refuses_switch
	for _, f := range families {
		if ready, fb := nativeStatus(nativeRules(f), nativeRoutes(f)[1:], f, true); ready || !fb {
			t.Errorf("%s: %v %v", f, ready, fb)
		}
	}
}

func TestLinkdownTunnelDefaultDoesNotCount(t *testing.T) {
	routes := nativeRoutes(rtnl.V4)
	routes[0].Flags |= rtnl.RTNHFLinkdown
	if ready, _ := nativeStatus(nativeRules(rtnl.V4), routes, rtnl.V4, true); ready {
		t.Fatal("a linkdown default route counted")
	}
}

func TestTunnelRouteWithAGatewayIsUnsafe(t *testing.T) {
	routes := nativeRoutes(rtnl.V4)
	routes[0].Gateway = netip.MustParseAddr("203.0.113.2")
	if ready, _ := nativeStatus(nativeRules(rtnl.V4), routes, rtnl.V4, true); ready {
		t.Fatal("healthy")
	}
}

// A unicast route out of the tunnel that is not the default is tolerated by
// family_status (the repair pass removes it); the Python did the same.
func TestOtherRouteThroughTheTunnelIsToleratedByStatus(t *testing.T) {
	routes := append(nativeRoutes(rtnl.V4), rtnl.Route{Family: rtnl.V4, Dst: netip.MustParsePrefix("203.0.113.0/24"),
		Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(exitIfIndex))})
	if ready, _ := nativeStatus(nativeRules(rtnl.V4), routes, rtnl.V4, true); !ready {
		t.Fatal("unhealthy")
	}
}

// ---- the gluetun backend (tools/test_gluetun.py) ----

func glRules(f rtnl.Family) []rtnl.Rule {
	ov := overlayOf(f)
	rules := []rtnl.Rule{
		rule(f, 1, not(), iif("wt0"), table(rtnl.TableLocal)),
		rule(f, 88, mark(0x1bd00), iif("lo"), table(51822)),
		rule(f, 89, mark(0x1bd00), iif("lo"), unreachable()),
		rule(f, 90, to(ov), iif("wg0"), table(rtnl.TableMain)),
		rule(f, 91, to(ov), iif("lo"), table(rtnl.TableMain), suppress(0)),
		rule(f, 92, to(ov), iif("lo"), unreachable()),
		rule(f, 94, from(hostOf(f)), proto(icmpOf(f)), table(51821)),
		rule(f, 95, iif("wt0"), table(51821)),
		rule(f, 96, oif("wg0"), table(51821)),
		rule(f, 97, iif("wt0"), unreachable()),
		rule(f, 98, to("198.51.100.0/28"), table(rtnl.TableMain)),
		rule(f, 101, not(), mark(0xca6c), table(51820)),
		rule(f, 102, mark(0xca6c), iif("lo"), table(rtnl.TableMain)),
		rule(f, 103, iif("lo"), table(51822), suppress(0)),
		rule(f, 104, iif("lo"), unreachable()),
		rule(f, 105, table(rtnl.TableMain), suppress(0)),
		rule(f, 110, not(), mark(0x1bd00), table(7120)),
	}
	return rules
}

func glSpec() Spec { return Spec{Config: gluetunConfig()} }

func glStatus(rules []rtnl.Rule, f rtnl.Family, spec Spec) (bool, bool) {
	routes := []rtnl.Route{
		tunnelRoute(f),
		fallbackRoute(f),
	}
	return FamilyStatus(spec, f, rules, routes, StatusOptions{TunnelAddress: netip.MustParseAddr(addrOf(f)), ExitIfIndex: exitIfIndex})
}

func TestValidatorAcceptsTheGluetunRuleSet(t *testing.T) { // test_validator_accepts_the_gluetun_rule_set
	for _, f := range families {
		if ready, fb := glStatus(glRules(f), f, glSpec()); !ready || !fb {
			t.Errorf("%s: %v %v", f, ready, fb)
		}
	}
}

func TestValidatorRejectsBrokenControlPlaneRules(t *testing.T) { // test_validator_rejects_broken_control_plane_rules
	cases := map[string]func(*[]rtnl.Rule){
		"88 removed":           func(r *[]rtnl.Rule) { *r = without(*r, 88) },
		"89 removed":           func(r *[]rtnl.Rule) { *r = without(*r, 89) },
		"88 without iif":       func(r *[]rtnl.Rule) { at(t, *r, 88).IifName = "" },
		"88 other mark":        func(r *[]rtnl.Rule) { at(t, *r, 88).FwMark = rtnl.Some(uint32(0x1bd21)) },
		"89 partial mask":      func(r *[]rtnl.Rule) { at(t, *r, 89).FwMask = rtnl.Some(uint32(0xff00)) },
		"88 main table":        func(r *[]rtnl.Rule) { at(t, *r, 88).Table = rtnl.TableMain },
		"89 second rule":       func(r *[]rtnl.Rule) { *r = append(*r, rule(rtnl.V4, 89, mark(0x1bd00), table(rtnl.TableMain))) },
		"91 removed":           func(r *[]rtnl.Rule) { *r = without(*r, 91) },
		"92 removed":           func(r *[]rtnl.Rule) { *r = without(*r, 92) },
		"91 without suppress":  func(r *[]rtnl.Rule) { at(t, *r, 91).SuppressPrefixLen = rtnl.Opt[uint32]{} },
		"91 suppress 1":        func(r *[]rtnl.Rule) { at(t, *r, 91).SuppressPrefixLen = rtnl.Some(uint32(1)) },
		"91 host table":        func(r *[]rtnl.Rule) { at(t, *r, 91).Table = 51822 },
		"92 without iif":       func(r *[]rtnl.Rule) { at(t, *r, 92).IifName = "" },
		"92 wider prefix":      func(r *[]rtnl.Rule) { at(t, *r, 92).Dst = netip.MustParsePrefix("192.0.0.0/8") },
		"95 suppress":          func(r *[]rtnl.Rule) { at(t, *r, 95).SuppressPrefixLen = rtnl.Some(uint32(0)) },
		"102 removed":          func(r *[]rtnl.Rule) { *r = without(*r, 102) },
		"103 removed":          func(r *[]rtnl.Rule) { *r = without(*r, 103) },
		"102 control mark":     func(r *[]rtnl.Rule) { at(t, *r, 102).FwMark = rtnl.Some(uint32(0x1bd00)) },
		"102 exit table":       func(r *[]rtnl.Rule) { at(t, *r, 102).Table = 51821 },
		"104 without iif":      func(r *[]rtnl.Rule) { at(t, *r, 104).IifName = "" },
		"104 removed":          func(r *[]rtnl.Rule) { *r = without(*r, 104) },
		"103 without suppress": func(r *[]rtnl.Rule) { at(t, *r, 103).SuppressPrefixLen = rtnl.Opt[uint32]{} },
		"103 main table":       func(r *[]rtnl.Rule) { at(t, *r, 103).Table = rtnl.TableMain },
		"102 second rule":      func(r *[]rtnl.Rule) { *r = append(*r, rule(rtnl.V4, 102, table(rtnl.TableMain))) },
	}
	for name, change := range cases {
		for _, f := range families {
			rules := glRules(f)
			change(&rules)
			if ready, _ := glStatus(rules, f, glSpec()); ready {
				t.Errorf("%s (%s): healthy", name, f)
			}
		}
	}
}

func TestValidatorAcceptsAnExplicitAllOnesMask(t *testing.T) { // test_validator_accepts_an_explicit_all_ones_mask_and_numeric_mark
	rules := glRules(rtnl.V4)
	r := at(t, rules, 88)
	r.FwMark, r.FwMask = rtnl.Some(uint32(113920)), rtnl.Some(uint32(0xffffffff))
	if ready, fb := glStatus(rules, rtnl.V4, glSpec()); !ready || !fb {
		t.Fatalf("%v %v", ready, fb)
	}
}

func TestWireguardBackendKeepsRejectingMarkRules(t *testing.T) { // test_wireguard_backend_keeps_rejecting_mark_rules
	// gluetun's own 98 (local subnets) goes too: natively, 98 is the backstop behind 94.
	rules := without(glRules(rtnl.V4), 88, 89, 91, 92, 98, 102, 103, 104)
	rules = append(rules, rule(rtnl.V4, 98, from("203.0.113.1/32"), proto(1), unreachable()))
	cfg := nativeConfig()
	cfg.ExitIf = "wg0"
	spec := Spec{Config: cfg}
	routes := []rtnl.Route{
		tunnelRoute(rtnl.V4),
		fallbackRoute(rtnl.V4),
	}
	opt := StatusOptions{TunnelAddress: netip.MustParseAddr(tunnel4), ExitIfIndex: exitIfIndex}
	if ready, fb := FamilyStatus(spec, rtnl.V4, rules, routes, opt); !ready || !fb {
		t.Fatalf("%v %v", ready, fb)
	}
	if ready, _ := FamilyStatus(spec, rtnl.V4, glRules(rtnl.V4), routes, opt); ready {
		t.Fatal("the gluetun rule set passed the native contract")
	}
}

func hostCfg() Config { return gluetunConfig() }

func hostRoute(f rtnl.Family, dst string, gateway string) rtnl.Route {
	r := rtnl.Route{Family: f, Table: 51822, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2))}
	if dst == "default" {
		r.Dst = zero(f)
	} else {
		r.Dst = netip.MustParsePrefix(dst)
	}
	if gateway != "" {
		r.Gateway = netip.MustParseAddr(gateway)
	}
	return r
}

func TestHostTableStatus(t *testing.T) { // test_host_table_status
	cfg := hostCfg()
	_ = cfg
	cases := []struct {
		name   string
		routes []rtnl.Route
		f      rtnl.Family
		ok     bool
	}{
		{"default and on-link", []rtnl.Route{hostRoute(4, "198.51.100.0/28", ""), hostRoute(4, "default", "198.51.100.2")}, rtnl.V4, true},
		{"no default", []rtnl.Route{hostRoute(4, "198.51.100.0/28", "")}, rtnl.V4, false},
		{"empty IPv6", nil, rtnl.V6, true},
		{"empty IPv4", nil, rtnl.V4, false},
		{"a route through the tunnel", []rtnl.Route{hostRoute(4, "default", "198.51.100.2"),
			{Family: 4, Dst: netip.MustParsePrefix("10.0.0.0/8"), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(9))}}, rtnl.V4, false},
		{"IPv6 default through the overlay", []rtnl.Route{{Family: 6, Dst: zero(6), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(3))}}, rtnl.V6, false},
		{"unreachable", []rtnl.Route{{Family: 6, Dst: zero(6), Type: rtnl.RTNUnreachable, Oif: rtnl.Some(uint32(2))}}, rtnl.V6, false},
		{"multipath", []rtnl.Route{{Family: 4, Dst: zero(4), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2)), MultiPath: true}}, rtnl.V4, false},
		{"a gateway on a non-default route", []rtnl.Route{hostRoute(4, "10.0.0.0/8", "198.51.100.3"), hostRoute(4, "default", "198.51.100.2")}, rtnl.V4, false},
	}
	for _, c := range cases {
		if got := HostTableStatus(c.routes, 2, c.f, nil, false); got != c.ok {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

func TestHostTableStatusComparesWithTheMainTable(t *testing.T) { // test_host_table_status_compares_with_the_main_table
	main := []rtnl.Route{
		{Family: 4, Table: 254, Dst: netip.MustParsePrefix("198.51.100.0/28"), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2)), Protocol: 2},
		hostRoute(4, "default", "198.51.100.2"),
		{Family: 4, Dst: netip.MustParsePrefix("192.0.2.0/24"), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(3))},
		hostRoute(4, "10.0.0.0/8", "198.51.100.3"),
	}
	copy := []rtnl.Route{hostRoute(4, "198.51.100.0/28", ""), hostRoute(4, "default", "198.51.100.2")}
	if !HostTableStatus(copy, 2, 4, main, true) {
		t.Error("a faithful copy")
	}
	if HostTableStatus(copy[1:], 2, 4, main, true) {
		t.Error("a copy missing the on-link route")
	}
	main6 := []rtnl.Route{hostRoute(6, "default", "fe80::1")}
	if HostTableStatus(nil, 2, 6, main6, true) {
		t.Error("an empty table against a main table with a default")
	}
	if !HostTableStatus(nil, 2, 6, nil, true) {
		t.Error("empty against empty")
	}
}

// ---- gluetun_transition_status (tools/test_gluetun_transition.py) ----

const (
	oldAddr   = "10.64.0.2"
	newAddr   = "10.64.0.9"
	thirdAddr = "10.64.0.77"
)

func glSpec4() Spec { return Spec{Config: gluetunConfig()} }

func tr94(addr string) rtnl.Rule {
	return rule(4, 94, from(addr+"/32"), proto(1), table(51821))
}

// snapshot is test_gluetun_transition.snapshot: the IPv4 rules with rule 94
// for the given addresses, optionally with 90 and 96 detached.
func trSnapshot(returnPaths []string, detached bool) []rtnl.Rule {
	var out []rtnl.Rule
	for _, r := range glRules(rtnl.V4) {
		if r.Priority == 94 {
			continue
		}
		if r.Priority >= 105 {
			continue
		}
		if detached && r.Priority == 90 {
			r.Flags |= rtnl.FIBRuleIifDetached
		}
		if detached && r.Priority == 96 {
			r.Flags |= rtnl.FIBRuleOifDetached
		}
		out = append(out, r)
	}
	for _, a := range returnPaths {
		out = append(out, tr94(a))
	}
	// Sorted by priority, as the kernel lists them.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Priority > out[j].Priority; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

var (
	trFallback = fallbackRoute(rtnl.V4)
	trTunnel   = rtnl.Route{Family: 4, Dst: zero(4), Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(exitIfIndex)), Scope: rtnl.RTScopeLink}
)

func trStatus(rules []rtnl.Rule, routes []rtnl.Route, address string, present, up bool) (bool, bool) {
	opt := TransitionOptions{PreviousAddress: netip.MustParseAddr(oldAddr), InterfacePresent: present, InterfaceUp: up,
		ExitIfIndex: exitIfIndex}
	if address != "" {
		opt.TunnelAddress = netip.MustParseAddr(address)
	}
	return GluetunTransitionStatus(glSpec4(), rtnl.V4, rules, routes, opt)
}

func TestEachReconnectionStateIsSafeAndItsTwinIsNot(t *testing.T) { // test_each_reconnection_state_is_safe_and_its_twin_is_not
	foreign := rtnl.Route{Family: 4, Dst: zero(4), Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2)),
		Gateway: netip.MustParseAddr("198.51.100.2")}
	type state struct {
		rules   []rtnl.Rule
		routes  []rtnl.Route
		address string
		present bool
	}
	steps := []struct {
		name      string
		good, bad state
	}{
		{"interface removed, rules detached",
			state{trSnapshot([]string{oldAddr}, true), []rtnl.Route{trFallback}, "", false},
			state{trSnapshot([]string{oldAddr, thirdAddr}, true), []rtnl.Route{trFallback}, "", false}},
		{"interface removed, the guard already took rule 94",
			state{trSnapshot(nil, true), []rtnl.Route{trFallback}, "", false},
			state{without(trSnapshot(nil, true), 97), []rtnl.Route{trFallback}, "", false}},
		{"interface up, no address yet",
			state{trSnapshot([]string{oldAddr}, false), []rtnl.Route{trFallback}, "", true},
			state{trSnapshot([]string{oldAddr}, true), []rtnl.Route{trFallback}, "", true}},
		{"address present, rule 94 missing",
			state{trSnapshot(nil, false), []rtnl.Route{trFallback}, newAddr, true},
			state{trSnapshot(nil, false), nil, newAddr, true}},
		{"old and new rule 94 together",
			state{trSnapshot([]string{oldAddr, newAddr}, false), []rtnl.Route{trFallback}, newAddr, true},
			state{trSnapshot([]string{newAddr, newAddr}, false), []rtnl.Route{trFallback}, newAddr, true}},
		{"old rule removed, route still missing",
			state{trSnapshot([]string{newAddr}, false), []rtnl.Route{trFallback}, newAddr, true},
			state{trSnapshot([]string{newAddr}, false), []rtnl.Route{trFallback, foreign}, newAddr, true}},
	}
	for _, s := range steps {
		for label, c := range map[string]state{"good": s.good, "bad": s.bad} {
			safe, ready := trStatus(c.rules, c.routes, c.address, c.present, true)
			if safe != (label == "good") || ready {
				t.Errorf("%s (%s): safe=%v ready=%v", s.name, label, safe, ready)
			}
		}
	}
}

func TestTheRouteRestoredIsReady(t *testing.T) { // test_the_route_restored_is_ready
	safe, ready := trStatus(trSnapshot([]string{newAddr}, false), []rtnl.Route{trTunnel, trFallback}, newAddr, true, true)
	if !safe || !ready {
		t.Errorf("%v %v", safe, ready)
	}
	if safe, _ := trStatus(trSnapshot([]string{newAddr}, false), []rtnl.Route{trTunnel}, newAddr, true, true); safe {
		t.Error("the fallback gone")
	}
}

func TestAnythingElseStillAborts(t *testing.T) { // test_anything_else_still_aborts
	changes := map[string]func([]rtnl.Rule) []rtnl.Rule{}
	for _, p := range []uint32{1, 88, 89, 91, 92, 95, 97, 102, 103, 104} {
		p := p
		changes[fmt.Sprintf("rule %d missing", p)] = func(r []rtnl.Rule) []rtnl.Rule { return without(r, p) }
	}
	changes["second rule 95"] = func(r []rtnl.Rule) []rtnl.Rule { return append(r, rule(4, 95, iif("wt0"), table(51821))) }
	changes["rule 94 for a third address"] = func(r []rtnl.Rule) []rtnl.Rule { return append(r, tr94(thirdAddr)) }
	changes["kernel rule 0"] = func(r []rtnl.Rule) []rtnl.Rule { return append(r, rule(4, 0, table(rtnl.TableLocal))) }
	changes["rule 96 into main"] = func(r []rtnl.Rule) []rtnl.Rule {
		at(t, r, 96).Table = rtnl.TableMain
		return r
	}
	changes["rule 95 detached"] = func(r []rtnl.Rule) []rtnl.Rule {
		at(t, r, 95).Flags |= rtnl.FIBRuleIifDetached
		return r
	}
	for name, change := range changes {
		for _, c := range []struct {
			present bool
			address string
		}{{false, ""}, {true, ""}, {true, newAddr}} {
			rules := change(trSnapshot([]string{oldAddr}, !c.present))
			if safe, _ := trStatus(rules, []rtnl.Route{trFallback}, c.address, c.present, true); safe {
				t.Errorf("%s (present=%v address=%q): safe", name, c.present, c.address)
			}
		}
	}
}

func TestARule94NotInItsExactFormAborts(t *testing.T) { // test_a_rule_94_not_in_its_exact_form_aborts
	loose := append(trSnapshot(nil, false), rule(4, 94, from(oldAddr+"/32"), table(51821))) // no protocol selector
	if safe, _ := trStatus(loose, []rtnl.Route{trFallback}, newAddr, true, true); safe {
		t.Fatal("safe")
	}
}

func TestRules90To92AreConditionalOnTheOverlayRange(t *testing.T) { // test_rules_90_to_92_are_conditional_on_the_overlay_range
	cfg := gluetunConfig()
	cfg.Overlay6 = netip.Prefix{}
	var v6 []rtnl.Rule
	for _, r := range glRules(rtnl.V6) {
		if r.Priority == 94 || r.Priority == 90 || r.Priority == 91 || r.Priority == 92 || r.Priority >= 105 {
			continue
		}
		v6 = append(v6, r)
	}
	safe, _ := GluetunTransitionStatus(Spec{Config: cfg}, rtnl.V6, v6, []rtnl.Route{fallbackRoute(rtnl.V6)},
		TransitionOptions{InterfacePresent: true, InterfaceUp: true, ExitIfIndex: exitIfIndex})
	if !safe {
		t.Fatal("not safe")
	}
}

func TestOutsideASwitchTheFullValidationApplies(t *testing.T) { // test_outside_a_switch_the_full_validation_applies
	table := trSnapshot([]string{oldAddr}, true)
	if ready, _ := FamilyStatus(glSpec4(), rtnl.V4, table, []rtnl.Route{trFallback}, StatusOptions{ExitIfIndex: exitIfIndex}); ready {
		t.Fatal("detached rules passed outside a switch")
	}
}

// ---- routing_status (applier/apply.py), from one snapshot ----

func routingSnapshot() *rtnl.Snapshot {
	s := nativeSnapshot()
	s.Addrs[4] = []rtnl.Addr{{Family: 4, Index: exitIfIndex, Local: netip.MustParsePrefix(tunnel4 + "/32")}}
	s.Addrs[6] = []rtnl.Addr{{Family: 6, Index: exitIfIndex, Local: netip.MustParsePrefix(tunnel6 + "/128")}}
	return s
}

func TestRoutingStatusOfAHealthyExit(t *testing.T) {
	protected, fallback := RoutingStatus(nativeSpec(), routingSnapshot(), RoutingOptions{RequireAddress: true, ReturnPath: true})
	if !protected || !fallback {
		t.Fatalf("%v %v", protected, fallback)
	}
}

func TestReturnPathSysctlIsRequiredForHealth(t *testing.T) { // test_return_path_sysctl_is_required_for_health_and_switching
	for _, value := range []string{"0\n", "", "x"} {
		if ReturnPathEnabled(value) {
			t.Errorf("%q", value)
		}
		protected, _ := RoutingStatus(nativeSpec(), routingSnapshot(), RoutingOptions{RequireAddress: true, ReturnPath: ReturnPathEnabled(value)})
		if protected {
			t.Errorf("%q: protected", value)
		}
	}
	if !ReturnPathEnabled("1\n") || !ReturnPathEnabled(" 1 ") {
		t.Error("1 should enable")
	}
}

func TestUnsupportedTunnelAddressesAreUnhealthy(t *testing.T) { // test_unsupported_tunnel_addresses_are_unhealthy
	a := func(f rtnl.Family, text string) rtnl.Addr {
		p := netip.MustParsePrefix(text)
		return rtnl.Addr{Family: f, Index: exitIfIndex, Local: p}
	}
	for name, addrs := range map[string]map[rtnl.Family][]rtnl.Addr{
		"none":               {4: nil, 6: nil},
		"two in one family":  {4: {a(4, tunnel4+"/32"), a(4, "203.0.113.2/32")}, 6: {a(6, tunnel6+"/128")}},
		"IPv6 only":          {4: nil, 6: {a(6, tunnel6+"/128")}},
		"two IPv6 addresses": {4: {a(4, tunnel4+"/32")}, 6: {a(6, tunnel6+"/128"), a(6, "2001:db8:3::2/128")}},
	} {
		s := routingSnapshot()
		s.Addrs[4], s.Addrs[6] = addrs[4], addrs[6]
		if protected, _ := RoutingStatus(nativeSpec(), s, RoutingOptions{RequireAddress: true, ReturnPath: true}); protected {
			t.Errorf("%s: protected", name)
		}
	}
	// Link-local and host-scope addresses are not tunnel addresses.
	s := routingSnapshot()
	s.Addrs[6] = append(s.Addrs[6], rtnl.Addr{Family: 6, Index: exitIfIndex, Scope: rtnl.RTScopeLink, Local: netip.MustParsePrefix("fe80::1/64")})
	if protected, _ := RoutingStatus(nativeSpec(), s, RoutingOptions{RequireAddress: true, ReturnPath: true}); !protected {
		t.Error("a link-local address broke the judgment")
	}
}

func TestIPv4OnlyTunnelKeepsTheIPv6GuardWithoutAnIPv6Address(t *testing.T) { // test_ipv4_only_tunnel_keeps_ipv6_guard_without_requiring_ipv6_egress
	s := routingSnapshot()
	s.Addrs[6] = nil
	s.Rules[6] = without(s.Rules[6], 94, 98)
	s.Routes[6] = s.Routes[6][1:]
	if protected, fallback := RoutingStatus(nativeSpec(), s, RoutingOptions{RequireAddress: true, ReturnPath: true}); !protected || !fallback {
		t.Fatalf("%v %v", protected, fallback)
	}
}

func TestAnAddresslessInterfaceIsProtectedWhenItsGuardsAreIntact(t *testing.T) { // PIA before the first registration
	s := routingSnapshot()
	s.Addrs[4], s.Addrs[6] = nil, nil
	for _, f := range families {
		s.Rules[f] = without(s.Rules[f], 94, 98)
	}
	s.Routes[6] = s.Routes[6][1:]
	if protected, _ := RoutingStatus(nativeSpec(), s, RoutingOptions{RequireAddress: true, ReturnPath: true}); protected {
		t.Error("an address was required")
	}
	if protected, fallback := RoutingStatus(nativeSpec(), s, RoutingOptions{ReturnPath: true}); !protected || !fallback {
		t.Errorf("%v %v", protected, fallback)
	}
}

func TestRoutingStatusNeedsBothInterfaces(t *testing.T) {
	s := routingSnapshot()
	s.Links = s.Links[:3] // no tunnel interface
	if protected, _ := RoutingStatus(nativeSpec(), s, RoutingOptions{ReturnPath: true}); protected {
		t.Error("protected without the tunnel interface")
	}
	s = routingSnapshot()
	s.Links = append(s.Links[:2:2], s.Links[3])
	if protected, _ := RoutingStatus(nativeSpec(), s, RoutingOptions{ReturnPath: true}); protected {
		t.Error("protected without the overlay interface")
	}
}
