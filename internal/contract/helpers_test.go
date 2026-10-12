package contract

import (
	"net/netip"
	"testing"

	"github.com/irashack/molebridge/internal/rtnl"
)

// A small vocabulary for writing kernel rules the way `ip rule show` prints
// them, so a test reads like the shell or Python fixture it was ported from.

type opt func(*rtnl.Rule)

func rule(f rtnl.Family, priority uint32, opts ...opt) rtnl.Rule {
	r := rtnl.Rule{Family: f, Priority: priority, Action: rtnl.FRActToTbl}
	for _, o := range opts {
		o(&r)
	}
	return r
}

func not() opt         { return func(r *rtnl.Rule) { r.Flags |= rtnl.FIBRuleInvert } }
func iif(n string) opt { return func(r *rtnl.Rule) { r.IifName = n } }
func oif(n string) opt { return func(r *rtnl.Rule) { r.OifName = n } }
func table(t uint32) opt {
	return func(r *rtnl.Rule) { r.Action, r.Table = rtnl.FRActToTbl, t }
}
func unreachable() opt {
	return func(r *rtnl.Rule) { r.Action, r.Table = rtnl.FRActUnreachable, 0 }
}
func from(p string) opt { return func(r *rtnl.Rule) { r.Src = netip.MustParsePrefix(p) } }
func to(p string) opt   { return func(r *rtnl.Rule) { r.Dst = netip.MustParsePrefix(p) } }
func proto(p uint8) opt { return func(r *rtnl.Rule) { r.IPProto = rtnl.Some(p) } }
func mark(v uint32) opt {
	return func(r *rtnl.Rule) { r.FwMark, r.FwMask = rtnl.Some(v), rtnl.Some(uint32(0xffffffff)) }
}
func maskedMark(v, m uint32) opt {
	return func(r *rtnl.Rule) { r.FwMark, r.FwMask = rtnl.Some(v), rtnl.Some(m) }
}
func suppress(n uint32) opt { return func(r *rtnl.Rule) { r.SuppressPrefixLen = rtnl.Some(n) } }
func iifDetached() opt      { return func(r *rtnl.Rule) { r.Flags |= rtnl.FIBRuleIifDetached } }
func oifDetached() opt      { return func(r *rtnl.Rule) { r.Flags |= rtnl.FIBRuleOifDetached } }

const (
	tunnel4 = "203.0.113.1"
	tunnel6 = "2001:db8:3::1"
)

func nativeConfig() Config {
	return Config{Kind: Overlay, Backend: Native, Overlay: netip.MustParsePrefix("192.0.2.0/24"),
		Overlay6: netip.MustParsePrefix("2001:db8:1::/64"), OverlayIf: "wt0", ExitIf: "mullvad", Table: 51821}
}

func gluetunConfig() Config {
	c := nativeConfig()
	c.Backend, c.ExitIf = Gluetun, "wg0"
	c.HostIf, c.HostTable, c.ControlMark = "eth0", 51822, 0x1bd00
	return c
}

func nativeSpec() Spec {
	return Spec{Config: nativeConfig(), ReturnPath: map[rtnl.Family][]netip.Addr{
		rtnl.V4: {netip.MustParseAddr(tunnel4)}, rtnl.V6: {netip.MustParseAddr(tunnel6)}}}
}

func icmpOf(f rtnl.Family) uint8 {
	if f == rtnl.V4 {
		return 1
	}
	return 58
}

func overlayOf(f rtnl.Family) string {
	if f == rtnl.V4 {
		return "192.0.2.0/24"
	}
	return "2001:db8:1::/64"
}

func addrOf(f rtnl.Family) string {
	if f == rtnl.V4 {
		return tunnel4
	}
	return tunnel6
}

func hostOf(f rtnl.Family) string {
	if f == rtnl.V4 {
		return tunnel4 + "/32"
	}
	return tunnel6 + "/128"
}

// nativeRules is test_runtime.rules(): the native contract as the kernel
// shows it, plus NetBird's rule 105.
func nativeRules(f rtnl.Family) []rtnl.Rule {
	return []rtnl.Rule{
		rule(f, 1, not(), iif("wt0"), table(rtnl.TableLocal)),
		rule(f, 90, iif("mullvad"), to(overlayOf(f)), table(rtnl.TableMain)),
		rule(f, 94, from(hostOf(f)), proto(icmpOf(f)), table(51821)),
		rule(f, 95, iif("wt0"), table(51821)),
		rule(f, 96, oif("mullvad"), table(51821)),
		rule(f, 97, iif("wt0"), unreachable()),
		rule(f, 98, from(hostOf(f)), proto(icmpOf(f)), unreachable()),
		rule(f, 105, table(7120)),
	}
}

func without(rules []rtnl.Rule, priorities ...uint32) []rtnl.Rule {
	var out []rtnl.Rule
outer:
	for _, r := range rules {
		for _, p := range priorities {
			if r.Priority == p {
				continue outer
			}
		}
		out = append(out, r)
	}
	return out
}

func at(t *testing.T, rules []rtnl.Rule, priority uint32) *rtnl.Rule {
	t.Helper()
	for i := range rules {
		if rules[i].Priority == priority {
			return &rules[i]
		}
	}
	t.Fatalf("no rule at priority %d", priority)
	return nil
}

const exitIfIndex = 7

func zero(f rtnl.Family) netip.Prefix {
	if f == rtnl.V4 {
		return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
}

func fallbackRoute(f rtnl.Family) rtnl.Route {
	return rtnl.Route{Family: f, Dst: zero(f), Table: 51821, Type: rtnl.RTNUnreachable, Metric: 4096}
}

func tunnelRoute(f rtnl.Family) rtnl.Route {
	return rtnl.Route{Family: f, Dst: zero(f), Table: 51821, Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(exitIfIndex))}
}

// nativeRoutes is test_runtime.routes().
func nativeRoutes(f rtnl.Family) []rtnl.Route {
	return []rtnl.Route{tunnelRoute(f), fallbackRoute(f)}
}

func nativeStatus(rules []rtnl.Rule, routes []rtnl.Route, f rtnl.Family, withTunnel bool) (bool, bool) {
	opt := StatusOptions{ExitIfIndex: exitIfIndex}
	spec := nativeSpec()
	if withTunnel {
		opt.TunnelAddress = netip.MustParseAddr(addrOf(f))
	}
	return FamilyStatus(spec, f, rules, routes, opt)
}
