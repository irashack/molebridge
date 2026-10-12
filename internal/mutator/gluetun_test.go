package mutator

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

func glConfig() contract.Config {
	c := nativeConfig()
	c.Backend, c.ExitIf = contract.Gluetun, "wg0"
	c.HostIf, c.HostTable, c.ControlMark = "eth0", 51822, 0x1bd00
	return c
}

// gluetunKernel is a namespace gluetun owns: its tunnel interface and
// addresses, the host's routes in the main table, NetBird's overlay interface.
func gluetunKernel() *fakeKernel {
	k := newFakeKernel()
	k.links = append(k.links, rtnl.Link{Index: 7, Name: "wg0", Flags: rtnl.IFFUp, Kind: "wireguard"})
	k.addrs[4] = []rtnl.Addr{{Family: 4, Index: 7, Local: netip.MustParsePrefix(tunnel4 + "/32")}}
	k.addrs[6] = []rtnl.Addr{{Family: 6, Index: 7, Local: netip.MustParsePrefix(tunnel6 + "/128")}}
	k.routes[4] = []rtnl.Route{
		{Family: 4, Table: 254, Dst: netip.MustParsePrefix("198.51.100.0/28"), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2)), PrefSrc: netip.MustParseAddr("198.51.100.1")},
		{Family: 4, Table: 254, Dst: netip.PrefixFrom(netip.IPv4Unspecified(), 0), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2)), Gateway: netip.MustParseAddr("198.51.100.2")},
		{Family: 4, Table: 254, Dst: netip.MustParsePrefix("192.0.2.0/24"), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(3))},
		{Family: 4, Table: 51820, Dst: netip.PrefixFrom(netip.IPv4Unspecified(), 0), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(7))},
	}
	k.routes[6] = []rtnl.Route{
		{Family: 6, Table: 254, Dst: netip.MustParsePrefix("2001:db8:2::/64"), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(2)), Metric: 256},
	}
	return k
}

func glSpec() contract.Spec { return contract.Spec{Config: glConfig()} }

func hostTable(k *fakeKernel, f rtnl.Family) []rtnl.Route {
	var out []rtnl.Route
	for _, r := range k.routes[f] {
		if r.Table == 51822 {
			out = append(out, r)
		}
	}
	return out
}

func TestGluetunInstallBuildsTheHostTableBeforeTheKillSwitch(t *testing.T) {
	k := gluetunKernel()
	spec := glSpec()
	m := start(t, k, spec)
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !m.Ready() {
		t.Fatalf("%+v", m.LastPass())
	}
	if n := len(hostTable(k, 4)); n != 2 {
		t.Errorf("host table: %+v", hostTable(k, 4))
	}
	for _, f := range families {
		af := f.AF()
		table := index(k.log, "route replace "+fmt.Sprint(af)+" 51822")
		ks := index(k.log, "add "+fmt.Sprint(af)+" 104")
		if f == rtnl.V4 && (table < 0 || ks < 0 || table > ks) {
			t.Errorf("%s: host table at %d, kill switch at %d", f, table, ks)
		}
		p := priorities(k, f)
		for _, want := range []uint32{1, 88, 89, 90, 91, 92, 95, 96, 97, 102, 103, 104} {
			if _, ok := p[want]; !ok {
				t.Errorf("%s: rule %d missing", f, want)
			}
		}
		if _, ok := p[80]; ok {
			t.Errorf("%s: the guard stayed", f)
		}
	}
	// The return-path rule follows the observed tunnel address.
	found := false
	for _, r := range k.rules[4] {
		if r.Priority == 94 && r.Src.Addr() == netip.MustParseAddr(tunnel4) {
			found = true
		}
	}
	if !found {
		t.Error("rule 94 for the tunnel address missing")
	}
	// The tunnel route is in the exit table.
	n := 0
	for _, r := range k.routes[4] {
		if r.Table == 51821 {
			n++
		}
	}
	if n != 2 {
		t.Errorf("exit table: %d routes", n)
	}
}

func TestGluetunHostTableDriftIsRefreshedAndTheKillSwitchWaits(t *testing.T) {
	k := gluetunKernel()
	spec := glSpec()
	m := start(t, k, spec)
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Both the host table and rule 104 are lost (a namespace rebuilt).
	var kept []rtnl.Route
	for _, r := range k.routes[4] {
		if r.Table != 51822 {
			kept = append(kept, r)
		}
	}
	k.routes[4] = kept
	_ = k.DelRulePriority(4, 104)
	mark := len(k.log)
	res, err := m.ReconcileNow(context.Background(), "x")
	if err != nil || !res.Verified {
		t.Fatalf("%+v %v", res, err)
	}
	log := k.log[mark:]
	table, ks := index(log, "route replace 2 51822"), index(log, "add 2 104")
	if table < 0 || ks < 0 || table > ks {
		t.Errorf("host table at %d, kill switch at %d: %v", table, ks, log)
	}
	// A stale route in the host table is flushed.
	k.routes[4] = append(k.routes[4], rtnl.Route{Family: 4, Table: 51822, Dst: netip.MustParsePrefix("10.0.0.0/8"), Type: rtnl.RTNUnicast, Oif: rtnl.Some(uint32(9))})
	res, err = m.ReconcileNow(context.Background(), "y")
	if err != nil || !res.Verified || len(hostTable(k, 4)) != 2 {
		t.Fatalf("%+v %v %+v", res, err, hostTable(k, 4))
	}
	// The host's default route changes (a new gateway): the copy follows.
	for i, r := range k.routes[4] {
		if r.Table == 254 && r.IsDefault() {
			k.routes[4][i].Gateway = netip.MustParseAddr("198.51.100.3")
		}
	}
	res, err = m.ReconcileNow(context.Background(), "z")
	if err != nil || !res.Verified {
		t.Fatalf("%+v %v", res, err)
	}
	for _, r := range hostTable(k, 4) {
		if r.IsDefault() && r.Gateway != netip.MustParseAddr("198.51.100.3") {
			t.Errorf("host default not updated: %+v", r)
		}
	}
}

func TestGluetunFollowsTheTunnelAddress(t *testing.T) {
	k := gluetunKernel()
	spec := glSpec()
	m := start(t, k, spec)
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	// gluetun reconnects and the tunnel gets another address.
	k.addrs[4][0].Local = netip.MustParsePrefix("10.64.0.9/32")
	mark := len(k.log)
	res, err := m.ReconcileNow(context.Background(), "x")
	if err != nil || !res.Verified {
		t.Fatalf("%+v %v", res, err)
	}
	var sources []netip.Addr
	for _, r := range k.rules[4] {
		if r.Priority == 94 {
			sources = append(sources, r.Src.Addr())
		}
	}
	if len(sources) != 1 || sources[0] != netip.MustParseAddr("10.64.0.9") {
		t.Errorf("%v", sources)
	}
	log := k.log[mark:]
	if index(log, "add 2 94") > index(log, "del 2 94") {
		t.Errorf("the old rule 94 went before the new one came: %v", log)
	}
}

func TestGluetunWithoutADefaultRouteHoldsTheContractButNotTheVerdict(t *testing.T) {
	k := gluetunKernel()
	var kept []rtnl.Route
	for _, r := range k.routes[4] {
		if !(r.Table == 254 && r.IsDefault()) {
			kept = append(kept, r)
		}
	}
	k.routes[4] = kept
	spec := glSpec()
	m := start(t, k, spec)
	err := m.Install(context.Background())
	if err != nil {
		t.Fatalf("install must not fail for a missing host default: %v", err)
	}
	res := m.LastPass()
	if !res.ContractHolds || res.Verified || m.Ready() {
		t.Fatalf("%+v", res)
	}
	if !contains(res.Problems[rtnl.V4], contract.ProblemNoDefault) {
		t.Errorf("%v", res.Problems)
	}
	if _, ok := priorities(k, rtnl.V4)[80]; ok {
		t.Error("the temporary guard stays for a condition no repair can fix")
	}
}

func TestGluetunRepairsWithoutTheTemporaryGuard(t *testing.T) {
	k := gluetunKernel()
	spec := glSpec()
	m := start(t, k, spec, func(o *Options) { o.GuardRepairs = false })
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, p := range []uint32{88, 89, 90, 91, 92, 94, 95, 96, 97, 102, 103, 104, 1} {
		mark := len(k.log)
		_ = k.DelRulePriority(4, p)
		res, err := m.ReconcileNow(context.Background(), "x")
		if err != nil || !res.Verified {
			t.Fatalf("rule %d: %+v %v", p, res, err)
		}
		for _, l := range k.log[mark:] {
			if strings.HasPrefix(l, "add 2 80") {
				t.Errorf("rule %d: the guard was used", p)
			}
		}
	}
}

// gluetun's rule 94 follows the address observed on the tunnel interface. A
// snapshot that kept changing may leave the address out; it must not cost the
// rule.
func TestGluetunUnstableSnapshotNeverRemovesRule94(t *testing.T) {
	k := gluetunKernel()
	m := start(t, k, glSpec())
	if err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	has94 := func() bool {
		for _, r := range k.rules[4] {
			if r.Priority == 94 {
				return true
			}
		}
		return false
	}
	if !has94() {
		t.Fatal("rule 94 missing after install")
	}
	k.unstableFn = func(int) bool { return true }
	mark := len(k.log)
	for i := 0; i < 3; i++ {
		res, _ := m.ReconcileNow(context.Background(), "x")
		if res.Verified || m.Ready() {
			t.Fatalf("a verdict on an unstable look: %+v", res)
		}
	}
	for _, l := range k.log[mark:] {
		if len(l) >= 3 && (l[:3] == "del" || l[:6] == "delprio" || l[:5] == "route" && len(l) > 9 && l[6:9] == "del") {
			t.Errorf("a removal on unstable evidence: %q", l)
		}
	}
	if !has94() {
		t.Fatal("rule 94 was removed on an unstable snapshot")
	}
	// On a stable look the rule follows an address that really changed.
	k.unstableFn = nil
	k.addrs[4][0].Local = netip.MustParsePrefix("10.64.0.9/32")
	res, err := m.ReconcileNow(context.Background(), "y")
	if err != nil || !res.Verified {
		t.Fatalf("%+v %v", res, err)
	}
}
