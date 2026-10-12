//go:build drill && linux

package exit

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/applier"
	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/nstest"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/tunnel"
	"github.com/irashack/molebridge/internal/tunnelconf"
)

const piaConfText = "[Interface]\nPrivateKey = " + zeroKey + "\nMTU = 1420\nTable = off\n" +
	"PostUp = ip route replace default dev %i table 51821\nPreDown = ip route del default dev %i table 51821\n"

// sysRig is a KernelSystem on a PIA-style exit (a tunnel config with no
// address) in a namespace of its own.
func sysRig(t *testing.T) (*KernelSystem, *nstest.NS) {
	t.Helper()
	ns := nstest.New(t, "sys")
	if _, err := ns.TryIP("link", "add", "wt0", "type", "wireguard"); err != nil {
		t.Skipf("no WireGuard: %v", err)
	}
	cfg, err := contract.ConfigFromEnv(func(k string) string {
		return map[string]string{"OVERLAY_CIDR": "192.0.2.0/24", "OVERLAY_IF": "wt0", "EXIT_IF": "mullvad", "EXIT_TABLE": "51821"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	conf, err := tunnelconf.Parse(piaConfText, tunnelconf.PIA, 51821)
	if err != nil {
		t.Fatal(err)
	}
	s := &Settings{Routing: cfg, Provider: "pia", Conf: conf, Env: map[string]string{}}
	w := &worker{s: s}
	spec := w.spec()
	conn, err := rtnl.Dial(rtnl.Options{NetNS: ns.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	obs, err := rtnl.Dial(rtnl.Options{NetNS: ns.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	tun, err := tunnel.Open(tunnel.Options{NetNS: ns.Fd()})
	if err != nil {
		t.Fatal(err)
	}
	mut := mutator.New(mutator.Options{Kernel: conn, Spec: spec, GuardRepairs: true, Logf: t.Logf})
	mut.Start()
	t.Cleanup(func() { mut.Close(); conn.Close(); obs.Close(); tun.Close() })
	ctx := context.Background()
	if err := mut.Install(ctx); err != nil {
		t.Fatal(err)
	}
	if err := mut.Do(ctx, "up", func(tx *mutator.Tx) error {
		return tun.UpContext(tx.Context(), tunnel.Params{ExitIf: "mullvad", Conf: conf})
	}); err != nil {
		t.Skipf("no WireGuard: %v", err)
	}
	ks := &KernelSystem{S: s, Spec: spec, Obs: obs, Mut: mut, Tun: tun, Generation: strings.Repeat("a", 32), NetNS: ns.Fd()}
	var _ applier.System = ks
	return ks, ns
}

func TestKernelSystemPIAAddressChangeIsOneTransaction(t *testing.T) {
	ks, ns := sysRig(t)
	ctx := context.Background()
	first, second := netip.MustParseAddr("10.1.2.3"), netip.MustParseAddr("10.1.2.4")

	if err := ks.ChangePIAAddress(ctx, netip.Addr{}, first); err != nil {
		t.Fatal(err)
	}
	rules, _ := ns.TryIP("-4", "rule", "show")
	for _, want := range []string{"94: from 10.1.2.3 ipproto icmp lookup 51821", "98: from 10.1.2.3 ipproto icmp unreachable"} {
		if !strings.Contains(strings.ReplaceAll(rules, "\t", " "), want) {
			t.Errorf("rules lack %q:\n%s", want, rules)
		}
	}
	addrs, err := ks.TunnelAddresses(ctx)
	if err != nil || len(addrs) != 1 || addrs[0] != first {
		t.Fatalf("addresses %v %v", addrs, err)
	}
	route, _ := ns.TryIP("-4", "route", "show", "table", "51821")
	if !strings.Contains(route, "default dev mullvad") {
		t.Errorf("exit table: %s", route)
	}

	if err := ks.ChangePIAAddress(ctx, first, second); err != nil {
		t.Fatal(err)
	}
	rules, _ = ns.TryIP("-4", "rule", "show")
	rules = strings.ReplaceAll(rules, "\t", " ")
	if strings.Contains(rules, "10.1.2.3") || !strings.Contains(rules, "94: from 10.1.2.4 ipproto icmp lookup 51821") ||
		!strings.Contains(rules, "98: from 10.1.2.4 ipproto icmp unreachable") {
		t.Errorf("after the change:\n%s", rules)
	}
	addrs, _ = ks.TunnelAddresses(ctx)
	if len(addrs) != 1 || addrs[0] != second {
		t.Errorf("addresses %v", addrs)
	}
	route, _ = ns.TryIP("-4", "route", "show", "table", "51821")
	if !strings.Contains(route, "default dev mullvad") {
		t.Errorf("the tunnel route did not return: %s", route)
	}
	// The repairer now expects the new pair: a pass finds nothing to do.
	if res, err := ks.Mut.ReconcileNow(ctx, "after the change"); err != nil || res.Repaired || !res.Verified {
		t.Errorf("pass after the change: %+v %v", res, err)
	}
	protected, fallback, err := ks.RoutingStatus(ctx, 4, second.String())
	if err != nil || !protected || !fallback {
		t.Errorf("routing status: %v %v %v", protected, fallback, err)
	}
	if p, _, _ := ks.RoutingStatus(ctx, 4, "10.9.9.9"); p {
		t.Error("another address must not satisfy the return-path rule")
	}
	// The primitives, one idempotent job each.
	rs, err := ks.IPv4Rules(ctx, 94)
	if err != nil || len(rs) != 1 || rs[0].Src != "10.1.2.4" || rs[0].SrcLen != 32 || rs[0].IPProto != 1 || rs[0].Table != 51821 || rs[0].Other {
		t.Errorf("rule 94: %+v %v", rs, err)
	}
	if rs, _ = ks.IPv4Rules(ctx, 98); len(rs) != 1 || rs[0].Action != "unreachable" || rs[0].Other {
		t.Errorf("rule 98: %+v", rs)
	}
	if err := ks.AddReturnPathRule(ctx, 94, second); err != nil {
		t.Errorf("adding an existing rule: %v", err)
	}
}

func TestKernelSystemPeers(t *testing.T) {
	ks, _ := sysRig(t)
	ctx := context.Background()
	if keys, err := ks.Peers(ctx); err != nil || len(keys) != 0 {
		t.Fatalf("a PIA config has no peer yet: %v %v", keys, err)
	}
	own, err := ks.PublicKey(ctx)
	if err != nil || len(own) != 44 {
		t.Fatalf("public key %q %v", own, err)
	}
	k1, _ := wgtypes.GeneratePrivateKey()
	k2, _ := wgtypes.GeneratePrivateKey()
	add := func(k wgtypes.Key, endpoint string) {
		t.Helper()
		err := ks.ReplacePeer(ctx, nil, applier.PeerConfig{PublicKey: k.PublicKey().String(), Endpoint: endpoint,
			AllowedIPs: []string{"0.0.0.0/0"}, KeepaliveSec: 25})
		if err != nil {
			t.Fatal(err)
		}
	}
	add(k1, "198.51.100.1:1337")
	keys, _ := ks.Peers(ctx)
	if len(keys) != 1 || keys[0] != k1.PublicKey().String() {
		t.Fatalf("%v", keys)
	}
	eps, err := ks.Endpoints(ctx)
	if err != nil || eps[keys[0]] != "198.51.100.1:1337" {
		t.Errorf("%v %v", eps, err)
	}
	hs, err := ks.LatestHandshakes(ctx)
	if err != nil || hs[keys[0]] != 0 {
		t.Errorf("no handshake yet: %v %v", hs, err)
	}
	// Replacing: remove the old, set the new.
	err = ks.ReplacePeer(ctx, keys, applier.PeerConfig{PublicKey: k2.PublicKey().String(), Endpoint: "198.51.100.2:1337", AllowedIPs: []string{"0.0.0.0/0"}})
	if err != nil {
		t.Fatal(err)
	}
	keys2, _ := ks.Peers(ctx)
	if len(keys2) != 1 || keys2[0] != k2.PublicKey().String() {
		t.Fatalf("%v", keys2)
	}
	// An empty public key means remove only.
	if err := ks.ReplacePeer(ctx, keys2, applier.PeerConfig{}); err != nil {
		t.Fatal(err)
	}
	if keys3, _ := ks.Peers(ctx); len(keys3) != 0 {
		t.Fatalf("%v", keys3)
	}
	if err := ks.ReplacePeer(ctx, []string{"not a key"}, applier.PeerConfig{}); err == nil {
		t.Error("an invalid key must be refused")
	}
	_ = time.Second
}

func TestKernelSystemReadsTheNamespace(t *testing.T) {
	ks, ns := sysRig(t)
	ctx := context.Background()
	if err := ks.LinkExists(ctx, "mullvad"); err != nil {
		t.Error(err)
	}
	if err := ks.LinkExists(ctx, "nonexistent0"); err == nil {
		t.Error("a missing interface")
	}
	if ok, err := ks.OverlayKernelWireGuard(ctx); err != nil || !ok {
		t.Errorf("a wireguard overlay: %v %v", ok, err)
	}
	ns.IP("link", "del", "wt0")
	ks.invalidate()
	if ok, err := ks.OverlayKernelWireGuard(ctx); err != nil || ok {
		t.Errorf("no overlay interface: %v %v", ok, err)
	}
	ns.IP("link", "add", "wt0", "type", "dummy")
	ks.invalidate()
	if ok, err := ks.OverlayKernelWireGuard(ctx); err != nil || ok {
		t.Errorf("a dummy overlay is not kernel WireGuard: %v %v", ok, err)
	}
	if ok, err := ks.NetbirdFirewallPresent(ctx); err != nil || ok {
		t.Errorf("no NetBird firewall yet: %v %v", ok, err)
	}
	if out, err := ns.Exec("nft", "add", "table", "ip", "netbird"); err == nil {
		_ = out
		ns.Exec("nft", "add", "chain", "ip", "netbird", "c")
		if ok, err := ks.NetbirdFirewallPresent(ctx); err != nil || !ok {
			t.Errorf("NetBird's table: %v %v", ok, err)
		}
	}
	if _, err := ks.ReadSysctl(ctx, "/etc/passwd"); err == nil {
		t.Error("only sysctl files can be read")
	}
	if _, err := ks.ReadSysctl(ctx, "/proc/sys/net/ipv4/ip_forward"); err != nil {
		t.Error(err)
	}
	routes, links, err := ks.IPv6Evidence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := routes.([]any); !ok {
		t.Errorf("routes %T", routes)
	}
	if _, ok := links.([]any); !ok {
		t.Errorf("links %T", links)
	}
	prefixes, err := ks.NamespaceIPv4Prefixes(ctx, "mullvad")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range prefixes {
		if p.Addr().String() == "10.1.2.4" {
			t.Errorf("the excluded interface's address is listed: %v", prefixes)
		}
	}
}
