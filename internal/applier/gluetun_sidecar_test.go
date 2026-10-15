// Tests ported from tools/test_sidecar_applier.py: the sidecar kind in the
// applier (EXIT_KIND=sidecar), an ordinary gluetun other containers share, with
// no routing contract and no NetBird. Fakes only. The host doctor's part of that
// file is gone (decision D22), as is main()'s handling of a bad configuration
// (the exit worker's); the configuration refusals are internal/contract's, and
// are checked here through the same entry point the exit uses.
package applier

import (
	"context"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
)

func sidecarFixture(t testing.TB, provider string) *glFixture {
	t.Helper()
	return newGluetunFixture(t, glOptions{provider: provider, sidecar: true, period: -1})
}

func TestSidecarConfigurationRefusals(t *testing.T) {
	for _, env := range []map[string]string{
		{"EXIT_KIND": "sidecar", "TUNNEL_BACKEND": "gluetun", "EXIT_IF": "wg-0"},
		{"EXIT_KIND": "exit", "TUNNEL_BACKEND": "gluetun", "OVERLAY_CIDR": "192.0.2.0/24"},
	} {
		if _, err := contract.ConfigFromEnv(func(k string) string { return env[k] }); err == nil {
			t.Errorf("%v accepted", env)
		}
	}
	c, err := contract.ConfigFromEnv(func(k string) string {
		return map[string]string{"EXIT_KIND": "sidecar", "TUNNEL_BACKEND": "gluetun", "EXIT_IF": "wg0"}[k]
	})
	if err != nil || c.Kind != contract.Sidecar || c.Backend != contract.Gluetun || c.ExitIf != "wg0" {
		t.Errorf("%+v %v", c, err)
	}
}

func TestASidecarAcceptsANativeProvider(t *testing.T) {
	k := newKernel(t)
	k.exit.Kind = "sidecar"
	if _, err := New(Config{StateDir: t.TempDir(), Exit: k.exit, Provider: NewNordVPN(), System: k}); err != nil {
		t.Errorf("a sidecar with a native provider was refused: %v", err)
	}
	getenv, _ := gluetunEnv(t, map[string]string{"OVERLAY_CIDR": ""})
	if _, err := ProviderFor("nordvpn", Exit{Kind: "sidecar", ExitIf: "wg0"}, getenv); err != nil {
		t.Errorf("the native provider could not be built: %v", err)
	}
}

func TestAProviderTierSidecarSwitchesAndVerifiesWithoutTheContract(t *testing.T) {
	f := sidecarFixture(t, "nordvpn")
	desire(t, f.a, glRequest(hostB))
	r := mustTick(t, f.a)
	if status(r) != "ok" || r.Get("server") != hostB || len(f.control.puts) != 1 || f.control.puts[0] != hostB {
		t.Fatalf("%s %q, puts %v", status(r), message(r), f.control.puts)
	}
	if r.Get("kind") != "sidecar" || r.Get("backend") != "gluetun" {
		t.Errorf("kind %v backend %v", r.Get("kind"), r.Get("backend"))
	}
	for _, name := range []string{"routing", "netbird", "owner_record"} {
		if checkState(r, name) != "n/a" {
			t.Errorf("%s: %s", name, checkState(r, name))
		}
	}
	tp := recordCheckOf(r, "traffic_protection")
	if len(tp) != 2 || tp["state"] != "not-checked" || tp["by"] != "gluetun's firewall" {
		t.Errorf("traffic_protection %v", tp)
	}
	aa := recordCheckOf(r, "app_attachment")
	if len(aa) != 2 || aa["state"] != "not-checked" || aa["by"] != "the host doctor" {
		t.Errorf("app_attachment %v", aa)
	}
	if checkField(r, "egress", "tier") != "provider" {
		t.Errorf("egress %v", recordCheckOf(r, "egress"))
	}
	v := f.a.assess(r.Decoded())
	if v.State != "ok" || v.Checks == nil {
		t.Errorf("verdict %s %s", v.State, v.Label)
	}
	// Nothing of the routing contract is read or written, and nothing is
	// measured off the tunnel.
	for _, prefix := range []string{"GluetunTables", "GluetunLinks", "ReadSysctl", "LinkExists", "OverlayKernelWireGuard",
		"NetbirdFirewallPresent", "RoutingStatus"} {
		if f.k.countCalls(prefix) != 0 {
			t.Errorf("a sidecar called %s", prefix)
		}
	}
	if len(f.k.marked) != 0 {
		t.Error("a sidecar measured off the tunnel")
	}
}

func recordCheckOf(r *Record, name string) map[string]any {
	return r.Decoded()["checks"].(map[string]any)[name].(map[string]any)
}

func TestATunnelTierSidecarIsSwitchedNeverVerifiedAndNeverReapplied(t *testing.T) {
	f := sidecarFixture(t, "ivpn")
	desire(t, f.a, glRequest(hostB))
	r := mustTick(t, f.a)
	if len(f.control.puts) != 1 || f.control.puts[0] != hostB || r.Get("server") != hostB {
		t.Fatalf("puts %v, server %v", f.control.puts, r.Get("server"))
	}
	if checkState(r, "egress") != "fail" || checkField(r, "egress", "reason") != "host-address-not-measurable" {
		t.Errorf("egress %v", recordCheckOf(r, "egress"))
	}
	if message(r) != "Switched; the egress couldn't be compared with this host's address." {
		t.Errorf("message %q", message(r))
	}
	if sel := selectionOf(r); sel["outcome"] != "applied-unverified" || sel["next_action"] != "recheck" {
		t.Errorf("selection %v", sel)
	}
	v := f.a.assess(r.Decoded())
	if v.State != "unknown" || v.Label != "switched, egress unverified" {
		t.Errorf("verdict %s %q", v.State, v.Label)
	}
	// The tunnel's address is shown, from one echo service.
	if r.Get("egress_ip") != glExit4 {
		t.Errorf("egress_ip %v", r.Get("egress_ip"))
	}
	for i := 0; i < 60; i++ {
		f.k.now += 60
		mustTick(t, f.a)
	}
	if len(f.control.puts) != 1 {
		t.Errorf("puts %v", f.control.puts)
	}
	if f.provider.selection.LastApplied != hostB || f.provider.selection.LastSuccessful != "" {
		t.Errorf("selection %+v", f.provider.selection)
	}
	if len(f.k.marked) != 0 {
		t.Error("a sidecar measured off the tunnel")
	}
}

func TestATunnelTierSidecarRestoresTheLastAppliedServer(t *testing.T) {
	f := sidecarFixture(t, "ivpn")
	if err := f.provider.saveSelection(func(s *selection) { s.LastPut, s.LastApplied = hostB, hostB }); err != nil {
		t.Fatal(err)
	}
	f.k.tunnel = hostA // gluetun restarted on its environment's server
	r := mustTick(t, f.a)
	if len(f.control.puts) != 1 || f.control.puts[0] != hostB || selectionOf(r)["source"] != "restore" {
		t.Errorf("puts %v, selection %v", f.control.puts, selectionOf(r))
	}
}

func TestAProviderTierSidecarRestoresTheLastVerifiedServerNotTheLastApplied(t *testing.T) {
	f := sidecarFixture(t, "nordvpn")
	if err := f.provider.saveSelection(func(s *selection) { s.LastPut, s.LastApplied, s.LastSuccessful = hostC, hostC, hostB }); err != nil {
		t.Fatal(err)
	}
	if target := f.provider.RestoreTarget(f.a); target == nil || target.Server != hostB || target.Source != "restore" {
		t.Errorf("target %+v", target)
	}
	g := sidecarFixture(t, "ivpn")
	if err := g.provider.saveSelection(func(s *selection) { s.LastApplied, s.LastSuccessful = hostC, hostB }); err != nil {
		t.Fatal(err)
	}
	if target := g.provider.RestoreTarget(g.a); target == nil || target.Server != hostC {
		t.Errorf("target %+v", target)
	}
	if target := sidecarFixture(t, "ivpn").provider.RestoreTarget(g.a); target != nil {
		t.Errorf("a fresh exit restores %+v", target)
	}
}

func TestADriftedTunnelTierSidecarIsStillPutBack(t *testing.T) {
	f := sidecarFixture(t, "ivpn")
	desire(t, f.a, glRequest(hostB))
	mustTick(t, f.a)
	f.k.tunnel = hostA
	f.k.now += 91
	mustTick(t, f.a)
	if len(f.control.puts) != 2 || f.control.puts[0] != hostB || f.control.puts[1] != hostB {
		t.Errorf("puts %v", f.control.puts)
	}
}

func TestHealthIsKindAware(t *testing.T) {
	// Container health for a sidecar: the control server answers and exactly one
	// peer; no routing or NetBird facts (the doctor half of the Python test is
	// gone with the doctor).
	f := sidecarFixture(t, "nordvpn")
	withPublished(f.a, f.dir)
	desire(t, f.a, glRequest(hostB))
	mustTick(t, f.a)
	ctx := context.Background()
	if !f.a.Healthy(ctx) {
		t.Fatal("not healthy")
	}
	f.control.statusErr = ErrGluetunRequest
	if f.a.Healthy(ctx) {
		t.Error("healthy with a control server that does not answer")
	}
	f.control.statusErr = nil
	if !f.a.Healthy(ctx) {
		t.Error("not healthy again")
	}
	f.k.tunnel = ""
	if f.a.Healthy(ctx) {
		t.Error("healthy without a peer")
	}
	for _, prefix := range []string{"GluetunTables", "ReadSysctl", "OverlayKernelWireGuard", "NetbirdFirewallPresent"} {
		if f.k.countCalls(prefix) != 0 {
			t.Errorf("a sidecar's health called %s", prefix)
		}
	}
}
