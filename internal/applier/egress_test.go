// Tests ported from tools/test_egress.py: the applier's tunnel tier ("the
// applier" section of that file) against a fake namespace with IP echo
// services on and off the tunnel. The pure checks (parse_echo, exit_addresses,
// host_lacks_ipv6, tunnel_verdict) are internal/egress's tests and the status
// model's are internal/state's and internal/verdict's. No current provider uses
// the tunnel tier, so a made-up registry entry exercises it here.
package applier

import (
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/egress"
	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/verdict"
)

// noHostRoutes6 is what a namespace with no IPv6 of its own still lists, in
// every table.
func noHostRoutes6() []any {
	return []any{
		map[string]any{"dst": "fe80::/64", "dev": "eth0", "protocol": "kernel", "metric": 256},
		map[string]any{"dst": "2001:db8:1::/64", "dev": "wt0", "protocol": "kernel", "metric": 256},
		map[string]any{"dst": "default", "dev": "mullvad", "table": "51821"},
		map[string]any{"type": "unreachable", "dst": "default", "table": "51821", "metric": 4096},
		map[string]any{"type": "local", "dst": "::1", "table": "local", "dev": "lo"},
		map[string]any{"type": "local", "dst": "fe80::2", "table": "local", "dev": "eth0"},
		map[string]any{"type": "local", "dst": exitIP6, "table": "local", "dev": "mullvad"},
		map[string]any{"type": "anycast", "dst": "fe80::", "table": "local", "dev": "eth0"},
		map[string]any{"type": "multicast", "dst": "ff00::/8", "table": "local", "dev": "eth0"},
	}
}

func globalOn(name string) map[string]any {
	return map[string]any{"ifname": name, "addr_info": []any{
		map[string]any{"family": "inet6", "scope": "global", "local": hostIP6, "prefixlen": 128}}}
}

func isEcho(r netx.Request) bool {
	for _, urls := range egress.EchoURLs {
		for _, u := range urls {
			if r.URL == u {
				return true
			}
		}
	}
	return false
}

func offTunnel(r netx.Request) bool { return isEcho(r) && r.BindInterface == "" }

// tunnelSetup is the Python tunnel_runtime fixture: an applier for a provider
// without a typed egress check.
func tunnelSetup(t testing.TB) (*Applier, *kernel, string) {
	t.Helper()
	spec := providers.Clone("mullvad")
	spec.ID, spec.Label, spec.EgressTier = "tunnelvpn", "Tunnel Example", providers.TierTunnel
	spec.ValidateEntry = providers.ValidateMullvadEntry
	t.Cleanup(providers.Replace(spec))
	dir := t.TempDir()
	writeSnapshot(t, dir, "tunnelvpn", map[string]any{testHost: mullvadEntry(testHost, testKey)})
	k := newKernel(t)
	k.host6Routes = append(noHostRoutes6(), map[string]any{"dst": "default", "gateway": "fe80::1", "dev": "eth0"})
	a := newApplier(t, k, dir, BaseProvider{Name: "tunnelvpn"}, "")
	return a, k, dir
}

func tierOf(r *Record) any {
	if checkState(r, "egress") == "pass" {
		return checkField(r, "egress", "tier")
	}
	return nil
}

func statusViewOf(t testing.TB, a *Applier, provider string) (string, string) {
	t.Helper()
	result := jsonfile.Read(a.resultPath, ResultMaxBytes)
	return verdict.StatusView(nil, result, provider, "overlay", time.Now())
}

func TestTunnelChecksConnectAProviderWithoutItsOwnCheck(t *testing.T) {
	a, k, dir := tunnelSetup(t)
	withPublished(a, dir)
	r := a.inspect(t)
	ips := r.Decoded()["egress_ips"].(map[string]any)
	if status(r) != "ok" || r.Get("server") != testHost || tierOf(r) != "tunnel" || r.Get("egress_ip") != exitIP4 ||
		ips["4"] != exitIP4 || ips["6"] != exitIP6 || len(ips) != 2 {
		t.Fatalf("%s %s %v", status(r), message(r), ips)
	}
	if state, label := statusViewOf(t, a, "tunnelvpn"); state != "ok" || label != "connected" {
		t.Errorf("status view %s %s", state, label)
	}
	echoes := 0
	for _, req := range k.reqs {
		if isEcho(req) {
			echoes++
		}
	}
	if echoes != 6 { // two through the tunnel and one off it, per family
		t.Errorf("%d echo requests", echoes)
	}
	if len(k.requestsTo("am.i.mullvad.net")) != 0 {
		t.Error("the tunnel tier asked the provider")
	}
}

func TestAnyFailedTunnelCheckFailsTheExit(t *testing.T) {
	for name, change := range map[string]func(*kernel){
		"ipv4 echoes disagree": func(k *kernel) { k.echo[echoKey{4, true}] = []string{exitIP4, "203.0.113.11"} },
		"ipv6 echoes disagree": func(k *kernel) { k.echo[echoKey{6, true}] = []string{exitIP6, "2001:db8:3::11"} },
		"host is the tunnel":   func(k *kernel) { k.echo[echoKey{4, false}] = []string{exitIP4} },
		"host echo down":       func(k *kernel) { k.echoDown[echoKey{4, false}] = true },
		"tunnel echo down":     func(k *kernel) { k.echoDown[echoKey{4, true}] = true },
		"not an address":       func(k *kernel) { k.echo[echoKey{4, true}] = []string{"not an address", "not an address"} },
		"stale handshake":      func(k *kernel) { k.age = 500 },
	} {
		a, k, _ := tunnelSetup(t)
		change(k)
		r := a.inspect(t)
		m := message(r)
		if status(r) != "failed" || tierOf(r) != nil ||
			(m != "Tunnel egress did not pass the tunnel checks." && m != EgressFailedMessage &&
				m != "Tunnel handshake is missing or stale; check the account and connectivity.") {
			t.Errorf("%s: %s %s", name, status(r), m)
		}
	}
}

func TestAHostShownToHaveNoIPv6OfItsOwnStillVerifies(t *testing.T) {
	a, k, _ := tunnelSetup(t)
	k.echoDown[echoKey{6, false}] = true
	k.host6Routes, k.host6Links = noHostRoutes6(), []any{}
	if r := a.inspect(t); tierOf(r) != "tunnel" {
		t.Fatalf("%s %s", status(r), message(r))
	}
}

func TestIPv6OnLoopbackOrInAPolicyTableKeepsTheMeasurementRequired(t *testing.T) {
	for name, evidence := range map[string]struct{ routes, links []any }{
		"loopback":     {nil, []any{globalOn("lo")}},
		"policy table": {[]any{map[string]any{"dst": "2001:db8:4::/48", "dev": "eth0", "table": "200"}}, nil},
	} {
		a, k, _ := tunnelSetup(t)
		k.echoDown[echoKey{6, false}] = true
		// Even a tunnel answer equal to the host's own address must not pass.
		k.echo[echoKey{6, true}] = []string{hostIP6, hostIP6}
		k.host6Routes = append(noHostRoutes6(), evidence.routes...)
		k.host6Links = append([]any{}, evidence.links...)
		r := a.inspect(t)
		if status(r) != "failed" || tierOf(r) != nil {
			t.Errorf("%s: %s", name, status(r))
		}
	}
}

func TestAFailedIPv6MeasurementIsUnverifiedWithoutEvidence(t *testing.T) {
	for _, failure := range []string{"down", "malformed"} {
		for _, evidence := range []string{"default route", "global address", "unreadable"} {
			a, k, dir := tunnelSetup(t)
			withPublished(a, dir)
			if failure == "down" {
				k.echoDown[echoKey{6, false}] = true
			} else {
				k.echo[echoKey{6, false}] = []string{"not an address"}
			}
			switch evidence {
			case "default route":
				k.host6Links = []any{}
			case "global address":
				k.host6Routes = noHostRoutes6()
			default:
				k.host6Routes = "not a list"
			}
			r := a.inspect(t)
			if status(r) != "failed" || tierOf(r) != nil {
				t.Errorf("%s/%s: %s", failure, evidence, status(r))
			}
			// No usable measurement is no answer: asked once more, then the
			// check fails.
			if message(r) != EgressFailedMessage || k.now != EgressRetrySec {
				t.Errorf("%s/%s: %q now %v", failure, evidence, message(r), k.now)
			}
			if state, _ := statusViewOf(t, a, "tunnelvpn"); state != "failed" {
				t.Errorf("%s/%s: status view %s", failure, evidence, state)
			}
		}
	}
}

func TestAHostMeasurementThatFailsOnceIsAskedOnceMore(t *testing.T) {
	a, k, _ := tunnelSetup(t)
	calls := k.unanswered(offTunnel, 1, 10)
	r := a.inspect(t)
	if status(r) != "ok" || tierOf(r) != "tunnel" || k.now != 10+EgressRetrySec || len(*calls) != 3 { // IPv4 twice, then IPv6
		t.Fatalf("%s %v now %v calls %d", status(r), tierOf(r), k.now, len(*calls))
	}
}

func TestEchoesThatDisagreeFailBeforeTheHostMeasurement(t *testing.T) {
	a, k, _ := tunnelSetup(t)
	k.echo[echoKey{4, true}] = []string{exitIP4, "203.0.113.11"}
	k.echoDown[echoKey{4, false}] = true
	r := a.inspect(t)
	if message(r) != "Tunnel egress did not pass the tunnel checks." || k.now != 0 {
		t.Fatalf("%s now %v", message(r), k.now)
	}
	for _, req := range k.reqs {
		if offTunnel(req) {
			t.Error("the host was measured")
		}
	}
}

func TestAFailedFamilyEndsTheTunnelChecksBeforeTheNextOne(t *testing.T) {
	a, k, _ := tunnelSetup(t)
	k.echo[echoKey{4, false}] = []string{exitIP4} // the "tunnel" answer is the host's own
	k.echoDown[echoKey{6, true}] = true
	r := a.inspect(t)
	if message(r) != "Tunnel egress did not pass the tunnel checks." || k.now != 0 {
		t.Fatalf("%s now %v", message(r), k.now)
	}
	for _, req := range k.reqs {
		if req.Family == 6 {
			t.Error("IPv6 asked")
		}
	}
}

func TestAnAddressTheCatalogueDoesNotListFailsBeforeTheHostMeasurement(t *testing.T) {
	a, k, _ := tunnelSetup(t)
	a.catalog.(*nativeCatalog).exitIPs = map[string][]string{testHost: {"203.0.113.11"}}
	k.echoDown[echoKey{4, false}] = true
	r := a.inspect(t)
	if message(r) != "Tunnel egress did not pass the tunnel checks." || k.now != 0 {
		t.Fatalf("%s now %v", message(r), k.now)
	}
	for _, req := range k.reqs {
		if offTunnel(req) {
			t.Error("the host was measured")
		}
	}
}

func TestASecondTunnelAttemptStaysWithinItsBudget(t *testing.T) {
	a, k, _ := tunnelSetup(t)
	// First attempt: the first echo unanswered. Second: every request takes 11
	// seconds, so the IPv6 echoes are never started.
	steps := []step{{10, false}}
	for i := 0; i < 6; i++ {
		steps = append(steps, step{11, true})
	}
	calls := k.delayed(isEcho, steps...)
	r := a.inspect(t)
	if message(r) != EgressFailedMessage || k.now != 10+EgressRetrySec+33 || len(*calls) != 4 {
		t.Fatalf("%s now %v calls %d", message(r), k.now, len(*calls))
	}
	if k.now > EgressRetryWithinSec+EgressRetrySec+EgressRetryBudgetSec+12 {
		t.Errorf("over the bound: %v", k.now)
	}
}

func TestEchoServicesThatDisagreeAreNeverAskedAgain(t *testing.T) {
	a, k, _ := tunnelSetup(t)
	k.echo[echoKey{4, true}] = []string{exitIP4, "203.0.113.11"}
	r := a.inspect(t)
	if message(r) != "Tunnel egress did not pass the tunnel checks." || k.now != 0 {
		t.Fatalf("%s now %v", message(r), k.now)
	}
}

func TestAFailedIPv4MeasurementIsUnverifiedEvenWithoutIPv6(t *testing.T) {
	a, k, _ := tunnelSetup(t)
	k.echoDown[echoKey{4, false}] = true
	k.host6Routes, k.host6Links = []any{}, []any{}
	if r := a.inspect(t); status(r) != "failed" || tierOf(r) != nil {
		t.Fatalf("%s", status(r))
	}
}

func TestCatalogueExitAddressesMustMatch(t *testing.T) {
	a, _, _ := tunnelSetup(t)
	for _, c := range []struct {
		listed []string
		want   string
	}{{[]string{exitIP4, exitIP6}, "ok"}, {[]string{"203.0.113.11"}, "failed"}, {[]string{exitIP4}, "ok"},
		{[]string{"2001:db8:3::11"}, "failed"}} {
		a.catalog.(*nativeCatalog).exitIPs = map[string][]string{testHost: c.listed}
		if got := status(a.inspect(t)); got != c.want {
			t.Errorf("%v: %s", c.listed, got)
		}
	}
}

func TestUnknownPeerIsNeverTunnelVerified(t *testing.T) {
	a, k, _ := tunnelSetup(t)
	k.keys = []string{otherKey}
	if r := a.inspect(t); status(r) != "failed" || tierOf(r) != nil {
		t.Fatalf("%s", status(r))
	}
}

func TestASwitchCompletesOnTheTunnelTier(t *testing.T) {
	a, k, _ := tunnelSetup(t)
	k.keys = []string{otherKey}
	r := a.switchTo(t, requestAt(testHost, nil))
	if status(r) != "ok" || tierOf(r) != "tunnel" || len(k.keys) != 1 || k.keys[0] != testKey {
		t.Fatalf("%s %s %v", status(r), message(r), k.keys)
	}
}

func TestProviderTierResultsCarryTheTier(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	r := a.inspect(t)
	if status(r) != "ok" || tierOf(r) != "provider" {
		t.Fatalf("%s", status(r))
	}
	k.probes[4]["mullvad_exit_ip"] = false
	r = a.inspect(t)
	if status(r) != "failed" || tierOf(r) != nil || message(r) != "Tunnel egress is not confirmed as Mullvad." {
		t.Fatalf("%s %s", status(r), message(r))
	}
	for _, req := range k.reqs {
		if isEcho(req) {
			t.Error("the provider tier asked an echo service")
		}
	}
	k.egressOK = false
	published, err := a.publishRecord("unknown", "x", "", nil, nil)
	if err != nil || checkState(published, "egress") != "unknown" {
		t.Fatalf("%v %v", published, err)
	}
	if !strings.Contains(message(published), "x") {
		t.Error("message lost")
	}
}
