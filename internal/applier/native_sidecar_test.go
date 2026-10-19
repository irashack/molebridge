package applier

import (
	"context"
	"encoding/base64"
	"net/netip"
	"net/url"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/validate"
)

// Native sidecars use the provider pipeline with no overlay. HTTP stays in
// memory so the tests need neither a tunnel nor a loopback listener.
func nativeSidecarSetup(t testing.TB, name string, forward bool) (*Applier, *kernel, *piaAPI) {
	t.Helper()
	dir := t.TempDir()
	k := newKernel(t)
	var provider Provider
	var api *piaAPI
	switch name {
	case "mullvad":
		writeSnapshot(t, dir, "mullvad", map[string]any{testHost: mullvadEntry(testHost, testKey)})
		provider = NewMullvad()
	case "nordvpn":
		k = newNordKernel(t)
		writeSnapshot(t, dir, "nordvpn", nordCatalogue(t))
		provider = NewNordVPN()
	case "pia":
		writeSnapshot(t, dir, "pia", piaEntries(t))
		k.exit.ExitIf = "pia"
		k.addrs, k.keys = nil, nil
		k.rules = map[int][]Rule{}
		k.publicKey, k.expectedSource = piaOurKey, "10.0.0.2"
		secrets := filepath.Join(dir, "secrets")
		writeFile(t, filepath.Join(secrets, "username"), piaUsername, 0o600)
		writeFile(t, filepath.Join(secrets, "password"), piaPassword, 0o600)
		api = &piaAPI{port: 43210, connected: true, addkey: map[string]any{
			"status": "OK", "server_key": piaServerKey, "server_port": 1337, "server_ip": "198.51.100.20",
			"server_vip": "10.0.0.1", "peer_ip": "10.0.0.2", "peer_pubkey": piaOurKey}}
		k.handler = func(req netx.Request) (netx.Response, error) {
			u, err := url.Parse(req.URL)
			if err != nil {
				return netx.Response{}, err
			}
			switch {
			case req.URL == PIATokenURL:
				return jsonBody(map[string]any{"token": piaToken}), nil
			case req.URL == PIAStatusURL:
				return jsonBody(map[string]any{"connected": api.connected, "ip": exitIP4}), nil
			case u.Path == "/addKey":
				return jsonBody(api.addkey), nil
			case u.Path == "/getSignature":
				payload, _ := validate.MarshalJSON(map[string]any{"port": api.port})
				return jsonBody(map[string]any{"status": "OK", "payload": base64.StdEncoding.EncodeToString(payload), "signature": "SIG"}), nil
			case u.Path == "/bindPort":
				if api.bindFail {
					return jsonBody(map[string]any{"status": "ERROR"}), nil
				}
				return jsonBody(map[string]any{"status": "OK"}), nil
			}
			t.Fatalf("unexpected request path %s", u.Path)
			return netx.Response{}, errInjected
		}
		provider = NewPIA(PIAConfig{SecretsDir: secrets, PortForward: forward, Choose: func(int) int { return 0 }})
	default:
		t.Fatalf("unknown provider %s", name)
	}
	k.exit.Kind, k.exit.Overlay, k.exit.OverlayIf = "sidecar", "", ""
	k.overlayPresent, k.overlayWG, k.netbirdChains, k.returnPath = false, false, false, "0\n"
	a := newApplier(t, k, dir, provider, "")
	withPublished(a, dir)
	return a, k, api
}

func noOverlayCalls(t testing.TB, k *kernel) {
	t.Helper()
	for _, call := range []string{"LinkExists", "ReadSysctl", "OverlayKernelWireGuard", "NetbirdFirewallPresent"} {
		if n := k.countCalls(call); n != 0 {
			t.Errorf("native sidecar called %s %d times", call, n)
		}
	}
	if k.guardInstalled != 0 {
		t.Error("native sidecar installed an overlay ingress guard")
	}
	for _, op := range k.nftOps {
		if !strings.HasPrefix(op, "sidecar-port ") {
			t.Errorf("native sidecar changed an overlay table: %s", op)
		}
	}
}

func connectNativeSidecar(t testing.TB, a *Applier) *Record {
	t.Helper()
	desire(t, a, requestAt(serverNames[a.hooks.ID()], nil))
	r := mustTick(t, a)
	if status(r) != "ok" {
		t.Fatalf("%s: %s", status(r), message(r))
	}
	return r
}

func TestNativeSidecarRecords(t *testing.T) {
	for _, provider := range nativeProviders {
		t.Run(provider, func(t *testing.T) {
			a, k, _ := nativeSidecarSetup(t, provider, false)
			r := connectNativeSidecar(t, a)
			if r.Get("kind") != "sidecar" || r.Get("backend") != "native" {
				t.Fatalf("kind %v backend %v", r.Get("kind"), r.Get("backend"))
			}
			for _, name := range []string{"routing", "traffic_protection", "peer", "handshake", "egress"} {
				if checkState(r, name) != "pass" {
					t.Errorf("%s: %v", name, recordCheckOf(r, name))
				}
			}
			for _, name := range []string{"netbird", "owner_record"} {
				if checkState(r, name) != "n/a" {
					t.Errorf("%s: %v", name, recordCheckOf(r, name))
				}
			}
			if checkState(r, "app_attachment") != "not-checked" || checkField(r, "traffic_protection", "from") != "routing" {
				t.Errorf("checks %v", r.Get("checks"))
			}
			if v := a.assess(r.Decoded()); v.State != "ok" || v.Label != "connected" {
				t.Errorf("verdict %s %s %v", v.State, v.Label, v.Reasons)
			}
			if k.countCalls("RoutingStatus 4") == 0 || k.countCalls("RoutingStatus 6") == 0 || k.countCalls("SidecarFirewall") == 0 {
				t.Error("native sidecar did not measure both routing families and the firewall")
			}
			noOverlayCalls(t, k)
		})
	}
}

func TestNativeSidecarGuardFailures(t *testing.T) {
	for _, provider := range nativeProviders {
		for _, fault := range []string{"routing4", "routing6", "firewall", "firewall-error", "both"} {
			t.Run(provider+"/"+fault, func(t *testing.T) {
				a, k, _ := nativeSidecarSetup(t, provider, false)
				connectNativeSidecar(t, a)
				from, guard, routing := "firewall", SidecarFirewallFailed, "pass"
				switch fault {
				case "routing4", "routing6", "both":
					family := 4
					if fault == "routing6" {
						family = 6
					}
					k.routeFault[family] = true
					from, guard, routing = "routing", RoutingFailed, "fail"
				case "firewall-error":
					k.sidecarFirewallErr = errInjected
				}
				if fault == "firewall" || fault == "both" {
					k.sidecarFirewallOK = false
				}
				n := len(k.reqs)
				r := a.inspect(t)
				if status(r) != "failed" || message(r) != guard || a.measurement.Safe {
					t.Errorf("%s %q safe %v", status(r), message(r), a.measurement.Safe)
				}
				if checkState(r, "routing") != routing || checkState(r, "traffic_protection") != "fail" || checkField(r, "traffic_protection", "from") != from {
					t.Errorf("checks %v", r.Get("checks"))
				}
				if checkState(r, "egress") != "unknown" || len(k.reqs) != n {
					t.Error("a failed guard allowed an egress request")
				}
				if v := a.assess(r.Decoded()); v.State != "failed" {
					t.Errorf("verdict %s %s", v.State, v.Label)
				}
				gate := a.gate(context.Background(), &Selection{Server: serverNames[provider]})
				if gate == nil || gate.state != "pending" || gate.message != "Waiting for the tunnel's routing and firewall; request will retry automatically." {
					t.Errorf("gate %+v", gate)
				}
				if a.Healthy(context.Background()) {
					t.Error("healthy with a failed guard")
				}
				noOverlayCalls(t, k)
			})
		}
	}
}

func TestNativeSidecarHealth(t *testing.T) {
	for _, provider := range nativeProviders {
		t.Run(provider, func(t *testing.T) {
			a, k, _ := nativeSidecarSetup(t, provider, false)
			r := connectNativeSidecar(t, a)
			ctx := context.Background()
			if !a.Healthy(ctx) {
				t.Fatal("connected sidecar not healthy")
			}
			// The pipeline repairs a missing peer; health measures the interface
			// and guards, even when the latest completed provider check failed.
			k.keys = nil
			a.inspect(t)
			if !a.Healthy(ctx) {
				t.Error("completed failed inspection not healthy")
			}
			k.tunnelPresent = false
			if a.Healthy(ctx) {
				t.Error("healthy without the tunnel interface")
			}
			k.tunnelPresent = true
			for _, fault := range []string{"stale", "future", "applying"} {
				record := r.Decoded()
				switch fault {
				case "stale":
					record["checked_at"] = validate.FormatTime(a.wall().Add(-151 * time.Second))
				case "future":
					record["checked_at"] = validate.FormatTime(a.wall().Add(time.Hour))
				case "applying":
					record["status"] = "applying"
				}
				if err := jsonfile.Write(a.resultPath, record, jsonfile.Options{}); err != nil {
					t.Fatal(err)
				}
				if a.Healthy(ctx) {
					t.Errorf("healthy with %s record", fault)
				}
			}
			noOverlayCalls(t, k)
		})
	}
}

func TestNativeSidecarPIAForwarding(t *testing.T) {
	a, k, api := nativeSidecarSetup(t, "pia", true)
	connectNativeSidecar(t, a)
	if !reflect.DeepEqual(k.forwardedPorts, []int{0, 0, api.port}) {
		t.Fatalf("start-up, switch and bound port: %v", k.forwardedPorts)
	}
	if r := a.inspect(t); r.Decoded()["forwarded_port"] != int64(api.port) {
		t.Errorf("forwarded_port %v", r.Decoded()["forwarded_port"])
	}
	k.now += BindIntervalSec
	a.nextHealth = 0
	mustTick(t, a)
	if len(k.forwardedPorts) != 3 || len(k.requestsTo("/bindPort")) != 2 {
		t.Fatalf("unchanged port rebind: %v", k.forwardedPorts)
	}
	// Renewing the signature can change the port without switching servers.
	k.now += SignatureMaxAgeSec
	a.nextHealth = 0
	api.port = 45678
	mustTick(t, a)
	if !reflect.DeepEqual(k.forwardedPorts, []int{0, 0, 43210, 45678}) {
		t.Fatalf("changed port: %v", k.forwardedPorts)
	}
	api.bindFail = true
	k.now += BindIntervalSec
	a.nextHealth = 0
	mustTick(t, a)
	if k.forwardedPorts[len(k.forwardedPorts)-1] != 0 || piaOf(a).forward != nil {
		t.Fatalf("failed bind: %v %+v", k.forwardedPorts, piaOf(a).forward)
	}
	if r := a.inspect(t); r.Get("forwarded_port") != nil || r.Get("port_forward_error") != "Port forwarding is unavailable; retrying." {
		t.Errorf("forwarded port %v error %v", r.Get("forwarded_port"), r.Get("port_forward_error"))
	}
	if !slices.Contains(k.logs, "applier: port forwarding failed: PIA refused to bind the forwarded port") {
		t.Errorf("the failure's log line names no cause: %q", k.logs)
	}
	noOverlayCalls(t, k)
}

func TestNativeSidecarPIAFirewallUpdateFailure(t *testing.T) {
	a, k, _ := nativeSidecarSetup(t, "pia", true)
	fail := true
	k.hooks = append(k.hooks, func(req netx.Request) error {
		if fail && strings.Contains(req.URL, "/bindPort?") {
			for _, port := range k.forwardedPorts {
				if port != 0 {
					t.Error("port admitted before PIA bound it")
				}
			}
			k.nftFailures, fail = 1, false
		}
		return nil
	})
	connectNativeSidecar(t, a)
	if piaOf(a).forward != nil || !reflect.DeepEqual(k.forwardedPorts, []int{0, 0, 0}) {
		t.Fatalf("failed firewall update: %v %+v", k.forwardedPorts, piaOf(a).forward)
	}
	k.now += ForwardRetrySec
	a.nextHealth = 0
	mustTick(t, a)
	if !reflect.DeepEqual(k.forwardedPorts, []int{0, 0, 0, 43210}) || !piaOf(a).forward.bound {
		t.Errorf("retry: %v %+v", k.forwardedPorts, piaOf(a).forward)
	}
	noOverlayCalls(t, k)
}

func TestNativeSidecarPIAStillRefusesNamespaceAddressCollisions(t *testing.T) {
	a, k, _ := nativeSidecarSetup(t, "pia", false)
	k.namespaceNets = []netip.Prefix{netip.PrefixFrom(mustAddr("10.0.0.2"), 32)}
	relay, _ := a.catalog.Relays().Get(piaRegion)
	_, err := piaOf(a).register(context.Background(), a, relay)
	if err == nil || err.Error() != "PIA tunnel address collides with this namespace" {
		t.Fatalf("collision: %v", err)
	}
	if k.countCalls("ChangePIAAddress") != 0 || len(k.mutations) != 0 {
		t.Error("refused registration mutated the tunnel")
	}
}

func TestNativeSidecarPIASwitchClearsThePort(t *testing.T) {
	a, k, api := nativeSidecarSetup(t, "pia", true)
	connectNativeSidecar(t, a)
	api.addkey["server_key"], api.port = piaOtherKey, 45678
	desire(t, a, piaRequest(map[string]any{"request_id": strings.Repeat("2", 32)}))
	k.now++
	mustTick(t, a)
	if !reflect.DeepEqual(k.forwardedPorts, []int{0, 0, 43210, 0, 45678}) {
		t.Fatalf("switch ports: %v", k.forwardedPorts)
	}
	noOverlayCalls(t, k)
}

func TestNativeSidecarPIAReconcilesWithForwardingOff(t *testing.T) {
	a, k, _ := nativeSidecarSetup(t, "pia", false)
	k.nftFailures = 1
	mustTick(t, a)
	if piaOf(a).forwardReconciled {
		t.Fatal("failed cleanup marked complete")
	}
	mustTick(t, a)
	mustTick(t, a)
	if !reflect.DeepEqual(k.forwardedPorts, []int{0}) || !piaOf(a).guardInstalled {
		t.Errorf("cleanup %v guard %v", k.forwardedPorts, piaOf(a).guardInstalled)
	}
	noOverlayCalls(t, k)
}

func TestNativeSidecarPIAConfiguration(t *testing.T) {
	for _, flag := range []string{"on", "off", ""} {
		for _, target := range []string{"", "192.0.2.10", "invalid"} {
			env := map[string]string{"PIA_PORT_FORWARD": flag, "PIA_PORT_FORWARD_TARGET": target}
			p, err := NewPIAFromEnv(Exit{Kind: "sidecar"}, func(k string) string { return env[k] })
			if target != "" {
				if err == nil || err.Error() != "PIA_PORT_FORWARD_TARGET is for the overlay kind; a sidecar's forwarded port reaches the namespace itself" {
					t.Errorf("%s %s: %v", flag, target, err)
				}
			} else if err != nil {
				t.Errorf("%s without target: %v", flag, err)
			} else if cfg := p.(*piaProvider).cfg; cfg.ForwardTarget != "" || cfg.PortForward != (flag == "on") {
				t.Errorf("%s: %+v", flag, cfg)
			}
		}
	}
}

func TestNativeSidecarRequests(t *testing.T) {
	for _, provider := range nativeProviders {
		t.Run(provider, func(t *testing.T) {
			a, k, _ := nativeSidecarSetup(t, provider, provider == "pia")
			// Catalogues are deliberately fetched before any tunnel exists.
			k.tunnelPresent = false
			k.hooks = append(k.hooks, func(req netx.Request) error {
				if req.URL == a.spec.CatalogURL {
					if req.BindInterface != "" {
						t.Error("catalogue bound before the tunnel exists")
					}
					return errInjected
				}
				if req.BindInterface != "" && !k.tunnelPresent {
					t.Error("tunnel-bound request before the tunnel exists")
				}
				return nil
			})
			_, _ = a.DefaultFetchCatalog(context.Background())
			mustTick(t, a)
			if len(k.reqs) != 1 {
				t.Error("missing tunnel allowed a provider request")
			}
			k.tunnelPresent = true
			connectNativeSidecar(t, a)
			for _, req := range k.reqs[1:] {
				bound := true
				if req.URL == PIATokenURL || strings.Contains(req.URL, "/addKey?") {
					bound = false
				}
				if bound && req.BindInterface != a.exit.ExitIf {
					t.Errorf("provider request escaped tunnel binding")
				}
				if !bound && req.BindInterface != "" {
					t.Error("PIA login or registration unexpectedly bound to tunnel")
				}
			}
		})
	}
}

func TestNativeSidecarIPv6EvidenceHasNoOverlayExemption(t *testing.T) {
	a, k, _ := nativeSidecarSetup(t, "mullvad", false)
	k.host6Routes, k.host6Links = []any{}, []any{}
	if !a.hostLacksIPv6(context.Background()) {
		t.Fatal("empty namespace claimed to have host IPv6")
	}
	a.exit.OverlayIf = testOverlay
	k.host6Links = []any{map[string]any{"ifname": testOverlay, "addr_info": []any{
		map[string]any{"family": "inet6", "scope": "global", "local": hostIP6}}}}
	if a.hostLacksIPv6(context.Background()) {
		t.Error("native sidecar ignored host IPv6 on an overlay-named interface")
	}
	k.host6Links = []any{map[string]any{"ifname": a.exit.ExitIf, "addr_info": []any{
		map[string]any{"family": "inet6", "scope": "global", "local": tunnel6}}}}
	if !a.hostLacksIPv6(context.Background()) {
		t.Error("tunnel IPv6 counted as host IPv6")
	}
}

func TestNativeSidecarPIARefusesAnAddressInsideTheLAN(t *testing.T) {
	a, k, _ := nativeSidecarSetup(t, "pia", false)
	a.exit.LAN = []string{"10.0.0.0/24", "2001:db8::/64"}
	relay, _ := a.catalog.Relays().Get(piaRegion)
	_, err := piaOf(a).register(context.Background(), a, relay)
	if err == nil || err.Error() != "PIA tunnel address collides with this namespace" {
		t.Fatalf("collision with SIDECAR_LAN_CIDRS: %v", err)
	}
	if k.countCalls("ChangePIAAddress") != 0 || len(k.mutations) != 0 {
		t.Error("refused registration mutated the tunnel")
	}
	a.exit.LAN = []string{"192.0.2.0/24"}
	if _, err := piaOf(a).register(context.Background(), a, relay); err != nil {
		t.Fatalf("a LAN elsewhere: %v", err)
	}
}
