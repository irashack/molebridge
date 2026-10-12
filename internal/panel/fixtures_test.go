package panel

// Status records and requests for the panel's tests, with fictitious values
// only: panel/fixtures/records.py in Go. schema 2 as the appliers publish it,
// and the 0.6 shape the panel still reads.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/verdict"
)

const (
	validPubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	egressIP    = "203.0.113.7"
	requestID   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var fixtureServer = map[string]string{
	"mullvad": "se-sto-wg-001", "pia": "ex_example", "nordvpn": "us9001.nordvpn.com",
	"gluetun-mullvad": "se-sto-wg-001", "gluetun-nordvpn": "us9001.nordvpn.com",
	"gluetun-surfshark": "us-chi.prod.surfshark.com",
}

func nowISO() string { return state.NowISO() }

// request is a panel request, as desired.json holds it.
func request(server string, opt ...string) map[string]any {
	id, at := requestID, ""
	if len(opt) > 0 {
		id = opt[0]
	}
	if len(opt) > 1 {
		at = opt[1]
	}
	if at == "" {
		at = nowISO()
	}
	return map[string]any{"server": server, "requested_at": at, "request_id": id}
}

// recOpts are schema2's keyword arguments; zero values mean the defaults.
type recOpts struct {
	Provider   string
	Kind       string
	Status     string
	Server     string
	Checks     map[string]any // a state string, or a whole check
	At         string
	Configured string
	Source     string
	Outcome    string
	Extra      map[string]any // replaces top-level fields
}

func or(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// schema2 is a schema-2 record: every required check passing unless Checks
// overrides it.
func schema2(o recOpts) map[string]any {
	o.Provider, o.Kind, o.Status = or(o.Provider, "mullvad"), or(o.Kind, "overlay"), or(o.Status, "ok")
	at := or(o.At, nowISO())
	backend := verdict.BackendOf(o.Provider)
	server := o.Server
	if server == "" {
		server = fixtureServer[o.Provider]
		if server == "" {
			server = "se-sto-wg-001"
		}
	}
	spec, _ := providers.Lookup(o.Provider)
	checks := map[string]any{}
	for _, name := range verdict.RequiredChecks(o.Kind, backend) {
		check := map[string]any{"state": "pass", "at": at}
		for _, bound := range verdict.ServerBound {
			if bound == name {
				check["server"] = server
			}
		}
		switch name {
		case "routing":
			check["fallback"] = true
		case "traffic_protection":
			check["from"] = "routing"
		case "handshake":
			check["age_s"] = 12
		case "egress":
			check["tier"] = spec.EgressTier
			check["expected_families"] = []any{"4"}
			check["families"] = map[string]any{"4": "pass"}
		}
		checks[name] = check
	}
	for _, fixed := range verdict.FixedChecks(o.Kind, backend) {
		check := map[string]any{"state": fixed.State}
		if fixed.State == "not-checked" {
			check["by"] = verdict.NotCheckedBy[fixed.Name]
		}
		checks[fixed.Name] = check
	}
	names := make([]string, 0, len(o.Checks))
	for name := range o.Checks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		switch change := o.Checks[name].(type) {
		case string:
			merged := map[string]any{}
			if old, ok := checks[name].(map[string]any); ok {
				for k, v := range old {
					merged[k] = v
				}
			}
			merged["state"] = change
			if name == "egress" && change != "pass" {
				merged["tier"] = nil
				family := "unknown"
				if change == "fail" {
					family = "fail"
				}
				merged["families"] = map[string]any{"4": family}
			}
			checks[name] = merged
		default:
			checks[name] = change
		}
	}
	egress, _ := checks["egress"].(map[string]any)
	egressIPs := map[string]any{}
	if egress["state"] == "pass" {
		egressIPs["4"] = egressIP
	}
	message := "Healthy."
	if o.Status != "ok" {
		message = "Tunnel egress is not confirmed."
	}
	var configured any
	if o.Configured != "" {
		configured = o.Configured
	}
	record := map[string]any{
		"schema": 2, "kind": o.Kind, "backend": backend, "provider": o.Provider, "status": o.Status,
		"message": message, "checked_at": at, "server": server, "requested_server": server,
		"configured_server": configured, "request_id": requestID,
		"selection": map[string]any{"source": or(o.Source, "panel"), "outcome": or(o.Outcome, "verified"), "attempt": 1,
			"target": server, "next_action": nil, "next_action_at": nil},
		"checks": checks,
		// egress_ips covers exactly the passing families.
		"egress_ip": egressIP, "egress_ips": egressIPs, "egress_city": "Stockholm", "egress_country": "Sweden",
	}
	for k, v := range o.Extra {
		record[k] = v
	}
	return record
}

// unmeasurableSidecar is a tunnel-tier sidecar after a switch: switched, its
// egress never comparable with the host's address.
func unmeasurableSidecar() map[string]any {
	record := schema2(recOpts{Provider: "gluetun-surfshark", Kind: "sidecar", Status: "failed", Outcome: "applied-unverified"})
	record["checks"].(map[string]any)["egress"] = map[string]any{
		"state": "fail", "at": record["checked_at"], "server": record["server"], "tier": nil,
		"expected_families": []any{"4"}, "families": map[string]any{"4": "unknown"}, "reason": "host-address-not-measurable"}
	record["message"] = "Switched; the egress couldn't be compared with this host's address."
	record["egress_ips"] = map[string]any{"4": egressIP}
	selection := record["selection"].(map[string]any)
	selection["next_action"], selection["next_action_at"] = "recheck", "2026-10-10T18:01:00Z"
	return record
}

// legacy is a 0.6 overlay record (no schema).
func legacy(status string, fields map[string]any) map[string]any {
	if status == "" {
		status = "ok"
	}
	record := map[string]any{
		"server": "se-sto-wg-001", "requested_server": "se-sto-wg-001", "request_id": requestID, "status": status,
		"message": "Healthy.", "checked_at": nowISO(), "routing_ok": true, "netbird_native": true,
		"exit_confirmed": true, "egress_tier": "provider", "handshake_age_s": 12, "unreachable_fallback": true,
		"egress_ip": egressIP, "egress_city": "Stockholm", "egress_country": "Sweden",
	}
	if status != "ok" {
		record["message"] = "Switch verification timed out."
		record["exit_confirmed"], record["egress_tier"] = false, nil
	}
	for k, v := range fields {
		record[k] = v
	}
	return record
}

func without(record map[string]any, check string) map[string]any {
	delete(record["checks"].(map[string]any), check)
	return record
}

// consumerCase is one row of the consumer matrix: one exit's record (and the
// panel's request), and the state and label every consumer must show for it.
// Records and requests are built when called, so their times are fresh.
type consumerCase struct {
	provider, kind string
	record         func() map[string]any
	request        func() map[string]any
	state, label   string
	tier           string
}

func serverOf(provider string) string { return fixtureServer[provider] }

var consumerCases = map[string]consumerCase{
	"legacy-ok": {"mullvad", "overlay", func() map[string]any { return legacy("", nil) },
		func() map[string]any { return request(serverOf("mullvad")) }, "ok", "connected", "provider"},
	"legacy-failed": {"mullvad", "overlay", func() map[string]any { return legacy("failed", nil) },
		func() map[string]any { return request(serverOf("mullvad")) }, "failed", "failed", ""},
	"overlay-ok": {"mullvad", "overlay", func() map[string]any { return schema2(recOpts{}) },
		func() map[string]any { return request(serverOf("mullvad")) }, "ok", "connected", "provider"},
	"overlay-routing-failed": {"mullvad", "overlay", func() map[string]any {
		return schema2(recOpts{Status: "failed", Checks: map[string]any{"routing": "fail", "traffic_protection": "fail", "egress": "unknown"}})
	}, func() map[string]any { return request(serverOf("mullvad")) }, "failed", "failed", ""},
	"overlay-retrying": {"mullvad", "overlay", func() map[string]any {
		return schema2(recOpts{Status: "failed", Checks: map[string]any{"egress": "fail"}, Outcome: "applied-unverified",
			Extra: map[string]any{"selection": map[string]any{"source": "panel", "outcome": "applied-unverified", "attempt": 2,
				"target": serverOf("mullvad"), "next_action": "reapply", "next_action_at": "2026-10-10T18:02:30Z"}}})
	}, func() map[string]any { return request(serverOf("mullvad")) }, "failed", "failed", ""},
	"pia-forwarding": {"pia", "overlay", func() map[string]any {
		return schema2(recOpts{Provider: "pia", Extra: map[string]any{"port_forward": true, "forwarded_port": 43210}})
	}, func() map[string]any { return request(serverOf("pia")) }, "ok", "connected", "provider"},
	"overlay-gluetun-tunnel-tier": {"gluetun-surfshark", "overlay", func() map[string]any { return schema2(recOpts{Provider: "gluetun-surfshark"}) },
		func() map[string]any { return request(serverOf("gluetun-surfshark")) }, "ok", "connected", "tunnel"},
	"sidecar-provider-tier": {"gluetun-mullvad", "sidecar", func() map[string]any { return schema2(recOpts{Provider: "gluetun-mullvad", Kind: "sidecar"}) },
		func() map[string]any { return request(serverOf("gluetun-mullvad")) }, "ok", "connected", "provider"},
	"sidecar-tunnel-tier": {"gluetun-surfshark", "sidecar", unmeasurableSidecar,
		func() map[string]any { return request(serverOf("gluetun-surfshark")) }, "unknown", "switched, egress unverified", ""},
	"unsupported-schema": {"mullvad", "overlay", func() map[string]any { return schema2(recOpts{Extra: map[string]any{"schema": 3}}) },
		func() map[string]any { return request(serverOf("mullvad")) }, "unknown", "unsupported status version", ""},
	"kind-mismatch": {"gluetun-mullvad", "overlay", func() map[string]any { return schema2(recOpts{Provider: "gluetun-mullvad", Kind: "sidecar"}) },
		func() map[string]any { return request(serverOf("gluetun-mullvad")) }, "unknown", "kind mismatch", ""},
	"provider-mismatch": {"mullvad", "overlay", func() map[string]any { return schema2(recOpts{Provider: "nordvpn"}) },
		func() map[string]any { return request(serverOf("mullvad")) }, "unknown", "provider mismatch", ""},
	"missing-check": {"mullvad", "overlay", func() map[string]any { return without(schema2(recOpts{}), "peer") },
		func() map[string]any { return request(serverOf("mullvad")) }, "unknown", "invalid status record", ""},
	"stale": {"mullvad", "overlay", func() map[string]any { return schema2(recOpts{At: "2000-01-01T00:00:00Z"}) },
		func() map[string]any { return request(serverOf("mullvad")) }, "unknown", "status stale", ""},
	"request-pending": {"mullvad", "overlay", func() map[string]any { return schema2(recOpts{}) },
		func() map[string]any { return request("se-got-wg-001", strings.Repeat("b", 32)) }, "applying", "switching", ""},
	"request-not-acknowledged": {"mullvad", "overlay", func() map[string]any { return schema2(recOpts{}) },
		func() map[string]any {
			return request("se-got-wg-001", strings.Repeat("b", 32), "2000-01-01T00:00:00Z")
		},
		"unknown", "request not acknowledged", ""},
	"target-disagreement": {"mullvad", "overlay", func() map[string]any {
		return schema2(recOpts{Extra: map[string]any{"requested_server": "se-got-wg-001"}})
	}, func() map[string]any { return request("se-got-wg-001") }, "failed", "verification failed", ""},
	"configured": {"mullvad", "overlay", func() map[string]any {
		return schema2(recOpts{Configured: serverOf("mullvad"), Source: "configured",
			Extra: map[string]any{"request_id": nil, "requested_server": nil}})
	}, func() map[string]any { return request("se-got-wg-001", strings.Repeat("b", 32)) }, "ok", "connected", "provider"},
	"no-status": {"mullvad", "overlay", func() map[string]any { return nil }, func() map[string]any { return nil },
		"unknown", "awaiting status", ""},
}

func caseNames() []string {
	names := make([]string, 0, len(consumerCases))
	for name := range consumerCases {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// mustWrite writes a state file the way the applier or panel would.
func mustWrite(t testing.TB, path string, value map[string]any) {
	t.Helper()
	if value == nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := state.WriteJSONAtomic(path, value, true, 0); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
