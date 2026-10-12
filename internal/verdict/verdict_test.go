// Tests for molebridge/verdict.py, ported from tools/test_verdict.py (every
// test there has a counterpart here, in the same order), plus the status_view
// checks from tools/test_runtime.py (test_status_never_trusts_old_invalid_or_
// future_checks, test_status_requires_routing_and_request_ack), tools/test_egress.py
// (test_tunnel_tier_counts_only_for_a_provider_without_its_own_check) and
// tools/test_pia.py (test_status_uses_the_generic_confirmation), and the new
// cases for the owner_record check's expires_at (decision D7).
package verdict

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
)

var now = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

const (
	host         = "se-sto-wg-001"
	other        = "se-sto-wg-002"
	gluetunHost  = "two.example.test"
	requestIDHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func at(secondsAgo int) string {
	return validate.FormatTime(now.Add(-time.Duration(secondsAgo) * time.Second))
}

func request(server string) map[string]any {
	return map[string]any{"server": server, "requested_at": "2026-10-11T11:59:50Z", "request_id": requestIDHex}
}

type opts struct {
	kind, provider, server, tier string
	families                     []string
}

func (o opts) withDefaults() opts {
	if o.kind == "" {
		o.kind = "overlay"
	}
	if o.provider == "" {
		o.provider = "mullvad"
	}
	if o.server == "" {
		o.server = host
	}
	if o.tier == "" {
		o.tier = "provider"
	}
	if o.families == nil {
		o.families = []string{"4", "6"}
	}
	return o
}

// record is a healthy schema-2 record as the applier writes it, changed by
// changes (a nil value is a JSON null; the string "\x00absent" removes the key).
func record(t testing.TB, o opts, changes map[string]any) map[string]any {
	t.Helper()
	o = o.withDefaults()
	backend := "native"
	if strings.HasPrefix(o.provider, "gluetun-") {
		backend = "gluetun"
	}
	expected := make([]any, len(o.families))
	families := map[string]any{}
	ips := map[string]any{}
	for i, f := range o.families {
		expected[i], families[f] = f, "pass"
		ips[f] = "2001:db8::7"
		if f == "4" {
			ips[f] = "203.0.113.7"
		}
	}
	checks := map[string]any{
		"peer":      map[string]any{"state": "pass", "at": at(5), "server": o.server},
		"handshake": map[string]any{"state": "pass", "at": at(5), "server": o.server, "age_s": 12},
		"egress": map[string]any{"state": "pass", "at": at(5), "server": o.server, "tier": o.tier,
			"expected_families": expected, "families": families}}
	if o.kind == "overlay" {
		checks["routing"] = map[string]any{"state": "pass", "at": at(5), "fallback": true}
		checks["netbird"] = map[string]any{"state": "pass", "at": at(5)}
		checks["traffic_protection"] = map[string]any{"state": "pass", "at": at(5), "from": "routing"}
		checks["app_attachment"] = map[string]any{"state": "n/a"}
		if backend == "native" {
			checks["owner_record"] = map[string]any{"state": "pass", "at": at(5)}
		} else {
			checks["owner_record"] = map[string]any{"state": "n/a"}
		}
	} else {
		checks["routing"] = map[string]any{"state": "n/a"}
		checks["netbird"] = map[string]any{"state": "n/a"}
		checks["owner_record"] = map[string]any{"state": "n/a"}
		checks["traffic_protection"] = map[string]any{"state": "not-checked", "by": "gluetun's firewall"}
		checks["app_attachment"] = map[string]any{"state": "not-checked", "by": "the host doctor"}
	}
	result := map[string]any{"schema": 2, "kind": o.kind, "backend": backend, "provider": o.provider, "status": "ok",
		"message": "Healthy.", "checked_at": at(5), "server": o.server, "requested_server": o.server,
		"configured_server": nil, "request_id": requestIDHex,
		"selection": map[string]any{"source": "panel", "outcome": "verified", "attempt": 1, "target": o.server,
			"next_action": nil, "next_action_at": nil},
		"checks": checks, "egress_ip": "203.0.113.7", "egress_ips": ips}
	for k, v := range changes {
		if s, ok := v.(string); ok && s == "\x00absent" {
			delete(result, k)
		} else {
			result[k] = v
		}
	}
	return result
}

func rec(t testing.TB, changes map[string]any) map[string]any { return record(t, opts{}, changes) }

// settle turns Go values into what the strict decoder would have produced.
func settle(t testing.TB, v any) any {
	t.Helper()
	raw, err := validate.MarshalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := validate.DecodeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// panel judges result the way the panel does. A nil desired is the standard
// request; pass an empty map for "no request".
func panel(t testing.TB, result any, desired any, provider, kind string) Verdict {
	t.Helper()
	if desired == nil {
		desired = request(host)
	}
	if provider == "" {
		provider = "mullvad"
	}
	if kind == "" {
		kind = "overlay"
	}
	result, desired = settle(t, result), settle(t, desired)
	exit, err := NewExitConfig(provider, kind, "")
	if err != nil {
		t.Fatal(err)
	}
	return Assess(exit, result, TargetForPanel(result, desired, provider), now)
}

func pm(t testing.TB, result any) Verdict { return panel(t, result, nil, "", "") }

func withCheck(result map[string]any, name string, fields map[string]any) map[string]any {
	merged := map[string]any{}
	for k, v := range result["checks"].(map[string]any)[name].(map[string]any) {
		merged[k] = v
	}
	for k, v := range fields {
		merged[k] = v
	}
	result["checks"].(map[string]any)[name] = merged
	return result
}

func sidecar(t testing.TB, changes map[string]any) map[string]any {
	return record(t, opts{kind: "sidecar", provider: "gluetun-nordvpn", server: gluetunHost, families: []string{"4"}}, changes)
}

func sidecarVerdict(t testing.TB, result any) Verdict {
	return panel(t, result, request(gluetunHost), "gluetun-nordvpn", "sidecar")
}

func reasonsOf(v Verdict) string { return strings.Join(v.Reasons, ",") }

// -- schema 2 -------------------------------------------------------------------------

func TestAHealthyRecordIsConnectedForEveryKind(t *testing.T) {
	v := pm(t, rec(t, nil))
	if v.State != "ok" || v.Label != "connected" || v.Tier != "provider" || v.Schema != 2 {
		t.Errorf("%+v", v)
	}
	if v.Checks.Get("owner_record") != "pass" || v.Checks.Get("app_attachment") != "n/a" {
		t.Errorf("%v", v.Checks)
	}
	v = sidecarVerdict(t, sidecar(t, nil))
	if v.State != "ok" || v.Checks.Get("traffic_protection") != "not-checked" || v.Checks.Get("routing") != "n/a" {
		t.Errorf("%+v", v)
	}
}

func TestUnknownOrNewerVersionsAreNeverConnected(t *testing.T) {
	for _, schema := range []any{1, 3, "2", nil, 2.0, true, []any{2}} {
		if v := pm(t, rec(t, map[string]any{"schema": schema})); v.Label != "unsupported status version" || v.State != "unknown" {
			t.Errorf("schema %#v: %+v", schema, v)
		}
	}
}

func TestKindProviderAndBackendAreNeverDefaulted(t *testing.T) {
	for name, tc := range map[string]struct {
		changes map[string]any
		label   string
	}{
		"kind sidecar": {map[string]any{"kind": "sidecar"}, "kind mismatch"}, "kind null": {map[string]any{"kind": nil}, "kind mismatch"},
		"provider pia": {map[string]any{"provider": "pia"}, "provider mismatch"}, "provider null": {map[string]any{"provider": nil}, "provider mismatch"},
		"backend gluetun": {map[string]any{"backend": "gluetun"}, "provider mismatch"}, "backend null": {map[string]any{"backend": nil}, "provider mismatch"},
		"kind missing": {map[string]any{"kind": "\x00absent"}, "kind mismatch"},
	} {
		v := pm(t, rec(t, tc.changes))
		if v.State != "unknown" || v.Label != tc.label {
			t.Errorf("%s: %+v", name, v)
		}
	}
}

func TestASidecarReaderRefusesAnOverlayRecordAndANativeProvider(t *testing.T) {
	if pm(t, rec(t, nil)).State != "ok" {
		t.Error("overlay record not ok")
	}
	if _, err := NewExitConfig("mullvad", "sidecar", ""); err == nil || err.Error() != "a sidecar exit needs a gluetun provider (PROVIDER=gluetun-<name>)" {
		t.Errorf("got %v", err)
	}
	if _, err := NewExitConfig("mullvad", "satellite", ""); err == nil || err.Error() != "EXIT_KIND must be overlay or sidecar" {
		t.Errorf("got %v", err)
	}
	if _, err := NewExitConfig("examplevpn", "overlay", ""); err == nil || err.Error() != "unknown provider" {
		t.Errorf("got %v", err)
	}
	if c, err := NewExitConfig("mullvad", "", "a"); err != nil || c.Kind != "overlay" || c.ID != "a" {
		t.Errorf("default kind: %+v %v", c, err)
	}
	overlay := record(t, opts{provider: "gluetun-nordvpn", server: gluetunHost}, nil)
	if v := panel(t, overlay, request(gluetunHost), "gluetun-nordvpn", "sidecar"); v.Label != "kind mismatch" {
		t.Errorf("%+v", v)
	}
}

func TestAStaleFutureOrMalformedEnvelopeIsUnknown(t *testing.T) {
	for _, checked := range []any{at(151), at(-10), "broken", nil, "2026-10-11T12:00:00", at(150) + "\n", 5} {
		v := pm(t, rec(t, map[string]any{"checked_at": checked}))
		if v.State != "unknown" || v.Label != "status stale" {
			t.Errorf("%#v: %+v", checked, v)
		}
	}
	if v := pm(t, rec(t, map[string]any{"checked_at": at(150)})); v.State == "unknown" && v.Label == "status stale" {
		t.Error("150 seconds is still fresh")
	}
}

func TestRequestAcknowledgement(t *testing.T) {
	newer := request(host)
	newer["request_id"] = strings.Repeat("b", 32)
	if v := panel(t, rec(t, nil), newer, "", ""); v.State != "applying" {
		t.Errorf("%+v", v)
	}
	newer["requested_at"] = at(151)
	if v := panel(t, rec(t, nil), newer, "", ""); v.Label != "request not acknowledged" || reasonsOf(v) != "request-not-acknowledged" {
		t.Errorf("%+v", v)
	}
}

func TestApplyingIsSwitching(t *testing.T) {
	if v := pm(t, rec(t, map[string]any{"status": "applying"})); v.State != "applying" || v.Label != "switching" {
		t.Errorf("%+v", v)
	}
}

func TestAMissingOrWaivedRequiredCheckIsAnInvalidRecord(t *testing.T) {
	for _, name := range []string{"routing", "netbird", "owner_record", "peer", "handshake", "egress", "traffic_protection"} {
		broken := rec(t, nil)
		delete(broken["checks"].(map[string]any), name)
		if v := pm(t, broken); v.Label != "invalid status record" {
			t.Errorf("%s missing: %+v", name, v)
		}
		waived := rec(t, nil)
		waived["checks"].(map[string]any)[name] = map[string]any{"state": "n/a"}
		if v := pm(t, waived); v.Label != "invalid status record" {
			t.Errorf("%s waived: %+v", name, v)
		}
	}
}

func TestTrafficProtectionIsTheRoutingContractItself(t *testing.T) {
	if v := pm(t, withCheck(rec(t, nil), "traffic_protection", map[string]any{"from": "gluetun"})); v.Label != "invalid status record" {
		t.Errorf("%+v", v)
	}
}

// Evidence rules -------------------------------------------------------------------

func TestExpiredFutureOrMissingEvidenceIsUnknownNotFailed(t *testing.T) {
	for _, name := range []string{"routing", "peer", "handshake", "egress"} {
		for _, when := range []any{at(151), at(-30), nil, "yesterday"} {
			v := pm(t, withCheck(rec(t, nil), name, map[string]any{"at": when}))
			if v.State != "unknown" || v.Label != "evidence expired" || v.Checks.Get(name) != "unknown" {
				t.Errorf("%s at %v: %+v", name, when, v)
			}
		}
	}
}

func TestASlowInspectionYieldsExpiredEvidenceNotExtendedEvidence(t *testing.T) {
	// A fresh envelope whose early measurements aged out while egress probes
	// ran (routing measured first) is unknown, never ok and never failed.
	slow := rec(t, nil)
	for _, name := range []string{"routing", "netbird", "owner_record", "traffic_protection", "peer", "handshake"} {
		slow["checks"].(map[string]any)[name].(map[string]any)["at"] = at(160)
	}
	if v := pm(t, slow); v.State != "unknown" || v.Label != "evidence expired" {
		t.Errorf("%+v", v)
	}
}

func TestAPassForAPreviousSelectionNeverCounts(t *testing.T) {
	for _, name := range []string{"peer", "handshake", "egress"} {
		v := pm(t, withCheck(rec(t, nil), name, map[string]any{"server": other}))
		if v.State != "unknown" || v.Checks.Get(name) != "unknown" {
			t.Errorf("%s: %+v", name, v)
		}
	}
}

func TestHandshakeTypesAreStrict(t *testing.T) {
	for _, age := range []any{180, 500, nil, -1, "12", 12.5, true} {
		if v := pm(t, withCheck(rec(t, nil), "handshake", map[string]any{"age_s": age})); v.Label != "invalid status record" {
			t.Errorf("age %#v: %+v", age, v)
		}
	}
	if v := pm(t, withCheck(rec(t, nil), "handshake", map[string]any{"age_s": 179})); v.State != "ok" {
		t.Errorf("179 seconds is fresh: %+v", v)
	}
}

func TestAFailedHandshakeMayBeStaleOrNeverCompleted(t *testing.T) {
	for _, age := range []any{180, 10000, nil} {
		v := pm(t, withCheck(rec(t, map[string]any{"status": "failed"}), "handshake", map[string]any{"state": "fail", "age_s": age}))
		if v.State != "failed" || !strings.Contains(reasonsOf(v), "handshake-failed") {
			t.Errorf("age %#v: %+v", age, v)
		}
	}
}

func TestEgressFamiliesAndTierAreStrict(t *testing.T) {
	for name, egress := range map[string]map[string]any{
		"an expected family missing": {"families": map[string]any{"4": "pass"}},
		"a family failed":            {"families": map[string]any{"4": "pass", "6": "fail"}},
		"unknown family":             {"families": map[string]any{"4": "pass", "5": "pass"}},
		"no expected families":       {"expected_families": []any{}},
		"duplicate expected":         {"expected_families": []any{"4", "4"}},
		"bad family state":           {"families": map[string]any{"4": "yes", "6": "pass"}},
		"unknown tier":               {"tier": "gold"},
		"no tier":                    {"tier": nil},
		"tier not text":              {"tier": 3},
		"expected not a list":        {"expected_families": "46"},
		"expected unknown family":    {"expected_families": []any{"4", "5"}},
		"expected not hashable":      {"expected_families": []any{[]any{"4"}}},
		"families not an object":     {"families": []any{"4"}},
	} {
		if v := pm(t, withCheck(rec(t, nil), "egress", egress)); v.Label != "invalid status record" {
			t.Errorf("%s: %+v", name, v)
		}
	}
}

func TestEgressIPsMustCoverExactlyThePassingFamilies(t *testing.T) {
	if v := pm(t, rec(t, map[string]any{"egress_ips": map[string]any{"4": "203.0.113.7"}})); v.Label != "invalid status record" {
		t.Errorf("%+v", v)
	}
	if v := pm(t, rec(t, map[string]any{"egress_ips": map[string]any{"4": "203.0.113.7", "6": "2001:db8::7", "5": "x"}})); v.Label != "invalid status record" {
		t.Errorf("%+v", v)
	}
	for _, ips := range []any{nil, []any{}, "x"} {
		if v := pm(t, rec(t, map[string]any{"egress_ips": ips})); v.Label != "invalid status record" {
			t.Errorf("%#v: %+v", ips, v)
		}
	}
	if v := pm(t, rec(t, map[string]any{"egress_ips": "\x00absent"})); v.Label != "invalid status record" {
		t.Errorf("absent: %+v", v)
	}
}

func TestTheTunnelTierCountsOnlyWhereTheProviderHasNoStrongerCheck(t *testing.T) {
	if v := pm(t, record(t, opts{tier: "tunnel"}, nil)); v.Label != "invalid status record" {
		t.Errorf("%+v", v)
	}
	ivpn := record(t, opts{provider: "gluetun-ivpn", server: gluetunHost, tier: "tunnel", families: []string{"4"}}, nil)
	if v := panel(t, ivpn, request(gluetunHost), "gluetun-ivpn", ""); v.Tier != "tunnel" || v.State != "ok" {
		t.Errorf("%+v", v)
	}
	sc := record(t, opts{kind: "sidecar", provider: "gluetun-ivpn", server: gluetunHost, tier: "tunnel", families: []string{"4"}}, nil)
	if v := panel(t, sc, request(gluetunHost), "gluetun-ivpn", "sidecar"); v.Label != "invalid status record" {
		t.Errorf("%+v", v)
	}
}

// Verdict order --------------------------------------------------------------------------

func TestAFreshFailureWinsOverWhatWasntMeasured(t *testing.T) {
	// Inspection stops at a routing failure without measuring egress.
	stopped := rec(t, map[string]any{"status": "failed", "message": "Routing protection is incomplete; run the recovery helper."})
	stopped["checks"].(map[string]any)["routing"] = map[string]any{"state": "fail", "at": at(5), "fallback": true}
	stopped["checks"].(map[string]any)["traffic_protection"] = map[string]any{"state": "fail", "at": at(5), "from": "routing"}
	stopped["checks"].(map[string]any)["egress"] = map[string]any{"state": "unknown"}
	v := pm(t, stopped)
	if v.State != "failed" || !strings.Contains(reasonsOf(v), "routing-failed") || v.Message == nil ||
		!strings.HasPrefix(*v.Message, "Routing protection") || v.Checks.Get("egress") != "unknown" {
		t.Errorf("%+v", v)
	}
}

func TestAFreshFailureWinsOverExpiredEvidence(t *testing.T) {
	mixed := withCheck(rec(t, map[string]any{"status": "failed"}), "peer", map[string]any{"at": at(400)})
	withCheck(mixed, "egress", map[string]any{"state": "fail", "reason": "not-confirmed"})
	if v := pm(t, mixed); v.State != "failed" {
		t.Errorf("%+v", v)
	}
}

func TestARejectionIsFailedWhateverWasMeasured(t *testing.T) {
	rejected := rec(t, map[string]any{"status": "failed", "message": "Requested server is not in a fresh trusted relay catalogue."})
	rejected["selection"].(map[string]any)["outcome"] = "rejected"
	for _, name := range []string{"peer", "handshake", "egress"} {
		rejected["checks"].(map[string]any)[name] = map[string]any{"state": "unknown"}
	}
	if v := pm(t, rejected); v.State != "failed" || !strings.Contains(reasonsOf(v), "rejected") {
		t.Errorf("%+v", v)
	}
	rejected["selection"].(map[string]any)["outcome"] = "mutation-failed"
	if v := pm(t, rejected); v.State != "failed" || !strings.Contains(reasonsOf(v), "rejected") {
		t.Errorf("mutation-failed: %+v", v)
	}
}

func TestNotYetMeasuredOnlyWhenNothingFailed(t *testing.T) {
	starting := rec(t, map[string]any{"status": "unknown"})
	for _, name := range []string{"peer", "handshake", "egress"} {
		starting["checks"].(map[string]any)[name] = map[string]any{"state": "unknown"}
	}
	v := pm(t, starting)
	if v.Label != "not yet measured" || reasonsOf(v) != "peer-unmeasured,handshake-unmeasured,egress-unmeasured" {
		t.Errorf("%+v", v)
	}
	pending := rec(t, map[string]any{"status": "failed", "message": "Waiting for a fresh trusted relay catalogue."})
	for _, name := range []string{"peer", "handshake", "egress"} {
		pending["checks"].(map[string]any)[name] = map[string]any{"state": "unknown"}
	}
	if v := pm(t, pending); v.State != "failed" || reasonsOf(v) != "status-failed" {
		t.Errorf("%+v", v)
	}
}

func TestNextActionPassesThrough(t *testing.T) {
	unverified := rec(t, map[string]any{"status": "failed"})
	withCheck(unverified, "egress", map[string]any{"state": "fail", "tier": nil, "reason": "unanswered", "families": map[string]any{}})
	unverified["egress_ips"] = map[string]any{}
	unverified["selection"] = map[string]any{"source": "panel", "outcome": "applied-unverified", "attempt": 1, "target": host,
		"next_action": "recheck", "next_action_at": at(-60)}
	v := pm(t, unverified)
	if v.State != "failed" || v.NextAction != "recheck" || v.NextActionAt != at(-60) {
		t.Errorf("%+v", v)
	}
	// An unknown action, or a deadline that isn't a timestamp, is dropped.
	unverified["selection"].(map[string]any)["next_action"] = "explode"
	if v := pm(t, unverified); v.NextAction != "" || v.NextActionAt != "" {
		t.Errorf("%+v", v)
	}
	unverified["selection"].(map[string]any)["next_action"], unverified["selection"].(map[string]any)["next_action_at"] = "reapply", "soon"
	if v := pm(t, unverified); v.NextAction != "reapply" || v.NextActionAt != "" {
		t.Errorf("%+v", v)
	}
}

func TestATunnelTierSidecarIsSwitchedNeverConnected(t *testing.T) {
	sc := record(t, opts{kind: "sidecar", provider: "gluetun-ivpn", server: gluetunHost, families: []string{"4"}},
		map[string]any{"status": "failed", "message": "Switched; the egress couldn't be compared with this host's address."})
	sc["checks"].(map[string]any)["egress"] = map[string]any{"state": "fail", "at": at(5), "server": gluetunHost, "tier": nil,
		"reason": "host-address-not-measurable", "expected_families": []any{"4"}, "families": map[string]any{"4": "unknown"}}
	sc["egress_ips"] = map[string]any{}
	sc["selection"].(map[string]any)["outcome"] = "applied-unverified"
	v := panel(t, sc, request(gluetunHost), "gluetun-ivpn", "sidecar")
	if v.State != "unknown" || v.Label != "switched, egress unverified" || v.Message == nil || !strings.HasPrefix(*v.Message, "Switched") ||
		v.Checks.Get("traffic_protection") != "not-checked" || reasonsOf(v) != "host-address-not-measurable" {
		t.Errorf("%+v", v)
	}
	// A rejection, or another failure beside it, is a failure after all.
	sc["selection"].(map[string]any)["outcome"] = "rejected"
	if v := panel(t, sc, request(gluetunHost), "gluetun-ivpn", "sidecar"); v.State != "failed" {
		t.Errorf("%+v", v)
	}
}

// Target agreement, for every source ---------------------------------------------------------

func TestTargetAgreementForAPanelRequest(t *testing.T) {
	if v := pm(t, record(t, opts{server: other}, map[string]any{"requested_server": host})); reasonsOf(v) != "not-requested-server" {
		t.Errorf("%+v", v)
	}
	if v := pm(t, rec(t, map[string]any{"requested_server": other})); reasonsOf(v) != "not-requested-server" {
		t.Errorf("%+v", v)
	}
}

func TestTargetAgreementForTheConfiguredServer(t *testing.T) {
	if v := pm(t, rec(t, map[string]any{"configured_server": host, "request_id": nil})); v.State != "ok" {
		t.Errorf("%+v", v)
	}
	v := pm(t, record(t, opts{server: other}, map[string]any{"configured_server": host, "request_id": nil}))
	if v.State != "failed" || reasonsOf(v) != "not-configured-server" {
		t.Errorf("%+v", v)
	}
}

func assess(t testing.TB, exit ExitConfig, result any, target Target) Verdict {
	return Assess(exit, settle(t, result), target, now)
}

func TestTheLocalServerSettingIsAuthoritative(t *testing.T) {
	// The applier and the doctor judge against their own SERVER, whatever the
	// record says.
	exit := ExitConfig{Provider: "mullvad", Kind: "overlay"}
	if v := assess(t, exit, rec(t, map[string]any{"configured_server": nil}), Target{Server: host, Source: "configured"}); v.State != "ok" {
		t.Errorf("omitted: %+v", v)
	}
	if v := assess(t, exit, rec(t, map[string]any{"configured_server": other}), Target{Server: host, Source: "configured"}); v.State != "ok" {
		t.Errorf("misreported: %+v", v)
	}
	changed := record(t, opts{server: other}, map[string]any{"requested_server": other,
		"selection": map[string]any{"source": "configured", "target": other}})
	if v := assess(t, exit, changed, Target{Server: host, Source: "configured"}); v.State != "failed" {
		t.Errorf("another server: %+v", v)
	}
}

func TestTargetAgreementForTheResolvedTarget(t *testing.T) {
	exit := ExitConfig{Provider: "mullvad", Kind: "overlay"}
	for _, source := range []string{"restore", "reconverge", "retry", "operator-retry"} {
		selection := map[string]any{"source": source, "outcome": "verified", "target": host}
		if v := assess(t, exit, rec(t, map[string]any{"selection": selection}), Target{Server: host, Source: "restore"}); v.State != "ok" {
			t.Errorf("%s: %+v", source, v)
		}
		if v := assess(t, exit, rec(t, map[string]any{"selection": selection}), Target{Server: other, Source: "restore"}); v.State != "failed" || reasonsOf(v) != "not-target-server" {
			t.Errorf("%s: %+v", source, v)
		}
		// A reader without a target of its own holds the record to itself.
		if v := panel(t, rec(t, map[string]any{"selection": selection}), map[string]any{}, "", ""); v.State != "ok" {
			t.Errorf("%s: %+v", source, v)
		}
		bad := map[string]any{"source": source, "outcome": "verified", "target": other}
		if v := panel(t, rec(t, map[string]any{"selection": bad}), map[string]any{}, "", ""); v.State != "failed" {
			t.Errorf("%s: %+v", source, v)
		}
	}
}

func TestASeedWithoutAnySelectionMayBeConnected(t *testing.T) {
	v := panel(t, rec(t, map[string]any{"selection": map[string]any{"source": "seed", "outcome": nil}, "request_id": nil, "requested_server": nil}),
		map[string]any{}, "", "")
	if v.State != "ok" || reasonsOf(v) != "no-selection" {
		t.Errorf("%+v", v)
	}
	// Records that name no source at all are the same.
	v = panel(t, rec(t, map[string]any{"selection": map[string]any{}, "request_id": nil, "requested_server": nil}), map[string]any{}, "", "")
	if v.State != "ok" || reasonsOf(v) != "no-selection" {
		t.Errorf("no source: %+v", v)
	}
}

// Legacy (0.6) records -----------------------------------------------------------------------

func legacyRecord(changes map[string]any) map[string]any {
	m := map[string]any{"status": "ok", "checked_at": at(5), "server": host, "requested_server": host,
		"request_id": requestIDHex, "routing_ok": true, "netbird_native": true, "exit_confirmed": true,
		"egress_tier": "provider", "provider": "mullvad"}
	for k, v := range changes {
		if s, ok := v.(string); ok && s == "\x00absent" {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

func TestTheLegacyTruthTable(t *testing.T) {
	absent := "\x00absent"
	for i, tc := range []struct {
		changes map[string]any
		state   string
	}{
		{nil, "ok"}, {map[string]any{"status": "failed"}, "failed"}, {map[string]any{"status": "applying"}, "applying"},
		{map[string]any{"status": "weird"}, "unknown"}, {map[string]any{"routing_ok": false}, "failed"},
		{map[string]any{"routing_ok": nil}, "failed"}, {map[string]any{"netbird_native": false}, "failed"},
		{map[string]any{"netbird_native": nil}, "failed"}, {map[string]any{"exit_confirmed": false}, "failed"},
		// Results written before the NetBird check and before exit_confirmed.
		{map[string]any{"netbird_native": absent}, "ok"},
		{map[string]any{"exit_confirmed": absent, "mullvad_exit_ip": true}, "ok"},
		// An explicit false confirmation overrides a historical true field.
		{map[string]any{"exit_confirmed": false, "mullvad_exit_ip": true}, "failed"},
		{map[string]any{"provider": absent}, "ok"}, {map[string]any{"provider": "pia"}, "unknown"},
		{map[string]any{"server": other}, "failed"}, {map[string]any{"checked_at": at(151)}, "unknown"},
	} {
		v := pm(t, legacyRecord(tc.changes))
		if v.State != tc.state {
			t.Errorf("case %d %v: %+v", i, tc.changes, v)
		}
		if !(v.Schema == 1 || tc.state == "unknown") {
			t.Errorf("case %d: schema %d", i, v.Schema)
		}
		if len(v.Checks) > 0 {
			// Never shown as passed: not reported individually.
			if v.Checks.Get("routing") != "legacy" || v.Checks.Get("app_attachment") != "n/a" {
				t.Errorf("case %d: %v", i, v.Checks)
			}
		}
	}
	if v := pm(t, legacyRecord(map[string]any{"server": other})); !strings.Contains(reasonsOf(v), "not-requested-server") {
		t.Errorf("%+v", v)
	}
}

func TestALegacyTunnelTierCountsOnlyForATunnelTierProvider(t *testing.T) {
	result := legacyRecord(map[string]any{"exit_confirmed": false, "egress_tier": "tunnel", "provider": "gluetun-ivpn",
		"server": gluetunHost, "requested_server": gluetunHost})
	if v := panel(t, result, request(gluetunHost), "gluetun-ivpn", ""); v.State != "ok" || v.Tier != "tunnel" {
		t.Errorf("%+v", v)
	}
	if v := pm(t, legacyRecord(map[string]any{"exit_confirmed": false, "egress_tier": "tunnel"})); v.State != "failed" {
		t.Errorf("%+v", v)
	}
}

func TestALegacyRecordUnderASidecarIsAMismatch(t *testing.T) {
	result := legacyRecord(map[string]any{"provider": "gluetun-nordvpn", "server": gluetunHost, "requested_server": gluetunHost})
	if v := sidecarVerdict(t, result); v.Label != "kind mismatch" {
		t.Errorf("%+v", v)
	}
}

func TestAConfiguredLockHoldsWhenTheRecordIsStale(t *testing.T) {
	v := pm(t, rec(t, map[string]any{"configured_server": host, "checked_at": at(3600)}))
	if v.State != "unknown" || v.ConfiguredServer != host {
		t.Errorf("%+v", v)
	}
}

func TestNothingReadableIsAwaitingStatus(t *testing.T) {
	for _, result := range []any{nil, []any{}, "ok", int64(3)} {
		if v := panel(t, result, nil, "", ""); v.Label != "awaiting status" || reasonsOf(v) != "no-status" {
			t.Errorf("%#v: %+v", result, v)
		}
	}
}

// The deprecated 0.6 projection ----------------------------------------------------------------

func TestTheProjectionDerivesTheOldFieldsFromTheVerdict(t *testing.T) {
	result := settle(t, rec(t, nil))
	p, ok := LegacyProjection(result, pm(t, result))
	raw, _ := validate.MarshalJSON(p)
	if !ok || string(raw) != `{"routing_ok": true, "netbird_native": true, "exit_confirmed": true, "egress_tier": null, "handshake_age_s": 12, "unreachable_fallback": true}` {
		t.Errorf("%s", raw)
	}
	sc := settle(t, sidecar(t, nil))
	p, ok = LegacyProjection(sc, sidecarVerdict(t, sc))
	if !ok || p.RoutingOK != nil || p.NetbirdNative != nil || p.UnreachableFallback != nil || p.ExitConfirmed == nil || !*p.ExitConfirmed {
		t.Errorf("%+v", p)
	}
	old := settle(t, legacyRecord(nil))
	if _, ok := LegacyProjection(old, pm(t, old)); ok {
		t.Error("a legacy record has no projection")
	}
	// A tunnel-tier egress is "not provider confirmed" with its tier named.
	ivpn := settle(t, record(t, opts{provider: "gluetun-ivpn", server: gluetunHost, tier: "tunnel", families: []string{"4"}}, nil))
	p, _ = LegacyProjection(ivpn, panel(t, ivpn, request(gluetunHost), "gluetun-ivpn", ""))
	if p.ExitConfirmed == nil || *p.ExitConfirmed || p.EgressTier == nil || *p.EgressTier != "tunnel" {
		t.Errorf("%+v", p)
	}
	// A failed handshake keeps its age; an unmeasured one has none.
	failed := withCheck(rec(t, map[string]any{"status": "failed"}), "handshake", map[string]any{"state": "fail", "age_s": 700})
	fr := settle(t, failed)
	if p, _ := LegacyProjection(fr, pm(t, fr)); p.HandshakeAgeS != int64(700) {
		t.Errorf("%+v", p)
	}
}

func TestTheRequestTokenIsTheAcknowledgement(t *testing.T) {
	r, ok := state.DesiredRequest(request(host), "mullvad")
	if !ok || rec(t, nil)["request_id"] != state.RequestToken(r) {
		t.Errorf("%+v", r)
	}
}

func TestVerdictJSON(t *testing.T) {
	v := pm(t, rec(t, nil))
	raw, err := validate.MarshalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"state": "ok", "label": "connected", "reasons": [], "message": null, "tier": "provider", "checks": {"app_attachment": "n/a", ` +
		`"routing": "pass", "netbird": "pass", "owner_record": "pass", "peer": "pass", "handshake": "pass", "egress": "pass", ` +
		`"traffic_protection": "pass"}, "schema": 2, "kind": "overlay", "configured_server": null, "next_action": null, "next_action_at": null}`
	if string(raw) != want {
		t.Errorf("\n got %s\nwant %s", raw, want)
	}
	raw, _ = validate.MarshalJSON(Verdict{State: "unknown", Label: "x"})
	if string(raw) != `{"state": "unknown", "label": "x", "reasons": [], "message": null, "tier": null, "checks": {}, "schema": null, "kind": null, "configured_server": null, "next_action": null, "next_action_at": null}` {
		t.Errorf("%s", raw)
	}
}

func TestChecksOrderFollowsPython(t *testing.T) {
	if got := fmt.Sprint(FixedChecks("overlay", "native")); got != "[{app_attachment n/a}]" {
		t.Error(got)
	}
	if got := fmt.Sprint(FixedChecks("overlay", "gluetun")); got != "[{app_attachment n/a} {owner_record n/a}]" {
		t.Error(got)
	}
	if got := FixedChecks("sidecar", "gluetun").Map(); len(got) != 5 || got["traffic_protection"] != "not-checked" {
		t.Error(got)
	}
	if strings.Join(RequiredChecks("overlay", "native"), ",") != "routing,netbird,owner_record,peer,handshake,egress,traffic_protection" ||
		strings.Join(RequiredChecks("overlay", "gluetun"), ",") != "routing,netbird,peer,handshake,egress,traffic_protection" ||
		strings.Join(RequiredChecks("sidecar", "gluetun"), ",") != "peer,handshake,egress" {
		t.Error("required checks")
	}
	if BackendOf("mullvad") != "native" || BackendOf("gluetun-ivpn") != "gluetun" || BackendOf("nope") != "native" {
		t.Error("BackendOf")
	}
}

// -- status_view ---------------------------------------------------------------------------------

func TestStatusNeverTrustsOldInvalidOrFutureChecks(t *testing.T) {
	// tools/test_runtime.py test_status_never_trusts_old_invalid_or_future_checks
	for _, when := range []any{at(151), at(-3600), "broken", nil} {
		result := map[string]any{"status": "ok", "checked_at": when, "routing_ok": true, "mullvad_exit_ip": true}
		if s, _ := StatusView(nil, settle(t, result), "mullvad", "", now); s != "unknown" {
			t.Errorf("%v: %s", when, s)
		}
	}
}

func TestStatusRequiresRoutingAndRequestAck(t *testing.T) {
	// tools/test_runtime.py test_status_requires_routing_and_request_ack
	req := map[string]any{"server": host, "requested_at": validate.FormatTime(now), "request_id": strings.Repeat("0", 32)}
	token := strings.Repeat("0", 32)
	result := map[string]any{"status": "ok", "checked_at": validate.FormatTime(now), "routing_ok": false, "mullvad_exit_ip": true,
		"request_id": token, "server": host, "requested_server": host}
	view := func(r map[string]any, d any) string {
		s, _ := StatusView(settle(t, d), settle(t, r), "mullvad", "", now)
		return s
	}
	if view(result, req) != "failed" {
		t.Error("routing false")
	}
	result["routing_ok"] = true
	if view(result, req) != "ok" {
		t.Error("routing true")
	}
	// The acknowledged request must also be the server the record reports.
	changed := map[string]any{}
	for k, v := range result {
		changed[k] = v
	}
	changed["server"] = other
	if view(changed, req) != "failed" {
		t.Error("another server")
	}
	req["request_id"] = strings.Repeat("1", 32)
	if view(result, req) != "applying" {
		t.Error("unacknowledged")
	}
	req["requested_at"] = at(151)
	if view(result, req) != "unknown" {
		t.Error("old request")
	}
}

func TestStatusUsesTheGenericConfirmation(t *testing.T) {
	// tools/test_pia.py test_status_uses_the_generic_confirmation
	desired := map[string]any{"server": "ex_example", "requested_at": validate.FormatTime(now), "request_id": strings.Repeat("1", 32)}
	result := map[string]any{"checked_at": validate.FormatTime(now), "request_id": strings.Repeat("1", 32), "status": "ok", "routing_ok": true,
		"server": "ex_example", "requested_server": "ex_example"}
	view := func(changes map[string]any) string {
		m := map[string]any{}
		for k, v := range result {
			m[k] = v
		}
		for k, v := range changes {
			m[k] = v
		}
		s, _ := StatusView(settle(t, desired), settle(t, m), "pia", "", now)
		return s
	}
	if view(map[string]any{"exit_confirmed": true}) != "ok" {
		t.Error("confirmed")
	}
	if view(map[string]any{"exit_confirmed": false, "mullvad_exit_ip": true}) != "failed" {
		t.Error("the Mullvad field must not confirm PIA")
	}
}

func TestTunnelTierCountsOnlyForAProviderWithoutItsOwnCheck(t *testing.T) {
	// tools/test_egress.py test_tunnel_tier_counts_only_for_a_provider_without_its_own_check
	spec := providers.Clone("mullvad")
	spec.ID, spec.Label, spec.EgressTier = "tunnelvpn", "Tunnel Example", providers.TierTunnel
	defer providers.Replace(spec)()
	okResult := func(changes map[string]any) map[string]any {
		m := map[string]any{"status": "ok", "checked_at": validate.FormatTime(now), "routing_ok": true, "netbird_native": true,
			"server": host, "exit_confirmed": false, "egress_tier": "tunnel"}
		for k, v := range changes {
			m[k] = v
		}
		return m
	}
	view := func(result map[string]any, provider string) [2]string {
		s, l := StatusView(nil, settle(t, result), provider, "", now)
		return [2]string{s, l}
	}
	if got := view(okResult(nil), "tunnelvpn"); got != [2]string{"ok", "connected"} {
		t.Errorf("%v", got)
	}
	for _, provider := range []string{"mullvad", "pia"} {
		if got := view(okResult(nil), provider); got != [2]string{"failed", "verification failed"} {
			t.Errorf("%s: %v", provider, got)
		}
	}
	for _, tier := range []any{nil, "TUNNEL"} {
		if got := view(okResult(map[string]any{"egress_tier": tier}), "tunnelvpn"); got != [2]string{"failed", "verification failed"} {
			t.Errorf("tier %v: %v", tier, got)
		}
	}
	if got := view(okResult(nil), "examplevpn"); got != [2]string{"unknown", "unknown provider"} {
		t.Errorf("%v", got)
	}
	for _, provider := range []string{"mullvad", "pia", "tunnelvpn"} {
		if got := view(okResult(map[string]any{"exit_confirmed": true, "egress_tier": "provider"}), provider); got != [2]string{"ok", "connected"} {
			t.Errorf("%s: %v", provider, got)
		}
	}
	// A kind the provider can't have is an unknown provider too, as in Python.
	if s, l := StatusView(nil, nil, "mullvad", "sidecar", now); s != "unknown" || l != "unknown provider" {
		t.Errorf("%s %s", s, l)
	}
}

// -- the owner_record lease deadline (decision D7) ---------------------------------------------------

func ownerWith(t testing.TB, fields map[string]any) Verdict {
	return pm(t, withCheck(rec(t, nil), "owner_record", fields))
}

func TestOwnerRecordExpiresAt(t *testing.T) {
	// Absent: the 0.7.0 behavior, whatever the age within the evidence window.
	if v := ownerWith(t, nil); v.State != "ok" {
		t.Errorf("absent: %+v", v)
	}
	// In the future: no effect.
	for _, secs := range []int{-1, -2, -30, -3600} {
		if v := ownerWith(t, map[string]any{"expires_at": at(secs)}); v.State != "ok" || v.Checks.Get("owner_record") != "pass" {
			t.Errorf("expires %ds from now: %+v", -secs, v)
		}
	}
	// Reached or in the past: the check fails, the exit is failed.
	for _, secs := range []int{0, 1, 5, 149, 3600} {
		v := ownerWith(t, map[string]any{"expires_at": at(secs)})
		if v.State != "failed" || v.Label != "failed" || v.Checks.Get("owner_record") != "fail" || reasonsOf(v) != "owner_record-failed" {
			t.Errorf("expired %ds ago: %+v", secs, v)
		}
		// The other checks keep their own evidence.
		if v.Checks.Get("routing") != "pass" || v.Checks.Get("egress") != "pass" {
			t.Errorf("expired %ds ago: %v", secs, v.Checks)
		}
	}
	// Malformed: the check fails.
	for name, bad := range map[string]any{"null": nil, "number": 1760184000, "text": "soon", "no zone": "2026-10-11T12:00:30",
		"offset": "2026-10-11T12:00:30+00:00", "spaced": " 2026-10-11T12:00:30Z", "trailing newline": "2026-10-11T12:00:30Z\n",
		"impossible date": "2026-02-30T12:00:30Z", "list": []any{}, "bool": true, "short": "2026-10-11T12:00:30"[:10]} {
		v := ownerWith(t, map[string]any{"expires_at": bad})
		if v.State != "failed" || v.Checks.Get("owner_record") != "fail" || reasonsOf(v) != "owner_record-failed" {
			t.Errorf("%s: %+v", name, v)
		}
	}
	// The deadline never extends: stale evidence stays stale whatever it says.
	v := ownerWith(t, map[string]any{"at": at(151), "expires_at": at(-3600)})
	if v.State != "unknown" || v.Label != "evidence expired" || v.Checks.Get("owner_record") != "unknown" {
		t.Errorf("stale evidence extended: %+v", v)
	}
	// A deadline in the past fails even when the evidence is fresh, and when it is
	// stale the evidence rule comes first.
	v = ownerWith(t, map[string]any{"at": at(151), "expires_at": at(10)})
	if v.State != "unknown" || v.Checks.Get("owner_record") != "unknown" {
		t.Errorf("stale and expired: %+v", v)
	}
	// An already failed check stays failed, with or without a deadline.
	v = pm(t, withCheck(rec(t, map[string]any{"status": "failed"}), "owner_record", map[string]any{"state": "fail", "expires_at": at(-3600)}))
	if v.State != "failed" || reasonsOf(v) != "owner_record-failed" {
		t.Errorf("failed check: %+v", v)
	}
	// An unmeasured check is unmeasured; its deadline is not looked at.
	v = pm(t, withCheck(rec(t, map[string]any{"status": "unknown"}), "owner_record", map[string]any{"state": "unknown", "expires_at": "soon"}))
	if v.State != "unknown" || v.Label != "not yet measured" {
		t.Errorf("unmeasured: %+v", v)
	}
	// The same lapse makes a failed record that the traffic_protection rule would
	// otherwise judge only on routing.
	if v := ownerWith(t, map[string]any{"expires_at": at(0)}); v.Checks.Get("traffic_protection") != "pass" {
		t.Errorf("traffic protection follows routing, not the owner: %v", v.Checks)
	}
}

func TestOwnerRecordExpiresAtOnlyConcernsNativeOverlayExits(t *testing.T) {
	// A gluetun overlay and a sidecar keep owner_record "n/a"; a deadline there is ignored.
	for _, key := range []string{"gluetun-overlay", "sidecar"} {
		var result map[string]any
		var v Verdict
		if key == "sidecar" {
			result = sidecar(t, nil)
			result["checks"].(map[string]any)["owner_record"] = map[string]any{"state": "n/a", "expires_at": "soon"}
			v = sidecarVerdict(t, result)
		} else {
			result = record(t, opts{provider: "gluetun-nordvpn", server: gluetunHost, families: []string{"4"}}, nil)
			result["checks"].(map[string]any)["owner_record"] = map[string]any{"state": "n/a", "expires_at": at(10)}
			v = panel(t, result, request(gluetunHost), "gluetun-nordvpn", "")
		}
		if v.State != "ok" || v.Checks.Get("owner_record") != "n/a" {
			t.Errorf("%s: %+v", key, v)
		}
	}
}

func TestOwnerRecordExpiresAtThroughTheJSONReader(t *testing.T) {
	// The record as the supervisor writes it: decoded from JSON text, so the
	// deadline is a string the way the file has it.
	check := fmt.Sprintf(`{"state": "pass", "at": %q, "expires_at": %q}`, at(2), at(-28))
	body := rec(t, nil)
	text, _ := validate.MarshalJSON(body)
	decodedRecord, err := validate.DecodeJSON([]byte(strings.Replace(string(text), `"owner_record": {"at": "`+at(5)+`", "state": "pass"}`, `"owner_record": `+check, 1)))
	if err != nil {
		t.Fatal(err)
	}
	exit, _ := NewExitConfig("mullvad", "overlay", "")
	v := Assess(exit, decodedRecord, TargetForPanel(decodedRecord, request(host), "mullvad"), now)
	if v.State != "ok" || v.Checks.Get("owner_record") != "pass" {
		t.Fatalf("%+v", v)
	}
	// 30 seconds later the lease is over and the record is not yet stale.
	v = Assess(exit, decodedRecord, TargetForPanel(decodedRecord, request(host), "mullvad"), now.Add(30*time.Second))
	if v.State != "failed" || reasonsOf(v) != "owner_record-failed" {
		t.Errorf("%+v", v)
	}
}

func FuzzAssess(f *testing.F) {
	f.Add([]byte(`{"schema": 2}`))
	good, _ := validate.MarshalJSON(rec(f, nil))
	f.Add(good)
	f.Add([]byte(`{"status": "ok", "checked_at": "2026-10-11T11:59:55Z"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		result, err := validate.DecodeJSON(data)
		if err != nil {
			return
		}
		for _, provider := range []string{"mullvad", "gluetun-ivpn"} {
			for _, kind := range []string{"overlay", "sidecar"} {
				exit, err := NewExitConfig(provider, kind, "")
				if err != nil {
					continue
				}
				v := Assess(exit, result, TargetForPanel(result, request(host), provider), now)
				if v.State == "ok" && (v.Label != "connected" || v.Schema == 0) {
					t.Fatalf("%+v", v)
				}
				// A connected exit has every required check passing.
				if v.State == "ok" && v.Schema == 2 {
					for _, name := range RequiredChecks(exit.Kind, exit.Backend()) {
						if v.Checks.Get(name) != "pass" {
							t.Fatalf("connected with %s=%s", name, v.Checks.Get(name))
						}
					}
				}
				if _, err := validate.MarshalJSON(v); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}
