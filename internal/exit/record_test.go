package exit

import (
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

func settingsFor(kind contract.Kind, backend contract.Backend, provider string) *Settings {
	s := &Settings{Provider: provider, Env: map[string]string{}}
	s.Routing.Kind, s.Routing.Backend = kind, backend
	return s
}

// okRecord is a healthy record for the settings' kind, fresh at now, as the
// pipeline would publish it with the supervisor's owner_record in place.
func okRecord(s *Settings, now time.Time) map[string]any {
	at := validate.FormatTime(now)
	server := "se-sto-wg-001"
	tier := "provider"
	if spec, _ := verdict.NewExitConfig(s.Provider, s.Kind(), ""); spec.Spec() != nil && spec.Spec().EgressTier == "tunnel" {
		tier = "tunnel"
	}
	checks := validate.Members(
		"routing", validate.Members("state", "pass", "at", at, "fallback", true),
		"netbird", validate.Members("state", "pass", "at", at),
		"owner_record", validate.Members("state", "pass", "at", at, "expires_at", validate.FormatTime(now.Add(20*time.Second))),
		"peer", validate.Members("state", "pass", "at", at, "server", server),
		"handshake", validate.Members("state", "pass", "at", at, "server", server, "age_s", 4),
		"egress", validate.Members("state", "pass", "at", at, "server", server, "tier", tier,
			"expected_families", []any{"4"}, "families", validate.Members("4", "pass")),
		"traffic_protection", validate.Members("state", "pass", "at", at, "from", "routing"),
		"app_attachment", validate.Members("state", "n/a"))
	if s.Kind() == "sidecar" {
		checks = validate.Members(
			"routing", validate.Members("state", "n/a"), "netbird", validate.Members("state", "n/a"),
			"owner_record", validate.Members("state", "n/a"),
			"peer", validate.Members("state", "pass", "at", at, "server", server),
			"handshake", validate.Members("state", "pass", "at", at, "server", server, "age_s", 4),
			"egress", validate.Members("state", "pass", "at", at, "server", server, "tier", tier,
				"expected_families", []any{"4"}, "families", validate.Members("4", "pass")),
			"traffic_protection", validate.Members("state", "not-checked", "by", "gluetun's firewall"),
			"app_attachment", validate.Members("state", "not-checked", "by", "the host doctor"))
	} else if s.BackendName() == "gluetun" {
		checks = checks.Set("owner_record", validate.Members("state", "n/a"))
	}
	return toMap(validate.Members(
		"schema", 2, "kind", s.Kind(), "backend", s.BackendName(), "provider", s.Provider,
		"status", "ok", "message", "Healthy.", "checked_at", at, "server", server,
		"requested_server", nil, "configured_server", nil, "request_id", nil,
		"selection", validate.Members("source", "seed", "outcome", nil, "attempt", 0, "target", nil, "next_action", nil, "next_action_at", nil),
		"checks", checks, "egress_ip", "203.0.113.9", "egress_ips", validate.Members("4", "203.0.113.9"),
		"egress_city", nil, "egress_country", nil))
}

type branch struct {
	name     string
	s        *Settings
	failed   []string // checks the failure record must fail
	unknown  []string // checks it must mark unknown
	reasons  []string // reasons of the verdict
	wantNote string
}

func branches() []branch {
	return []branch{
		{"native overlay", settingsFor("overlay", "wireguard", "mullvad"),
			[]string{"owner_record", "routing", "netbird", "traffic_protection"}, nil,
			[]string{"routing-failed", "netbird-failed", "owner_record-failed", "traffic_protection-failed"}, ""},
		{"gluetun overlay", settingsFor("overlay", "gluetun", "gluetun-mullvad"),
			[]string{"routing", "netbird", "traffic_protection"}, nil,
			[]string{"routing-failed", "netbird-failed", "traffic_protection-failed"}, ""},
		{"sidecar", settingsFor("sidecar", "gluetun", "gluetun-mullvad"),
			nil, []string{"peer", "handshake", "egress"}, []string{"status-failed"}, ""},
	}
}

func assess(t *testing.T, s *Settings, rec map[string]any, target verdict.Target, now time.Time) verdict.Verdict {
	t.Helper()
	cfg, err := verdict.NewExitConfig(s.Provider, s.Kind(), "")
	if err != nil {
		t.Fatal(err)
	}
	// Through the file format: the reader sees encoded JSON.
	raw, err := validate.MarshalJSON(verdict.OrderRecord(rec, s.Kind(), s.BackendName()))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := validate.DecodeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return verdict.Assess(cfg, decoded, target, now)
}

func TestTheHealthyFixturesAreConnected(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	for _, b := range branches() {
		v := assess(t, b.s, okRecord(b.s, now), verdict.Target{}, now)
		if v.State != "ok" {
			t.Errorf("%s: %+v", b.name, v)
		}
	}
}

func TestFailureRecordThroughAssess(t *testing.T) {
	start := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	lapse := start.Add(40 * time.Second) // the last evidence is 40 s old
	for _, b := range branches() {
		t.Run(b.name, func(t *testing.T) {
			prev := okRecord(b.s, start)
			failure := FailureRecord(prev, b.s, lapse)

			// Fresh: failed within the lapse time, not after the 150-second window.
			v := assess(t, b.s, failure, verdict.Target{}, lapse.Add(time.Second))
			if v.State != "failed" {
				t.Fatalf("fresh: %+v", v)
			}
			for _, r := range b.reasons {
				found := false
				for _, got := range v.Reasons {
					found = found || got == r
				}
				if !found {
					t.Errorf("reasons %v lack %s", v.Reasons, r)
				}
			}
			// The record's own fields.
			if failure["status"] != "failed" || failure["message"] != OwnerStoppedMessage || failure["checked_at"] != validate.FormatTime(lapse) {
				t.Errorf("header: %v %v %v", failure["status"], failure["message"], failure["checked_at"])
			}
			checks := failure["checks"].(map[string]any)
			for _, name := range b.failed {
				c := checks[name].(map[string]any)
				if c["state"] != "fail" || c["at"] != validate.FormatTime(lapse) {
					t.Errorf("%s: %v", name, c)
				}
				if _, ok := c["expires_at"]; ok {
					t.Errorf("%s keeps an expiry", name)
				}
			}
			for _, name := range b.unknown {
				if c := checks[name].(map[string]any); c["state"] != "unknown" || len(c) != 1 {
					t.Errorf("%s: %v", name, c)
				}
			}
			// Unrelated checks keep their earlier evidence times.
			prevChecks := prev["checks"].(map[string]any)
			for _, name := range []string{"peer", "handshake", "egress"} {
				if len(b.unknown) > 0 {
					break
				}
				if checks[name].(map[string]any)["at"] != prevChecks[name].(map[string]any)["at"] {
					t.Errorf("%s: its evidence time changed", name)
				}
			}
			if b.s.BackendName() == "gluetun" && b.s.Kind() == "overlay" && checks["owner_record"].(map[string]any)["state"] != "n/a" {
				t.Errorf("gluetun keeps owner_record n/a: %v", checks["owner_record"])
			}
			if b.s.Kind() == "sidecar" {
				for _, name := range []string{"routing", "netbird", "owner_record"} {
					if checks[name].(map[string]any)["state"] != "n/a" {
						t.Errorf("sidecar fixed field %s: %v", name, checks[name])
					}
				}
			}
			if failure["selection"].(map[string]any)["source"] != "seed" || failure["server"] != prev["server"] {
				t.Error("selection and server are kept")
			}

			// Expired: past the readers' window the record is simply stale.
			v = assess(t, b.s, failure, verdict.Target{}, lapse.Add(151*time.Second))
			if v.State != "unknown" || v.Reasons[0] != "status-stale" {
				t.Errorf("expired: %+v", v)
			}

			// An unacknowledged panel request still shows as applying, today's
			// documented behavior.
			req := state.Request{Server: "se-sto-wg-002", RequestedAt: validate.FormatTime(lapse), RequestID: strings.Repeat("a", 32)}
			target := verdict.Target{Server: req.Server, Source: "panel", Request: &req}
			v = assess(t, b.s, failure, target, lapse.Add(time.Second))
			if v.State != "applying" || v.Reasons[0] != "request-pending" {
				t.Errorf("unacknowledged: %+v", v)
			}
			// An acknowledged one does not hide the failure.
			failure2 := map[string]any{}
			for k, x := range failure {
				failure2[k] = x
			}
			failure2["request_id"] = req.RequestID
			failure2["requested_server"] = req.Server
			v = assess(t, b.s, failure2, target, lapse.Add(time.Second))
			if v.State != "failed" {
				t.Errorf("acknowledged request: %+v", v)
			}
		})
	}
}

func TestFailureRecordKeepsTheTunnelTier(t *testing.T) {
	// A tunnel-tier record (the gluetun providers without a stronger check)
	// that was connected is failed, not "connected", once the lease lapses.
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	for _, s := range []*Settings{settingsFor("overlay", "gluetun", "gluetun-surfshark")} {
		prev := okRecord(s, now)
		if prev["checks"].(map[string]any)["egress"].(map[string]any)["tier"] != "tunnel" {
			t.Fatal("the fixture should be tunnel tier")
		}
		if v := assess(t, s, prev, verdict.Target{}, now); v.State != "ok" || v.Tier != "tunnel" {
			t.Fatalf("%s before: %+v", s.Kind(), v)
		}
		v := assess(t, s, FailureRecord(prev, s, now.Add(time.Minute)), verdict.Target{}, now.Add(time.Minute))
		if v.State != "failed" {
			t.Errorf("%s after: %+v", s.Kind(), v)
		}
	}
}

func TestFailureRecordFromNothing(t *testing.T) {
	s := settingsFor("overlay", "wireguard", "mullvad")
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	v := assess(t, s, FailureRecord(nil, s, now), verdict.Target{}, now)
	if v.State != "failed" {
		t.Fatalf("%+v", v)
	}
}

func TestStartingRecord(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	for _, b := range branches() {
		s := b.s
		s.Server = "se-sto-wg-001"
		rec := StartingRecord(s, now)
		if rec["status"] != "unknown" || rec["message"] != "Applier starting; waiting for verification." || rec["configured_server"] != "se-sto-wg-001" {
			t.Errorf("%s: %v", b.name, rec)
		}
		v := assess(t, s, rec, verdict.Target{}, now)
		if v.State != "unknown" {
			t.Errorf("%s: %+v", b.name, v)
		}
		for _, name := range verdict.RequiredChecks(s.Kind(), s.BackendName()) {
			if rec["checks"].(map[string]any)[name].(map[string]any)["state"] != "unknown" {
				t.Errorf("%s: %s is measured", b.name, name)
			}
		}
	}
}

func TestNetBirdHeldRecordFailsNamingTheReason(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	refusal := "the stored NetBird profile /var/lib/netbird/default.json does not exclude the tunnel interface wg0 " +
		"from NetBird's connection candidates; example"
	for _, b := range branches()[:2] {
		t.Run(b.name, func(t *testing.T) {
			rec := NetBirdHeldRecord(b.s, now, refusal)
			if rec["status"] != "failed" || rec["message"] != refusal {
				t.Fatalf("%v %q", rec["status"], rec["message"])
			}
			v := assess(t, b.s, rec, verdict.Target{}, now.Add(time.Second))
			if v.State != "failed" || v.Message == nil || *v.Message != refusal ||
				len(v.Reasons) != 1 || v.Reasons[0] != "netbird-failed" {
				t.Errorf("%+v", v)
			}
		})
	}
	// Bounded, and valid text whatever the error carried.
	s := settingsFor("overlay", "wireguard", "mullvad")
	rec := NetBirdHeldRecord(s, now, strings.Repeat("é", 1000)+"\xff")
	if m := rec["message"].(string); len([]rune(m)) != 900 || !strings.HasPrefix(m, "éé") {
		t.Errorf("%d runes", len([]rune(m)))
	}
}

func TestOwnerCheckAndOrdering(t *testing.T) {
	now := time.Date(2026, 10, 12, 12, 0, 0, 900_000_000, time.UTC)
	exp := now.Add(5*time.Second + 500*time.Millisecond) // 12:00:06.4
	c := toMap(OwnerCheck(true, now, exp))
	if c["state"] != "pass" || c["at"] != "2026-10-12T12:00:00Z" || c["expires_at"] != "2026-10-12T12:00:06Z" {
		t.Errorf("%v", c)
	}
	if c := toMap(OwnerCheck(false, now, exp)); c["state"] != "fail" || c["expires_at"] != nil {
		t.Errorf("%v", c)
	}
	s := settingsFor("overlay", "wireguard", "mullvad")
	raw, _ := validate.MarshalJSON(verdict.OrderRecord(okRecord(s, now), "overlay", "native"))
	text := string(raw)
	if !strings.HasPrefix(text, `{"schema": 2, "kind": "overlay", "backend": "native", "provider": "mullvad", "status": "ok"`) {
		t.Errorf("record order: %.120s", text)
	}
	if i, j := strings.Index(text, `"routing"`), strings.Index(text, `"app_attachment"`); i < 0 || j < i {
		t.Errorf("check order")
	}
}
