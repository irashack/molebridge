package proxy

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

var tunnelNow = time.Date(2026, 11, 19, 18, 0, 0, 0, time.UTC)

// healthyRecord is a native Mullvad exit's result.json with every check
// passed, as of checkedAt.
func healthyRecord(checkedAt string) string {
	at := checkedAt
	return `{"schema": 2, "kind": "overlay", "backend": "native", "provider": "mullvad", "status": "ok",
  "message": "Healthy.", "checked_at": "` + at + `", "server": "se-got-wg-001", "requested_server": null,
  "configured_server": null, "request_id": null,
  "selection": {"source": "restore", "outcome": "verified", "attempt": 1, "target": "se-got-wg-001", "next_action": null, "next_action_at": null},
  "checks": {"routing": {"state": "pass", "at": "` + at + `"}, "netbird": {"state": "pass", "at": "` + at + `"},
    "owner_record": {"state": "pass", "at": "` + at + `"},
    "peer": {"state": "pass", "at": "` + at + `", "server": "se-got-wg-001"},
    "handshake": {"state": "pass", "at": "` + at + `", "server": "se-got-wg-001", "age_s": 12},
    "egress": {"state": "pass", "at": "` + at + `", "server": "se-got-wg-001", "tier": "provider", "expected_families": ["4"], "families": {"4": "pass"}},
    "traffic_protection": {"state": "pass", "at": "` + at + `", "from": "routing"},
    "app_attachment": {"state": "n/a"}},
  "egress_ip": "203.0.113.7", "egress_ips": {"4": "203.0.113.7"}}`
}

func decode(t *testing.T, raw string) any {
	t.Helper()
	v, err := validate.DecodeJSONString(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTunnelFromResult(t *testing.T) {
	exit, err := verdict.NewExitConfig("mullvad", "", "")
	if err != nil {
		t.Fatal(err)
	}
	fresh := validate.FormatTime(tunnelNow.Add(-5 * time.Second))
	got := TunnelFromResult(exit, decode(t, healthyRecord(fresh)), tunnelNow)
	if got != (TunnelState{Verdict: "ok", Server: "se-got-wg-001", CheckedAt: fresh}) {
		t.Fatalf("%+v", got)
	}
	// The verdict is the exit's, unchanged: stale, missing, another kind.
	stale := validate.FormatTime(tunnelNow.Add(-10 * time.Minute))
	if got := TunnelFromResult(exit, decode(t, healthyRecord(stale)), tunnelNow); got.Verdict != "unknown" || got.CheckedAt != stale {
		t.Fatalf("%+v", got)
	}
	if got := TunnelFromResult(exit, nil, tunnelNow); got != (TunnelState{Verdict: "unknown"}) {
		t.Fatalf("%+v", got)
	}
	sidecar, _ := verdict.NewExitConfig("mullvad", "sidecar", "")
	if got := TunnelFromResult(sidecar, decode(t, healthyRecord(fresh)), tunnelNow); got.Verdict == "ok" {
		t.Fatalf("an overlay record judged ok for a sidecar: %+v", got)
	}
}

func TestResultGateRereadsOncePerSecond(t *testing.T) {
	exit, _ := verdict.NewExitConfig("mullvad", "overlay", "")
	path := filepath.Join(t.TempDir(), "result.json")
	clock := &fakeClock{t: tunnelNow}
	gate := ResultGate(path, exit, clock.now)
	if got := gate(); got.Verdict != "unknown" {
		t.Fatalf("no file: %+v", got)
	}
	if err := os.WriteFile(path, []byte(healthyRecord(validate.FormatTime(tunnelNow))), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := gate(); got.Verdict != "unknown" {
		t.Fatalf("read again within a second: %+v", got)
	}
	clock.advance(time.Second)
	if got := gate(); got.Verdict != "ok" {
		t.Fatalf("%+v", got)
	}
	// A record with a duplicate key is not read.
	os.WriteFile(path, []byte(`{"schema": 2, "schema": 2}`), 0o644)
	clock.advance(time.Second)
	if got := gate(); got.Verdict != "unknown" {
		t.Fatalf("%+v", got)
	}
}
