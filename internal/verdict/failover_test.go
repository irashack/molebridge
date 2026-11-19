package verdict

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/validate"
)

// Automatic failover (docs/design/failover.md, "The record and the
// verdict"). testdata/failover_golden.json holds a record for each phase as
// the applier writes it, with the verdict this package must give and the one
// a reader from before failover gives.

type failoverCase struct {
	Name   string          `json:"name"`
	Raw    json.RawMessage `json:"record"`
	Record map[string]any  `json:"-"`
	Target string          `json:"target"` // "panel", "configured" or "none"
	Want   struct {
		State   string   `json:"state"`
		Label   string   `json:"label"`
		Reasons []string `json:"reasons"`
	} `json:"want"`
	Old struct {
		State   string   `json:"state"`
		Label   string   `json:"label"`
		Reasons []string `json:"reasons"`
	} `json:"old"`
}

func failoverGolden(t *testing.T) (map[string]any, []failoverCase) {
	t.Helper()
	raw, err := os.ReadFile("testdata/failover_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Desired map[string]any `json:"desired"`
		Cases   []failoverCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) < 10 {
		t.Fatalf("%d cases", len(file.Cases))
	}
	for i := range file.Cases {
		record, err := validate.DecodeJSON(file.Cases[i].Raw)
		if err != nil {
			t.Fatalf("%s: %v", file.Cases[i].Name, err)
		}
		file.Cases[i].Record = record.(map[string]any)
	}
	return file.Desired, file.Cases
}

func judgeCase(t *testing.T, desired map[string]any, c failoverCase) Verdict {
	t.Helper()
	var d any = desired
	if c.Target == "none" {
		d = map[string]any{}
	}
	return panel(t, c.Record, d, "mullvad", "overlay")
}

func TestFailoverGoldenRecords(t *testing.T) {
	desired, cases := failoverGolden(t)
	phases := map[string]bool{}
	for _, c := range cases {
		_, _, phase, _ := Failover(settle(t, c.Record).(map[string]any))
		phases[phase] = true
		v := judgeCase(t, desired, c)
		if v.State != c.Want.State || v.Label != c.Want.Label || !reflect.DeepEqual(v.Reasons, c.Want.Reasons) {
			t.Errorf("%s: got %s/%s %v, want %s/%s %v", c.Name, v.State, v.Label, v.Reasons, c.Want.State, c.Want.Label, c.Want.Reasons)
			continue
		}
		if v.Label == BackupLabel {
			fo := c.Record["failover"].(map[string]any)
			if v.Failover == nil || v.Failover.From != fo["from"] || v.Failover.To != c.Record["server"] ||
				v.Failover.Since != fo["since"] || (fo["next_return_at"] != nil && v.Failover.NextReturnAt != fo["next_return_at"]) {
				t.Errorf("%s: failover view %+v", c.Name, v.Failover)
			}
			found := false
			for _, pair := range v.AsJSON() {
				found = found || (pair.Key == "failover" && pair.Value != nil)
			}
			if !found {
				t.Errorf("%s: the API's verdict has no failover member", c.Name)
			}
		} else if v.Failover != nil {
			t.Errorf("%s: failover view on %s", c.Name, v.Label)
		}
	}
	for _, phase := range FailoverPhases {
		if !phases[phase] {
			t.Errorf("no golden record for phase %q", phase)
		}
	}
}

// TestOldReadersNeverSayConnectedOnABackup judges every golden record with
// the agreement rules as they were before failover (a copy below) and
// requires the verdict recorded for old readers: never connected on a
// backup for a reader with a target of its own. A reader with no target
// holds the record to itself, before failover as now, and is the one case
// that says connected (the proxy; no reader before failover had none).
func TestOldReadersNeverSayConnectedOnABackup(t *testing.T) {
	desired, cases := failoverGolden(t)
	agreement = targetDisagreementBeforeFailover
	defer func() { agreement = targetDisagreement }()
	for _, c := range cases {
		v := judgeCase(t, desired, c)
		// Nor the backup's label and reason, or the exhausted reason: what
		// the old ok branch said is what is left.
		reasons := []string{}
		for _, r := range v.Reasons {
			if r != ReasonFailoverExhausted && r != ReasonFailover {
				reasons = append(reasons, r)
			}
		}
		label := v.Label
		if label == BackupLabel {
			label = "connected"
		}
		if v.State != c.Old.State || label != c.Old.Label || !reflect.DeepEqual(reasons, c.Old.Reasons) {
			t.Errorf("%s: old reader got %s/%s %v, want %s/%s %v", c.Name, v.State, label, reasons, c.Old.State, c.Old.Label, c.Old.Reasons)
		}
		onBackup := c.Record["server"] != c.Record["requested_server"] && c.Record["server"] != c.Record["configured_server"]
		if onBackup && c.Target != "none" && c.Record["status"] == "ok" && v.State != "failed" {
			t.Errorf("%s: an old reader says %s on a backup", c.Name, v.State)
		}
	}
}

// targetDisagreementBeforeFailover is targetDisagreement and movedFrom as
// they were before failover (commit 0c331ff), kept so the test above judges
// with a reader that doesn't know the failover member.
func targetDisagreementBeforeFailover(record map[string]any, target Target, selection map[string]any, configured string, hasConfigured bool) string {
	movedFrom := func(record map[string]any, requested string) bool {
		moved, ok := object(record["moved"])
		if !ok || requested == "" {
			return false
		}
		to, isString := moved["to"].(string)
		return isString && to != "" && moved["from"] == requested && record["server"] == to
	}
	server := record["server"]
	if target.Source == "configured" || hasConfigured {
		expected := configured
		if target.Source == "configured" {
			expected = target.Server
		}
		if server == expected || movedFrom(record, expected) {
			return ""
		}
		return "not-configured-server"
	}
	if target.Source == "panel" {
		if record["requested_server"] == target.Server && (server == target.Server || movedFrom(record, target.Server)) {
			return ""
		}
		return "not-requested-server"
	}
	if target.Server != "" {
		if server == target.Server {
			return ""
		}
		return "not-target-server"
	}
	if source, isString := selection["source"].(string); isString && contains([]string{"restore", "reconverge", "retry", "operator-retry", "failover"}, source) {
		if same(server, selection["target"]) {
			return ""
		}
		return "not-target-server"
	}
	return ""
}

func backupRecord(t *testing.T, changes map[string]any) map[string]any {
	fo := map[string]any{"from": host, "to": other, "phase": "on-backup", "reason": "handshake-failed",
		"since": at(300), "next_return_at": nil, "tried": []any{other}}
	r := record(t, opts{server: other}, map[string]any{"requested_server": host, "failover": fo,
		"selection": map[string]any{"source": "failover", "outcome": "verified", "attempt": 1, "target": other}})
	for k, v := range changes {
		r[k] = v
	}
	return r
}

func TestFailoverAgreesOnlyWithAllFourConditions(t *testing.T) {
	if v := pm(t, backupRecord(t, nil)); v.State != BackupState || v.Label != BackupLabel || reasonsOf(v) != ReasonFailover {
		t.Fatalf("%+v", v)
	}
	member := func(change map[string]any) map[string]any {
		fo := map[string]any{"from": host, "to": other, "phase": "on-backup", "reason": "handshake-failed"}
		for k, v := range change {
			fo[k] = v
		}
		return fo
	}
	for name, changes := range map[string]map[string]any{
		"from another server":   {"failover": member(map[string]any{"from": "se-got-wg-001"})},
		"to another server":     {"failover": member(map[string]any{"to": "se-got-wg-001"})},
		"returning":             {"failover": member(map[string]any{"phase": "returning"})},
		"exhausted":             {"failover": member(map[string]any{"phase": "exhausted"})},
		"an unknown phase":      {"failover": member(map[string]any{"phase": "standby"})},
		"source panel":          {"selection": map[string]any{"source": "panel", "outcome": "verified", "target": other}},
		"source moved":          {"selection": map[string]any{"source": "retry", "outcome": "verified", "target": other}},
		"from missing":          {"failover": member(map[string]any{"from": nil})},
		"not an object":         {"failover": "se-sto-wg-001"},
		"from is the backup":    {"failover": member(map[string]any{"from": other})},
		"no member":             {"failover": nil},
		"another request":       {"requested_server": "se-got-wg-001", "failover": member(map[string]any{"from": "se-got-wg-001"})},
		"moved chain elsewhere": {"failover": member(map[string]any{"from": "se-got-wg-004"}), "moved": map[string]any{"from": "se-got-wg-001", "to": "se-got-wg-004", "reason": "left-catalogue"}},
	} {
		v := pm(t, backupRecord(t, changes))
		want := "not-requested-server"
		if name == "exhausted" {
			want += ",failover-exhausted"
		}
		if v.State != "failed" || reasonsOf(v) != want {
			t.Errorf("%s: %+v", name, v)
		}
	}
}

func TestFailoverAgreesForEveryTarget(t *testing.T) {
	exit := ExitConfig{Provider: "mullvad", Kind: "overlay"}
	configured := backupRecord(t, map[string]any{"configured_server": host, "request_id": nil, "requested_server": nil})
	if v := pm(t, configured); v.State != "ok" || v.Label != BackupLabel {
		t.Errorf("configured, read from the record: %+v", v)
	}
	if v := assess(t, exit, configured, Target{Server: host, Source: "configured"}); v.State != "ok" || v.Label != BackupLabel {
		t.Errorf("configured, the exit's own SERVER: %+v", v)
	}
	if v := assess(t, exit, configured, Target{Server: "se-got-wg-001", Source: "configured"}); v.State != "failed" {
		t.Errorf("configured, another SERVER: %+v", v)
	}
	// The applier's own target is what was asked for, whatever its source.
	if v := assess(t, exit, backupRecord(t, nil), Target{Server: host, Source: "restore"}); v.State != "ok" || v.Label != BackupLabel {
		t.Errorf("resolved target: %+v", v)
	}
	if v := assess(t, exit, backupRecord(t, nil), Target{Server: "se-got-wg-001", Source: "restore"}); v.State != "failed" || reasonsOf(v) != "not-target-server" {
		t.Errorf("resolved target elsewhere: %+v", v)
	}
	// With no target, the record agrees with itself.
	if v := panel(t, backupRecord(t, nil), map[string]any{}, "", ""); v.State != "ok" || v.Label != BackupLabel {
		t.Errorf("no target: %+v", v)
	}
	// The chain request -> moved.to -> failover.to.
	chained := backupRecord(t, map[string]any{"moved": map[string]any{"from": host, "to": "se-sto-wg-004", "reason": "left-catalogue"}})
	chained["failover"].(map[string]any)["from"] = "se-sto-wg-004"
	if v := pm(t, chained); v.State != "ok" || reasonsOf(v) != ReasonFailover {
		t.Errorf("chained: %+v", v)
	}
}

func TestFailoverExhaustedFollowsTheOtherReasons(t *testing.T) {
	r := withCheck(rec(t, map[string]any{"status": "failed",
		"failover": map[string]any{"from": host, "to": nil, "phase": "exhausted", "reason": "handshake-failed"}}),
		"handshake", map[string]any{"state": "fail", "age_s": nil})
	if v := pm(t, r); v.State != "failed" || reasonsOf(v) != "handshake-failed,failover-exhausted" {
		t.Errorf("failed: %+v", v)
	}
	expired := withCheck(rec(t, map[string]any{"failover": map[string]any{"from": host, "to": nil, "phase": "exhausted"}}),
		"peer", map[string]any{"at": at(400)})
	if v := pm(t, expired); v.State != "unknown" || !strings.HasSuffix(reasonsOf(v), ",failover-exhausted") {
		t.Errorf("unknown: %+v", v)
	}
	// Connected on the primary while the hold-down lasts: no such reason.
	ok := rec(t, map[string]any{"failover": map[string]any{"from": host, "to": nil, "phase": "exhausted"}})
	if v := pm(t, ok); v.State != "ok" || strings.Contains(reasonsOf(v), "failover") {
		t.Errorf("ok: %+v", v)
	}
}

func TestFailoverAccessor(t *testing.T) {
	r := settle(t, backupRecord(t, nil)).(map[string]any)
	if from, to, phase, ok := Failover(r); !ok || from != host || to != other || phase != "on-backup" {
		t.Errorf("Failover = %q %q %q %v", from, to, phase, ok)
	}
	if _, _, _, ok := Failover(settle(t, rec(t, nil)).(map[string]any)); ok {
		t.Error("a record without the member")
	}
	r["failover"] = map[string]any{"from": host, "phase": "later"}
	if _, _, _, ok := Failover(r); ok {
		t.Error("an unknown phase")
	}
}

func TestFailoverViewIgnoresMalformedTimes(t *testing.T) {
	r := backupRecord(t, nil)
	r["failover"].(map[string]any)["since"] = "yesterday"
	r["failover"].(map[string]any)["next_return_at"] = 7
	v := pm(t, r)
	if v.Failover == nil || v.Failover.Since != "" || v.Failover.NextReturnAt != "" {
		t.Errorf("%+v", v.Failover)
	}
}
