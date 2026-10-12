// Tests for applier/attempt.py, ported from tools/test_pipeline.py
// (test_deadlines_from_another_boot_are_rebased and
// test_an_unreadable_attempt_starts_idle in full; the resting-states test
// without the applier it restarts) and from tools/test_runtime.py's boot id
// helpers. The rest of those files tests the admission pipeline in
// applier/apply.py, which the applier port carries. The golden file is what
// 0.7.0's Python code wrote (commit d553f25); it is now fixed.
package attempt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/validate"
)

const (
	boot    = "00000000-0000-4000-8000-0000000000aa"
	host    = "se-sto-wg-001"
	zeroKey = "00000000000000000000000000000000"
)

func fp(f float64) *float64 { return &f }

func TestPythonFilesRoundTripByteForByte(t *testing.T) {
	raw, err := os.ReadFile("testdata/saved_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var files []struct {
		Bytes string `json:"bytes"`
		Mode  string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &files); err != nil {
		t.Fatal(err)
	}
	if len(files) < 6 {
		t.Fatalf("%d files", len(files))
	}
	for i, f := range files {
		dir := t.TempDir()
		path := filepath.Join(dir, "applier", "attempt.json")
		os.MkdirAll(filepath.Dir(path), 0o700)
		os.WriteFile(path, []byte(f.Bytes), 0o600)
		// Read on the boot it was written on, so nothing is rebased.
		a := Load(path, bootOf(t, f.Bytes), 0)
		if a.State == "idle" && !strings.Contains(f.Bytes, `"state": "idle"`) {
			t.Errorf("file %d read as idle: %s", i, f.Bytes)
		}
		out := filepath.Join(dir, "again.json")
		if err := a.Save(out); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(out)
		if string(got) != f.Bytes {
			t.Errorf("file %d:\n got %s\nwant %s", i, got, f.Bytes)
		}
		info, _ := os.Stat(out)
		if info.Mode().Perm() != 0o600 || f.Mode != "0o600" {
			t.Errorf("mode %v / %s", info.Mode(), f.Mode)
		}
	}
}

func bootOf(t testing.TB, text string) string {
	v, err := validate.DecodeJSONString(text)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)["boot_id"].(string)
}

func newAttempt(bootID string) *Attempt {
	a := New(time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC), NewParams{Source: "panel", Target: host, TargetKey: zeroKey, BootID: bootID})
	a.AttemptID = "0123456789abcdef"
	return a
}

func TestNewAttempt(t *testing.T) {
	a := newAttempt(boot)
	if a.State != "idle" || a.StartedAt != "2026-10-11T12:00:00Z" || a.Source != "panel" || a.Attempts != 0 || a.BackoffStep != 0 {
		t.Errorf("%+v", a)
	}
	first := New(time.Now(), NewParams{})
	second := New(time.Now(), NewParams{})
	if len(first.AttemptID) != 16 || first.AttemptID == second.AttemptID || strings.Trim(first.AttemptID, "0123456789abcdef") != "" {
		t.Errorf("ids %q %q", first.AttemptID, second.AttemptID)
	}
}

func TestRestingStatesSurviveARestart(t *testing.T) {
	for _, state := range []string{"unverified", "failed", "pending", "rejected"} {
		path := filepath.Join(t.TempDir(), "applier", "attempt.json")
		a := newAttempt(boot)
		a.State, a.Message = state, "Example."
		if state == "failed" {
			a.NextAction, a.NextActionAt, a.BackoffStep = "reapply", fp(500), 2
		}
		if state == "rejected" {
			a.Extra = Extra{Why: "invalid", Release: "invalid"}
			a.Rejected = &Rejected{Key: zeroKey, Reason: "Example.", Why: "invalid", Release: "invalid"}
		}
		if err := a.Save(path); err != nil {
			t.Fatal(err)
		}
		loaded := Load(path, boot, 100)
		if loaded.State != state || loaded.Target != host || loaded.Message != "Example." {
			t.Errorf("%s: %+v", state, loaded)
		}
		if state == "failed" && (loaded.NextAction != "reapply" || *loaded.NextActionAt != 500 || loaded.BackoffStep != 2) {
			t.Errorf("deadline lost: %+v", loaded)
		}
		if state == "rejected" && (loaded.Extra.Why != "invalid" || loaded.Rejected == nil || loaded.Rejected.Release != "invalid") {
			t.Errorf("rejection lost: %+v", loaded)
		}
	}
}

func TestDeadlinesFromAnotherBootAreRebased(t *testing.T) {
	path := filepath.Join(t.TempDir(), "applier", "attempt.json")
	a := newAttempt("old-boot")
	a.State, a.NextAction, a.NextActionAt, a.BackoffStep = "failed", "reapply", fp(9e9), 3
	a.LastMutationAt = fp(9e9)
	if err := a.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded := Load(path, boot, 100)
	if *loaded.NextActionAt != float64(100+BackoffSec[3]) || loaded.LastMutationAt != nil || loaded.BootID != boot {
		t.Errorf("%+v", loaded)
	}
	a.NextAction, a.NextActionAt = "recheck", fp(9e9)
	a.Save(path)
	if got := Load(path, boot, 100); *got.NextActionAt != 100 {
		t.Errorf("%+v", got)
	}
	// With nothing scheduled, nothing is invented; the same boot keeps everything.
	a.NextAction, a.NextActionAt = "", nil
	a.Save(path)
	if got := Load(path, boot, 100); got.NextActionAt != nil || got.NextAction != "" || got.LastMutationAt != nil {
		t.Errorf("%+v", got)
	}
	a.BootID, a.NextAction, a.NextActionAt, a.LastMutationAt = boot, "reapply", fp(777), fp(555)
	a.Save(path)
	if got := Load(path, boot, 100); *got.NextActionAt != 777 || *got.LastMutationAt != 555 {
		t.Errorf("same boot rebased: %+v", got)
	}
}

func TestAnUnreadableAttemptStartsIdle(t *testing.T) {
	for name, content := range map[string]string{
		"broken": "{broken", "list": "[]", "unknown state": `{"state": "exploded"}`, "negative step": `{"state": "failed", "backoff_step": -1}`,
		"step text": `{"state": "failed", "backoff_step": "1"}`, "step bool": `{"state": "failed", "backoff_step": true}`,
		"step float": `{"state": "failed", "backoff_step": 1.5}`, "state null": `{"state": null}`, "state number": `{"state": 1}`,
		"attempts text": `{"attempts": "x"}`, "target number": `{"target": 5}`, "duplicate key": `{"state": "failed", "state": "idle"}`,
		"empty": "", "null": "null", "nan": `{"next_action_at": NaN}`,
	} {
		path := filepath.Join(t.TempDir(), "applier", "attempt.json")
		os.MkdirAll(filepath.Dir(path), 0o700)
		os.WriteFile(path, []byte(content), 0o600)
		a := Load(path, boot, 0)
		if a.State != "idle" || a.BootID != boot || a.Target != "" || a.Attempts != 0 || a.NextAction != "" {
			t.Errorf("%s: %+v", name, a)
		}
	}
	if a := Load(filepath.Join(t.TempDir(), "nothing.json"), boot, 0); a.State != "idle" || a.BootID != boot {
		t.Errorf("missing file: %+v", a)
	}
	// Special files and large files are never read.
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	syscall.Mkfifo(fifo, 0o600)
	link := filepath.Join(dir, "link")
	big := filepath.Join(dir, "big")
	os.WriteFile(big, []byte(`{"state": "failed", "message": "`+strings.Repeat("x", MaxBytes)+`"}`), 0o600)
	os.WriteFile(filepath.Join(dir, "real"), []byte(`{"state": "failed"}`), 0o600)
	os.Symlink(filepath.Join(dir, "real"), link)
	for _, p := range []string{fifo, link, big} {
		if Load(p, boot, 0).State != "idle" {
			t.Errorf("%s was read", filepath.Base(p))
		}
	}
}

func TestOddMembersAreRepairedNotFatal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attempt.json")
	os.WriteFile(path, []byte(`{"state": "failed", "boot_id": "`+boot+`", "next_action": "explode", "next_action_at": "soon",
		"last_mutation_at": true, "target": "`+host+`", "rejected": "x", "extra": [], "unknown": 1}`), 0o600)
	a := Load(path, boot, 0)
	if a.State != "failed" || a.NextAction != "" || a.NextActionAt != nil || a.LastMutationAt != nil || a.Target != host ||
		a.Rejected != nil || a.Extra != (Extra{}) {
		t.Errorf("%+v", a)
	}
}

func TestBackoff(t *testing.T) {
	for step, want := range map[int]int{-5: 60, 0: 60, 1: 120, 2: 240, 3: 480, 4: 900, 5: 900, 100: 900} {
		if got := Backoff(step); got != want {
			t.Errorf("Backoff(%d) = %d", step, got)
		}
	}
	if ReapplyGuardSec != 90 || UnidentifiedSec != 90 || BootIDFile != "/proc/sys/kernel/random/boot_id" {
		t.Error("constants")
	}
}

func TestGuardScheduleSettle(t *testing.T) {
	a := newAttempt(boot)
	if !a.GuardPassed(0) {
		t.Error("no mutation yet")
	}
	a.LastMutationAt = fp(1000)
	if a.GuardPassed(1089.9) || !a.GuardPassed(1090) || !a.GuardPassed(5000) {
		t.Error("the guard is 90 seconds")
	}
	a.Schedule("recheck", 200)
	if a.NextAction != "recheck" || *a.NextActionAt != 260 || a.BackoffStep != 1 {
		t.Errorf("%+v", a)
	}
	a.Schedule("reapply", 300)
	a.Schedule("reapply", 400)
	if *a.NextActionAt != 400+240 || a.BackoffStep != 3 {
		t.Errorf("%+v", a)
	}
	a.State, a.Message, a.MutationCertainty, a.Attempts = "failed", "Example.", "uncertain", 4
	a.Rejected = &Rejected{Key: "k"}
	a.Settle()
	if a.State != "idle" || a.Outcome != "verified" || a.Message != "" || a.NextAction != "" || a.NextActionAt != nil ||
		a.BackoffStep != 0 || a.MutationCertainty != "" || a.Attempts != 4 || a.Rejected == nil || a.LastMutationAt == nil {
		t.Errorf("%+v", a)
	}
}

func TestReadBootID(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		p := filepath.Join(dir, "boot")
		os.WriteFile(p, []byte(content), 0o600)
		return p
	}
	for content, want := range map[string]string{
		boot + "\n": boot, "  " + boot + "  \n": boot, "abc123": "abc123", "A-b-C": "A-b-C", strings.Repeat("a", 64): strings.Repeat("a", 64),
		strings.Repeat("a", 65): "unknown", "": "unknown", "\n": "unknown", "a b": "unknown", "a_b": "unknown", "caf\xc3\xa9": "unknown",
		"a\x00b": "unknown", "---": "unknown", "a\nb": "unknown",
	} {
		if got := ReadBootID(write(content)); got != want {
			t.Errorf("ReadBootID(%q) = %q, want %q", content, got, want)
		}
	}
	if got := ReadBootID(filepath.Join(dir, "missing")); got != "unknown" {
		t.Errorf("missing: %q", got)
	}
	if got := ReadBootID(write(strings.Repeat("a", 5000))); got != "unknown" {
		t.Errorf("huge: %q", got)
	}
	// The real one, on a Linux host, is a UUID.
	if raw, err := os.ReadFile(BootIDFile); err == nil {
		if got := ReadBootID(BootIDFile); got != strings.TrimSpace(string(raw)) {
			t.Errorf("real boot id %q", got)
		}
	}
}

func FuzzLoad(f *testing.F) {
	for _, s := range []string{`{"state": "failed", "backoff_step": 2, "next_action": "reapply", "next_action_at": 5.5}`, `[]`, `{"state": "idle"}`,
		`{"rejected": {"key": "k"}, "extra": {"why": "w"}}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "attempt.json")
		os.WriteFile(path, data, 0o600)
		a := Load(path, boot, 100)
		if !contains(States, a.State) || a.BackoffStep < 0 || a.BootID != boot {
			t.Fatalf("%+v", a)
		}
		// Whatever was read can be written again, and reads back the same.
		again := filepath.Join(t.TempDir(), "again.json")
		if err := a.Save(again); err != nil {
			t.Fatal(err)
		}
		b := Load(again, boot, 100)
		x, _ := validate.MarshalJSON(a)
		y, _ := validate.MarshalJSON(b)
		if string(x) != string(y) {
			t.Fatalf("not stable:\n%s\n%s", x, y)
		}
	})
}
