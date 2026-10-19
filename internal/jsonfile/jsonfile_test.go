// Tests for molebridge/state.py read_json and write_json_atomic, ported from
// tools/test_runtime.py (test_duplicate_json_and_special_files_rejected,
// test_symlink_and_fifo_requests_never_followed_or_block) and
// tools/test_providers.py (the write-with-a-limit, streamed-output and bounded
// memory tests).
package jsonfile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/irashack/molebridge/internal/validate"
)

func names(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func TestDuplicateJSONAndSpecialFilesRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "request.json")
	os.WriteFile(path, []byte(`{"server":"a","server":"b"}`), 0o600)
	if Read(path, 1<<20) != nil {
		t.Error("duplicate keys accepted")
	}
	os.WriteFile(path, []byte(strings.Repeat("x", 4097)), 0o600)
	if Read(path, 4096) != nil {
		t.Error("oversized file accepted")
	}
	os.WriteFile(path, []byte(`{"a":1}`), 0o600)
	if m, ok := ReadObject(path, 4096); !ok || m["a"] != int64(1) {
		t.Errorf("good file: %v %v", m, ok)
	}
	// Exactly at the limit is fine, one more byte is not.
	if Read(path, 7) == nil || Read(path, 6) != nil {
		t.Error("the limit is inclusive")
	}
	if Read(dir, 1<<20) != nil {
		t.Error("directory accepted")
	}
	if Read(filepath.Join(dir, "missing"), 1<<20) != nil {
		t.Error("missing file accepted")
	}
	for name, content := range map[string]string{"nan": `{"value":NaN}`, "empty": ``, "bad": `{broken`, "array": `[]`, "utf8": "{\"a\":\"\xff\"}"} {
		os.WriteFile(path, []byte(content), 0o600)
		v := Read(path, 1<<20)
		if name == "array" {
			if _, ok := v.([]any); !ok {
				t.Errorf("array: %#v", v)
			}
			if _, ok := ReadObject(path, 1<<20); ok {
				t.Error("ReadObject accepted an array")
			}
			continue
		}
		if v != nil {
			t.Errorf("%s accepted: %#v", name, v)
		}
	}
}

func TestSymlinkAndFIFONeverFollowedOrBlock(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	if err := Write(original, validate.Members("server", "a"), Options{}); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	os.Symlink(original, link)
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if Read(link, 1<<20) != nil {
		t.Error("symlink followed")
	}
	if Read(fifo, 1<<20) != nil {
		t.Error("fifo read")
	}
	if Read(original, 1<<20) == nil {
		t.Error("the original must still read")
	}
}

func TestWriteModesAndOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "deeper", "out.json")
	obj := validate.Members("fetched_at", "2026-10-11T12:00:00Z", "relays", map[string]any{"a": validate.Members("city", strings.Repeat("é", 250), "n", 1.5, "b", true, "x", nil)})
	if err := Write(path, obj, Options{MaxBytes: 1_000_000}); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("private mode %v", info.Mode())
	}
	got, _ := os.ReadFile(path)
	want, _ := validate.MarshalJSON(obj)
	if string(got) != string(want) || strings.HasSuffix(string(got), "\n") {
		t.Errorf("file content differs from json.dump output: %.80s", got)
	}
	if err := Write(path, validate.Obj{}, Options{Public: true}); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(path)
	if info.Mode().Perm() != 0o644 {
		t.Errorf("public mode %v", info.Mode())
	}
	// Non-finite numbers are refused and leave the old file alone.
	if err := Write(path, map[string]any{"x": nan()}, Options{}); !errors.Is(err, validate.ErrNonFiniteFloat) {
		t.Errorf("NaN: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "{}" {
		t.Errorf("old file changed: %s", b)
	}
	if got := names(t, filepath.Dir(path)); len(got) != 1 {
		t.Errorf("temporary files left behind: %v", got)
	}
}

func TestWriteWithoutSyncStillReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "result.json")
	for i := 0; i < 3; i++ {
		if err := Write(path, validate.Members("n", i), Options{Public: true, NoSync: true}); err != nil {
			t.Fatal(err)
		}
	}
	if b, _ := os.ReadFile(path); string(b) != `{"n": 2}` {
		t.Errorf("content %s", b)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", info.Mode())
	}
	if got := names(t, dir); len(got) != 1 {
		t.Errorf("temporary files left behind: %v", got)
	}
}

func nan() float64 { var z float64; return z / z }

func TestWriteWithALimitRefusesBeforeTouchingTheOldFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relays.json")
	if err := Write(path, map[string]any{"old": true}, Options{Public: true}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	err := Write(path, map[string]any{"x": strings.Repeat("y", 100)}, Options{Public: true, MaxBytes: 50})
	if !errors.Is(err, ErrSizeLimit) {
		t.Fatalf("got %v", err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) || len(names(t, dir)) != 1 {
		t.Errorf("old file changed or temporary left: %s %v", after, names(t, dir))
	}
	if err := Write(path, map[string]any{"x": "y"}, Options{Public: true, MaxBytes: 50}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != `{"x": "y"}` {
		t.Errorf("%s", b)
	}
	// The limit is on the output: exactly the limit passes.
	if err := Write(path, map[string]any{"x": "y"}, Options{MaxBytes: int64(len(`{"x": "y"}`))}); err != nil {
		t.Errorf("exact limit: %v", err)
	}
	if err := Write(path, map[string]any{"x": "y"}, Options{MaxBytes: int64(len(`{"x": "y"}`)) - 1}); !errors.Is(err, ErrSizeLimit) {
		t.Errorf("one under the limit: %v", err)
	}
}

func TestWriteErrorsLeaveNothingBehind(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	os.WriteFile(blocker, []byte("x"), 0o600)
	if err := Write(filepath.Join(blocker, "out.json"), 1, Options{}); err == nil {
		t.Error("writing below a regular file must fail")
	}
	// A directory in the way of the rename.
	target := filepath.Join(dir, "dir")
	os.Mkdir(target, 0o700)
	os.WriteFile(filepath.Join(target, "keep"), []byte("x"), 0o600)
	if err := Write(target, 1, Options{}); err == nil {
		t.Error("renaming over a non-empty directory must fail")
	}
	if got := names(t, dir); len(got) != 2 {
		t.Errorf("leftovers: %v", got)
	}
}

// allocated returns the bytes the action allocates in total.
func allocated(action func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	action()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestEncodingStopsAtTheLimitWithBoundedMemory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relays.json")
	Write(path, map[string]any{"last": "good"}, Options{Public: true})
	before, _ := os.ReadFile(path)
	// About 150 MB serialised; the limit is 16 MiB.
	long := strings.Repeat("é", 250)
	rows := make([]any, 50000)
	for i := range rows {
		rows[i] = validate.Members("hostname", "us", "city", long, "country", long, "virtual", false)
	}
	var err error
	grown := allocated(func() { err = Write(path, validate.Members("relays", rows), Options{Public: true, MaxBytes: 16 << 20}) })
	if !errors.Is(err, ErrSizeLimit) {
		t.Fatalf("got %v", err)
	}
	// The encoder must not build the document: it stops within a chunk of the
	// limit. 16 MiB is the output it may have produced, plus its small buffers.
	if grown > 40<<20 {
		t.Errorf("allocated %d MiB while refusing a 16 MiB document", grown>>20)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) || len(names(t, dir)) != 1 {
		t.Error("old file changed or temporary left behind")
	}
}
