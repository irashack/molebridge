package exit

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestStateGIDIsParsed(t *testing.T) {
	f := newFixture(t)
	s, err := f.load()
	if err != nil || s.StateGID != -1 {
		t.Fatalf("unset: %v %v", s, err)
	}
	f.env["STATE_GID"] = "1000"
	if s, err := f.load(); err != nil || s.StateGID != 1000 {
		t.Fatalf("1000: %v", err)
	}
	for _, bad := range []string{"x", "-1", "+5", "01", " 5", "2147483648", "1000:1000"} {
		f.env["STATE_GID"] = bad
		if _, err := f.load(); err == nil || !strings.Contains(err.Error(), "STATE_GID must be a group id") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func groupOf(t *testing.T, path string) (int, os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return int(info.Sys().(*syscall.Stat_t).Gid), info.Mode()
}

func TestStateGIDSharesThePublishedFiles(t *testing.T) {
	f := newFixture(t)
	gid := os.Getegid() // a group the test can give files to without CHOWN
	applierDir := filepath.Join(f.env["STATE_DIR"], "applier")
	if err := os.Chmod(applierDir, 0o770); err != nil {
		t.Fatal(err)
	}
	files := map[string]os.FileMode{"result.json": 0o644, "relays.json": 0o640, "attempt.json": 0o600, "odd.json": 0o664}
	for name, mode := range files {
		path := filepath.Join(applierDir, name)
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(f.dir, "outside.json")
	if err := os.WriteFile(outside, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(applierDir, "link.json")); err != nil {
		t.Fatal(err)
	}
	f.env["STATE_GID"] = strconv.Itoa(gid)
	f.opts.WriteChecks = true
	if _, err := f.load(); err != nil {
		t.Fatal(err)
	}
	if g, mode := groupOf(t, applierDir); g != gid || mode.Perm() != 0o750 {
		t.Errorf("directory: group %d mode %04o", g, mode.Perm())
	}
	for name, want := range map[string]os.FileMode{"result.json": 0o640, "relays.json": 0o640, "attempt.json": 0o600, "odd.json": 0o664} {
		if g, mode := groupOf(t, filepath.Join(applierDir, name)); mode.Perm() != want || (want == 0o640 && g != gid) {
			t.Errorf("%s: group %d mode %04o, want %04o", name, g, mode.Perm(), want)
		}
	}
	// The link is not followed: its target keeps its mode.
	if _, mode := groupOf(t, outside); mode.Perm() != 0o644 {
		t.Errorf("followed the link: %04o", mode.Perm())
	}
	// Without WriteChecks (check-config, the worker) nothing changes.
	if err := os.Chmod(applierDir, 0o770); err != nil {
		t.Fatal(err)
	}
	f.opts.WriteChecks = false
	if _, err := f.load(); err != nil {
		t.Fatal(err)
	}
	if _, mode := groupOf(t, applierDir); mode.Perm() != 0o770 {
		t.Errorf("changed without WriteChecks: %04o", mode.Perm())
	}
}

func TestStateGIDRefusesAGroupTheExitCannotGive(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may give any group")
	}
	groups, _ := os.Getgroups()
	foreign := 1
	for foreign == os.Getegid() || slices.Contains(groups, foreign) {
		foreign++
	}
	f := newFixture(t)
	f.env["STATE_GID"] = strconv.Itoa(foreign)
	f.opts.WriteChecks = true
	_, err := f.load()
	if err == nil || !strings.Contains(err.Error(), "STATE_GID ") || !strings.Contains(err.Error(), "supplementalGroups") {
		t.Fatalf("%v", err)
	}
}
