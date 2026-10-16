// New in 0.8.0 (D25): no Python counterpart. tools/molebridge.py had no
// repair tool; these tests cover the fix-blacklist function the role file
// calls.
package nbprofile

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func noSocket(string) bool { return false }

func fixOpts() FixOptions { return FixOptions{SocketAnswers: noSocket} }

func readGolden(t *testing.T, name string) (in, want []byte) {
	t.Helper()
	in, err := os.ReadFile(filepath.Join("testdata", "fix", name+".in"))
	if err != nil {
		t.Fatal(err)
	}
	want, err = os.ReadFile(filepath.Join("testdata", "fix", name+".want"))
	if err != nil {
		t.Fatal(err)
	}
	return in, want
}

func goldenNames(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "fix", "*.in"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden files (%v)", err)
	}
	var names []string
	for _, f := range files {
		names = append(names, strings.TrimSuffix(filepath.Base(f), ".in"))
	}
	return names
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// Absent, null, empty and populated lists, and the file styles NetBird and
// other tools write; every unrelated byte is preserved.
func TestFixBlacklistGolden(t *testing.T) {
	for _, name := range goldenNames(t) {
		t.Run(name, func(t *testing.T) {
			in, want := readGolden(t, name)
			f := newFixture(t)
			path := f.write("default.json", in)
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
			res, err := FixBlacklistWith(f.paths, "mullvad", fixOpts())
			if err != nil || !res.Changed || res.Path != path {
				t.Fatalf("result %+v, error %v", res, err)
			}
			got, _ := os.ReadFile(path)
			if !bytes.Equal(got, want) {
				t.Fatalf("edited profile:\n%s\nwant:\n%s", got, want)
			}
			st, _ := os.Stat(path)
			if st.Mode().Perm() != 0o640 {
				t.Errorf("mode = %v", st.Mode())
			}
			if entries := dirEntries(t, f.paths.StateDir); len(entries) != 1 {
				t.Errorf("directory holds %v", entries)
			}
			// The edited profile now satisfies the check, and a second run
			// changes nothing.
			if _, err := CheckBlacklist(f.paths, "mullvad"); err != nil {
				t.Errorf("check after the repair: %v", err)
			}
			before, _ := os.Stat(path)
			res, err = FixBlacklistWith(f.paths, "mullvad", fixOpts())
			if err != nil || res.Changed {
				t.Fatalf("second run: %+v, %v", res, err)
			}
			after, _ := os.Stat(path)
			again, _ := os.ReadFile(path)
			if !os.SameFile(before, after) || !bytes.Equal(again, want) {
				t.Error("the second run rewrote the file")
			}
		})
	}
}

// Every field other than the blacklist decodes to the same value, including
// the ones with escapes, and every existing blacklist entry stays in order.
func TestFixBlacklistKeepsEveryOtherFieldAndEntry(t *testing.T) {
	for _, name := range goldenNames(t) {
		in, want := readGolden(t, name)
		var before, after map[string]any
		if err := json.Unmarshal(in, &before); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := json.Unmarshal(want, &after); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var oldList, newList any
		for _, m := range []map[string]any{before, after} {
			for k, v := range m {
				if strings.EqualFold(k, "IFaceBlackList") {
					if reflect.ValueOf(m).Pointer() == reflect.ValueOf(before).Pointer() {
						oldList = v
					} else {
						newList = v
					}
					delete(m, k)
				}
			}
		}
		if !reflect.DeepEqual(before, after) {
			t.Errorf("%s: other fields changed:\n%v\n%v", name, before, after)
		}
		old, _ := oldList.([]any)
		now, _ := newList.([]any)
		if len(old) > 0 {
			if len(now) != len(old)+1 || !reflect.DeepEqual(now[:len(old)], old) || now[len(old)] != "mullvad" {
				t.Errorf("%s: list %v -> %v", name, old, now)
			}
		} else if len(now) != len(DefaultInterfaceBlacklist())+1 || now[len(now)-1] != "mullvad" {
			t.Errorf("%s: filled list = %v", name, now)
		}
	}
}

// Outside the one spliced span the file is byte for byte the original.
func TestFixBlacklistChangesOnlyOneSpan(t *testing.T) {
	for _, name := range goldenNames(t) {
		in, want := readGolden(t, name)
		p := 0
		for p < len(in) && p < len(want) && in[p] == want[p] {
			p++
		}
		s := 0
		for s < len(in)-p && s < len(want)-p && in[len(in)-1-s] == want[len(want)-1-s] {
			s++
		}
		// What is left of the original between prefix and suffix is at most
		// the old list value (or nothing, for an insertion).
		removed := string(in[p : len(in)-s])
		if strings.Trim(removed, "nul[] \t\r\n") != "" {
			t.Errorf("%s: the edit removed %q", name, removed)
		}
	}
}

func TestFixBlacklistDefaultFillingDoesNotDuplicateTheTunnel(t *testing.T) {
	f := newFixture(t)
	path := f.write("default.json", `{"WgIface": "mesh0"}`)
	if _, err := FixBlacklistWith(f.paths, "docker", fixOpts()); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if n := strings.Count(string(data), `"docker"`); n != 1 {
		t.Fatalf("docker listed %d times:\n%s", n, data)
	}
}

func TestFixBlacklistAlreadyPresentIsANoOp(t *testing.T) {
	for _, text := range []string{
		listProfile(`["wt0", "mullvad"]`),
		"{\"ifaceblacklist\":[\"mullvad\"]}",
		listProfile(`["mullvad"]`),
	} {
		f := newFixture(t)
		path := f.write("default.json", text)
		past := time.Now().Add(-48 * time.Hour)
		_ = os.Chtimes(path, past, past)
		before := mustStat(t, path)
		res, err := FixBlacklistWith(f.paths, "mullvad", fixOpts())
		if err != nil || res.Changed || res.Path != path {
			t.Fatalf("%q: %+v, %v", text, res, err)
		}
		after := mustStat(t, path)
		if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
			t.Errorf("%q: the file was touched", text)
		}
		if got, _ := os.ReadFile(path); string(got) != text {
			t.Errorf("%q: content changed", text)
		}
	}
}

// The tunnel interface is already excluded when an entry is a prefix of its
// name; otherwise the exact name is added.
func TestFixBlacklistFollowsNetBirdsPrefixMatching(t *testing.T) {
	for _, c := range []struct {
		list, tunnel, want string
	}{
		{`["wg"]`, "wg0", `["wg"]`},
		{`["wt0", "wg"]`, "wg0", `["wt0", "wg"]`},
		{`["mull"]`, "mullvad", `["mull"]`},
		{`["mullvad0"]`, "mullvad", `["mullvad0", "mullvad"]`},
		{`[""]`, "mullvad", `["", "mullvad"]`},
		{`["", "wt0"]`, "mullvad", `["", "wt0", "mullvad"]`},
	} {
		f := newFixture(t)
		path := f.write("default.json", listProfile(c.list))
		res, err := FixBlacklistWith(f.paths, c.tunnel, fixOpts())
		if err != nil || res.Changed != (c.want != c.list) {
			t.Errorf("%s with %s: %+v, %v", c.list, c.tunnel, res, err)
			continue
		}
		if got, _ := os.ReadFile(path); string(got) != listProfile(c.want) {
			t.Errorf("%s with %s:\n%s", c.list, c.tunnel, got)
		}
	}
}

func TestFixBlacklistEditsTheLegacyProfileInPlace(t *testing.T) {
	f := newFixture(t)
	path := f.write(f.paths.Legacy[0], "{\n  \"WgIface\": \"mesh0\"\n}\n")
	res, err := FixBlacklistWith(f.paths, "mullvad", fixOpts())
	if err != nil || !res.Changed || res.Path != path {
		t.Fatalf("%+v, %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(f.paths.StateDir, "default.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a default profile was created")
	}
	if entries := dirEntries(t, filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("legacy directory holds %v", entries)
	}
	if _, err := CheckBlacklist(f.paths, "mullvad"); err != nil {
		t.Fatalf("check after the repair: %v", err)
	}
	// With a default profile present, the legacy one is never touched.
	f.write("default.json", listProfile(`["wt0"]`))
	legacy, _ := os.ReadFile(path)
	if _, err := FixBlacklistWith(f.paths, "mullvad", fixOpts()); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, legacy) {
		t.Fatal("the legacy profile changed although the default exists")
	}
	if def, _ := os.ReadFile(filepath.Join(f.paths.StateDir, "default.json")); !strings.Contains(string(def), `"mullvad"`) {
		t.Fatal("the default profile was not repaired")
	}
}

func TestFixBlacklistRefusesWithoutAnIdentity(t *testing.T) {
	f := newFixture(t)
	_, err := FixBlacklistWith(f.paths, "mullvad", fixOpts())
	if err == nil || !strings.Contains(err.Error(), "no NetBird identity found; refusing to create one") {
		t.Fatalf("error = %v", err)
	}
	if entries := dirEntries(t, f.paths.StateDir); len(entries) != 0 {
		t.Fatalf("directory holds %v", entries)
	}
}

func TestFixBlacklistRefusesMalformedOrAmbiguousJSON(t *testing.T) {
	for _, c := range []struct{ name, text, why string }{
		{"truncated", `{"IFaceBlackList": ["wt0"`, "is not a valid JSON object"},
		{"trailing data", `{"WgIface": "mesh0"} {}`, "is not a valid JSON object"},
		{"array root", `[]`, "is not a valid JSON object"},
		{"empty file", ``, "is not a valid JSON object"},
		{"duplicate list", `{"IFaceBlackList": ["a"], "IFaceBlackList": ["b"]}`, "repeats a key within one object"},
		{"duplicate list in another case", `{"IFaceBlackList": ["a"], "ifaceblacklist": []}`, "repeats a field in another case"},
		{"duplicate list in all caps", `{"ifaceblacklist": null, "IFACEBLACKLIST": ["a"]}`, "repeats a field in another case"},
		{"duplicate WgIface in another case", `{"WgIface": "a", "wgiface": "a"}`, "repeats a field in another case"},
		{"duplicate nested key", `{"Nested": {"a": 1, "a": 2}, "IFaceBlackList": []}`, "repeats a key within one object"},
		{"duplicate key in an array element", `{"List": [{"a": 1, "a": 1}]}`, "repeats a key within one object"},
		{"duplicate escaped key", `{"a": 1, "a": 2}`, "repeats a key within one object"},
		{"folded name", "{\"IFaceBlackLiſt\": [\"a\"]}", "outside printable ASCII"},
		{"kelvin escape", `{"Key": 1}`, "outside printable ASCII"},
		{"list is a string", `{"IFaceBlackList": "wt0"}`, "IFaceBlackList that is not a list of strings"},
		{"list of numbers", `{"IFaceBlackList": [1]}`, "IFaceBlackList that is not a list of strings"},
		{"list with null", `{"IFaceBlackList": ["a", null]}`, "IFaceBlackList that is not a list of strings"},
		{"list is an object", `{"IFaceBlackList": {}}`, "IFaceBlackList that is not a list of strings"},
		{"invalid UTF-8", "{\"a\": \"\xff\"}", "is not a valid JSON object"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			path := f.write("default.json", c.text)
			_, err := FixBlacklistWith(f.paths, "mullvad", fixOpts())
			if err == nil || !strings.Contains(err.Error(), c.why) {
				t.Fatalf("error = %v, want %q", err, c.why)
			}
			if got, _ := os.ReadFile(path); string(got) != c.text {
				t.Error("the file changed")
			}
			if entries := dirEntries(t, f.paths.StateDir); len(entries) != 1 {
				t.Errorf("directory holds %v", entries)
			}
		})
	}
}

func TestFixBlacklistRefusesAnotherActiveProfile(t *testing.T) {
	f := newFixture(t)
	f.write("default.json", `{}`)
	f.write("active_profile.json", `{"name": "alternate"}`)
	if _, err := FixBlacklistWith(f.paths, "mullvad", fixOpts()); err == nil || !strings.Contains(err.Error(), "active NetBird profile is not the default profile") {
		t.Fatalf("error = %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(f.paths.StateDir, "default.json")); string(got) != `{}` {
		t.Fatal("the profile changed")
	}
}

func TestFixBlacklistRefusesAnInvalidTunnelName(t *testing.T) {
	f := newFixture(t)
	f.write("default.json", `{}`)
	for _, name := range []string{"", `x"y`, "a b", "abcdefghijklmnop", "-x"} {
		if _, err := FixBlacklistWith(f.paths, name, fixOpts()); err == nil {
			t.Errorf("%q accepted", name)
		}
	}
}

func TestFixBlacklistRefusesASymlinkedProfile(t *testing.T) {
	f := newFixture(t)
	target := f.write(filepath.Join(f.dir, "real.json"), `{"WgIface": "mesh0"}`)
	if err := os.Symlink(target, filepath.Join(f.paths.StateDir, "default.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := FixBlacklistWith(f.paths, "mullvad", fixOpts()); err == nil || !strings.Contains(err.Error(), "as a regular file") {
		t.Fatalf("error = %v", err)
	}
	if got, _ := os.ReadFile(target); string(got) != `{"WgIface": "mesh0"}` {
		t.Fatal("the link target changed")
	}
}

// The daemon check: a socket that answers, or a netbird process in the
// process table, stops the repair before anything is read.
func TestFixBlacklistRefusesWhileTheDaemonIsVisible(t *testing.T) {
	f := newFixture(t)
	path := f.write("default.json", `{"WgIface": "mesh0"}`)

	t.Run("injected socket", func(t *testing.T) {
		f.paths.Socket = "/run/netbird.sock"
		_, err := FixBlacklistWith(f.paths, "mullvad", FixOptions{SocketAnswers: func(p string) bool { return p == "/run/netbird.sock" }})
		if err == nil || !strings.Contains(err.Error(), "daemon socket /run/netbird.sock answers") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("real socket", func(t *testing.T) {
		dir, err := os.MkdirTemp("/tmp", "nbsock")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(dir)
		sock := filepath.Join(dir, "s")
		ln, err := net.Listen("unix", sock)
		if err != nil {
			t.Skip("cannot listen on a unix socket:", err)
		}
		defer ln.Close()
		p := f.paths
		p.Socket = sock
		if _, err := FixBlacklistWith(p, "mullvad", FixOptions{}); err == nil || !strings.Contains(err.Error(), "answers") {
			t.Fatalf("error = %v", err)
		}
		// A stale socket file that nothing listens on does not block.
		ln.Close()
		other := newFixture(t)
		other.write("default.json", `{"WgIface": "mesh0"}`)
		other.paths.Socket = sock
		if _, err := FixBlacklistWith(other.paths, "mullvad", FixOptions{}); err != nil {
			t.Fatalf("stale socket: %v", err)
		}
	})
	t.Run("process table", func(t *testing.T) {
		proc := t.TempDir()
		write := func(pid, argv string) {
			if err := os.MkdirAll(filepath.Join(proc, pid), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(proc, pid, "cmdline"), []byte(argv), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		write("17", "/bin/sh\x00-c\x00netbird\x00")         // only an argument
		write("18", "/usr/bin/molebridge\x00fix-blacklist") // this tool
		write("self", "/usr/local/bin/netbird\x00service\x00run\x00")
		_ = os.MkdirAll(filepath.Join(proc, "19"), 0o755) // no cmdline: a kernel thread
		fresh := newFixture(t)
		fresh.write("default.json", `{"WgIface": "mesh0"}`)
		p := fresh.paths
		p.ProcDir = proc
		if _, err := FixBlacklistWith(p, "mullvad", fixOpts()); err != nil {
			t.Fatalf("no daemon in the table: %v", err)
		}
		write("21", "/usr/local/bin/netbird\x00service\x00run\x00--log-level\x00info")
		if _, err := FixBlacklistWith(p, "mullvad", fixOpts()); err == nil || !strings.Contains(err.Error(), "a NetBird process (pid 21) is running") {
			t.Fatalf("error = %v", err)
		}
	})
	if got, _ := os.ReadFile(path); string(got) != `{"WgIface": "mesh0"}` {
		t.Fatal("the profile changed")
	}
}

// Ownership preservation: when the replacement cannot be given the original's
// owner and group the tool refuses and nothing changes.
func TestFixBlacklistRefusesWhenOwnershipCannotBePreserved(t *testing.T) {
	text := listProfile(`["wt0"]`)
	for _, c := range []struct {
		name string
		opts FixOptions
		why  string
	}{
		{"chown fails", FixOptions{Fchown: func(*os.File, int, int) error { return syscall.EPERM }}, "cannot give the replacement the owner and group"},
		{"chown does nothing", FixOptions{
			Fchown: func(*os.File, int, int) error { return nil },
			// The original claims another owner than any file this process creates.
			Owner: func(fi os.FileInfo) (int, int, bool) {
				uid, gid, ok := ownerOf(fi)
				if strings.HasPrefix(fi.Name(), ".") {
					return uid, gid, ok
				}
				return uid + 1, gid, ok
			},
		}, "does not have the original's owner, group and mode"},
		{"owner unreadable", FixOptions{Owner: func(os.FileInfo) (int, int, bool) { return 0, 0, false }}, "cannot read the owner"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			path := f.write("default.json", text)
			c.opts.SocketAnswers = noSocket
			before, _ := os.Stat(path)
			_, err := FixBlacklistWith(f.paths, "mullvad", c.opts)
			if err == nil || !strings.Contains(err.Error(), c.why) {
				t.Fatalf("error = %v, want %q", err, c.why)
			}
			after, _ := os.Stat(path)
			if got, _ := os.ReadFile(path); string(got) != text || !os.SameFile(before, after) {
				t.Error("the original changed")
			}
			if entries := dirEntries(t, f.paths.StateDir); len(entries) != 1 {
				t.Errorf("a temporary file was left: %v", entries)
			}
		})
	}
}

// The replacement gets the original's owner and group from the injected
// Fchown, and only after that is the content written.
func TestFixBlacklistChownsBeforeWriting(t *testing.T) {
	f := newFixture(t)
	path := f.write("default.json", listProfile(`["wt0"]`))
	var calls int
	opts := fixOpts()
	opts.Fchown = func(file *os.File, uid, gid int) error {
		calls++
		wantUID, wantGID, _ := ownerOf(mustStat(t, path))
		if uid != wantUID || gid != wantGID {
			t.Errorf("fchown(%d, %d), want (%d, %d)", uid, gid, wantUID, wantGID)
		}
		if st, _ := file.Stat(); st.Size() != 0 {
			t.Error("content was written before the ownership was set")
		}
		return file.Chown(uid, gid)
	}
	if _, err := FixBlacklistWith(f.paths, "mullvad", opts); err != nil || calls != 1 {
		t.Fatalf("calls %d, error %v", calls, err)
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestFixBlacklistPreservesTheMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o600, 0o640, 0o644, 0o400} {
		f := newFixture(t)
		path := f.write("default.json", listProfile(`["wt0"]`))
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := FixBlacklistWith(f.paths, "mullvad", fixOpts()); err != nil {
			t.Fatalf("%v: %v", mode, err)
		}
		if got := mustStat(t, path).Mode(); got != mode {
			t.Errorf("mode %v became %v", mode, got)
		}
	}
}

func TestFixBlacklistRefusesWhenTheProfileChangesUnderIt(t *testing.T) {
	f := newFixture(t)
	path := f.write("default.json", listProfile(`["wt0"]`))
	opts := fixOpts()
	opts.beforeRename = func() { f.write("default.json", listProfile(`["wt0", "extra"]`)) }
	_, err := FixBlacklistWith(f.paths, "mullvad", opts)
	if err == nil || !strings.Contains(err.Error(), "changed while it was being edited") {
		t.Fatalf("error = %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != listProfile(`["wt0", "extra"]`) {
		t.Fatal("the concurrent change was overwritten")
	}
	if entries := dirEntries(t, f.paths.StateDir); len(entries) != 1 {
		t.Fatalf("a temporary file was left: %v", entries)
	}
}

func TestFixBlacklistRefusesInAnUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	f := newFixture(t)
	text := listProfile(`["wt0"]`)
	path := f.write("default.json", text)
	if err := os.Chmod(f.paths.StateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(f.paths.StateDir, 0o700)
	if _, err := FixBlacklistWith(f.paths, "mullvad", fixOpts()); err == nil || !strings.Contains(err.Error(), "cannot create a replacement beside") {
		t.Fatalf("error = %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != text {
		t.Fatal("the original changed")
	}
}

func FuzzScan(f *testing.F) {
	for _, name := range []string{"absent", "null", "populated", "crlf_absent", "nested"} {
		in, err := os.ReadFile(filepath.Join("testdata", "fix", name+".in"))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(in)
	}
	f.Add([]byte(`{"a": [1, {"b": "😀"}], "a": 2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		root, err := scan(data, true)
		if err != nil && !errors.Is(err, errMalformed) && !errors.Is(err, errDuplicateDeep) {
			t.Fatalf("unexpected error %v", err)
		}
		if err != nil && errors.Is(err, errMalformed) {
			return
		}
		// Valid input agrees with encoding/json.
		var v map[string]any
		if json.Unmarshal(data, &v) != nil {
			t.Fatalf("scan accepted what encoding/json rejects: %q", data)
		}
		if data[root.open] != '{' || data[root.close] != '}' {
			t.Fatalf("root span wrong in %q", data)
		}
		for _, m := range root.members {
			if data[m.keyStart] != '"' || data[m.keyEnd-1] != '"' || m.valStart < m.keyEnd || m.valEnd <= m.valStart || m.valEnd > root.close {
				t.Fatalf("member span wrong in %q: %+v", data, m)
			}
		}
	})
}

func FuzzFixBlacklistSplice(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("testdata", "fix", "*.in"))
	for _, file := range files {
		in, err := os.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(in)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		root, err := scan(data, true)
		if err != nil || root.hasNonPlainKey() {
			return
		}
		l := loaded{data: data, root: root}
		for _, n := range []string{"ifaceblacklist"} {
			if len(root.lookup(n)) > 1 {
				return
			}
		}
		st, ok := blacklistOf(l)
		if !ok || covers(st.entries, "mullvad") {
			return
		}
		out, err := spliceBlacklist(l, st, []string{"mullvad"})
		if err != nil {
			t.Fatalf("splice failed on valid input %q: %v", data, err)
		}
		again, err := scan(out, true)
		if err != nil {
			t.Fatalf("splice produced invalid JSON from %q: %q", data, out)
		}
		chk, _ := blacklistOf(loaded{data: out, root: again})
		if !contains(chk.entries, "mullvad") {
			t.Fatalf("entry missing in %q", out)
		}
		// Prefix and suffix around the edit are the original bytes.
		p := 0
		for p < len(data) && p < len(out) && data[p] == out[p] {
			p++
		}
		if p == 0 && len(data) > 0 && data[0] != out[0] {
			t.Fatalf("the first byte changed: %q -> %q", data, out)
		}
	})
}

// New in 0.9.1: the edits for a peer that moved to another runtime.

func TestFixProfileAddsMoreInterfacesInOrder(t *testing.T) {
	for _, c := range []struct {
		list string
		add  []string
		want string
	}{
		{`["wt0"]`, []string{"eth0"}, `["wt0", "mullvad", "eth0"]`},
		{`["wt0", "mullvad"]`, []string{"eth0", "net1"}, `["wt0", "mullvad", "eth0", "net1"]`},
		{`["wt0", "mullvad", "eth"]`, []string{"eth0"}, `["wt0", "mullvad", "eth"]`},
		{`["wt0", "mullvad"]`, []string{"eth0", "eth0", "mullvad"}, `["wt0", "mullvad", "eth0"]`},
	} {
		f := newFixture(t)
		path := f.write("default.json", listProfile(c.list))
		res, err := FixProfileWith(f.paths, "mullvad", FixRequest{Add: c.add}, fixOpts())
		if err != nil || res.Changed != (c.want != c.list) {
			t.Errorf("%s + %v: %+v, %v", c.list, c.add, res, err)
			continue
		}
		if got, _ := os.ReadFile(path); string(got) != listProfile(c.want) {
			t.Errorf("%s + %v:\n%s", c.list, c.add, got)
		}
	}
	// An empty list gets NetBird's defaults, then the tunnel and the extra.
	f := newFixture(t)
	path := f.write("default.json", "{\"IFaceBlackList\":[]}")
	res, err := FixProfileWith(f.paths, "mullvad", FixRequest{Add: []string{"eth0"}}, fixOpts())
	if err != nil || !reflect.DeepEqual(res.Added, []string{"mullvad", "eth0"}) {
		t.Fatalf("%+v %v", res, err)
	}
	var got struct{ IFaceBlackList []string }
	raw, _ := os.ReadFile(path)
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if want := append(DefaultInterfaceBlacklist(), "mullvad", "eth0"); !reflect.DeepEqual(got.IFaceBlackList, want) {
		t.Errorf("%v", got.IFaceBlackList)
	}
}

func TestFixProfileRefusesAnInvalidInterfaceToAdd(t *testing.T) {
	f := newFixture(t)
	text := listProfile(`["wt0"]`)
	path := f.write("default.json", text)
	for _, name := range []string{"", "a/b", "eth 0", "abcdefghijklmnopq"} {
		if _, err := FixProfileWith(f.paths, "mullvad", FixRequest{Add: []string{name}}, fixOpts()); err == nil ||
			!strings.Contains(err.Error(), "--add") {
			t.Errorf("%q: %v", name, err)
		}
	}
	if got, _ := os.ReadFile(path); string(got) != text {
		t.Errorf("changed:\n%s", got)
	}
}

func TestFixProfileClearsTheExternalIPMap(t *testing.T) {
	const in = "{\n    \"PrivateKey\": \"AAAA\",\n    \"NATExternalIPs\": [\n        \"198.51.100.10/eth0\"\n    ],\n    \"IFaceBlackList\": [\n        \"wt0\",\n        \"mullvad\"\n    ],\n    \"WgPort\": 51825\n}\n"
	const want = "{\n    \"PrivateKey\": \"AAAA\",\n    \"NATExternalIPs\": [],\n    \"IFaceBlackList\": [\n        \"wt0\",\n        \"mullvad\"\n    ],\n    \"WgPort\": 51825\n}\n"
	f := newFixture(t)
	path := f.write("default.json", in)
	res, err := FixProfileWith(f.paths, "mullvad", FixRequest{ClearExternalIPMap: true}, fixOpts())
	if err != nil || !res.Changed || !res.ClearedExternalIPMap || len(res.Added) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if got, _ := os.ReadFile(path); string(got) != want {
		t.Fatalf("edited profile:\n%s", got)
	}
	// Both edits at once, and the case NetBird doesn't write but reads.
	f = newFixture(t)
	path = f.write("default.json", "{\"natexternalips\":[\"198.51.100.10\"],\"IFaceBlackList\":[\"wt0\"]}")
	res, err = FixProfileWith(f.paths, "mullvad", FixRequest{Add: []string{"eth0"}, ClearExternalIPMap: true}, fixOpts())
	if err != nil || !res.ClearedExternalIPMap || !reflect.DeepEqual(res.Added, []string{"mullvad", "eth0"}) {
		t.Fatalf("%+v %v", res, err)
	}
	if got, _ := os.ReadFile(path); string(got) != "{\"natexternalips\":[],\"IFaceBlackList\":[\"wt0\",\"mullvad\",\"eth0\"]}" {
		t.Fatalf("edited profile:\n%s", got)
	}
}

func TestFixProfileLeavesAnAbsentOrEmptyExternalIPMap(t *testing.T) {
	for _, text := range []string{
		listProfile(`["wt0", "mullvad"]`),
		"{\"NATExternalIPs\":null,\"IFaceBlackList\":[\"mullvad\"]}",
		"{\"NATExternalIPs\":[],\"IFaceBlackList\":[\"mullvad\"]}",
	} {
		f := newFixture(t)
		path := f.write("default.json", text)
		res, err := FixProfileWith(f.paths, "mullvad", FixRequest{ClearExternalIPMap: true}, fixOpts())
		if err != nil || res.Changed {
			t.Errorf("%q: %+v %v", text, res, err)
		}
		if got, _ := os.ReadFile(path); string(got) != text {
			t.Errorf("%q: content changed", text)
		}
	}
	// Without the flag a stored map is kept.
	f := newFixture(t)
	text := "{\"NATExternalIPs\":[\"198.51.100.10\"],\"IFaceBlackList\":[\"wt0\"]}"
	path := f.write("default.json", text)
	if _, err := FixProfileWith(f.paths, "mullvad", FixRequest{}, fixOpts()); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(path); !strings.Contains(string(got), "198.51.100.10") {
		t.Errorf("the map went without the flag:\n%s", got)
	}
}

func TestFixProfileRefusesAnExternalIPMapItCannotRead(t *testing.T) {
	for _, text := range []string{
		"{\"NATExternalIPs\":\"198.51.100.10\",\"IFaceBlackList\":[\"wt0\"]}",
		"{\"NATExternalIPs\":[1],\"IFaceBlackList\":[\"wt0\"]}",
		"{\"NATExternalIPs\":[],\"natexternalips\":[\"198.51.100.10\"],\"IFaceBlackList\":[\"wt0\"]}",
	} {
		f := newFixture(t)
		path := f.write("default.json", text)
		if _, err := FixProfileWith(f.paths, "mullvad", FixRequest{ClearExternalIPMap: true}, fixOpts()); err == nil {
			t.Errorf("%q: accepted", text)
		}
		if got, _ := os.ReadFile(path); string(got) != text {
			t.Errorf("%q: content changed", text)
		}
	}
}

func TestFixBlacklistIgnoresTheExternalIPMapWithoutTheFlag(t *testing.T) {
	f := newFixture(t)
	path := f.write("default.json", "{\"NATExternalIPs\":\"odd\",\"IFaceBlackList\":[\"wt0\"]}")
	res, err := FixBlacklistWith(f.paths, "mullvad", fixOpts())
	if err != nil || !res.Changed {
		t.Fatalf("%+v %v", res, err)
	}
	if got, _ := os.ReadFile(path); string(got) != "{\"NATExternalIPs\":\"odd\",\"IFaceBlackList\":[\"wt0\",\"mullvad\"]}" {
		t.Errorf("%s", got)
	}
}
