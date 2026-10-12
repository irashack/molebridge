// Ported from tools/test_host_and_routing.py (the NetBird gate's stored
// profile tests: test_netbird_gate_reads_rosenpass_as_go_does,
// test_netbird_gate_refuses_a_repeated_checked_field,
// test_netbird_gate_refuses_root_field_names_outside_ascii,
// test_netbird_gate_refuses_malformed_json,
// test_netbird_gate_refuses_an_unreadable_profile,
// test_netbird_gate_refuses_a_profile_for_another_interface,
// test_netbird_gate_accepts_a_profile_for_the_guarded_interface,
// test_netbird_gate_supports_only_the_default_profile,
// test_netbird_gate_accepts_the_default_active_profile,
// test_netbird_gate_reads_only_the_files_netbird_loads_at_start,
// test_netbird_gate_checks_the_legacy_files_netbird_migrates) and from the
// JSON reader cases of tools/check-routing.sh (json_case), which ran under
// busybox, mawk and gawk. Every case is a table row here.
package nbprofile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func profileText(rosenpass string) string {
	return "{\n    \"PrivateKey\": \"" + testKey + "\",\n    \"WgIface\": \"mesh0\",\n" +
		"    \"RosenpassEnabled\": " + rosenpass + ",\n    \"RosenpassPermissive\": false\n}\n"
}

// fixture is a state directory and two legacy profile paths in a temp dir.
type fixture struct {
	t     *testing.T
	dir   string
	paths Paths
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{t: t, dir: dir}
	f.paths = Paths{
		StateDir: filepath.Join(dir, "state"),
		Legacy:   []string{filepath.Join(dir, "etc-netbird", "config.json"), filepath.Join(dir, "etc-wiretrustee", "config.json")},
	}
	if err := os.MkdirAll(f.paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return f
}

// write stores text (a string or []byte) under name, relative to the state
// directory, or at an absolute path.
func (f *fixture) write(name string, text any) string {
	f.t.Helper()
	path := name
	if !filepath.IsAbs(name) {
		path = filepath.Join(f.paths.StateDir, name)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		f.t.Fatal(err)
	}
	var data []byte
	switch v := text.(type) {
	case string:
		data = []byte(v)
	case []byte:
		data = v
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		f.t.Fatal(err)
	}
	return path
}

// notContent fails when an error reveals anything but fixed text and a path.
func notContent(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		return
	}
	for _, s := range append(secrets, testKey[:8]) {
		if s != "" && strings.Contains(err.Error(), s) {
			t.Errorf("refusal %q reveals file content %q", err, s)
		}
	}
}

func TestNetBirdGateReadsRosenpassAsGoDoes(t *testing.T) {
	for _, text := range []string{
		profileText("true"),
		`{"PrivateKey": "` + testKey + `", "WgIface": "mesh0", "RosenpassEnabled":
  true}`,
		"{\"WgIface\":\"mesh0\",\n\"RosenpassEnabled\"\n:\ttrue\n}",
		`{"WgIface": "mesh0", "rosenpassenabled": true}`, // Go matches field names in any ASCII case
		`{"WgIface": "mesh0", "ROSENPASSENABLED": true}`,
		`{"WgIface": "mesh0", "Rosenpass\u0045nabled": true}`, // an escape that decodes to ASCII
		`{"WgIface": "mesh0", "RosenpassEnabled": null}`,      // null counts as on
		`{"WgIface": "mesh0", "RosenpassEnabled": 0}`,
		`{"WgIface": "mesh0", "RosenpassEnabled": "false"}`,
		`{"WgIface": "mesh0", "RosenpassEnabled": []}`,
		`{"WgIface": "mesh0", "RosenpassEnabled": {}}`,
	} {
		f := newFixture(t)
		f.write("default.json", text)
		err := CheckProfiles(f.paths, "mesh0")
		if err == nil || !strings.Contains(err.Error(), "Rosenpass is enabled in a stored NetBird profile") {
			t.Errorf("%q: error = %v", text, err)
		}
		if err != nil && err.Error() != "NetBird gate: refusing to start NetBird: Rosenpass is enabled in a stored NetBird profile (RosenpassEnabled) (see docs/troubleshooting.md)" {
			t.Errorf("%q: message = %q", text, err)
		}
		notContent(t, err)
	}
}

func TestNetBirdGateRefusesARepeatedCheckedField(t *testing.T) {
	for _, text := range []string{
		`{"WgIface": "mesh0", "RosenpassEnabled": false, "rosenpassEnabled": true}`,
		`{"WgIface": "mesh0", "wgiface": "mesh0"}`,
		`{"WgIface": "mesh0", "WGIFACE": "wt0"}`,
		`{"RosenpassEnabled": false, "WgIface": "mesh0", "RosenpassEnabled": false}`,
	} {
		f := newFixture(t)
		path := f.write("default.json", text)
		err := CheckProfiles(f.paths, "mesh0")
		want := "NetBird gate: refusing to start NetBird: the stored NetBird profile " + path + " repeats WgIface or RosenpassEnabled (see docs/troubleshooting.md)"
		if err == nil || err.Error() != want {
			t.Errorf("%q: error = %v", text, err)
		}
	}
}

func TestNetBirdGateRefusesRootFieldNamesOutsideASCII(t *testing.T) {
	for _, text := range []string{
		"{\"WgIface\": \"mesh0\", \"R\u00f6senpassEnabled\": true}", // a non-ASCII field name
		"{\"WgIface\": \"mesh0\", \"Ro\u017fenpassEnabled\": true}", // long s, which Go folds to s
		`{"WgIface": "mesh0", "\u212aey": 1}`,                       // Kelvin sign, as an escape
		`{"WgIface": "mesh0", "Wg\tIface": "wt0"}`,
		`{"WgIface": "mesh0", "Key\u007f": 1}`,
		`{"WgIface": "mesh0", "Key\u0000": 1}`,
	} {
		f := newFixture(t)
		path := f.write("default.json", text)
		err := CheckProfiles(f.paths, "mesh0")
		want := "NetBird gate: refusing to start NetBird: the stored NetBird profile " + path + " has a field name outside printable ASCII (see docs/troubleshooting.md)"
		if err == nil || err.Error() != want {
			t.Errorf("%q: error = %v", text, err)
		}
	}
}

func TestNetBirdGateRefusesMalformedJSON(t *testing.T) {
	for _, text := range []any{
		`["WgIface", "mesh0"]`, `"mesh0"`, ``, `   `, `null`, `123`, `true`,
		`{"WgIface": "mesh0"`, `{"WgIface": "mesh0"} {}`, `{"WgIface": "mesh0"}x`,
		`{"WgIface": "mesh0",}`, `{"WgIface" "mesh0"}`, `{'WgIface': 'mesh0'}`, `{`, `{"a"`, `{"a":`, `{"a":1`,
		`{"WgIface": "mesh0", "Port": 01}`, `{"WgIface": "mesh0", "Port": 1.}`, `{"WgIface": "mesh0", "Port": -}`,
		`{"WgIface": "mesh0", "Port": 1e}`, `{"WgIface": "mesh0", "Port": .5}`, `{"WgIface": "mesh0", "Port": +1}`,
		`{"WgIface": "mesh0", "On": tru}`, `{"WgIface": "mesh0", "On": truex}`, `{"WgIface": "mesh0", "On": True}`,
		`{"WgIface": "mesh0", "Name": "a\qb"}`, `{"WgIface": "mesh0", "Name": "\u00g0"}`, `{"WgIface": "mesh0", "Name": "\u00"}`,
		"{\"WgIface\": \"mesh0\", \"Name\": \"tab\there\"}", // raw control character in a string
		`{"WgIface": "mesh0", "Name": "unterminated}`,
		`{"WgIface": "mesh0", "List": [1, 2,]}`, `{"WgIface": "mesh0", "List": [1 2]}`, `{"WgIface": "mesh0", "List": [,1]}`,
		`{"WgIface": "mesh0", "Obj": {"a": 1]}`, `{"WgIface": "mesh0", "Obj": {"a": 1,}}`, `{"WgIface": "mesh0", "Obj": {1: 1}}`,
		[]byte("{\"WgIface\": \"mesh0\", \"Name\": \"a\x00b\"}"),
		[]byte("{\"WgIface\": \"mesh0\", \"Name\": \"a\xffb\"}"), // invalid UTF-8
		[]byte("\xef\xbb\xbf{\"WgIface\": \"mesh0\"}"),           // a byte order mark
		// A repeated key in a nested object is fine for the gate, but a
		// document nested deeper than encoding/json allows is not.
		strings.Repeat("[", 20000),
		`{"a":` + strings.Repeat("[", 10001) + strings.Repeat("]", 10001) + `}`,
	} {
		f := newFixture(t)
		path := f.write("default.json", text)
		err := CheckProfiles(f.paths, "mesh0")
		want := "NetBird gate: refusing to start NetBird: the stored NetBird profile " + path + " is not a valid JSON object (see docs/troubleshooting.md)"
		if err == nil || err.Error() != want {
			t.Errorf("%.60q: error = %v", text, err)
		}
	}
}

func TestNetBirdGateAcceptsDeepNestingUpToTheDaemonLimit(t *testing.T) {
	f := newFixture(t)
	f.write("default.json", `{"WgIface": "mesh0", "a":`+strings.Repeat("[", 9999)+strings.Repeat("]", 9999)+`}`)
	if err := CheckProfiles(f.paths, "mesh0"); err != nil {
		t.Fatal(err)
	}
}

func TestNetBirdGateRefusesAnOversizeProfile(t *testing.T) {
	f := newFixture(t)
	path := f.write("default.json", `{"WgIface": "mesh0", "Pad": "`+strings.Repeat("x", 1<<20)+`"}`)
	err := CheckProfiles(f.paths, "mesh0")
	if err == nil || !strings.Contains(err.Error(), "the stored NetBird profile "+path+" is not a valid JSON object") {
		t.Fatalf("error = %v", err)
	}
	// Exactly the bound is accepted.
	body := `{"WgIface": "mesh0", "Pad": "`
	f.write("default.json", body+strings.Repeat("x", (1<<20)-len(body)-2)+`"}`)
	if st, _ := os.Stat(path); st.Size() != 1<<20 {
		t.Fatalf("fixture size = %d", st.Size())
	}
	if err := CheckProfiles(f.paths, "mesh0"); err != nil {
		t.Fatalf("a profile of exactly 1 MiB: %v", err)
	}
}

func TestNetBirdGateRefusesAnUnreadableProfile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads mode 0 files")
	}
	f := newFixture(t)
	path := f.write("default.json", profileText("false"))
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	err := CheckProfiles(f.paths, "mesh0")
	want := "NetBird gate: refusing to start NetBird: cannot read the stored NetBird profile " + path + " (see docs/troubleshooting.md)"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v", err)
	}
}

// The gate used [ -r ], which follows symlinks; the Go reader does not (it
// opens with O_NOFOLLOW), and refuses a directory, a dangling link and a FIFO.
func TestNetBirdGateRefusesAProfileThatIsNotARegularFile(t *testing.T) {
	f := newFixture(t)
	target := f.write(filepath.Join(f.dir, "real.json"), profileText("false"))
	for name, make := range map[string]func(path string) error{
		"symlink":  func(p string) error { return os.Symlink(target, p) },
		"dangling": func(p string) error { return os.Symlink(filepath.Join(f.dir, "nowhere"), p) },
		"dir":      func(p string) error { return os.Mkdir(p, 0o700) },
		"fifo":     func(p string) error { return mkfifo(p) },
	} {
		path := filepath.Join(f.paths.StateDir, "default.json")
		_ = os.Remove(path)
		if err := make(path); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		err := CheckProfiles(f.paths, "mesh0")
		want := "NetBird gate: refusing to start NetBird: cannot read the stored NetBird profile " + path + " (see docs/troubleshooting.md)"
		if err == nil || err.Error() != want {
			t.Errorf("%s: error = %v", name, err)
		}
		_ = os.Remove(path)
	}
}

func TestNetBirdGateRefusesAProfileForAnotherInterface(t *testing.T) {
	for _, c := range []struct{ text, iface string }{
		{`{"WgIface": "wt0"}`, "mesh0"},
		{`{"PrivateKey": "` + testKey + `"}`, "mesh0"}, // absent: NetBird uses wt0
		{`{"WgIface": ""}`, "mesh0"},                   // empty: NetBird uses wt0
		{`{"WgIface": null}`, "mesh0"},
		{`{"WgIface": 5}`, "mesh0"},
		{`{"WgIface": ["mesh0"]}`, "mesh0"},
		{`{"WgIface": "mesh00"}`, "mesh0"},
		{`{"WgIface": "mesh\u0030 "}`, "mesh0"},
		{`{"WgIface": "mesh0", "Extra": {"WgIface": "mesh0"}}`, "wt0"},
		{`{"Extra": {"WgIface": "mesh0"}, "RosenpassEnabled": false}`, "mesh0"}, // nested: not the field
		{`{"Wg Iface": "mesh0", "RosenpassEnabled": false}`, "mesh0"},           // another field
		{`{"List": [{"WgIface": "mesh0"}]}`, "mesh0"},
		{`{"WgIface": "mesh0"}`, "wt0"},
		{`{"WgIface": "MESH0"}`, "mesh0"}, // the value is compared exactly
		{`{}`, "mesh0"},
	} {
		f := newFixture(t)
		path := f.write("default.json", c.text)
		err := CheckProfiles(f.paths, c.iface)
		want := "NetBird gate: refusing to start NetBird: a stored NetBird profile (" + path + ") uses a WireGuard interface other than " + c.iface + " (WgIface) (see docs/troubleshooting.md)"
		if err == nil || err.Error() != want {
			t.Errorf("%q on %s: error = %v", c.text, c.iface, err)
		}
		notContent(t, err)
	}
}

func TestNetBirdGateAcceptsAProfileForTheGuardedInterface(t *testing.T) {
	for _, c := range []struct{ text, iface string }{
		{`{"PrivateKey": "` + testKey + `"}`, "wt0"},
		{`{"WgIface": ""}`, "wt0"},
		{`{"wgiface": "mesh0", "RosenpassEnabled": false}`, "mesh0"},
		{`{"WgIface": "mesh\u0030"}`, "mesh0"},
		{"{\n  \"WgIface\":\n    \"wt0\",\n  \"SSHKey\": \"-----BEGIN-----\\nAAAA\\n-----END-----\\n\"\n}", "wt0"},
		// Escapes, Unicode and nesting in unrelated fields are fine.
		{`{"Name": "R\u0026D \u00e9t\u00e9 \ud83d\ude00 \"q\" \\ \/", "WgIface": "mesh0"}`, "mesh0"},
		{"{\"Name\": \"caf\u00e9\", \"WgIface\": \"mesh0\", \"ManagementURL\": {\"Scheme\": \"https\", \"Host\": \"example.net\"}}", "mesh0"},
		{`{"WgIface": "mesh0", "Nested": {"RosenpassEnabled": true, "WgIface": "wt0", "WgIface": "x"}}`, "mesh0"},
		{`{"WgIface": "mesh0", "Numbers": [0, -1, 2.5, 1e3, -0.5E-2, 10], "Flags": [true, false, null], "Empty": {}, "None": []}`, "mesh0"},
		{`{"WgIface": "mesh0", "RosenpassEnabled": false}`, "mesh0"},
		// check-routing.sh: escapes, Unicode and nesting in other fields.
		{`{"Name": "R&D é 😀 \"q\" \\ \/", "WgIface": "mesh0",
          "Nested": {"WgIface": "wt0", "RosenpassEnabled": true}, "List": [0, -2.5e3, true, null, {}, []]}`, "mesh0"},
		{`{"WgIface": "mesh0", "Lone": "\ud800 \udc00 \ud800\u0041"}`, "mesh0"}, // lone surrogates decode to U+FFFD in Go
		{"\t\r\n {\"WgIface\": \"mesh0\"} \r\n", "mesh0"},
	} {
		f := newFixture(t)
		f.write("default.json", c.text)
		if err := CheckProfiles(f.paths, c.iface); err != nil {
			t.Errorf("%q on %s: %v", c.text, c.iface, err)
		}
	}
}

func TestNetBirdGateSupportsOnlyTheDefaultProfile(t *testing.T) {
	for _, state := range []string{
		`{"name": "alternate", "username": ""}`,
		`{"name": "alternate", "username": "root"}`,
		`{"Name": "alternate"}`, // Go matches "name" in any case
		`{"name": null}`,
		`{"name": 1}`,
		`{"name": "def\u0061ult2"}`,
		`{"name": "Default"}`,
		`{"name": " default"}`,
		`{"name": "def\u00e1ult"}`,
	} {
		f := newFixture(t)
		f.write("default.json", profileText("false"))
		path := f.write("active_profile.json", state)
		err := CheckProfiles(f.paths, "mesh0")
		want := "NetBird gate: refusing to start NetBird: the active NetBird profile is not the default profile (" + path + ") (see docs/troubleshooting.md)"
		if err == nil || err.Error() != want {
			t.Errorf("%q: error = %v", state, err)
		}
	}
	for _, state := range []string{`{"name": "default", "NAME": "alternate"}`, `{"name": "default", "name": "default"}`,
		`not json`, `[]`, ``, `{"name": "default"} x`, `{"Na\u00efve": 1}`} {
		f := newFixture(t)
		f.write("default.json", profileText("false"))
		path := f.write("active_profile.json", state)
		err := CheckProfiles(f.paths, "mesh0")
		want := "NetBird gate: refusing to start NetBird: the active NetBird profile state " + path + " is not a valid JSON object (see docs/troubleshooting.md)"
		if err == nil || err.Error() != want {
			t.Errorf("%q: error = %v", state, err)
		}
	}
}

func TestNetBirdGateRefusesAnUnreadableActiveProfileState(t *testing.T) {
	f := newFixture(t)
	f.write("default.json", profileText("false"))
	path := filepath.Join(f.paths.StateDir, "active_profile.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	err := CheckProfiles(f.paths, "mesh0")
	want := "NetBird gate: refusing to start NetBird: cannot read the active NetBird profile state " + path + " (see docs/troubleshooting.md)"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v", err)
	}
}

func TestNetBirdGateAcceptsTheDefaultActiveProfile(t *testing.T) {
	for _, state := range []string{`{"name": "default", "username": ""}`, `{"name": "default", "username": "root"}`,
		`{"name": ""}`, `{}`, `{"username": "root"}`, `{"name": "def\u0061ult"}`, `{"NAME": "default"}`,
		`{"name": "default", "extra": {"name": "alternate"}}`} {
		f := newFixture(t)
		f.write("default.json", profileText("false"))
		f.write("active_profile.json", state)
		if err := CheckProfiles(f.paths, "mesh0"); err != nil {
			t.Errorf("%q: %v", state, err)
		}
	}
}

func TestNetBirdGateReadsOnlyTheFilesNetBirdLoadsAtStart(t *testing.T) {
	// Other profiles and state files cannot be loaded at start while the
	// active profile is the default one.
	f := newFixture(t)
	f.write("default.json", profileText("false"))
	f.write("root/0123456789abcdef.json", `{"WgIface": "wt0", "RosenpassEnabled": true}`)
	f.write("root/0123456789abcdef.state.json", `{"email": "user@example.net"}`)
	f.write("state.json", `not json`)
	f.write("active_profile.json", `{"name": "default", "username": "root"}`)
	if err := CheckProfiles(f.paths, "mesh0"); err != nil {
		t.Fatal(err)
	}
}

func TestNetBirdGateChecksTheLegacyFilesNetBirdMigrates(t *testing.T) {
	for i, name := range []string{"/etc/netbird/config.json", "/etc/wiretrustee/config.json"} {
		f := newFixture(t)
		legacy := f.paths.Legacy[i]
		f.write(legacy, `{"WgIface": "mesh0", "RosenpassEnabled": true}`)
		if err := CheckProfiles(f.paths, "mesh0"); err == nil || !strings.Contains(err.Error(), "Rosenpass is enabled") {
			t.Errorf("%s: %v", name, err)
		}
		f.write(legacy, `{"WgIface": "wt0"}`)
		if err := CheckProfiles(f.paths, "mesh0"); err == nil || !strings.Contains(err.Error(), "other than mesh0") ||
			!strings.Contains(err.Error(), legacy) {
			t.Errorf("%s: %v", name, err)
		}
		f.write(legacy, `{"WgIface": "mesh0"}`)
		if err := CheckProfiles(f.paths, "mesh0"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The gate checks every one of the three files that exists, not only the one
// NetBird would load.
func TestNetBirdGateChecksEveryStoredProfileThatExists(t *testing.T) {
	f := newFixture(t)
	f.write("default.json", profileText("false"))
	f.write(f.paths.Legacy[0], `{"WgIface": "mesh0"}`)
	f.write(f.paths.Legacy[1], `{"WgIface": "mesh0", "RosenpassEnabled": true}`)
	if err := CheckProfiles(f.paths, "mesh0"); err == nil || !strings.Contains(err.Error(), "Rosenpass") {
		t.Fatalf("error = %v", err)
	}
}

func TestNetBirdGateWithNoStoredProfileAccepts(t *testing.T) {
	f := newFixture(t)
	if err := CheckProfiles(f.paths, "mesh0"); err != nil {
		t.Fatal(err)
	}
}

// check-routing.sh's json_case table: accept or refuse a default.json, with
// an optional active_profile.json, for the guarded interface mesh0.
func TestJSONReaderCases(t *testing.T) {
	for _, c := range []struct {
		accept bool
		name   string
		text   string
		active string
	}{
		{true, "a plain profile", `{"WgIface": "mesh0", "RosenpassEnabled": false}`, ""},
		{true, "escapes, Unicode and nesting in other fields",
			`{"Name": "R&D é 😀 \"q\" \\ \/", "WgIface": "mesh0",
          "Nested": {"WgIface": "wt0", "RosenpassEnabled": true}, "List": [0, -2.5e3, true, null, {}, []]}`, ""},
		{false, "Rosenpass across lines", `{"WgIface": "mesh0", "RosenpassEnabled":
        true}`, ""},
		{false, "an escaped Rosenpass field name", `{"WgIface": "mesh0", "Rosenpass\u0045nabled": true}`, ""},
		{false, "Rosenpass null", `{"WgIface": "mesh0", "RosenpassEnabled": null}`, ""},
		{false, "a field repeated in another case", `{"WgIface": "mesh0", "wgiface": "mesh0"}`, ""},
		{false, "a nested WgIface only", `{"Extra": {"WgIface": "mesh0"}}`, ""},
		{false, `a "Wg Iface" field only`, `{"Wg Iface": "mesh0"}`, ""},
		{false, "a field name escaped outside ASCII", `{"WgIface": "mesh0", "K\u00e9y": 1}`, ""},
		{false, "a field name with a non-ASCII byte", "{\"WgIface\": \"mesh0\", \"R\u00f6senpassEnabled\": true}", ""},
		{false, "a top-level array", `["WgIface", "mesh0"]`, ""},
		{false, "trailing data", `{"WgIface": "mesh0"} {}`, ""},
		{false, "a bad number", `{"WgIface": "mesh0", "Port": 01}`, ""},
		{false, "a bad escape", `{"WgIface": "mesh0", "Name": "a\qb"}`, ""},
		{false, "another active profile", `{"WgIface": "mesh0"}`, `{"name": "alternate", "username": ""}`},
		{true, "the default active profile", `{"WgIface": "mesh0"}`, `{"name": "default", "username": ""}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			f.write("default.json", c.text+"\n")
			if c.active != "" {
				f.write("active_profile.json", c.active+"\n")
			}
			err := CheckProfiles(f.paths, "mesh0")
			if c.accept != (err == nil) {
				t.Fatalf("accept=%v, error = %v", c.accept, err)
			}
		})
	}
	t.Run("Rosenpass in the legacy profile", func(t *testing.T) {
		f := newFixture(t)
		f.write("default.json", `{"WgIface": "mesh0"}`+"\n")
		f.write(f.paths.Legacy[0], `{"WgIface": "mesh0", "RosenpassEnabled": true}`+"\n")
		if err := CheckProfiles(f.paths, "mesh0"); err == nil {
			t.Fatal("accepted")
		}
	})
}

// CheckAll runs the common settings, then the profiles, then the backend's
// settings, as the gate did.
func TestCheckAllOrder(t *testing.T) {
	f := newFixture(t)
	f.write("default.json", profileText("true"))
	env := gluetunEnv(map[string]string{"NB_INTERFACE_NAME": "mesh0", "NB_SKIP_SOCKET_MARK": "1"})
	if _, err := CheckAll(env, "", f.paths); err == nil || !strings.Contains(err.Error(), "Rosenpass is enabled") {
		t.Fatalf("a bad profile comes before a gluetun setting: %v", err)
	}
	f.write("default.json", profileText("false"))
	if _, err := CheckAll(env, "", f.paths); err == nil || !strings.Contains(err.Error(), "NB_SKIP_SOCKET_MARK") {
		t.Fatalf("error = %v", err)
	}
	delete(env, "NB_SKIP_SOCKET_MARK")
	env["NB_STATE_DIR"] = f.paths.StateDir
	s, err := CheckAll(env, "", Paths{})
	if err != nil || s.OverlayIF != "mesh0" || s.Backend != BackendGluetun {
		t.Fatalf("settings = %+v, %v", s, err)
	}
	env["WT_CONFIG"] = "x"
	if _, err := CheckAll(env, "", f.paths); err == nil || !strings.Contains(err.Error(), "WT_CONFIG is set") {
		t.Fatalf("error = %v", err)
	}
}
