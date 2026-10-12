// New in 0.8.0 (D25): no Python counterpart. The shell's check of the stored
// ICE blacklist lived in tools/molebridge.py:775 (doctor, removed by D22);
// these tests cover the start-time check that replaces it.
package nbprofile

import (
	"os"
	"strings"
	"testing"
)

func listProfile(list string) string {
	return "{\n    \"PrivateKey\": \"" + testKey + "\",\n    \"WgIface\": \"mesh0\",\n    \"IFaceBlackList\": " + list + "\n}\n"
}

func refusalFor(path, tunnel string) string {
	return "NetBird gate: refusing to start NetBird: the stored NetBird profile " + path +
		" does not exclude the tunnel interface " + tunnel +
		" from NetBird's connection candidates; stop the exit and run fix-blacklist" +
		" (docs/operations.md#netbird-interface-blacklist) (see docs/troubleshooting.md)"
}

func TestDefaultInterfaceBlacklistIsNetBird0800s(t *testing.T) {
	// client/internal/profilemanager/config.go:56-59 at v0.80.0.
	want := []string{"wt0", "wt", "utun", "tun0", "zt", "ZeroTier", "wg", "ts", "Tailscale", "tailscale", "docker", "veth", "br-", "lo"}
	got := DefaultInterfaceBlacklist()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("defaults = %v", got)
	}
	got[0] = "changed"
	if DefaultInterfaceBlacklist()[0] != "wt0" {
		t.Fatal("the default list is shared")
	}
}

func TestCheckBlacklistRequiresTheTunnelInterface(t *testing.T) {
	for _, c := range []struct {
		name string
		text string
		ok   bool
	}{
		{"populated with the tunnel", listProfile(`["wt0", "docker", "mullvad"]`), true},
		{"only the tunnel", listProfile(`["mullvad"]`), true},
		{"the host interface is never required", listProfile(`["mullvad", "lo"]`), true},
		{"entry spelled with an escape", listProfile(`["mullvad"]`), true},
		{"case-variant key", "{\"ifaceblacklist\": [\"mullvad\"]}", true},
		{"missing key", `{"WgIface": "mesh0"}`, false},
		{"null", listProfile(`null`), false},
		{"empty", listProfile(`[]`), false},
		{"populated without the tunnel", listProfile(`["wt0", "docker"]`), false},
		{"the host interface only", listProfile(`["eth0"]`), false},
		{"entries are exact names", listProfile(`["mullvad0"]`), false},
		{"entries are case-sensitive", listProfile(`["Mullvad"]`), false},
		{"another case of the tunnel in a key", `{"Nested": {"IFaceBlackList": ["mullvad"]}}`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			path := f.write("default.json", c.text)
			res, err := CheckBlacklist(f.paths, "mullvad")
			if c.ok {
				if err != nil || res.NoIdentity || res.Path != path {
					t.Fatalf("result %+v, error %v", res, err)
				}
				return
			}
			if err == nil || err.Error() != refusalFor(path, "mullvad") {
				t.Fatalf("error = %v", err)
			}
			notContent(t, err)
		})
	}
}

func TestCheckBlacklistRefusesAnUnusableList(t *testing.T) {
	for _, list := range []string{`"mullvad"`, `{"mullvad": true}`, `["mullvad", 1]`, `["mullvad", null]`, `[["mullvad"]]`, `true`, `7`} {
		f := newFixture(t)
		path := f.write("default.json", listProfile(list))
		_, err := CheckBlacklist(f.paths, "mullvad")
		want := "NetBird gate: refusing to start NetBird: the stored NetBird profile " + path +
			" has an IFaceBlackList that is not a list of strings; stop the exit and run fix-blacklist" +
			" (docs/operations.md#netbird-interface-blacklist) (see docs/troubleshooting.md)"
		if err == nil || err.Error() != want {
			t.Errorf("%s: error = %v", list, err)
		}
	}
}

func TestCheckBlacklistRefusesAmbiguousFiles(t *testing.T) {
	f := newFixture(t)
	path := f.write("default.json", `{"IFaceBlackList": ["mullvad"], "ifaceblacklist": []}`)
	_, err := CheckBlacklist(f.paths, "mullvad")
	want := "NetBird gate: refusing to start NetBird: the stored NetBird profile " + path + " repeats IFaceBlackList (see docs/troubleshooting.md)"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v", err)
	}
	for text, frag := range map[string]string{
		`{"IFaceBlackList": ["mullvad"`:                                   "is not a valid JSON object",
		`{"IFaceBlackList": ["mullvad"], "Köy": 1}`:                       "field name outside printable ASCII",
		`{"WgIface": "a", "wgiface": "a", "IFaceBlackList": ["mullvad"]}`: "repeats WgIface or RosenpassEnabled",
	} {
		f.write("default.json", text)
		if _, err := CheckBlacklist(f.paths, "mullvad"); err == nil || !strings.Contains(err.Error(), frag) {
			t.Errorf("%q: error = %v", text, err)
		}
	}
}

func TestCheckBlacklistWithoutAnIdentityIsNotARefusal(t *testing.T) {
	f := newFixture(t)
	res, err := CheckBlacklist(f.paths, "mullvad")
	if err != nil || !res.NoIdentity || res.Path != "" {
		t.Fatalf("result %+v, error %v", res, err)
	}
	if !strings.Contains(NoIdentityNotice, "enroll a new peer") || res.String() != NoIdentityNotice {
		t.Fatalf("notice = %q / %q", NoIdentityNotice, res.String())
	}
}

// The check reads the profile the daemon will load: the default profile, else
// the legacy file NetBird copies into it.
func TestCheckBlacklistResolvesTheProfileTheDaemonLoads(t *testing.T) {
	f := newFixture(t)
	good, bad := listProfile(`["mullvad"]`), listProfile(`["wt0"]`)

	// Only the legacy files: the first that exists is the one.
	f.write(f.paths.Legacy[1], bad)
	if _, err := CheckBlacklist(f.paths, "mullvad"); err == nil || !strings.Contains(err.Error(), f.paths.Legacy[1]) {
		t.Fatalf("wiretrustee profile: %v", err)
	}
	f.write(f.paths.Legacy[0], good)
	res, err := CheckBlacklist(f.paths, "mullvad")
	if err != nil || res.Path != f.paths.Legacy[0] {
		t.Fatalf("netbird legacy profile: %+v, %v", res, err)
	}
	// The default profile wins; the legacy copy is then never read.
	def := f.write("default.json", bad)
	if _, err := CheckBlacklist(f.paths, "mullvad"); err == nil || !strings.Contains(err.Error(), def) {
		t.Fatalf("default profile: %v", err)
	}
	f.write("default.json", good)
	f.write(f.paths.Legacy[0], bad)
	res, err = CheckBlacklist(f.paths, "mullvad")
	if err != nil || res.Path != def {
		t.Fatalf("default over legacy: %+v, %v", res, err)
	}
}

func TestCheckBlacklistRefusesAnotherActiveProfile(t *testing.T) {
	f := newFixture(t)
	f.write("default.json", listProfile(`["mullvad"]`))
	f.write("active_profile.json", `{"name": "alternate"}`)
	if _, err := CheckBlacklist(f.paths, "mullvad"); err == nil || !strings.Contains(err.Error(), "the active NetBird profile is not the default profile") {
		t.Fatalf("error = %v", err)
	}
}

func TestCheckBlacklistRefusesAnInvalidTunnelName(t *testing.T) {
	f := newFixture(t)
	f.write("default.json", listProfile(`["mullvad"]`))
	for _, name := range []string{"", "a b", `a"b`, "../x", "abcdefghijklmnop"} {
		if _, err := CheckBlacklist(f.paths, name); err == nil || !strings.Contains(err.Error(), "the tunnel interface name is invalid") {
			t.Errorf("%q: error = %v", name, err)
		}
	}
}

func TestCheckBlacklistAfterUp(t *testing.T) {
	f := newFixture(t)
	if err := CheckBlacklistAfterUp(f.paths, "mesh0", "mullvad"); err == nil ||
		!strings.Contains(err.Error(), "wrote no stored profile after `netbird up`") {
		t.Fatalf("no profile after up: %v", err)
	}
	path := f.write("default.json", listProfile(`["wt0"]`))
	if err := CheckBlacklistAfterUp(f.paths, "mesh0", "mullvad"); err == nil || err.Error() != refusalFor(path, "mullvad") {
		t.Fatalf("missing entry: %v", err)
	}
	f.write("default.json", listProfile(`["wt0", "mullvad"]`))
	if err := CheckBlacklistAfterUp(f.paths, "mesh0", "mullvad"); err != nil {
		t.Fatalf("entry in place: %v", err)
	}
	// The re-read applies the profile checks too.
	f.write("default.json", `{"WgIface": "mesh0", "RosenpassEnabled": true, "IFaceBlackList": ["mullvad"]}`)
	if err := CheckBlacklistAfterUp(f.paths, "mesh0", "mullvad"); err == nil || !strings.Contains(err.Error(), "Rosenpass") {
		t.Fatalf("rosenpass after up: %v", err)
	}
	f.write("default.json", `{"WgIface": "other0", "IFaceBlackList": ["mullvad"]}`)
	if err := CheckBlacklistAfterUp(f.paths, "mesh0", "mullvad"); err == nil || !strings.Contains(err.Error(), "other than mesh0") {
		t.Fatalf("interface after up: %v", err)
	}
}

func TestRefusalsNeverContainFileContent(t *testing.T) {
	const marker = "SECRETMARKER0123"
	for _, text := range []string{
		`{"PrivateKey": "` + marker + `", "WgIface": "other0"}`,
		`{"PrivateKey": "` + marker + `", "WgIface": "mesh0", "RosenpassEnabled": true}`,
		`{"PrivateKey": "` + marker + `", "WgIface": "mesh0", "wgiface": "mesh0"}`,
		`{"PrivateKey": "` + marker + `", "WgIface": "mesh0", "Köy": 1}`,
		`{"PrivateKey": "` + marker + `", "WgIface": "mesh0",`,
		`{"PrivateKey": "` + marker + `", "WgIface": "mesh0", "x": "\q"}`,
		`{"PrivateKey": "` + marker + `", "WgIface": "mesh0", "IFaceBlackList": "` + marker + `"}`,
		`{"PrivateKey": "` + marker + `", "WgIface": "mesh0", "IFaceBlackList": ["` + marker + `"]}`,
		`{"PrivateKey": "` + marker + `", "WgIface": "mesh0", "IFaceBlackList": ["` + marker + `"], "ifaceblacklist": []}`,
		`{"PrivateKey": "` + marker + `", "WgIface": "` + marker + `"}`,
	} {
		f := newFixture(t)
		f.write("default.json", text)
		for _, check := range []func() error{
			func() error { return CheckProfiles(f.paths, "mesh0") },
			func() error { _, err := CheckBlacklist(f.paths, "mullvad"); return err },
			func() error { return CheckBlacklistAfterUp(f.paths, "mesh0", "mullvad") },
			func() error {
				_, err := FixBlacklistWith(f.paths, "mullvad", FixOptions{SocketAnswers: func(string) bool { return false }})
				return err
			},
		} {
			notContent(t, check(), marker)
		}
	}
	f := newFixture(t)
	f.write("active_profile.json", `{"name": "`+marker+`"}`)
	notContent(t, CheckProfiles(f.paths, "mesh0"), marker)
	if _, err := os.Stat(f.paths.StateDir); err != nil {
		t.Fatal(err)
	}
}
