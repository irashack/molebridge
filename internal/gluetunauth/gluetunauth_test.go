package gluetunauth

// Ported from the helper parts of tools/test_gluetun_client.py (read_api_key
// and gluetun_auth_config), tools/test_gluetun_applier.py
// (test_auth_file_takes_only_url_safe_keys) and tools/test_gluetun.py (the
// role-file check against routing/gluetun-preflight, test_preflight_default_role,
// test_python_and_preflight_agree_on_the_generated_file). The control-server
// client parts of those files belong to the exit worker.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const apiKey = "Zx9-_" + "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"

func keyFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Skipf("cannot set mode %v here: %v", mode, err)
	}
	return path
}

func wantKeyError(t *testing.T, path string) {
	t.Helper()
	_, err := ReadAPIKey(path)
	if err == nil || err.Error() != "cannot read gluetun API key" {
		t.Errorf("%s: %v", path, err)
	}
}

func TestRestrictiveKeyMode(t *testing.T) { // test_restrictive_key_mode
	for _, mode := range []os.FileMode{0o600, 0o400} {
		if got, err := ReadAPIKey(keyFile(t, apiKey+"\n", mode)); err != nil || got != apiKey {
			t.Errorf("%v: %q %v", mode, got, err)
		}
	}
}

func TestExposedKeyMode(t *testing.T) { // test_exposed_key_mode
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o700} {
		wantKeyError(t, keyFile(t, apiKey+"\n", mode))
	}
	wantKeyError(t, keyFile(t, apiKey+"\n", 0o600|os.ModeSticky)) // 0o1600
}

func TestSpecialKeyMode(t *testing.T) { // test_special_key_mode
	wantKeyError(t, keyFile(t, apiKey+"\n", 0o600|os.ModeSetuid))
	wantKeyError(t, keyFile(t, apiKey+"\n", 0o600|os.ModeSetgid))
}

func TestBadKeyFile(t *testing.T) { // test_bad_key_file
	for name, raw := range map[string]string{
		"empty": "", "newline": "\n", "high byte": "\xff", "two lines": "key\nother", "bare cr": "key\r",
		"nul": "key\x00", "tab": "key\t", "del": "key\x7f", "esc": "key\x1b", "leading space": " key",
		"trailing space": "key ", "too big": strings.Repeat("x", MaxKeyBytes+1), "crlf then more": "key\r\n\n",
		"two newlines": "key\n\n",
	} {
		path := keyFile(t, raw, 0o600)
		if _, err := ReadAPIKey(path); err == nil || err.Error() != "cannot read gluetun API key" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if got, err := ReadAPIKey(keyFile(t, strings.Repeat("x", MaxKeyBytes), 0o600)); err != nil || len(got) != MaxKeyBytes {
		t.Errorf("a key of exactly the limit: %v", err)
	}
}

func TestKeyNewline(t *testing.T) { // test_key_newline
	for _, ending := range []string{"", "\n", "\r\n"} {
		if got, err := ReadAPIKey(keyFile(t, apiKey+ending, 0o600)); err != nil || got != apiKey {
			t.Errorf("%q: %q %v", ending, got, err)
		}
	}
}

func TestUnsafeKeyFile(t *testing.T) { // test_unsafe_key_file
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte(apiKey), 0o600)
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(dir, "directory")
	os.Mkdir(directory, 0o600)
	for _, path := range []string{link, fifo, directory, filepath.Join(dir, "missing")} {
		wantKeyError(t, path)
	}
}

func TestAuthConfig(t *testing.T) { // test_auth_config
	got, err := AuthConfig("example-role")
	want := "[[roles]]\nname = \"example-role\"\nauth = \"apikey\"\napikey = \"\"\n" +
		`routes = ["PUT /v1/vpn/settings", "GET /v1/vpn/status", "GET /v1/publicip/ip", "GET /v1/updater/status", "PUT /v1/updater/status"]` + "\n"
	if err != nil || got != want {
		t.Errorf("%q %v", got, err)
	}
	if len(Routes) != 5 {
		t.Errorf("routes %v", Routes)
	}
}

func TestBadAuthRole(t *testing.T) { // test_bad_auth_role
	for _, role := range []string{"", strings.Repeat("x", 65), "role\n", `role"`, "role name", "[roles]", "-lead", "_lead"} {
		if _, err := AuthConfig(role); err == nil || err.Error() != "invalid gluetun role name" {
			t.Errorf("%q: %v", role, err)
		}
	}
	for _, role := range []string{"a", "molebridge", strings.Repeat("x", 64), "A_b-9"} {
		if _, err := AuthConfig(role); err != nil {
			t.Errorf("%q: %v", role, err)
		}
	}
}

func TestAuthFileTakesOnlyURLSafeKeys(t *testing.T) { // test_auth_file_takes_only_url_safe_keys
	good := strings.Repeat("k", 43)
	text, err := AuthFile(good, DefaultRoleName)
	if err != nil || !strings.Contains(text, `apikey = "`+good+`"`) {
		t.Fatalf("%q %v", text, err)
	}
	for _, bad := range []string{"short", strings.Repeat("k", 42) + `"`, strings.Repeat("k", 42) + "\n", strings.Repeat("k", 129), "", strings.Repeat("k", 31), strings.Repeat("é", 40)} {
		if _, err := AuthFile(bad, DefaultRoleName); err == nil || err.Error() != "invalid gluetun API key" {
			t.Errorf("%q: %v", bad, err)
		}
	}
	for _, ok := range []string{strings.Repeat("k", 32), strings.Repeat("k", 128), "A-_" + strings.Repeat("0", 29)} {
		if _, err := AuthFile(ok, DefaultRoleName); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	if _, err := AuthFile(good, "bad role"); err == nil {
		t.Error("a bad role name was accepted")
	}
}

func validRoleFile(t *testing.T) string {
	t.Helper()
	text, err := AuthFile(apiKey, DefaultRoleName)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func TestValidAuthFileAcceptsExactlyWhatIsGenerated(t *testing.T) { // test_python_and_preflight_agree_on_the_generated_file
	text := validRoleFile(t)
	if !ValidAuthFile(text) || !ValidAuthFile(strings.TrimSuffix(text, "\n")) {
		t.Error("the generated file is not valid")
	}
}

var brokenRoleFiles = map[string]func(string) string{
	"misspelled key field": func(s string) string { return strings.Replace(s, "apikey = ", "api_key = ", 1) },
	"extra field":          func(s string) string { return s + `password = "` + apiKey + "\"\n" },
	"extra field inside": func(s string) string {
		return strings.Replace(s, "auth = \"apikey\"\n", "auth = \"apikey\"\nusername = \"x\"\n", 1)
	},
	"wrong route": func(s string) string { return strings.Replace(s, "GET /v1/vpn/status", "GET /v1/vpn/settings", 1) },
	"extra route": func(s string) string {
		return strings.Replace(s, `"PUT /v1/updater/status"`, `"PUT /v1/updater/status", "PUT /v1/vpn/status"`, 1)
	},
	"older route list": func(s string) string {
		return strings.Replace(s, `, "GET /v1/updater/status", "PUT /v1/updater/status"`, "", 1)
	},
	"basic auth":  func(s string) string { return strings.Replace(s, `auth = "apikey"`, `auth = "basic"`, 1) },
	"none auth":   func(s string) string { return strings.Replace(s, `auth = "apikey"`, `auth = "none"`, 1) },
	"second role": func(s string) string { return s + s },
	"short key":   func(s string) string { return strings.Replace(s, apiKey, strings.Repeat("k", 31), 1) },
	"quote in key": func(s string) string {
		return strings.Replace(s, apiKey, apiKey[:len(apiKey)-1]+`"`, 1)
	},
	"crlf":       func(s string) string { return strings.ReplaceAll(s, "\n", "\r\n") },
	"blank line": func(s string) string { return "\n" + s },
	"empty":      func(string) string { return "" },
	"nul":        func(s string) string { return s + "\x00" },
	"too large":  func(s string) string { return s + strings.Repeat("#", 4096) },
	"bad role":   func(s string) string { return strings.Replace(s, `name = "molebridge"`, `name = "-bad"`, 1) },
	"long role": func(s string) string {
		return strings.Replace(s, `name = "molebridge"`, `name = "`+strings.Repeat("r", 65)+`"`, 1)
	},
	"invalid utf-8": func(s string) string { return s + "\xff" },
}

func TestValidAuthFileRefusesAnythingElse(t *testing.T) { // test_preflight_refuses_anything_else_without_printing_it (valid_auth_file half)
	for name, f := range brokenRoleFiles {
		if ValidAuthFile(f(validRoleFile(t))) {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDefaultRoleAllowed(t *testing.T) { // test_preflight_default_role
	for value, ok := range map[string]bool{
		"": true, "{}": true, " {} ": true, "\t{}\t": true,
		`{"auth":"none"}`: false, `{"auth":"apikey","apikey":"x"}`: false, "{ }": false, "{}x": false,
		"{}\n{\"auth\":\"none\"}": false, "null": false, "\n{}": false,
	} {
		if DefaultRoleAllowed(value) != ok {
			t.Errorf("%q: want %v", value, ok)
		}
	}
}

// -- routing/gluetun-preflight accepts and refuses the same files ----------

const preflight = "../../routing/gluetun-preflight"

func runPreflight(t *testing.T, text string, env ...string) (code int, started bool, output string) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	auth := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(auth, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	mark := filepath.Join(dir, "started")
	cmd := exec.Command(sh, preflight, "touch", mark)
	// The role-file cases run as a sidecar's gluetun, which has no post-rules.
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH=" + auth,
		"MOLEBRIDGE_KIND=sidecar", "MOLEBRIDGE_POST_RULES_FILE=" + filepath.Join(dir, "no-post-rules")}, env...)
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	_, statErr := os.Stat(mark)
	return code, statErr == nil, string(out)
}

func TestPreflightAgreesOnTheGeneratedFile(t *testing.T) { // test_preflight_hands_a_valid_role_file_to_gluetun
	code, started, out := runPreflight(t, validRoleFile(t))
	if code != 0 || !started {
		t.Fatalf("%d %s", code, out)
	}
	if strings.Contains(out, apiKey) {
		t.Error("the key is in the output")
	}
}

func TestPreflightAgreesOnTheBrokenFiles(t *testing.T) {
	for name, f := range brokenRoleFiles {
		if name == "invalid utf-8" {
			continue // the shell reads bytes; it has no UTF-8 rule
		}
		code, started, out := runPreflight(t, f(validRoleFile(t)))
		if code != 1 || started || !strings.HasPrefix(out, "molebridge: not starting gluetun: ") {
			t.Errorf("%s: %d started=%v %q", name, code, started, out)
		}
		if strings.Contains(out, apiKey) || strings.Contains(out, strings.Repeat("k", 20)) {
			t.Errorf("%s: output carries the key", name)
		}
	}
}

func TestPreflightDefaultRoleAgrees(t *testing.T) { // test_preflight_default_role
	for _, value := range []string{"", "{}", " {} ", "\t{}\t", `{"auth":"none"}`, "{ }", "{}x", "null"} {
		code, started, out := runPreflight(t, validRoleFile(t), "HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE="+value)
		if ok := code == 0 && started; ok != DefaultRoleAllowed(value) {
			t.Errorf("%q: preflight %v (%s), DefaultRoleAllowed %v", value, ok, out, DefaultRoleAllowed(value))
		}
	}
}
