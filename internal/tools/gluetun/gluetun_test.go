package gluetun

// Ported from tools/test_gluetun.py: test_host_tool_writes_post_rules_from_env_without_an_engine,
// test_host_tool_post_rules_follow_compose_precedence (now: the process
// environment alone, the .env file reader is dropped),
// test_host_tool_refuses_bad_post_rule_settings, test_gluetun_auth_writes_one_key_into_both_files,
// test_gluetun_auth_command_never_prints_the_key and the auth half of
// test_gluetun_files_must_exist_with_mode_0600. Not ported (D22, the doctor
// and recover are dropped): test_gluetun_files_must_exist_with_mode_0600's
// check_gluetun_files half, test_doctor_refuses_an_invalid_role_file,
// test_env_file_reader. test_post_rules_* and the parser tests of the rendered
// text are internal/contract's.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/gluetunauth"
)

type fixedRandom byte

func (f fixedRandom) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(f)
	}
	return len(p), nil
}

func opts(env map[string]string, random byte) (Options, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return Options{Env: env, Random: fixedRandom(random), Stdout: &out, Stderr: &errb}, &out, &errb
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// -- gluetun-auth ------------------------------------------------------------

func TestAuthWritesOneKeyIntoBothFiles(t *testing.T) { // test_gluetun_auth_writes_one_key_into_both_files
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	dir := filepath.Join(t.TempDir(), "secrets", "gluetun")
	o, stdout, stderr := opts(nil, 0x41)
	if code := AuthMain([]string{dir}, o); code != 0 || stderr.Len() != 0 {
		t.Fatalf("%d %s", code, stderr)
	}
	keyRaw, _ := os.ReadFile(filepath.Join(dir, "api_key"))
	key := strings.TrimSuffix(string(keyRaw), "\n")
	if len(key) != 43 || strings.ContainsAny(key, "+/=") {
		t.Errorf("key shape %q", key)
	}
	authRaw, _ := os.ReadFile(filepath.Join(dir, "auth.toml"))
	want, _ := gluetunauth.AuthFile(key, "molebridge")
	if string(authRaw) != want || !gluetunauth.ValidAuthFile(string(authRaw)) {
		t.Errorf("auth.toml:\n%s", authRaw)
	}
	if got, err := gluetunauth.ReadAPIKey(filepath.Join(dir, "api_key")); err != nil || got != key {
		t.Errorf("the exit's reader: %q %v", got, err)
	}
	for _, name := range []string{"api_key", "auth.toml"} {
		if m := mode(t, filepath.Join(dir, name)); m != 0o600 {
			t.Errorf("%s mode %v", name, m)
		}
	}
	if m := mode(t, dir); m != 0o700 {
		t.Errorf("directory mode %v", m)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("files: %v", entries)
	}
	wantOut := "Wrote " + dir + "/auth.toml and " + dir + "/api_key (mode 0600, key not shown); recreate gluetun and the exit container to use them.\n"
	if stdout.String() != wantOut {
		t.Errorf("stdout %q", stdout)
	}
	if strings.Contains(stdout.String()+stderr.String(), key) { // test_gluetun_auth_command_never_prints_the_key
		t.Error("the key is printed")
	}

	// Kept unless asked; replaced together with --rotate.
	o2, stdout2, _ := opts(nil, 0x42)
	if code := AuthMain([]string{dir}, o2); code != 0 || stdout2.String() != dir+"/auth.toml and api_key already exist; --rotate replaces them.\n" {
		t.Errorf("second run: %d %q", code, stdout2)
	}
	if again, _ := os.ReadFile(filepath.Join(dir, "api_key")); string(again) != string(keyRaw) {
		t.Error("kept files changed")
	}
	o3, stdout3, _ := opts(nil, 0x43)
	if code := AuthMain([]string{"--rotate", dir}, o3); code != 0 || !strings.HasPrefix(stdout3.String(), "Wrote ") {
		t.Fatalf("rotate: %d %q", code, stdout3)
	}
	rotated, _ := os.ReadFile(filepath.Join(dir, "api_key"))
	auth2, _ := os.ReadFile(filepath.Join(dir, "auth.toml"))
	if string(rotated) == string(keyRaw) || !strings.Contains(string(auth2), strings.TrimSuffix(string(rotated), "\n")) {
		t.Error("rotation did not replace both with one new key")
	}
	if strings.Contains(stdout3.String(), strings.TrimSuffix(string(rotated), "\n")) {
		t.Error("rotated key printed")
	}
	// Flags may follow the directory.
	o4, _, _ := opts(nil, 0x44)
	if code := AuthMain([]string{dir, "--rotate"}, o4); code != 0 {
		t.Error("--rotate after DIR refused")
	}

	// One file missing: refused unless rotating.
	os.Remove(filepath.Join(dir, "api_key"))
	o5, stdout5, stderr5 := opts(nil, 0x45)
	if code := AuthMain([]string{dir}, o5); code != 1 || stdout5.Len() != 0 ||
		stderr5.String() != "FAIL Only one of "+dir+"/api_key and auth.toml exists; run gluetun-auth --rotate to write both again.\n" {
		t.Errorf("one file: %d %q %q", code, stdout5, stderr5)
	}
	if code := AuthMain([]string{"--rotate", dir}, o5); code != 0 {
		t.Error("rotate did not repair")
	}
}

func TestAuthRefusesSymlinks(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	os.Mkdir(real, 0o700)
	link := filepath.Join(root, "link")
	os.Symlink(real, link)
	o, stdout, stderr := opts(nil, 1)
	if code := AuthMain([]string{"--rotate", link}, o); code != 1 || stdout.Len() != 0 ||
		stderr.String() != "FAIL "+link+" and its files must not be symlinks.\n" {
		t.Errorf("symlinked directory: %d %q %q", code, stdout, stderr)
	}
	if entries, _ := os.ReadDir(real); len(entries) != 0 {
		t.Error("wrote through the link")
	}
	// A symlinked file inside is refused as well, and nothing is written.
	dir := filepath.Join(root, "dir")
	os.Mkdir(dir, 0o700)
	outside := filepath.Join(root, "outside")
	os.WriteFile(outside, []byte("keep"), 0o600)
	os.Symlink(outside, filepath.Join(dir, "api_key"))
	os.Symlink(outside, filepath.Join(dir, "auth.toml"))
	o2, _, stderr2 := opts(nil, 1)
	if code := AuthMain([]string{"--rotate", dir}, o2); code != 1 || !strings.Contains(stderr2.String(), "must not be symlinks") {
		t.Errorf("symlinked files: %d %q", code, stderr2)
	}
	if raw, _ := os.ReadFile(outside); string(raw) != "keep" {
		t.Error("wrote through a symlinked file")
	}
}

func TestAuthUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"--rotate"}, {"a", "b"}, {"--bogus", "a"}, {"-x"}} {
		o, stdout, stderr := opts(nil, 1)
		if code := AuthMain(args, o); code != 2 || stdout.Len() != 0 || stderr.String() != "usage: molebridge gluetun-auth [--rotate] DIR\n" {
			t.Errorf("%q: %d %q %q", args, code, stdout, stderr)
		}
	}
	o, stdout, _ := opts(nil, 1)
	if code := AuthMain([]string{"--help"}, o); code != 0 || !strings.Contains(stdout.String(), "gluetun-auth --rotate /out") {
		t.Error("help")
	}
}

func TestAuthFailureIsGenericOnOSErrors(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	os.WriteFile(file, nil, 0o600)
	o, stdout, stderr := opts(nil, 1)
	// A directory under a regular file cannot be made.
	if code := AuthMain([]string{filepath.Join(file, "sub")}, o); code != 1 || stdout.Len() != 0 ||
		stderr.String() != "FAIL unable to inspect local configuration.\n" {
		t.Errorf("%d %q %q", code, stdout, stderr)
	}
}

// -- gluetun-post-rules ------------------------------------------------------

var overlayEnv = map[string]string{"OVERLAY_CIDR": "192.0.2.0/24", "OVERLAY6_CIDR": "2001:db8:1::/64", "EXIT_IF": "wg0", "HOST_IF": "eth0"}

func gluetunConfig(t *testing.T, env map[string]string) contract.Config {
	t.Helper()
	c, err := contract.ConfigFromEnv(func(n string) string {
		if n == "TUNNEL_BACKEND" {
			return "gluetun"
		}
		return env[n]
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPostRulesFromTheEnvironment(t *testing.T) { // test_host_tool_writes_post_rules_from_env_without_an_engine
	dir := filepath.Join(t.TempDir(), "tunnel", "gluetun")
	o, stdout, stderr := opts(overlayEnv, 0)
	if code := PostRulesMain([]string{dir}, o); code != 0 || stderr.Len() != 0 {
		t.Fatalf("%d %s", code, stderr)
	}
	path := filepath.Join(dir, "post-rules.txt")
	if want := "Wrote " + path + "; recreate gluetun to apply it.\n"; stdout.String() != want {
		t.Errorf("stdout %q", stdout)
	}
	got, _ := os.ReadFile(path)
	want, err := contract.RenderPostRules(gluetunConfig(t, map[string]string{
		"OVERLAY_CIDR": "192.0.2.0/24", "OVERLAY6_CIDR": "2001:db8:1::/64", "OVERLAY_IF": "wt0", "EXIT_IF": "wg0", "HOST_IF": "eth0",
		"HOST_TABLE": "51822", "EXIT_TABLE": "51821"}), 51820, true)
	if err != nil || string(got) != want {
		t.Errorf("post-rules:\n%s", got)
	}
	if m := mode(t, path); m != 0o644 {
		t.Errorf("mode %v", m)
	}
	if !strings.Contains(string(got), "iptables -A OUTPUT -o eth0 -j ACCEPT") || !strings.Contains(string(got), "ip6tables ") {
		t.Errorf("rules:\n%s", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("leftovers: %v", entries)
	}
	// --ipv4-only leaves the ip6tables lines out (anywhere on the line).
	o2, _, _ := opts(overlayEnv, 0)
	if code := PostRulesMain([]string{"--ipv4-only", dir}, o2); code != 0 {
		t.Fatal("--ipv4-only failed")
	}
	if v4, _ := os.ReadFile(path); strings.Contains(string(v4), "ip6tables") || !strings.Contains(string(v4), "iptables -A FORWARD") {
		t.Errorf("--ipv4-only:\n%s", v4)
	}
}

func TestPostRulesFollowTheEnvironment(t *testing.T) { // test_host_tool_post_rules_follow_compose_precedence (environment half)
	env := map[string]string{"OVERLAY_CIDR": "192.0.2.0/24", "HOST_IF": "enp3s0", "CONTROL_MARK": "0x2000", "NB_WIREGUARD_PORT": "40000"}
	dir := t.TempDir()
	o, _, stderr := opts(env, 0)
	if code := PostRulesMain([]string{dir}, o); code != 0 {
		t.Fatal(stderr.String())
	}
	text, _ := os.ReadFile(filepath.Join(dir, "post-rules.txt"))
	if !strings.Contains(string(text), "-o enp3s0 ") || !strings.Contains(string(text), "--dport 40000 ") {
		t.Errorf("rules:\n%s", text)
	}
	// Empty settings are the defaults, as in ${NAME:-default}.
	o2, _, stderr2 := opts(map[string]string{"OVERLAY_CIDR": "192.0.2.0/24", "HOST_IF": "", "NB_WIREGUARD_PORT": "", "EXIT_IF": ""}, 0)
	if code := PostRulesMain([]string{dir}, o2); code != 0 {
		t.Fatal(stderr2.String())
	}
	if text, _ := os.ReadFile(filepath.Join(dir, "post-rules.txt")); !strings.Contains(string(text), "-o eth0 ") || !strings.Contains(string(text), "--dport 51820 ") {
		t.Errorf("defaults:\n%s", text)
	}
}

func TestPostRulesRefuseBadSettings(t *testing.T) { // test_host_tool_refuses_bad_post_rule_settings
	const message = "FAIL Invalid gluetun routing settings; check OVERLAY_CIDR, CONTROL_MARK, HOST_IF, EXIT_IF, " +
		"EXIT_TABLE, HOST_TABLE and NB_WIREGUARD_PORT in the environment passed with -e or --env-file (docs/configuration.md).\n"
	for name, extra := range map[string]map[string]string{
		"mark":                  {"CONTROL_MARK": "0x1bd01"},
		"port":                  {"NB_WIREGUARD_PORT": "x"},
		"port zero":             {"NB_WIREGUARD_PORT": "0"},
		"port big":              {"NB_WIREGUARD_PORT": "65536"},
		"no overlay":            {"OVERLAY_CIDR": ""},
		"host table":            {"HOST_TABLE": "51821"},
		"exit if":               {"EXIT_IF": "wg-0"},
		"interpolate":           {"HOST_IF": "${OTHER}"},
		"default overlay route": {"OVERLAY_CIDR": "0.0.0.0/0"},
		"same interface":        {"OVERLAY_IF": "wg0"},
	} {
		env := map[string]string{}
		for k, v := range overlayEnv {
			env[k] = v
		}
		for k, v := range extra {
			env[k] = v
		}
		root := t.TempDir()
		dir := filepath.Join(root, "tunnel", "gluetun")
		o, stdout, stderr := opts(env, 0)
		if code := PostRulesMain([]string{dir}, o); code != 1 || stdout.Len() != 0 || stderr.String() != message {
			t.Errorf("%s: %d %q %q", name, code, stdout, stderr)
		}
		if _, err := os.Stat(filepath.Join(root, "tunnel")); err == nil {
			t.Errorf("%s: created the directory", name)
		}
	}
	// A settings value is never echoed.
	o, _, stderr := opts(map[string]string{"OVERLAY_CIDR": "SECRETVALUE"}, 0)
	PostRulesMain([]string{t.TempDir()}, o)
	if strings.Contains(stderr.String(), "SECRETVALUE") {
		t.Error("a setting is echoed")
	}
}

func TestPostRulesRefuseWhatIsNotARegularFile(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "d")
	os.Mkdir(dir, 0o755)
	path := filepath.Join(dir, "post-rules.txt")
	os.Mkdir(path, 0o755)
	o, stdout, stderr := opts(overlayEnv, 0)
	if code := PostRulesMain([]string{dir}, o); code != 1 || stdout.Len() != 0 ||
		stderr.String() != "FAIL "+path+" must be a regular file; remove what is there.\n" {
		t.Errorf("directory: %d %q %q", code, stdout, stderr)
	}
	os.Remove(path)
	outside := filepath.Join(root, "outside")
	os.WriteFile(outside, []byte("keep"), 0o600)
	os.Symlink(outside, path)
	if code := PostRulesMain([]string{dir}, o); code != 1 {
		t.Error("a symlinked file was replaced")
	}
	if raw, _ := os.ReadFile(outside); string(raw) != "keep" {
		t.Error("wrote through the link")
	}
	// A symlinked directory is refused too.
	os.Remove(path)
	link := filepath.Join(root, "link")
	os.Symlink(dir, link)
	if code := PostRulesMain([]string{link}, o); code != 1 {
		t.Error("a symlinked directory was used")
	}
	// An existing regular file is replaced.
	os.WriteFile(path, []byte("old"), 0o600)
	if code := PostRulesMain([]string{dir}, o); code != 0 {
		t.Fatal("replacing a regular file failed")
	}
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), "iptables") || mode(t, path) != 0o644 {
		t.Error("not replaced with mode 0644")
	}
}

func TestPostRulesUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"--ipv4-only"}, {"a", "b"}, {"--rotate", "a"}} {
		o, stdout, stderr := opts(overlayEnv, 0)
		if code := PostRulesMain(args, o); code != 2 || stdout.Len() != 0 || stderr.String() != "usage: molebridge gluetun-post-rules [--ipv4-only] DIR\n" {
			t.Errorf("%q: %d %q %q", args, code, stdout, stderr)
		}
	}
	o, stdout, _ := opts(nil, 0)
	if code := PostRulesMain([]string{"-h"}, o); code != 0 || !strings.Contains(stdout.String(), "OVERLAY_CIDR") {
		t.Error("help")
	}
}

// New in 0.9.1: the image carries the preflight script.
func TestPreflightWritesTheScriptOfTheSourceTree(t *testing.T) {
	want, err := os.ReadFile("../../../routing/gluetun-preflight")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "preflight")
	o, stdout, stderr := opts(nil, 0)
	if code := PreflightMain([]string{dir}, o); code != 0 || stderr.Len() != 0 {
		t.Fatalf("%d %s", code, stderr)
	}
	path := filepath.Join(dir, "gluetun-preflight")
	if want := "Wrote " + path + "; mount it into gluetun at /usr/local/bin/molebridge-gluetun-preflight.\n"; stdout.String() != want {
		t.Errorf("stdout %q", stdout)
	}
	if got, _ := os.ReadFile(path); string(got) != string(want) {
		t.Error("the written script is not routing/gluetun-preflight")
	}
	if m := mode(t, path); m != 0o755 {
		t.Errorf("mode %v", m)
	}
	// Written again over itself; a symlink is refused.
	o2, _, _ := opts(nil, 0)
	if code := PreflightMain([]string{dir}, o2); code != 0 {
		t.Error("rewrite failed")
	}
	link := filepath.Join(t.TempDir(), "gluetun-preflight")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	o3, _, stderr3 := opts(nil, 0)
	if code := PreflightMain([]string{filepath.Dir(link)}, o3); code != 1 || !strings.Contains(stderr3.String(), "must be a regular file") {
		t.Errorf("symlink: %d %q", code, stderr3)
	}
	for _, args := range [][]string{nil, {"a", "b"}, {"--ipv4-only", dir}} {
		o4, _, stderr4 := opts(nil, 0)
		if code := PreflightMain(args, o4); code != 2 || stderr4.String() != "usage: molebridge gluetun-preflight DIR\n" {
			t.Errorf("%v: %d %q", args, code, stderr4)
		}
	}
}
