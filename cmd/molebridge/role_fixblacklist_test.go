// New in 0.8.0 (D25): the fix-blacklist role.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/nbprofile"
)

func testPaths(stateDir string) nbprofile.Paths {
	// No daemon socket or process table: the test host may run NetBird.
	return nbprofile.Paths{StateDir: stateDir}
}

func TestFixBlacklistRoleRegistered(t *testing.T) {
	if _, ok := roles["fix-blacklist"]; !ok {
		t.Fatal("fix-blacklist is not registered")
	}
}

func TestFixBlacklistRole(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "default.json")
	const secret = "SECRETMARKER0123"
	text := "{\n    \"PrivateKey\": \"" + secret + "\",\n    \"IFaceBlackList\": [\n        \"wt0\"\n    ]\n}\n"
	if err := os.WriteFile(profile, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PROVIDER": "mullvad", "EXIT_IF": "mullvad", "TUNNEL_BACKEND": "native", "NB_STATE_DIR": dir}
	run := func(args []string, env map[string]string) (int, string, string) {
		var out, errw bytes.Buffer
		code := fixBlacklistMain(args, env, &out, &errw, testPaths)
		if strings.Contains(out.String()+errw.String(), secret) {
			t.Errorf("output reveals profile content: %q %q", out.String(), errw.String())
		}
		return code, out.String(), errw.String()
	}

	code, out, errOut := run(nil, env)
	wantOut := "fix-blacklist: added the tunnel interface mullvad to the interface blacklist of the stored NetBird profile " + profile + "\n"
	if code != 0 || out != wantOut || errOut != "" {
		t.Fatalf("first run: %d %q %q", code, out, errOut)
	}
	got, _ := os.ReadFile(profile)
	if want := strings.Replace(text, "\"wt0\"\n", "\"wt0\",\n        \"mullvad\"\n", 1); string(got) != want {
		t.Fatalf("profile:\n%s", got)
	}

	code, out, _ = run(nil, env)
	wantOut = "fix-blacklist: the stored NetBird profile " + profile + " already excludes the tunnel interface mullvad; nothing changed\n"
	if code != 0 || out != wantOut {
		t.Fatalf("second run: %d %q", code, out)
	}

	// The gluetun tunnel name defaults to wg0 and is added the same way.
	code, out, _ = run(nil, map[string]string{"TUNNEL_BACKEND": "gluetun", "NB_STATE_DIR": dir})
	if code != 0 || !strings.Contains(out, "tunnel interface wg0") {
		t.Fatalf("gluetun run: %d %q", code, out)
	}

	if code, _, errOut = run([]string{"extra"}, env); code != 2 || !strings.HasPrefix(errOut, "usage: molebridge fix-blacklist") {
		t.Fatalf("usage: %d %q", code, errOut)
	}
	if code, _, errOut = run(nil, map[string]string{"TUNNEL_BACKEND": "other"}); code != 1 || !strings.Contains(errOut, "TUNNEL_BACKEND must be native or gluetun") {
		t.Fatalf("backend: %d %q", code, errOut)
	}
	if code, _, errOut = run(nil, map[string]string{"NB_STATE_DIR": t.TempDir()}); code != 1 || !strings.Contains(errOut, "no NetBird identity found") {
		t.Fatalf("no identity: %d %q", code, errOut)
	}
}
