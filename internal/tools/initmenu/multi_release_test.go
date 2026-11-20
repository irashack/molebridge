//go:build !drill

package initmenu

import (
	"os"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/exit"
)

// TestReleaseBuildRefusesMultiProvider: the release build's exit refuses
// PROVIDERS, so init neither offers nor writes a multi-provider exit, in an
// answers file, on the terminal or in --help.
func TestReleaseBuildRefusesMultiProvider(t *testing.T) {
	if exit.MultiProviderAvailable() {
		t.Fatal("multi-provider exits are on in the release build")
	}
	for _, a := range []Answers{
		{"mullvad,nordvpn", []string{WayNetBird}, nil},
		{"mullvad,pia,nordvpn", []string{WayNetBird}, []string{ExtraSwitchyard}},
		{"pia,nordvpn", []string{WaySidecar}, nil},
		{"mullvad,gluetun-nordvpn", []string{WayNetBird}, nil},
	} {
		if _, err := a.Plan(); err == nil || err.Error() != MultiUnavailable {
			t.Errorf("%+v: %v", a, err)
		}
	}
	dir := t.TempDir()
	answers := writeAnswers(t, `{"schema":1,"provider":"mullvad,nordvpn","ways_in":["netbird-exit"]}`)
	code, _, stderr := run(t, "", false, "--out", dir, "--answers", answers)
	if code != 1 || stderr != "molebridge init: "+MultiUnavailable+"\n" {
		t.Errorf("answers file: exit %d, %q", code, stderr)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("a refusal wrote %v", entries)
	}
	// On the terminal: not offered, and refused as an answer, which is asked
	// again.
	code, stdout, stderr := run(t, "mullvad, nordvpn\nmullvad\nnetbird-exit\n\n", true, "--out", t.TempDir())
	if code != 0 || !strings.Contains(stdout, MultiUnavailable) {
		t.Errorf("prompt: exit %d, %s %s", code, stdout, stderr)
	}
	if strings.Contains(stdout, "comma-separated):") || strings.Contains(stdout, "switches between") {
		t.Errorf("the prompt offers several providers: %s", stdout)
	}
	if code, out, _ := run(t, "", false, "--help"); code != 0 || strings.Contains(out, "multi-provider") {
		t.Errorf("--help offers a multi-provider exit: %s", out)
	}
}
