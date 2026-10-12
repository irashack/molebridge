// The gluetun rows of tools/test_server_setting.py (the parametrized tests the
// native port left, and test_gluetun_restore_and_request_use_server_not_saved_or_panel):
// configuration authority against fakes only; no live host or provider. The
// native rows are server_setting_test.go.
package applier

import (
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
)

// gluetunProviderNames are the gluetun-backed registry entries, with the Python
// NAMES' server for each (HOST_B).
func gluetunProviderNames() []string {
	var out []string
	for _, id := range providers.IDs() {
		if spec, _ := providers.Get(id); spec.Backend == providers.BackendGluetun {
			out = append(out, id)
		}
	}
	return out
}

func TestGluetunServerFromEnvUsesDesiredNameValidation(t *testing.T) {
	names := gluetunProviderNames()
	if len(names) < 5 {
		t.Fatalf("gluetun entries %v", names)
	}
	for _, id := range names {
		getenv, dir := gluetunEnv(t, nil)
		provider, err := ProviderFor(id, Exit{Kind: "overlay"}, getenv)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		k := newGlKernel(t, glRouting(t))
		for _, server := range []string{hostB, "", "--bad", hostB + "\n", "bad name", "<script>", strings.Repeat("x", 4096)} {
			a, err := New(Config{StateDir: dir, Exit: k.exit, Provider: provider, System: k, Server: server, BootID: testBoot,
				Monotonic: k.clock, Sleep: k.sleep, Log: func(string) {}})
			if err != nil {
				t.Fatalf("%s: %v", id, err)
			}
			if a.configuredServer != server {
				t.Fatalf("%s: configured %q", id, a.configuredServer)
			}
			_, valid := state.DesiredRequest(map[string]any{"server": server, "requested_at": validate.FormatTime(time.Now())}, id)
			if (a.configuredRequest() != nil) != valid {
				t.Errorf("%s %q: configured request %v, desired request %v", id, server, a.configuredRequest() != nil, valid)
			}
			r, err := a.publishRecord("unknown", "Starting.", "", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			var want any
			if server != "" {
				want = truncateChars(server, ServerReportChars)
			}
			if r.Get("configured_server") != want {
				t.Errorf("%s %q: reported %v", id, server, r.Get("configured_server"))
			}
		}
	}
}

func TestGluetunBadConfigurationHasQuotedFailureAndNoFallback(t *testing.T) {
	for _, id := range gluetunProviderNames() {
		if id == "gluetun-surfshark" { // its names are narrower than the fixture's hostnames
			continue
		}
		for _, c := range []struct{ server, kind string }{{"--bad\n\"", "Invalid"}, {"absent.example.test", "Unknown"}} {
			f := newGluetunFixture(t, glOptions{provider: strings.TrimPrefix(id, "gluetun-"), server: c.server, period: -1})
			desire(t, f.a, glRequest(hostB))
			r := mustTick(t, f.a)
			quoted, _ := validate.MarshalJSON(c.server)
			if status(r) != "failed" || !strings.HasPrefix(message(r), c.kind+" SERVER "+string(quoted)+";") {
				t.Errorf("%s %s: %s %q", id, c.kind, status(r), message(r))
			}
			if again := f.a.inspect(t); status(again) != "failed" {
				t.Errorf("%s %s: inspect %s", id, c.kind, status(again))
			}
			if len(f.control.puts) != 0 {
				t.Errorf("%s %s: puts %v", id, c.kind, f.control.puts)
			}
		}
	}
}

func TestGluetunRestoreAndRequestUseServerNotSavedOrPanel(t *testing.T) {
	for _, id := range gluetunProviderNames() {
		if id == "gluetun-surfshark" {
			continue
		}
		f := newGluetunFixture(t, glOptions{provider: strings.TrimPrefix(id, "gluetun-"), server: hostB, period: -1})
		if err := f.provider.saveSelection(func(s *selection) { s.Desired, s.LastPut, s.LastSuccessful = hostC, hostA, hostC }); err != nil {
			t.Fatal(err)
		}
		desire(t, f.a, glRequest(hostC))
		// No filesystem read or stat of the request path.
		f.a.readJSON = func(path string, limit int64) any {
			if path == f.a.desiredPath {
				t.Fatalf("%s: read the desired-state file", id)
			}
			return state.ReadJSON(path, limit)
		}
		f.a.exists = func(path string) bool {
			if path == f.a.desiredPath {
				t.Fatalf("%s: stat of the desired-state file", id)
			}
			return fileExists(path)
		}
		r := mustTick(t, f.a)
		if len(f.control.puts) != 1 || f.control.puts[0] != hostB {
			t.Fatalf("%s: puts %v", id, f.control.puts)
		}
		if status(r) != "ok" || r.Get("server") != hostB || selectionOf(r)["source"] != "configured" {
			t.Errorf("%s: %s %q %v", id, status(r), message(r), selectionOf(r))
		}
		f.k.tunnel = hostA
		f.k.now += 91
		mustTick(t, f.a)
		if len(f.control.puts) != 2 || f.control.puts[1] != hostB {
			t.Errorf("%s: puts %v", id, f.control.puts)
		}
	}
}
