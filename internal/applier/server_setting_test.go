// Tests ported from tools/test_server_setting.py: configuration authority
// against fakes only; no live host or provider. The gluetun cases of that file
// (test_gluetun_restore_and_request_use_server_not_saved_or_panel and the
// gluetun rows of the parametrized tests) belong to the gluetun applier's
// port. The doctor is gone (decision D22): its question, whether the exit is
// verified on SERVER, is the verdict's, asked here with Applier.assess, and
// Healthy stays operational.
package applier

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
)

var serverNames = map[string]string{"mullvad": testHost, "pia": piaRegion, "nordvpn": nordUS}
var absentNames = map[string]string{"mullvad": "zz-zzz-wg-999", "pia": "ex_absent", "nordvpn": "us9999.nordvpn.com"}
var nativeProviders = []string{"mullvad", "pia", "nordvpn"}

// native is the Python helper of that name: an applier for a native provider
// with SERVER set, on its fake kernel.
func native(t testing.TB, provider, server string) (*Applier, *kernel) {
	t.Helper()
	switch provider {
	case "mullvad":
		dir := t.TempDir()
		writeSnapshot(t, dir, "", map[string]any{testHost: mullvadEntry(testHost, testKey)})
		k := newKernel(t)
		return newApplier(t, k, dir, NewMullvad(), server), k
	case "nordvpn":
		dir := t.TempDir()
		writeSnapshot(t, dir, "nordvpn", nordCatalogue(t))
		k := newNordKernel(t)
		return newApplier(t, k, dir, NewNordVPN(), server), k
	}
	a, k, _, _, _ := piaSetupFor(t, false, server)
	return a, k
}

func TestServerFromEnvUsesDesiredNameValidation(t *testing.T) {
	for _, provider := range nativeProviders {
		for _, server := range []string{serverNames[provider], "", "--bad", serverNames[provider] + "\n", "bad name", "<script>",
			strings.Repeat("x", 4096)} {
			a, _ := native(t, provider, server)
			if a.configuredServer != server {
				t.Fatalf("%s: configured %q", provider, a.configuredServer)
			}
			_, valid := state.DesiredRequest(map[string]any{"server": server, "requested_at": validate.FormatTime(time.Now())}, provider)
			if (a.configuredRequest() != nil) != valid {
				t.Errorf("%s %q: configured request %v, desired request %v", provider, server, a.configuredRequest() != nil, valid)
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
				t.Errorf("%s %q: reported %v", provider, server, r.Get("configured_server"))
			}
		}
	}
}

func TestNativeRequestPathNeverReadsDesired(t *testing.T) {
	for _, provider := range nativeProviders {
		for _, kind := range []string{"valid", "malformed", "missing", "symlink"} {
			a, _ := native(t, provider, serverNames[provider])
			switch kind {
			case "valid":
				desire(t, a, requestAt(absentNames[provider], nil))
			case "malformed":
				writeFile(t, a.desiredPath, "{broken", 0o644)
			case "symlink":
				if err := os.MkdirAll(filepath.Dir(a.desiredPath), 0o777); err != nil {
					t.Fatal(err)
				}
				if err := symlink(a.directory+"/missing", a.desiredPath); err != nil {
					t.Fatal(err)
				}
			}
			// No filesystem read or stat of the request path, even if malformed.
			a.readJSON = func(path string, limit int64) any {
				if path == a.desiredPath {
					t.Fatalf("%s/%s: read the desired-state file", provider, kind)
				}
				return state.ReadJSON(path, limit)
			}
			a.exists = func(path string) bool {
				if path == a.desiredPath {
					t.Fatalf("%s/%s: stat of the desired-state file", provider, kind)
				}
				return fileExists(path)
			}
			r := mustTick(t, a)
			if status(r) != "ok" || r.Get("server") != serverNames[provider] || r.Get("requested_server") != serverNames[provider] ||
				r.Get("configured_server") != serverNames[provider] {
				t.Errorf("%s/%s: %s %s", provider, kind, status(r), message(r))
			}
		}
	}
}

func TestBadConfigurationHasQuotedFailureAndNoFallback(t *testing.T) {
	for _, provider := range nativeProviders {
		for _, c := range []struct{ server, kind string }{{"--bad\n\"", "Invalid"}, {"absent.example.test", "Unknown"}} {
			server := c.server
			if c.kind == "Unknown" {
				server = absentNames[provider]
			}
			a, k := native(t, provider, server)
			desire(t, a, requestAt(serverNames[provider], nil))
			r := mustTick(t, a)
			quoted, _ := validate.MarshalJSON(server)
			if status(r) != "failed" || !strings.HasPrefix(message(r), c.kind+" SERVER "+string(quoted)+";") {
				t.Errorf("%s %s: %s %q", provider, c.kind, status(r), message(r))
			}
			if again := a.inspect(t); status(again) != "failed" {
				t.Errorf("%s %s: inspect %s", provider, c.kind, status(again))
			}
			if len(k.mutations) != 0 || k.addKeys() != 0 {
				t.Errorf("%s %s: changed something: %v", provider, c.kind, k.mutations)
			}
		}
	}
}

func TestConfigurationRetriesFailedApplyAndReconverges(t *testing.T) {
	a, k := native(t, "mullvad", testHost)
	k.keys = nil
	k.failSet = true
	failed := mustTick(t, a)
	sel := failed.Decoded()["selection"].(map[string]any)
	if status(failed) != "failed" || message(failed) != "Peer update failed; retrying automatically." ||
		sel["source"] != "configured" || sel["next_action"] != "reapply" {
		t.Fatalf("%s %s %v", status(failed), message(failed), sel)
	}
	k.failSet = false
	k.now += RefreshSec
	if r := mustTick(t, a); status(r) != "ok" {
		t.Fatalf("%s %s", status(r), message(r))
	}
	// A recreated interface has no peer; the configuration remains
	// authoritative and is applied again once that has lasted.
	k.keys = nil
	k.now++
	mustTick(t, a)
	k.now += 90
	if r := mustTick(t, a); status(r) != "ok" || len(k.keys) != 1 || k.keys[0] != testKey {
		t.Fatalf("%s %s %v", status(r), message(r), k.keys)
	}
}

func TestConfigurationWaitsForFreshCatalogueThenValidates(t *testing.T) {
	a, k := native(t, "mullvad", testHost)
	k.keys = nil
	snapshot(a).Snapshot["fetched_at"] = "2000-01-01T00:00:00Z"
	r := mustTick(t, a)
	if status(r) != "failed" || a.attempt.State != "pending" || len(k.mutations) != 0 {
		t.Fatalf("%s %s %v", status(r), a.attempt.State, k.mutations)
	}
	snapshot(a).Snapshot["fetched_at"] = validate.FormatTime(time.Now())
	if r := mustTick(t, a); status(r) != "ok" {
		t.Fatalf("%s %s", status(r), message(r))
	}
}

func TestConfiguredServerIsTheVerdictsQuestionNotTheHealthChecks(t *testing.T) {
	// D5: the container health check is operational; whether the exit is
	// verified on SERVER is the verdict's.
	var none any
	for name, c := range map[string]struct {
		status   string
		reported any
		actual   string
		verified bool
	}{
		"ok on the server":              {"ok", testHost, testHost, true},
		"failed on the server":          {"failed", testHost, testHost, false},
		"the local SERVER is authority": {"ok", none, testHost, true},
		"ok on another server":          {"ok", testHost, "zz-zzz-wg-999", false},
		"reported a bad name":           {"failed", "--bad", testHost, false},
		"reported another name":         {"failed", "zz-zzz-wg-999", testHost, false},
	} {
		a, k := native(t, "mullvad", testHost)
		_ = k
		dir := a.directory[:len(a.directory)-len("/applier")]
		withPublished(a, dir)
		checks := a.blankChecks()
		now := validate.FormatTime(time.Now())
		for i, pair := range checks {
			if check, ok := pair.Value.(validate.Obj); ok && check[0].Value == "unknown" {
				checks[i].Value = validate.Members("state", "pass", "at", now, "server", c.actual)
			}
		}
		set := func(name, field string, value any) {
			for i, pair := range checks {
				if pair.Key == name {
					checks[i].Value = pair.Value.(validate.Obj).Set(field, value)
				}
			}
		}
		set("handshake", "age_s", 1)
		set("egress", "tier", "provider")
		set("egress", "expected_families", []any{"4"})
		set("egress", "families", validate.Members("4", "pass"))
		set("traffic_protection", "from", "routing")
		if _, err := a.publishRecord(c.status, "Example status.", c.actual, checks,
			validate.Members("configured_server", c.reported, "egress_ips", validate.Members("4", "203.0.113.10"))); err != nil {
			t.Fatal(err)
		}
		if !a.Healthy(context.Background()) {
			t.Errorf("%s: unhealthy", name)
		}
		v := a.assess(jsonfile.Read(a.resultPath, ResultMaxBytes))
		if (v.State == "ok") != c.verified {
			t.Errorf("%s: verdict %s %v, verified %v", name, v.State, v.Reasons, c.verified)
		}
	}
}

func TestConfiguredInspectionCannotMarkADifferentServerHealthy(t *testing.T) {
	dir := t.TempDir()
	writeSnapshot(t, dir, "", map[string]any{testHost: mullvadEntry(testHost, testKey)})
	k := newKernel(t)
	o := &overridden{Provider: NewMullvad(), serverFor: func(context.Context, *Applier, []string) (string, error) {
		return "zz-zzz-wg-999", nil
	}}
	a := newApplier(t, k, dir, o, testHost)
	r := a.inspect(t)
	if status(r) != "failed" || message(r) != "The configured SERVER is not the current server; waiting for convergence." {
		t.Fatalf("%s %s", status(r), message(r))
	}
}

func TestInvalidUnicodeSettingKeepsStatusBoundedAndReadable(t *testing.T) {
	a, _ := native(t, "mullvad", strings.Repeat("\U0001F600", 4096))
	dir := a.directory[:len(a.directory)-len("/applier")]
	withPublished(a, dir)
	r := mustTick(t, a)
	if status(r) != "failed" {
		t.Fatalf("%s", status(r))
	}
	size, err := fileSize(a.resultPath)
	if err != nil || size > ResultMaxBytes {
		t.Fatalf("size %d %v", size, err)
	}
	if _, ok := state.ConfiguredServer(jsonfile.Read(a.resultPath, ResultMaxBytes)); !ok {
		t.Error("configured server unreadable")
	}
}

func TestAServerSettingWithInvalidBytesIsReportedEscaped(t *testing.T) {
	// Python's os.environ keeps undecodable bytes as lone surrogates; they are
	// reported escaped and the status stays encodable.
	a, _ := native(t, "mullvad", "se-\xff-wg-001")
	dir := a.directory[:len(a.directory)-len("/applier")]
	withPublished(a, dir)
	r := mustTick(t, a)
	if status(r) != "failed" || !strings.HasPrefix(message(r), `Invalid SERVER "se-\udcff-wg-001"`) {
		t.Fatalf("%s %s", status(r), message(r))
	}
	if _, ok := state.ConfiguredServer(jsonfile.Read(a.resultPath, ResultMaxBytes)); !ok {
		t.Error("configured server unreadable")
	}
}
