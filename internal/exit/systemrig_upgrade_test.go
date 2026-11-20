//go:build drill && systemrig && linux

package exit

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The upgrade drill on the system rig: the previous release's exit and panel
// build real state on a state directory, then the candidate's start on the
// same directory, as an upgrade by Compose does (docs/operations.md,
// upgrades), and then the previous release's again, as a rollback does.
//
// The previous release's binary is built by tools/previous-release.sh, which
// checks that it hashes equal to the released image's; CI's "Upgrade drill"
// job runs it and passes the binary in MOLEBRIDGE_PREVIOUS_BIN and the version
// it reports in MOLEBRIDGE_PREVIOUS_VERSION:
//
//	sh tools/previous-release.sh /tmp/previous
//	MOLEBRIDGE_PREVIOUS_BIN=/tmp/previous/molebridge MOLEBRIDGE_PREVIOUS_VERSION=v0.14.1-rc.1 \
//	  go test -count=1 -tags drill,systemrig -run TestUpgradeFromPrevious ./internal/exit/
//
// Its name stays outside TestSystemRig so that the System rig job, which has
// no previous binary, does not run it.

// rigStateGID is the group the state-gid case gives the published files: the
// panel's own (it runs as 65534:65534).
const rigStateGID = rigPanelUID

func TestUpgradeFromPrevious(t *testing.T) {
	src, version := os.Getenv("MOLEBRIDGE_PREVIOUS_BIN"), os.Getenv("MOLEBRIDGE_PREVIOUS_VERSION")
	if src == "" || version == "" {
		t.Fatal("set MOLEBRIDGE_PREVIOUS_BIN and MOLEBRIDGE_PREVIOUS_VERSION (tools/previous-release.sh builds the binary)")
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	// Beside the candidate, where uid 65534 can run it for the panel.
	prev := filepath.Join(rigBinaries(t), "molebridge-previous")
	if err := os.WriteFile(prev, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(prev, "version").Output(); err != nil || strings.TrimSpace(string(out)) != "molebridge "+version {
		t.Fatalf("%s version: %q %v, want molebridge %s", prev, out, err, version)
	}
	// Whether the previous release reads STATE_GID (0.14.1 and earlier don't).
	prevKnowsStateGID := bytes.Contains(raw, []byte("STATE_GID must be a group id"))
	t.Logf("previous release: %s (STATE_GID known: %v); candidate: %s", version, prevKnowsStateGID, rigVersion)

	for _, tc := range []struct {
		name     string
		stateGID bool
	}{{"same-settings", false}, {"state-gid", true}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			upgradeDrill(t, prev, version, tc.stateGID, prevKnowsStateGID)
		})
	}
}

// stopPanel ends the panel, as a container stop would.
func (r *systemRig) stopPanel() {
	killTree(r.panelNS)
	r.waitFor(15*time.Second, "the panel to stop", func() bool {
		out, _ := exec.Command("ip", "netns", "pids", r.panelNS.Name).Output()
		return strings.TrimSpace(string(out)) == ""
	})
}

// stateFile reads one file under the state directory.
func (r *systemRig) stateFile(rel string) []byte {
	r.t.Helper()
	raw, err := os.ReadFile(filepath.Join(r.stateDir, rel))
	if err != nil {
		r.t.Fatal(err)
	}
	return raw
}

// stateJSON reads one JSON file under the state directory as an object.
func (r *systemRig) stateJSON(rel string) map[string]any {
	r.t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.stateFile(rel), &m); err != nil {
		r.t.Fatalf("%s: %v", rel, err)
	}
	return m
}

// modeOf is a state path's permission bits and group.
func (r *systemRig) modeOf(rel string) (os.FileMode, int) {
	r.t.Helper()
	info, err := os.Lstat(filepath.Join(r.stateDir, rel))
	if err != nil {
		r.t.Fatal(err)
	}
	return info.Mode().Perm(), int(info.Sys().(*syscall.Stat_t).Gid)
}

// wantVersion requires the build's first line in out.
func wantVersion(t *testing.T, what, out, line string) {
	t.Helper()
	if !strings.Contains(out, line) {
		t.Fatalf("%s: no %q in its output:\n%s", what, line, out)
	}
}

func upgradeDrill(t *testing.T, prev, prevVersion string, stateGID, prevKnowsStateGID bool) {
	r := newSystemRig(t)
	a, b := r.relays[0], r.relays[1]
	cand := r.bin

	// 1. The previous release builds state: verified on A, A asked for by
	// name (location.json), then a switch to B (the request the upgrade
	// must keep, on a server other than the tunnel config's).
	r.bin = prev
	p := r.bringUp()
	wantVersion(t, "the previous exit", p.out.String(), "molebridge-exit: molebridge "+prevVersion)
	wantVersion(t, "the previous panel", r.panelOut.String(), "molebridge panel: molebridge "+prevVersion)
	idA, _ := r.panelSwitch(a.host)
	r.waitVerified(p, a, idA, 120*time.Second)
	idB, _ := r.panelSwitch(b.host)
	r.waitVerified(p, b, idB, 120*time.Second)
	r.waitPanelVerified(b, idB, 30*time.Second)
	r.clientVia(b, 30*time.Second)
	desired := r.stateFile("panel/desired.json")
	attemptBefore := r.stateJSON("applier/attempt.json")
	locBefore := r.location()
	if locBefore["server"] != b.host || locBefore["city"] != rigCity || locBefore["country"] != rigCountry || locBefore["replacement"] != nil {
		t.Fatalf("location.json on the previous release: %s", jsonText(locBefore))
	}
	t.Logf("previous release: ok on %s for request %s; desired.json %s; attempt.json %s; location.json %s; selection %s",
		b.host, idB, bytes.TrimSpace(desired), jsonText(attemptBefore), jsonText(locBefore), jsonText(r.result()["selection"]))

	// 2. The candidate reads the previous exit's record: its status role,
	// and its panel, upgraded first as docs/operations.md orders it.
	cmd := exec.Command("ip", "netns", "exec", r.exit.Name, cand, "status")
	cmd.Env = r.env("SSL_CERT_FILE=" + r.caPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("the candidate's status on the previous exit's record: %v\n%s", err, out)
	}
	r.stopPanel()
	r.bin = cand
	r.startPanel()
	wantVersion(t, "the candidate panel", r.panelOut.String(), "molebridge panel: molebridge "+rigVersion)
	r.waitPanelVerified(b, idB, 30*time.Second)
	t.Logf("the candidate panel shows the previous exit ok on %s (request %s)", b.host, idB)

	// 3. The exit is upgraded on the same state directory.
	if stateGID {
		r.exitExtra = append(r.exitExtra, "STATE_GID="+strconv.Itoa(rigStateGID))
	}
	upgraded := time.Now()
	p = r.restart(p)
	wantVersion(t, "the candidate exit", p.out.String(), "molebridge-exit: molebridge "+rigVersion)
	r.waitVerified(p, b, idB, 120*time.Second)
	after := time.Since(upgraded)
	res := r.result()
	if res["requested_server"] != b.host {
		t.Errorf("requested_server after the upgrade: %v, want %s", res["requested_server"], b.host)
	}
	if got := r.stateFile("panel/desired.json"); !bytes.Equal(got, desired) {
		t.Errorf("desired.json changed in the upgrade: %s, was %s", got, desired)
	}
	locAfter := r.location()
	if locAfter["server"] != b.host || locAfter["city"] != rigCity || locAfter["country"] != rigCountry || locAfter["replacement"] != nil {
		t.Errorf("location.json after the upgrade: %s, was %s", jsonText(locAfter), jsonText(locBefore))
	}
	attemptAfter := r.stateJSON("applier/attempt.json")
	if attemptAfter["rejected"] != nil {
		t.Errorf("the candidate refused the previous release's request: attempt.json %s", jsonText(attemptAfter))
	}
	r.waitPanelVerified(b, idB, 30*time.Second)
	r.clientVia(b, 30*time.Second)
	t.Logf("candidate exit: ok and verified on %s for request %s %v after the stop of the previous one; selection %s; attempt.json %s",
		b.host, idB, after.Round(time.Millisecond), jsonText(res["selection"]), jsonText(attemptAfter))

	if stateGID {
		// docs/configuration.md, readers in another group: the directory
		// 0750 and the published files already there 0640, both the group's;
		// the private files the exit's alone.
		checkMode := func(rel string, mode os.FileMode, gid int) {
			t.Helper()
			if m, g := r.modeOf(rel); m != mode || (gid >= 0 && g != gid) {
				t.Errorf("%s: mode %o group %d, want %o group %d", rel, m, g, mode, gid)
			}
		}
		checkMode("applier", 0o750, rigStateGID)
		checkMode("applier/result.json", 0o640, rigStateGID)
		checkMode("applier/relays.json", 0o640, rigStateGID)
		checkMode("applier/attempt.json", 0o600, -1)
		checkMode("applier/location.json", 0o600, -1)
	}

	// The candidate keeps working from that state: a switch through its panel.
	idA2, at := r.panelSwitch(a.host)
	r.waitVerified(p, a, idA2, 120*time.Second)
	r.waitPanelVerified(a, idA2, 30*time.Second)
	r.clientVia(a, 30*time.Second)
	t.Logf("candidate: switch to %s verified %v after the panel's answer", a.host, time.Since(at).Round(time.Millisecond))

	// 4. Rollback (docs/operations.md, upgrades: the previous bundle's files
	// back): the previous release's exit, then its panel, on the
	// candidate's state.
	r.bin = prev
	rolled := time.Now()
	p = r.restart(p)
	wantVersion(t, "the previous exit after the rollback", p.out.String(), "molebridge-exit: molebridge "+prevVersion)
	r.waitVerified(p, a, idA2, 120*time.Second)
	t.Logf("rollback: the previous exit ok on %s for request %s %v after the candidate's stop", a.host, idA2, time.Since(rolled).Round(time.Millisecond))
	r.stopPanel()
	r.startPanel()
	wantVersion(t, "the previous panel after the rollback", r.panelOut.String(), "molebridge panel: molebridge "+prevVersion)
	r.waitPanelVerified(a, idA2, 30*time.Second)
	r.clientVia(a, 30*time.Second)
	if stateGID && !prevKnowsStateGID {
		// "An older release ignores the setting and writes mode 0644 again."
		if m, _ := r.modeOf("applier/result.json"); m != 0o644 {
			t.Errorf("result.json after the rollback: mode %o, want 644", m)
		}
	}

	if n := r.counted("leak"); n != 0 {
		t.Errorf("%d client packets reached the internet by the exit's host path", n)
	}
	if !p.running() {
		t.Fatalf("the exit stopped (%d):\n%s", p.code, p.out.String())
	}
}
