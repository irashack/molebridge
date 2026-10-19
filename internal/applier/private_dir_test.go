package applier

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/validate"
)

// With PrivateDir set, the files only the exit reads live there and
// state/applier holds only what the exit publishes.

func assertOnlyPrivate(t *testing.T, dir, private, name string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(private, name)); err != nil {
		t.Errorf("%s not in the private directory: %v", name, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "applier", name)); err == nil {
		t.Errorf("%s written to state/applier", name)
	}
}

func TestPrivateDirHoldsTheAttempt(t *testing.T) {
	dir, private := t.TempDir(), t.TempDir()
	k := newKernel(t)
	k.keys = []string{otherKey}
	writeSnapshot(t, dir, "", map[string]any{testHost: mullvadEntry(testHost, testKey), otherHost: mullvadEntry(otherHost, otherKey)})
	a, err := New(Config{StateDir: dir, PrivateDir: private, Exit: k.exit, Provider: NewMullvad(), System: k, BootID: testBoot,
		Monotonic: k.clock, Sleep: k.sleep, Log: func(s string) { k.logs = append(k.logs, s) }})
	if err != nil {
		t.Fatal(err)
	}
	a.nextCatalog = infinity
	a.ownerCheck = func() validate.Obj { return validate.Members("state", "pass", "at", validate.FormatTime(time.Now())) }
	withPublished(a, dir)
	desire(t, a, requestAt(testHost, nil))
	if r := mustTick(t, a); status(r) != "ok" {
		t.Fatalf("%s: %s", status(r), message(r))
	}
	assertOnlyPrivate(t, dir, private, "attempt.json")
	for _, name := range []string{"result.json", "relays.json"} {
		if _, err := os.Stat(filepath.Join(dir, "applier", name)); err != nil {
			t.Errorf("%s not published: %v", name, err)
		}
	}
}

func TestPrivateDirHoldsGluetunsSelection(t *testing.T) {
	private := t.TempDir()
	f := newGluetunFixture(t, glOptions{private: private})
	if r := f.a.switchTo(t, glRequest(hostB)); status(r) != "ok" {
		t.Fatalf("%s: %s", status(r), message(r))
	}
	assertOnlyPrivate(t, f.dir, private, "gluetun-selection.json")
	if file := readState(t, filepath.Join(private, "gluetun-selection.json")); file["last_successful"] != hostB {
		t.Errorf("selection file %v", file)
	}
}

func TestPrivateDirHoldsPIAsRegistration(t *testing.T) {
	a, _, _, dir, _ := piaSetup(t, false)
	a.privateDir = t.TempDir()
	if r := a.switchTo(t, piaRequest(nil)); status(r) != "ok" {
		t.Fatalf("%s: %s", status(r), message(r))
	}
	assertOnlyPrivate(t, dir, a.privateDir, "tunnel.json")
}
