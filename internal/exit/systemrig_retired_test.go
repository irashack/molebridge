//go:build drill && systemrig && linux

package exit

import (
	"encoding/json"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The applier's lines for a retired server (internal/applier/moved.go).
const (
	logMoving    = "applier: the requested server left the catalogue; moving to another server in the same city"
	logReturning = "applier: the requested server is in the catalogue again; returning to it"
)

var rigMovedNote = regexp.MustCompile(`<p class="note" data-moved>([^<]*)</p>`)

// restart stops the exit as a container stop does (SIGTERM, its own
// cleanup), resets the fake NetBird, starts it again and keys the overlay it
// creates. The native exit reads the relay catalogue at start, then every six
// hours: a restart is how the rig makes it refresh.
func (r *systemRig) restart(p *exitProc) *exitProc {
	t := r.t
	t.Helper()
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	if code := p.wait(30 * time.Second); code != 0 {
		t.Errorf("a requested stop exited %d", code)
	}
	_, _ = r.exit.Exec("nft", "delete", "table", "ip", "netbird")
	for _, f := range []string{"live", "trace"} {
		_ = os.Remove(filepath.Join(r.fakeDir, f))
	}
	p2 := r.start()
	r.waitReady(p2)
	r.keyOverlay()
	return p2
}

// location is the exit's location.json.
func (r *systemRig) location() map[string]any {
	raw, err := os.ReadFile(filepath.Join(r.stateDir, "applier", "location.json"))
	if err != nil {
		return nil
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

// movedNote is the panel page's note for a moved server, "" when there is
// none.
func (r *systemRig) movedNote() string {
	_, page, _ := r.panelGet("/" + r.panelQS)
	if m := rigMovedNote.FindSubmatch(page); m != nil {
		return html.UnescapeString(string(m[1]))
	}
	return ""
}

// TestSystemRigRetiredServer is the retired-server move on the native Mullvad
// exit (docs/verification.md, a retired server): the requested server leaves
// the relay API's list, the exit moves to the next server of its city, and
// returns once the server is listed again.
func TestSystemRigRetiredServer(t *testing.T) {
	t.Parallel()
	r := newSystemRig(t)
	a, b := r.relays[0], r.relays[1]
	p := r.bringUp()

	// Ask for relay A by name, so the exit records where it is.
	id, _ := r.panelSwitch(a.host)
	r.waitVerified(p, a, id, 120*time.Second)
	if l := r.location(); l["server"] != a.host || l["city"] != rigCity || l["country"] != rigCountry || l["replacement"] != nil {
		t.Fatalf("location.json after the request: %s", jsonText(l))
	}

	// A leaves the list; the exit refreshes it at its restart.
	r.retire(a.host, true)
	retired := time.Now()
	p = r.restart(p)
	wantMoved := map[string]any{"from": a.host, "to": b.host, "reason": "left-catalogue"}
	r.waitFor(150*time.Second, "the exit to move to "+b.host, func() bool {
		if !p.running() {
			t.Fatalf("the exit stopped:\n%s", p.out.String())
		}
		res := r.result()
		moved, _ := res["moved"].(map[string]any)
		return r.verified(b, "") && res["requested_server"] == a.host && res["request_id"] == id && jsonText(moved) == jsonText(wantMoved)
	})
	movedAfter := time.Since(retired)
	res := r.result()
	if !strings.Contains(p.out.String(), logMoving) {
		t.Errorf("no %q in the log:\n%s", logMoving, p.out.String())
	}
	if l := r.location(); l["server"] != a.host || l["replacement"] != b.host {
		t.Errorf("location.json after the move: %s", jsonText(l))
	}
	var v map[string]any
	r.waitFor(15*time.Second, "the panel to show the move", func() bool {
		v = r.panelStatus()
		reasons, _ := v["reasons"].([]any)
		return v["state"] == "ok" && v["label"] == "connected" && slices.Contains(reasons, any("server-moved"))
	})
	wantNote := a.host + " is no longer in the provider's server list. Connected through " + b.host + ", in the same city, instead."
	if note := r.movedNote(); note != wantNote {
		t.Errorf("the panel's note: %q, want %q", note, wantNote)
	}
	r.clientVia(b, 30*time.Second)
	t.Logf("retired %s: ok and verified on %s %v after the removal (restart included); moved %s, selection %s; panel %s %v",
		a.host, b.host, movedAfter.Round(time.Millisecond), jsonText(res["moved"]), jsonText(res["selection"]), v["label"], v["reasons"])

	// A is listed again: the exit returns to it.
	r.retire(a.host, false)
	restored := time.Now()
	p = r.restart(p)
	r.waitFor(150*time.Second, "the exit to return to "+a.host, func() bool {
		if !p.running() {
			t.Fatalf("the exit stopped:\n%s", p.out.String())
		}
		res := r.result()
		_, hasMoved := res["moved"]
		return r.verified(a, "") && res["request_id"] == id && (!hasMoved || res["moved"] == nil)
	})
	backAfter := time.Since(restored)
	res = r.result()
	if !strings.Contains(p.out.String(), logReturning) {
		t.Errorf("no %q in the log:\n%s", logReturning, p.out.String())
	}
	if l := r.location(); l["server"] != a.host || l["replacement"] != nil {
		t.Errorf("location.json after the return: %s", jsonText(l))
	}
	r.waitFor(15*time.Second, "the panel to show "+a.host+" with no move", func() bool {
		v = r.panelStatus()
		reasons, _ := v["reasons"].([]any)
		return v["state"] == "ok" && !slices.Contains(reasons, any("server-moved"))
	})
	if note := r.movedNote(); note != "" {
		t.Errorf("the panel still notes a move: %q", note)
	}
	r.clientVia(a, 30*time.Second)
	if n := r.counted("leak"); n != 0 {
		t.Errorf("%d client packets by the host path", n)
	}
	t.Logf("%s listed again: ok on %s %v after it returned (restart included), no moved; selection %s; panel %s %v",
		a.host, a.host, backAfter.Round(time.Millisecond), jsonText(res["selection"]), v["label"], v["reasons"])
}
