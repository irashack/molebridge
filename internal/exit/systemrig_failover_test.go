//go:build drill && systemrig && linux

package exit

import (
	"html"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The drills of automatic failover (docs/design/failover.md, system rig
// drills) on the native Mullvad exit, with the rig's two relays in one city,
// FAILOVER=same-city and the policy's timings shortened by the drill binary's
// hook (failover_hook_drill.go): returns 45 s apart, FAILOVER_AFTER its
// minimum, 120 s. The failures still come from the pipeline's own checks
// (one every 60 s; the first after the drop asks twice, up to 90 s) and
// every switch waits out the 90-second reapply guard.

// The applier's lines (internal/applier/failover.go).
const (
	logFailingOver   = "applier: the selected server has kept failing for "
	logBackOnBackup  = "applier: the selected server still fails; back to backup "
	logFailoverEnded = "applier: the selected server verified again; failover ended"
	logNewSelection  = "applier: a new selection ends the failover"
	logUplinkDown    = "applier: the host's network does not answer; not failing over"
	logNoBackup      = "applier: no backup verified; staying on the selected server"
	logTryingPrimary = "applier: trying the selected server again"
)

var (
	rigFailoverNote = regexp.MustCompile(`<p class="note" data-failover>([^<]*)</p>`)
	rigKeptFailing  = regexp.MustCompile(regexp.QuoteMeta(logFailingOver) + `(\d+) s`)
)

// drillAfter is the drills' FAILOVER_AFTER. A dropped server must count
// from the first check after the drop, which ends within detectWithin (the
// next periodic check, 60 s, and its two tries of up to 100 s, on 5-second
// passes), and the failover come within drillAfter and a minute of that.
const (
	drillAfter   = 120 * time.Second
	detectWithin = 170 * time.Second
)

// failoverRig is a system rig whose exit runs the drill binary with failover
// on.
func failoverRig(t *testing.T) *systemRig {
	r := newSystemRig(t)
	r.bin = filepath.Join(filepath.Dir(r.bin), "molebridge-drill")
	r.exitExtra = append(r.exitExtra, "FAILOVER=same-city", "FAILOVER_RETURN=auto",
		"MOLEBRIDGE_DRILL_FAILOVER_AFTER="+strconv.Itoa(int(drillAfter.Seconds())), "MOLEBRIDGE_DRILL_FAILOVER_RETURN=45,45,45", "MOLEBRIDGE_DRILL_FAILOVER_TRACE=1")
	return r
}

// dropRelay makes relay rl drop the exit's WireGuard packets (dropped true)
// or answer them again.
func (r *systemRig) dropRelay(rl *rigRelay, dropped bool) {
	r.t.Helper()
	if !dropped {
		if out, err := rl.ns.Exec("nft", "delete", "table", "inet", "drill_drop"); err != nil {
			r.t.Fatalf("nft in %s: %v\n%s", rl.host, err, out)
		}
		return
	}
	rules := `table inet drill_drop {
  chain in {
    type filter hook input priority filter; policy accept;
    udp dport 51820 drop
  }
}
`
	if out, err := rl.ns.ExecInput(rules, "nft", "-f", "-"); err != nil {
		r.t.Fatalf("nft in %s: %v\n%s", rl.host, err, out)
	}
}

// dropUplink makes the relay API (the catalogue host, which the uplink probe
// asks) unreachable over the exit's host path, or reachable again.
func (r *systemRig) dropUplink(dropped bool) {
	r.t.Helper()
	if !dropped {
		if out, err := r.internet.Exec("nft", "delete", "table", "inet", "drill_uplink"); err != nil {
			r.t.Fatalf("nft: %v\n%s", err, out)
		}
		return
	}
	rules := `table inet drill_uplink {
  chain in {
    type filter hook input priority filter; policy accept;
    iifname "exit0" ip daddr ` + rigAPI4 + ` drop
    iifname "exit0" ip6 daddr ` + rigAPI6 + ` drop
  }
}
`
	if out, err := r.internet.ExecInput(rules, "nft", "-f", "-"); err != nil {
		r.t.Fatalf("nft: %v\n%s", err, out)
	}
}

// linesSince is the exit's applier and drill lines after the first mark
// bytes of its output.
func linesSince(p *exitProc, mark int) string {
	var out []string
	for _, line := range strings.Split(p.out.String()[mark:], "\n") {
		if strings.Contains(line, "applier:") || strings.Contains(line, "drill:") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

// failoverMember is result.json's failover member, nil when there is none.
func failoverMember(res map[string]any) map[string]any {
	m, _ := res["failover"].(map[string]any)
	return m
}

// failoverNote is the panel page's failover note, "" when there is none.
func (r *systemRig) failoverNote() string {
	_, page, _ := r.panelGet("/" + r.panelQS)
	if m := rigFailoverNote.FindSubmatch(page); m != nil {
		return html.UnescapeString(string(m[1]))
	}
	return ""
}

// onBackup reports result.json verified on backup b, standing in for a under
// requestID.
func (r *systemRig) onBackup(a, b *rigRelay, requestID string) bool {
	res := r.result()
	fo := failoverMember(res)
	sel, _ := res["selection"].(map[string]any)
	return r.verified(b, "") && res["requested_server"] == a.host && res["request_id"] == requestID &&
		sel["source"] == "failover" && fo["from"] == a.host && fo["to"] == b.host && fo["phase"] == "on-backup"
}

// selectedAndVerified asks the panel for relay a and waits for the exit to
// verify it, so that location.json knows a's city.
func (r *systemRig) selectedAndVerified(p *exitProc, a *rigRelay) string {
	r.t.Helper()
	id, _ := r.panelSwitch(a.host)
	r.waitVerified(p, a, id, 120*time.Second)
	if l := r.location(); l["server"] != a.host || l["city"] != rigCity {
		r.t.Fatalf("location.json after the request: %s", jsonText(l))
	}
	return id
}

// waitRunning waits for cond while the exit runs; on a timeout it logs the
// applier's lines and result.json before failing.
func (r *systemRig) waitRunning(p *exitProc, d time.Duration, what string, cond func() bool) {
	r.t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if !p.running() {
			r.t.Fatalf("the exit stopped:\n%s", p.out.String())
		}
		if time.Now().After(deadline) {
			var lines []string
			for _, line := range strings.Split(p.out.String(), "\n") {
				if strings.Contains(line, "applier:") {
					lines = append(lines, line)
				}
			}
			if len(lines) > 120 {
				lines = lines[len(lines)-120:]
			}
			r.t.Fatalf("timed out after %v waiting for %s\nthe applier's lines:\n%s\nresult.json: %s", d, what,
				strings.Join(lines, "\n"), jsonText(r.result()))
		}
		time.Sleep(time.Second)
	}
}

// TestSystemRigFailover is drills 1 to 3: the primary's UDP dropped, the exit
// moves to the backup in its city; a return while it is still dropped goes
// back to the backup; once it answers again, the next return ends the
// episode.
func TestSystemRigFailover(t *testing.T) {
	t.Parallel()
	r := failoverRig(t)
	a, b := r.relays[0], r.relays[1]
	p := r.bringUp()
	id := r.selectedAndVerified(p, a)

	// 1. A drops: the exit moves to B and both verdicts say so.
	r.dropRelay(a, true)
	dropped, mark := time.Now(), len(p.out.String())
	var decided time.Duration
	r.waitRunning(p, 600*time.Second, "the exit to fail over to "+b.host, func() bool {
		if decided == 0 && strings.Contains(p.out.String()[mark:], logFailingOver) {
			decided = time.Since(dropped)
		}
		return r.onBackup(a, b, id)
	})
	movedAfter := time.Since(dropped)
	res := r.result()
	t.Logf("the exit's lines from the drop to the failover:\n%s", linesSince(p, mark))
	// The policy's bound: the failover within FAILOVER_AFTER and a minute
	// of the first eligible failure, and that failure the first check
	// after the drop.
	m := rigKeptFailing.FindStringSubmatch(p.out.String()[mark:])
	if m == nil {
		t.Fatalf("no %q line after the drop", logFailingOver)
	}
	failing, _ := strconv.Atoi(m[1])
	counted := time.Duration(failing) * time.Second
	if counted > drillAfter+time.Minute || decided-counted > detectWithin || movedAfter > decided+time.Minute {
		t.Errorf("the failover came %v after the drop (decided at %v, %v after the first eligible failure; on the backup at %v), want within %v of a first eligible failure at most %v after the drop",
			decided.Round(time.Second), decided.Round(time.Second), counted, movedAfter.Round(time.Second), drillAfter+time.Minute, detectWithin)
	}
	if !strings.Contains(p.out.String(), logFailingOver) || !strings.Contains(p.out.String(), "moving to backup "+b.host) {
		t.Errorf("no failover line in the log:\n%s", p.out.String())
	}
	if l := r.location(); l["server"] != a.host || l["replacement"] != nil {
		t.Errorf("location.json remembers the backup: %s", jsonText(l))
	}
	if _, err := os.Stat(filepath.Join(r.stateDir, "applier", "failover.json")); err != nil {
		t.Errorf("failover.json: %v", err)
	}
	var v map[string]any
	r.waitFor(15*time.Second, "the panel to show the backup", func() bool {
		v = r.panelStatus()
		reasons, _ := v["reasons"].([]any)
		return v["state"] == "ok" && v["label"] == "connected to backup" && slices.Contains(reasons, any("failover"))
	})
	wantNote := "Connected to backup " + b.host + ". " + a.host + " has kept failing since "
	if note := r.failoverNote(); !strings.HasPrefix(note, wantNote) || !strings.Contains(note, "trying it again at") {
		t.Errorf("the panel's note: %q, want it to start %q", note, wantNote)
	}
	r.clientVia(b, 30*time.Second)
	t.Logf("%s dropped: failover decided %v later, %v after the first eligible failure; on backup %s %v after the drop; failover %s; panel %s %v",
		a.host, decided.Round(time.Second), counted, b.host, movedAfter.Round(time.Second), jsonText(res["failover"]), v["label"], v["reasons"])

	// 3. The first return, A still dropped: back on B.
	r.waitRunning(p, 240*time.Second, "a return to "+a.host, func() bool { return strings.Contains(p.out.String(), logTryingPrimary) })
	returned := time.Now()
	r.waitRunning(p, 360*time.Second, "the exit back on "+b.host, func() bool {
		return strings.Contains(p.out.String(), logBackOnBackup+b.host) && r.onBackup(a, b, id)
	})
	t.Logf("a return to %s, still dropped: on %s again %v later", a.host, b.host, time.Since(returned).Round(time.Second))

	// 2. A answers again: the next return ends the episode.
	r.dropRelay(a, false)
	restored := time.Now()
	r.waitRunning(p, 420*time.Second, "the exit to return to "+a.host, func() bool {
		res := r.result()
		sel, _ := res["selection"].(map[string]any)
		return r.verified(a, id) && failoverMember(res) == nil && sel["source"] == "panel"
	})
	if !strings.Contains(p.out.String(), logFailoverEnded) {
		t.Errorf("no %q in the log:\n%s", logFailoverEnded, p.out.String())
	}
	r.waitFor(15*time.Second, "the panel to show "+a.host+" connected", func() bool {
		v = r.panelStatus()
		return v["state"] == "ok" && v["label"] == "connected"
	})
	if note := r.failoverNote(); note != "" {
		t.Errorf("the panel still notes a failover: %q", note)
	}
	r.clientVia(a, 30*time.Second)
	if n := r.counted("leak"); n != 0 {
		t.Errorf("%d client packets by the host path", n)
	}
	t.Logf("%s answers again: back on it %v later, no failover member", a.host, time.Since(restored).Round(time.Second))
}

// TestSystemRigFailoverUplinkAndPanel is drills 4 and 6: with the host's
// uplink (the catalogue host) unreachable too, the exit doesn't fail over;
// once it answers, it does; a panel request then ends the episode at once.
func TestSystemRigFailoverUplinkAndPanel(t *testing.T) {
	t.Parallel()
	r := failoverRig(t)
	a, b := r.relays[0], r.relays[1]
	p := r.bringUp()
	id := r.selectedAndVerified(p, a)

	// 4. A drops and the uplink is down: no failover.
	r.dropUplink(true)
	r.dropRelay(a, true)
	r.waitRunning(p, 600*time.Second, "the uplink probe to hold the failover", func() bool {
		return strings.Contains(p.out.String(), logUplinkDown)
	})
	if res := r.result(); res["server"] != a.host || failoverMember(res) != nil {
		t.Fatalf("failed over with the uplink down: %s", jsonText(res))
	}
	r.dropUplink(false)
	r.waitRunning(p, 540*time.Second, "the exit to fail over to "+b.host, func() bool { return r.onBackup(a, b, id) })
	t.Logf("the uplink down held the failover; once it answered, on %s", b.host)

	// 6. A panel request during the episode: applied at once, the episode
	// ended.
	r.dropRelay(a, false)
	id2, at := r.panelSwitch(a.host)
	r.waitRunning(p, 90*time.Second, "the request applied on "+a.host, func() bool {
		res := r.result()
		return r.verified(a, id2) && failoverMember(res) == nil
	})
	if !strings.Contains(p.out.String(), logNewSelection) {
		t.Errorf("no %q in the log:\n%s", logNewSelection, p.out.String())
	}
	if n := r.counted("leak"); n != 0 {
		t.Errorf("%d client packets by the host path", n)
	}
	t.Logf("a panel request during the episode: verified on %s %v after it", a.host, time.Since(at).Round(time.Second))
}

// TestSystemRigFailoverExhausted is drill 5: both relays dropped, the backup
// doesn't verify, the episode is exhausted and the exit retries the primary.
func TestSystemRigFailoverExhausted(t *testing.T) {
	t.Parallel()
	r := failoverRig(t)
	a, b := r.relays[0], r.relays[1]
	p := r.bringUp()
	r.selectedAndVerified(p, a)

	r.dropRelay(a, true)
	r.dropRelay(b, true)
	dropped := time.Now()
	r.waitRunning(p, 720*time.Second, "an exhausted episode", func() bool {
		fo := failoverMember(r.result())
		return fo["phase"] == "exhausted" && fo["from"] == a.host && strings.Contains(p.out.String(), logNoBackup)
	})
	res := r.result()
	if tried, _ := failoverMember(res)["tried"].([]any); len(tried) != 1 || tried[0] != b.host {
		t.Errorf("tried %v", failoverMember(res)["tried"])
	}
	var v map[string]any
	r.waitRunning(p, 240*time.Second, "the exit back on "+a.host+", failed", func() bool {
		v = r.panelStatus()
		reasons, _ := v["reasons"].([]any)
		return r.result()["server"] == a.host && v["state"] == "failed" && slices.Contains(reasons, any("failover-exhausted"))
	})
	if note := r.failoverNote(); note != "No backup verified; retrying "+a.host+"." {
		t.Errorf("the panel's note: %q", note)
	}
	if n := r.counted("leak"); n != 0 {
		t.Errorf("%d client packets by the host path", n)
	}
	t.Logf("both dropped: exhausted %v later; panel %s %v", time.Since(dropped).Round(time.Second), v["label"], v["reasons"])
}
