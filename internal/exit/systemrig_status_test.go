//go:build drill && systemrig && linux

package exit

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/applier"
	"github.com/irashack/molebridge/internal/verdict"
)

// switchInProgress is the panel's answer to a switch while another is
// applying (internal/panel/server.go).
const switchInProgress = "A switch is in progress; wait for it to finish."

// TestSystemRigStatus is the status drills of docs/verification.md on the
// system rig, each on a rig of its own, in parallel with each other and
// with TestSystemRigClientSwitch.
func TestSystemRigStatus(t *testing.T) {
	t.Parallel()
	t.Run("EgressCheckFailure", func(t *testing.T) {
		t.Parallel()
		r := newSystemRig(t)
		_, b := r.relays[0], r.relays[1]
		p := r.bringUp()
		id, _ := r.panelSwitch(b.host)
		r.waitVerified(p, b, id, 120*time.Second)

		// The exit's own HTTPS through the tunnel, which only its egress
		// check uses, as the live drill drops it.
		drop := "table inet molebridge_drill {\n  chain out {\n    type filter hook output priority 0; policy accept;\n" +
			"    oifname \"" + dExit + "\" tcp dport 443 drop\n  }\n}\n"
		if out, err := r.exit.ExecInput(drop, "nft", "-f", "-"); err != nil {
			t.Fatalf("nft: %v\n%s", err, out)
		}
		dropped := time.Now()
		seen := map[string]bool{}
		watch := func() {
			if res := r.result(); res != nil {
				seen[fmtStatus(res)] = true
				if res["server"] != b.host || res["status"] == "applying" {
					t.Errorf("the live server must stay %s, not applying: %s", b.host, fmtStatus(res))
				}
			}
		}
		r.waitFor(150*time.Second, "result.json failed, applied-unverified with a recheck", func() bool {
			watch()
			res := r.result()
			sel, _ := res["selection"].(map[string]any)
			return res["status"] == "failed" && res["message"] == applier.EgressFailedMessage && res["server"] == b.host &&
				sel["outcome"] == "applied-unverified" && sel["next_action"] == "recheck" && res["request_id"] == id
		})
		failedAfter := time.Since(dropped)
		if v := r.panelStatus(); v["state"] != "failed" || v["message"] != applier.EgressFailedMessage {
			t.Errorf("the panel's verdict while the check fails: %s", jsonText(v))
		}
		// The client's traffic continues meanwhile.
		r.clientVia(b, 20*time.Second)
		if out, err := r.exit.Exec("nft", "delete", "table", "inet", "molebridge_drill"); err != nil {
			t.Fatalf("nft: %v\n%s", err, out)
		}
		lifted := time.Now()
		r.waitFor(150*time.Second, "result.json ok again on "+b.host, func() bool {
			watch()
			return r.verified(b, id)
		})
		okAfter := time.Since(lifted)
		t.Logf("egress check dropped: failed (applied-unverified, recheck) %v after the drop; ok %v after it was lifted; records seen: %v",
			failedAfter.Round(time.Millisecond), okAfter.Round(time.Millisecond), keys(seen))
		if n := r.counted("leak"); n != 0 {
			t.Errorf("%d client packets by the host path", n)
		}
	})

	t.Run("SecondSwitch409", func(t *testing.T) {
		t.Parallel()
		r := newSystemRig(t)
		drillSecondSwitch(r, r.bringUp())
	})

	t.Run("FailedSwitchRetry", func(t *testing.T) {
		t.Parallel()
		r := newSystemRig(t)
		drillFailedRetry(r, r.bringUp())
	})

	t.Run("StoppedExit", func(t *testing.T) {
		t.Parallel()
		r := newSystemRig(t)
		p := r.bringUp()
		ready := func() (int, int) {
			rc, _, _ := r.panelGet("/readyz")
			hc, _, _ := r.panelGet("/healthz")
			return rc, hc
		}
		if rc, hc := ready(); rc != 200 || hc != 200 {
			t.Fatalf("before the stop: /readyz %d, /healthz %d", rc, hc)
		}
		// A stopped container: the whole tree at once, no cleanup.
		stopped := time.Now()
		killTree(r.exit)
		p.wait(15 * time.Second)
		limit := time.Duration(verdict.EvidenceMaxAge)*time.Second + 10*time.Second
		var notReady time.Duration
		r.waitFor(limit, "/readyz 503", func() bool {
			rc, hc := ready()
			if hc != 200 {
				t.Errorf("/healthz %d while the exit is stopped", hc)
			}
			if rc == 503 {
				notReady = time.Since(stopped)
				return true
			}
			time.Sleep(time.Second)
			return false
		})
		v := r.panelStatus()
		// Stale once the record is EvidenceMaxAge old; the lapsed lease can
		// fail it sooner.
		staleBy := time.Duration(verdict.EvidenceMaxAge)*time.Second + 10*time.Second - time.Since(stopped)
		r.waitFor(staleBy+time.Second, "the verdict to say status stale", func() bool {
			v = r.panelStatus()
			if rc, hc := ready(); rc != 503 || hc != 200 {
				t.Errorf("while stopped: /readyz %d, /healthz %d", rc, hc)
			}
			time.Sleep(time.Second)
			return v["label"] == "status stale"
		})
		staleAfter := time.Since(stopped)

		// The namespace outlives the stop here, as a container's would not:
		// run the exit's own cleanup role, and reset the fake NetBird.
		cleanup := exec.Command("ip", "netns", "exec", r.exit.Name, r.bin, "exit", "--cleanup", "--backend", "native", "--kind", "overlay")
		cleanup.Env = CleanupEnv(EnvMap(r.env()))
		if out, err := cleanup.CombinedOutput(); err != nil {
			t.Fatalf("cleanup: %v\n%s", err, out)
		}
		_, _ = r.exit.Exec("nft", "delete", "table", "ip", "netbird")
		for _, f := range []string{"live", "trace"} {
			_ = os.Remove(filepath.Join(r.fakeDir, f))
		}
		restarted := time.Now()
		p2 := r.start()
		r.waitReady(p2)
		var readyAgain time.Duration
		r.waitFor(150*time.Second, "/readyz 200 after the restart", func() bool {
			if !p2.running() {
				t.Fatalf("the exit stopped:\n%s", p2.out.String())
			}
			if rc, _ := ready(); rc == 200 {
				readyAgain = time.Since(restarted)
				return true
			}
			time.Sleep(time.Second)
			return false
		})
		t.Logf("stopped exit: /readyz 503 %v after the stop (verdict %s at %v), /healthz 200 throughout; /readyz 200 %v after the restart",
			notReady.Round(time.Millisecond), v["label"], staleAfter.Round(time.Millisecond), readyAgain.Round(time.Millisecond))
	})
}

// drillSecondSwitch holds the exit's checks so a switch to relay B stays
// applying, posts a second switch through the panel and expects the 409, then
// lets the first complete. The panel's side is read from /api/status, so it
// runs the same through the network exchange.
func drillSecondSwitch(r *systemRig, p *exitProc) {
	t := r.t
	a, b := r.relays[0], r.relays[1]
	release := r.holdChecks()
	defer release()
	id, at := r.panelSwitch(b.host)
	r.waitFor(30*time.Second, "the panel to read the record applying for "+b.host, func() bool {
		res := r.panelResult()
		return res["status"] == "applying" && res["request_id"] == id && r.panelStatus()["state"] == "applying"
	})
	code, body, _, _ := r.panelPost(a.host)
	if code != 409 || body != switchInProgress {
		t.Errorf("a second switch while the first applies: %d %q, want 409 %q", code, body, switchInProgress)
	}
	if got := r.requestID(b.host); got != id {
		t.Errorf("the refused switch replaced the request: %s, want %s", got, id)
	}
	release()
	r.waitVerified(p, b, id, 120*time.Second)
	r.waitPanelVerified(b, id, 30*time.Second)
	t.Logf("409 %q while the first switch applied; the first switch verified %v after its request, on the panel's side",
		body, time.Since(at).Round(time.Millisecond))
}

// drillFailedRetry blocks relay B's WireGuard port, switches to B and expects
// the handshake failure and the panel's Retry; then lifts the block, posts
// Retry and expects verified with source operator-retry.
func drillFailedRetry(r *systemRig, p *exitProc) {
	t := r.t
	b := r.relays[1]
	drop := "table inet drill {\n  chain in {\n    type filter hook input priority 0; policy accept;\n    udp dport 51820 drop\n  }\n}\n"
	if out, err := b.ns.ExecInput(drop, "nft", "-f", "-"); err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}
	id, at := r.panelSwitch(b.host)
	var v, res map[string]any
	r.waitFor(150*time.Second, "the switch to "+b.host+" to fail on the handshake", func() bool {
		if !p.running() {
			t.Fatalf("the exit stopped:\n%s", p.out.String())
		}
		payload := r.panelPayload()
		res, _ = payload["result"].(map[string]any)
		v, _ = payload["verdict"].(map[string]any)
		sel, _ := res["selection"].(map[string]any)
		checks, _ := res["checks"].(map[string]any)
		hs, _ := checks["handshake"].(map[string]any)
		reasons, _ := v["reasons"].([]any)
		return res["status"] == "failed" && res["server"] == b.host && res["request_id"] == id &&
			sel["outcome"] == "applied-unverified" && hs["state"] == "fail" &&
			v["state"] == "failed" && slices.Contains(reasons, any("handshake-failed"))
	})
	failedAfter := time.Since(at)
	retryButton := `name="server" value="` + b.host + `" class="relay-switch" data-retry>Retry</button>`
	if _, page, _ := r.panelGet("/" + r.panelQS); !strings.Contains(string(page), retryButton) {
		t.Fatalf("the panel offers no Retry for %s; verdict %s", b.host, jsonText(v))
	}
	if out, err := b.ns.Exec("nft", "delete", "table", "inet", "drill"); err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}
	// Retry posts the server form with the failed server, as its button does.
	code, body, retried, _ := r.panelPost(b.host)
	if code != 303 {
		t.Fatalf("Retry: %d %s", code, body)
	}
	retryID := r.requestID(b.host)
	r.waitVerified(p, b, retryID, 120*time.Second)
	verifiedAfter := time.Since(retried)
	r.waitPanelVerified(b, retryID, 30*time.Second)
	panelAfter := time.Since(retried)
	if sel, _ := r.panelResult()["selection"].(map[string]any); sel["source"] != "operator-retry" {
		t.Errorf("the retry's selection: %s", jsonText(sel))
	}
	r.clientVia(b, 30*time.Second)
	t.Logf("failed switch: failed (verdict %v, message %v, outcome applied-unverified) %v after the request; verified with source operator-retry %v after Retry, on the panel's side at %v",
		v["reasons"], res["message"], failedAfter.Round(time.Millisecond), verifiedAfter.Round(time.Millisecond), panelAfter.Round(time.Millisecond))
}

func fmtStatus(res map[string]any) string {
	sel, _ := res["selection"].(map[string]any)
	return strings.Join([]string{toString(res["status"]), toString(res["server"]), toString(sel["outcome"]), toString(sel["next_action"])}, "/")
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return jsonText(v)
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
