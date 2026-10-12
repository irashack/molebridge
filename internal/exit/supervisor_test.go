package exit

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/contract"
)

const fakeNetBird = `#!/bin/sh
# A stand-in for the netbird client: it records what it was asked to do.
t=${NB_TRACE_FILE:?}
case "$1" in
service)
    echo "netbird service run" >> "$t"
    echo "log line from the fake daemon"
    : > "$t.live"
    trap 'echo "netbird terminated" >> "$t"; exit 0' TERM
    if [ "$NB_FAKE_MODE" = die ]; then sleep 1; echo "netbird died" >> "$t"; exit 9; fi
    if [ "$NB_FAKE_MODE" = deaf ]; then trap '' TERM; fi
    sleep 600 &
    wait $!
    ;;
status) [ -f "$t.live" ] ;;
up)
    echo "netbird up" >> "$t"
    [ "$NB_FAKE_MODE" != upfail ] ;;
*) exit 2 ;;
esac
`

type harness struct {
	t       *testing.T
	dir     string
	trace   string
	s       *Settings
	cfg     Config
	sigs    chan os.Signal
	mu      sync.Mutex
	written []map[string]any
	writes  int
}

func newHarness(t *testing.T, workerMode, cleanupMode string) *harness {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the boot clock is shared between processes only on Linux; run in the Linux container")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "netbird"), []byte(fakeNetBird), 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, dir: dir, trace: filepath.Join(dir, "trace"), sigs: make(chan os.Signal, 4)}
	s := settingsFor(contract.Overlay, contract.Native, "mullvad")
	s.Grace = time.Second
	s.StateDir = filepath.Join(dir, "state")
	s.RunDir = filepath.Join(dir, "run")
	s.Env = map[string]string{"PATH": bin + ":/usr/bin:/bin", "NB_TRACE_FILE": h.trace, "MB_TRACE_FILE": h.trace}
	h.s = s
	h.cfg = Config{
		Settings: s, Reaper: testReaper, Self: self,
		WorkerArgs:  []string{"fake-worker", workerMode},
		CleanupArgs: []string{"fake-cleanup", cleanupMode},
		Signals:     h.sigs, Stderr: os.Stderr,
		Timing: Timing{Tick: 50 * time.Millisecond, PublishEvery: 100 * time.Millisecond,
			StopKill: time.Second, StopReaped: 1500 * time.Millisecond, CleanupEnd: 3 * time.Second, ExitBy: 3500 * time.Millisecond,
			NBLive: 5 * time.Second, NBPoll: 50 * time.Millisecond, NBProbe: 2 * time.Second, NBUp: 5 * time.Second, NBTerm: time.Second},
		Write: func(path string, v any) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.writes++
			raw, err := marshalForTest(v)
			if err == nil {
				h.written = append(h.written, raw)
			}
			return nil
		},
	}
	return h
}

// run starts the supervisor and returns its exit code on a channel.
func (h *harness) run() <-chan int {
	sup := New(h.cfg)
	done := make(chan int, 1)
	go func() { done <- sup.Run() }()
	return done
}

func (h *harness) traceLines() []string {
	raw, _ := os.ReadFile(h.trace)
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func (h *harness) waitTrace(substr string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, l := range h.traceLines() {
			if strings.Contains(l, substr) {
				return true
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

func index(lines []string, substr string) int {
	for i, l := range lines {
		if strings.Contains(l, substr) {
			return i
		}
	}
	return -1
}

func (h *harness) wait(done <-chan int, d time.Duration) int {
	h.t.Helper()
	select {
	case code := <-done:
		return code
	case <-time.After(d):
		h.t.Fatalf("the supervisor did not exit within %v\ntrace:\n%s", d, strings.Join(h.traceLines(), "\n"))
		return -1
	}
}

func (h *harness) lastRecord() map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.written) == 0 {
		return nil
	}
	return h.written[len(h.written)-1]
}

func TestNetBirdStartsOnlyAfterReady(t *testing.T) {
	h := newHarness(t, "good", "ok")
	done := h.run()
	if !h.waitTrace("netbird up", 10*time.Second) {
		t.Fatalf("NetBird never came up\n%s", strings.Join(h.traceLines(), "\n"))
	}
	lines := h.traceLines()
	ready, svc, up := index(lines, "worker ready"), index(lines, "netbird service run"), index(lines, "netbird up")
	if ready < 0 || svc < ready || up < svc {
		t.Fatalf("order: ready %d, service %d, up %d\n%v", ready, svc, up, lines)
	}
	if !h.waitTrace("worker told netbird started 1", 5*time.Second) {
		t.Fatalf("the worker was never told NetBird started\n%v", h.traceLines())
	}
	h.sigs <- syscall.SIGTERM
	if code := h.wait(done, 10*time.Second); code != 0 {
		t.Fatalf("a requested stop with complete cleanup exits 0, got %d", code)
	}
	lines = h.traceLines()
	for _, want := range []string{"netbird terminated", "worker told to stop", "cleanup ok"} {
		if index(lines, want) < 0 {
			t.Errorf("missing %q in %v", want, lines)
		}
	}
	if index(lines, "cleanup ok") < index(lines, "netbird terminated") {
		t.Error("the cleanup must run after NetBird is gone")
	}
}

func TestNoNetBirdWithoutReady(t *testing.T) {
	h := newHarness(t, "crash", "ok") // renews, never says ready
	done := h.run()
	h.wait(done, 10*time.Second)
	if index(h.traceLines(), "netbird service run") >= 0 {
		t.Fatal("NetBird was started without a ready")
	}
}

func TestFrozenWorkerLapsesTheLeaseAndStopsNetBird(t *testing.T) {
	h := newHarness(t, "freeze", "ok")
	start := time.Now()
	done := h.run()
	if !h.waitTrace("worker frozen", 10*time.Second) {
		t.Fatal("never froze")
	}
	frozen := time.Now()
	code := h.wait(done, 15*time.Second)
	if code == 0 {
		t.Fatal("a lapsed lease must exit non-zero")
	}
	// The grace (1 s here) plus the shortened stop timeline.
	if took := time.Since(frozen); took > h.s.Grace+h.cfg.Timing.ExitBy+500*time.Millisecond {
		t.Errorf("failure to exit took %v (started %v ago)", took, time.Since(start))
	}
	lines := h.traceLines()
	if index(lines, "netbird terminated") < 0 {
		t.Errorf("NetBird was not stopped: %v", lines)
	}
	if index(lines, "cleanup ok") < 0 {
		t.Errorf("the cleanup did not run: %v", lines)
	}
	rec := h.lastRecord()
	if rec == nil || rec["status"] != "failed" || rec["message"] != OwnerStoppedMessage {
		t.Fatalf("the failure record: %v", rec)
	}
	if rec["checks"].(map[string]any)["owner_record"].(map[string]any)["state"] != "fail" {
		t.Errorf("owner_record: %v", rec["checks"])
	}
}

func TestWedgedLoopLapsesTheLeaseEvenWithRenewalsArriving(t *testing.T) {
	h := newHarness(t, "stale", "ok")
	done := h.run()
	if code := h.wait(done, 20*time.Second); code == 0 {
		t.Fatal("exit status")
	}
	if index(h.traceLines(), "netbird terminated") < 0 {
		t.Errorf("NetBird was not stopped: %v", h.traceLines())
	}
}

func TestCrashedWorkerCleansUpAndExitsNonZero(t *testing.T) {
	h := newHarness(t, "crash", "ok")
	done := h.run()
	if code := h.wait(done, 10*time.Second); code != 1 {
		t.Fatalf("exit %d", code)
	}
	lines := h.traceLines()
	if index(lines, "worker crashing") < 0 || index(lines, "cleanup ok") < 0 {
		t.Fatalf("%v", lines)
	}
	if rec := h.lastRecord(); rec["status"] != "failed" || rec["message"] != OwnerStoppedMessage {
		t.Fatalf("%v", rec)
	}
}

func TestProtocolViolationsStopTheExit(t *testing.T) {
	for _, mode := range []string{"badprotocol", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, mode, "ok")
			done := h.run()
			if code := h.wait(done, 10*time.Second); code != 1 {
				t.Fatalf("exit %d", code)
			}
			if index(h.traceLines(), "cleanup ok") < 0 {
				t.Error("the cleanup did not run")
			}
		})
	}
}

func TestAWorkerThatIgnoresStopIsKilledAndCleanupStillRuns(t *testing.T) {
	h := newHarness(t, "hangstop", "ok")
	done := h.run()
	if !h.waitTrace("worker ready", 10*time.Second) {
		t.Fatal("not ready")
	}
	start := time.Now()
	h.sigs <- syscall.SIGTERM
	h.sigs <- syscall.SIGTERM // a second TERM changes nothing
	if code := h.wait(done, 10*time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if took := time.Since(start); took < h.cfg.Timing.StopKill {
		t.Errorf("the stop finished in %v, before the KILL deadline %v: a second TERM must not shorten it", took, h.cfg.Timing.StopKill)
	}
	if index(h.traceLines(), "cleanup ok") < 0 {
		t.Error("the cleanup did not run after the worker was killed")
	}
}

func TestIncompleteCleanupIsNonZeroEvenForARequestedStop(t *testing.T) {
	for _, mode := range []string{"fail", "hang"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t, "good", mode)
			done := h.run()
			if !h.waitTrace("worker ready", 10*time.Second) {
				t.Fatal("not ready")
			}
			h.sigs <- syscall.SIGINT
			start := time.Now()
			if code := h.wait(done, 10*time.Second); code != 1 {
				t.Fatalf("exit %d", code)
			}
			if took := time.Since(start); took > h.cfg.Timing.ExitBy+time.Second {
				t.Errorf("took %v", took)
			}
		})
	}
}

func TestUnreadyStopsNetBirdAndReadyStartsItAgain(t *testing.T) {
	h := newHarness(t, "unready-after-start", "ok")
	done := h.run()
	if !h.waitTrace("worker ready again", 15*time.Second) {
		t.Fatalf("%v", h.traceLines())
	}
	if !h.waitTrace("worker told netbird started 2", 15*time.Second) {
		t.Fatalf("NetBird was not started a second time: %v", h.traceLines())
	}
	lines := h.traceLines()
	if first, term, second := index(lines, "netbird service run"), index(lines, "netbird terminated"), strings.Count(strings.Join(lines, "\n"), "netbird service run"); first < 0 || term < first || second != 2 {
		t.Fatalf("%v", lines)
	}
	h.sigs <- syscall.SIGTERM
	h.wait(done, 10*time.Second)
}

func TestNetBirdExitingUnexpectedlyStopsTheExit(t *testing.T) {
	h := newHarness(t, "good", "ok")
	h.s.Env["NB_FAKE_MODE"] = "die"
	done := h.run()
	if code := h.wait(done, 15*time.Second); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if index(h.traceLines(), "netbird died") < 0 || index(h.traceLines(), "cleanup ok") < 0 {
		t.Fatalf("%v", h.traceLines())
	}
}

func TestNetBirdStartupFailureStopsTheExit(t *testing.T) {
	h := newHarness(t, "good", "ok")
	h.s.Env["NB_FAKE_MODE"] = "upfail"
	done := h.run()
	if code := h.wait(done, 15*time.Second); code != 1 {
		t.Fatalf("exit %d", code)
	}
}

func TestPublicationRules(t *testing.T) {
	h := newHarness(t, "good", "ok")
	done := h.run()
	if !h.waitTrace("netbird up", 10*time.Second) {
		t.Fatal("not up")
	}
	time.Sleep(600 * time.Millisecond)
	h.mu.Lock()
	n := len(h.written)
	h.mu.Unlock()
	if n < 4 {
		t.Fatalf("only %d publications", n)
	}
	rec := h.lastRecord()
	owner := rec["checks"].(map[string]any)["owner_record"].(map[string]any)
	if owner["state"] != "pass" || owner["expires_at"] == nil {
		t.Fatalf("owner_record: %v", owner)
	}
	if rec["status"] != "ok" {
		t.Fatalf("status %v", rec["status"])
	}
	h.sigs <- syscall.SIGTERM
	h.wait(done, 10*time.Second)
	// A requested stop writes no failure record.
	if last := h.lastRecord(); last["message"] == OwnerStoppedMessage {
		t.Error("a requested stop must not publish the failure record")
	}
}
