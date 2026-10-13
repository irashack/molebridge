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
	"github.com/irashack/molebridge/internal/proc"
)

const fakeNetBird = `#!/bin/sh
# A stand-in for the netbird client: it records what it was asked to do.
t=${NB_TRACE_FILE:?}
# Which commands were given the enrollment secret.
echo "netbird $1 setup-key=${NB_SETUP_KEY:+yes}${WT_SETUP_KEY:+yes}" >> "$t"
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
	sup     *Supervisor
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
	s.Env = map[string]string{"PATH": bin + ":/usr/bin:/bin", "NB_TRACE_FILE": h.trace, "MB_TRACE_FILE": h.trace,
		"NB_SETUP_KEY": "SETUPVALUE", "GATUS_TOKEN": "TOKENVALUE"}
	h.s = s
	h.cfg = Config{
		Settings: s, Reaper: reaperFor(t), Self: self,
		WorkerArgs:  []string{"fake-worker", workerMode},
		CleanupArgs: []string{"fake-cleanup", cleanupMode, h.trace},
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
	h.sup = sup
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

func TestSecretsReachOnlyWhatNeedsThem(t *testing.T) {
	h := newHarness(t, "good", "ok")
	done := h.run()
	if !h.waitTrace("netbird up", 10*time.Second) {
		t.Fatal("not up")
	}
	h.sigs <- syscall.SIGTERM
	h.wait(done, 10*time.Second)
	lines := h.traceLines()
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l, "netbird up setup-key="):
			if l != "netbird up setup-key=yes" {
				t.Errorf("`netbird up` enrolls and needs the key: %q", l)
			}
		case strings.HasPrefix(l, "netbird ") && strings.Contains(l, " setup-key="):
			if !strings.HasSuffix(l, "setup-key=") {
				t.Errorf("only `netbird up` gets the setup key: %q", l)
			}
		case strings.Contains(l, "worker has the setup key"):
			t.Error("the worker has the setup key")
		case strings.HasPrefix(l, "cleanup env "):
			for _, bad := range []string{"NB_SETUP_KEY", "GATUS_TOKEN", "STATE_DIR", "NB_TRACE_FILE", "MB_TRACE_FILE"} {
				if strings.Contains(l, bad) {
					t.Errorf("the cleanup child got %s: %s", bad, l)
				}
			}
		}
	}
	if index(lines, "netbird status setup-key=") < 0 || index(lines, "netbird service setup-key=") < 0 {
		t.Errorf("the probes and the daemon ran: %v", lines)
	}
}

// A blocked log sink and a stalled state volume must not delay the signals:
// the lease lapses, NetBird gets TERM at once, and the supervisor still leaves
// within its budget.
func TestStalledSinksNeverDelayTheStop(t *testing.T) {
	h := newHarness(t, "freeze", "ok")
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	h.cfg.Stderr = blockingWriter{release}
	h.cfg.Write = func(path string, v any) error {
		<-release // the volume is stuck
		return nil
	}
	done := h.run()
	if !h.waitTrace("worker frozen", 10*time.Second) {
		t.Fatal("never froze")
	}
	frozen := time.Now()
	if !h.waitTrace("netbird terminated", 10*time.Second) {
		t.Fatal("NetBird was not terminated: the deadline path waited on a sink")
	}
	if took := time.Since(frozen); took > h.s.Grace+1500*time.Millisecond {
		t.Errorf("NetBird got TERM %v after the freeze, grace is %v", took, h.s.Grace)
	}
	code := h.wait(done, 15*time.Second)
	if total := time.Since(frozen); total > h.s.Grace+h.cfg.Timing.ExitBy+2*time.Second {
		t.Errorf("the exit took %v", total)
	}
	if code == 0 {
		t.Error("a lapsed lease exits non-zero")
	}
	if index(h.traceLines(), "cleanup ok") < 0 {
		t.Error("the cleanup did not run")
	}
}

type blockingWriter struct{ release chan struct{} }

func (b blockingWriter) Write(p []byte) (int, error) { <-b.release; return len(p), nil }

func TestACleanupIsNeverRunBesideASurvivingNetBird(t *testing.T) {
	h := newHarness(t, "good", "ok")
	sup := New(h.cfg)
	sup.testFinal = func() (bool, bool) { return false, true }
	done := make(chan int, 1)
	go func() { done <- sup.Run() }()
	if !h.waitTrace("netbird up", 10*time.Second) {
		t.Fatal("not up")
	}
	h.sigs <- syscall.SIGTERM
	if code := h.wait(done, 10*time.Second); code != 1 {
		t.Fatalf("a requested stop with a surviving NetBird must exit non-zero, got %d", code)
	}
	if index(h.traceLines(), "cleanup ok") >= 0 {
		t.Fatal("the cleanup ran beside a NetBird that survived")
	}
}

func TestMessagesAfterTheExpiryStopTheExit(t *testing.T) {
	h := newHarness(t, "good", "ok")
	clock := &fakeClock{now: 500 * time.Second}
	h.cfg.Clock = clock.read
	sup := New(h.cfg)
	gen, err := sup.lease.NewGeneration()
	if err != nil {
		t.Fatal(err)
	}
	sup.gen = gen
	loops := func() map[string]int64 {
		return map[string]int64{LoopMutator: int64(clock.now), LoopWatcher: int64(clock.now)}
	}
	if reason, _ := sup.handle(evWorkerMsg{Msg{Type: TypeRenew, Gen: gen, Seq: 1, Loops: loops()}}); reason != "" {
		t.Fatalf("a renewal inside the lease: %q", reason)
	}
	clock.now += 2 * time.Second // past the 1-second grace
	// A worker that resumes after the deadline and renews before the
	// supervisor's timer fires does not revive the lease.
	reason, _ := sup.handle(evWorkerMsg{Msg{Type: TypeRenew, Gen: gen, Seq: 2, Loops: loops()}})
	if reason != ReasonLapsed {
		t.Fatalf("a late renewal: reason %q", reason)
	}
	// Nor does a queued record.
	rec := okRecord(h.s, time.Now())
	reason, _ = sup.handle(evWorkerMsg{Msg{Type: TypeStatus, Gen: gen, Seq: 3, Record: rec}})
	if reason != ReasonLapsed {
		t.Fatalf("a late record: reason %q", reason)
	}
	if sup.lease.Held() {
		t.Fatal("held")
	}
}

// Process creation can stall (a hung exec). The supervisor's deadline path
// takes no lock that a creation in flight holds: with a liveness probe stuck
// in the middle of being started, the lease still lapses on time, NetBird's
// daemon still gets TERM, and the exit still ends within its budget.
func TestAStalledSpawnNeverDelaysTheStop(t *testing.T) {
	h := newHarness(t, "freeze", "ok")
	stall, entered := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { close(stall) })
	h.cfg.nbHook = func(stage string) {
		if stage == "spawn status --check live" {
			once.Do(func() { close(entered) })
			<-stall
		}
	}
	done := h.run()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("no probe was started")
	}
	// The daemon runs; the next liveness probe never gets going. Renewals keep
	// arriving (Active() is asked on each) until the worker freezes.
	if !h.waitTrace("worker frozen", 10*time.Second) {
		t.Fatal("never froze")
	}
	frozen := time.Now()
	if !h.waitTrace("netbird terminated", 10*time.Second) {
		t.Fatal("NetBird got no TERM: the deadline path waited on the stalled creation")
	}
	if took := time.Since(frozen); took > h.s.Grace+1500*time.Millisecond {
		t.Errorf("TERM %v after the freeze, grace is %v", took, h.s.Grace)
	}
	if code := h.wait(done, 15*time.Second); code == 0 {
		t.Error("exit status")
	}
}

// A worker that stops reading its pipe fills it, and the supervisor's writer
// goroutine blocks; the deadline path never writes to that pipe.
func TestAWorkerThatStopsReadingItsPipeDelaysNothing(t *testing.T) {
	h := newHarness(t, "freeze", "ok")
	done := h.run()
	if !h.waitTrace("worker frozen", 10*time.Second) {
		t.Fatal("never froze")
	}
	frozen := time.Now()
	start := time.Now()
	for i := 0; i < 20000; i++ {
		h.sup.send(Msg{Type: TypeAck, Gen: h.sup.gen, Seq: uint64(i), ExpiryBootNs: 1})
	}
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Errorf("20000 sends took %v: a send must never wait on the pipe", took)
	}
	if !h.waitTrace("netbird terminated", 10*time.Second) {
		t.Fatal("NetBird got no TERM")
	}
	if took := time.Since(frozen); took > h.s.Grace+1500*time.Millisecond {
		t.Errorf("TERM %v after the freeze", took)
	}
	if code := h.wait(done, 15*time.Second); code == 0 {
		t.Error("exit status")
	}
}

// Events of an older launch change nothing: the manager marks a launch inactive
// before its stopped event reaches the loop, so a newer launch can already run.
func TestAStaleStoppedEventIsDropped(t *testing.T) {
	h := newHarness(t, "good", "ok")
	sup := New(h.cfg)
	sup.nb = &nbManager{launch: 2, active: true, closed: false}
	sup.toW = make(chan Msg, 8)
	sup.gen = strings.Repeat("a", 32)
	for _, kind := range []nbKind{nbStopped, nbStarted, nbFailed, nbExited} {
		if reason, _ := sup.handleNB(nbEvent{kind: kind, launch: 1}); reason != "" {
			t.Errorf("kind %d of launch 1 stops the exit: %q", kind, reason)
		}
	}
	select {
	case m := <-sup.toW:
		t.Fatalf("a message was sent to the worker for an old launch: %+v", m)
	default:
	}
	// The current launch's started event carries its launch and start time.
	sup.handleNB(nbEvent{kind: nbStarted, launch: 2, offset: 7, at: 5 * time.Second})
	m := <-sup.toW
	if m.State != NBStarted || m.Launch != 2 || m.LogOffset != 7 || m.AtBootNs != int64(5*time.Second) {
		t.Fatalf("%+v", m)
	}
}

// The cleanup child's creation is bounded by the cleanup deadline like the rest
// of its work: a stalled fork cannot hold the stop sequence past ExitBy, a stop
// that missed its deadline never exits 0, and the child that finally attaches
// is killed and reaped, not adopted.
func TestAStalledCleanupCreationEndsAtTheDeadlineNonZero(t *testing.T) {
	h := newHarness(t, "good", "ok")
	release := make(chan struct{})
	late := make(chan *proc.Process, 1)
	h.cfg.cleanupHook = func(stage string, p *proc.Process) {
		switch stage {
		case "create":
			<-release
		case "late":
			late <- p
		}
	}
	done := h.run()
	if !h.waitTrace("worker ready", 10*time.Second) {
		t.Fatal("not ready")
	}
	h.sigs <- syscall.SIGTERM
	start := time.Now()
	code := h.wait(done, 10*time.Second)
	took := time.Since(start)
	if code == 0 {
		t.Fatal("a requested stop that missed its cleanup deadline must not exit 0")
	}
	// Reaping took a moment first; the exit is at ExitBy, not a second later.
	if took > h.cfg.Timing.ExitBy+400*time.Millisecond {
		t.Errorf("exit after %v, ExitBy is %v", took, h.cfg.Timing.ExitBy)
	}
	if index(h.traceLines(), "cleanup ok") >= 0 {
		t.Error("the cleanup ran")
	}
	close(release)
	select {
	case p := <-late:
		select {
		case <-p.Reaped():
		case <-time.After(5 * time.Second):
			t.Fatal("the late child was not reaped")
		}
		if ws, _ := p.Status(); !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
			t.Errorf("the late child ended with %v, want KILL", ws)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the late child never attached")
	}
}

// Whatever else blocks on the stop path, the process ends: the watchdog behind
// the absolute exit deadline fires, non-zero.
func TestTheExitDeadlineHoldsWhateverBlocks(t *testing.T) {
	h := newHarness(t, "good", "ok")
	release := make(chan struct{})
	fired := make(chan int, 1)
	h.cfg.hardExit = func(code int) { fired <- code }
	sup := New(h.cfg)
	sup.testFinal = func() (bool, bool) { <-release; return false, false }
	done := make(chan int, 1)
	go func() { done <- sup.Run() }()
	if !h.waitTrace("worker ready", 10*time.Second) {
		t.Fatal("not ready")
	}
	h.sigs <- syscall.SIGTERM
	start := time.Now()
	select {
	case code := <-fired:
		if code == 0 {
			t.Error("the watchdog exits non-zero")
		}
		if took := time.Since(start); took > h.cfg.Timing.ExitBy+time.Second {
			t.Errorf("fired after %v", took)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the watchdog never fired")
	}
	close(release)
	h.wait(done, 10*time.Second)
}
