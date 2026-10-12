package exit

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type nbRig struct {
	t      *testing.T
	m      *nbManager
	trace  string
	events chan nbEvent
}

func newNBRig(t *testing.T) *nbRig {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "netbird"), []byte(fakeNetBird), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &nbRig{t: t, trace: filepath.Join(dir, "trace"), events: make(chan nbEvent, 64)}
	env := []string{"PATH=" + bin + ":/usr/bin:/bin", "NB_TRACE_FILE=" + r.trace, "TMPDIR=" + dir}
	tm := DefaultTiming()
	tm.NBLive, tm.NBPoll, tm.NBProbe, tm.NBUp, tm.NBTerm = 5*time.Second, 20*time.Millisecond, 2*time.Second, 5*time.Second, time.Second
	r.m = &nbManager{reaper: testReaper, bin: "netbird", env: env, envUp: env, clock: func() time.Duration { return time.Second },
		out: io.Discard, timing: tm, emit: func(e nbEvent) { r.events <- e }}
	t.Cleanup(func() {
		r.m.Close()
		r.m.KillAll()
		r.m.waitGone(2 * time.Second)
	})
	return r
}

func (r *nbRig) next(kinds ...nbKind) nbEvent {
	r.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e := <-r.events:
			for _, k := range kinds {
				if e.kind == k {
					return e
				}
			}
		case <-deadline:
			r.t.Fatalf("no event of kinds %v", kinds)
		}
	}
}

func (r *nbRig) traceText() string {
	b, _ := os.ReadFile(r.trace)
	return string(b)
}

// A launch cancelled before its goroutine spawns anything starts nothing: no
// daemon exists that nobody supervises, and nbStopped is not reported before
// the launch goroutine is done.
func TestACancelledLaunchStartsNothing(t *testing.T) {
	r := newNBRig(t)
	gate, reached := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.m.hook = func(stage string) {
		if stage == "begin" {
			once.Do(func() { close(reached) })
			<-gate
		}
	}
	if _, ok := r.m.Start(); !ok {
		t.Fatal("start")
	}
	<-reached
	r.m.Stop() // the goroutine is held right before its first spawn
	time.Sleep(50 * time.Millisecond)
	close(gate)
	r.next(nbStopped)
	if strings.Contains(r.traceText(), "service") {
		t.Fatalf("a cancelled launch started the daemon:\n%s", r.traceText())
	}
	if r.m.Alive() {
		t.Fatal("a process is alive")
	}
	if r.m.Active() {
		t.Fatal("still active after nbStopped")
	}
	// And the manager works again afterwards.
	r.m.hook = nil
	if _, ok := r.m.Start(); !ok {
		t.Fatal("a new launch after the stop")
	}
	r.next(nbStarted)
	if !strings.Contains(r.traceText(), "netbird service run") {
		t.Fatal("the next launch did not run")
	}
}

// Whatever the timing, Stop leaves nothing behind: when nbStopped arrives no
// process of the manager is alive.
func TestStopRightAfterStartLeavesNothingAlive(t *testing.T) {
	for i := 0; i < 60; i++ {
		r := newNBRig(t)
		if _, ok := r.m.Start(); !ok {
			t.Fatal("start")
		}
		time.Sleep(time.Duration(i%6) * 5 * time.Millisecond)
		r.m.Stop()
		r.next(nbStopped)
		if r.m.Alive() {
			t.Fatalf("round %d: a process outlived nbStopped\n%s", i, r.traceText())
		}
		r.m.Close()
	}
}

// After Close returns no process is ever started.
func TestNothingStartsAfterClose(t *testing.T) {
	for i := 0; i < 40; i++ {
		r := newNBRig(t)
		if _, ok := r.m.Start(); !ok {
			t.Fatal("start")
		}
		time.Sleep(time.Duration(i%5) * 4 * time.Millisecond)
		r.m.Close()
		n := len(r.m.snapshot())
		time.Sleep(60 * time.Millisecond)
		if got := len(r.m.snapshot()); got != n {
			t.Fatalf("round %d: %d processes after Close, %d before", i, got, n)
		}
		if _, ok := r.m.Start(); ok {
			t.Fatal("a launch was accepted after Close")
		}
		r.m.TermAll()
		r.m.KillAll()
		if !r.m.waitGone(2 * time.Second) {
			t.Fatalf("round %d: processes survive KILL", i)
		}
	}
}

func TestEachCommandGetsItsOwnEnvironment(t *testing.T) {
	r := newNBRig(t)
	r.m.envUp = append(append([]string{}, r.m.env...), "NB_SETUP_KEY=SETUPVALUE")
	if _, ok := r.m.Start(); !ok {
		t.Fatal("start")
	}
	r.next(nbStarted)
	text := r.traceText()
	for _, want := range []string{"netbird service setup-key=\n", "netbird status setup-key=\n", "netbird up setup-key=yes\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	r.m.Stop()
	r.next(nbStopped)
}
