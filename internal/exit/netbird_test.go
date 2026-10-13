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
	r.m = &nbManager{reaper: reaperFor(t), bin: "netbird", env: env, envUp: env, clock: func() time.Duration { return time.Second },
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

// After Close returns, a process whose creation was already in flight may
// still appear, but it is killed the moment it is attached: nothing that
// starts after Close is left running, with no signal sent by anyone else.
func TestNothingSurvivesThatStartsAfterClose(t *testing.T) {
	for i := 0; i < 40; i++ {
		r := newNBRig(t)
		if _, ok := r.m.Start(); !ok {
			t.Fatal("start")
		}
		time.Sleep(time.Duration(i%5) * 4 * time.Millisecond)
		r.m.Close()
		before := len(r.m.snapshot())
		if _, ok := r.m.Start(); ok {
			t.Fatal("a launch was accepted after Close")
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			late := r.m.snapshot()
			if len(late) >= before {
				late = late[before:]
			}
			alive := false
			for _, p := range late {
				select {
				case <-p.Reaped():
				default:
					alive = true
				}
			}
			if !alive && r.m.pending.Load() == 0 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("round %d: a process that started after Close is still alive", i)
			}
			time.Sleep(5 * time.Millisecond)
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

// A process creation that stalls holds no lock the deadline path takes: Active,
// Close, TermAll and Alive answer at once, the running daemon gets TERM, and
// when the creation finally returns the late child is killed, not adopted.
func TestAStalledCreationHoldsNoLock(t *testing.T) {
	r := newNBRig(t)
	stall, entered := make(chan struct{}), make(chan struct{})
	var once sync.Once
	r.m.hook = func(stage string) {
		if stage == "spawn status --check live" {
			once.Do(func() { close(entered) })
			<-stall
		}
	}
	if _, ok := r.m.Start(); !ok {
		t.Fatal("start")
	}
	<-entered
	answered := make(chan bool, 1)
	go func() {
		active := r.m.Active()
		r.m.Close()
		r.m.TermAll()
		answered <- active && r.m.Alive() // the creation in flight counts as alive
	}()
	select {
	case ok := <-answered:
		if !ok {
			t.Error("a creation in flight must count as alive")
		}
	case <-time.After(time.Second):
		t.Fatal("Active, Close or TermAll waited on the stalled creation")
	}
	// The daemon, started before the stall, was told to end.
	procs := r.m.snapshot()
	if len(procs) == 0 {
		t.Fatal("the daemon was not started before the stall")
	}
	select {
	case <-procs[0].Reaped():
	case <-time.After(5 * time.Second):
		t.Fatal("the daemon got no TERM")
	}
	close(stall)
	deadline := time.Now().Add(5 * time.Second)
	for r.m.Alive() {
		if time.Now().After(deadline) {
			t.Fatal("the late child outlived the cancelled launch")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Whatever the late child managed to write, it did not go on to `up`.
	if strings.Contains(r.traceText(), "netbird up ") {
		t.Fatalf("the cancelled launch went on:\n%s", r.traceText())
	}
}
