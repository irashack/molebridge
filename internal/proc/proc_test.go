package proc

import (
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

var testReaper *Reaper

func TestMain(m *testing.M) {
	_ = BecomeSubreaper()
	r, err := NewReaper()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	testReaper = r
	code := m.Run()
	r.Close()
	os.Exit(code)
}

func sh(script string) Spec {
	return Spec{Path: "/bin/sh", Args: []string{"sh", "-c", script}, Env: []string{"PATH=/usr/bin:/bin"}}
}

func TestSecondReaperIsRefused(t *testing.T) {
	if r, err := NewReaper(); err == nil {
		r.Close()
		t.Fatal("a second reaper must be refused")
	}
}

func TestStartMakesAProcessGroupOfItsOwn(t *testing.T) {
	p, err := testReaper.Start(sh("sleep 30 & wait"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.KillGroup()
	pgid, err := syscall.Getpgid(p.Pid)
	if err != nil || pgid != p.Pid {
		t.Fatalf("pgid %d pid %d err %v", pgid, p.Pid, err)
	}
	if pgid == syscall.Getpgrp() {
		t.Fatal("the child shares our process group")
	}
}

func TestReaperRoutesEveryStatusToItsOwner(t *testing.T) {
	const n = 40
	procs := make([]*Process, n)
	for i := range procs {
		p, err := testReaper.Start(sh(fmt.Sprintf("exit %d", i%7)))
		if err != nil {
			t.Fatal(err)
		}
		procs[i] = p
	}
	for i, p := range procs {
		ws, ok := p.Wait(5 * time.Second)
		if !ok {
			t.Fatalf("process %d was not reaped", i)
		}
		if ExitCode(ws) != i%7 {
			t.Errorf("process %d: exit %d, want %d", i, ExitCode(ws), i%7)
		}
	}
}

func TestAChildThatExitsAtOnceIsStillRouted(t *testing.T) {
	// The registration race: the child can exit before Start returns.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				p, err := testReaper.Start(Spec{Path: "/usr/bin/true", Args: []string{"true"}})
				if err != nil {
					p, err = testReaper.Start(Spec{Path: "/bin/true", Args: []string{"true"}})
				}
				if err != nil {
					t.Error(err)
					return
				}
				if _, ok := p.Wait(5 * time.Second); !ok {
					t.Error("a quickly exiting child was lost")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestTermThenKillDeadlines(t *testing.T) {
	// Ignores TERM, as a wedged child would.
	p, err := testReaper.Start(sh(`trap "" TERM; while :; do sleep 1; done`))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // let the trap be installed
	start := time.Now()
	if !p.Stop(600*time.Millisecond, 3*time.Second) {
		t.Fatal("the group survived KILL")
	}
	took := time.Since(start)
	if took < 500*time.Millisecond || took > 2*time.Second {
		t.Errorf("TERM was ignored, so KILL should land near 600ms, took %v", took)
	}
	ws, _ := p.Status()
	if !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Errorf("status %v, want killed", ws)
	}
}

func TestTermAloneEndsACooperativeChild(t *testing.T) {
	p, err := testReaper.Start(sh(`sleep 30 & wait`))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	if !p.Stop(5*time.Second, 2*time.Second) {
		t.Fatal("not gone")
	}
	if time.Since(start) > 2*time.Second {
		t.Error("TERM should have been enough")
	}
}

func TestSignalGroupReachesGrandchildren(t *testing.T) {
	// The leader exits at once; its sleeping child keeps the group alive.
	p, err := testReaper.Start(sh(`sleep 30 & exit 0`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Wait(5 * time.Second); !ok {
		t.Fatal("leader not reaped")
	}
	if !p.GroupAlive() {
		t.Fatal("the grandchild should keep the group alive")
	}
	_ = p.KillGroup()
	if !p.WaitGone(5 * time.Second) {
		t.Fatal("the group did not empty after KILL")
	}
	if p.GroupAlive() {
		t.Error("GroupAlive after WaitGone")
	}
	// A group seen empty is never signaled again.
	if err := p.SignalGroup(syscall.SIGKILL); err != nil {
		t.Error(err)
	}
}

func TestRunKillsALateProbe(t *testing.T) {
	start := time.Now()
	res, err := testReaper.Run(sh(`sleep 30`), 300*time.Millisecond, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut || res.Survived {
		t.Fatalf("%+v", res)
	}
	if time.Since(start) > 3*time.Second {
		t.Error("took too long")
	}
	res, err = testReaper.Run(sh(`exit 3`), 5*time.Second, time.Second)
	if err != nil || res.TimedOut || ExitCode(res.Status) != 3 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestRunKillsAProbesStrayMember(t *testing.T) {
	res, err := testReaper.Run(sh(`sleep 30 & exit 0`), 5*time.Second, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.TimedOut || res.Survived {
		t.Fatalf("%+v", res)
	}
}

func TestStartReportsAMissingProgram(t *testing.T) {
	if _, err := testReaper.Start(Spec{Path: "/nonexistent/program", Args: []string{"x"}}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestTheEnvironmentIsNotInherited(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MB_PROC_TEST_SECRET", "x")
	s := sh(`env`)
	s.Stdout = w
	p, err := testReaper.Start(s)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	p.Wait(5 * time.Second)
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	if got := string(buf[:n]); contains(got, "MB_PROC_TEST_SECRET") || !contains(got, "PATH=") {
		t.Fatalf("environment: %q", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestExtraFilesArriveAtDescriptor3(t *testing.T) {
	r, w, _ := os.Pipe()
	s := sh(`echo hello >&3`)
	s.ExtraFiles = []*os.File{w}
	p, err := testReaper.Start(s)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	p.Wait(5 * time.Second)
	buf := make([]byte, 64)
	n, _ := r.Read(buf)
	if string(buf[:n]) != "hello\n" {
		t.Fatalf("got %q", buf[:n])
	}
}

// A fork that stalls blocks nothing but its caller: other children still start,
// and their statuses are still collected and routed.
func TestAStalledForkBlocksNothingElse(t *testing.T) {
	stall, entered := make(chan struct{}), make(chan struct{})
	testReaper.mu.Lock()
	real := testReaper.fork
	var once sync.Once
	testReaper.fork = func(argv0 string, argv []string, attr *syscall.ProcAttr) (int, error) {
		stalled := false
		once.Do(func() { stalled = true })
		if stalled {
			close(entered)
			<-stall
		}
		return real(argv0, argv, attr)
	}
	testReaper.mu.Unlock()
	t.Cleanup(func() {
		testReaper.mu.Lock()
		testReaper.fork = real
		testReaper.mu.Unlock()
	})
	started := make(chan *Process, 1)
	go func() {
		p, err := testReaper.Start(sh("exit 5"))
		if err != nil {
			t.Error(err)
		}
		started <- p
	}()
	<-entered
	// With that fork stalled, others start, exit and are reaped.
	for i := 0; i < 5; i++ {
		p, err := testReaper.Start(sh(fmt.Sprintf("exit %d", i)))
		if err != nil {
			t.Fatal(err)
		}
		ws, ok := p.Wait(5 * time.Second)
		if !ok || ExitCode(ws) != i {
			t.Fatalf("child %d: %v %v", i, ws, ok)
		}
	}
	done := make(chan struct{})
	go func() { testReaper.Orphans(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the reaper's lock is held across a stalled fork")
	}
	close(stall)
	p := <-started
	if ws, ok := p.Wait(5 * time.Second); !ok || ExitCode(ws) != 5 {
		t.Fatalf("the stalled child: %v %v", ws, ok)
	}
}

// A child that exits and is collected before its fork call returns is still
// routed to its owner.
func TestAChildCollectedBeforeTheForkReturns(t *testing.T) {
	proceed := make(chan struct{})
	testReaper.mu.Lock()
	real := testReaper.fork
	testReaper.fork = func(argv0 string, argv []string, attr *syscall.ProcAttr) (int, error) {
		pid, err := real(argv0, argv, attr)
		// Hold the return until the child has exited and been reaped.
		time.Sleep(300 * time.Millisecond)
		close(proceed)
		return pid, err
	}
	testReaper.mu.Unlock()
	defer func() {
		testReaper.mu.Lock()
		testReaper.fork = real
		testReaper.mu.Unlock()
	}()
	p, err := testReaper.Start(sh("exit 9"))
	if err != nil {
		t.Fatal(err)
	}
	<-proceed
	if ws, ok := p.Wait(5 * time.Second); !ok || ExitCode(ws) != 9 {
		t.Fatalf("%v %v", ws, ok)
	}
}
