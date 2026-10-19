// Package proc starts and supervises child processes for a process that is
// PID 1 (or a sub-reaper): every child has a process group of its own, every
// exit status is collected by one reaper, and every wait has a deadline.
//
// Why not os/exec. exec.Cmd.Wait waits for one pid. A PID 1 must also collect
// the orphans that are reparented to it, which means calling wait4(-1) -- and a
// wait4(-1) loop races any exec.Cmd.Wait running in the same process: whichever
// loses gets ECHILD and the exit status is gone. So the process has exactly one
// waiter, the Reaper, and children are started with syscall.ForkExec and
// registered with it. The reaper hands each exit status to whoever started that
// pid and drops the statuses of pids nobody registered (orphans).
//
// A process using this package must not also wait for children another way
// (exec.Cmd.Wait, os.Process.Wait) while a Reaper is running.
//
// The registration race (a child that exits before its pid is recorded) is
// closed without holding any lock across the fork, so a fork that stalls
// blocks nothing but its caller: Start counts the fork in flight, and while one
// is in flight the reaper keeps the status of a pid it does not know instead of
// discarding it; Start, when the fork returns, registers the pid and picks up
// a status kept for it. The reaper's lock is held only for non-blocking calls.
package proc

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// Reaper is the process's single waiter. There is at most one per process.
type Reaper struct {
	mu      sync.Mutex
	procs   map[int]*Process
	orphans int
	// forking counts Starts between the start of the fork and the registration
	// of its pid. While it is above zero a status for an unknown pid is kept in
	// early rather than counted as an orphan's: it may be the child of a fork
	// that has not returned yet.
	forking int
	early   map[int]syscall.WaitStatus
	// fork is syscall.ForkExec (tests replace it).
	fork    func(argv0 string, argv []string, attr *syscall.ProcAttr) (int, error)
	sig     chan os.Signal
	stop    chan struct{}
	stopped chan struct{}
}

var (
	activeMu sync.Mutex
	active   *Reaper
)

// NewReaper starts the reaper. A second Reaper in one process would steal the
// first one's statuses, so it is refused until the first is closed.
func NewReaper() (*Reaper, error) {
	activeMu.Lock()
	defer activeMu.Unlock()
	if active != nil {
		return nil, errors.New("proc: a reaper is already running in this process")
	}
	r := &Reaper{
		procs:   map[int]*Process{},
		early:   map[int]syscall.WaitStatus{},
		fork:    syscall.ForkExec,
		sig:     make(chan os.Signal, 1),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	signal.Notify(r.sig, syscall.SIGCHLD)
	active = r
	go r.run()
	// Children that exited before the handler existed.
	r.kick()
	return r, nil
}

// Close stops the reaper. Statuses of children still running are lost.
func (r *Reaper) Close() {
	activeMu.Lock()
	defer activeMu.Unlock()
	if active != r {
		return
	}
	signal.Stop(r.sig)
	close(r.stop)
	<-r.stopped
	active = nil
}

// Orphans is the number of exit statuses collected for pids nobody started
// through the reaper: the processes reparented to this one.
func (r *Reaper) Orphans() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.orphans
}

func (r *Reaper) kick() {
	select {
	case r.sig <- syscall.SIGCHLD:
	default:
	}
}

func (r *Reaper) run() {
	defer close(r.stopped)
	for {
		select {
		case <-r.stop:
			return
		case <-r.sig:
			r.collect()
		}
	}
}

// collect reaps every child that has exited and routes the statuses. It holds
// the lock throughout, so a Start in progress registers its pid first.
func (r *Reaper) collect() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, syscall.WNOHANG, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil || pid <= 0 {
			return
		}
		p := r.procs[pid]
		if p == nil {
			if r.forking > 0 && len(r.early) < 1024 {
				r.early[pid] = ws
				continue
			}
			r.orphans++
			continue
		}
		delete(r.procs, pid)
		p.finish(ws)
	}
}

// Spec describes a child to start.
type Spec struct {
	// Path is the executable and Args its argv (Args[0] included).
	Path string
	Args []string
	// Env is the whole environment, "NAME=value" each. It is never inherited.
	Env []string
	Dir string
	// Stdin, Stdout and Stderr become descriptors 0, 1 and 2; nil is the null
	// device.
	Stdin, Stdout, Stderr *os.File
	// ExtraFiles become descriptors 3 and up.
	ExtraFiles []*os.File
}

// Process is a started child, the leader of a process group of its own.
type Process struct {
	// Pid is the child's pid and its process group id.
	Pid int

	done   chan struct{}
	mu     sync.Mutex
	status syscall.WaitStatus
	gone   bool // the group was seen empty
}

func (p *Process) finish(ws syscall.WaitStatus) {
	p.mu.Lock()
	p.status = ws
	p.mu.Unlock()
	close(p.done)
}

// Start forks and executes a child in a new process group and registers it
// with the reaper before it can be reaped.
func (r *Reaper) Start(s Spec) (*Process, error) {
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("proc: open the null device: %w", err)
	}
	defer null.Close()
	pick := func(f *os.File) uintptr {
		if f == nil {
			return null.Fd()
		}
		return f.Fd()
	}
	files := []uintptr{pick(s.Stdin), pick(s.Stdout), pick(s.Stderr)}
	for _, f := range s.ExtraFiles {
		files = append(files, f.Fd())
	}
	attr := &syscall.ProcAttr{Dir: s.Dir, Env: s.Env, Files: files, Sys: &syscall.SysProcAttr{Setpgid: true}}
	r.mu.Lock()
	r.forking++
	fork := r.fork
	r.mu.Unlock()
	pid, err := fork(s.Path, s.Args, attr)
	// The descriptors must stay open (and unfinalized) until the fork is done.
	runtime.KeepAlive(s.Stdin)
	runtime.KeepAlive(s.Stdout)
	runtime.KeepAlive(s.Stderr)
	runtime.KeepAlive(s.ExtraFiles)
	runtime.KeepAlive(null)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.forking--
	if err != nil {
		r.settleEarlyLocked()
		return nil, fmt.Errorf("proc: start %s: %w", s.Path, err)
	}
	p := &Process{Pid: pid, done: make(chan struct{})}
	if ws, ok := r.early[pid]; ok {
		delete(r.early, pid)
		p.finish(ws)
	} else {
		r.procs[pid] = p
	}
	r.settleEarlyLocked()
	return p, nil
}

// settleEarlyLocked forgets the statuses kept for forks once none is in flight:
// they were the orphans' after all.
func (r *Reaper) settleEarlyLocked() {
	if r.forking == 0 && len(r.early) > 0 {
		r.orphans += len(r.early)
		r.early = map[int]syscall.WaitStatus{}
	}
}

// Reaped is closed when the leader's exit status has been collected.
func (p *Process) Reaped() <-chan struct{} { return p.done }

// Status returns the leader's wait status once it has been reaped.
func (p *Process) Status() (syscall.WaitStatus, bool) {
	select {
	case <-p.done:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.status, true
	default:
		return 0, false
	}
}

// Wait waits up to d for the leader to be reaped.
func (p *Process) Wait(d time.Duration) (syscall.WaitStatus, bool) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-p.done:
		return p.status, true
	case <-t.C:
		return 0, false
	}
}

// ExitCode maps a wait status to a shell-style code: the exit status, or 128
// plus the signal.
func ExitCode(ws syscall.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

// SignalGroup sends a signal to every process of the group. A group seen
// empty is not signaled again: its id could be reused.
func (p *Process) SignalGroup(sig syscall.Signal) error {
	p.mu.Lock()
	gone := p.gone
	p.mu.Unlock()
	if gone {
		return nil
	}
	if err := syscall.Kill(-p.Pid, sig); err != nil && err != syscall.ESRCH {
		return err
	}
	return nil
}

// KillGroup is SignalGroup(SIGKILL).
func (p *Process) KillGroup() error { return p.SignalGroup(syscall.SIGKILL) }

// GroupAlive reports whether any process of the group exists (a zombie that
// has not been reaped yet counts).
func (p *Process) GroupAlive() bool {
	p.mu.Lock()
	if p.gone {
		p.mu.Unlock()
		return false
	}
	p.mu.Unlock()
	err := syscall.Kill(-p.Pid, 0)
	if err == syscall.ESRCH {
		p.mu.Lock()
		p.gone = true
		p.mu.Unlock()
		return false
	}
	return true
}

// WaitGone waits up to d for the leader to be reaped and the group to be
// empty. Members that outlive their leader are reparented to this process (it
// is PID 1 or a sub-reaper) and reaped like any orphan.
func (p *Process) WaitGone(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		select {
		case <-p.done:
			if !p.GroupAlive() {
				return true
			}
		default:
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Stop ends the group on a timeline measured from now: TERM to the group at
// once, KILL after kill, and a final wait of up to gone after that for the
// group to be reaped and empty. It returns false if the group is still there.
func (p *Process) Stop(kill, gone time.Duration) bool {
	_ = p.SignalGroup(syscall.SIGTERM)
	if p.WaitGone(kill) {
		return true
	}
	_ = p.KillGroup()
	return p.WaitGone(gone)
}

// Result is what a bounded run produced.
type Result struct {
	Status syscall.WaitStatus
	// TimedOut: the run was group-killed for being late.
	TimedOut bool
	// Survived: the group was still not gone after the kill and the wait.
	Survived bool
}

// Run starts a child and waits up to limit for it. A late child is
// group-killed (no TERM: these runs are short probes), then waited for up to
// grace more. The group is always checked empty at the end, so a probe that
// left a member behind is killed too.
func (r *Reaper) Run(s Spec, limit, grace time.Duration) (Result, error) {
	p, err := r.Start(s)
	if err != nil {
		return Result{}, err
	}
	var res Result
	if ws, ok := p.Wait(limit); ok {
		res.Status = ws
	} else {
		res.TimedOut = true
		_ = p.KillGroup()
		if ws, ok := p.Wait(grace); ok {
			res.Status = ws
		}
	}
	if p.GroupAlive() {
		_ = p.KillGroup()
	}
	res.Survived = !p.WaitGone(grace)
	return res, nil
}
