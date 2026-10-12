package exit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/proc"
	"github.com/irashack/molebridge/internal/validate"
)

// Stop reasons, as the stop sequence names them.
const (
	ReasonRequested = "requested"
	ReasonLapsed    = "lease lapsed"
	ReasonWorker    = "worker exited"
	ReasonProtocol  = "protocol"
	ReasonNetBird   = "netbird exited"
)

// Config configures a Supervisor. Zero values take the production defaults.
type Config struct {
	Settings *Settings
	// Reaper is the process's reaper; the supervisor creates one when nil.
	Reaper *proc.Reaper
	Clock  bootclock.Clock
	Wall   func() time.Time
	// Stderr receives the supervisor's own lines and the NetBird output.
	Stderr io.Writer
	// Self is the executable the worker and the cleanup child are started
	// from (/proc/self/exe); WorkerArgs and CleanupArgs are their arguments.
	Self        string
	WorkerArgs  []string
	CleanupArgs []string
	// ExtraWorkerEnv is appended to the worker's environment (tests).
	ExtraWorkerEnv []string
	// NetBirdBin is the NetBird client ("netbird", found in PATH).
	NetBirdBin string
	// Signals delivers the TERM and INT that request a stop; Run subscribes to
	// them itself when nil.
	Signals <-chan os.Signal
	Timing  Timing
	// Write replaces the result.json writer (tests).
	Write func(path string, v any) error
	// Bounds replaces the loops and bounds the lease supervises (tests).
	Bounds map[string]time.Duration
}

type event interface{}

type (
	evWorkerMsg  struct{ m Msg }
	evViolation  struct{ err error }
	evWorkerGone struct{}
	evNB         struct{ e nbEvent }
)

// Supervisor is `molebridge exit`.
type Supervisor struct {
	c      Config
	s      *Settings
	reap   *proc.Reaper
	lease  *Lease
	pub    *publisher
	nb     *nbManager
	stderr io.Writer // never blocks: see boundedLog
	log    *boundedLog
	// leaseOut writes the lease file off the deadline path.
	leaseOut *coalescer

	events chan event
	done   chan struct{}

	worker  *proc.Process
	toW     chan Msg
	toWFile *os.File
	gen     string

	wantNB      bool
	stopping    bool
	lastPublish time.Time
	warned      map[string]time.Time
}

// New creates a supervisor.
func New(c Config) *Supervisor {
	if c.Clock == nil {
		c.Clock = bootclock.System()
	}
	if c.Wall == nil {
		c.Wall = time.Now
	}
	if c.Stderr == nil {
		c.Stderr = os.Stderr
	}
	if c.Self == "" {
		c.Self = "/proc/self/exe"
	}
	if c.WorkerArgs == nil {
		c.WorkerArgs = []string{"exit", "--worker"}
	}
	if c.NetBirdBin == "" {
		c.NetBirdBin = "netbird"
	}
	if c.Timing == (Timing{}) {
		c.Timing = DefaultTiming()
	}
	log := newBoundedLog(c.Stderr, 512)
	s := &Supervisor{c: c, s: c.Settings, stderr: log, log: log, leaseOut: newCoalescer(),
		events: make(chan event, 256), done: make(chan struct{}), warned: map[string]time.Time{}}
	bounds := c.Bounds
	if bounds == nil {
		bounds = LoopBounds(s.s)
	}
	s.lease = NewLease(c.Clock, s.s.Grace, bounds)
	s.pub = newPublisher(s.s, s.lease, c.Clock, c.Wall, s.logf)
	if c.Write != nil {
		s.pub.write = c.Write
	}
	return s
}

func (s *Supervisor) logf(format string, a ...any) {
	fmt.Fprintf(s.stderr, prefix+format+"\n", a...)
}

// warnOnce logs a repeating condition at most once a period.
func (s *Supervisor) warnEvery(key string, period time.Duration, format string, a ...any) {
	now := time.Now()
	if t, ok := s.warned[key]; ok && now.Sub(t) < period {
		return
	}
	s.warned[key] = now
	s.logf(format, a...)
}

// push delivers an event to the loop; it never blocks once the loop is over.
func (s *Supervisor) push(e event) {
	select {
	case s.events <- e:
	case <-s.done:
	}
}

// Lease exposes the lease (for tests).
func (s *Supervisor) Lease() *Lease { return s.lease }

// Run is the supervisor: it starts the worker, holds the lease, starts NetBird
// when told and runs the stop sequence. It returns the process's exit status.
func (s *Supervisor) Run() int {
	code := s.run()
	// The log is a bounded queue behind a sink that may be stuck: give it a
	// moment to land, never longer.
	s.log.Flush(300 * time.Millisecond)
	return code
}

func (s *Supervisor) run() int {
	defer close(s.done)
	if s.c.Reaper == nil {
		_ = proc.BecomeSubreaper()
		r, err := proc.NewReaper()
		if err != nil {
			s.logf("%v", err)
			return 1
		}
		defer r.Close()
		s.c.Reaper = r
	}
	s.reap = s.c.Reaper
	sigs := s.c.Signals
	if sigs == nil {
		ch := make(chan os.Signal, 4)
		signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)
		defer signal.Stop(ch)
		sigs = ch
	}
	if err := s.prepareRun(); err != nil {
		s.logf("%v", err)
		return 1
	}
	if s.s.Overlay() {
		tmp := filepath.Join(s.s.RunDir, "tmp")
		s.nb = &nbManager{reaper: s.reap, bin: s.c.NetBirdBin, clock: s.c.Clock,
			env: ChildEnvNetBird(s.s.Env, tmp, false), envUp: ChildEnvNetBird(s.s.Env, tmp, true),
			logPath: watchLogPath(s.s.Env), out: s.stderr, timing: s.c.Timing,
			emit: func(e nbEvent) { s.push(evNB{e}) }}
	}
	s.pub.Full(StartingRecord(s.s, s.c.Wall()))
	if err := s.startWorker(); err != nil {
		s.logf("cannot start the worker: %v", err)
		return s.stopSequence(ReasonWorker, false)
	}
	s.writeLeaseFile()
	tick := time.NewTicker(s.c.Timing.Tick)
	defer tick.Stop()
	for {
		select {
		case sig := <-sigs:
			s.logf("received %v", sig)
			return s.stopSequence(ReasonRequested, true)
		case <-tick.C:
			if s.lease.Lapsed() {
				return s.stopSequence(ReasonLapsed, false)
			}
			if now := time.Now(); now.Sub(s.lastPublish) >= s.c.Timing.PublishEvery {
				s.lastPublish = now
				s.pub.LeaseOnly()
				s.writeLeaseFile()
			}
		case e := <-s.events:
			if reason, detail := s.handle(e); reason != "" {
				if detail != "" {
					s.logf("%s", detail)
				}
				return s.stopSequence(reason, false)
			}
		}
	}
}

// prepareRun creates the runtime directories on the tmpfs.
func (s *Supervisor) prepareRun() error {
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{{filepath.Join(s.s.RunDir, "molebridge"), 0o755}, {filepath.Join(s.s.RunDir, "tmp"), 0o700}} {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return fmt.Errorf("cannot create %s: %w", d.path, err)
		}
		_ = os.Chmod(d.path, d.mode)
	}
	return nil
}

// startWorker forks the worker with a pipe in each direction (descriptors 3,
// worker to supervisor, and 4, supervisor to worker).
func (s *Supervisor) startWorker() error {
	gen, err := s.lease.NewGeneration()
	if err != nil {
		return err
	}
	s.gen = gen
	rFrom, wFrom, err := os.Pipe()
	if err != nil {
		return err
	}
	rTo, wTo, err := os.Pipe()
	if err != nil {
		rFrom.Close()
		wFrom.Close()
		return err
	}
	env := append(WorkerEnv(s.s.Env), "MOLEBRIDGE_GENERATION="+gen, "TMPDIR="+filepath.Join(s.s.RunDir, "tmp"))
	env = append(env, s.c.ExtraWorkerEnv...)
	args := append([]string{"molebridge"}, s.c.WorkerArgs...)
	p, err := s.reap.Start(proc.Spec{Path: s.c.Self, Args: args, Env: env,
		Stderr: osStderr(s.c.Stderr), Stdout: osStderr(s.c.Stderr), ExtraFiles: []*os.File{wFrom, rTo}})
	wFrom.Close()
	rTo.Close()
	if err != nil {
		rFrom.Close()
		wTo.Close()
		return err
	}
	s.worker = p
	s.toW = make(chan Msg, 32)
	s.toWFile = wTo
	go s.readWorker(rFrom)
	go s.writeWorker(wTo, s.toW)
	go func() {
		<-p.Reaped()
		s.push(evWorkerGone{})
	}()
	return nil
}

// osStderr returns the *os.File behind w when it is one, else the null device.
func osStderr(w io.Writer) *os.File {
	if f, ok := w.(*os.File); ok {
		return f
	}
	return nil
}

func (s *Supervisor) readWorker(r *os.File) {
	defer r.Close()
	lr := NewLineReader(r)
	for {
		line, err := lr.Next()
		if err != nil {
			if errors.Is(err, ErrProtocol) {
				s.push(evViolation{err})
			}
			return
		}
		m, err := DecodeFromWorker(line)
		if err != nil {
			s.push(evViolation{err})
			return
		}
		s.push(evWorkerMsg{m})
	}
}

// writeWorker sends queued messages; the pipe to a stuck worker blocks only
// this goroutine, never the supervisor.
func (s *Supervisor) writeWorker(w *os.File, q <-chan Msg) {
	defer w.Close()
	for m := range q {
		b, err := m.Encode()
		if err != nil {
			continue
		}
		if _, err := w.Write(b); err != nil {
			return
		}
		if m.Type == TypeStop {
			return
		}
	}
}

// send queues a message for the worker, dropping it if the queue is full (the
// worker is not reading; the lease will say so).
func (s *Supervisor) send(m Msg) {
	select {
	case s.toW <- m:
	default:
	}
}

// handle processes one event; a non-empty reason starts the stop sequence.
func (s *Supervisor) handle(e event) (reason, detail string) {
	switch e := e.(type) {
	case evViolation:
		return ReasonProtocol, "worker protocol violation: " + e.err.Error()
	case evWorkerGone:
		ws, _ := s.worker.Status()
		return ReasonWorker, fmt.Sprintf("the worker exited (status %d)", proc.ExitCode(ws))
	case evNB:
		return s.handleNB(e.e)
	case evWorkerMsg:
		// Expiry is checked before any message is processed: a renewal or a
		// record that arrives after the deadline revives nothing.
		if s.lease.Lapsed() {
			return ReasonLapsed, "the lease expired before the worker's message was processed"
		}
		return s.handleMsg(e.m)
	}
	return "", ""
}

func (s *Supervisor) handleMsg(m Msg) (string, string) {
	switch m.Type {
	case TypeRenew:
		expiry, err := s.lease.Accept(m)
		if err != nil {
			s.warnEvery("renew", 10*time.Second, "%v", err)
			return "", ""
		}
		s.send(Msg{Type: TypeAck, Gen: m.Gen, Seq: m.Seq, ExpiryBootNs: int64(expiry)})
		s.maybeStartNetBird()
	case TypeReady:
		if m.Gen != s.gen {
			return "", ""
		}
		s.wantNB = true
		s.maybeStartNetBird()
	case TypeUnready:
		if m.Gen != s.gen {
			return "", ""
		}
		s.wantNB = false
		s.logf("the worker cannot hold the routing contract: %s; stopping NetBird", m.Reason)
		if s.nb != nil {
			s.nb.Stop()
		}
	case TypeStatus:
		if !s.lease.AcceptStatus(m.Gen, m.Seq) {
			return "", ""
		}
		if err := s.checkRecord(m.Record); err != nil {
			return ReasonProtocol, "worker protocol violation: " + err.Error()
		}
		s.pub.Full(m.Record)
	case TypeLog:
		if m.Gen == s.gen {
			s.logf("worker %s: %s", m.Level, sanitize(m.Text))
		}
	}
	return "", ""
}

// checkRecord requires a record to be the one this exit publishes; the
// readers judge the rest.
func (s *Supervisor) checkRecord(rec map[string]any) error {
	if n, ok := validate.IsInt(rec["schema"]); !ok || n != 2 {
		return violation("the record's schema is not 2")
	}
	if rec["kind"] != s.s.Kind() || rec["backend"] != s.s.BackendName() || rec["provider"] != s.s.Provider {
		return violation("the record is for another kind, backend or provider")
	}
	if _, ok := rec["checks"].(map[string]any); !ok {
		return violation("the record has no checks")
	}
	if _, ok := rec["status"].(string); !ok {
		return violation("the record has no status")
	}
	return nil
}

// maybeStartNetBird starts NetBird when the worker wants it and the lease is
// held, and never while stopping.
func (s *Supervisor) maybeStartNetBird() {
	if s.nb == nil || s.stopping || !s.wantNB || !s.lease.Held() || s.nb.Active() {
		return
	}
	if info, ok := s.nb.Start(); ok {
		s.logf("starting NetBird")
		// The launch's log offset and start time go to the worker now, before
		// the daemon exists: its monitors count from the launch.
		s.send(Msg{Type: TypeNetBird, Gen: s.gen, Launch: info.launch, State: NBLaunching, LogOffset: info.offset, AtBootNs: int64(info.at)})
	}
}

func (s *Supervisor) handleNB(e nbEvent) (string, string) {
	if e.kind != nbStopped && e.launch != s.nb.currentLaunch() {
		return "", "" // an event of a launch that has been stopped
	}
	switch e.kind {
	case nbStarted:
		s.logf("NetBird is up (launch %d)", e.launch)
		s.send(Msg{Type: TypeNetBird, Gen: s.gen, Launch: e.launch, State: NBStarted, LogOffset: e.offset, AtBootNs: int64(s.c.Clock())})
	case nbFailed:
		s.send(Msg{Type: TypeNetBird, Gen: s.gen, Launch: e.launch, State: NBFailed})
		return ReasonNetBird, "NetBird could not be started: " + e.detail
	case nbExited:
		return ReasonNetBird, "NetBird stopped unexpectedly: " + e.detail
	case nbStopped:
		s.send(Msg{Type: TypeNetBird, Gen: s.gen, Launch: e.launch, State: NBStopped})
		s.maybeStartNetBird()
	}
	return "", ""
}

// writeLeaseFile queues the small file `molebridge status` reads. The write
// happens on a goroutine of its own.
func (s *Supervisor) writeLeaseFile() {
	expiry, ok := s.lease.Expiry()
	state := "starting"
	switch {
	case s.stopping || s.lease.Revoked():
		state = "revoked"
	case ok && s.lease.Held():
		state = "held"
	case ok:
		state = "lapsed"
	}
	obj := validate.Members("state", state, "generation", s.gen,
		"expiry_boot_ns", int64(expiry), "updated_boot_ns", int64(s.c.Clock()), "grace_s", int(s.s.Grace/time.Second))
	path := s.s.PathLease()
	s.leaseOut.Submit(func() { _ = jsonfile.Write(path, obj, jsonfile.Options{Public: true}) }, s.stopping)
}

// stopSequence is the plan's timeline, budget 15 seconds:
//
//	T+0   the worker is told to stop and every NetBird group gets TERM
//	T+6   KILL to the worker and to any NetBird process still alive
//	T+7   everything is reaped, or the step is named as incomplete
//	T+7..12 the cleanup child (not while the worker survives)
//	T+13  exit: 0 only for a requested stop with complete cleanup
//
// Every wait is bounded; a second TERM changes nothing.
func (s *Supervisor) stopSequence(reason string, requested bool) int {
	t0 := time.Now()
	at := func(d time.Duration) time.Time { return t0.Add(d) }
	tm := s.c.Timing
	s.stopping = true
	s.wantNB = false
	s.lease.Revoke()
	// The signals go first. Nothing before them touches a file, a pipe that
	// can fill, or a log: every write below is queued off this goroutine.
	if s.nb != nil {
		s.nb.Close()
		s.nb.TermAll()
	}
	if s.worker != nil {
		s.send(Msg{Type: TypeStop})
	}
	if requested {
		s.pub.Close()
	} else {
		s.pub.Failure(s.c.Wall())
	}
	s.writeLeaseFile()
	s.logf("stopping (%s)", reason)

	alive := func() (worker, netbird bool) {
		if s.worker != nil {
			select {
			case <-s.worker.Reaped():
				worker = s.worker.GroupAlive()
			default:
				worker = true
			}
		}
		if s.nb != nil {
			netbird = s.nb.Alive()
		}
		return
	}
	wait := func(until time.Time) {
		for time.Now().Before(until) {
			if w, n := alive(); !w && !n {
				return
			}
			s.drain(10 * time.Millisecond)
		}
	}
	wait(at(tm.StopKill))
	if w, n := alive(); w || n {
		if w {
			_ = s.worker.KillGroup()
		}
		if n {
			s.nb.KillAll()
		}
	}
	wait(at(tm.StopReaped))
	var left []string
	workerLeft, nbLeft := alive()
	if workerLeft {
		left = append(left, "the worker")
	}
	if nbLeft {
		left = append(left, "NetBird")
	}

	// The cleanup is an executor independent of the failed worker, and never
	// runs beside a mutator that survived: not beside the worker, and not
	// beside a NetBird process either, which could recreate the overlay link
	// the cleanup is deleting. With either left, it is reported incomplete.
	if !workerLeft && !nbLeft {
		if err := s.cleanup(at(tm.CleanupEnd)); err != nil {
			left = append(left, err.Error())
		}
	} else {
		left = append(left, "the cleanup (not run while a process of this exit survives)")
	}
	// The failure record and the lease file were queued at T+0; give them the
	// rest of the budget to land, and no more.
	if rest := time.Until(at(tm.ExitBy)); rest > 0 {
		if rest > time.Second {
			rest = time.Second
		}
		if !s.pub.Wait(rest) {
			s.logf("the status record could not be written in time (is the state volume stuck?)")
		}
	}
	code := 1
	if len(left) > 0 {
		fmt.Fprintf(s.stderr, prefix+"cleanup incomplete: %s still there; the routing guards stay in place\n", join(left))
	} else if requested {
		code = 0
	}
	s.logf("stopped (%s, exit %d); the routing guards stay in place", reason, code)
	return code
}

func join(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

// drain waits up to d for an event and discards it: during the stop sequence
// only the processes' fate matters.
func (s *Supervisor) drain(d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.events:
	case <-t.C:
	}
}

// cleanup runs `molebridge exit --cleanup` and waits for it until the
// deadline, then kills its group.
func (s *Supervisor) cleanup(deadline time.Time) error {
	args := s.c.CleanupArgs
	if args == nil {
		args = []string{"exit", "--cleanup", "--backend", s.s.BackendName(), "--kind", s.s.Kind()}
	}
	p, err := s.reap.Start(proc.Spec{Path: s.c.Self, Args: append([]string{"molebridge"}, args...), Env: CleanupEnv(s.s.Env),
		Stderr: osStderr(s.c.Stderr), Stdout: osStderr(s.c.Stderr)})
	if err != nil {
		return errors.New("the cleanup (could not start)")
	}
	left := time.Until(deadline)
	if left < 500*time.Millisecond {
		left = 500 * time.Millisecond
	}
	ws, ok := p.Wait(left)
	if !ok {
		_ = p.KillGroup()
		p.WaitGone(500 * time.Millisecond)
		return errors.New("the cleanup (it ran past its time)")
	}
	if p.GroupAlive() {
		_ = p.KillGroup()
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		return fmt.Errorf("the cleanup (exit %d)", proc.ExitCode(ws))
	}
	return nil
}
