package exit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/proc"
)

// Timing holds every wait of the supervisor. Production uses DefaultTiming;
// tests shorten the ones they exercise.
type Timing struct {
	// Tick is the supervisor's timer: lease deadline check and publication.
	Tick time.Duration
	// PublishEvery is the period of the lease-only publication.
	PublishEvery time.Duration
	// The stop sequence (budget 15 s): at T+StopKill any survivor is killed, by
	// T+StopReaped everything is reaped or the step is named, the cleanup child
	// runs until T+CleanupEnd and the supervisor exits by T+ExitBy.
	StopKill, StopReaped, CleanupEnd, ExitBy time.Duration
	// NetBird's sequence: the daemon has NBLive to answer `status --check
	// live` (polled every NBPoll, each run bounded by NBProbe) and `netbird up`
	// has NBUp. NBUp is 120 s rather than the entrypoint's unbounded wait:
	// a first enrollment with a setup key can be slow, and nothing else may
	// be waited on forever.
	NBLive, NBPoll, NBProbe, NBUp time.Duration
	// NBTerm is how long a NetBird group gets after TERM before KILL when the
	// supervisor stops it for an unready contract.
	NBTerm time.Duration
}

// DefaultTiming is the plan's timeline.
func DefaultTiming() Timing {
	return Timing{
		Tick: 500 * time.Millisecond, PublishEvery: 2 * time.Second,
		StopKill: 6 * time.Second, StopReaped: 7 * time.Second, CleanupEnd: 12 * time.Second, ExitBy: 13 * time.Second,
		NBLive: 30 * time.Second, NBPoll: time.Second, NBProbe: 5 * time.Second, NBUp: 120 * time.Second,
		NBTerm: 6 * time.Second,
	}
}

type nbKind int

const (
	nbStarted nbKind = iota
	nbFailed
	nbExited
	nbStopped
)

// nbEvent is what the NetBird manager tells the supervisor.
type nbEvent struct {
	kind   nbKind
	launch int
	detail string
	offset int64
	// at is the boot-clock time the launch began.
	at time.Duration
}

// nbManager runs NetBird's 0.80.0 entrypoint sequence itself: `netbird service
// run` as a daemon in a process group of its own, `netbird status --check
// live` once a second until the daemon answers, then `netbird up`. Every wait
// is bounded and every process is reaped by the reaper.
type nbManager struct {
	reaper *proc.Reaper
	bin    string
	// env is NetBird's environment for every command; envUp adds the
	// enrollment secret for `netbird up` alone.
	env, envUp []string
	clock      bootclock.Clock
	logPath    string
	out        io.Writer
	timing     Timing
	emit       func(nbEvent)

	mu       sync.Mutex
	closed   bool
	active   bool
	stopping bool
	launch   int
	cancel   context.CancelFunc
	done     chan struct{}
	procs    []*proc.Process
	// pending counts process creations in flight.
	pending atomic.Int32
	// hook, when set (tests), is called at stages of a launch's sequence and
	// right before each process creation.
	hook func(stage string)
}

// lookPath finds name in the PATH of an environment, as the NetBird children
// would; the supervisor starts programs by absolute path.
func lookPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	path := "/usr/local/bin:/usr/bin:/bin"
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			path = kv[5:]
		}
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s: not found in PATH", name)
}

// watchLogPath is the first absolute path of NB_LOG_FILE (the NetBird log the
// exit reads its own launch's lines from).
func watchLogPath(env map[string]string) string {
	v := env["NB_LOG_FILE"]
	if v == "" {
		v = DefaultNetBirdLog
	}
	for _, entry := range strings.Split(v, ",") {
		if strings.HasPrefix(entry, "/") {
			return entry
		}
	}
	return ""
}

// fileSize is the size of the file, 0 for anything unreadable.
func fileSize(path string) int64 {
	if path == "" {
		return 0
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return 0
	}
	return fi.Size()
}

// launchInfo says what a launch begins with: its number, the size of NetBird's
// log at that moment (the launch's own lines start there) and the boot-clock
// time it began (the gluetun fwmark accounting starts there).
type launchInfo struct {
	launch int
	offset int64
	at     time.Duration
}

// Start begins a launch. It reports false when the supervisor is stopping or a
// launch is already running or being stopped.
func (m *nbManager) Start() (launchInfo, bool) {
	// Read before the lock is taken: a stat of the log must not be held under
	// the lock the deadline path takes.
	offset, at := fileSize(m.logPath), m.clock()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.active || m.stopping {
		return launchInfo{}, false
	}
	m.pruneLocked()
	m.active = true
	m.launch++
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	info := launchInfo{launch: m.launch, offset: offset, at: at}
	go m.run(ctx, info, m.done)
	return info, true
}

func (m *nbManager) currentLaunch() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.launch
}

// Active reports a launch in progress (starting or running).
func (m *nbManager) Active() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active || m.stopping
}

// Close forbids new launches for good and cancels the running launch's
// sequence. The cancellation and the refusal of every later spawn happen under
// the lock spawn checks them under, so a process either exists before Close
// returns (and the stop sequence signals it) or is never started.
func (m *nbManager) Close() {
	m.mu.Lock()
	m.closed = true
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Unlock()
}

// Stop ends the running launch for an unready contract: the launch is
// cancelled (under the spawn lock), TERM goes to every group, the launch's
// goroutine is joined, KILL follows after NBTerm, and only when every process
// is reaped is nbStopped emitted. It does not block.
func (m *nbManager) Stop() {
	m.mu.Lock()
	if !m.active || m.stopping {
		m.mu.Unlock()
		return
	}
	m.stopping = true
	launch := m.launch
	done := m.done
	m.cancel()
	m.mu.Unlock()
	go func() {
		m.TermAll()
		// The startup goroutine ends at once on cancellation (every wait it
		// has selects on its context); it is joined before anything is
		// reported, so nothing it started can be missed. The wait is bounded
		// all the same.
		select {
		case <-done:
		case <-time.After(m.timing.NBTerm):
		}
		m.TermAll()
		if !m.waitGone(m.timing.NBTerm) {
			m.KillAll()
			m.waitGone(time.Second)
		}
		m.mu.Lock()
		m.active, m.stopping = false, false
		m.mu.Unlock()
		m.emit(nbEvent{kind: nbStopped, launch: launch})
	}()
}

// pruneLocked forgets the processes that are reaped and whose group is gone:
// nothing of them is left to signal or wait for, and without this every
// probe, daemon and `netbird up` of every launch would stay in the list for
// the supervisor's life, each one scanned again by every stop. Start calls it
// with m.mu held, between launches; a process still around stays tracked.
// GroupAlive's check is one kill(2) with signal 0, which never blocks.
func (m *nbManager) pruneLocked() {
	kept := m.procs[:0]
	for _, p := range m.procs {
		select {
		case <-p.Reaped():
			if !p.GroupAlive() {
				continue
			}
		default:
		}
		kept = append(kept, p)
	}
	clear(m.procs[len(kept):])
	m.procs = kept
}

func (m *nbManager) snapshot() []*proc.Process {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]*proc.Process(nil), m.procs...)
}

// TermAll sends TERM to every NetBird process group.
func (m *nbManager) TermAll() {
	for _, p := range m.snapshot() {
		_ = p.SignalGroup(syscall.SIGTERM)
	}
}

// KillAll sends KILL to every NetBird process group.
func (m *nbManager) KillAll() {
	for _, p := range m.snapshot() {
		_ = p.KillGroup()
	}
}

// Alive reports whether any NetBird process is left (unreaped, or a group
// member still around).
func (m *nbManager) Alive() bool {
	if m.pending.Load() > 0 {
		return true
	}
	for _, p := range m.snapshot() {
		select {
		case <-p.Reaped():
			if !p.GroupAlive() {
				continue
			}
		default:
		}
		return true
	}
	return false
}

func (m *nbManager) waitGone(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for m.Alive() {
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
	return true
}

var errClosed = errors.New("the supervisor is stopping or the launch was cancelled; NetBird is not started")

// spawn starts a NetBird program in a group of its own, its output copied
// line by line to the supervisor's log (when copyOutput), and tracks it.
//
// Process creation can stall (a hung exec on a sick filesystem, a fork that
// waits on memory), and the supervisor's deadline path takes m.mu: Active,
// Close, Stop and the stop sequence's signalling. So no lock is held while the
// process is created. The launch is checked under the lock first (open, still
// the current launch, not cancelled) and a creation in flight is counted
// (Alive reports it, so nothing is called finished, and no cleanup runs,
// beside it); the lock is released for the fork; and the lock is taken again to
// attach the pid. If the launch was cancelled or the manager closed in the
// meantime, the late child is killed at once, by its group, before anything
// else happens to it: a cancelled launch never leaves a process nobody
// supervises. env is the command's own environment.
func (m *nbManager) spawn(ctx context.Context, launch int, args []string, env []string, copyOutput bool) (*proc.Process, error) {
	path, err := lookPath(args[0], env)
	if err != nil {
		return nil, err
	}
	spec := proc.Spec{Path: path, Args: args, Env: env}
	var r *os.File
	if copyOutput {
		var w *os.File
		if r, w, err = os.Pipe(); err != nil {
			return nil, err
		}
		spec.Stdout, spec.Stderr = w, w
		defer w.Close()
	}
	if !m.admit(ctx, launch) {
		if r != nil {
			r.Close()
		}
		return nil, errClosed
	}
	defer m.pending.Add(-1)
	if m.hook != nil {
		m.hook("spawn " + strings.Join(args[1:], " "))
	}
	p, err := m.reaper.Start(spec)
	if err != nil {
		if r != nil {
			r.Close()
		}
		return nil, err
	}
	m.mu.Lock()
	// Tracked before anything else, so Alive and the stop sequence see it.
	m.procs = append(m.procs, p)
	cancelled := m.closed || m.launch != launch || ctx.Err() != nil
	m.mu.Unlock()
	if cancelled {
		_ = p.KillGroup()
		if r != nil {
			r.Close()
		}
		return nil, errClosed
	}
	if r != nil {
		go func() {
			CopyLines("netbird: ", r, m.out, 4096)
			r.Close()
		}()
	}
	return p, nil
}

// admit counts a process creation in flight if the launch may still start one.
func (m *nbManager) admit(ctx context.Context, launch int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.launch != launch || ctx.Err() != nil {
		return false
	}
	m.pending.Add(1)
	return true
}

// probe runs a short NetBird command (status check), killing its group if it
// is late or the launch is cancelled. It reports whether it exited 0.
func (m *nbManager) probe(ctx context.Context, launch int, args []string, limit time.Duration) bool {
	p, err := m.spawn(ctx, launch, args, m.env, false)
	if err != nil {
		return false
	}
	t := time.NewTimer(limit)
	defer t.Stop()
	select {
	case <-p.Reaped():
	case <-t.C:
		_ = p.KillGroup()
		p.WaitGone(time.Second)
		return false
	case <-ctx.Done():
		_ = p.KillGroup()
		p.WaitGone(time.Second)
		return false
	}
	if p.GroupAlive() {
		_ = p.KillGroup()
	}
	ws, _ := p.Status()
	return ws.Exited() && ws.ExitStatus() == 0
}

func (m *nbManager) fail(ctx context.Context, launch int, format string, a ...any) {
	if ctx.Err() != nil {
		return
	}
	m.emit(nbEvent{kind: nbFailed, launch: launch, detail: fmt.Sprintf(format, a...)})
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (m *nbManager) run(ctx context.Context, info launchInfo, done chan struct{}) {
	defer close(done)
	launch, offset := info.launch, info.offset
	if m.hook != nil {
		m.hook("begin")
	}
	// The daemon gets NetBird's environment without the enrollment secret.
	svc, err := m.spawn(ctx, launch, []string{"netbird", "service", "run"}, m.env, true)
	if err != nil {
		m.fail(ctx, launch, "could not start `netbird service run`: %v", err)
		return
	}
	// The entrypoint's wait_for_daemon_startup: `status --check live` once a
	// second until it succeeds, for up to NBLive.
	deadline := time.Now().Add(m.timing.NBLive)
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-svc.Reaped():
			ws, _ := svc.Status()
			m.fail(ctx, launch, "`netbird service run` exited with status %d before the daemon answered", proc.ExitCode(ws))
			return
		default:
		}
		if m.probe(ctx, launch, []string{"netbird", "status", "--check", "live"}, m.timing.NBProbe) {
			break
		}
		if !time.Now().Before(deadline) {
			m.fail(ctx, launch, "the NetBird daemon did not become responsive within %d seconds", int(m.timing.NBLive/time.Second))
			return
		}
		if !sleepCtx(ctx, m.timing.NBPoll) {
			return
		}
	}
	if m.hook != nil {
		m.hook("before up")
	}
	// Only `netbird up` enrolls: only it gets the setup key.
	up, err := m.spawn(ctx, launch, []string{"netbird", "up"}, m.envUp, true)
	if err != nil {
		m.fail(ctx, launch, "could not start `netbird up`: %v", err)
		return
	}
	t := time.NewTimer(m.timing.NBUp)
	defer t.Stop()
	select {
	case <-up.Reaped():
		ws, _ := up.Status()
		if up.GroupAlive() {
			_ = up.KillGroup()
		}
		if !ws.Exited() || ws.ExitStatus() != 0 {
			m.fail(ctx, launch, "`netbird up` failed (exit %d)", proc.ExitCode(ws))
			return
		}
	case <-svc.Reaped():
		m.fail(ctx, launch, "`netbird service run` exited while `netbird up` ran")
		return
	case <-t.C:
		_ = up.KillGroup()
		m.fail(ctx, launch, "`netbird up` did not finish within %d seconds", int(m.timing.NBUp/time.Second))
		return
	case <-ctx.Done():
		return
	}
	if ctx.Err() != nil {
		return
	}
	m.emit(nbEvent{kind: nbStarted, launch: launch, offset: offset, at: info.at})
	select {
	case <-svc.Reaped():
		ws, _ := svc.Status()
		if ctx.Err() == nil {
			m.emit(nbEvent{kind: nbExited, launch: launch, detail: fmt.Sprintf("`netbird service run` exited with status %d", proc.ExitCode(ws))})
		}
	case <-ctx.Done():
	}
}

// CopyLines copies r to w one line at a time with a prefix, cutting lines
// longer than max bytes (the rest of such a line is dropped and marked), so a
// daemon that logs without newlines cannot make the supervisor buffer without
// bound. It returns when r ends.
func CopyLines(prefix string, r io.Reader, w io.Writer, max int) {
	br := bufio.NewReaderSize(r, max)
	for {
		line, err := br.ReadSlice('\n')
		if len(line) > 0 {
			text := strings.TrimRight(string(line), "\r\n")
			if errors.Is(err, bufio.ErrBufferFull) {
				text += " [line cut]"
				// Drop the rest of the line.
				for errors.Is(err, bufio.ErrBufferFull) {
					_, err = br.ReadSlice('\n')
				}
			}
			fmt.Fprintf(w, "%s%s\n", prefix, sanitize(text))
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return
		}
	}
}
