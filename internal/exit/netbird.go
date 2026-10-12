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
	"syscall"
	"time"

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
}

// nbManager runs NetBird's 0.80.0 entrypoint sequence itself: `netbird service
// run` as a daemon in a process group of its own, `netbird status --check
// live` once a second until the daemon answers, then `netbird up`. Every wait
// is bounded and every process is reaped by the reaper.
type nbManager struct {
	reaper  *proc.Reaper
	bin     string
	env     []string
	logPath string
	out     io.Writer
	timing  Timing
	emit    func(nbEvent)

	mu       sync.Mutex
	closed   bool
	active   bool
	stopping bool
	launch   int
	cancel   context.CancelFunc
	procs    []*proc.Process
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

// Start begins a launch. It reports false when the supervisor is stopping or a
// launch is already running or being stopped.
func (m *nbManager) Start() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.active || m.stopping {
		return false
	}
	m.active = true
	m.launch++
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	go m.run(ctx, m.launch)
	return true
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

// Close forbids new launches for good and abandons the running launch's
// sequence; the stop sequence ends the processes.
func (m *nbManager) Close() {
	m.mu.Lock()
	m.closed = true
	cancel := m.cancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// Stop ends the running launch for an unready contract: TERM to every group,
// KILL after NBTerm, reaped; then nbStopped. It does not block.
func (m *nbManager) Stop() {
	m.mu.Lock()
	if !m.active || m.stopping {
		m.mu.Unlock()
		return
	}
	m.stopping = true
	launch := m.launch
	cancel := m.cancel
	m.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	go func() {
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

var errClosed = errors.New("the supervisor is stopping; NetBird is not started")

// spawn starts a NetBird program in a group of its own, its output copied
// line by line to the supervisor's stderr (when copy), and tracks it.
func (m *nbManager) spawn(args []string, copyOutput bool) (*proc.Process, error) {
	path, err := lookPath(args[0], m.env)
	if err != nil {
		return nil, err
	}
	spec := proc.Spec{Path: path, Args: args, Env: m.env}
	var r *os.File
	if copyOutput {
		var w *os.File
		if r, w, err = os.Pipe(); err != nil {
			return nil, err
		}
		spec.Stdout, spec.Stderr = w, w
		defer w.Close()
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		if r != nil {
			r.Close()
		}
		return nil, errClosed
	}
	p, err := m.reaper.Start(spec)
	if err == nil {
		m.procs = append(m.procs, p)
	}
	m.mu.Unlock()
	if err != nil {
		if r != nil {
			r.Close()
		}
		return nil, err
	}
	if r != nil {
		go func() {
			CopyLines("netbird: ", r, m.out, 4096)
			r.Close()
		}()
	}
	return p, nil
}

// probe runs a short NetBird command (status check), killing its group if it
// is late or the launch is cancelled. It reports whether it exited 0.
func (m *nbManager) probe(ctx context.Context, args []string, limit time.Duration) bool {
	p, err := m.spawn(args, false)
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

func (m *nbManager) run(ctx context.Context, launch int) {
	offset := fileSize(m.logPath)
	svc, err := m.spawn([]string{"netbird", "service", "run"}, true)
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
		if m.probe(ctx, []string{"netbird", "status", "--check", "live"}, m.timing.NBProbe) {
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
	up, err := m.spawn([]string{"netbird", "up"}, true)
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
	m.emit(nbEvent{kind: nbStarted, launch: launch, offset: offset})
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

// lockedWriter serializes writes from several goroutines.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
