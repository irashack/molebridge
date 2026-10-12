//go:build linux

package exit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/nbprofile"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/tunnel"
	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/watch"
)

// workerSender writes the worker's messages. Sequence numbers are taken under
// the same lock as the write, so they reach the supervisor in order.
type workerSender struct {
	mu  sync.Mutex
	w   io.Writer
	gen string
	seq uint64
}

func (s *workerSender) send(m Msg) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m.Gen = s.gen
	if m.Type == TypeRenew || m.Type == TypeStatus {
		s.seq++
		m.Seq = s.seq
	}
	b, err := m.Encode()
	if err != nil {
		return err
	}
	_, err = s.w.Write(b)
	return err
}

// loopSource is one supervised loop: where its last completion is read and
// how stale it may be.
type loopSource struct {
	progress func() time.Duration
	bound    time.Duration
}

// worker is `molebridge exit --worker`.
type worker struct {
	s     *Settings
	gen   string
	clock bootclock.Clock
	out   io.Writer // standard error
	send  *workerSender

	ctx    context.Context
	cancel context.CancelFunc

	loops map[string]loopSource

	// ackExpiry is the boot-clock nanoseconds the supervisor last
	// acknowledged: informational, the supervisor's clock decides.
	ackExpiry atomic.Int64

	// resetReady asks the readiness loop to forget that it sent ready (a
	// monitor stopped NetBird).
	resetReady atomic.Bool
	tunnelUp   atomic.Bool
	nbRunning  atomic.Bool
	blocked    atomic.Bool
	pipeOn     atomic.Bool
	launch     atomic.Int64
	netbirdCh  chan Msg

	mut  *mutator.Mutator
	sys  *KernelSystem
	pipe Pipeline

	monitors *gluetunMonitors

	logMu  sync.Mutex
	warned map[string]time.Time
}

// RunWorker is the worker's main. environ is the process environment; the
// descriptors are 3 (to the supervisor) and 4 (from it). It returns the exit
// status.
func RunWorker(environ []string, stderr io.Writer) int {
	env := EnvMap(environ)
	// NetBird's setup key is the supervisor's; the worker never needs it.
	delete(env, "NB_SETUP_KEY")
	delete(env, "WT_SETUP_KEY")
	_ = os.Unsetenv("NB_SETUP_KEY")
	_ = os.Unsetenv("WT_SETUP_KEY")
	gen := env["MOLEBRIDGE_GENERATION"]
	if !validGen(gen) {
		fmt.Fprintln(stderr, prefix+"the worker is started by the supervisor only")
		return 2
	}
	s, err := LoadSettings(env, LoadOptions{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	w := &worker{s: s, gen: gen, clock: bootclock.System(), out: stderr, warned: map[string]time.Time{},
		netbirdCh: make(chan Msg, 8)}
	w.send = &workerSender{w: os.NewFile(3, "to-supervisor"), gen: gen}
	w.ctx, w.cancel = context.WithCancel(context.Background())
	defer w.cancel()
	go w.readSupervisor(os.NewFile(4, "from-supervisor"))
	return w.run()
}

func (w *worker) logf(format string, a ...any) {
	w.logMu.Lock()
	defer w.logMu.Unlock()
	fmt.Fprintf(w.out, prefix+format+"\n", a...)
}

// warnEvery logs a repeating condition at most once per period.
func (w *worker) warnEvery(key string, period time.Duration, format string, a ...any) {
	w.logMu.Lock()
	now := time.Now()
	if t, ok := w.warned[key]; ok && now.Sub(t) < period {
		w.logMu.Unlock()
		return
	}
	w.warned[key] = now
	w.logMu.Unlock()
	w.logf(format, a...)
}

// readSupervisor handles the supervisor's messages. The end of the pipe, like
// a stop message, ends the worker: a worker whose supervisor is gone holds a
// contract nobody supervises.
func (w *worker) readSupervisor(in io.Reader) {
	lr := NewLineReader(in)
	for {
		line, err := lr.Next()
		if err != nil {
			w.cancel()
			return
		}
		m, err := DecodeFromSupervisor(line)
		if err != nil {
			w.logf("the supervisor sent something unreadable: %v", err)
			w.cancel()
			return
		}
		switch m.Type {
		case TypeStop:
			w.cancel()
			return
		case TypeAck:
			if m.Gen == w.gen {
				w.ackExpiry.Store(m.ExpiryBootNs)
			}
		case TypeNetBird:
			select {
			case w.netbirdCh <- m:
			default:
			}
		}
	}
}

// ownerCheck is the owner_record check as the supervisor will write it, from
// the last acknowledgement.
func (w *worker) ownerCheck() validate.Obj {
	now := time.Now()
	expiry := time.Duration(w.ackExpiry.Load())
	left := expiry - w.clock()
	return OwnerCheck(expiry > 0 && left > 0, now, now.Add(left))
}

// eligible reports that every supervised loop completed a step within its
// bound.
func (w *worker) eligible() bool {
	now := w.clock()
	for _, l := range w.loops {
		if p := l.progress(); now-p > l.bound {
			return false
		}
	}
	return true
}

func (w *worker) loopTimes() map[string]int64 {
	out := map[string]int64{}
	for name, l := range w.loops {
		out[name] = int64(l.progress())
	}
	return out
}

func (w *worker) renewOnce() {
	if !w.eligible() {
		w.warnEvery("ineligible", 10*time.Second, "a supervised loop is late; no lease renewal is sent")
		return
	}
	if err := w.send.send(Msg{Type: TypeRenew, Loops: w.loopTimes()}); err != nil {
		w.warnEvery("send", 10*time.Second, "cannot reach the supervisor: %v", err)
	}
}

func (w *worker) renewLoop() {
	w.renewOnce()
	t := time.NewTicker(RenewEvery)
	defer t.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-t.C:
			w.renewOnce()
		}
	}
}

func (w *worker) spec() contract.Spec {
	sp := contract.Spec{Config: w.s.Routing, ReturnPath: map[rtnl.Family][]netip.Addr{},
		LeaveReturnPath: map[rtnl.Family]bool{}, TempGuard: map[rtnl.Family]bool{}}
	if c := w.s.Conf; c != nil {
		if c.Addr4.IsValid() {
			sp.ReturnPath[rtnl.V4] = []netip.Addr{c.Addr4}
		}
		if c.Addr6.IsValid() {
			sp.ReturnPath[rtnl.V6] = []netip.Addr{c.Addr6}
		}
		if c.RuleOwner() == "applier" {
			// A config with no address leaves rules 94 and 98 to the
			// transaction that sets the address (PIA).
			sp.LeaveReturnPath[rtnl.V4], sp.LeaveReturnPath[rtnl.V6] = true, true
		}
	}
	return sp
}

type noKernel struct{}

func (noKernel) Take(rtnl.Interest) (*rtnl.Snapshot, error) { return rtnl.NewSnapshot(), nil }
func (noKernel) AddRule(rtnl.Rule) error                    { return errors.New("no kernel") }
func (noKernel) DelRule(rtnl.Rule) error                    { return errors.New("no kernel") }
func (noKernel) DelRulePriority(rtnl.Family, uint32) error  { return errors.New("no kernel") }
func (noKernel) ReplaceRoute(rtnl.Route) error              { return errors.New("no kernel") }
func (noKernel) DelRoute(rtnl.Route) error                  { return errors.New("no kernel") }

// run is the worker's start order: validate (done), subscribe before the first
// snapshot, install the contract, bring the tunnel up, report ready, watch and
// repair.
func (w *worker) run() int {
	s := w.s
	if s.NoIdentity {
		w.logf("%s", nbprofile.NoIdentityNotice)
	}
	if s.OtherConfs > 0 {
		w.logf("warning: %d other .conf file(s) in %s are ignored; only %s.conf is used", s.OtherConfs, s.ConfDir, s.Routing.ExitIf)
	}
	if s.Overlay() {
		if v, err := os.ReadFile(contract.ReturnPathSysctl); err != nil || !contract.ReturnPathEnabled(string(v)) {
			w.logf("warning: net.ipv4.icmp_errors_use_inbound_ifaddr is not 1; set it in compose.yaml or IPv4 path MTU discovery through the exit will fail")
		}
	}

	if s.Routing.IsGluetun() {
		if err := w.checkControlServer(); err != nil {
			if w.ctx.Err() != nil {
				return 0
			}
			w.logf("%v", err)
			return 1
		}
	}

	var (
		sub  *rtnl.Subscriber
		conn *rtnl.Conn
	)
	if s.Overlay() {
		var err error
		// Subscribe before the first snapshot, so no change between the
		// snapshot and the watch is missed.
		if sub, err = rtnl.Subscribe(rtnl.Options{}); err != nil {
			w.logf("%v", err)
			return 1
		}
		defer sub.Close()
		if conn, err = rtnl.Dial(rtnl.Options{}); err != nil {
			w.logf("%v", err)
			return 1
		}
		defer conn.Close()
	}
	obs, err := rtnl.Dial(rtnl.Options{})
	if err != nil {
		w.logf("%v", err)
		return 1
	}
	defer obs.Close()
	tun, err := tunnel.Open(tunnel.Options{})
	if err != nil {
		w.logf("%v", err)
		return 1
	}
	defer tun.Close()

	spec := w.spec()
	var kernel mutator.Kernel = noKernel{}
	if conn != nil {
		kernel = conn
	}
	w.mut = mutator.New(mutator.Options{Kernel: kernel, Spec: spec, Clock: w.clock, GuardRepairs: s.Native(),
		Logf: func(format string, a ...any) { w.logf(format, a...) }})
	w.mut.Start()
	defer w.mut.Close()

	w.loops = map[string]loopSource{LoopMutator: {w.mut.Progress, MutatorBound}}
	if s.Overlay() {
		wt := watch.New(watch.Config{Source: sub, Mutator: w.mut, Interval: s.Interval, Clock: w.clock,
			Tables: spec.Interest().Tables, Links: []string{s.Routing.ExitIf, s.Routing.OverlayIf, s.Routing.HostIf},
			Logf: func(format string, a ...any) { w.logf(format, a...) }})
		w.loops[LoopWatcher] = loopSource{wt.Progress, LoopBound}
		go func() {
			if err := wt.Run(w.ctx); err != nil {
				w.logf("%v", err)
				w.cancel()
			}
		}()
	}
	if s.Routing.IsGluetun() && s.Overlay() {
		if err := w.startGluetunMonitors(tun); err != nil {
			w.logf("%v", err)
			return 1
		}
	}

	w.sys = &KernelSystem{S: s, Spec: spec, Obs: obs, Mut: w.mut, Tun: tun, Generation: w.gen}
	// The first renewal goes out before the long steps below: the supervisor
	// gives a new worker only StartupAllowance for it.
	go w.renewLoop()

	if err := w.mut.Install(w.ctx); err != nil {
		if w.ctx.Err() != nil {
			return 0
		}
		w.logf("%v", err)
		w.logf("the routing contract could not be installed; no tunnel was started")
		return 1
	}
	if s.Overlay() {
		w.logf("rules installed; the exit table holds its unreachable fallback")
	}

	pipe, err := newPipeline(pipelineEnv{S: s, System: w.sys, Publish: w.publish, OwnerCheck: w.ownerCheckFor(), Log: func(l string) { w.logf("%s", l) }})
	if err != nil {
		w.logf("applier: invalid configuration or unavailable state")
		w.logf("%v", err)
		return 1
	}
	w.pipe = pipe

	var wg sync.WaitGroup
	spawn := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	if s.Native() {
		spawn(func() { w.tunnelLoop(tun, obs) })
	} else {
		w.tunnelUp.Store(true)
	}
	if s.Overlay() {
		spawn(w.readinessLoop)
		spawn(w.netbirdLoop)
	} else {
		w.pipeOn.Store(true)
	}
	spawn(w.pipelineLoop)
	spawn(w.heartbeatLoop)
	w.drillHooks()

	<-w.ctx.Done()
	w.logf("stopping")
	wg.Wait()
	return 0
}

func (w *worker) ownerCheckFor() func() validate.Obj {
	if w.s.Native() {
		return w.ownerCheck
	}
	return nil
}

// publish hands a record to the supervisor.
func (w *worker) publish(r validate.ObjectMarshaler) error {
	return w.send.send(Msg{Type: TypeStatus, Rec: r})
}

func (w *worker) tunnelParams() tunnel.Params {
	return tunnel.Params{ExitIf: w.s.Routing.ExitIf, Conf: w.s.Conf}
}

// tunnelLoop keeps the tunnel up: when the interface is missing or down it is
// recreated, on the curve 2 s doubling to 60 s between failed attempts.
func (w *worker) tunnelLoop(tun *tunnel.Manager, obs *rtnl.Conn) {
	var delay time.Duration
	var next time.Time
	for {
		up := false
		if links, err := obs.Links(); err == nil {
			for _, l := range links {
				if l.Name == w.s.Routing.ExitIf && l.Up() {
					up = true
				}
			}
		}
		w.tunnelUp.Store(up)
		if !up && !time.Now().Before(next) {
			w.logf("bringing the tunnel up")
			err := w.mut.Do(w.ctx, "bring the tunnel up", func(tx *mutator.Tx) error { return tun.Up(w.tunnelParams()) })
			if err != nil {
				if w.ctx.Err() != nil {
					return
				}
				delay = tunnel.Delay(delay)
				next = time.Now().Add(delay)
				w.logf("tunnel bring-up failed (%v); retrying in %d s", err, int(delay/time.Second))
			} else {
				delay = 0
				w.logf("tunnel up")
				w.mut.Reconcile("tunnel up")
				w.tunnelUp.Store(true)
			}
		}
		if !sleepCtx(w.ctx, time.Second) {
			return
		}
	}
}

// readinessLoop decides when the supervisor may run NetBird.
func (w *worker) readinessLoop() {
	r := &readiness{grace: w.s.Grace}
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-t.C:
		}
		if w.resetReady.Swap(false) {
			r.markUnready()
		}
		res := w.mut.LastPass()
		holds := res.ContractHolds
		if w.s.Native() {
			holds = res.Verified
		}
		switch r.step(time.Now(), holds, w.tunnelUp.Load(), w.blocked.Load()) {
		case actReady:
			if err := w.recheckNetBird(); err != nil {
				r.markUnready()
				w.warnEvery("recheck", 30*time.Second, "NetBird is not started: %v", err)
				continue
			}
			w.logf("ready")
			w.renewOnce()
			_ = w.send.send(Msg{Type: TypeReady})
		case actUnready:
			reason := w.unreadyReason(res)
			w.logf("not ready: %s", reason)
			_ = w.send.send(Msg{Type: TypeUnready, Reason: reason})
		}
	}
}

func (w *worker) unreadyReason(res mutator.PassResult) string {
	if w.blocked.Load() {
		return "the NetBird profile does not exclude the tunnel interface; nothing is admitted"
	}
	var parts []string
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		for _, p := range res.Problems[f] {
			parts = append(parts, fmt.Sprintf("%s %s", f, p))
		}
	}
	msg := fmt.Sprintf("the routing contract has not held for %d seconds", int(w.s.Grace/time.Second))
	if len(parts) > 0 {
		msg += ": " + strings.Join(parts, ", ")
	}
	return msg
}

// recheckNetBird repeats the checks that run before the daemon starts
// (D25): NetBird's settings, the stored profile the daemon will load and its
// interface blacklist.
func (w *worker) recheckNetBird() error {
	s := w.s
	backend := nbprofile.BackendWireGuard
	if s.Routing.IsGluetun() {
		backend = nbprofile.BackendGluetun
	}
	if _, err := nbprofile.CheckAll(withDefaults(s.Env, map[string]string{"EXIT_IF": s.Routing.ExitIf}), backend, s.NBPaths); err != nil {
		return err
	}
	_, err := nbprofile.CheckBlacklist(s.NBPaths, s.Routing.ExitIf)
	return err
}

// netbirdLoop handles the supervisor's reports about NetBird.
func (w *worker) netbirdLoop() {
	for {
		select {
		case <-w.ctx.Done():
			return
		case m := <-w.netbirdCh:
			switch m.State {
			case NBStarted:
				w.launch.Store(int64(m.Launch))
				// `netbird up` in daemon mode can return before any
				// configuration change applies: read the profile again and
				// admit nothing unless the tunnel is excluded.
				if err := nbprofile.CheckBlacklistAfterUp(w.s.NBPaths, w.s.Routing.OverlayIf, w.s.Routing.ExitIf); err != nil {
					w.logf("%v", err)
					w.blocked.Store(true)
					w.nbRunning.Store(false)
					_ = w.send.send(Msg{Type: TypeUnready, Reason: truncate(err.Error(), 900)})
					continue
				}
				w.nbRunning.Store(true)
				if w.monitors != nil {
					w.monitors.newLaunch(m.Launch, m.LogOffset)
				}
				w.pipeOn.Store(true)
			case NBStopped, NBFailed:
				w.nbRunning.Store(false)
				if w.monitors != nil {
					w.monitors.endLaunch()
				}
			}
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// pipelineLoop runs the control cycle, once NetBird is up and its profile
// verified (overlay) or at once (sidecar).
func (w *worker) pipelineLoop() {
	for {
		if w.pipeOn.Load() && !w.blocked.Load() {
			if err := w.pipe.Tick(w.ctx); err != nil && w.ctx.Err() == nil {
				w.warnEvery("tick", 30*time.Second, "applier: control cycle failed")
			}
		}
		if !sleepCtx(w.ctx, TickInterval) {
			return
		}
	}
}

// heartbeatLoop writes the heartbeat after each tick whose operational checks
// pass: the tunnel interface, the contract, NetBird running, and the pipeline's
// own health. A failed provider verification never fails health.
func (w *worker) heartbeatLoop() {
	for {
		if w.operational() {
			if err := writeHeartbeat(w.s.PathHeartbeat(), w.clock()); err != nil {
				w.warnEvery("heartbeat", time.Minute, "cannot write the heartbeat: %v", err)
			}
		}
		if !sleepCtx(w.ctx, TickInterval) {
			return
		}
	}
}

func (w *worker) operational() bool {
	if w.blocked.Load() || !w.pipeOn.Load() {
		return false
	}
	if w.s.Overlay() {
		res := w.mut.LastPass()
		holds := res.ContractHolds
		if w.s.Native() {
			holds = res.Verified && w.tunnelUp.Load()
		}
		if !holds || !w.nbRunning.Load() {
			return false
		}
	}
	return w.pipe.Healthy(w.ctx)
}
