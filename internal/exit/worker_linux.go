//go:build linux

package exit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
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
	out   io.Writer // standard error, through a boundedLog
	send  *workerSender

	ctx    context.Context
	cancel context.CancelFunc

	loops map[string]loopSource

	// ackExpiry is the boot-clock nanoseconds the supervisor last
	// acknowledged: informational, the supervisor's clock decides.
	ackExpiry atomic.Int64

	tunnelUp atomic.Bool
	// firewallOK is a native sidecar's firewall as last read back: installed
	// and exactly as described.
	firewallOK atomic.Bool
	// fatalMsg is set when the generation must end with a failure (a gluetun
	// monitor condemned NetBird).
	fatalOnce sync.Once
	fatalMsg  atomic.Pointer[string]
	nbRunning atomic.Bool
	blocked   atomic.Bool
	pipeOn    atomic.Bool
	launch    atomic.Int64
	netbirdCh chan Msg

	mut *mutator.Mutator
	// watcher is the kernel watcher, nil without a routing contract.
	watcher *watch.Watcher
	sys     *KernelSystem
	pipe    Pipeline

	monitors *gluetunMonitors
	// drillStop is set by the drill-only hook (worker_hook_drill_linux.go).
	drillStop func()

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
	// The worker's lines go through the same bounded queue as the
	// supervisor's (boundedLog): a log driver that stops reading must not
	// stall a supervised loop, the mutation owner or the watcher among them,
	// until the lease lapses. While the queue is full a line is dropped and
	// counted, and the count is logged once the sink moves again.
	log := newBoundedLog(stderr, 512)
	w := &worker{s: s, gen: gen, clock: bootclock.System(), out: log, warned: map[string]time.Time{},
		netbirdCh: make(chan Msg, 64)}
	w.send = &workerSender{w: os.NewFile(3, "to-supervisor"), gen: gen}
	w.ctx, w.cancel = context.WithCancel(context.Background())
	defer w.cancel()
	go w.readSupervisor(os.NewFile(4, "from-supervisor"))
	code := w.run()
	// The last lines, a failure's reason among them, get a moment to land; a
	// stuck sink costs this and nothing more, well inside the 6 seconds the
	// supervisor's stop sequence gives the worker.
	log.Flush(300 * time.Millisecond)
	return code
}

// libLogf is the log sink of the routing libraries, whose lines already begin
// "molebridge: ": one prefix per line, the program's.
func (w *worker) libLogf(format string, a ...any) {
	w.logf(strings.TrimPrefix(format, "molebridge: "), a...)
}

// fatal ends the worker with a failure: the line is printed, the worker stops
// and exits non-zero, and the supervisor does the rest.
func (w *worker) fatal(msg string) {
	w.fatalOnce.Do(func() {
		w.fatalMsg.Store(&msg)
		w.logf("%s", msg)
		w.cancel()
	})
}

// logf writes one line. In the running worker w.out is a boundedLog, so this
// never waits on the log sink.
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
	if s.HasContract() {
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
		Logf: w.libLogf})
	w.mut.Start()

	w.loops = map[string]loopSource{LoopMutator: {w.mut.Progress, MutatorBound}}
	if s.HasContract() {
		var links []string
		for _, l := range []string{s.Routing.ExitIf, s.Routing.OverlayIf, s.Routing.HostIf} {
			if l != "" {
				links = append(links, l)
			}
		}
		wt := watch.New(watch.Config{Source: sub, Mutator: w.mut, Interval: s.Interval, Clock: w.clock,
			Tables: spec.Interest().Tables, Links: links, Logf: w.libLogf})
		w.watcher = wt
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

	if s.Routing.IsNativeSidecar() {
		// Whatever an earlier run left on the tmpfs says nothing about this
		// run's guards (Guarded also refuses another namespace's).
		_ = os.Remove(s.PathGuarded())
		// The firewall goes in before the rules: until the contract holds it
		// alone keeps the applications sharing this namespace off the host
		// path. A namespace that outlived an earlier run (a pod's, across a
		// container restart) has the old table replaced in one transaction.
		if err := w.sys.InstallSidecarFirewall(w.ctx); err != nil {
			if w.ctx.Err() != nil {
				return 0
			}
			w.logf("%v", err)
			w.logf("the sidecar firewall could not be installed; no tunnel was started")
			return 1
		}
		w.firewallOK.Store(true)
		w.logf("the sidecar firewall is installed")
		w.warnStrictReversePath()
	}
	if err := w.mut.Install(w.ctx); err != nil {
		if w.ctx.Err() != nil {
			return 0
		}
		w.logf("%v", err)
		w.logf("the routing contract could not be installed; no tunnel was started")
		return 1
	}
	if s.HasContract() {
		w.logf("rules installed; the exit table holds its unreachable fallback")
	}
	if s.Routing.IsNativeSidecar() {
		w.writeGuarded()
	}

	pipe, err := newPipeline(pipelineEnv{S: s, System: w.sys, Publish: w.publish, OwnerCheck: w.ownerCheckFor(),
		Log: func(l string) { w.logf("%s", l) }, RoutingActivity: w.routingActivityFor()})
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
	if s.NativeTunnel() {
		spawn(func() { w.tunnelLoop(tun, obs) })
	} else {
		w.tunnelUp.Store(true)
	}
	if s.Routing.IsNativeSidecar() {
		spawn(w.firewallLoop)
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
	// The worker holds nothing that needs tearing down (the rules and the
	// fallback stay by design), so a stop never waits on a wedged owner or a
	// blocked loop: a second to wind down, then the process ends.
	finished := make(chan struct{})
	go func() {
		wg.Wait()
		w.mut.Close()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(time.Second):
	}
	if w.drillStop != nil {
		w.drillStop()
	}
	if w.fatalMsg.Load() != nil {
		return 1
	}
	return 0
}

func (w *worker) ownerCheckFor() func() validate.Obj {
	if w.s.Native() {
		return w.ownerCheck
	}
	return nil
}

// routingActivityFor is the records' routing_activity member, nil for an exit
// without a routing contract (a gluetun sidecar), whose owner and watcher
// have nothing to count.
func (w *worker) routingActivityFor() func() validate.Obj {
	if w.watcher == nil {
		return nil
	}
	return func() validate.Obj {
		m, e := w.mut.Stats(), w.watcher.Stats()
		r := RoutingActivity{Repairs: m.Repairs, Events: e.Events, Relevant: e.Relevant, Lost: e.Overruns, Periodic: e.Periodic}
		if m.HasLast {
			// The boot clock's second, placed on the wall clock now.
			ago := w.clock() - time.Duration(m.LastRepair)*time.Second
			r.LastRepair = time.Now().Add(-ago)
		}
		return r.JSONObject()
	}
}

// publish hands a record to the supervisor.
func (w *worker) publish(r validate.ObjectMarshaler) error {
	return w.send.send(Msg{Type: TypeStatus, Rec: r})
}

func (w *worker) tunnelParams() tunnel.Params {
	p := tunnel.Params{ExitIf: w.s.Routing.ExitIf, Conf: w.s.Conf}
	if w.s.Routing.IsNativeSidecar() {
		// Rule 93 sends the device's own UDP to the host by this mark;
		// everything else the namespace sends goes to the exit table.
		p.FirewallMark = w.s.Routing.TunnelMark()
	}
	return p
}

// writeGuarded renews the native sidecar's guard heartbeat while the firewall
// read back as installed and the routing contract holds: what `molebridge
// health --guarded` reads, so a Kubernetes startup probe can hold the
// applications back until both guards are in place, before the tunnel is up.
func (w *worker) writeGuarded() {
	if !w.firewallOK.Load() || !w.mut.LastPass().ContractHolds {
		return
	}
	if err := writeGuarded(w.s.PathGuarded(), w.clock()); err != nil {
		w.warnEvery("guarded", time.Minute, "cannot write the guard heartbeat: %v", err)
	}
}

// warnStrictReversePath says when the host interface filters reverse paths
// strictly. The kernel validates a packet's source with a lookup from
// loopback, which the sidecar's iif lo rules send to the tunnel: replies to the
// exit's own traffic and the tunnel's UDP arriving on HOST_IF then fail strict
// validation and are dropped, and the tunnel never comes up. Loose (2) or off
// (0) is fine. A container usually cannot write the sysctl itself.
func (w *worker) warnStrictReversePath() {
	host := w.s.Routing.HostIf
	read := func(name string) int {
		b, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + name + "/rp_filter")
		if err != nil {
			return -1
		}
		n, err := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil {
			return -1
		}
		return n
	}
	// The kernel uses the larger of the two values.
	if max(read("all"), read(host)) == 1 {
		w.logf("warning: net.ipv4.conf.%s.rp_filter is strict (1): replies arriving on %s are dropped and the tunnel cannot come up; set rp_filter to 0 or 2 for this namespace (docs/native-sidecar.md)", host, host)
	}
}

// firewallLoop keeps a native sidecar's firewall exactly as installed: it is
// read back every FirewallCheckInterval and, if anything differs, replaced in
// one transaction. nftables announces no change the worker subscribes to, so
// this is a poll, not a watch.
func (w *worker) firewallLoop() {
	for {
		if !sleepCtx(w.ctx, FirewallCheckInterval) {
			return
		}
		ok, reason, err := w.sys.SidecarFirewall(w.ctx)
		switch {
		case w.ctx.Err() != nil:
			return
		case err != nil:
			w.firewallOK.Store(false)
			w.warnEvery("firewall-read", time.Minute, "the sidecar firewall cannot be read: %v", err)
		case ok:
			w.firewallOK.Store(true)
			w.writeGuarded()
		default:
			w.firewallOK.Store(false)
			if err := w.sys.InstallSidecarFirewall(w.ctx); err != nil {
				w.warnEvery("firewall-install", time.Minute, "the sidecar firewall was not as installed (%s) and could not be replaced: %v", reason, err)
				continue
			}
			w.logf("the sidecar firewall was not as installed (%s); reinstalled", reason)
			if ok, _, err := w.sys.SidecarFirewall(w.ctx); err == nil && ok {
				w.firewallOK.Store(true)
			}
		}
	}
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
			err := w.mut.Do(w.ctx, "bring the tunnel up", func(tx *mutator.Tx) error { return tun.UpContext(tx.Context(), w.tunnelParams()) })
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
		if !sleepCtx(w.ctx, 2*time.Second) {
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

// netbirdLoop handles the supervisor's reports about NetBird. Every report
// names its launch, and a report of a launch older than the current one is
// ignored before it touches any state.
func (w *worker) netbirdLoop() {
	for {
		select {
		case <-w.ctx.Done():
			return
		case m := <-w.netbirdCh:
			if m.State == NBLaunching {
				if int64(m.Launch) < w.launch.Load() {
					continue
				}
				w.launch.Store(int64(m.Launch))
			} else if int64(m.Launch) != w.launch.Load() {
				continue
			}
			if w.monitors != nil {
				w.monitors.event(m)
			}
			switch m.State {
			case NBStarted:
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
				w.pipeOn.Store(true)
			case NBStopped, NBFailed:
				w.nbRunning.Store(false)
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
				w.warnEvery("tick", 30*time.Second, "applier: control cycle failed: %v", err)
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
		if why := w.notOperational(); why != "" {
			w.warnEvery("operational:"+why, time.Minute, "not operational: %s", why)
		} else {
			if err := writeHeartbeat(w.s.PathHeartbeat(), w.clock()); err != nil {
				w.warnEvery("heartbeat", time.Minute, "cannot write the heartbeat: %v", err)
			}
		}
		if !sleepCtx(w.ctx, TickInterval) {
			return
		}
	}
}

// notOperational is why the heartbeat is not written, "" when the exit is
// operational.
func (w *worker) notOperational() string {
	switch {
	case w.blocked.Load():
		return "the NetBird profile check refused"
	case !w.pipeOn.Load():
		return "NetBird has not been started yet"
	}
	if w.s.Overlay() {
		res := w.mut.LastPass()
		holds := res.ContractHolds
		if w.s.Native() {
			holds = res.Verified && w.tunnelUp.Load()
		}
		switch {
		case !holds:
			return "the routing contract is not verified"
		case !w.nbRunning.Load():
			return "NetBird is not running"
		}
	}
	if w.s.Routing.IsNativeSidecar() {
		res := w.mut.LastPass()
		switch {
		case !res.Verified || !w.tunnelUp.Load():
			return "the routing contract is not verified"
		case !w.firewallOK.Load():
			return "the sidecar firewall is not as installed"
		}
	}
	if !w.pipe.Healthy(w.ctx) {
		return "the pipeline reports the namespace is not intact (" + w.diagnose() + ")"
	}
	return ""
}

// routingDiagnosis names each family whose routing is not intact.
func (w *worker) routingDiagnosis(ctx context.Context) []string {
	var parts []string
	addrs, err := w.sys.TunnelAddresses(ctx)
	if err != nil {
		parts = append(parts, "the tunnel addresses cannot be read")
	}
	for _, fam := range []int{4, 6} {
		var addr string
		for _, a := range addrs {
			if (fam == 4) == a.Is4() {
				addr = a.String()
			}
		}
		if p, _, err := w.sys.RoutingStatus(ctx, fam, addr); err != nil || !p {
			parts = append(parts, fmt.Sprintf("IPv%d routing is not intact", fam))
		}
	}
	return parts
}

// diagnose names what an unhealthy pipeline is missing, from the same reads
// the pipeline makes; nothing here is secret.
func (w *worker) diagnose() string {
	var parts []string
	ctx := w.ctx
	if r, ok := readResult(w.s.PathResult()); !ok {
		parts = append(parts, "no readable status record")
	} else if st, _ := r["status"].(string); st != "ok" && st != "failed" {
		parts = append(parts, "the last record is not a completed check")
	}
	if w.s.Routing.IsGluetunSidecar() {
		if keys, err := w.sys.Peers(ctx); err != nil || len(keys) != 1 {
			parts = append(parts, "not exactly one tunnel peer")
		}
		return strings.Join(parts, "; ")
	}
	if w.s.Routing.IsNativeSidecar() {
		if _, err := w.sys.Peers(ctx); err != nil {
			parts = append(parts, "the tunnel interface has no WireGuard device")
		}
		parts = append(parts, w.routingDiagnosis(ctx)...)
		if ok, _, err := w.sys.SidecarFirewall(ctx); err != nil || !ok {
			parts = append(parts, "the sidecar firewall is not as installed")
		}
		if len(parts) == 0 {
			parts = append(parts, "the record may be stale")
		}
		return strings.Join(parts, "; ")
	}
	if _, err := w.sys.Peers(ctx); err != nil {
		parts = append(parts, "the tunnel interface has no WireGuard device")
	}
	parts = append(parts, w.routingDiagnosis(ctx)...)
	if v, err := w.sys.ReadSysctl(ctx, contract.ReturnPathSysctl); err != nil || !contract.ReturnPathEnabled(v) {
		parts = append(parts, "icmp_errors_use_inbound_ifaddr is not 1")
	}
	if ok, err := w.sys.OverlayKernelWireGuard(ctx); err != nil || !ok {
		parts = append(parts, "the overlay interface is not kernel WireGuard")
	}
	if ok, err := w.sys.NetbirdFirewallPresent(ctx); err != nil || !ok {
		parts = append(parts, "NetBird's kernel firewall is not present")
	}
	if len(parts) == 0 {
		parts = append(parts, "the record may be stale")
	}
	return strings.Join(parts, "; ")
}
