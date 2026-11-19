//go:build linux

package exit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/nbprofile"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/tunnel"
)

// nbWorker is the worker's side of NetBird, the overlay exit's way in
// (workerWayIn, wayin_worker_linux.go): it decides when the supervisor may run
// NetBird (readinessLoop), checks NetBird's profile before every start and
// after `netbird up`, follows the supervisor's reports about each launch
// (netbirdLoop), runs the gluetun backend's NetBird monitors, and holds the
// control cycle back until NetBird runs, publishing why while it is held.
type nbWorker struct {
	s *Settings
	h workerWayInHost

	nbRunning atomic.Bool
	blocked   atomic.Bool
	// refusal is the profile check's refusal that set blocked.
	refusal atomic.Pointer[string]
	// held is why the readiness loop holds NetBird back while the contract
	// holds (a missing precondition), nil once it starts NetBird.
	held      atomic.Pointer[string]
	pipeOn    atomic.Bool
	launch    atomic.Int64
	netbirdCh chan Msg

	monitors *gluetunMonitors
}

func newNetBirdWorker(s *Settings, h workerWayInHost) *nbWorker {
	return &nbWorker{s: s, h: h, netbirdCh: make(chan Msg, 64)}
}

// Announce warns when a gluetun overlay lacks the return-path sysctl.
func (n *nbWorker) Announce() {
	if !n.s.Native() && returnPathPrecondition() != nil {
		// gluetun's own rule 101 takes the exit's ICMP errors into the
		// tunnel, sourced from its address, whatever the sysctl says, and
		// rule 104 refuses them without it: only path MTU discovery suffers.
		// A native overlay holds NetBird instead (readinessLoop).
		n.h.logf("warning: net.ipv4.icmp_errors_use_inbound_ifaddr is not 1; set it in compose.yaml or IPv4 path MTU discovery through the exit will fail")
	}
}

// Start begins the gluetun backend's NetBird monitors.
func (n *nbWorker) Start(tun *tunnel.Manager) error {
	if n.s.Routing.IsGluetun() {
		return n.startGluetunMonitors(tun)
	}
	return nil
}

// Loops are the readiness loop and the report loop.
func (n *nbWorker) Loops() []func() { return []func(){n.readinessLoop, n.netbirdLoop} }

// Report queues a report about NetBird for netbirdLoop; one that finds the
// queue full is dropped.
func (n *nbWorker) Report(m Msg) {
	select {
	case n.netbirdCh <- m:
	default:
	}
}

// Cycle runs the control cycle once NetBird is up and its profile verified.
// Once the profile check after `netbird up` has refused, the cycle never runs
// again in this generation and the refusal is published instead; while
// NetBird is held back before its first start (hold), why is published.
func (n *nbWorker) Cycle() bool {
	switch {
	case n.blocked.Load():
		n.publishHeld(n.refusal.Load())
	case !n.pipeOn.Load() && n.held.Load() != nil:
		n.publishHeld(n.held.Load())
	case n.pipeOn.Load():
		return true
	}
	return false
}

// NotOperational: the profile check refused, NetBird never started, the
// routing contract does not verify, or NetBird is not running.
func (n *nbWorker) NotOperational() string {
	switch {
	case n.blocked.Load():
		return "the NetBird profile check refused"
	case !n.pipeOn.Load():
		return "NetBird has not been started yet"
	}
	res := n.h.lastPass()
	holds := res.ContractHolds
	if n.s.Native() {
		holds = res.Verified && n.h.tunnelUp()
	}
	switch {
	case !holds:
		return "the routing contract is not verified"
	case !n.nbRunning.Load():
		return "NetBird is not running"
	}
	return ""
}

// Diagnose names a NetBird that does not run kernel WireGuard on the overlay
// interface, or whose kernel firewall is missing.
func (n *nbWorker) Diagnose(ctx context.Context, sys *KernelSystem) []string {
	var parts []string
	if ok, err := sys.OverlayKernelWireGuard(ctx); err != nil || !ok {
		parts = append(parts, "the overlay interface is not kernel WireGuard")
	}
	if ok, err := sys.NetbirdFirewallPresent(ctx); err != nil || !ok {
		parts = append(parts, "NetBird's kernel firewall is not present")
	}
	return parts
}

// readinessLoop decides when the supervisor may run NetBird.
func (n *nbWorker) readinessLoop() {
	r := &readiness{grace: n.s.Grace}
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-n.h.ctx.Done():
			return
		case <-t.C:
		}
		res := n.h.lastPass()
		holds := res.ContractHolds
		if n.s.Native() {
			holds = res.Verified
		}
		switch r.step(time.Now(), holds, n.h.tunnelUp(), n.blocked.Load()) {
		case actReady:
			if n.s.Native() {
				if err := returnPathPrecondition(); err != nil {
					r.markUnready()
					n.hold(err)
					n.h.warnEvery("return-path", 30*time.Second, "NetBird is not started: %v", err)
					continue
				}
			}
			if err := n.recheckNetBird(); err != nil {
				r.markUnready()
				n.hold(err)
				n.h.warnEvery("recheck", 30*time.Second, "NetBird is not started: %v", err)
				continue
			}
			n.held.Store(nil)
			n.h.logf("ready")
			n.h.renew()
			_ = n.h.send(Msg{Type: TypeReady})
		case actUnready:
			reason := n.unreadyReason(res)
			n.h.logf("not ready: %s", reason)
			_ = n.h.send(Msg{Type: TypeUnready, Reason: reason})
		}
	}
}

func (n *nbWorker) unreadyReason(res mutator.PassResult) string {
	if n.blocked.Load() {
		return "the NetBird profile does not exclude the tunnel interface; nothing is admitted"
	}
	var parts []string
	for _, f := range []rtnl.Family{rtnl.V4, rtnl.V6} {
		for _, p := range res.Problems[f] {
			parts = append(parts, fmt.Sprintf("%s %s", f, p))
		}
	}
	msg := fmt.Sprintf("the routing contract has not held for %d seconds", int(n.s.Grace/time.Second))
	if len(parts) > 0 {
		msg += ": " + strings.Join(parts, ", ")
	}
	return msg
}

// returnPathSysctl is the file returnPathPrecondition reads (tests replace it).
var returnPathSysctl = contract.ReturnPathSysctl

// returnPathPrecondition: the kernel sources ICMP errors from the inbound
// interface's address. A native overlay exit needs it before NetBird starts:
// without it the errors the exit generates for traffic arriving from the
// tunnel (fragmentation needed toward the overlay) are sourced from the
// host's address, so rule 94 cannot match them and they leave by the host
// interface carrying the inner headers.
func returnPathPrecondition() error {
	v, err := os.ReadFile(returnPathSysctl)
	if err != nil || !contract.ReturnPathEnabled(string(v)) {
		return errors.New("net.ipv4.icmp_errors_use_inbound_ifaddr is not 1; set it on the exit service (compose.yaml sets it), or the exit's ICMP errors for tunnel traffic would leave by the host interface")
	}
	return nil
}

// recheckNetBird repeats the checks that run before the daemon starts
// (D25): NetBird's settings, the stored profile the daemon will load and its
// interface blacklist.
func (n *nbWorker) recheckNetBird() error {
	s := n.s
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
func (n *nbWorker) netbirdLoop() {
	for {
		select {
		case <-n.h.ctx.Done():
			return
		case m := <-n.netbirdCh:
			if m.State == NBLaunching {
				if int64(m.Launch) < n.launch.Load() {
					continue
				}
				n.launch.Store(int64(m.Launch))
			} else if int64(m.Launch) != n.launch.Load() {
				continue
			}
			if n.monitors != nil {
				n.monitors.event(m)
			}
			switch m.State {
			case NBStarted:
				// `netbird up` in daemon mode can return before any
				// configuration change applies: read the profile again and
				// admit nothing unless the tunnel is excluded.
				if err := nbprofile.CheckBlacklistAfterUp(n.s.NBPaths, n.s.Routing.OverlayIf, n.s.Routing.ExitIf); err != nil {
					n.h.logf("%v", err)
					refusal := err.Error()
					n.refusal.Store(&refusal)
					n.blocked.Store(true)
					n.nbRunning.Store(false)
					_ = n.h.send(Msg{Type: TypeUnready, Reason: truncate(err.Error(), 900)})
					continue
				}
				n.nbRunning.Store(true)
				n.pipeOn.Store(true)
			case NBStopped, NBFailed:
				n.nbRunning.Store(false)
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

// hold records why the readiness loop does not start NetBird, as the log
// line says it: "NetBird is not started: <reason>".
func (n *nbWorker) hold(err error) {
	why := "NetBird is not started: " + err.Error()
	n.held.Store(&why)
}

// publishHeld hands the supervisor the failed record that names why NetBird
// does not run.
func (n *nbWorker) publishHeld(why *string) {
	if why == nil {
		return
	}
	if err := n.h.send(Msg{Type: TypeStatus, Record: NetBirdHeldRecord(n.s, time.Now(), *why)}); err != nil {
		n.h.warnEvery("held", time.Minute, "cannot publish why NetBird does not run: %v", err)
	}
}
