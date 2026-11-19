//go:build linux

package exit

import (
	"context"
	"time"

	"github.com/irashack/molebridge/internal/mutator"
	"github.com/irashack/molebridge/internal/tunnel"
)

// workerWayIn is the worker's one boundary to the exit's way in, the
// counterpart of the supervisor's wayIn (wayin.go): NetBird for an overlay
// exit (nbWorker, in netbird_worker_linux.go) and nothing for a sidecar
// (noWorkerWayIn).
//
// The worker's core keeps its start order, its loops and the lease, and asks
// the way in only at these points: Preface before its own start notices and
// Announce after them;
// Start once the kernel watcher runs, before the contract is installed;
// Loops once the pipeline exists, beside its own; Report for every message
// the supervisor sends about the way in; Cycle before each control cycle;
// NotOperational before each heartbeat; Diagnose when an overlay's pipeline
// is unhealthy. When the supervisor may run the way in, what the worker
// checks first, and the record published while it is held back are the
// implementation's.
type workerWayIn interface {
	// Preface logs what the way in says first at start, before the worker's
	// own notices.
	Preface()
	// Announce logs what the way in warns about at start.
	Announce()
	// Start begins the way in's loops that run under the lease from the start,
	// with the worker's tunnel manager; an error ends the worker.
	Start(tun *tunnel.Manager) error
	// Loops are the way in's loops, run until the worker stops.
	Loops() []func()
	// Report hands the way in a message the supervisor sent about it; it
	// never blocks.
	Report(m Msg)
	// Cycle reports whether the control cycle runs this pass. When it does
	// not, the way in has published the record that says why, if it holds
	// the exit back.
	Cycle() bool
	// NotOperational is why the way in keeps the heartbeat from being
	// written, "" when it does not.
	NotOperational() string
	// Diagnose names what of the way in an unhealthy pipeline may be
	// missing, from the same reads the pipeline makes.
	Diagnose(ctx context.Context, sys *KernelSystem) []string
}

// workerWayInHost is what a way in may use of the worker.
type workerWayInHost struct {
	ctx   context.Context
	clock func() time.Duration
	// logf and warnEvery write the worker's lines.
	logf      func(format string, a ...any)
	warnEvery func(key string, period time.Duration, format string, a ...any)
	// send writes a message to the supervisor.
	send func(m Msg) error
	// renew sends a lease renewal now, if the worker's loops are on time.
	renew func()
	// fatal ends the generation with a failure.
	fatal func(msg string)
	// addLoop supervises one more loop under the lease (Start only).
	addLoop func(name string, l loopSource)
	// lastPass is the mutation owner's last verification pass.
	lastPass func() mutator.PassResult
	// tunnelUp reports the tunnel interface up (always true where the exit
	// does not own it).
	tunnelUp func() bool
}

// noWorkerWayIn is the way in of an exit kind that runs no client (the
// sidecars): the control cycle runs from the start and nothing is held.
type noWorkerWayIn struct{}

func (noWorkerWayIn) Preface()                                         {}
func (noWorkerWayIn) Announce()                                        {}
func (noWorkerWayIn) Start(*tunnel.Manager) error                      { return nil }
func (noWorkerWayIn) Loops() []func()                                  { return nil }
func (noWorkerWayIn) Report(Msg)                                       {}
func (noWorkerWayIn) Cycle() bool                                      { return true }
func (noWorkerWayIn) NotOperational() string                           { return "" }
func (noWorkerWayIn) Diagnose(context.Context, *KernelSystem) []string { return nil }

// newWayIn is the way in this exit's kind runs; it is created before the
// worker reads the supervisor's messages.
func (w *worker) newWayIn() workerWayIn {
	if !w.s.Overlay() {
		return noWorkerWayIn{}
	}
	return newNetBirdWorker(w.s, w.host())
}

// host is the worker as a way in sees it.
func (w *worker) host() workerWayInHost {
	return workerWayInHost{ctx: w.ctx, clock: w.clock, logf: w.logf, warnEvery: w.warnEvery,
		send: w.send.send, renew: w.renewOnce, fatal: w.fatal,
		addLoop:  func(name string, l loopSource) { w.loops[name] = l },
		lastPass: func() mutator.PassResult { return w.mut.LastPass() },
		tunnelUp: w.tunnelUp.Load}
}
