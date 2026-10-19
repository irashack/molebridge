// Package watch is the exit's event loop: it reads rtnetlink multicast
// notifications and asks the mutation owner for a repair pass on any change
// that could matter, on a full pass every ROUTING_RECONCILE_INTERVAL as the
// fallback, and at once when the kernel says events were lost (ENOBUFS).
//
// The watcher decides nothing about the kernel and changes nothing. A repair
// pass is an operation of the mutation owner (internal/mutator), which takes
// its own fresh snapshot and compares it with the expected state at the
// moment it runs; asking for one is cheap and requests made while one is
// pending are one request. That is what lets the watcher stay trivially
// correct: any event, however stale, only ever results in a look at the
// current state.
//
// Every receive carries a deadline, so an idle watcher still reports a step
// every IdleStep (2 seconds); Progress is that report on the boot clock, for
// the supervisor's lease.
package watch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/rtnl"
)

// Source delivers notifications; *rtnl.Subscriber is the real one.
type Source interface {
	// Next waits for notifications until the deadline. It returns
	// rtnl.ErrOverrun when events were lost and an error satisfying
	// rtnl.Timeout when the deadline passes with nothing to read.
	Next(deadline time.Time) ([]rtnl.Event, error)
	Close() error
}

// Reconciler asks for a repair pass; *mutator.Mutator is the real one.
type Reconciler interface {
	Reconcile(reason string)
}

// Defaults.
const (
	DefaultIdleStep = 2 * time.Second
	DefaultInterval = 30 * time.Second
)

// Config configures a Watcher.
type Config struct {
	Source  Source
	Mutator Reconciler
	// Interval is the period of the full pass that backs the events.
	Interval time.Duration
	// IdleStep bounds each receive.
	IdleStep time.Duration
	Clock    bootclock.Clock
	// Tables are the routing tables whose route events matter; none means all.
	Tables []uint32
	// Links are the interface names whose link events matter (the tunnel,
	// the overlay, the host interface); none means all.
	Links []string
	// OnProgress is called after each step with its boot-clock time.
	OnProgress func(time.Duration)
	// Logf receives notable events (lost events); it must not block.
	Logf func(format string, args ...any)
}

// Stats count what the watcher has seen.
type Stats struct {
	Events, Relevant, Overruns, Periodic uint64
}

// Watcher is the event loop.
type Watcher struct {
	c        Config
	progress atomic.Int64
	events   atomic.Uint64
	relevant atomic.Uint64
	overruns atomic.Uint64
	periodic atomic.Uint64
}

// New creates a watcher; Run drives it.
func New(c Config) *Watcher {
	if c.IdleStep <= 0 {
		c.IdleStep = DefaultIdleStep
	}
	if c.Interval <= 0 {
		c.Interval = DefaultInterval
	}
	if c.Clock == nil {
		c.Clock = bootclock.System()
	}
	if c.Logf == nil {
		c.Logf = func(string, ...any) {}
	}
	w := &Watcher{c: c}
	w.progress.Store(int64(c.Clock()))
	return w
}

// Progress is the boot-clock time of the last step: an event batch, an overrun,
// or an idle timeout.
func (w *Watcher) Progress() time.Duration { return time.Duration(w.progress.Load()) }

// Bound is how stale Progress may be before the watcher counts as stalled:
// one idle step, and a little for scheduling.
func (w *Watcher) Bound() time.Duration { return w.c.IdleStep }

// Stats returns the counters.
func (w *Watcher) Stats() Stats {
	return Stats{Events: w.events.Load(), Relevant: w.relevant.Load(), Overruns: w.overruns.Load(), Periodic: w.periodic.Load()}
}

func (w *Watcher) step() {
	now := w.c.Clock()
	w.progress.Store(int64(now))
	if w.c.OnProgress != nil {
		w.c.OnProgress(now)
	}
}

// Relevant reports whether a notification could change the contract's
// standing: any rule change, a route change in a table of interest, a link
// change of an interface of interest, any address change. A notification that
// could not be decoded counts, because it is a change of something.
func (w *Watcher) Relevant(e rtnl.Event) bool {
	if e.Err != nil {
		return true
	}
	switch e.Kind {
	case rtnl.EventRule, rtnl.EventAddr:
		return true
	case rtnl.EventRoute:
		if len(w.c.Tables) == 0 {
			return true
		}
		for _, t := range w.c.Tables {
			if t == e.Table {
				return true
			}
		}
		return false
	case rtnl.EventLink:
		if len(w.c.Links) == 0 || e.Name == "" {
			return true
		}
		for _, n := range w.c.Links {
			if n == e.Name {
				return true
			}
		}
		return false
	}
	return true
}

// Run reads notifications until ctx ends (it then closes the source and
// returns nil) or the socket fails (it returns the error, and the caller treats
// the exit as unwatched: the supervisor's lease lapses because no more steps
// are reported).
func (w *Watcher) Run(ctx context.Context) error {
	stopped, closed := make(chan struct{}), make(chan struct{})
	defer close(stopped)
	go func() {
		select {
		case <-ctx.Done():
			// Unblock a pending receive.
			_ = w.c.Source.Close()
			close(closed)
		case <-stopped:
		}
	}()
	// cancelled waits for the close, so a cancellation seen between receives
	// still closes the source: stopped is closed only after this returns.
	cancelled := func() error {
		<-closed
		return nil
	}
	nextFull := w.c.Clock() + w.c.Interval
	var lost overrunLog
	for {
		if ctx.Err() != nil {
			return cancelled()
		}
		wait := w.c.IdleStep
		if left := nextFull - w.c.Clock(); left < wait {
			wait = left
		}
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		events, err := w.c.Source.Next(time.Now().Add(wait))
		switch {
		case err == nil:
			relevant := false
			for _, e := range events {
				w.events.Add(1)
				if w.Relevant(e) {
					relevant = true
					w.relevant.Add(1)
				}
			}
			if relevant {
				w.c.Mutator.Reconcile("event")
			}
		case errors.Is(err, rtnl.ErrOverrun):
			// Events were lost: whatever they were, look at everything now.
			w.overruns.Add(1)
			lost.unlogged++
			if lost.due(w.c.Clock()) {
				if lost.unlogged == 1 {
					w.c.Logf("molebridge: netlink events were lost; running a full pass")
				} else {
					w.c.Logf("molebridge: netlink events were lost; running a full pass (%s since the last line)", times(lost.unlogged))
				}
				lost.logged(w.c.Clock())
			}
			w.c.Mutator.Reconcile("events lost")
		case errors.Is(err, os.ErrDeadlineExceeded) || rtnl.Timeout(err):
			// Idle: nothing to read within the step.
		default:
			if ctx.Err() != nil {
				return cancelled()
			}
			return fmt.Errorf("watch: reading rtnetlink events: %w", err)
		}
		if now := w.c.Clock(); now >= nextFull {
			w.periodic.Add(1)
			w.c.Mutator.Reconcile("periodic")
			nextFull = now + w.c.Interval
		}
		if now := w.c.Clock(); lost.unlogged > 0 && lost.due(now) {
			// Overruns that came after the last line, and then stopped.
			w.c.Logf("molebridge: netlink events were lost again since the last line (%s); each ran a full pass", times(lost.unlogged))
			lost.logged(now)
		}
		w.step()
	}
}

// OverrunRelog is the least time between two lines about lost events: under
// a flood the kernel can report an overrun on every receive, and each one
// already runs a full pass. Overruns in between are counted into the next
// line.
const OverrunRelog = time.Minute

// overrunLog paces the lines about lost events (OverrunRelog).
type overrunLog struct {
	unlogged int
	last     time.Duration
	ever     bool
}

func (o *overrunLog) due(now time.Duration) bool { return !o.ever || now-o.last >= OverrunRelog }

func (o *overrunLog) logged(now time.Duration) {
	o.unlogged, o.last, o.ever = 0, now, true
}

func times(n int) string {
	if n == 1 {
		return "1 time"
	}
	return fmt.Sprintf("%d times", n)
}
