package exit

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// The supervisor's deadline path (lease check, signals to NetBird and the
// worker, KILL, reaping) must never wait on a file or a log sink: a stalled
// state volume or a blocked stderr would otherwise leave NetBird running past
// its lease. Everything that does I/O for the supervisor goes through the two
// types below, each on goroutines of its own with a bound on what it holds.
// The worker writes its log through a boundedLog too, so a blocked stderr
// can't stall its supervised loops into a lapsed lease either.

// boundedLog is an io.Writer that never blocks. Lines go through a bounded
// queue to the real sink on a goroutine of their own; when the queue is full
// (the sink is slow or stuck) the line is dropped and counted, and the count is
// reported as a line of its own once the sink moves again.
type boundedLog struct {
	w       io.Writer
	q       chan []byte
	dropped atomic.Int64
	pending atomic.Int64
}

func newBoundedLog(w io.Writer, depth int) *boundedLog {
	b := &boundedLog{w: w, q: make(chan []byte, depth)}
	go b.run()
	return b
}

// Write queues a copy of p. It always reports success.
func (b *boundedLog) Write(p []byte) (int, error) {
	line := append([]byte(nil), p...)
	b.pending.Add(1)
	select {
	case b.q <- line:
	default:
		b.pending.Add(-1)
		b.dropped.Add(1)
	}
	return len(p), nil
}

func (b *boundedLog) run() {
	for line := range b.q {
		if n := b.dropped.Swap(0); n > 0 {
			_, _ = fmt.Fprintf(b.w, "%slog: %d lines were dropped while the log sink was slow\n", prefix, n)
		}
		_, _ = b.w.Write(line)
		b.pending.Add(-1)
	}
}

// Dropped is the number of lines dropped and not yet reported.
func (b *boundedLog) Dropped() int64 { return b.dropped.Load() }

// Flush waits up to d for the queue to reach the sink. A stuck sink costs d
// and nothing more.
func (b *boundedLog) Flush(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for b.pending.Load() > 0 {
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
	return true
}

// coalescer runs jobs on one goroutine, newest first: a job submitted while
// another runs (or waits) replaces the one waiting, so a stalled write never
// builds a backlog, and only the latest state is written when it moves again.
// A final job is never replaced and shuts the door behind it: later
// submissions are ignored.
type coalescer struct {
	mu      sync.Mutex
	pending func()
	final   bool
	running bool
	wake    chan struct{}
}

func newCoalescer() *coalescer {
	c := &coalescer{wake: make(chan struct{}, 1)}
	go c.loop()
	return c
}

// Submit queues a job; it never blocks.
func (c *coalescer) Submit(job func(), final bool) {
	c.mu.Lock()
	if c.final {
		c.mu.Unlock()
		return
	}
	c.pending, c.final = job, final
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *coalescer) loop() {
	for range c.wake {
		for {
			c.mu.Lock()
			job := c.pending
			c.pending = nil
			c.running = job != nil
			c.mu.Unlock()
			if job == nil {
				break
			}
			job()
			c.mu.Lock()
			c.running = false
			c.mu.Unlock()
		}
	}
}

// Wait waits up to d for nothing to be queued or running.
func (c *coalescer) Wait(d time.Duration) bool {
	deadline := time.Now().Add(d)
	for {
		c.mu.Lock()
		idle := c.pending == nil && !c.running
		c.mu.Unlock()
		if idle {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
}
