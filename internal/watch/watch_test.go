package watch

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/rtnl"
)

type script struct {
	mu        sync.Mutex
	steps     []func() ([]rtnl.Event, error)
	deadlines []time.Time
	closed    atomic.Bool
	idle      chan struct{}
}

func newScript() *script { return &script{idle: make(chan struct{})} }

func (s *script) push(f func() ([]rtnl.Event, error)) {
	s.mu.Lock()
	s.steps = append(s.steps, f)
	s.mu.Unlock()
}

func (s *script) Next(deadline time.Time) ([]rtnl.Event, error) {
	s.mu.Lock()
	s.deadlines = append(s.deadlines, deadline)
	var f func() ([]rtnl.Event, error)
	if len(s.steps) > 0 {
		f, s.steps = s.steps[0], s.steps[1:]
	}
	s.mu.Unlock()
	if f != nil {
		return f()
	}
	if s.closed.Load() {
		return nil, errors.New("closed")
	}
	// Idle: wait out most of the deadline, like a socket with a read deadline.
	d := time.Until(deadline)
	if d > 5*time.Millisecond {
		d = 5 * time.Millisecond
	}
	time.Sleep(d)
	return nil, os.ErrDeadlineExceeded
}

func (s *script) Close() error { s.closed.Store(true); return nil }

type counter struct {
	mu      sync.Mutex
	reasons []string
}

func (c *counter) Reconcile(reason string) {
	c.mu.Lock()
	c.reasons = append(c.reasons, reason)
	c.mu.Unlock()
}

func (c *counter) get() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.reasons...)
}

func run(t *testing.T, w *Watcher) (stop func() error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	return func() error { cancel(); return <-done }
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestARelevantEventAsksForAPass(t *testing.T) {
	s, c := newScript(), &counter{}
	w := New(Config{Source: s, Mutator: c, Interval: time.Hour, IdleStep: 20 * time.Millisecond, Tables: []uint32{51821}, Links: []string{"mullvad"}})
	s.push(func() ([]rtnl.Event, error) { return []rtnl.Event{{Kind: rtnl.EventRule, Family: rtnl.V4}}, nil })
	stop := run(t, w)
	waitFor(t, "a pass", func() bool { return len(c.get()) == 1 })
	if c.get()[0] != "event" {
		t.Fatal(c.get())
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

func TestIrrelevantEventsAreIgnored(t *testing.T) {
	s, c := newScript(), &counter{}
	w := New(Config{Source: s, Mutator: c, Interval: time.Hour, IdleStep: 20 * time.Millisecond, Tables: []uint32{51821}, Links: []string{"mullvad"}})
	s.push(func() ([]rtnl.Event, error) {
		return []rtnl.Event{
			{Kind: rtnl.EventRoute, Table: 254, Family: rtnl.V4},
			{Kind: rtnl.EventLink, Name: "veth123"},
			{Kind: rtnl.EventRoute, Table: 7120},
		}, nil
	})
	stop := run(t, w)
	waitFor(t, "the events", func() bool { return w.Stats().Events == 3 })
	time.Sleep(30 * time.Millisecond)
	if len(c.get()) != 0 {
		t.Fatalf("passes %v", c.get())
	}
	_ = stop()
	for _, e := range []rtnl.Event{
		{Kind: rtnl.EventRoute, Table: 51821}, {Kind: rtnl.EventLink, Name: "mullvad"}, {Kind: rtnl.EventAddr},
		{Kind: rtnl.EventRule}, {Kind: rtnl.EventLink}, {Kind: rtnl.EventLink, Name: "veth1", Err: errors.New("undecodable")},
	} {
		if !w.Relevant(e) {
			t.Errorf("%+v should matter", e)
		}
	}
}

func TestOverrunRunsAFullPassAtOnce(t *testing.T) {
	s, c := newScript(), &counter{}
	var logs atomic.Int32
	w := New(Config{Source: s, Mutator: c, Interval: time.Hour, IdleStep: 20 * time.Millisecond, Logf: func(string, ...any) { logs.Add(1) }})
	s.push(func() ([]rtnl.Event, error) { return nil, rtnl.ErrOverrun })
	stop := run(t, w)
	waitFor(t, "a pass", func() bool { return len(c.get()) == 1 })
	if c.get()[0] != "events lost" || w.Stats().Overruns != 1 || logs.Load() != 1 {
		t.Fatalf("%v %+v", c.get(), w.Stats())
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

func TestAFullPassEveryIntervalWhenNothingHappens(t *testing.T) {
	var now atomic.Int64
	s, c := newScript(), &counter{}
	w := New(Config{Source: s, Mutator: c, Interval: 30 * time.Second, IdleStep: 10 * time.Millisecond,
		Clock: func() time.Duration { return time.Duration(now.Load()) }})
	stop := run(t, w)
	time.Sleep(40 * time.Millisecond)
	if len(c.get()) != 0 {
		t.Fatalf("a pass before the interval: %v", c.get())
	}
	now.Store(int64(31 * time.Second))
	waitFor(t, "the periodic pass", func() bool { return len(c.get()) == 1 })
	if c.get()[0] != "periodic" {
		t.Fatal(c.get())
	}
	// The next one is an interval later, not at once.
	time.Sleep(40 * time.Millisecond)
	if len(c.get()) != 1 {
		t.Fatalf("%v", c.get())
	}
	now.Store(int64(62 * time.Second))
	waitFor(t, "the second periodic pass", func() bool { return len(c.get()) == 2 })
	_ = stop()
}

func TestAnIdleWatcherStillReportsAStepAndEveryReceiveHasADeadline(t *testing.T) {
	var now atomic.Int64
	var steps []time.Duration
	var mu sync.Mutex
	s, c := newScript(), &counter{}
	w := New(Config{Source: s, Mutator: c, Interval: time.Hour, IdleStep: 15 * time.Millisecond,
		Clock:      func() time.Duration { return time.Duration(now.Load()) },
		OnProgress: func(d time.Duration) { mu.Lock(); steps = append(steps, d); mu.Unlock() }})
	stop := run(t, w)
	now.Store(int64(7 * time.Second))
	waitFor(t, "a step on the new time", func() bool { return w.Progress() == 7*time.Second })
	waitFor(t, "three steps", func() bool { mu.Lock(); defer mu.Unlock(); return len(steps) >= 3 })
	_ = stop()
	mu.Lock()
	if len(steps) < 2 {
		t.Errorf("steps %v", steps)
	}
	mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, d := range s.deadlines {
		if d.IsZero() {
			t.Fatalf("receive %d had no deadline", i)
		}
	}
	if w.Bound() != 15*time.Millisecond {
		t.Errorf("bound %v", w.Bound())
	}
}

func TestReceiveDeadlineNeverExceedsTheNextFullPass(t *testing.T) {
	var now atomic.Int64
	s, c := newScript(), &counter{}
	w := New(Config{Source: s, Mutator: c, Interval: 4 * time.Millisecond, IdleStep: time.Hour,
		Clock: func() time.Duration { return time.Duration(now.Load()) }})
	stop := run(t, w)
	waitFor(t, "a deadline", func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.deadlines) > 0 })
	s.mu.Lock()
	if time.Until(s.deadlines[0]) > time.Second {
		t.Errorf("an hour-long receive with a 4 ms interval: %v", time.Until(s.deadlines[0]))
	}
	s.mu.Unlock()
	_ = stop()
}

func TestASocketFailureEndsTheLoop(t *testing.T) {
	s, c := newScript(), &counter{}
	w := New(Config{Source: s, Mutator: c, IdleStep: 10 * time.Millisecond})
	s.push(func() ([]rtnl.Event, error) { return nil, errors.New("netlink socket failed") })
	err := w.Run(context.Background())
	if err == nil || !errors.Is(err, err) {
		t.Fatal(err)
	}
	// Cancelling is not an error.
	s2 := newScript()
	w = New(Config{Source: s2, Mutator: c, IdleStep: 10 * time.Millisecond})
	stop := run(t, w)
	time.Sleep(20 * time.Millisecond)
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	if !s2.closed.Load() {
		t.Error("the source was not closed to unblock the receive")
	}
}
