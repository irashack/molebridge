package mutator

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// Kernel is what the owner needs of the kernel; *rtnl.Conn implements it.
type Kernel interface {
	Take(rtnl.Interest) (*rtnl.Snapshot, error)
	AddRule(rtnl.Rule) error
	DelRule(rtnl.Rule) error
	DelRulePriority(f rtnl.Family, priority uint32) error
	ReplaceRoute(rtnl.Route) error
	DelRoute(rtnl.Route) error
}

// timeouter is implemented by kernels whose requests can be given a deadline
// (rtnl.Conn); the owner narrows it to what is left of the operation.
type timeouter interface{ SetTimeout(time.Duration) }

// Defaults of the bounds the lease is built on.
const (
	DefaultOpTimeout = 10 * time.Second
	DefaultIdleStep  = 2 * time.Second
)

// Errors of the owner.
var (
	// ErrClosed: the owner refuses new work.
	ErrClosed = errors.New("mutator: closed")
	// ErrOpTimeout: the operation used up its budget.
	ErrOpTimeout = errors.New("mutator: operation exceeded its time budget")
)

// Options configure the owner.
type Options struct {
	Kernel Kernel
	// Spec is the initial expected state.
	Spec contract.Spec
	// Clock is the boot clock Progress is stated on.
	Clock bootclock.Clock
	// OpTimeout bounds every operation; IdleStep is the idle report period.
	OpTimeout, IdleStep time.Duration
	// GuardRepairs puts the temporary priority-80 guard in front of repairs
	// that change rules 90-97, the native backend's practice. The install
	// always uses it.
	GuardRepairs bool
	// Logf receives one line per repair; it must not block.
	Logf func(format string, args ...any)
	// OnPass is called, on the owner's goroutine, after every pass.
	OnPass func(PassResult)
	// QueueLen is the length of the operation queue (default 64).
	QueueLen int
}

// Stats are the figures the legacy owner record carries.
type Stats struct {
	// Repairs counts passes that changed the kernel.
	Repairs uint64
	// LastRepair is the boot-clock second of the last one; HasLast is false
	// before the first.
	LastRepair uint64
	HasLast    bool
}

// Mutator is the mutation owner.
type Mutator struct {
	o Options

	mu       sync.RWMutex
	spec     contract.Spec
	stats    Stats
	lastPass PassResult

	queue chan *op
	// wake carries the coalesced reconcile request.
	wake    chan struct{}
	pending atomic.Bool
	reason  atomic.Pointer[string]

	progress atomic.Int64 // boot-clock nanoseconds of the last completion
	ready    atomic.Bool

	closing  atomic.Bool
	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
	started  atomic.Bool
}

type op struct {
	name string
	fn   func(*Tx) error
	done chan error
	ctx  context.Context
}

// New creates the owner; Start runs it.
func New(o Options) *Mutator {
	if o.OpTimeout <= 0 {
		o.OpTimeout = DefaultOpTimeout
	}
	if o.IdleStep <= 0 {
		o.IdleStep = DefaultIdleStep
	}
	if o.QueueLen <= 0 {
		o.QueueLen = 64
	}
	if o.Clock == nil {
		o.Clock = bootclock.System()
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	m := &Mutator{
		o:     o,
		spec:  o.Spec.Clone(),
		queue: make(chan *op, o.QueueLen),
		wake:  make(chan struct{}, 1),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	m.progress.Store(int64(o.Clock()))
	return m
}

// Start runs the owner goroutine. It returns at once.
func (m *Mutator) Start() {
	if m.started.Swap(true) {
		return
	}
	go m.run()
}

// Close stops accepting work, lets the operation in flight finish, fails what
// is queued with ErrClosed and waits for the goroutine to end.
func (m *Mutator) Close() {
	m.closing.Store(true)
	m.stopOnce.Do(func() { close(m.stop) })
	if m.started.Load() {
		<-m.done
	}
}

// Progress is the boot-clock time of the owner's last completed operation or
// idle step, and Bound how stale it may be before the owner counts as wedged:
// one operation budget.
func (m *Mutator) Progress() time.Duration { return time.Duration(m.progress.Load()) }

// Bound is the longest the owner may go without reporting.
func (m *Mutator) Bound() time.Duration { return m.o.OpTimeout }

// Ready reports whether the last pass verified the whole contract.
func (m *Mutator) Ready() bool { return m.ready.Load() }

// LastPass returns the last pass's result.
func (m *Mutator) LastPass() PassResult {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastPass
}

// Expected returns a copy of the expected state.
func (m *Mutator) Expected() contract.Spec {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.spec.Clone()
}

// Stats returns the repair counters.
func (m *Mutator) Stats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

func (m *Mutator) step() { m.progress.Store(int64(m.o.Clock())) }

func (m *Mutator) run() {
	defer close(m.done)
	idle := time.NewTimer(m.o.IdleStep)
	defer idle.Stop()
	resetIdle := func() {
		if !idle.Stop() {
			select {
			case <-idle.C:
			default:
			}
		}
		idle.Reset(m.o.IdleStep)
	}
	for {
		select {
		case <-m.stop:
			m.drain()
			return
		case o := <-m.queue:
			if m.closing.Load() {
				o.done <- ErrClosed
				continue
			}
			m.exec(o)
			m.step()
			resetIdle()
		case <-m.wake:
			if m.closing.Load() {
				continue
			}
			if m.pending.Swap(false) {
				reason := "event"
				if r := m.reason.Load(); r != nil {
					reason = *r
				}
				m.exec(&op{name: "reconcile: " + reason, ctx: context.Background(), fn: func(tx *Tx) error {
					tx.reconcile(reason)
					return nil
				}})
			}
			m.step()
			resetIdle()
		case <-idle.C:
			if len(m.queue) == 0 && !m.pending.Load() {
				m.step()
			}
			idle.Reset(m.o.IdleStep)
		}
	}
}

func (m *Mutator) drain() {
	for {
		select {
		case o := <-m.queue:
			o.done <- ErrClosed
		default:
			return
		}
	}
}

func (m *Mutator) exec(o *op) {
	if o.ctx.Err() != nil {
		o.done <- o.ctx.Err()
		return
	}
	ctx, cancel := context.WithTimeout(o.ctx, m.o.OpTimeout)
	defer cancel()
	tx := &Tx{m: m, ctx: ctx, name: o.name}
	// The operation runs on a goroutine of its own and the owner waits for it:
	// still one mutation at a time, but a panic or a runtime.Goexit inside the
	// operation (a test helper calling t.Fatal, say) cannot end the owner.
	result := make(chan error, 1)
	go func() {
		finished := false
		defer func() {
			if finished {
				return
			}
			if r := recover(); r != nil {
				result <- fmt.Errorf("mutator: operation %q panicked: %v", o.name, r)
				return
			}
			result <- fmt.Errorf("mutator: operation %q ended its goroutine", o.name)
		}()
		err := o.fn(tx)
		finished = true
		result <- err
	}()
	err := <-result
	if err == nil && ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = ErrOpTimeout
	}
	if o.done != nil {
		o.done <- err
	}
}

// Do runs fn as one operation of the owner and returns its error. The
// operation's context carries the OpTimeout deadline (and is cancelled when
// ctx is, if that happens before it starts).
func (m *Mutator) Do(ctx context.Context, name string, fn func(*Tx) error) error {
	if m.closing.Load() {
		return ErrClosed
	}
	if !m.started.Load() {
		return errors.New("mutator: not started")
	}
	o := &op{name: name, fn: fn, done: make(chan error, 1), ctx: ctx}
	select {
	case m.queue <- o:
	case <-ctx.Done():
		return ctx.Err()
	case <-m.stop:
		return ErrClosed
	}
	select {
	case err := <-o.done:
		return err
	case <-ctx.Done():
		// The operation stays queued or running; it will complete or be
		// skipped on its own. The caller stops waiting.
		return ctx.Err()
	}
}

// Reconcile asks for a repair pass without waiting. Requests made while one is
// pending are one request; the reason of the latest is kept.
func (m *Mutator) Reconcile(reason string) {
	if m.closing.Load() {
		return
	}
	m.reason.Store(&reason)
	if !m.pending.Swap(true) {
		select {
		case m.wake <- struct{}{}:
		default:
		}
	}
}

// ReconcileNow runs a pass as an operation and returns its result.
func (m *Mutator) ReconcileNow(ctx context.Context, reason string) (PassResult, error) {
	var res PassResult
	err := m.Do(ctx, "reconcile: "+reason, func(tx *Tx) error {
		res = tx.reconcile(reason)
		return res.Err
	})
	return res, err
}

func (m *Mutator) setSpec(s contract.Spec) {
	m.mu.Lock()
	m.spec = s.Clone()
	m.mu.Unlock()
}

func (m *Mutator) recordPass(res PassResult) {
	m.mu.Lock()
	m.lastPass = res
	if res.Repaired {
		m.stats.Repairs++
		m.stats.LastRepair = uint64(res.At / time.Second)
		m.stats.HasLast = true
	}
	m.mu.Unlock()
	m.ready.Store(res.Verified)
	if m.o.OnPass != nil {
		m.o.OnPass(res)
	}
}
