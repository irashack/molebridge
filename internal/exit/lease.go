package exit

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/contract"
)

// The supervised loops. Each reports the boot-clock time of its last completed
// step in every renewal.
const (
	LoopMutator = "mutator"
	LoopWatcher = "watcher"
	LoopFwmark  = "fwmark"
	LoopLog     = "log"
)

// Bounds of the loops (D21). The mutation owner completes or fails every
// operation within 10 seconds and reports an idle step every 2; the watcher,
// the fwmark monitor and the log monitor report every 2 seconds. The 2-second
// loops are given one second of scheduling slack: a Go program on a busy,
// throttled container can be late by a few hundred milliseconds, and a bound
// with no slack would lapse the lease on a healthy exit.
const (
	MutatorBound = 10 * time.Second
	LoopBound    = 3 * time.Second
	// TransitSlack is what the supervisor allows beyond a loop's bound for the
	// time a renewal spends in the pipe and waiting for the supervisor's
	// goroutine; the worker itself uses the plain bound.
	TransitSlack = time.Second
	// StartupAllowance is how long a new worker has to send its first accepted
	// renewal. Nothing depends on it before that: NetBird is not running.
	StartupAllowance = 30 * time.Second
	// RenewEvery is the worker's renewal period.
	RenewEvery = 2 * time.Second
)

// LoopBounds returns the loops the settings' mode supervises and their bounds.
func LoopBounds(s *Settings) map[string]time.Duration {
	b := map[string]time.Duration{LoopMutator: MutatorBound, LoopWatcher: LoopBound}
	if s.Routing.IsGluetun() && s.Routing.Kind == contract.Overlay {
		b[LoopFwmark] = LoopBound
		b[LoopLog] = LoopBound
	}
	if s.Routing.IsSidecar() {
		// A sidecar has no contract and no watcher; its worker's one loop is
		// the pipeline's tick, reported as the mutator's idle step.
		delete(b, LoopWatcher)
	}
	return b
}

// RejectError says why a renewal was refused.
type RejectError struct{ Reason string }

func (e *RejectError) Error() string { return "renewal refused: " + e.Reason }

// Lease is the supervisor's side of the progress lease. It never extends an
// expiry on anything but an accepted renewal, and reads time only from the
// supervisor's own boot clock.
type Lease struct {
	clock  bootclock.Clock
	grace  time.Duration
	bounds map[string]time.Duration

	mu            sync.Mutex
	gen           string
	lastSeq       uint64
	lastStatusSeq uint64
	accepted      bool
	deadline      time.Duration
	revoked       bool
}

// NewLease creates a lease with the given grace and loop bounds. It has no
// generation until NewGeneration.
func NewLease(clock bootclock.Clock, grace time.Duration, bounds map[string]time.Duration) *Lease {
	if clock == nil {
		clock = bootclock.System()
	}
	return &Lease{clock: clock, grace: grace, bounds: bounds, revoked: true}
}

// NewGeneration starts a launch: a random 128-bit generation, sequence numbers
// reset, no renewal accepted yet, and the first one due within
// StartupAllowance.
func (l *Lease) NewGeneration() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("exit: cannot draw a launch generation: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gen = hex.EncodeToString(b[:])
	l.lastSeq, l.lastStatusSeq = 0, 0
	l.accepted = false
	l.revoked = false
	l.deadline = l.clock() + StartupAllowance
	return l.gen, nil
}

// Gen is the current generation, empty before the first launch.
func (l *Lease) Gen() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.gen
}

// Revoke ends the lease: nothing is accepted again until the next generation.
func (l *Lease) Revoke() {
	l.mu.Lock()
	l.revoked = true
	l.mu.Unlock()
}

// Revoked reports a revoked (or never started) lease.
func (l *Lease) Revoked() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.revoked
}

// Accept judges a renewal. On acceptance the expiry becomes now plus the
// grace, on the supervisor's clock, and is returned.
func (l *Lease) Accept(m Msg) (time.Duration, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	switch {
	case l.revoked:
		return 0, &RejectError{"the lease is revoked"}
	case m.Gen != l.gen:
		return 0, &RejectError{"stale generation"}
	case m.Seq <= l.lastSeq:
		return 0, &RejectError{"sequence number not above the last accepted"}
	case len(m.Loops) != len(l.bounds):
		return 0, &RejectError{"the loops reported are not the loops supervised"}
	}
	for name, bound := range l.bounds {
		ns, ok := m.Loops[name]
		if !ok {
			return 0, &RejectError{"the " + name + " loop is missing"}
		}
		at := time.Duration(ns)
		if at > now {
			return 0, &RejectError{"the " + name + " loop's time is in the future"}
		}
		if now-at > bound+TransitSlack {
			return 0, &RejectError{"the " + name + " loop is older than its bound"}
		}
	}
	l.lastSeq = m.Seq
	l.accepted = true
	l.deadline = now + l.grace
	return l.deadline, nil
}

// AcceptStatus judges a status record's identity: current generation, live
// lease, a sequence number above the last record's.
func (l *Lease) AcceptStatus(gen string, seq uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.revoked || gen != l.gen || seq <= l.lastStatusSeq {
		return false
	}
	l.lastStatusSeq = seq
	return true
}

// Held reports an acknowledged, unexpired, unrevoked lease: the worker is
// live. This is what owner_record states.
func (l *Lease) Held() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.revoked && l.accepted && l.clock() < l.deadline
}

// Expiry returns the accepted expiry on the boot clock; ok is false before the
// first accepted renewal and after a revocation.
func (l *Lease) Expiry() (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.revoked || !l.accepted {
		return 0, false
	}
	return l.deadline, true
}

// Lapsed reports that the current deadline (the first renewal's, or the
// accepted expiry) has passed without the lease being revoked.
func (l *Lease) Lapsed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.revoked && l.clock() >= l.deadline
}
