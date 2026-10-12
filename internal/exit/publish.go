package exit

import (
	"fmt"
	"sync"
	"time"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/validate"
)

// publisher writes result.json. The supervisor alone does (D7).
//
// It holds the last full record the worker handed over. A native overlay
// exit's owner_record check is filled in here, from the lease, at write time;
// a lease-only publication rewrites the last record with nothing changed but
// that check, so checked_at and every other check's evidence time stay those of
// the last full inspection.
type publisher struct {
	s     *Settings
	lease *Lease
	boot  bootclock.Clock
	wall  func() time.Time
	write func(path string, v any) error
	logf  func(format string, a ...any)

	mu       sync.Mutex
	last     map[string]any
	closed   bool // a failure record was written or the lease revoked: nothing more
	warnedAt time.Time
}

func newPublisher(s *Settings, lease *Lease, boot bootclock.Clock, wall func() time.Time, logf func(string, ...any)) *publisher {
	return &publisher{s: s, lease: lease, boot: boot, wall: wall, logf: logf,
		write: func(path string, v any) error {
			return jsonfile.Write(path, v, jsonfile.Options{Public: true})
		}}
}

// ownerCheck is the check as it would be written now.
func (p *publisher) ownerCheck() validate.Obj {
	now := p.wall()
	expiry, ok := p.lease.Expiry()
	held := ok && p.lease.Held()
	var wall time.Time
	if held {
		wall = now.Add(expiry - p.boot())
	}
	return OwnerCheck(held, now, wall)
}

// OwnerCheckNow is exported for the applier's seam in the worker's view: see
// WorkerLeaseView.
func (p *publisher) render(rec map[string]any) validate.Obj {
	if p.s.Native() {
		rec = WithOwnerCheck(rec, p.ownerCheck())
	}
	return OrderRecord(rec, p.s.Kind(), p.s.BackendName())
}

func (p *publisher) writeOut(rec map[string]any) {
	if err := p.write(p.s.PathResult(), p.render(rec)); err != nil {
		now := p.wall()
		if now.Sub(p.warnedAt) > time.Minute {
			p.warnedAt = now
			p.logf("cannot write %s: %v", p.s.PathResult(), err)
		}
	}
}

// Full publishes a record from the worker (or the starting record).
func (p *publisher) Full(rec map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.last = rec
	p.writeOut(rec)
}

// LeaseOnly rewrites the last record with a fresh owner_record check. It does
// nothing for exits that carry no such check, or before there is a record.
func (p *publisher) LeaseOnly() {
	if !p.s.Native() {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.last == nil {
		return
	}
	p.writeOut(p.last)
}

// Failure publishes the failure record built from the last one and closes the
// publisher: nothing the worker says afterwards is published.
func (p *publisher) Failure(lapse time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	rec := FailureRecord(p.last, p.s, lapse)
	// The failure record carries the owner_record check as built (fail, no
	// expiry): the lease is revoked.
	p.writeOut(rec)
}

// Close stops publication without writing a record (a requested stop leaves
// the last record to go stale, as the Python applier did).
func (p *publisher) Close() {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
}

func (p *publisher) String() string { return fmt.Sprintf("publisher(%s)", p.s.PathResult()) }
