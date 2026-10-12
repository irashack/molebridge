package exit

import "time"

// readiness is the worker's decision when to tell the supervisor that NetBird
// may run. It is pure, so the policy is tested without a kernel.
//
// ready is sent once the routing contract verifies and, natively, the tunnel is
// up. unready is sent when the contract has not held for the whole grace
// (GUARD_GRACE, as the old gate's "guards not intact" bound): a repair takes
// milliseconds, so a contract that stays broken is one the worker cannot
// restore. A lost tunnel alone never takes NetBird down: the exit table's
// unreachable fallback already stops any traffic.
type readiness struct {
	grace time.Duration
	sent  bool
	// badSince is when the contract was first seen not holding in this
	// stretch; zero while it holds.
	badSince time.Time
}

type action int

const (
	actNone action = iota
	actReady
	actUnready
)

// step takes one observation. holds: the contract verifies; tunnelOK: the
// tunnel is up (always true where the exit does not own it); blocked: the
// NetBird profile check after `netbird up` refused (nothing is admitted).
func (r *readiness) step(now time.Time, holds, tunnelOK, blocked bool) action {
	if holds {
		r.badSince = time.Time{}
	} else if r.badSince.IsZero() {
		r.badSince = now
	}
	switch {
	case r.sent && (!holds && now.Sub(r.badSince) >= r.grace || blocked):
		r.sent = false
		return actUnready
	case !r.sent && !blocked && holds && tunnelOK:
		r.sent = true
		return actReady
	}
	return actNone
}

// markUnready records that the supervisor was told NetBird is not wanted, for
// an unready the caller sent itself (the profile check after `netbird up`).
func (r *readiness) markUnready() { r.sent = false }
