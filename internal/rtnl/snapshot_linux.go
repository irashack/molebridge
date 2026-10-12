//go:build linux

package rtnl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"
)

// maxSnapshotAttempts bounds how many times a whole snapshot is taken again
// because a dump was interrupted by a concurrent change or the request stream
// had to be replaced.
const maxSnapshotAttempts = 8

// Take dumps the rules, the routes of the wanted tables, the links and the
// addresses. Callers that watch for changes must have joined the multicast
// groups (Subscribe) before calling it. See TakeContext.
func (c *Conn) Take(in Interest) (*Snapshot, error) { return c.TakeContext(context.Background(), in) }

// TakeContext is Take bounded by ctx and by the Conn's deadline: one absolute
// deadline covers every dump and every retry, and cancellation is checked
// between dumps.
//
// A snapshot is taken twice and used only if the two agree. If any dump is marked
// NLM_F_DUMP_INTR (on an entry or on NLMSG_DONE), or the request stream has to
// be replaced because a reply was lost, late or out of sequence, everything
// read so far is discarded and the whole snapshot is taken again on the
// (possibly fresh) socket. A timeout is not retried; the operation is out of
// time.
func (c *Conn) TakeContext(ctx context.Context, in Interest) (*Snapshot, error) {
	c.takeMu.Lock()
	defer c.takeMu.Unlock()
	var last error
	var lastSnap *Snapshot
	for attempt := 0; attempt < maxSnapshotAttempts; attempt++ {
		if err := c.expired(ctx); err != nil {
			return nil, err
		}
		churn := c.getChurn()
		blind := false
		if churn == nil && c.reopen != nil {
			// Coverage was lost and not yet restored: try again now.
			c.reopenChurn()
			if churn = c.getChurn(); churn == nil {
				last, blind = errObservation, true
			}
		}
		if churn != nil {
			if _, err := c.settleChurn(ctx, churn, in, false); err != nil {
				if !errors.Is(err, errObservation) {
					return nil, err
				}
				// Coverage is lost until the subscription is replaced: this
				// attempt can be taken but not vouched for.
				c.reopenChurn()
				last, blind = err, true
			}
		}
		s, err := c.takeOnce(ctx, in)
		if err == nil && blind {
			lastSnap = s
			continue
		}
		if err == nil {
			// Not every dump the kernel makes is checked for consistency (the
			// FIB rule dump of the kernels measured is not, and repeats or
			// skips a rule when the list changes under it), so the snapshot is
			// checked here: by the notifications that arrived while it was
			// taken, or, without a subscription, by a second look that agrees.
			if churn != nil {
				changed, cerr := c.settleChurn(ctx, churn, in, true)
				switch {
				case cerr == nil && !changed:
					return s, nil
				case cerr != nil && !errors.Is(cerr, errObservation):
					return nil, cerr // out of time: no snapshot is returned after the deadline
				case cerr != nil:
					c.reopenChurn()
					last = cerr
				default:
					last = ErrInconsistent
				}
				lastSnap = s
				continue
			}
			var again *Snapshot
			if again, err = c.takeOnce(ctx, in); err == nil {
				if reflect.DeepEqual(s, again) {
					return again, nil
				}
				lastSnap = again
				last = ErrInconsistent
				continue
			}
		}
		switch {
		case errors.Is(err, errInterrupted):
			last = ErrInconsistent
		case IsStreamError(err) && !errors.Is(err, os.ErrDeadlineExceeded):
			last = err
		default:
			return nil, err
		}
	}
	if lastSnap != nil && (errors.Is(last, ErrInconsistent) || errors.Is(last, errObservation)) {
		// The kernel never held still (or could not be watched), but no dump
		// failed: hand over the last look, marked, so that repairs are not
		// starved by churn. It is evidence of nothing it shows to be absent.
		lastSnap.Unstable = true
		return lastSnap, nil
	}
	return nil, fmt.Errorf("rtnl: no consistent snapshot after %d attempts: %w", maxSnapshotAttempts, last)
}

// expired reports ErrDeadline once the operation's deadline (the context's or
// the Conn's) has passed, and the context's own error if it was cancelled.
func (c *Conn) expired(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ErrDeadline
		}
		return err
	}
	if dl := c.operationDeadline(ctx); !dl.IsZero() && !time.Now().Before(dl) {
		return ErrDeadline
	}
	return nil
}

// operationDeadline is the earlier of the context's deadline and the Conn's
// absolute one; zero if neither is set.
func (c *Conn) operationDeadline(ctx context.Context) time.Time {
	c.mu.Lock()
	dl := c.deadline
	c.mu.Unlock()
	if d, ok := ctx.Deadline(); ok && (dl.IsZero() || d.Before(dl)) {
		dl = d
	}
	return dl
}

func (c *Conn) takeOnce(ctx context.Context, in Interest) (*Snapshot, error) {
	s := NewSnapshot()
	want := func(t uint32) bool {
		for _, w := range in.Tables {
			if w == t {
				return true
			}
		}
		return false
	}
	for _, f := range []Family{V4, V6} {
		rules, err := c.rulesOnce(ctx, f)
		if err != nil {
			return nil, err
		}
		s.Rules[f] = rules
		routes, err := c.routesOnce(ctx, f, want)
		if err != nil {
			return nil, err
		}
		s.Routes[f] = routes
		addrs, err := c.addrsOnce(ctx, f)
		if err != nil {
			return nil, err
		}
		s.Addrs[f] = addrs
	}
	links, err := c.linksOnce(ctx)
	if err != nil {
		return nil, err
	}
	s.Links = links
	return s, nil
}

// errObservation says the change notifications could not be read: the
// snapshot cannot be vouched for, and the subscription is replaced.
var errObservation = errors.New("rtnl: change notifications could not be read")

// settleChurn reads the change notifications that are waiting. With
// report=false it discards them (the start of a snapshot: whatever happened
// before is in the state the dumps will see); with report=true it says whether
// any of them could have changed what the snapshot read.
//
// Every read is capped by the operation's deadline, which is checked before
// each, and a failure to read other than a plain timeout (nothing waiting) is
// not silence: it returns errObservation, and a lost-events overrun counts as
// a change.
func (c *Conn) settleChurn(ctx context.Context, churn churnSource, in Interest, report bool) (changed bool, err error) {
	dl := c.operationDeadline(ctx)
	for i := 0; i < 256; i++ {
		if cerr := c.expired(ctx); cerr != nil {
			return false, cerr
		}
		until := time.Now().Add(time.Millisecond)
		if !dl.IsZero() && dl.Before(until) {
			until = dl
		}
		events, rerr := churn.Next(until)
		if rerr != nil {
			switch {
			case errors.Is(rerr, ErrOverrun):
				return true, nil
			case Timeout(rerr):
				return changed, nil
			default:
				return false, fmt.Errorf("%w: %v", errObservation, rerr)
			}
		}
		for _, e := range events {
			if relevantToSnapshot(e, in) {
				if report {
					return true, nil
				}
				changed = true
			}
		}
	}
	// Notifications never stopped coming: for a start that is fine, for a
	// check it is a kernel that did not hold still.
	return report, nil
}

// reopenChurn replaces the change subscription after it failed.
func (c *Conn) reopenChurn() {
	if old := c.swapChurn(nil); old != nil {
		_ = old.Close()
	}
	if c.reopen == nil {
		return
	}
	if sub, err := c.reopen(); err == nil {
		c.swapChurn(sub)
	}
}

// relevantToSnapshot: rule, address and link changes always; route changes in
// the tables the snapshot reads.
func relevantToSnapshot(e Event, in Interest) bool {
	if e.Err != nil {
		return true
	}
	if e.Kind != EventRoute {
		return true
	}
	for _, t := range in.Tables {
		if t == e.Table {
			return true
		}
	}
	return false
}
