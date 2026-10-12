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
	var last error
	var lastSnap *Snapshot
	for attempt := 0; attempt < maxSnapshotAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if c.churn != nil {
			c.settleChurn(in, false)
		}
		s, err := c.takeOnce(ctx, in)
		if err == nil {
			// Not every dump the kernel makes is checked for consistency (the
			// FIB rule dump of the kernels measured is not, and repeats or
			// skips a rule when the list changes under it), so the snapshot is
			// checked here: by the notifications that arrived while it was
			// taken, or, without a subscription, by a second look that agrees.
			if c.churn != nil {
				if !c.settleChurn(in, true) {
					return s, nil
				}
				lastSnap, last = s, ErrInconsistent
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
	if lastSnap != nil && errors.Is(last, ErrInconsistent) {
		// The kernel never held still, but no dump failed: hand over the last
		// look, marked, so that repairs are not starved by churn.
		lastSnap.Unstable = true
		return lastSnap, nil
	}
	return nil, fmt.Errorf("rtnl: no consistent snapshot after %d attempts: %w", maxSnapshotAttempts, last)
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

// settleChurn reads the change notifications that are waiting. With
// report=false it discards them (the start of a snapshot: whatever happened
// before is in the state the dumps will see); with report=true it says whether
// any of them could have changed what the snapshot read.
func (c *Conn) settleChurn(in Interest, report bool) (changed bool) {
	for i := 0; i < 256; i++ {
		events, err := c.churn.Next(time.Now().Add(time.Millisecond))
		if err != nil {
			if errors.Is(err, ErrOverrun) {
				return true
			}
			return changed
		}
		for _, e := range events {
			if relevantToSnapshot(e, in) {
				if report {
					return true
				}
				changed = true
			}
		}
	}
	return report
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
