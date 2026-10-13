//go:build linux

package rtnl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"

	"golang.org/x/sys/unix"
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
// A snapshot is taken twice and used only if the two agree, multiplicity
// included: a rule that is really there twice (ip rule restore adds each rule
// again; the kernel refuses an identical rule only on a request with
// NLM_F_EXCL) is in both looks twice, and one that is in one look only is an
// artifact of the dump, so the looks disagree. If any dump is marked
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
				// The notification for a change can reach the subscription after
				// the dump that saw it (the changer is between updating the
				// list and notifying, and the dump takes no lock), so silence
				// proves little; a second look that agrees, and a dump that
				// holds no rule twice, are what make the snapshot stable.
				again, aerr := c.takeOnce(ctx, in)
				if aerr != nil {
					switch {
					case errors.Is(aerr, errInterrupted):
						last = ErrInconsistent
					case IsStreamError(aerr) && !errors.Is(aerr, os.ErrDeadlineExceeded):
						last = aerr
					default:
						return nil, aerr
					}
					lastSnap = s
					continue
				}
				if !reflect.DeepEqual(s, again) {
					lastSnap, last = again, ErrInconsistent
					continue
				}
				if hasRepeats(again) {
					// A rule twice is real (ip rule restore does it) or an
					// artifact of the dump; real ones are in every look.
					if more, merr := c.confirmRepeats(ctx, in, again); merr != nil || !more {
						if merr != nil && !errors.Is(merr, errInterrupted) && !(IsStreamError(merr) && !errors.Is(merr, os.ErrDeadlineExceeded)) {
							return nil, merr
						}
						lastSnap, last = again, ErrInconsistent
						continue
					}
				}
				// Every change to the rules holds the rtnl lock from the moment it
				// updates the list until it has notified, and the dump holds
				// nothing: a request that takes the lock returns only after every
				// change that was under way has notified, so the drain that
				// follows sees them all. Without the barrier a notification
				// can be later than any drain.
				if berr := c.barrier(ctx); berr != nil {
					switch {
					case IsStreamError(berr) && !errors.Is(berr, os.ErrDeadlineExceeded):
						last = berr
						lastSnap = again
						continue
					case berr != nil && !IsKernelRefusal(berr):
						return nil, berr
					}
					// The kernel will not take the barrier (a namespace without
					// the privilege, say): the drain below waits longer instead.
					if errors.Is(berr, unix.EPERM) || errors.Is(berr, unix.EACCES) || errors.Is(berr, unix.EOPNOTSUPP) ||
						errors.Is(berr, unix.ENODEV) || errors.Is(berr, unix.EINVAL) || errors.Is(berr, unix.ENOSYS) {
						c.noBarrier.Store(true)
					}
				}
				changed, cerr := c.settleChurn(ctx, churn, in, true)
				switch {
				case cerr == nil && !changed:
					if eerr := c.expired(ctx); eerr != nil {
						return nil, eerr
					}
					return again, nil
				case cerr != nil && !errors.Is(cerr, errObservation):
					return nil, cerr // out of time: no snapshot is returned after the deadline
				case cerr != nil:
					c.reopenChurn()
					last = cerr
				default:
					last = ErrInconsistent
				}
				lastSnap = again
				continue
			}
			var again *Snapshot
			if again, err = c.takeOnce(ctx, in); err == nil {
				if reflect.DeepEqual(s, again) {
					if hasRepeats(again) {
						if more, merr := c.confirmRepeats(ctx, in, again); merr != nil || !more {
							if merr != nil && !errors.Is(merr, errInterrupted) && !(IsStreamError(merr) && !errors.Is(merr, os.ErrDeadlineExceeded)) {
								return nil, merr
							}
							lastSnap = again
							last = ErrInconsistent
							continue
						}
					}
					if eerr := c.expired(ctx); eerr != nil {
						return nil, eerr
					}
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
		if eerr := c.expired(ctx); eerr != nil {
			return nil, eerr
		}
		lastSnap.Unstable = true
		return lastSnap, nil
	}
	return nil, fmt.Errorf("rtnl: no consistent snapshot after %d attempts: %w", maxSnapshotAttempts, last)
}

// barrier sends a request the kernel handles under the rtnl lock and that
// changes nothing: RTM_NEWLINK for the loopback interface with no attribute and
// no flag to change. It is acknowledged once the lock was taken, that is, once
// every change that held it has finished and notified.
func (c *Conn) barrier(ctx context.Context) error {
	if c.noBarrier.Load() {
		return &kernelError{errno: unix.EPERM, message: "the barrier was refused earlier"}
	}
	_, _, err := c.exchange(ctx, rtmNewLink, nlmRequest|nlmAck, ifinfo(1, 0, 0))
	return err
}

// IsKernelRefusal reports an error the kernel answered a request with, which
// leaves the request stream intact.
func IsKernelRefusal(err error) bool {
	var ke *kernelError
	return errors.As(err, &ke)
}

// repeatLooks is how many more looks must show a rule twice before it is
// believed.
const repeatLooks = 2

// hasRepeats reports a rule that is in the snapshot more than once: two rules
// of one priority and the same selectors, action and installer.
func hasRepeats(s *Snapshot) bool {
	for _, rules := range s.Rules {
		seen := map[string]bool{}
		for _, r := range rules {
			k := ruleIdentity(r)
			if seen[k] {
				return true
			}
			seen[k] = true
		}
	}
	return false
}

// ruleIdentity is what the kernel compares to call two rules alike: the
// priority, every selector and the action, and who installed it.
func ruleIdentity(r Rule) string {
	var items []string
	for _, it := range r.Items() {
		if it != "not" {
			items = append(items, it)
		}
	}
	return fmt.Sprintf("%d %v proto %d", r.Priority, items, r.Protocol.V)
}

// confirmRepeats takes more looks and says whether they all agree with the
// snapshot. The dump of the kernels measured repeats a rule when the list
// changes under it and nothing in the dump says so; a rule that is really
// there twice is in every look, an artifact is not.
func (c *Conn) confirmRepeats(ctx context.Context, in Interest, s *Snapshot) (bool, error) {
	for i := 0; i < repeatLooks; i++ {
		more, err := c.takeOnce(ctx, in)
		if err != nil {
			return false, err
		}
		if !reflect.DeepEqual(s, more) {
			return false, nil
		}
	}
	return true, nil
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
		quiet := time.Millisecond
		if c.noBarrier.Load() {
			quiet = 5 * time.Millisecond // nothing orders the notifications before this read
		}
		until := time.Now().Add(quiet)
		if !dl.IsZero() && dl.Before(until) {
			until = dl
		}
		events, rerr := churn.Next(until)
		if rerr != nil {
			switch {
			case errors.Is(rerr, ErrOverrun):
				return true, nil
			case Timeout(rerr):
				// A timeout at the operation's own deadline says nothing
				// about the queue: only one with time to spare is silence.
				if cerr := c.expired(ctx); cerr != nil {
					return false, cerr
				}
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
