//go:build linux

package rtnl

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sync"
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
// TakeReadOnly is one look at the namespace for judgments that change
// nothing, such as the status record's checks: no settling of the
// subscription, no second look, no barrier. Rule dumps are not atomic (see
// TakeContext), so the snapshot is always marked Unstable: the mutation owner
// never bases a deletion, a guard release or a verdict on one. A status check
// that reads one during a concurrent change may be wrong for that tick and is
// read again on the next.
func (c *Conn) TakeReadOnly(ctx context.Context, in Interest) (*Snapshot, error) {
	c.takeMu.Lock()
	defer c.takeMu.Unlock()
	if err := c.expired(ctx); err != nil {
		return nil, err
	}
	s, err := c.takeOnce(ctx, in)
	if err != nil {
		return nil, err
	}
	s.Unstable = true
	return s, nil
}

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
				againRules, aerr := c.takeRulesOnce(ctx)
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
				if !reflect.DeepEqual(s.Rules, againRules) {
					lastSnap, last = s, ErrInconsistent
					continue
				}
				if hasRepeats(s) {
					// A rule twice is real (ip rule restore does it) or an
					// artifact of the dump; real ones are in every look.
					if more, merr := c.confirmRepeats(ctx, s); merr != nil || !more {
						if merr != nil && !errors.Is(merr, errInterrupted) && !(IsStreamError(merr) && !errors.Is(merr, os.ErrDeadlineExceeded)) {
							return nil, merr
						}
						lastSnap, last = s, ErrInconsistent
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
						lastSnap = s
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
					if hasRepeats(again) {
						if more, merr := c.confirmRepeats(ctx, again); merr != nil || !more {
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

// confirmRepeats takes more looks at the rules and says whether they all agree
// with the snapshot. The dump of the kernels measured repeats a rule when the
// list changes under it and nothing in the dump says so; a rule that is really
// there twice is in every look, an artifact is not.
func (c *Conn) confirmRepeats(ctx context.Context, s *Snapshot) (bool, error) {
	for i := 0; i < repeatLooks; i++ {
		more, err := c.takeRulesOnce(ctx)
		if err != nil {
			return false, err
		}
		if !reflect.DeepEqual(s.Rules, more) {
			return false, nil
		}
	}
	return true, nil
}

// takeRulesOnce dumps the rules of both families: the second look of a
// snapshot. Only the rule dump needs one (the dumps of routes, addresses and
// links are marked when they are interrupted).
func (c *Conn) takeRulesOnce(ctx context.Context) (map[Family][]Rule, error) {
	out := map[Family][]Rule{}
	for _, f := range []Family{V4, V6} {
		rules, err := c.rulesOnce(ctx, f)
		if err != nil {
			return nil, err
		}
		out[f] = rules
	}
	return out, nil
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
	return c.settleChurnFor(ctx, churn, report, func(e Event) bool { return relevantToSnapshot(e, in) })
}

func (c *Conn) settleChurnFor(ctx context.Context, churn churnSource, report bool, relevant func(Event) bool) (changed bool, err error) {
	dl := c.operationDeadline(ctx)
	for i := 0; i < 256; i++ {
		if cerr := c.expired(ctx); cerr != nil {
			return false, cerr
		}
		until := time.Now().Add(c.quietWindow())
		if !dl.IsZero() && dl.Before(until) {
			until = dl
		}
		events, rerr := c.readEvents(churn, until)
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
			if relevant(e) {
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

// ForeignChange drains the Conn's own change subscription and reports whether
// it saw a change that the Conn did not make itself and that could alter what a
// snapshot of in reads. The kernel stamps every notification with the port id
// of the socket whose request caused it (nlmsg_pid), so the notifications of
// this Conn's own mutations - which the owner has already applied to its model
// of the kernel - are told from those of anyone else's. Anything that cannot
// be told (no subscription, a read that failed, lost events, a notification
// that does not decode) counts as foreign. The drain is preceded by the same
// barrier as a snapshot's, so that notifications of changes under way are in
// the queue where the kernel orders them.
func (c *Conn) ForeignChange(ctx context.Context, in Interest) (bool, error) {
	c.takeMu.Lock()
	defer c.takeMu.Unlock()
	churn := c.getChurn()
	if churn == nil {
		return true, nil
	}
	if err := c.expired(ctx); err != nil {
		return false, err
	}
	if berr := c.barrier(ctx); berr != nil && !IsKernelRefusal(berr) {
		return false, berr
	}
	own := c.PortID()
	dl := c.operationDeadline(ctx)
	changed := false
	for i := 0; i < 256; i++ {
		if err := c.expired(ctx); err != nil {
			return false, err
		}
		until := time.Now().Add(c.quietWindow())
		if !dl.IsZero() && dl.Before(until) {
			until = dl
		}
		events, rerr := c.readEvents(churn, until)
		if rerr != nil {
			switch {
			case errors.Is(rerr, ErrOverrun):
				return true, nil
			case Timeout(rerr):
				if err := c.expired(ctx); err != nil {
					return false, err
				}
				return changed, nil
			default:
				c.reopenChurn()
				return true, nil
			}
		}
		for _, e := range events {
			if relevantToSnapshot(e, in) && (e.Err != nil || own == 0 || e.Pid != own) {
				changed = true
			}
		}
	}
	return true, nil
}

// quietWindow is how long a drain waits for one more notification. Where the
// kernel notifies under the rtnl lock the barrier has put every notification of
// a change under way in the queue, so a read that finds it empty can stop at
// once; elsewhere (from Linux 6.18, or when the barrier is refused) nothing
// orders them and the wait is a heuristic.
func (c *Conn) quietWindow() time.Duration {
	switch {
	case c.noBarrier.Load():
		return 5 * time.Millisecond
	case notifiesUnderLock():
		return 200 * time.Microsecond
	}
	return time.Millisecond
}

var notifiesUnderLockOnce struct {
	sync.Once
	v bool
}

// notifiesUnderLock reports a kernel older than 6.18 (see docs/architecture.md).
func notifiesUnderLock() bool {
	notifiesUnderLockOnce.Do(func() {
		// MOLEBRIDGE_RTNL_NOTIFY_LOCKED=1 or 0 overrides the version test (the
		// drills use it to run the behaviour of an older kernel on a newer one).
		switch os.Getenv("MOLEBRIDGE_RTNL_NOTIFY_LOCKED") {
		case "1":
			notifiesUnderLockOnce.v = true
			return
		case "0":
			return
		}
		var u unix.Utsname
		if unix.Uname(&u) != nil {
			return
		}
		rel := unix.ByteSliceToString(u.Release[:])
		var major, minor int
		if _, err := fmt.Sscanf(rel, "%d.%d", &major, &minor); err != nil {
			return
		}
		notifiesUnderLockOnce.v = major < 6 || major == 6 && minor < 18
	})
	return notifiesUnderLockOnce.v
}

// RulesStable reads one family's rules and says whether the read is stable, with
// the evidence a snapshot has for the rules: two looks that agree (a repeat
// confirmed by more), and, with a subscription, no notification of a rule change
// behind the barrier. It is the read-back of rules the owner just installed,
// without the dumps of everything else.
func (c *Conn) RulesStable(ctx context.Context, f Family) (rules []Rule, stable bool, err error) {
	c.takeMu.Lock()
	defer c.takeMu.Unlock()
	for attempt := 0; attempt < maxSnapshotAttempts; attempt++ {
		if err := c.expired(ctx); err != nil {
			return nil, false, err
		}
		churn := c.getChurn()
		if churn != nil {
			if _, err := c.settleRuleChurn(ctx, churn, false); err != nil {
				if !errors.Is(err, errObservation) {
					return nil, false, err
				}
				c.reopenChurn()
				continue
			}
		}
		first, err := c.rulesOnce(ctx, f)
		if err != nil {
			if errors.Is(err, errInterrupted) || IsStreamError(err) && !errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			return nil, false, err
		}
		again, err := c.rulesOnce(ctx, f)
		if err != nil {
			if errors.Is(err, errInterrupted) || IsStreamError(err) && !errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			return nil, false, err
		}
		if !reflect.DeepEqual(first, again) {
			rules = again
			continue
		}
		if hasRepeats(&Snapshot{Rules: map[Family][]Rule{f: first}}) {
			agreed := true
			for i := 0; i < repeatLooks && agreed; i++ {
				more, err := c.rulesOnce(ctx, f)
				if err != nil {
					return nil, false, err
				}
				agreed = reflect.DeepEqual(first, more)
			}
			if !agreed {
				rules = first
				continue
			}
		}
		if churn != nil {
			if berr := c.barrier(ctx); berr != nil && !IsKernelRefusal(berr) {
				return nil, false, berr
			}
			changed, cerr := c.settleRuleChurn(ctx, churn, true)
			if cerr != nil {
				if !errors.Is(cerr, errObservation) {
					return nil, false, cerr
				}
				c.reopenChurn()
				rules = first
				continue
			}
			if changed {
				rules = first
				continue
			}
		}
		if err := c.expired(ctx); err != nil {
			return nil, false, err
		}
		return first, true, nil
	}
	return rules, false, nil
}

// settleRuleChurn is settleChurn for a read of rules alone: only a change of
// rules counts.
func (c *Conn) settleRuleChurn(ctx context.Context, churn churnSource, report bool) (bool, error) {
	return c.settleChurnFor(ctx, churn, report, func(e Event) bool { return e.Err != nil || e.Kind == EventRule })
}

// poller is implemented by change sources that can return what is waiting
// without arming a timer (*Subscriber).
type poller interface {
	Poll() ([]Event, error)
}

// readEvents reads what the subscription has. Where the barrier orders the
// notifications of every change under way before this read, what is waiting is
// all there is and nothing needs to be waited for; elsewhere it waits until the
// quiet window ends.
func (c *Conn) readEvents(churn churnSource, until time.Time) ([]Event, error) {
	p, ok := churn.(poller)
	if !ok {
		return churn.Next(until)
	}
	if !c.noBarrier.Load() && notifiesUnderLock() {
		return p.Poll()
	}
	// Wait out the window by polling: a read with a deadline wakes up on the
	// timer's granularity, which can be several milliseconds, a great deal more
	// than the window.
	for {
		events, err := p.Poll()
		if err == nil || !Timeout(err) || !time.Now().Before(until) {
			return events, err
		}
		runtime.Gosched()
	}
}
