package mutator

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/policy"
	"github.com/irashack/molebridge/internal/rtnl"
)

// Tx is the handle an operation uses; it is valid only inside the operation.
// Kernel requests made through it stop with ErrOpTimeout once the operation's
// budget is spent, and carry a deadline of what is left of it.
type Tx struct {
	m    *Mutator
	ctx  context.Context
	name string
	// refused remembers the deletions already refused, so each is logged once.
	refused map[string]bool
	// retiring are return-path addresses a transaction is moving away from: the
	// expected state keeps their pair until the transaction settles, but the
	// transaction's own steps may remove it once the address is no longer live
	// (the deletion check still protects it while it is).
	retiring map[netip.Addr]bool
	// model is the policy model of the kernel for this operation: a stable
	// snapshot with the operation's own changes applied; nil when unknown.
	model *policy.State
}

// ErrUnsafeDeletion says the owner did not delete a rule or route because the
// kernel's policy without it would let a class of protected traffic escape (see
// internal/policy), or because that could not be judged.
var ErrUnsafeDeletion = errors.New("refused: the deletion could let protected traffic escape")

// approve evaluates a deletion against the policy model of the kernel with the
// rule or route taken out. It refuses a deletion that turns any protected class
// of traffic from stopped or routed-by-the-contract into an escape, and one it
// cannot judge. Every deletion the owner makes goes through it.
//
// The model is one stable snapshot per pass, kept up to date with the pass's
// own changes: every add and delete the owner makes is applied to it, so each
// deletion is judged against the simulated current state. Only a change that
// someone else made - told by the port id the kernel stamps on the
// notification - sends the owner back to the kernel for a fresh stable snapshot
// before the next deletion. A kernel that cannot say who made a change is
// treated as if everything were foreign: a snapshot per deletion.
func (tx *Tx) approve(what string, remove func(policy.State) (policy.State, bool)) (after policy.State, changed bool, err error) {
	spec := tx.m.Expected()
	if spec.Config.IsSidecar() {
		return policy.State{}, false, nil
	}
	if len(tx.retiring) > 0 {
		for f, addrs := range spec.ReturnPath {
			var keep []netip.Addr
			for _, a := range addrs {
				if !tx.retiring[a] {
					keep = append(keep, a)
				}
			}
			spec.ReturnPath[f] = keep
		}
	}
	refuse := func(reason string, cause error) error {
		msg := fmt.Sprintf("kept %s: %s", what, reason)
		if !tx.refused[msg] {
			if tx.refused == nil {
				tx.refused = map[string]bool{}
			}
			tx.refused[msg] = true
			tx.Logf("molebridge: %s", msg)
		}
		if cause != nil {
			return fmt.Errorf("%w: %s: %w", ErrUnsafeDeletion, msg, cause)
		}
		return fmt.Errorf("%w: %s", ErrUnsafeDeletion, msg)
	}
	model, err := tx.currentModel(spec)
	if err != nil {
		return policy.State{}, false, refuse("the kernel could not be read to judge it", err)
	}
	if model == nil {
		return policy.State{}, false, refuse("the kernel kept changing, so it could not be judged", nil)
	}
	before := *model
	before.Spec = spec
	after, changed = remove(before)
	if !changed {
		return before, false, nil // nothing there to delete
	}
	if worse := policy.Worsens(before, after); len(worse) > 0 {
		return policy.State{}, false, refuse(worse[0].String(), nil)
	}
	return after, true, nil
}

// foreignDetector is implemented by kernels that can say whether anyone but the
// caller changed what a snapshot reads since the last look (rtnl.Conn).
type foreignDetector interface {
	ForeignChange(ctx context.Context, in rtnl.Interest) (bool, error)
}

// currentModel returns the model of the kernel as it is now: the pass's
// snapshot with its own changes, unless something else changed the kernel, in
// which case a fresh stable snapshot. nil means no stable snapshot could be
// had.
func (tx *Tx) currentModel(spec contract.Spec) (*policy.State, error) {
	if tx.model != nil {
		if d, ok := tx.m.o.Kernel.(foreignDetector); ok {
			foreign, err := d.ForeignChange(tx.ctx, spec.Interest())
			if err != nil {
				return nil, err
			}
			if !foreign {
				return tx.model, nil
			}
		}
		tx.model = nil
	}
	snap, err := tx.Snapshot()
	if err != nil {
		return nil, err
	}
	if snap.Unstable {
		return nil, nil
	}
	return tx.model, nil // Snapshot recorded it
}

// afterDelete records a deletion in the model: the simulated state when it was
// made, nothing known when it failed.
func (tx *Tx) afterDelete(after policy.State, changed bool, err error) {
	switch {
	case tx.model == nil:
	case err != nil:
		tx.model = nil
	case changed:
		tx.model = &after
	}
}

// afterAdd records an add: a request the kernel refused as a duplicate changed
// nothing, any other failure leaves the state unknown.
func (tx *Tx) afterAdd(r rtnl.Rule, err error) {
	switch {
	case tx.model == nil:
	case err == nil:
		next := tx.model.WithRule(r)
		tx.model = &next
	case rtnl.IsExist(err):
	default:
		tx.model = nil
	}
}

func (tx *Tx) afterRoute(r rtnl.Route, err error) {
	switch {
	case tx.model == nil:
	case err == nil:
		next := tx.model.WithRoute(r)
		tx.model = &next
	default:
		tx.model = nil
	}
}

// kAddRule, kDelRule, kDelRulePriority, kReplaceRoute and kDelRoute are the
// owner's requests to the kernel: the add and delete calls apply to the model,
// and every delete is approved first.
func (tx *Tx) kAddRule(r rtnl.Rule) error {
	err := tx.m.o.Kernel.AddRule(r)
	tx.afterAdd(r, err)
	return err
}

func (tx *Tx) kDelRule(r rtnl.Rule) error {
	after, changed, err := tx.approve(fmt.Sprintf("%s rule %d", r.Family, r.Priority), func(s policy.State) (policy.State, bool) { return s.WithoutRule(r) })
	if err != nil {
		return err
	}
	err = tx.m.o.Kernel.DelRule(r)
	tx.afterDelete(after, changed, err)
	return err
}

func (tx *Tx) kDelRulePriority(f rtnl.Family, priority uint32) error {
	after, changed, err := tx.approve(fmt.Sprintf("the first %s rule at priority %d", f, priority), func(s policy.State) (policy.State, bool) { return s.WithoutPriority(f, priority) })
	if err != nil {
		return err
	}
	err = tx.m.o.Kernel.DelRulePriority(f, priority)
	tx.afterDelete(after, changed, err)
	return err
}

func (tx *Tx) kReplaceRoute(r rtnl.Route) error {
	err := tx.m.o.Kernel.ReplaceRoute(r)
	tx.afterRoute(r, err)
	return err
}

func (tx *Tx) kDelRoute(r rtnl.Route) error {
	after, changed, err := tx.approve(fmt.Sprintf("a %s route in table %d", r.Family, r.Table), func(s policy.State) (policy.State, bool) { return s.WithoutRoute(r) })
	if err != nil {
		return err
	}
	err = tx.m.o.Kernel.DelRoute(r)
	tx.afterDelete(after, changed, err)
	return err
}

// Context carries the operation's deadline.
func (tx *Tx) Context() context.Context { return tx.ctx }

// Spec returns a copy of the expected state.
func (tx *Tx) Spec() contract.Spec { return tx.m.Expected() }

// SetSpec replaces the expected state. Call it before the kernel change it
// anticipates, so a pass that runs next judges against the new state.
func (tx *Tx) SetSpec(s contract.Spec) { tx.m.setSpec(s) }

// Logf writes a log line.
func (tx *Tx) Logf(format string, args ...any) { tx.m.o.Logf(format, args...) }

// budget checks the operation's context and gives the kernel the operation's
// one absolute deadline. A kernel that takes a deadline gets it as such, so
// every request, dump and retry of the operation ends by that instant; one
// that only takes a per-request timeout gets what is left.
func (tx *Tx) budget() error {
	if err := tx.ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return ErrOpTimeout
		}
		return err
	}
	if dl, ok := tx.ctx.Deadline(); ok {
		switch k := tx.m.o.Kernel.(type) {
		case deadliner:
			k.SetDeadline(dl)
		case timeouter:
			left := time.Until(dl)
			if left < time.Millisecond {
				left = time.Millisecond
			}
			k.SetTimeout(left)
		}
	}
	return nil
}

// Snapshot dumps the state the contract is judged on, within the operation's
// deadline and cancellation.
func (tx *Tx) Snapshot() (*rtnl.Snapshot, error) {
	if err := tx.budget(); err != nil {
		return nil, err
	}
	in := tx.m.spec.Interest()
	var snap *rtnl.Snapshot
	var err error
	if k, ok := tx.m.o.Kernel.(contextTaker); ok {
		snap, err = k.TakeContext(tx.ctx, in)
	} else {
		snap, err = tx.m.o.Kernel.Take(in)
	}
	tx.model = nil
	if err == nil && !snap.Unstable {
		m := policy.FromSnapshot(tx.m.Expected(), snap)
		tx.model = &m
	}
	return snap, err
}

// AddRule installs a rule; an identical rule already there is not an error.
func (tx *Tx) AddRule(r rtnl.Rule) error {
	if err := tx.budget(); err != nil {
		return err
	}
	if err := tx.kAddRule(r); err != nil && !rtnl.IsExist(err) {
		return err
	}
	return nil
}

// DelRule removes the first rule that has every attribute of r; a rule
// that is already gone is not an error.
func (tx *Tx) DelRule(r rtnl.Rule) error {
	if err := tx.budget(); err != nil {
		return err
	}
	if err := tx.kDelRule(r); err != nil && !rtnl.IsNotExist(err) {
		return err
	}
	return nil
}

// DelRulePriority removes the first rule at a priority; none left is not an
// error but is reported by the bool.
func (tx *Tx) DelRulePriority(f rtnl.Family, priority uint32) (bool, error) {
	if err := tx.budget(); err != nil {
		return false, err
	}
	if err := tx.kDelRulePriority(f, priority); err != nil {
		if rtnl.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ReplaceRoute creates or replaces a route.
func (tx *Tx) ReplaceRoute(r rtnl.Route) error {
	if err := tx.budget(); err != nil {
		return err
	}
	return tx.kReplaceRoute(r)
}

// DelRoute removes a route; one already gone is not an error.
func (tx *Tx) DelRoute(r rtnl.Route) error {
	if err := tx.budget(); err != nil {
		return err
	}
	if err := tx.kDelRoute(r); err != nil && !rtnl.IsNotExist(err) {
		return err
	}
	return nil
}

// Reconcile runs a repair pass inside the operation.
func (tx *Tx) Reconcile(reason string) PassResult { return tx.reconcile(reason) }

func opErr(op string, err error) error { return fmt.Errorf("%s: %w", op, err) }
