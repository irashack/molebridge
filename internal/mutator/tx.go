package mutator

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// Tx is the handle an operation uses; it is valid only inside the operation.
// Kernel requests made through it stop with ErrOpTimeout once the operation's
// budget is spent, and carry a deadline of what is left of it.
type Tx struct {
	m    *Mutator
	ctx  context.Context
	name string
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
	if k, ok := tx.m.o.Kernel.(contextTaker); ok {
		return k.TakeContext(tx.ctx, in)
	}
	return tx.m.o.Kernel.Take(in)
}

// AddRule installs a rule; an identical rule already there is not an error.
func (tx *Tx) AddRule(r rtnl.Rule) error {
	if err := tx.budget(); err != nil {
		return err
	}
	if err := tx.m.o.Kernel.AddRule(r); err != nil && !rtnl.IsExist(err) {
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
	if err := tx.m.o.Kernel.DelRule(r); err != nil && !rtnl.IsNotExist(err) {
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
	if err := tx.m.o.Kernel.DelRulePriority(f, priority); err != nil {
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
	return tx.m.o.Kernel.ReplaceRoute(r)
}

// DelRoute removes a route; one already gone is not an error.
func (tx *Tx) DelRoute(r rtnl.Route) error {
	if err := tx.budget(); err != nil {
		return err
	}
	if err := tx.m.o.Kernel.DelRoute(r); err != nil && !rtnl.IsNotExist(err) {
		return err
	}
	return nil
}

// Reconcile runs a repair pass inside the operation.
func (tx *Tx) Reconcile(reason string) PassResult { return tx.reconcile(reason) }

func opErr(op string, err error) error { return fmt.Errorf("%s: %w", op, err) }
