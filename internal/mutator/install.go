package mutator

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// InstallError says the contract could not be installed; the temporary guard
// (priority 80) stays in whichever family has it.
type InstallError struct {
	Problems map[rtnl.Family][]contract.Problem
	Cause    error
}

func (e *InstallError) Error() string {
	var parts []string
	for _, f := range families {
		for _, p := range e.Problems[f] {
			parts = append(parts, fmt.Sprintf("%s %s", f, p))
		}
	}
	msg := "the routing contract could not be installed"
	if len(parts) > 0 {
		msg += ":" + " " + strings.Join(parts, ", ")
	}
	if e.Cause != nil {
		msg += " (" + e.Cause.Error() + ")"
	}
	return msg + "; the temporary guard (priority 80) stays"
}

func (e *InstallError) Unwrap() error { return e.Cause }

// Install installs the routing contract, before the tunnel exists
// (10-exit-routing --install): in both families rule 1, the local-delivery
// guard, goes in before the kernel's priority-0 rule comes out, so loopback
// and the host interface never lose local delivery; then the temporary guard
// at priority 80 and the exit table's unreachable fallback; then everything
// else behind the guard; and the guard comes out once the result verifies. If
// rule 1 cannot be installed nothing else changes. If the contract cannot be
// installed the guard stays: nothing forwarded can leave.
//
// Nothing forwarded can leave before the tunnel exists: the exit table holds
// only the unreachable fallback until the tunnel's default route goes in.
func (m *Mutator) Install(ctx context.Context) error {
	return m.Do(ctx, "install the routing contract", func(tx *Tx) error {
		spec := tx.Spec()
		if spec.Config.IsSidecar() {
			return nil
		}
		snap, err := tx.Snapshot()
		if err != nil {
			return opErr("look at the kernel", err)
		}
		if allClean(planAll(spec, snap)) {
			// Already installed and exact: no guard, no change.
			if res := tx.reconcile("install"); res.ContractHolds {
				return nil
			}
		}
		for _, f := range families {
			want := spec.RulesAt(f, contract.PrioLocalGuard)
			if len(want) != 1 {
				return fmt.Errorf("no local-delivery guard is expected for %s", f)
			}
			if hasExact(snap.Rules[f], want[0]) {
				continue
			}
			if _, err := tx.addRule(want[0]); err != nil {
				return opErr(fmt.Sprintf("add the %s local-delivery guard", f), err)
			}
			tx.Logf("molebridge: added %s rule %d", f, contract.PrioLocalGuard)
		}
		for _, f := range families {
			spec.TempGuard[f] = true
		}
		tx.SetSpec(spec)
		for _, f := range families {
			if _, err := tx.addRule(guardRule(spec, f)); err != nil {
				return &InstallError{Cause: opErr(fmt.Sprintf("add the %s temporary guard", f), err)}
			}
		}
		for _, f := range families {
			if err := tx.ReplaceRoute(contract.FallbackRoute(f, spec.Config.Table)); err != nil {
				return &InstallError{Cause: opErr(fmt.Sprintf("install the %s unreachable fallback", f), err)}
			}
		}
		res := tx.reconcile("install")
		if !res.ContractHolds {
			return &InstallError{Problems: res.Problems, Cause: res.Err}
		}
		return nil
	})
}

// hasExact reports a rule with exactly the expected selectors and action
// among the rules, detached or not (an overlay rule exists before NetBird
// creates the interface).
func hasExact(rules []rtnl.Rule, want rtnl.Rule) bool {
	items := want.Items()
	for _, r := range rules {
		if r.Priority == want.Priority && equalStrings(r.Items(), items) {
			return true
		}
	}
	return false
}

// ChangeReturnPath is PIA's address change as one transaction under the
// owner: install and confirm the new rule 94 and 98 pair, change the address,
// restore the exit table's default route, remove the old pair, with the
// expected state carrying both pairs meanwhile. The rules the repairer
// compares are therefore never ahead of or behind the kernel's.
//
// change is called with the pairs in place; it changes the address (and may
// touch nothing else the contract names). old may be the zero Addr for a
// first registration. If change fails the new pair is taken out again and the
// expected state returns to what it was; if it succeeds but a later step
// fails, the new address stays expected.
//
// The owner is never held across a provider call: register with the
// provider first, then call this with the address it returned.
func (m *Mutator) ChangeReturnPath(ctx context.Context, f rtnl.Family, old, next netip.Addr, change func(*Tx) error) error {
	return m.Do(ctx, fmt.Sprintf("change the %s return-path address", f), func(tx *Tx) error {
		before := tx.Spec()
		if before.Config.IsGluetun() || before.Config.IsSidecar() {
			return fmt.Errorf("the return-path address is the native backend's")
		}
		both := before.Clone()
		both.LeaveReturnPath[f] = false
		both.ReturnPath[f] = nil
		if old.IsValid() && old != next {
			both.ReturnPath[f] = append(both.ReturnPath[f], old)
		}
		both.ReturnPath[f] = append(both.ReturnPath[f], next)
		tx.SetSpec(both)
		res := tx.reconcile("install the new return-path pair")
		if !res.ContractHolds {
			backOut(tx, before, f, next)
			return fmt.Errorf("the new %s return-path rules could not be confirmed: %w", f, orUnverified(res.Err))
		}
		if err := change(tx); err != nil {
			backOut(tx, before, f, next)
			return err
		}
		// The address is changed. The exit table's default route comes back
		// (changing the address removed the routes through the interface)
		// while both pairs are still expected, then the old pair goes.
		res = tx.reconcile("restore the exit route")
		if !res.ContractHolds {
			return fmt.Errorf("the %s routing could not be confirmed after the address change: %w", f, orUnverified(res.Err))
		}
		final := both.Clone()
		final.ReturnPath[f] = []netip.Addr{next}
		tx.SetSpec(final)
		res = tx.reconcile("remove the old return-path pair")
		if !res.ContractHolds {
			return fmt.Errorf("the %s routing could not be confirmed after the address change: %w", f, orUnverified(res.Err))
		}
		return nil
	})
}

// backOut returns the expected state to what it was and takes the new pair out
// of the kernel. When the earlier state left rules 94 and 98 uncompared, the
// pass would not look at them, so they are removed by name.
func backOut(tx *Tx, before contract.Spec, f rtnl.Family, next netip.Addr) {
	pair := before.Clone()
	pair.LeaveReturnPath[f] = false
	pair.ReturnPath[f] = []netip.Addr{next}
	tx.SetSpec(before)
	for _, r := range pair.Rules(f) {
		if (r.Priority == contract.PrioReturnPath || r.Priority == contract.PrioBackstop) && r.Src.Addr() == next {
			if _, err := tx.delRule(r); err != nil {
				tx.Logf("molebridge: could not remove the new %s return-path rule %d: %v", f, r.Priority, err)
			}
		}
	}
	tx.reconcile("take the new return-path pair out")
}

func orUnverified(err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("the contract does not verify")
}
