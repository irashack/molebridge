package mutator

import (
	"context"
	"errors"
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
// first registration, and old == next is a transaction that must not take
// anything away.
//
// Fail-closed under partial failure. change may fail at any step, and so may
// any request the transaction makes. What a failure leaves is decided from
// the kernel, never from what the callback was supposed to have done: after
// change returns, success or not, the addresses on the tunnel interface are
// read back, and every address that is live there, and every address that was
// protected before, keeps its pair. A pair comes out only for an address
// that the read shows is gone and that was not protected before: the new
// pair of an address that never arrived, the old pair of an address that has
// left. If the read itself fails, both pairs stay.
//
// The owner is never held across a provider call: register with the
// provider first, then call this with the address it returned.
func (m *Mutator) ChangeReturnPath(ctx context.Context, f rtnl.Family, old, next netip.Addr, change func(*Tx) error) error {
	return m.Do(ctx, fmt.Sprintf("change the %s return-path address", f), func(tx *Tx) error {
		before := tx.Spec()
		if before.Config.IsGluetun() || before.Config.IsSidecar() {
			return fmt.Errorf("the return-path address is the native backend's")
		}
		if !next.IsValid() || (f == rtnl.V4) != next.Is4() || (old.IsValid() && (f == rtnl.V4) != old.Is4()) {
			return fmt.Errorf("the %s return-path address is not an address of that family", f)
		}
		both := withReturnPath(before, f, dedupe(old, next))
		tx.SetSpec(both)
		res := tx.reconcile("install the new return-path pair")
		if !res.ContractHolds {
			// The new pair may be partly in. Whether it stays depends only on
			// whether its address is live.
			return errors.Join(
				fmt.Errorf("the new %s return-path rules could not be confirmed: %w", f, orUnverified(res.Err)),
				tx.settle(before, both, f, old, next, true))
		}
		cerr := change(tx)
		if cerr == nil {
			// The exit table's default route comes back (changing the address
			// removed the routes through the interface) while both pairs are
			// still expected; only then may an old pair go.
			if res = tx.reconcile("restore the exit route"); !res.ContractHolds {
				cerr = fmt.Errorf("the %s routing could not be confirmed after the address change: %w", f, orUnverified(res.Err))
			}
		}
		return errors.Join(cerr, tx.settle(before, both, f, old, next, cerr != nil))
	})
}

func dedupe(addrs ...netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if a.IsValid() && !containsAddr(out, a) {
			out = append(out, a)
		}
	}
	return out
}

func containsAddr(s []netip.Addr, a netip.Addr) bool {
	for _, x := range s {
		if x == a {
			return true
		}
	}
	return false
}

func withReturnPath(s contract.Spec, f rtnl.Family, addrs []netip.Addr) contract.Spec {
	out := s.Clone()
	out.LeaveReturnPath[f] = false
	out.ReturnPath[f] = append([]netip.Addr(nil), addrs...)
	return out
}

// settle decides, from the kernel, which return-path pairs survive a
// transaction, and removes the others. failed says the transaction did not
// complete: then everything protected before stays protected too.
func (tx *Tx) settle(before, both contract.Spec, f rtnl.Family, old, next netip.Addr, failed bool) error {
	snap, err := tx.Snapshot()
	if err != nil {
		// Cannot tell what is live: both pairs stay, as they are expected now.
		return opErr("read the tunnel addresses back; both return-path pairs stay", err)
	}
	var keep []netip.Addr
	if link, ok := snap.Link(both.Config.ExitIf); ok {
		for _, a := range snap.Addrs[f] {
			if a.Index == link.Index && a.Global() {
				keep = append(keep, a.Local.Addr())
			}
		}
	}
	if failed {
		keep = append(keep, before.ReturnPath[f]...)
		if old.IsValid() {
			keep = append(keep, old)
		}
	} else {
		keep = append(keep, next)
	}
	keep = dedupe(keep...)
	final := withReturnPath(both, f, keep)
	tx.SetSpec(final)
	res := tx.reconcile("settle the return-path pairs")
	if !res.ContractHolds {
		return fmt.Errorf("the %s return-path rules could not be settled: %w", f, orUnverified(res.Err))
	}
	// Nothing new survived: the earlier state, including leaving the pair to
	// its owner, is restored.
	if failed && subsetOf(keep, before.ReturnPath[f], old) {
		tx.SetSpec(before)
	}
	return nil
}

func subsetOf(set, of []netip.Addr, extra netip.Addr) bool {
	for _, a := range set {
		if !containsAddr(of, a) && a != extra {
			return false
		}
	}
	return true
}

func orUnverified(err error) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("the contract does not verify")
}
