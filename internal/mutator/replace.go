package mutator

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// TunnelChange is a whole-tunnel replacement as the owner runs it
// (ReplaceTunnel): the new tunnel's return path, and the two kernel changes
// only the tunnel's own code can make.
type TunnelChange struct {
	// ReturnPath and LeaveReturnPath are the new tunnel's return path as the
	// expected state takes it: per family, its addresses, and whether rules
	// 94 and 98 are left to the transaction that sets an address (a config
	// without one, as PIA's is). A family may not have both.
	ReturnPath      map[rtnl.Family][]netip.Addr
	LeaveReturnPath map[rtnl.Family]bool
	// Old are the old tunnel's addresses as its config gives them, added to
	// what the expected state and the kernel already say is protected.
	Old []netip.Addr
	// RemoveLink deletes the tunnel interface if there is one; its addresses
	// and its routes go with it. It must remove the link even when the
	// operation's deadline has passed: it is also the cleanup after a
	// failure.
	RemoveLink func(*Tx) error
	// CreateLink creates the new link, configures it, assigns its addresses,
	// brings it up and puts its default route into the exit table. A failure
	// leaves no link.
	CreateLink func(*Tx) error
}

// ErrNoTunnelChange says a TunnelChange was refused before anything changed:
// a native backend's change with both callbacks and addresses of the right
// family is required.
var ErrNoTunnelChange = errors.New("mutator: not a tunnel replacement")

func (c TunnelChange) check() error {
	if c.RemoveLink == nil || c.CreateLink == nil {
		return fmt.Errorf("%w: the link callbacks are missing", ErrNoTunnelChange)
	}
	for f, addrs := range c.ReturnPath {
		if f != rtnl.V4 && f != rtnl.V6 {
			return fmt.Errorf("%w: unknown family %v", ErrNoTunnelChange, f)
		}
		for _, a := range addrs {
			if !a.IsValid() || (f == rtnl.V4) != a.Is4() {
				return fmt.Errorf("%w: the %s return-path address is not an address of that family", ErrNoTunnelChange, f)
			}
		}
		if len(addrs) > 0 && c.LeaveReturnPath[f] {
			return fmt.Errorf("%w: the %s return path is both given and left to the applier", ErrNoTunnelChange, f)
		}
	}
	for _, a := range c.Old {
		if !a.IsValid() {
			return fmt.Errorf("%w: an old address is not valid", ErrNoTunnelChange)
		}
	}
	return nil
}

// target is the new tunnel's return path, normalized: per family its
// addresses, or leaving the pair to the applier.
func (c TunnelChange) target() contract.Spec {
	out := contract.Spec{ReturnPath: map[rtnl.Family][]netip.Addr{}, LeaveReturnPath: map[rtnl.Family]bool{}}
	for _, f := range families {
		out.ReturnPath[f] = dedupe(c.ReturnPath[f]...)
		out.LeaveReturnPath[f] = len(out.ReturnPath[f]) == 0 && c.LeaveReturnPath[f]
	}
	return out
}

// withPaths is s, the expected state as it is now (a pass may have changed
// its temporary guard), with the return path of p.
func withPaths(s, p contract.Spec) contract.Spec {
	out := s.Clone()
	for _, f := range families {
		out.ReturnPath[f] = append([]netip.Addr(nil), p.ReturnPath[f]...)
		out.LeaveReturnPath[f] = p.LeaveReturnPath[f]
	}
	return out
}

// ReplaceTunnel swaps the tunnel's whole configuration as ONE operation of the
// owner, in the order that keeps every intermediate state allowed by the
// policy model (internal/policy):
//
//  1. The expected state takes the new tunnel's return path, keeping the old
//     one's meanwhile, and a pass installs and confirms the new pairs (rules
//     94 and 98), as PIA's address transaction does. The old pairs are every
//     address the expected state names, every address live on the tunnel
//     interface (from a stable look) and the old config's own. So the
//     repairer neither removes the new pairs nor re-adds the old ones, and the
//     new addresses are protected before they exist.
//  2. The exit table's routes through the old link are deleted (each deletion
//     approved), then the link itself (RemoveLink), and a stable look confirms
//     it is gone. Forwarded traffic now meets the exit table's unreachable
//     fallback. The link goes before its pairs, so no tunnel address is ever
//     live without its rule 94.
//  3. The old pairs that are not the new tunnel's are deleted, each deletion
//     approved like every other, and the expected state drops them: it names
//     the new tunnel's return path only.
//  4. The new link is created (CreateLink), and a pass confirms the contract
//     with it.
//
// A failure at any step fails closed: the link is removed whatever it is (the
// old one, or a half-built new one), and the expected state is settled from a
// stable look at the kernel, naming the new tunnel's return path and every
// address still live, never fewer than are live. The exit then has no tunnel
// and the forwarded traffic meets the fallback until the caller's recovery
// brings up the new configuration. If the kernel cannot be read back, every
// pair stays expected. Arguments that are not a change (ErrNoTunnelChange,
// or a gluetun backend) are refused before anything changes.
//
// It never runs across a provider call: register first, then replace.
func (m *Mutator) ReplaceTunnel(ctx context.Context, c TunnelChange) error {
	return m.Do(ctx, "replace the tunnel", func(tx *Tx) error {
		before := tx.Spec()
		if before.Config.IsGluetun() || before.Config.IsGluetunSidecar() {
			return fmt.Errorf("%w: the tunnel is the native backend's", ErrNoTunnelChange)
		}
		if err := c.check(); err != nil {
			return err
		}
		next := c.target()
		// From here until a pass verifies the new tunnel there is no verdict.
		tx.unverified("a tunnel replacement is in progress")
		if err := tx.replaceTunnel(before, next, c); err != nil {
			return errors.Join(err, tx.failClosed(next, c))
		}
		return nil
	})
}

// replaceTunnel runs the four steps; next carries the new return path only.
func (tx *Tx) replaceTunnel(before, next contract.Spec, c TunnelChange) error {
	exit := before.Config.ExitIf
	snap, err := tx.stableSnapshot()
	if err != nil {
		return opErr("look at the kernel before the replacement", err)
	}

	// 1. Both return paths expected, the new pairs installed and confirmed.
	both := before.Clone()
	old := map[rtnl.Family][]netip.Addr{}
	for _, f := range families {
		old[f] = dedupe(append(append(append([]netip.Addr(nil), before.ReturnPath[f]...), liveOn(snap, exit, f)...), ofFamily(c.Old, f)...)...)
		if all := dedupe(append(append([]netip.Addr(nil), old[f]...), next.ReturnPath[f]...)...); len(all) > 0 {
			both.ReturnPath[f], both.LeaveReturnPath[f] = all, false
		}
	}
	tx.SetSpec(both)
	if res := tx.reconcile("install the new tunnel's return-path pairs"); !res.ContractHolds {
		return fmt.Errorf("the new tunnel's return-path rules could not be confirmed: %w", orUnverified(res.Err))
	}

	// 2. The old link's routes in the exit table, then the link.
	if snap, err = tx.stableSnapshot(); err != nil {
		return opErr("look at the old tunnel", err)
	}
	if link, ok := snap.Link(exit); ok {
		for _, f := range families {
			for _, r := range snap.RoutesInTable(f, before.Config.Table) {
				if r.Oif.OK && r.Oif.V == link.Index {
					if err := tx.DelRoute(r); err != nil {
						return opErr(fmt.Sprintf("remove the %s route through the old tunnel", f), err)
					}
				}
			}
		}
	}
	if err := c.RemoveLink(tx); err != nil {
		return opErr("delete the old tunnel link", err)
	}
	tx.model = nil // the link went by another socket
	if snap, err = tx.stableSnapshot(); err != nil {
		return opErr("look at the kernel after deleting the old tunnel", err)
	}
	if _, ok := snap.Link(exit); ok {
		return fmt.Errorf("the old tunnel link %s is still there", exit)
	}

	// 3. The old pairs go, then the expected state names only the new ones.
	for _, f := range families {
		var going []netip.Addr
		for _, a := range old[f] {
			if !containsAddr(next.ReturnPath[f], a) {
				going = append(going, a)
			}
		}
		if err := tx.dropPairs(snap, both, f, going); err != nil {
			return err
		}
	}
	tx.SetSpec(withPaths(tx.Spec(), next))

	// 4. The new link, and the contract with it.
	if err := c.CreateLink(tx); err != nil {
		return opErr("create the new tunnel link", err)
	}
	tx.model = nil
	if res := tx.reconcile("the new tunnel is up"); !res.ContractHolds {
		return fmt.Errorf("the routing could not be confirmed with the new tunnel: %w", orUnverified(res.Err))
	}
	return nil
}

// failClosed is what a failed replacement leaves: no link, and the expected
// state settled from the kernel. next carries the new return path only.
func (tx *Tx) failClosed(next contract.Spec, c TunnelChange) error {
	tx.retiring = nil
	var errs []error
	if err := c.RemoveLink(tx); err != nil {
		errs = append(errs, opErr("remove the tunnel link after the failure", err))
	}
	tx.model = nil
	cur := tx.Spec()
	exit := cur.Config.ExitIf
	keepAll := func(why error) error {
		// Cannot tell what is live: whatever is expected now stays, and the
		// new tunnel's return path joins it.
		all := cur.Clone()
		for _, f := range families {
			if a := dedupe(append(append([]netip.Addr(nil), cur.ReturnPath[f]...), next.ReturnPath[f]...)...); len(a) > 0 {
				all.ReturnPath[f], all.LeaveReturnPath[f] = a, false
			}
		}
		tx.SetSpec(all)
		tx.unverified("the tunnel replacement failed and the kernel could not be read back")
		return errors.Join(append(errs, why)...)
	}
	snap, err := tx.stableSnapshot()
	if err != nil {
		return keepAll(opErr("read the kernel back after the failure; every return-path pair stays", err))
	}
	final := withPaths(cur, next)
	for _, f := range families {
		live := liveOn(snap, exit, f)
		keep := dedupe(append(append([]netip.Addr(nil), next.ReturnPath[f]...), live...)...)
		var going []netip.Addr
		for _, a := range cur.ReturnPath[f] {
			if !containsAddr(keep, a) {
				going = append(going, a)
			}
		}
		if err := tx.dropPairs(snap, cur, f, going); err != nil {
			return keepAll(err)
		}
		final.ReturnPath[f] = keep
		final.LeaveReturnPath[f] = len(keep) == 0 && next.LeaveReturnPath[f]
	}
	tx.SetSpec(final)
	if res := tx.reconcile("settle after a failed tunnel replacement"); !res.ContractHolds {
		errs = append(errs, fmt.Errorf("the routing could not be confirmed after the failed replacement: %w", orUnverified(res.Err)))
	}
	return errors.Join(errs...)
}

// dropPairs deletes the return-path pairs of addresses that are going, as the
// contract writes them, from the rules a stable snapshot shows. None of them
// may be live. Each deletion is the usual approved one, with the addresses
// not counted as expected for it.
func (tx *Tx) dropPairs(snap *rtnl.Snapshot, spec contract.Spec, f rtnl.Family, going []netip.Addr) error {
	if len(going) == 0 {
		return nil
	}
	tx.retiring = map[netip.Addr]bool{}
	defer func() { tx.retiring = nil }()
	for _, a := range going {
		for _, x := range snap.Addrs[f] {
			if x.Local.Addr() == a {
				return fmt.Errorf("the %s address %s is still live; its return-path pair stays", f, a)
			}
		}
		tx.retiring[a] = true
	}
	for _, a := range going {
		probe := withReturnPath(spec, f, []netip.Addr{a})
		for _, p := range []uint32{contract.PrioReturnPath, contract.PrioBackstop} {
			for _, want := range probe.RulesAt(f, p) {
				if !hasExact(snap.Rules[f], want) {
					continue
				}
				if err := tx.DelRule(want); err != nil {
					return opErr(fmt.Sprintf("remove the %s return-path pair of %s", f, a), err)
				}
			}
		}
	}
	return nil
}

// stableSnapshot is a snapshot the kernel held still for, in up to settleLooks
// tries.
func (tx *Tx) stableSnapshot() (*rtnl.Snapshot, error) {
	for i := 0; i < settleLooks; i++ {
		snap, err := tx.Snapshot()
		if err != nil {
			return nil, err
		}
		if !snap.Unstable {
			return snap, nil
		}
	}
	return nil, errors.New("the kernel kept changing")
}

// liveOn lists the global addresses of a family on the named interface.
func liveOn(snap *rtnl.Snapshot, name string, f rtnl.Family) []netip.Addr {
	link, ok := snap.Link(name)
	if !ok {
		return nil
	}
	var out []netip.Addr
	for _, a := range snap.Addrs[f] {
		if a.Index == link.Index && a.Global() {
			out = append(out, a.Local.Addr())
		}
	}
	return dedupe(out...)
}

func ofFamily(addrs []netip.Addr, f rtnl.Family) []netip.Addr {
	var out []netip.Addr
	for _, a := range addrs {
		if a.IsValid() && a.Is4() == (f == rtnl.V4) {
			out = append(out, a)
		}
	}
	return out
}
