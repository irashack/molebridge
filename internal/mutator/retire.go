package mutator

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// ErrReturnPathLive says a return-path address was not retired because it is
// still on an interface: its pair stays and so does the expectation of it.
var ErrReturnPathLive = errors.New("mutator: the return-path address is still live; it was not retired")

// RetireReturnPath is the provider's word that a return-path address is no
// longer in use (the tunnel lost it: the interface was recreated, or the
// provider handed out another). It is ONE job of the owner that takes the
// address out of the expected return-path set and deletes its pair (rules 94
// and 98), so that nothing is left to fight over: the repairer does not add
// back a pair for an address that was retired, and the provider's own cleanup
// does not run against a pair the repairer defends.
//
// Only an address that is live nowhere is retired. It reads the kernel first,
// and from a stable look: an address on any interface, or a snapshot that cannot
// be trusted, refuses (ErrReturnPathLive, or an error saying it is unverified)
// and changes nothing, so the caller retries on its next tick. Every live
// address stays protected exactly as before. The pair's deletion is the usual
// approved one (internal/policy): the address is not counted as expected for it,
// and it must not be live.
//
// When the set becomes empty on an exit that left rules 94 and 98 to their
// owner from the start (a tunnel config with no address), that arrangement is
// restored: the owner's own later additions are not strays. An address that is
// not expected and has no pair is already retired: no change, no error. The
// gluetun backend derives the return-path address from the tunnel's own
// address on every pass, so there is nothing to retire there (a pair of an
// address that went away is a stray and goes with the next pass).
func (m *Mutator) RetireReturnPath(ctx context.Context, f rtnl.Family, addr netip.Addr) error {
	return m.Do(ctx, fmt.Sprintf("retire the %s return-path address", f), func(tx *Tx) error {
		spec := tx.Spec()
		if spec.Config.IsGluetunSidecar() || spec.Config.IsGluetun() {
			return nil
		}
		if !addr.IsValid() || (f == rtnl.V4) != addr.Is4() {
			return fmt.Errorf("the %s return-path address is not an address of that family", f)
		}
		var snap *rtnl.Snapshot
		var err error
		for i := 0; i < settleLooks; i++ {
			if snap, err = tx.Snapshot(); err != nil {
				return opErr("read the tunnel addresses; the return-path pair stays", err)
			}
			if !snap.Unstable {
				break
			}
		}
		if snap.Unstable {
			return errors.New("the kernel kept changing; the return-path address cannot be retired until a stable look")
		}
		for _, a := range snap.Addrs[f] {
			if a.Local.Addr() == addr {
				return ErrReturnPathLive
			}
		}
		expected := containsAddr(spec.ReturnPath[f], addr)
		// The pair as the contract writes it for this address.
		probe := withReturnPath(spec, f, []netip.Addr{addr})
		var present []rtnl.Rule
		for _, p := range []uint32{contract.PrioReturnPath, contract.PrioBackstop} {
			for _, want := range probe.RulesAt(f, p) {
				if hasExact(snap.Rules[f], want) {
					present = append(present, want)
				}
			}
		}
		if !expected && len(present) == 0 {
			return nil
		}
		// The address is going: its pair may be deleted once the address is
		// known not to be live, which was just read.
		tx.retiring = map[netip.Addr]bool{addr: true}
		for _, r := range present {
			if err := tx.DelRule(r); err != nil {
				return opErr(fmt.Sprintf("remove the %s return-path pair of a retired address", f), err)
			}
		}
		var rest []netip.Addr
		for _, a := range spec.ReturnPath[f] {
			if a != addr {
				rest = append(rest, a)
			}
		}
		next := withReturnPath(spec, f, rest)
		if len(rest) == 0 && m.o.Spec.LeaveReturnPath[f] {
			next.LeaveReturnPath[f] = true
		}
		tx.SetSpec(next)
		tx.retiring = nil
		if res := tx.reconcile("retired a return-path address"); !res.ContractHolds {
			return fmt.Errorf("the %s routing could not be confirmed after the retirement: %w", f, orUnverified(res.Err))
		}
		return nil
	})
}
