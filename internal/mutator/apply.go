package mutator

import (
	"fmt"
	"net/netip"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// addRule installs a rule and reports whether the kernel changed.
func (tx *Tx) addRule(r rtnl.Rule) (bool, error) {
	if err := tx.budget(); err != nil {
		return false, err
	}
	err := tx.m.o.Kernel.AddRule(r)
	if err != nil && rtnl.IsExist(err) {
		return false, nil
	}
	return err == nil, err
}

// delRule removes the first rule with every attribute of r and reports
// whether the kernel changed.
func (tx *Tx) delRule(r rtnl.Rule) (bool, error) {
	if err := tx.budget(); err != nil {
		return false, err
	}
	err := tx.m.o.Kernel.DelRule(r)
	if err != nil && rtnl.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func (tx *Tx) delRoute(r rtnl.Route) (bool, error) {
	if err := tx.budget(); err != nil {
		return false, err
	}
	err := tx.m.o.Kernel.DelRoute(r)
	if err != nil && rtnl.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// apply carries out one family's plan in order: the host table, the rules
// (missing ones first, terminal rules first, then the removals), the exit
// table. It never stops at a failure; every failure is returned and the pass's
// verification decides what it meant.
//
// With removals=false (the snapshot was Unstable: the kernel kept changing
// while it was taken) only additions are made: no rule, route or host-table
// entry is removed or rebuilt on evidence that may show a gap or a repeat
// that is not there. A phantom absence must never cost a protection.
func (tx *Tx) apply(spec contract.Spec, p contract.Plan, removals bool) (mutations int, errs []error) {
	f := p.Family
	note := func(changed bool, err error, what string) {
		if changed {
			mutations++
		}
		if err != nil {
			errs = append(errs, opErr(what, err))
		}
	}
	c := spec.Config
	if p.HostRefresh && removals {
		changedAny := false
		for _, r := range p.HostFlush {
			ch, err := tx.delRoute(clearSource(r))
			note(ch, err, fmt.Sprintf("remove a %s route from table %d", f, c.HostTable))
			changedAny = changedAny || ch
		}
		for _, h := range p.HostWant {
			if err := tx.ReplaceRoute(h.Route(f, c.HostTable, p.HostIf.Index)); err != nil {
				note(false, err, fmt.Sprintf("copy a %s host route into table %d", f, c.HostTable))
			} else {
				mutations++
				changedAny = true
			}
		}
		if changedAny {
			tx.Logf("molebridge: %s host table %d refreshed from %s", f, c.HostTable, c.HostIf)
		}
	}
	rebuilt := map[uint32]bool{}
	// Adds that failed. A rule one priority earlier with the same selectors
	// is the copy that protects while the expected rule is missing (see
	// rebuild); it is not removed as a stray until the expected rule is back.
	failedAdd := map[string]bool{}
	for _, a := range p.Rules {
		if !removals && a.Kind != contract.Add {
			continue
		}
		switch a.Kind {
		case contract.Add:
			ch, err := tx.addRule(a.Rule)
			if err != nil {
				failedAdd[copyKey(a.Priority, a.Rule)] = true
			}
			note(ch, err, fmt.Sprintf("could not restore %s rule %d", f, a.Priority))
			if ch {
				tx.Logf("molebridge: added %s rule %d", f, a.Priority)
			}
		case contract.Sub:
			if rebuilt[a.Priority] {
				continue
			}
			rebuilt[a.Priority] = true
			n, err := tx.rebuild(spec, f, a.Priority)
			mutations += n
			if err != nil {
				errs = append(errs, err)
			} else {
				tx.Logf("molebridge: rebuilt %s rule %d", f, a.Priority)
			}
		case contract.Del:
			if failedAdd[copyKey(a.Priority+1, a.Rule)] {
				tx.Logf("molebridge: keeping %s rule %d: it protects while rule %d cannot be restored", f, a.Priority, a.Priority+1)
				continue
			}
			ch, err := tx.delRule(a.Rule)
			if err != nil && len(spec.RulesAt(f, a.Priority)) == 0 {
				// The attributes were refused (a selector the kernel will
				// not take back); nothing is expected at this priority, so
				// removing whatever is first there is safe.
				var gone bool
				gone, err = tx.DelRulePriority(f, a.Priority)
				ch = gone
			}
			note(ch, err, fmt.Sprintf("could not remove %s rule %d: %s", f, a.Priority, a.Rule))
			if ch {
				tx.Logf("molebridge: removed %s rule %d: %s", f, a.Priority, a.Rule)
			}
		}
	}
	for _, ra := range p.Routes {
		switch ra.Kind {
		case contract.AddFallback:
			if err := tx.ReplaceRoute(ra.Route); err != nil {
				note(false, err, fmt.Sprintf("restore the %s unreachable fallback in table %d", f, c.Table))
			} else {
				mutations++
				tx.Logf("molebridge: %s unreachable fallback in table %d restored", f, c.Table)
			}
		case contract.AddTunnel:
			if err := tx.ReplaceRoute(ra.Route); err != nil {
				note(false, err, fmt.Sprintf("restore the %s tunnel route through %s", f, c.ExitIf))
			} else {
				mutations++
				tx.Logf("molebridge: %s tunnel route through %s restored", f, c.ExitIf)
			}
		case contract.DelRoute:
			if !removals {
				continue
			}
			ch, err := tx.delRoute(clearSource(ra.Route))
			note(ch, err, fmt.Sprintf("remove a %s route from table %d", f, c.Table))
		}
	}
	return mutations, errs
}

// clearSource drops the preferred source so a delete names the destination,
// the device, the gateway and the metric, as the shell's selectors did.
func clearSource(r rtnl.Route) rtnl.Route {
	r.PrefSrc = netip.Addr{}
	return r
}

// rebuild replaces everything at a priority with its expected rules without a
// gap: a copy of each goes in one priority earlier, the priority is cleared and
// refilled, then the copies go. Each copy's selectors or action differ from
// the expected rule at that earlier priority, so removing it cannot take that
// one. The copies come out only if this call put them in.
func (tx *Tx) rebuild(spec contract.Spec, f rtnl.Family, priority uint32) (mutations int, err error) {
	want := spec.RulesAt(f, priority)
	if len(want) == 0 {
		return 0, fmt.Errorf("rebuild %s rule %d: nothing is expected there", f, priority)
	}
	previous := priority - 1
	var copies []rtnl.Rule
	for _, w := range want {
		cp := w
		cp.Priority = previous
		ch, aerr := tx.addRule(cp)
		if aerr != nil && !tx.stillAlive() {
			return mutations, aerr
		}
		if ch {
			mutations++
			copies = append(copies, cp)
		}
	}
	for i := 0; i < 32; i++ {
		gone, derr := tx.DelRulePriority(f, priority)
		if derr != nil {
			return mutations, opErr(fmt.Sprintf("clear %s priority %d", f, priority), derr)
		}
		if !gone {
			break
		}
		mutations++
	}
	var firstErr error
	for _, w := range want {
		ch, aerr := tx.addRule(w)
		if ch {
			mutations++
		}
		if aerr != nil && firstErr == nil {
			firstErr = opErr(fmt.Sprintf("could not restore %s rule %d", f, priority), aerr)
		}
	}
	// The copies protect until the expected rules are confirmed back: if any
	// re-add failed they stay, and the next pass adds the missing rule before
	// it removes the copy as the stray it then is.
	if firstErr == nil {
		for _, cp := range copies {
			ch, _ := tx.delRule(cp)
			if ch {
				mutations++
			}
		}
	}
	return mutations, firstErr
}

func (tx *Tx) stillAlive() bool { return tx.ctx.Err() == nil }

// copyKey identifies a rule's selectors and action at a priority.
func copyKey(priority uint32, r rtnl.Rule) string {
	return fmt.Sprintf("%d %q", priority, r.Items())
}
