package mutator

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/policy"
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
	if err := tx.approve(fmt.Sprintf("%s rule %d", r.Family, r.Priority), func(s policy.State) (policy.State, bool) { return s.WithoutRule(r) }); err != nil {
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
	if err := tx.approve(fmt.Sprintf("a %s route in table %d", r.Family, r.Table), func(s policy.State) (policy.State, bool) { return s.WithoutRoute(r) }); err != nil {
		return false, err
	}
	err := tx.m.o.Kernel.DelRoute(r)
	if err != nil && rtnl.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

// confirmed reads the kernel back and reports an error unless every rule is
// there exactly, on a snapshot the kernel held still for. It is the proof
// that a protection is installed: a request the kernel acknowledged, or that
// returned no error, is not.
func (tx *Tx) confirmed(f rtnl.Family, rules ...rtnl.Rule) error {
	snap, err := tx.Snapshot()
	if err != nil {
		return fmt.Errorf("could not read the kernel back: %w", err)
	}
	if snap.Unstable {
		return errors.New("the kernel kept changing; the rules could not be confirmed")
	}
	for _, r := range rules {
		if !hasExact(snap.Rules[f], r) {
			return fmt.Errorf("rule %d is not installed: %s", r.Priority, r)
		}
	}
	return nil
}

// dependents are the expected rules that a removal makes up for: the rule one
// priority later with the same selectors (a protective copy stands in for
// it), and, for the kernel's priority-0 local-delivery rule, the guard at
// priority 1 that replaces it.
func dependents(spec contract.Spec, f rtnl.Family, a contract.Action) []rtnl.Rule {
	if a.Priority == 0 {
		return spec.RulesAt(f, contract.PrioLocalGuard)
	}
	var out []rtnl.Rule
	items := a.Rule.Items()
	for _, e := range spec.RulesAt(f, a.Priority+1) {
		if equalStrings(e.Items(), items) {
			out = append(out, e)
		}
	}
	return out
}

// inGuardRange: rules 90-97, which a native repair changes behind the guard.
func inGuardRange(priority uint32) bool {
	return priority >= contract.PrioFromTunnel && priority <= contract.PrioIngressReject
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
func (tx *Tx) apply(p contract.Plan, removals bool) (mutations int, errs []error) {
	spec := p.Effective
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
	// Every removal that makes up for an addition of this plan waits for the
	// addition to be read back (see dependents): an Add whose request failed,
	// or that the kernel does not show, never costs the rule it was replacing.
	added := map[string]bool{}
	for _, a := range p.Rules {
		if a.Kind == contract.Add {
			added[copyKey(a.Priority, a.Rule)] = true
		}
	}
	// A native repair of rules 90-97 is done behind the temporary guard, and
	// only once the guard is read back in the kernel.
	guardRead := false
	behindGuard := func(priority uint32) error {
		if !spec.TempGuard[f] || !inGuardRange(priority) || guardRead {
			return nil
		}
		if err := tx.confirmed(f, guardRule(spec, f)); err != nil {
			return fmt.Errorf("the temporary guard is not in place: %w", err)
		}
		guardRead = true
		return nil
	}
	for _, a := range p.Rules {
		if !removals && a.Kind != contract.Add {
			continue
		}
		switch a.Kind {
		case contract.Add:
			ch, err := tx.addRule(a.Rule)
			note(ch, err, fmt.Sprintf("could not restore %s rule %d", f, a.Priority))
			if ch {
				tx.Logf("molebridge: added %s rule %d", f, a.Priority)
			}
		case contract.Sub:
			if rebuilt[a.Priority] {
				continue
			}
			rebuilt[a.Priority] = true
			if err := behindGuard(a.Priority); err != nil {
				errs = append(errs, opErr(fmt.Sprintf("left %s rule %d as it is", f, a.Priority), err))
				continue
			}
			n, err := tx.rebuild(spec, f, a.Priority)
			mutations += n
			if err != nil {
				errs = append(errs, err)
			} else {
				tx.Logf("molebridge: rebuilt %s rule %d", f, a.Priority)
			}
		case contract.Del:
			if err := behindGuard(a.Priority); err != nil {
				errs = append(errs, opErr(fmt.Sprintf("kept %s rule %d", f, a.Priority), err))
				continue
			}
			if deps := dependents(spec, f, a); len(deps) > 0 {
				addedNow := false
				for _, d := range deps {
					addedNow = addedNow || added[copyKey(d.Priority, d)]
				}
				if addedNow {
					if err := tx.confirmed(f, deps...); err != nil {
						tx.Logf("molebridge: keeping %s rule %d: it protects until what replaces it is read back", f, a.Priority)
						errs = append(errs, opErr(fmt.Sprintf("kept %s rule %d, which protects until what replaces it is installed", f, a.Priority), err))
						continue
					}
				}
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
	routeAddFailed := false
	for _, ra := range p.Routes {
		switch ra.Kind {
		case contract.AddFallback:
			if err := tx.ReplaceRoute(ra.Route); err != nil {
				routeAddFailed = true
				note(false, err, fmt.Sprintf("restore the %s unreachable fallback in table %d", f, c.Table))
			} else {
				mutations++
				tx.Logf("molebridge: %s unreachable fallback in table %d restored", f, c.Table)
			}
		case contract.AddTunnel:
			if err := tx.ReplaceRoute(ra.Route); err != nil {
				routeAddFailed = true
				note(false, err, fmt.Sprintf("restore the %s tunnel route through %s", f, c.ExitIf))
			} else {
				mutations++
				tx.Logf("molebridge: %s tunnel route through %s restored", f, c.ExitIf)
			}
		case contract.DelRoute:
			if !removals {
				continue
			}
			if routeAddFailed {
				// A route that could not be restored may be what this one is
				// being replaced by.
				errs = append(errs, fmt.Errorf("kept a %s route in table %d: a route this pass adds could not be installed", f, c.Table))
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
// one.
//
// Nothing is deleted at the priority unless every copy is in the kernel: a
// copy whose request failed, for whatever reason and however often, ends the
// rebuild there with the rules found left as they are, and the pass reports
// the failure. The copies are read back on a stable snapshot before the
// priority is cleared, and the refilled rules before the copies go. The
// copies come out only if this call put them in, and stay while anything is
// unconfirmed.
func (tx *Tx) rebuild(spec contract.Spec, f rtnl.Family, priority uint32) (mutations int, err error) {
	want := spec.RulesAt(f, priority)
	if len(want) == 0 {
		return 0, fmt.Errorf("rebuild %s rule %d: nothing is expected there", f, priority)
	}
	previous := priority - 1
	var copies, installed []rtnl.Rule
	for _, w := range want {
		cp := w
		cp.Priority = previous
		ch, aerr := tx.addRule(cp)
		if aerr != nil {
			return mutations, opErr(fmt.Sprintf("could not install the protective copy of %s rule %d; the rules there are left as they are", f, priority), aerr)
		}
		copies = append(copies, cp)
		if ch {
			mutations++
			installed = append(installed, cp)
		}
	}
	if cerr := tx.confirmed(f, copies...); cerr != nil {
		return mutations, opErr(fmt.Sprintf("the protective copies of %s rule %d are not confirmed; the rules there are left as they are", f, priority), cerr)
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
	// re-add failed, or cannot be read back, they stay, and the next pass adds
	// the missing rule before it removes the copy as the stray it then is.
	if firstErr == nil {
		if cerr := tx.confirmed(f, want...); cerr != nil {
			firstErr = opErr(fmt.Sprintf("%s rule %d is not confirmed after the rebuild; its protective copy stays", f, priority), cerr)
		}
	}
	if firstErr == nil {
		for _, cp := range installed {
			ch, _ := tx.delRule(cp)
			if ch {
				mutations++
			}
		}
	}
	return mutations, firstErr
}

// copyKey identifies a rule's selectors and action at a priority.
func copyKey(priority uint32, r rtnl.Rule) string {
	return fmt.Sprintf("%d %q", priority, r.Items())
}
