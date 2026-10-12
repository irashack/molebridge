package contract

import (
	"fmt"
	"sort"

	"github.com/irashack/molebridge/internal/rtnl"
)

// ActionKind is what to do about one rule.
type ActionKind uint8

const (
	// Add installs a missing expected rule.
	Add ActionKind = iota + 1
	// Del removes a rule that is not expected and whose selectors cannot
	// also match an expected rule.
	Del
	// Sub is a rule that is not expected but whose selectors are a subset of
	// an expected rule's. The kernel deletes the first rule that has every
	// attribute it is given, which could then be the expected rule, so the
	// priority is rebuilt behind a copy instead (Rebuild).
	Sub
)

func (k ActionKind) String() string {
	switch k {
	case Add:
		return "add"
	case Del:
		return "del"
	case Sub:
		return "sub"
	}
	return "?"
}

// Action is one step of a repair. For Add, Rule is the expected rule; for Del
// and Sub it is the rule the kernel reported.
type Action struct {
	Kind     ActionKind
	Priority uint32
	Rule     rtnl.Rule
}

func (a Action) String() string { return fmt.Sprintf("%s %d: %s", a.Kind, a.Priority, a.Rule) }

// addOrder is the order missing rules go in: terminal rules first, so nothing
// falls through while the rest go in; 102 and 103, the exceptions, before 104,
// which would block them (rule_actions' END block).
var addOrder = []uint32{97, 98, 89, 92, 102, 103, 104, 1, 80, 88, 90, 91, 94, 95, 96}

// DiffOptions tune a comparison.
type DiffOptions struct {
	// HoldKillSwitch leaves rule 104 out of the additions: the gluetun kill
	// switch waits for the host table its exceptions use.
	HoldKillSwitch bool
}

func itemSet(items []string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, it := range items {
		m[it] = struct{}{}
	}
	return m
}

func equalItems(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func subsetOf(have []string, want []string) bool {
	set := itemSet(want)
	for _, it := range have {
		if _, ok := set[it]; !ok {
			return false
		}
	}
	return true
}

// Diff compares the rules of one family with the Spec and returns the
// actions that restore the contract, in the order to apply them: first the
// Add actions, terminal rules first (see addOrder), then the Sub and Del
// actions in the order the rules were found. A rule at a priority the
// contract owns is expected only if it has exactly an expected rule's
// selectors and action; interface detachment is not looked at (an overlay
// rule exists before NetBird creates the interface).
//
// Nothing is returned when the rules are exactly the expected ones. This is
// rule_actions of routing/contract-rules, with several expected rules allowed
// at one priority for the two return-path pairs of PIA's address change.
func Diff(spec Spec, f rtnl.Family, actual []rtnl.Rule, opt DiffOptions) []Action {
	want := map[uint32][]rtnl.Rule{}
	for _, r := range spec.Rules(f) {
		want[r.Priority] = append(want[r.Priority], r)
	}
	matched := map[uint32][]bool{}
	for p, rules := range want {
		matched[p] = make([]bool, len(rules))
	}
	var removals []Action
	subbed := map[uint32]bool{}
	for _, a := range actual {
		if !spec.Owned(a.Priority) || spec.Skipped(f, a.Priority) {
			continue
		}
		expected, ok := want[a.Priority]
		if !ok {
			removals = append(removals, Action{Kind: Del, Priority: a.Priority, Rule: a})
			continue
		}
		items := a.Items()
		kept, covered := false, false
		for i, e := range expected {
			ei := e.Items()
			if !matched[a.Priority][i] && equalItems(items, ei) {
				matched[a.Priority][i], kept = true, true
				break
			}
			if subsetOf(items, ei) {
				covered = true
			}
		}
		switch {
		case kept:
		case covered:
			if !subbed[a.Priority] {
				subbed[a.Priority] = true
				removals = append(removals, Action{Kind: Sub, Priority: a.Priority, Rule: a})
			}
		default:
			removals = append(removals, Action{Kind: Del, Priority: a.Priority, Rule: a})
		}
	}
	var out []Action
	for _, p := range addOrder {
		for i, e := range want[p] {
			if matched[p][i] {
				continue
			}
			if p == PrioKillSwitch && opt.HoldKillSwitch {
				continue
			}
			out = append(out, Action{Kind: Add, Priority: p, Rule: e})
		}
	}
	return append(out, removals...)
}

// Priorities returns the distinct priorities the actions touch, ascending.
func Priorities(actions []Action) []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for _, a := range actions {
		if !seen[a.Priority] {
			seen[a.Priority] = true
			out = append(out, a.Priority)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// TouchesGuards reports whether any action changes a rule in 90-97, the
// range a native repair does behind the temporary guard.
func TouchesGuards(actions []Action) bool {
	for _, a := range actions {
		if a.Priority >= PrioFromTunnel && a.Priority <= PrioIngressReject {
			return true
		}
	}
	return false
}
