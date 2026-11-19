package policy

import (
	"net/netip"
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// The states a tunnel replacement (mutator.ReplaceTunnel, design
// docs/design/multi-provider.md step 1) passes through, judged by the model:
// none has an escape, and each rule deletion is one the model approves.

var (
	next4 = netip.MustParseAddr("203.0.113.9")
	next6 = netip.MustParseAddr("2001:db8:3::9")
)

func returnPath(v4, v6 []netip.Addr) map[rtnl.Family][]netip.Addr {
	rp := map[rtnl.Family][]netip.Addr{}
	if len(v4) > 0 {
		rp[rtnl.V4] = v4
	}
	if len(v6) > 0 {
		rp[rtnl.V6] = v6
	}
	return rp
}

// withSpec is s with spec expected and its rules installed (the kernel's own
// rules kept).
func withSpec(s State, spec contract.Spec) State {
	out := s.clone()
	out.Spec = spec
	for _, f := range families {
		out.Rules[f] = append(kernelRules(f), spec.Rules(f)...)
		sortRules(&out, f)
	}
	return out
}

// withoutPair is s without the rules 94 and 98 for a, deleted one at a time;
// it fails the test if the model refuses a deletion or finds an escape.
func withoutPair(t *testing.T, s State, a netip.Addr) State {
	t.Helper()
	f := rtnl.V4
	if a.Is6() {
		f = rtnl.V6
	}
	for _, prio := range []uint32{contract.PrioReturnPath, contract.PrioBackstop} {
		after := s.set(f, func(r []rtnl.Rule) []rtnl.Rule {
			return filter(r, func(x rtnl.Rule) bool { return x.Priority != prio || x.Src.Addr() != a })
		})
		if len(after.Rules[f]) == len(s.Rules[f]) {
			t.Fatalf("no rule %d for %s", prio, a)
		}
		if v := Worsens(s, after); len(v) != 0 {
			t.Fatalf("deleting rule %d for %s: %v", prio, a, v)
		}
		if v := after.Violations(); len(v) != 0 {
			t.Fatalf("after deleting rule %d for %s: %v", prio, a, v)
		}
		s = after
	}
	return s
}

func noViolation(t *testing.T, step string, s State) {
	t.Helper()
	if v := s.Violations(); len(v) != 0 {
		t.Fatalf("%s: %v", step, v)
	}
}

func TestEveryStateOfATunnelReplacementIsAllowed(t *testing.T) {
	for name, tc := range map[string]struct {
		next4, next6 []netip.Addr
		same         bool
	}{
		"new addresses":       {next4: []netip.Addr{next4}, next6: []netip.Addr{next6}},
		"IPv4 only":           {next4: []netip.Addr{next4}},
		"the same addresses":  {next4: []netip.Addr{tunnel4}, next6: []netip.Addr{tunnel6}, same: true},
		"no address (to PIA)": {},
	} {
		t.Run(name, func(t *testing.T) {
			s0 := nativeState(t)
			noViolation(t, "before", s0)
			c := s0.Spec.Config
			old := []netip.Addr{tunnel4, tunnel6}

			// 1. Both pairs expected and installed.
			both := contract.Spec{Config: c, ReturnPath: returnPath(append([]netip.Addr{tunnel4}, tc.next4...), append([]netip.Addr{tunnel6}, tc.next6...))}
			if tc.same {
				both.ReturnPath = s0.Spec.ReturnPath
			}
			s1 := withSpec(s0, both)
			noViolation(t, "both pairs", s1)

			// 2. The route through the old link, approved, then the link.
			s2 := s1.clone()
			for _, f := range families {
				s2.Routes[f][c.Table] = []rtnl.Route{contract.FallbackRoute(f, c.Table)}
			}
			if v := Worsens(s1, s2); len(v) != 0 {
				t.Fatalf("deleting the tunnel route: %v", v)
			}
			s2.ExitIdx, s2.Live = 0, map[rtnl.Family][]netip.Addr{}
			for _, f := range families {
				s2.Locals[f] = filterAddrs(s2.Locals[f], old)
			}
			noViolation(t, "no link", s2)

			// 3. The old pairs, judged without them in the expected state
			// (the owner's retiring set) and with no link.
			nextSpec := contract.Spec{Config: c, ReturnPath: returnPath(tc.next4, tc.next6)}
			if len(tc.next4)+len(tc.next6) == 0 {
				nextSpec.LeaveReturnPath = map[rtnl.Family]bool{rtnl.V4: true, rtnl.V6: true}
			}
			s3 := s2.clone()
			s3.Spec = nextSpec
			if !tc.same {
				for _, a := range old {
					s3 = withoutPair(t, s3, a)
				}
			}

			// 4. The new link.
			s4 := s3.clone()
			s4.ExitIdx = 7
			s4.Live = returnPath(tc.next4, tc.next6)
			for _, f := range families {
				s4.Locals[f] = append(s4.Locals[f], s4.Live[f]...)
				s4.Routes[f][c.Table] = []rtnl.Route{contract.FallbackRoute(f, c.Table), contract.TunnelRoute(f, c.Table, 7)}
			}
			noViolation(t, "the new link", s4)
		})
	}
}

// The order matters: with the old link still up its pairs are refused, and a
// new link before its pairs leaves its address without a return path.
func TestTheReplacementOrderIsWhatTheModelRequires(t *testing.T) {
	s0 := nativeState(t)
	c := s0.Spec.Config
	nextSpec := contract.Spec{Config: c, ReturnPath: returnPath([]netip.Addr{next4}, []netip.Addr{next6})}
	s1 := withSpec(s0, contract.Spec{Config: c, ReturnPath: returnPath([]netip.Addr{tunnel4, next4}, []netip.Addr{tunnel6, next6})})
	s1.Spec = nextSpec // retiring the old addresses while their link is up
	mid := s1.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule {
		return filter(r, func(x rtnl.Rule) bool { return x.Priority != contract.PrioReturnPath || x.Src.Addr() != tunnel4 })
	})
	gone := mid.set(rtnl.V4, func(r []rtnl.Rule) []rtnl.Rule {
		return filter(r, func(x rtnl.Rule) bool { return x.Priority != contract.PrioBackstop || x.Src.Addr() != tunnel4 })
	})
	if v := Worsens(mid, gone); len(v) == 0 {
		t.Error("the old address's last rule deleted while its link is up")
	}

	// The design's literal order: the new link up while only the old pairs exist.
	early := s0.clone()
	early.Spec = nextSpec
	early.ExitIdx, early.Live = 7, returnPath([]netip.Addr{next4}, []netip.Addr{next6})
	for _, f := range families {
		early.Locals[f] = append(filterAddrs(early.Locals[f], []netip.Addr{tunnel4, tunnel6}), early.Live[f]...)
		early.Routes[f][c.Table] = []rtnl.Route{contract.FallbackRoute(f, c.Table), contract.TunnelRoute(f, c.Table, 7)}
	}
	if v := early.Violations(); len(v) == 0 {
		t.Error("a live tunnel address without rules 94 and 98 is not a violation")
	}
}

func filterAddrs(in, drop []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range in {
		keep := true
		for _, d := range drop {
			keep = keep && a != d
		}
		if keep {
			out = append(out, a)
		}
	}
	return out
}
