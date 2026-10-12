package contract

import (
	"net/netip"

	"github.com/irashack/molebridge/internal/rtnl"
)

// Interest returns what a snapshot must contain to judge the contract: the
// exit table, and with gluetun the host table and the main table.
func (s Spec) Interest() rtnl.Interest {
	t := []uint32{s.Config.Table}
	if s.Config.IsGluetun() {
		t = append(t, s.Config.HostTable, rtnl.TableMain)
	}
	return rtnl.Interest{Tables: t}
}

// Problem names one thing wrong with a family, as gr_problems and
// native_problems name them.
type Problem string

// The problems a pass can report.
const (
	// ProblemRules: something at Molebridge's priorities differs.
	ProblemRules Problem = "rules"
	// ProblemExit: the exit table differs.
	ProblemExit Problem = "exit"
	// ProblemHost: the host table differs from the main table's host routes.
	ProblemHost Problem = "host"
	// ProblemNoDefault: IPv4 has no default route through the host interface.
	ProblemNoDefault Problem = "nodefault"
)

// PlanInput is what a pass knows beyond the snapshot.
type PlanInput struct {
	// TunnelStarting is the native backend's bring-up in progress: a default
	// route through the tunnel is allowed but not required.
	TunnelStarting bool
}

// Plan is everything one pass over one family has to do, in the order to do
// it: host table first (rule 103 needs it before rule 104 may go in), then
// the rules, then the exit table.
type Plan struct {
	Family rtnl.Family
	// ExitIf is the tunnel interface as the snapshot shows it.
	ExitIf  rtnl.Link
	Tunnel  TunnelMode
	Address netip.Addr
	// HostRefresh is set when the host table must be flushed and refilled:
	// HostFlush are the routes to remove, HostWant the routes to put in.
	HostRefresh bool
	HostFlush   []rtnl.Route
	HostWant    []HostRoute
	// HoldKillSwitch keeps rule 104 out of the additions: the host table is
	// not yet what rule 103 needs.
	HoldKillSwitch bool
	Rules          []Action
	Routes         []RouteAction
	// Problems are what is still wrong if the plan is not applied; with
	// gluetun, Problems also carries the conditions no action can fix
	// (ProblemNoDefault) and a held kill switch is reported by HoldKillSwitch,
	// not as ProblemRules.
	Problems []Problem
}

// Clean reports that nothing needs doing.
func (p Plan) Clean() bool {
	return len(p.Rules) == 0 && len(p.Routes) == 0 && !p.HostRefresh && len(p.Problems) == 0
}

// PlanFamily judges one family of a snapshot. For the gluetun backend the
// return-path address is the one observed on the tunnel interface, whatever
// the Spec says; natively it is the Spec's.
func (s Spec) PlanFamily(snap *rtnl.Snapshot, f rtnl.Family, in PlanInput) Plan {
	c := s.Config
	p := Plan{Family: f}
	p.ExitIf, _ = snap.Link(c.ExitIf)
	up := p.ExitIf.Index != 0 && p.ExitIf.Up()
	spec := s
	if c.IsGluetun() {
		spec = s.Clone()
		spec.ReturnPath[f] = nil
		if a, ok := snap.GlobalAddr(c.ExitIf, f); ok {
			p.Address = a
			spec.ReturnPath[f] = []netip.Addr{a}
		}
		if p.Address.IsValid() && up {
			p.Tunnel = TunnelRequired
		}
	} else {
		switch {
		case in.TunnelStarting:
			p.Tunnel = TunnelMaybe
		case up && (f == rtnl.V4 || len(s.ReturnPath[rtnl.V6]) > 0):
			p.Tunnel = TunnelRequired
		}
	}

	if c.IsGluetun() {
		hostIf, _ := snap.Link(c.HostIf)
		mainList, _ := HostRoutes(snap.RoutesInTable(f, rtnl.TableMain), hostIf.Index, false)
		hostList, hostOdd := HostRoutes(snap.RoutesInTable(f, c.HostTable), hostIf.Index, true)
		if !HostTableMatches(mainList, hostList, hostOdd) {
			p.HostRefresh = true
			p.HostFlush = snap.RoutesInTable(f, c.HostTable)
			p.HostWant = mainList
			// The kill switch waits for its exceptions' table.
			p.HoldKillSwitch = true
			p.Problems = append(p.Problems, ProblemHost)
		} else if f == rtnl.V4 && !HasIPv4Default(hostList) {
			p.Problems = append(p.Problems, ProblemNoDefault)
		}
	}
	p.Rules = Diff(spec, f, snap.Rules[f], DiffOptions{HoldKillSwitch: p.HoldKillSwitch})
	p.Routes = ExitTableActions(snap.RoutesInTable(f, c.Table), f, c.Table, p.ExitIf.Index, p.Tunnel)
	if len(p.Rules) > 0 {
		p.Problems = append(p.Problems, ProblemRules)
	}
	if len(p.Routes) > 0 {
		p.Problems = append(p.Problems, ProblemExit)
	}
	return p
}
