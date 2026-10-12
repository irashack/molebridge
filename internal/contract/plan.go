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
	// ProblemUnprotected: a global address on the tunnel interface has no
	// return-path rule pair (rules 94 and 98, or 94 with gluetun) in the
	// snapshot. Natively the repair adds the pair; where the pair is left to a
	// transaction (an addressless config) only a transaction can.
	ProblemUnprotected Problem = "unprotected"
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
	ExitIf rtnl.Link
	// HostIf is the namespace's host interface (the gluetun backend).
	HostIf  rtnl.Link
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
	// Unprotected: a live tunnel address lacks its return-path pair.
	Unprotected bool
	// Problems are what is still wrong if the plan is not applied; with
	// gluetun, Problems also carries the conditions no action can fix
	// (ProblemNoDefault) and a held kill switch is reported by HoldKillSwitch,
	// not as ProblemRules.
	Problems []Problem
}

// Clean reports that nothing needs doing: the rules, the exit table and the
// host table are what they should be. A missing IPv4 default route through the
// host interface (ProblemNoDefault) is not something a repair can do anything
// about, so it does not make a plan unclean; see Healthy.
func (p Plan) Clean() bool {
	return len(p.Rules) == 0 && len(p.Routes) == 0 && !p.HostRefresh
}

// Healthy is Clean and nothing is wrong that no action can repair, and no live
// tunnel address is without its pair.
func (p Plan) Healthy() bool {
	if !p.Clean() || p.Unprotected {
		return false
	}
	for _, pr := range p.Problems {
		if pr == ProblemNoDefault {
			return false
		}
	}
	return true
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
		// Every global address live on the tunnel interface is protected, in
		// addition to the addresses the expected state names: a pair is added
		// for a live address that lacks one, and the expected state's own
		// entries (kept after a failed change) are never dropped here. Only an
		// address that is neither expected nor live loses its pair.
		spec = s.Clone()
		if !s.LeaveReturnPath[f] {
			for _, a := range liveGlobals(snap, c.ExitIf, f) {
				if !containsAddr(spec.ReturnPath[f], a) {
					spec.ReturnPath[f] = append(spec.ReturnPath[f], a)
				}
			}
		}
		switch {
		case in.TunnelStarting:
			p.Tunnel = TunnelMaybe
		case up && (f == rtnl.V4 || len(spec.ReturnPath[rtnl.V6]) > 0):
			p.Tunnel = TunnelRequired
		}
	}

	if c.IsGluetun() {
		hostIf, _ := snap.Link(c.HostIf)
		p.HostIf = hostIf
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
	if unprotected(snap, c, f) {
		p.Problems = append(p.Problems, ProblemUnprotected)
		p.Unprotected = true
	}
	if len(p.Routes) > 0 {
		p.Problems = append(p.Problems, ProblemExit)
	}
	return p
}

func liveGlobals(snap *rtnl.Snapshot, ifName string, f rtnl.Family) []netip.Addr {
	link, ok := snap.Link(ifName)
	if !ok {
		return nil
	}
	var out []netip.Addr
	for _, a := range snap.Addrs[f] {
		if a.Index == link.Index && a.Global() && !containsAddr(out, a.Local.Addr()) {
			out = append(out, a.Local.Addr())
		}
	}
	return out
}

// unprotected: some live global address on the tunnel interface lacks a rule
// 94 (and, natively, a rule 98) for it in the snapshot.
func unprotected(snap *rtnl.Snapshot, c Config, f rtnl.Family) bool {
	for _, a := range liveGlobals(snap, c.ExitIf, f) {
		var has94, has98 bool
		for _, r := range snap.Rules[f] {
			if r.Src.IsValid() && r.Src.Addr() == a {
				has94 = has94 || r.Priority == PrioReturnPath
				has98 = has98 || r.Priority == PrioBackstop
			}
		}
		if !has94 || (!c.IsGluetun() && !has98) {
			return true
		}
	}
	return false
}
