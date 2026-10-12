package contract

import (
	"net/netip"
	"sort"

	"github.com/irashack/molebridge/internal/rtnl"
)

// Priorities of the contract's rules.
const (
	PrioLocalGuard    = 1
	PrioTempGuard     = 80
	PrioMarkHost      = 88
	PrioMarkReject    = 89
	PrioFromTunnel    = 90
	PrioOverlayMain   = 91
	PrioOverlayReject = 92
	PrioReturnPath    = 94
	PrioIngress       = 95
	PrioEgress        = 96
	PrioIngressReject = 97
	PrioBackstop      = 98
	PrioGluetunMark   = 102
	PrioHostSubnets   = 103
	PrioKillSwitch    = 104
)

// Spec is the contract at one moment: what the kernel must hold, for both
// families. It is a value; the mutation owner replaces it as transactions
// begin and end (internal/mutator).
type Spec struct {
	Config Config
	// ReturnPath lists, per family, the tunnel addresses whose rule 94 (and,
	// natively, 98) are expected. The native backend fills it from the tunnel
	// config; the gluetun backend from the address observed on the tunnel
	// interface. More than one address is expected only while PIA's address
	// changes.
	ReturnPath map[rtnl.Family][]netip.Addr
	// LeaveReturnPath, per family, leaves rules 94 and 98 out of the
	// comparison entirely: a native config without an address leaves them to
	// the transaction that sets the address (MOLEBRIDGE_RULE94=applier).
	LeaveReturnPath map[rtnl.Family]bool
	// TempGuard, per family, expects the temporary priority-80 rule that
	// blocks forwarded traffic while rules 90-97 are rebuilt.
	TempGuard map[rtnl.Family]bool
}

// Clone copies the maps so a Spec can be edited without sharing.
func (s Spec) Clone() Spec {
	out := Spec{Config: s.Config}
	out.ReturnPath = map[rtnl.Family][]netip.Addr{}
	for f, a := range s.ReturnPath {
		out.ReturnPath[f] = append([]netip.Addr(nil), a...)
	}
	out.LeaveReturnPath = map[rtnl.Family]bool{}
	for f, v := range s.LeaveReturnPath {
		out.LeaveReturnPath[f] = v
	}
	out.TempGuard = map[rtnl.Family]bool{}
	for f, v := range s.TempGuard {
		out.TempGuard[f] = v
	}
	return out
}

// Owned reports whether a priority belongs to Molebridge for the backend:
// 0-98 natively; 0-97 and 102-104 with gluetun.
func (s Spec) Owned(priority uint32) bool {
	if s.Config.IsGluetun() {
		return priority <= 97 || priority >= PrioGluetunMark && priority <= PrioKillSwitch
	}
	return priority <= PrioBackstop
}

// Skipped reports priorities left out of the comparison.
func (s Spec) Skipped(f rtnl.Family, priority uint32) bool {
	return !s.Config.IsGluetun() && s.LeaveReturnPath[f] && (priority == PrioReturnPath || priority == PrioBackstop)
}

func hostPrefix(a netip.Addr) netip.Prefix { return netip.PrefixFrom(a, a.BitLen()) }

func icmp(f rtnl.Family) uint8 {
	if f == rtnl.V6 {
		return 58
	}
	return 1
}

func lookup(priority uint32, f rtnl.Family, table uint32) rtnl.Rule {
	return rtnl.Rule{Family: f, Priority: priority, Action: rtnl.FRActToTbl, Table: table}
}

func reject(priority uint32, f rtnl.Family) rtnl.Rule {
	return rtnl.Rule{Family: f, Priority: priority, Action: rtnl.FRActUnreachable}
}

func exactMark(mark uint32) (rtnl.Opt[uint32], rtnl.Opt[uint32]) {
	return rtnl.Some(mark), rtnl.Some(uint32(0xffffffff))
}

// Rules returns the rules expected for a family, in priority order. A
// sidecar has none. Rules the Spec leaves out of the comparison are absent.
func (s Spec) Rules(f rtnl.Family) []rtnl.Rule {
	c := s.Config
	if c.IsSidecar() {
		return nil
	}
	var out []rtnl.Rule
	add := func(r rtnl.Rule) {
		if !s.Skipped(f, r.Priority) {
			out = append(out, r)
		}
	}
	guard := lookup(PrioLocalGuard, f, rtnl.TableLocal)
	guard.Flags = rtnl.FIBRuleInvert
	guard.IifName = c.OverlayIf
	add(guard)
	if s.TempGuard[f] {
		r := reject(PrioTempGuard, f)
		r.IifName = c.OverlayIf
		add(r)
	}
	overlay := c.OverlayFor(f)
	if c.IsGluetun() {
		mark, mask := exactMark(c.ControlMark)
		r := lookup(PrioMarkHost, f, c.HostTable)
		r.IifName, r.FwMark, r.FwMask = "lo", mark, mask
		add(r)
		r = reject(PrioMarkReject, f)
		r.IifName, r.FwMark, r.FwMask = "lo", mark, mask
		add(r)
	}
	if overlay.IsValid() {
		r := lookup(PrioFromTunnel, f, rtnl.TableMain)
		r.IifName, r.Dst = c.ExitIf, overlay
		add(r)
		if c.IsGluetun() {
			// What the exit itself sends to the overlay (ICMP errors to
			// clients) may use only NetBird's overlay route.
			r = lookup(PrioOverlayMain, f, rtnl.TableMain)
			r.IifName, r.Dst, r.SuppressPrefixLen = "lo", overlay, rtnl.Some(uint32(0))
			add(r)
			r = reject(PrioOverlayReject, f)
			r.IifName, r.Dst = "lo", overlay
			add(r)
		}
	}
	for _, a := range s.ReturnPath[f] {
		r := lookup(PrioReturnPath, f, c.Table)
		r.Src, r.IPProto = hostPrefix(a), rtnl.Some(icmp(f))
		add(r)
		if !c.IsGluetun() {
			// The backstop behind 94: the same packets are unreachable if 94
			// or the exit table's routes are ever gone.
			r = reject(PrioBackstop, f)
			r.Src, r.IPProto = hostPrefix(a), rtnl.Some(icmp(f))
			add(r)
		}
	}
	r := lookup(PrioIngress, f, c.Table)
	r.IifName = c.OverlayIf
	add(r)
	r = lookup(PrioEgress, f, c.Table)
	r.OifName = c.ExitIf
	add(r)
	r = reject(PrioIngressReject, f)
	r.IifName = c.OverlayIf
	add(r)
	if c.IsGluetun() {
		mark, mask := exactMark(GluetunMark)
		r = lookup(PrioGluetunMark, f, rtnl.TableMain)
		r.IifName, r.FwMark, r.FwMask = "lo", mark, mask
		add(r)
		r = lookup(PrioHostSubnets, f, c.HostTable)
		r.IifName, r.SuppressPrefixLen = "lo", rtnl.Some(uint32(0))
		add(r)
		r = reject(PrioKillSwitch, f)
		r.IifName = "lo"
		add(r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Priority < out[j].Priority })
	return out
}

// RulesAt returns the expected rules of a family at one priority.
func (s Spec) RulesAt(f rtnl.Family, priority uint32) []rtnl.Rule {
	var out []rtnl.Rule
	for _, r := range s.Rules(f) {
		if r.Priority == priority {
			out = append(out, r)
		}
	}
	return out
}
