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
	prioTunnelMark    = 93
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
	// LeaveReturnPath, per family, leaves the return-path rules at 94 and 98
	// out of the comparison: a native config without an address leaves them
	// to the transaction that sets the address (MOLEBRIDGE_RULE94=applier).
	// Any other rule at those priorities is still removed (Skipped).
	LeaveReturnPath map[rtnl.Family]bool
	// TempGuard, per family, expects the temporary priority-80 rule that
	// blocks forwarded traffic while rules 90-97 are rebuilt.
	TempGuard map[rtnl.Family]bool
}

// Clone copies the maps and slices so a Spec can be edited without sharing.
func (s Spec) Clone() Spec {
	out := Spec{Config: s.Config}
	out.Config.LAN = append([]netip.Prefix(nil), s.Config.LAN...)
	out.Config.LAN6 = append([]netip.Prefix(nil), s.Config.LAN6...)
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
// 0-98 for native overlays, 1-98 for native sidecars; 0-97 and 102-104
// with gluetun.
func (s Spec) Owned(priority uint32) bool {
	if s.Config.IsNativeSidecar() {
		return priority >= 1 && priority <= PrioBackstop
	}
	if s.Config.IsGluetun() {
		return priority <= 97 || priority >= PrioGluetunMark && priority <= PrioKillSwitch
	}
	return priority <= PrioBackstop
}

// Skipped reports the priorities whose return-path rules are left out of the
// comparison: a rule there in the shape a transaction installs
// (ReturnPathShaped) is neither expected nor removed. Anything else there is
// still a stray (Diff).
func (s Spec) Skipped(f rtnl.Family, priority uint32) bool {
	return !s.Config.IsGluetun() && s.LeaveReturnPath[f] && (priority == PrioReturnPath || priority == PrioBackstop)
}

// returnPathPair is rule 94 for one tunnel address and, natively, the
// backstop at 98 behind it.
func returnPathPair(c Config, f rtnl.Family, a netip.Addr) []rtnl.Rule {
	r := lookup(PrioReturnPath, f, c.Table)
	r.Src, r.IPProto = hostPrefix(a), rtnl.Some(icmp(f))
	out := []rtnl.Rule{r}
	if !c.IsGluetun() {
		// The backstop behind 94: the same packets are unreachable if 94
		// or the exit table's routes are ever gone.
		r = reject(PrioBackstop, f)
		r.Src, r.IPProto = hostPrefix(a), rtnl.Some(icmp(f))
		out = append(out, r)
	}
	return out
}

// ReturnPathShaped reports whether a rule is exactly rule 94 or 98 as the
// contract writes it for some address of the family. Only the address is
// free: another selector, action or table makes it a different rule.
func (s Spec) ReturnPathShaped(f rtnl.Family, r rtnl.Rule) bool {
	if r.Family != f || !r.Src.IsValid() || r.Src.Bits() != r.Src.Addr().BitLen() || (f == rtnl.V4) != r.Src.Addr().Is4() {
		return false
	}
	for _, e := range returnPathPair(s.Config, f, r.Src.Addr()) {
		if e.Priority == r.Priority && equalItems(r.Items(), e.Items()) {
			return true
		}
	}
	return false
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
// gluetun sidecar has none. Rules the Spec leaves out of the comparison are absent.
func (s Spec) Rules(f rtnl.Family) []rtnl.Rule {
	c := s.Config
	if c.IsGluetunSidecar() {
		return nil
	}
	var out []rtnl.Rule
	add := func(r rtnl.Rule) {
		if !s.Skipped(f, r.Priority) {
			out = append(out, r)
		}
	}
	if !c.IsNativeSidecar() {
		guard := lookup(PrioLocalGuard, f, rtnl.TableLocal)
		guard.Flags = rtnl.FIBRuleInvert
		guard.IifName = c.OverlayIf
		add(guard)
		if s.TempGuard[f] {
			r := reject(PrioTempGuard, f)
			r.IifName = c.OverlayIf
			add(r)
		}
	}
	overlay := c.OverlayFor(f)
	if c.IsGluetun() || c.IsNativeSidecar() {
		mark, mask := exactMark(c.ControlMark)
		table := c.HostTable
		if c.IsNativeSidecar() {
			table = rtnl.TableMain
		}
		r := lookup(PrioMarkHost, f, table)
		r.IifName, r.FwMark, r.FwMask = "lo", mark, mask
		add(r)
		r = reject(PrioMarkReject, f)
		r.IifName, r.FwMark, r.FwMask = "lo", mark, mask
		add(r)
	}
	if c.IsNativeSidecar() {
		for _, prefix := range c.LANFor(f) {
			r := lookup(PrioFromTunnel, f, rtnl.TableMain)
			r.IifName, r.Dst = "lo", prefix
			add(r)
		}
		mark, mask := exactMark(c.TunnelMark())
		r := lookup(prioTunnelMark, f, rtnl.TableMain)
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
		for _, r := range returnPathPair(c, f, a) {
			add(r)
		}
	}
	var r rtnl.Rule
	if c.IsNativeSidecar() {
		r = lookup(PrioEgress, f, c.Table)
		r.IifName = "lo"
		add(r)
		r = reject(PrioIngressReject, f)
		r.IifName = "lo"
		add(r)
	} else {
		r = lookup(PrioIngress, f, c.Table)
		r.IifName = c.OverlayIf
		add(r)
		r = lookup(PrioEgress, f, c.Table)
		r.OifName = c.ExitIf
		add(r)
		r = reject(PrioIngressReject, f)
		r.IifName = c.OverlayIf
		add(r)
	}
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
