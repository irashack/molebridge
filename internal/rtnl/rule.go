package rtnl

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Rule is one FIB rule as the kernel reports it. Only what the kernel put on
// the wire is set; Opt fields distinguish "absent" from zero.
type Rule struct {
	Family   Family
	Priority uint32
	// Action is fib_rule_hdr.action (FRAct*). Table is the table of a
	// FRActToTbl rule; the kernel reports 0 for other actions.
	Action uint8
	Table  uint32
	// Flags is fib_rule_hdr.flags, verbatim.
	Flags uint32
	Tos   uint8
	// Src and Dst are unset (invalid) for "from all" and "to anywhere".
	Src, Dst netip.Prefix

	IifName, OifName string

	FwMark, FwMask    Opt[uint32]
	IPProto           Opt[uint8]
	SuppressPrefixLen Opt[uint32]
	SuppressIfGroup   Opt[uint32]
	Goto              Opt[uint32]
	L3Mdev            Opt[uint8]
	// Protocol is who installed the rule (RTPROT_*). It is metadata, not a
	// selector, and is ignored when rules are compared.
	Protocol Opt[uint8]

	// Unknown holds every attribute this package does not model (flow
	// realms, tunnel ids, uid and port ranges, DSCP, attributes of newer
	// kernels) and every modeled attribute whose payload had the wrong shape,
	// verbatim and in arrival order. A non-empty Unknown means the rule has
	// selectors the contract never installs.
	Unknown []RawAttr

	// Bad is set when the header and attributes disagree (a prefix length
	// without its address, an address of the wrong size).
	Bad bool
}

// Invert reports FIB_RULE_INVERT, the "not" in "not iif wt0 lookup local".
func (r Rule) Invert() bool { return r.Flags&FIBRuleInvert != 0 }

// IifDetached reports that the iif names an interface that does not exist.
func (r Rule) IifDetached() bool { return r.Flags&FIBRuleIifDetached != 0 }

// OifDetached reports that the oif names an interface that does not exist.
func (r Rule) OifDetached() bool { return r.Flags&FIBRuleOifDetached != 0 }

// ExtraFlags returns flag bits that are neither bookkeeping (permanent,
// find-saddr), nor the invert and detached bits the contract understands.
func (r Rule) ExtraFlags() uint32 {
	return r.Flags &^ (FIBRulePermanent | FIBRuleInvert | FIBRuleIifDetached | FIBRuleOifDetached | FIBRuleFindSaddr)
}

// unsetSuppress is how the kernel reports a rule without a suppressor.
const unsetSuppress = 0xffffffff

// DecodeRule parses the payload of an RTM_NEWRULE or RTM_DELRULE message (the
// bytes after the netlink header).
func DecodeRule(data []byte) (Rule, error) {
	if len(data) < 12 {
		return Rule{}, fmt.Errorf("%w: rule header is %d bytes", ErrMalformed, len(data))
	}
	family, ok := FamilyOfAF(data[0])
	if !ok {
		return Rule{}, fmt.Errorf("%w: rule of family %d", ErrMalformed, data[0])
	}
	r := Rule{
		Family: family,
		Tos:    data[3],
		Action: data[7],
		Flags:  native.Uint32(data[8:12]),
	}
	dstLen, srcLen := int(data[1]), int(data[2])
	headerTable := uint32(data[4])
	attrs, err := parseAttrs(data[12:])
	if err != nil {
		return Rule{}, err
	}
	var haveDst, haveSrc, haveTable bool
	var tableAttr uint32
	for _, a := range attrs {
		keep := func() { r.Unknown = append(r.Unknown, RawAttr{Type: a.typ, Data: cloneBytes(a.data)}) }
		switch a.typ {
		case fraDst, fraSrc:
			addr, ok := attrAddr(family, a.data)
			if !ok {
				keep()
				r.Bad = true
				continue
			}
			bits := dstLen
			if a.typ == fraSrc {
				bits = srcLen
			}
			if bits > family.Bits() {
				r.Bad = true
				bits = family.Bits()
			}
			if a.typ == fraDst {
				haveDst = true
				r.Dst = netip.PrefixFrom(addr, bits)
			} else {
				haveSrc = true
				r.Src = netip.PrefixFrom(addr, bits)
			}
		case fraIifname, fraOifname:
			s, ok := attrString(a.data)
			if !ok {
				keep()
				continue
			}
			if a.typ == fraIifname {
				r.IifName = s
			} else {
				r.OifName = s
			}
		case fraGoto:
			if v, ok := attrU32(a.data); ok {
				r.Goto = Some(v)
			} else {
				keep()
			}
		case fraPriority:
			if v, ok := attrU32(a.data); ok {
				r.Priority = v
			} else {
				keep()
			}
		case fraFwmark:
			if v, ok := attrU32(a.data); ok {
				r.FwMark = Some(v)
			} else {
				keep()
			}
		case fraFwmask:
			if v, ok := attrU32(a.data); ok {
				r.FwMask = Some(v)
			} else {
				keep()
			}
		case fraSuppressIfgrp:
			// The kernel reports -1 (all ones) for "not set".
			if v, ok := attrU32(a.data); ok {
				if v != unsetSuppress {
					r.SuppressIfGroup = Some(v)
				}
			} else {
				keep()
			}
		case fraSuppressPrefix:
			if v, ok := attrU32(a.data); ok {
				if v != unsetSuppress {
					r.SuppressPrefixLen = Some(v)
				}
			} else {
				keep()
			}
		case fraTable:
			if v, ok := attrU32(a.data); ok {
				haveTable, tableAttr = true, v
			} else {
				keep()
			}
		case fraL3mdev:
			if v, ok := attrU8(a.data); ok {
				r.L3Mdev = Some(v)
			} else {
				keep()
			}
		case fraProtocol:
			if v, ok := attrU8(a.data); ok {
				r.Protocol = Some(v)
			} else {
				keep()
			}
		case fraIPProto:
			if v, ok := attrU8(a.data); ok {
				r.IPProto = Some(v)
			} else {
				keep()
			}
		case fraPad:
			// Alignment only; carries no selector.
		default:
			keep()
		}
	}
	if dstLen > 0 && !haveDst || srcLen > 0 && !haveSrc {
		r.Bad = true
	}
	if haveTable {
		r.Table = tableAttr
	} else {
		r.Table = headerTable
	}
	return r, nil
}

// Marshal encodes the rule as the payload of a rule request. Raw attributes
// are sent back unchanged, so a rule read from a dump can be deleted exactly.
func (r Rule) Marshal() []byte {
	hdr := make([]byte, 12)
	hdr[0] = r.Family.AF()
	if r.Dst.IsValid() {
		hdr[1] = uint8(r.Dst.Bits())
	}
	if r.Src.IsValid() {
		hdr[2] = uint8(r.Src.Bits())
	}
	hdr[3] = r.Tos
	if r.Table < 256 {
		hdr[4] = uint8(r.Table)
	} else {
		hdr[4] = tableCompat
	}
	hdr[7] = r.Action
	native.PutUint32(hdr[8:12], r.Flags&^(FIBRulePermanent|FIBRuleIifDetached|FIBRuleOifDetached|FIBRuleFindSaddr))
	b := hdr
	if r.Dst.IsValid() {
		b = appendAttr(b, fraDst, addrBytes(r.Dst.Addr()))
	}
	if r.Src.IsValid() {
		b = appendAttr(b, fraSrc, addrBytes(r.Src.Addr()))
	}
	if r.IifName != "" {
		b = appendAttrStr(b, fraIifname, r.IifName)
	}
	if r.OifName != "" {
		b = appendAttrStr(b, fraOifname, r.OifName)
	}
	if r.Goto.OK {
		b = appendAttrU32(b, fraGoto, r.Goto.V)
	}
	b = appendAttrU32(b, fraPriority, r.Priority)
	if r.FwMark.OK {
		b = appendAttrU32(b, fraFwmark, r.FwMark.V)
	}
	if r.FwMask.OK {
		b = appendAttrU32(b, fraFwmask, r.FwMask.V)
	}
	if r.SuppressIfGroup.OK {
		b = appendAttrU32(b, fraSuppressIfgrp, r.SuppressIfGroup.V)
	}
	if r.SuppressPrefixLen.OK {
		b = appendAttrU32(b, fraSuppressPrefix, r.SuppressPrefixLen.V)
	}
	if r.Action == FRActToTbl || r.Table != 0 {
		b = appendAttrU32(b, fraTable, r.Table)
	}
	if r.L3Mdev.OK {
		b = appendAttrU8(b, fraL3mdev, r.L3Mdev.V)
	}
	if r.Protocol.OK {
		b = appendAttrU8(b, fraProtocol, r.Protocol.V)
	}
	if r.IPProto.OK {
		b = appendAttrU8(b, fraIPProto, r.IPProto.V)
	}
	for _, u := range r.Unknown {
		b = appendAttr(b, u.Type, u.Data)
	}
	return b
}

// PriorityOnly encodes a delete request that names only the family and the
// priority: the kernel removes the first rule at that priority, whatever its
// selectors, as `ip rule del priority N` does.
func PriorityOnly(f Family, priority uint32) []byte {
	hdr := make([]byte, 12)
	hdr[0] = f.AF()
	return appendAttrU32(hdr, fraPriority, priority)
}

// Items returns the rule as a sorted list of canonical "key value" strings
// covering every selector and the action, the form `ip rule show` prints
// (without the priority, the detached markers and the installer). Two rules
// that select and act alike have equal Items; a rule with an attribute the
// contract never uses has an item nothing expected has.
//
// An invalid or unreadable rule yields an item beginning "bad", so it equals
// nothing.
func (r Rule) Items() []string {
	var s []string
	add := func(format string, a ...any) { s = append(s, fmt.Sprintf(format, a...)) }
	if r.Invert() {
		s = append(s, "not")
	}
	if r.Src.IsValid() {
		add("from %s", r.Src.Masked())
	} else {
		s = append(s, "from all")
	}
	if r.Dst.IsValid() {
		add("to %s", r.Dst.Masked())
	}
	if r.Tos != 0 {
		add("tos %d", r.Tos)
	}
	if r.FwMark.OK || r.FwMask.OK {
		mask := uint32(0xffffffff)
		if r.FwMask.OK {
			mask = r.FwMask.V
		}
		if mask == 0xffffffff {
			add("fwmark %#x", r.FwMark.V)
		} else {
			add("fwmark %#x/%#x", r.FwMark.V, mask)
		}
	}
	if r.IifName != "" {
		add("iif %s", r.IifName)
	}
	if r.OifName != "" {
		add("oif %s", r.OifName)
	}
	if r.IPProto.OK {
		add("ipproto %s", protoName(r.IPProto.V))
	}
	if r.L3Mdev.OK {
		add("l3mdev %d", r.L3Mdev.V)
	}
	if r.SuppressPrefixLen.OK {
		add("suppress_prefixlength %d", r.SuppressPrefixLen.V)
	}
	if r.SuppressIfGroup.OK {
		add("suppress_ifgroup %d", r.SuppressIfGroup.V)
	}
	switch r.Action {
	case FRActToTbl:
		add("lookup %d", r.Table)
	case FRActGoto:
		if r.Goto.OK {
			add("goto %d", r.Goto.V)
		} else {
			s = append(s, "goto")
		}
	case FRActNop:
		s = append(s, "nop")
	case FRActBlackhole:
		s = append(s, "blackhole")
	case FRActUnreachable:
		s = append(s, "unreachable")
	case FRActProhibit:
		s = append(s, "prohibit")
	default:
		add("action %d", r.Action)
	}
	if r.Action != FRActToTbl && r.Table != 0 {
		add("table %d", r.Table)
	}
	if r.Action != FRActGoto && r.Goto.OK {
		add("goto %d", r.Goto.V)
	}
	if x := r.ExtraFlags(); x != 0 {
		add("flags %#x", x)
	}
	for _, u := range r.Unknown {
		add("attr %d:%x", u.Type, u.Data)
	}
	if r.Bad {
		s = append(s, "bad")
	}
	sort.Strings(s)
	// Duplicate items collapse, as the shell's associative array did.
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func protoName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 58:
		return "ipv6-icmp"
	}
	return strconv.Itoa(int(p))
}

// String renders the rule roughly as `ip rule show` does, for logs. It never
// contains anything secret.
func (r Rule) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d:", r.Priority)
	for _, it := range r.Items() {
		b.WriteByte(' ')
		b.WriteString(it)
	}
	if r.IifDetached() || r.OifDetached() {
		b.WriteString(" [detached]")
	}
	return b.String()
}
