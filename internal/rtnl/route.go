package rtnl

import (
	"fmt"
	"net/netip"
)

// Route is one route as the kernel reports it. Only what the contract's
// checks read is modeled; everything else is counted in Other.
type Route struct {
	Family Family
	// Dst is the destination; a default route is a zero-length prefix.
	Dst   netip.Prefix
	Table uint32
	Type  uint8
	Scope uint8
	// Protocol is rtm_protocol (RTPROT_*), metadata only.
	Protocol uint8
	Flags    uint32
	Oif      Opt[uint32]
	Gateway  netip.Addr
	PrefSrc  netip.Addr
	// Metric is RTA_PRIORITY, 0 when absent.
	Metric uint32
	Tos    uint8
	// Src is the route's source selector (RTA_SRC with the header's source
	// prefix length: an IPv6 source-specific route), invalid when absent.
	Src netip.Prefix
	// Iif is an input-interface selector (RTA_IIF), set only on routes that
	// match forwarded traffic arriving on that interface.
	Iif Opt[uint32]
	// Via, MultiPath, NHID and Encap record attributes that make a route
	// something other than a plain device or gateway route.
	Via       bool
	MultiPath bool
	NHID      Opt[uint32]
	Encap     bool
	// Other counts attributes that were read and ignored (metrics, cache
	// info, router preference).
	Other int
}

// Unconditional reports a route that applies to every packet its destination
// covers: no TOS, source or input-interface selector narrows it. A route with
// one is a different route, whatever else it shares with the one the contract
// installs.
func (r Route) Unconditional() bool { return r.Tos == 0 && !r.Src.IsValid() && !r.Iif.OK }

// IsDefault reports a zero-length destination.
func (r Route) IsDefault() bool { return r.Dst.IsValid() && r.Dst.Bits() == 0 }

// LinkDown reports RTNH_F_LINKDOWN.
func (r Route) LinkDown() bool { return r.Flags&RTNHFLinkdown != 0 }

// OnLink reports RTNH_F_ONLINK.
func (r Route) OnLink() bool { return r.Flags&RTNHFOnlink != 0 }

// DecodeRoute parses the payload of an RTM_NEWROUTE or RTM_DELROUTE message.
func DecodeRoute(data []byte) (Route, error) {
	if len(data) < 12 {
		return Route{}, fmt.Errorf("%w: route header is %d bytes", ErrMalformed, len(data))
	}
	family, ok := FamilyOfAF(data[0])
	if !ok {
		return Route{}, fmt.Errorf("%w: route of family %d", ErrMalformed, data[0])
	}
	r := Route{
		Family:   family,
		Tos:      data[3],
		Table:    uint32(data[4]),
		Protocol: data[5],
		Scope:    data[6],
		Type:     data[7],
		Flags:    native.Uint32(data[8:12]),
	}
	dstLen := int(data[1])
	if dstLen > family.Bits() {
		return Route{}, fmt.Errorf("%w: route prefix length %d", ErrMalformed, dstLen)
	}
	srcLen := int(data[2])
	if srcLen > family.Bits() {
		return Route{}, fmt.Errorf("%w: route source prefix length %d", ErrMalformed, srcLen)
	}
	zero := netip.IPv4Unspecified()
	if family == V6 {
		zero = netip.IPv6Unspecified()
	}
	r.Dst = netip.PrefixFrom(zero, 0)
	attrs, err := parseAttrs(data[12:])
	if err != nil {
		return Route{}, err
	}
	haveDst := false
	for _, a := range attrs {
		switch a.typ {
		case rtaDst:
			addr, ok := attrAddr(family, a.data)
			if !ok {
				return Route{}, fmt.Errorf("%w: route destination", ErrMalformed)
			}
			r.Dst = netip.PrefixFrom(addr, dstLen)
			haveDst = true
		case rtaSrc:
			addr, ok := attrAddr(family, a.data)
			if !ok {
				return Route{}, fmt.Errorf("%w: route source selector", ErrMalformed)
			}
			r.Src = netip.PrefixFrom(addr, srcLen)
		case rtaIif:
			if v, ok := attrU32(a.data); ok {
				r.Iif = Some(v)
			} else {
				return Route{}, fmt.Errorf("%w: route iif", ErrMalformed)
			}
		case rtaOif:
			if v, ok := attrU32(a.data); ok {
				r.Oif = Some(v)
			} else {
				return Route{}, fmt.Errorf("%w: route oif", ErrMalformed)
			}
		case rtaGateway:
			addr, ok := attrAddr(family, a.data)
			if !ok {
				return Route{}, fmt.Errorf("%w: route gateway", ErrMalformed)
			}
			r.Gateway = addr
		case rtaPrefsrc:
			addr, ok := attrAddr(family, a.data)
			if !ok {
				return Route{}, fmt.Errorf("%w: route source", ErrMalformed)
			}
			r.PrefSrc = addr
		case rtaPriority:
			if v, ok := attrU32(a.data); ok {
				r.Metric = v
			} else {
				return Route{}, fmt.Errorf("%w: route metric", ErrMalformed)
			}
		case rtaTable:
			if v, ok := attrU32(a.data); ok {
				r.Table = v
			} else {
				return Route{}, fmt.Errorf("%w: route table", ErrMalformed)
			}
		case rtaMultipath:
			r.MultiPath = true
		case rtaVia:
			r.Via = true
		case rtaNHID:
			if v, ok := attrU32(a.data); ok {
				r.NHID = Some(v)
			} else {
				r.NHID = Some(uint32(0))
			}
		case rtaEncap, rtaEncapType:
			r.Encap = true
		default:
			r.Other++
		}
	}
	if dstLen > 0 && !haveDst {
		return Route{}, fmt.Errorf("%w: route without destination", ErrMalformed)
	}
	return r, nil
}

// Marshal encodes the route as the payload of a route request. Only
// attributes that are set are sent.
func (r Route) Marshal() []byte {
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
	hdr[5] = r.Protocol
	hdr[6] = r.Scope
	hdr[7] = r.Type
	native.PutUint32(hdr[8:12], r.Flags&RTNHFOnlink)
	b := hdr
	if r.Dst.IsValid() && r.Dst.Bits() > 0 {
		b = appendAttr(b, rtaDst, addrBytes(r.Dst.Addr()))
	}
	if r.Src.IsValid() && r.Src.Bits() > 0 {
		b = appendAttr(b, rtaSrc, addrBytes(r.Src.Addr()))
	}
	if r.Iif.OK {
		b = appendAttrU32(b, rtaIif, r.Iif.V)
	}
	if r.Oif.OK {
		b = appendAttrU32(b, rtaOif, r.Oif.V)
	}
	if r.Gateway.IsValid() {
		b = appendAttr(b, rtaGateway, addrBytes(r.Gateway))
	}
	if r.PrefSrc.IsValid() {
		b = appendAttr(b, rtaPrefsrc, addrBytes(r.PrefSrc))
	}
	if r.Metric != 0 {
		b = appendAttrU32(b, rtaPriority, r.Metric)
	}
	b = appendAttrU32(b, rtaTable, r.Table)
	return b
}

// Link is one network interface.
type Link struct {
	Index uint32
	Name  string
	// Flags is ifi_flags (IFF_*).
	Flags uint32
	MTU   uint32
	// Kind is IFLA_INFO_KIND ("wireguard", "veth", ...), empty when absent.
	Kind string
}

// Up reports IFF_UP, the administrative state.
func (l Link) Up() bool { return l.Flags&IFFUp != 0 }

// DecodeLink parses the payload of an RTM_NEWLINK or RTM_DELLINK message.
func DecodeLink(data []byte) (Link, error) {
	if len(data) < 16 {
		return Link{}, fmt.Errorf("%w: link header is %d bytes", ErrMalformed, len(data))
	}
	l := Link{
		Index: native.Uint32(data[4:8]),
		Flags: native.Uint32(data[8:12]),
	}
	attrs, err := parseAttrs(data[16:])
	if err != nil {
		return Link{}, err
	}
	for _, a := range attrs {
		switch a.typ {
		case iflaIfname:
			if s, ok := attrString(a.data); ok {
				l.Name = s
			}
		case iflaMTU:
			if v, ok := attrU32(a.data); ok {
				l.MTU = v
			}
		case iflaLinkinfo:
			sub, err := parseAttrs(a.data)
			if err != nil {
				return Link{}, err
			}
			for _, s := range sub {
				if s.typ == iflaInfoKind {
					if k, ok := attrString(s.data); ok {
						l.Kind = k
					}
				}
			}
		}
	}
	return l, nil
}

// Addr is one interface address.
type Addr struct {
	Family Family
	Index  uint32
	// Local is the address with its prefix length. For a point-to-point
	// IPv4 address it is IFA_LOCAL, the exit's own end, as `ip addr show`
	// prints it first.
	Local netip.Prefix
	Scope uint8
	Flags uint32
}

// Global reports an address of universe scope, what `ip addr show scope
// global` lists.
func (a Addr) Global() bool { return a.Scope == RTScopeUniverse }

// DecodeAddr parses the payload of an RTM_NEWADDR or RTM_DELADDR message.
func DecodeAddr(data []byte) (Addr, error) {
	if len(data) < 8 {
		return Addr{}, fmt.Errorf("%w: address header is %d bytes", ErrMalformed, len(data))
	}
	family, ok := FamilyOfAF(data[0])
	if !ok {
		return Addr{}, fmt.Errorf("%w: address of family %d", ErrMalformed, data[0])
	}
	a := Addr{Family: family, Flags: uint32(data[2]), Scope: data[3], Index: native.Uint32(data[4:8])}
	prefixLen := int(data[1])
	if prefixLen > family.Bits() {
		return Addr{}, fmt.Errorf("%w: address prefix length %d", ErrMalformed, prefixLen)
	}
	attrs, err := parseAttrs(data[8:])
	if err != nil {
		return Addr{}, err
	}
	var address, local netip.Addr
	for _, at := range attrs {
		switch at.typ {
		case ifaAddress:
			if v, ok := attrAddr(family, at.data); ok {
				address = v
			}
		case ifaLocal:
			if v, ok := attrAddr(family, at.data); ok {
				local = v
			}
		case ifaFlags:
			if v, ok := attrU32(at.data); ok {
				a.Flags = v
			}
		}
	}
	if !local.IsValid() {
		local = address
	}
	if !local.IsValid() {
		return Addr{}, fmt.Errorf("%w: address without an address", ErrMalformed)
	}
	a.Local = netip.PrefixFrom(local, prefixLen)
	return a, nil
}
