package rtnl

import "net/netip"

// The request builders for link and address changes. They are the encoding
// half of DecodeLink and DecodeAddr, so they build and are tested on any
// platform.

const ifinfoLen = 16

func ifinfo(index uint32, flags, change uint32) []byte {
	b := make([]byte, ifinfoLen)
	// family AF_UNSPEC, a pad byte and ifi_type stay zero.
	native.PutUint32(b[4:8], index)
	native.PutUint32(b[8:12], flags)
	native.PutUint32(b[12:16], change)
	return b
}

// LinkLookupRequest is the payload of an RTM_GETLINK for one interface by name.
func LinkLookupRequest(name string) []byte {
	return appendAttrStr(ifinfo(0, 0, 0), iflaIfname, name)
}

// LinkCreateRequest is the payload of an RTM_NEWLINK that creates an
// interface of a kind ("wireguard") with a name:
// IFLA_IFNAME, and IFLA_LINKINFO { IFLA_INFO_KIND }.
func LinkCreateRequest(name, kind string) []byte {
	b := appendAttrStr(ifinfo(0, 0, 0), iflaIfname, name)
	info := appendAttrStr(nil, iflaInfoKind, kind)
	return appendAttr(b, iflaLinkinfo|nlaFNested, info)
}

// LinkDeleteRequest is the payload of an RTM_DELLINK by index.
func LinkDeleteRequest(index uint32) []byte { return ifinfo(index, 0, 0) }

// LinkMTURequest is the payload of an RTM_NEWLINK that sets IFLA_MTU.
func LinkMTURequest(index, mtu uint32) []byte {
	return appendAttrU32(ifinfo(index, 0, 0), iflaMTU, mtu)
}

// LinkUpRequest is the payload of an RTM_NEWLINK that sets IFF_UP (and only
// that flag: ifi_change selects it).
func LinkUpRequest(index uint32) []byte { return ifinfo(index, IFFUp, IFFUp) }

// Marshal encodes an address as the payload of an RTM_NEWADDR or RTM_DELADDR:
// ifaddrmsg, IFA_LOCAL and IFA_ADDRESS (both the local prefix's address; a
// point-to-point peer is not modeled).
func (a Addr) Marshal() []byte {
	b := make([]byte, 8)
	b[0] = a.Family.AF()
	b[1] = uint8(a.Local.Bits())
	b[2] = uint8(a.Flags)
	b[3] = a.Scope
	native.PutUint32(b[4:8], a.Index)
	ip := a.Local.Addr()
	b = appendAttr(b, ifaLocal, addrBytes(ip))
	b = appendAttr(b, ifaAddress, addrBytes(ip))
	return b
}

// HostAddr is the address a/32 or a/128 on an interface, universe scope: what
// the tunnel's own address is.
func HostAddr(index uint32, a netip.Addr) Addr {
	a = a.Unmap()
	f := V4
	if a.Is6() {
		f = V6
	}
	return Addr{Family: f, Index: index, Local: netip.PrefixFrom(a, a.BitLen())}
}
