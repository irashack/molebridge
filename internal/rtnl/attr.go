package rtnl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Family is an address family, 4 or 6.
type Family uint8

// The two families the contract covers.
const (
	V4 Family = 4
	V6 Family = 6
)

// AF returns the AF_* number of the family.
func (f Family) AF() uint8 {
	if f == V6 {
		return afInet6
	}
	return afInet
}

// Bits is the length of a host address of the family.
func (f Family) Bits() int {
	if f == V6 {
		return 128
	}
	return 32
}

func (f Family) String() string {
	switch f {
	case V4:
		return "IPv4"
	case V6:
		return "IPv6"
	}
	return fmt.Sprintf("family(%d)", uint8(f))
}

// FamilyOfAF maps AF_INET and AF_INET6 to a Family.
func FamilyOfAF(af uint8) (Family, bool) {
	switch af {
	case afInet:
		return V4, true
	case afInet6:
		return V6, true
	}
	return 0, false
}

// Opt is an optional value: the zero Opt is "not present". The kernel omits
// attributes whose value is the default, so presence is part of a rule.
type Opt[T comparable] struct {
	V  T
	OK bool
}

// Some is a present Opt.
func Some[T comparable](v T) Opt[T] { return Opt[T]{V: v, OK: true} }

// RawAttr is an attribute kept as it arrived.
type RawAttr struct {
	Type uint16
	Data []byte
}

// ErrMalformed marks a message the codec could not take apart.
var ErrMalformed = errors.New("rtnl: malformed netlink message")

var native = binary.NativeEndian

// attr is one parsed netlink attribute (type with the flag bits removed).
type attr struct {
	typ  uint16
	data []byte
}

// parseAttrs walks a netlink attribute stream. It never reads past b and
// rejects lengths that are shorter than the header or run off the end.
func parseAttrs(b []byte) ([]attr, error) {
	var out []attr
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, fmt.Errorf("%w: truncated attribute header", ErrMalformed)
		}
		n := int(native.Uint16(b[0:2]))
		typ := native.Uint16(b[2:4]) & nlaTypeMask
		if n < 4 || n > len(b) {
			return nil, fmt.Errorf("%w: attribute length %d", ErrMalformed, n)
		}
		out = append(out, attr{typ: typ, data: b[4:n]})
		adv := (n + 3) &^ 3
		if adv > len(b) {
			adv = len(b)
		}
		b = b[adv:]
	}
	return out, nil
}

// appendAttr appends one attribute, padded to four bytes.
func appendAttr(b []byte, typ uint16, data []byte) []byte {
	n := 4 + len(data)
	b = native.AppendUint16(b, uint16(n))
	b = native.AppendUint16(b, typ)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func appendAttrU32(b []byte, typ uint16, v uint32) []byte {
	return appendAttr(b, typ, native.AppendUint32(nil, v))
}

func appendAttrU8(b []byte, typ uint16, v uint8) []byte {
	return appendAttr(b, typ, []byte{v})
}

func appendAttrStr(b []byte, typ uint16, s string) []byte {
	return appendAttr(b, typ, append([]byte(s), 0))
}

func attrU32(d []byte) (uint32, bool) {
	if len(d) != 4 {
		return 0, false
	}
	return native.Uint32(d), true
}

func attrU8(d []byte) (uint8, bool) {
	if len(d) != 1 {
		return 0, false
	}
	return d[0], true
}

// attrString reads a NUL-terminated string attribute. The terminator is
// required and nothing may follow it, as the kernel writes them.
func attrString(d []byte) (string, bool) {
	if len(d) < 2 || d[len(d)-1] != 0 {
		return "", false
	}
	s := d[:len(d)-1]
	for _, c := range s {
		if c == 0 {
			return "", false
		}
	}
	return string(s), true
}

// attrAddr reads a 4- or 16-byte address of the given family.
func attrAddr(f Family, d []byte) (netip.Addr, bool) {
	switch {
	case f == V4 && len(d) == 4:
		return netip.AddrFrom4([4]byte(d)), true
	case f == V6 && len(d) == 16:
		return netip.AddrFrom16([16]byte(d)), true
	}
	return netip.Addr{}, false
}

func addrBytes(a netip.Addr) []byte {
	if a.Is4() {
		b := a.As4()
		return b[:]
	}
	b := a.As16()
	return b[:]
}

func cloneBytes(b []byte) []byte {
	return append([]byte(nil), b...)
}
