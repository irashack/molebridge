package validate

import (
	"encoding/base64"
	"math/big"
	"net/netip"
	"unicode"
	"unicode/utf8"
)

// Strings decoded from JSON may hold a lone surrogate (Python keeps one as a
// str character). Go strings cannot, so DecodeJSON stores it in its
// three-byte WTF-8 form (ED A0..BF 80..BF). These helpers see such strings
// the way Python's len() and iteration do: one code point per character,
// surrogates included.

// appendCodePoint appends r as UTF-8, or WTF-8 when r is a surrogate.
func appendCodePoint(b []byte, r rune) []byte {
	if r >= 0xD800 && r < 0xE000 {
		return append(b, 0xE0|byte(r>>12), 0x80|byte(r>>6)&0x3F, 0x80|byte(r)&0x3F)
	}
	return utf8.AppendRune(b, r)
}

// NextRune decodes the code point at the start of s and its width in bytes.
// A surrogate in WTF-8 form is returned as that surrogate. Bytes that are
// neither UTF-8 nor WTF-8 give (utf8.RuneError, 1).
func NextRune(s string) (rune, int) {
	r, size := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError && size == 1 && len(s) >= 3 && s[0] == 0xED && s[1] >= 0xA0 && s[1] <= 0xBF &&
		s[2] >= 0x80 && s[2] <= 0xBF {
		return rune(0xD000) | rune(s[1]&0x3F)<<6 | rune(s[2]&0x3F), 3
	}
	return r, size
}

// Runes returns the code points of s, surrogates included.
func Runes(s string) []rune {
	out := make([]rune, 0, len(s))
	for len(s) > 0 {
		r, size := NextRune(s)
		out = append(out, r)
		s = s[size:]
	}
	return out
}

// RuneCount is Python's len(s).
func RuneCount(s string) int {
	n := 0
	for len(s) > 0 {
		_, size := NextRune(s)
		s = s[size:]
		n++
	}
	return n
}

// IsSurrogate reports whether r is a UTF-16 surrogate code point.
func IsSurrogate(r rune) bool { return r >= 0xD800 && r < 0xE000 }

// IsSpace is Python's str.isspace() for one character: Unicode white space
// plus the four ASCII separators U+001C to U+001F.
func IsSpace(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }

// -- decoded-JSON type predicates ---------------------------------------------
//
// Python tells JSON types apart with isinstance and `type(x) is int`; these
// are the equivalents on the values DecodeJSON produces (and, for ints, on any
// Go integer type, so a value built in Go behaves like a decoded one).

// IsInt is `type(v) is int`: any integer that is not a bool. The second result
// is false for a *big.Int (an integer beyond int64), which this port does not
// treat as an int; every range check that matters would reject it anyway.
func IsInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		return int64(n), uint64(n) <= 1<<63-1
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), n <= 1<<63-1
	}
	return 0, false
}

// IsIntType is `type(v) is int` without the range limit of IsInt.
func IsIntType(v any) bool {
	if _, ok := IsInt(v); ok {
		return true
	}
	_, big := v.(*big.Int)
	return big
}

// IsFloat is `type(v) is float`.
func IsFloat(v any) (float64, bool) {
	switch f := v.(type) {
	case float64:
		return f, true
	case float32:
		return float64(f), true
	}
	return 0, false
}

// IsNumber is isinstance(v, (int, float)) without bool.
func IsNumber(v any) (float64, bool) {
	if n, ok := IsInt(v); ok {
		return float64(n), true
	}
	return IsFloat(v)
}

// Object is a decoded JSON object, and List a decoded array.
type (
	Object = map[string]any
	List   = []any
)

// -- value checks -----------------------------------------------------------------

// ValidKey reports whether value is the canonical base64 text of a 32-byte
// WireGuard key (44 characters, padded, no whitespace).
func ValidKey(value any) bool {
	s, ok := value.(string)
	if !ok || len(s) != 44 {
		return false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	return err == nil && len(raw) == 32 && base64.StdEncoding.EncodeToString(raw) == s
}

// ValidIPv4 reports whether value is a canonical dotted-quad IPv4 address
// (no leading zeros, no spaces, no IPv6 forms).
func ValidIPv4(value any) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4() && a.String() == s
}

// nonPublicIPv4 are the IPv4 ranges netip's predicates leave out that no
// relay is ever reached at: "this network" (0.0.0.0/8), shared address
// space for carrier-grade NAT (100.64.0.0/10, which NetBird's overlay also
// uses), and the reserved 240.0.0.0/4 with the limited broadcast address.
var nonPublicIPv4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// ValidPublicIPv4 is ValidIPv4 for an address taken from a provider's list
// and dialled (a relay's latency target or WireGuard endpoint): it also
// refuses private, loopback, link-local, multicast, unspecified, shared
// (100.64.0.0/10) and reserved addresses, so a hostile or tampered list
// cannot point the panel's prober or a switch at the host's own networks.
// The documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
// pass: they reach nothing, and the tests use them as fictitious relays.
func ValidPublicIPv4(value any) bool {
	if !ValidIPv4(value) {
		return false
	}
	a := netip.MustParseAddr(value.(string))
	if a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	for _, p := range nonPublicIPv4 {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// ValidText reports whether value is a string of 1 to 256 code points, none
// of them a control character below U+0020.
func ValidText(value any) bool {
	s, ok := value.(string)
	if !ok || len(s) == 0 || len(s) > 256*4 {
		return false
	}
	n := 0
	for len(s) > 0 {
		r, size := NextRune(s)
		if r < 32 {
			return false
		}
		s = s[size:]
		n++
	}
	return n <= 256
}
