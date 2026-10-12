package validate

import (
	"encoding/base64"
	"math/big"
	"net/netip"
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

// IsBool is `type(v) is bool`.
func IsBool(v any) (value, ok bool) {
	value, ok = v.(bool)
	return
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
