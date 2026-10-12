// Package pystr holds the few Python string behaviours the panel's ports
// depend on, so that a Go port refuses and escapes exactly the strings the
// Python panel did: str.strip() and str.split() (which treat the ASCII
// separators U+001C to U+001F as whitespace), str.isprintable(),
// html.escape(), and urllib.parse.urlencode()'s quoting.
package pystr

import (
	"net/url"
	"strings"
	"unicode"
)

// IsSpace is Python's str.isspace() for one character.
func IsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

// Strip is str.strip().
func Strip(s string) string { return strings.TrimFunc(s, IsSpace) }

// Fields is str.split() with no separator.
func Fields(s string) []string { return strings.FieldsFunc(s, IsSpace) }

// IsPrintable is str.isprintable(): true for the empty string and for text
// whose characters are all letters, marks, numbers, punctuation, symbols or
// the ASCII space.
func IsPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

var escaper = strings.NewReplacer(
	"&", "&amp;",
	"<", "&lt;",
	">", "&gt;",
	`"`, "&quot;",
	"'", "&#x27;",
)

// Escape is html.escape(s) with quote=True: the five characters Python
// replaces, with the same entities (&#x27; for the apostrophe).
func Escape(s string) string { return escaper.Replace(s) }

// Pair is one name and value for Encode.
type Pair struct{ Key, Value string }

// Encode is urllib.parse.urlencode() for string pairs: in the given order,
// quote_plus quoting, UTF-8.
func Encode(pairs ...Pair) string {
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(url.QueryEscape(p.Key))
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(p.Value))
	}
	return b.String()
}

// Quote is urllib.parse.quote(s, safe=”).
func Quote(s string) string {
	// QueryEscape differs from quote(safe='') only in writing a space as '+'
	// and in leaving '~' alone, which quote also leaves alone since 3.7.
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
