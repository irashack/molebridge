package panel

import (
	"strings"
	"unicode/utf8"
)

// Query and form parsing with urllib.parse.parse_qs semantics.

// unquotePlus is urllib.parse.unquote(s.replace('+', ' ')): percent-escapes
// are decoded as UTF-8 with invalid sequences replaced; a '%' not followed
// by two hex digits stays as it is.
func unquotePlus(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			out = append(out, ' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			out = append(out, hexVal(s[i+1])<<4|hexVal(s[i+2]))
			i += 2
		default:
			out = append(out, c)
		}
	}
	if utf8.Valid(out) {
		return string(out)
	}
	return strings.ToValidUTF8(string(out), "�")
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// parseQS is urllib.parse.parse_qs(text, keep_blank_values=keepBlank): name
// to the list of its values, in order.
func parseQS(text string, keepBlank bool) map[string][]string {
	fields := map[string][]string{}
	for _, pair := range strings.Split(text, "&") {
		if pair == "" {
			continue
		}
		name, value, found := strings.Cut(pair, "=")
		if !found {
			if !keepBlank {
				continue
			}
			value = ""
		}
		if value == "" && !keepBlank {
			continue
		}
		name, value = unquotePlus(name), unquotePlus(value)
		fields[name] = append(fields[name], value)
	}
	return fields
}

// first is query.get(name, [”])[0].
func first(query map[string][]string, name string) string {
	if values := query[name]; len(values) > 0 {
		return values[0]
	}
	return ""
}

// parseSelectForm is parse_select_form: the POST body as form fields, the
// first value of each; the body is decoded as UTF-8 with invalid bytes
// replaced.
func parseSelectForm(body []byte) map[string]string {
	text := strings.ToValidUTF8(string(body), "�")
	fields := map[string]string{}
	for name, values := range parseQS(text, true) {
		if len(values) > 0 {
			fields[name] = values[0]
		}
	}
	return fields
}

// splitTarget is urlsplit(target) for a request target: its path and query.
// A target with a leading "//" has a network location first, as in Python;
// an absolute-form target keeps only its path.
func splitTarget(target string) (path, query string) {
	rest := target
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		rest, query = rest[:i], rest[i+1:]
	}
	// scheme://netloc/path or //netloc/path
	if i := strings.Index(rest, "://"); i > 0 && isScheme(rest[:i]) {
		rest = "//" + rest[i+3:]
	}
	if strings.HasPrefix(rest, "//") {
		rest = rest[2:]
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			rest = rest[i:]
		} else {
			rest = ""
		}
	}
	return rest, query
}

func isScheme(s string) bool {
	if s == "" || !(s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}
