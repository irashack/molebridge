package panel

import (
	"regexp"
	"strings"
)

// Cookie parsing, ported from app.py's get_cookie (Python's
// http.cookies.SimpleCookie, used when sign-in is off, as before it existed)
// and get_cookie_strict (used with sign-in on).

const (
	legalKeyChars   = `\w!#%&'~_` + "`" + `><@,:/\$\*\+\-\.\^\|\)\(\?\}\{\=`
	legalValueChars = legalKeyChars + `\[\]`
)

// cookiePattern is http.cookies._CookiePattern with re.ASCII: \w is ASCII
// and \s also matches the vertical tab.
var cookiePattern = regexp.MustCompile(`\A[\t\n\v\f\r ]*` +
	`(?P<key>[` + legalKeyChars + `]+?)` +
	`(?:[\t\n\v\f\r ]*=[\t\n\v\f\r ]*(?P<val>` +
	`"(?:[^\\"]|\\.)*"` +
	`|(?:\w{3,6}day|\w{3}),[\t\n\v\f\r ][\w\-\t\n\v\f\r ]{9,11}[\t\n\v\f\r ][\d:]{8}[\t\n\v\f\r ]GMT` +
	`|[` + legalValueChars + `]*` +
	`))?` +
	`[\t\n\v\f\r ]*(?:[\t\n\v\f\r ]+|;|\z)`)

var reservedCookieAttrs = map[string]bool{
	"expires": true, "path": true, "comment": true, "domain": true, "max-age": true,
	"secure": true, "httponly": true, "version": true, "samesite": true,
}

var cookieFlags = map[string]bool{"secure": true, "httponly": true}

// legalCookieKey is http.cookies._is_legal_key: letters, digits and
// !#$%&'*+-.^_`|~: only. The parse pattern accepts more, and Python's
// SimpleCookie then raises, which get_cookie turns into "no cookies".
var legalCookieKey = regexp.MustCompile("\\A[A-Za-z0-9!#$%&'*+\\-.^_`|~:]+\\z")

var cookieUnquote = regexp.MustCompile(`\\(?:([0-3][0-7][0-7])|(.))`)

func unquoteCookie(s string) string {
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return s
	}
	return cookieUnquote.ReplaceAllStringFunc(s[1:len(s)-1], func(m string) string {
		sub := cookieUnquote.FindStringSubmatch(m)
		if sub[1] != "" {
			n := 0
			for _, c := range sub[1] {
				n = n*8 + int(c-'0')
			}
			return string(rune(n))
		}
		return sub[2]
	})
}

// getCookie is get_cookie: the value of the named cookie as
// http.cookies.SimpleCookie reads the header, or false when the header is
// absent, malformed or holds no such cookie.
func getCookie(header, name string) (string, bool) {
	if header == "" {
		return "", false
	}
	type item struct {
		attribute bool
		key       string
		value     string
	}
	var items []item
	morselSeen := false
	rest := header
	for len(rest) > 0 {
		loc := cookiePattern.FindStringSubmatchIndex(rest)
		if loc == nil {
			break
		}
		key := rest[loc[2]:loc[3]]
		hasValue := loc[4] >= 0
		value := ""
		if hasValue {
			value = rest[loc[4]:loc[5]]
		}
		rest = rest[loc[1]:]
		lower := strings.ToLower(key)
		switch {
		case key[0] == '$':
			if !morselSeen {
				continue
			}
			if !reservedCookieAttrs[strings.ToLower(key[1:])] {
				return "", false // CookieError: invalid attribute
			}
			items = append(items, item{attribute: true})
		case reservedCookieAttrs[lower]:
			if !morselSeen {
				return "", false // an invalid cookie string
			}
			if !hasValue && !cookieFlags[lower] {
				return "", false
			}
			items = append(items, item{attribute: true})
		case hasValue:
			if !legalCookieKey.MatchString(key) {
				return "", false // CookieError: illegal key
			}
			items = append(items, item{key: key, value: unquoteCookie(value)})
			morselSeen = true
		default:
			return "", false
		}
	}
	found, ok := "", false
	for _, it := range items {
		if !it.attribute && it.key == name {
			found, ok = it.value, true
		}
	}
	return found, ok
}

// getCookieStrict is get_cookie_strict: one cookie by exact name; false when
// absent, repeated or malformed. SimpleCookie reads `a=x __Host-y=z` as two
// cookies and lets a later duplicate win, which would let a cookie planted
// from a sibling subdomain or over plain http stand in for a __Host- cookie.
func getCookieStrict(header, name string) (string, bool) {
	if header == "" {
		return "", false
	}
	found, seen := "", false
	for _, part := range strings.Split(header, ";") {
		key, value, sep := strings.Cut(strings.Trim(part, " \t"), "=")
		if key != name {
			continue
		}
		if seen || !sep {
			return "", false
		}
		found, seen = strings.Trim(value, " \t"), true
	}
	return found, seen
}
