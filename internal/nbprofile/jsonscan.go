package nbprofile

import (
	"bytes"
	"errors"
	"unicode/utf8"
)

// The scanner validates a whole file as one JSON object (strings with every
// escape, numbers, literals, nesting) and records the root object's own
// members with their byte spans. It is the Go form of the gate's awk JSON
// reader (routing/wait-for-guards, json_reader); the spans exist for
// fix-blacklist, which edits the raw text.
//
// Field names are matched as Go's encoding/json matches struct fields: by
// name, without regard to ASCII case (util/file.go:196-215 reads profiles
// with json.Unmarshal). encoding/json also folds a few non-ASCII letters (the
// Kelvin sign, the long s), so a root field name with any byte or escape
// outside printable ASCII is refused outright instead of being compared.

// maxNesting is encoding/json's limit; the daemon cannot load deeper files.
const maxNesting = 10000

var (
	errMalformed = errors.New("not a single valid JSON object")
	// errDuplicateDeep is reported only when scanning with dupAny.
	errDuplicateDeep = errors.New("a key is repeated within one object")
)

type valueKind uint8

const (
	kindString valueKind = iota + 1
	kindNumber
	kindTrue
	kindFalse
	kindNull
	kindObject
	kindArray
)

// member is one field of the root object.
type member struct {
	key      string // decoded
	plain    bool   // the decoded key is printable ASCII only
	keyStart int    // offset of the key's opening quote
	keyEnd   int    // offset just past the key's closing quote
	valStart int    // offset of the value's first byte
	valEnd   int    // offset just past the value's last byte
	kind     valueKind
	str      string // decoded value, for strings
	strPlain bool   // the decoded string is printable ASCII only
}

type rootInfo struct {
	open    int // offset of the root '{'
	close   int // offset of the root '}'
	members []member
}

// lookup returns the indexes of the members whose name matches name in ASCII
// case folding. Only plain keys can match; a root with a non-plain key is
// refused before any lookup matters.
func (r *rootInfo) lookup(name string) []int {
	var found []int
	for i := range r.members {
		if r.members[i].plain && asciiLower(r.members[i].key) == name {
			found = append(found, i)
		}
	}
	return found
}

func (r *rootInfo) hasNonPlainKey() bool {
	for i := range r.members {
		if !r.members[i].plain {
			return true
		}
	}
	return false
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

type scanner struct {
	data     []byte
	pos      int
	dupAny   bool
	dupFound bool
}

// scan validates data as one JSON object. With dupAny, an exact repeated key
// inside any object (at any depth) is reported as errDuplicateDeep, together
// with the root, after the whole file has been found valid.
func scan(data []byte, dupAny bool) (*rootInfo, error) {
	// JSON text never contains NUL, and the daemon replaces invalid UTF-8
	// silently; both are refused.
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return nil, errMalformed
	}
	s := &scanner{data: data, dupAny: dupAny}
	s.skipWS()
	if s.pos >= len(data) || data[s.pos] != '{' {
		return nil, errMalformed
	}
	root := &rootInfo{open: s.pos}
	if err := s.object(1, root); err != nil {
		return nil, err
	}
	root.close = s.pos - 1
	s.skipWS()
	if s.pos != len(data) {
		return nil, errMalformed
	}
	if s.dupFound {
		return root, errDuplicateDeep
	}
	return root, nil
}

func (s *scanner) skipWS() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\n', '\r':
			s.pos++
		default:
			return
		}
	}
}

// object parses an object whose '{' is at s.pos. root is non-nil only for the
// root object, whose members are recorded.
func (s *scanner) object(depth int, root *rootInfo) error {
	if depth > maxNesting {
		return errMalformed
	}
	s.pos++ // '{'
	var seen map[string]struct{}
	if s.dupAny {
		seen = map[string]struct{}{}
	}
	s.skipWS()
	if s.pos < len(s.data) && s.data[s.pos] == '}' {
		s.pos++
		return nil
	}
	for {
		s.skipWS()
		if s.pos >= len(s.data) || s.data[s.pos] != '"' {
			return errMalformed
		}
		m := member{keyStart: s.pos}
		key, plain, err := s.str()
		if err != nil {
			return err
		}
		m.key, m.plain, m.keyEnd = key, plain, s.pos
		if seen != nil {
			if _, dup := seen[key]; dup {
				// Still report malformed files as malformed first: finish the
				// scan, then report the repeat.
				s.dupFound = true
			}
			seen[key] = struct{}{}
		}
		s.skipWS()
		if s.pos >= len(s.data) || s.data[s.pos] != ':' {
			return errMalformed
		}
		s.pos++
		s.skipWS()
		m.valStart = s.pos
		kind, vstr, vplain, err := s.value(depth)
		if err != nil {
			return err
		}
		m.valEnd, m.kind, m.str, m.strPlain = s.pos, kind, vstr, vplain
		if root != nil {
			root.members = append(root.members, m)
		}
		s.skipWS()
		if s.pos >= len(s.data) {
			return errMalformed
		}
		switch s.data[s.pos] {
		case ',':
			s.pos++
		case '}':
			s.pos++
			return nil
		default:
			return errMalformed
		}
	}
}

// value parses one value at s.pos. depth is the depth of the container that
// holds it.
func (s *scanner) value(depth int) (kind valueKind, str string, plain bool, err error) {
	if s.pos >= len(s.data) {
		return 0, "", false, errMalformed
	}
	switch c := s.data[s.pos]; {
	case c == '{':
		return kindObject, "", true, s.object(depth+1, nil)
	case c == '[':
		return kindArray, "", true, s.array(depth + 1)
	case c == '"':
		str, plain, err = s.str()
		return kindString, str, plain, err
	case s.literal("true"):
		return kindTrue, "", true, nil
	case s.literal("false"):
		return kindFalse, "", true, nil
	case s.literal("null"):
		return kindNull, "", true, nil
	case c == '-' || isDigit(c):
		return kindNumber, "", true, s.number()
	}
	return 0, "", false, errMalformed
}

func (s *scanner) literal(word string) bool {
	if bytes.HasPrefix(s.data[s.pos:], []byte(word)) {
		s.pos += len(word)
		return true
	}
	return false
}

func (s *scanner) array(depth int) error {
	if depth > maxNesting {
		return errMalformed
	}
	s.pos++ // '['
	s.skipWS()
	if s.pos < len(s.data) && s.data[s.pos] == ']' {
		s.pos++
		return nil
	}
	for {
		s.skipWS()
		if _, _, _, err := s.value(depth); err != nil {
			return err
		}
		s.skipWS()
		if s.pos >= len(s.data) {
			return errMalformed
		}
		switch s.data[s.pos] {
		case ',':
			s.pos++
		case ']':
			s.pos++
			return nil
		default:
			return errMalformed
		}
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (s *scanner) digits() bool {
	start := s.pos
	for s.pos < len(s.data) && isDigit(s.data[s.pos]) {
		s.pos++
	}
	return s.pos > start
}

// number follows the JSON grammar: no leading zeros, digits on both sides of
// a point, digits in an exponent.
func (s *scanner) number() error {
	if s.data[s.pos] == '-' {
		s.pos++
	}
	switch {
	case s.pos >= len(s.data):
		return errMalformed
	case s.data[s.pos] == '0':
		s.pos++
	case isDigit(s.data[s.pos]):
		s.digits()
	default:
		return errMalformed
	}
	if s.pos < len(s.data) && s.data[s.pos] == '.' {
		s.pos++
		if !s.digits() {
			return errMalformed
		}
	}
	if s.pos < len(s.data) && (s.data[s.pos] == 'e' || s.data[s.pos] == 'E') {
		s.pos++
		if s.pos < len(s.data) && (s.data[s.pos] == '+' || s.data[s.pos] == '-') {
			s.pos++
		}
		if !s.digits() {
			return errMalformed
		}
	}
	return nil
}

// str parses the string at s.pos (an opening quote) and returns its decoded
// text. plain reports that every decoded character is printable ASCII: the
// awk reader's str_plain, which treated \b \f \n \r \t, \u escapes outside
// 32..126 and every non-ASCII byte as not plain.
func (s *scanner) str() (string, bool, error) {
	s.pos++ // opening quote
	var out []byte
	plain := true
	for {
		if s.pos >= len(s.data) {
			return "", false, errMalformed
		}
		c := s.data[s.pos]
		switch {
		case c == '"':
			s.pos++
			return string(out), plain, nil
		case c == '\\':
			if s.pos+1 >= len(s.data) {
				return "", false, errMalformed
			}
			switch e := s.data[s.pos+1]; e {
			case '"', '\\', '/':
				out = append(out, e)
				s.pos += 2
			case 'b', 'f', 'n', 'r', 't':
				out = append(out, '?')
				plain = false
				s.pos += 2
			case 'u':
				r, n, ok := s.unicodeEscape()
				if !ok {
					return "", false, errMalformed
				}
				if r < 32 || r >= 127 {
					plain = false
				}
				out = utf8.AppendRune(out, r)
				s.pos += n
			default:
				return "", false, errMalformed
			}
		case c < 32:
			return "", false, errMalformed
		default:
			if c < 32 || c >= 127 {
				plain = false
			}
			out = append(out, c)
			s.pos++
		}
	}
}

func hexVal(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

func (s *scanner) hex4(at int) (rune, bool) {
	if at+4 > len(s.data) {
		return 0, false
	}
	v := 0
	for _, c := range s.data[at : at+4] {
		d, ok := hexVal(c)
		if !ok {
			return 0, false
		}
		v = v*16 + d
	}
	return rune(v), true
}

// unicodeEscape decodes the \uXXXX escape at s.pos, joining a surrogate pair
// when a second escape follows. n is the number of bytes consumed. A lone
// surrogate is accepted, as encoding/json accepts it (it decodes to U+FFFD).
func (s *scanner) unicodeEscape() (r rune, n int, ok bool) {
	hi, ok := s.hex4(s.pos + 2)
	if !ok {
		return 0, 0, false
	}
	if hi >= 0xD800 && hi < 0xDC00 && s.pos+12 <= len(s.data) && s.data[s.pos+6] == '\\' && s.data[s.pos+7] == 'u' {
		if lo, ok2 := s.hex4(s.pos + 8); ok2 && lo >= 0xDC00 && lo < 0xE000 {
			return (hi-0xD800)<<10 + (lo - 0xDC00) + 0x10000, 12, true
		}
	}
	if hi >= 0xD800 && hi < 0xE000 {
		return utf8.RuneError, 6, true
	}
	return hi, 6, true
}
