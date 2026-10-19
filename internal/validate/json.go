// Package validate holds the strict decoding, the value checks and the
// Python-compatible JSON encoding that every other data package shares. It
// imports nothing else from Molebridge.
//
// It offers:
//
//   - DecodeJSON / DecodeJSONString: strict decoding (duplicate keys rejected
//     at every depth, strict UTF-8, no BOM, no NaN or Infinity, bounded
//     nesting) into map[string]any, []any, string, bool, nil, float64 and
//     int64 (an integer written without fraction or exponent is an int64, as
//     in Python; one beyond int64 is a *big.Int).
//   - CheckJSON and DecodeJSONMembers: the same checks and errors without
//     building the parts of a document nobody reads (skip.go), for the large
//     server lists.
//   - EncodeJSON / MarshalJSON: the bytes json.dump(obj, allow_nan=False)
//     writes (ensure_ascii, ", " and ": " separators, no trailing newline),
//     with Obj for objects whose key order matters.
//   - ValidKey, ValidIPv4, ValidText and the type predicates (IsInt, ...)
//     that stand in for Python's isinstance and `type(x) is int` checks on
//     decoded JSON.
//   - Timestamps in the state files' format (FormatTime, ParseTime,
//     AgeSeconds, Recent).
package validate

import (
	"errors"
	"math"
	"math/big"
	"strconv"
	"unicode/utf8"
)

// MaxDepth is the deepest nesting of arrays and objects DecodeJSON accepts;
// Python's decoder stops at its recursion limit, about the same depth.
const MaxDepth = 1000

// maxIntDigits mirrors Python's limit on converting a decimal string to int.
const maxIntDigits = 4300

// Errors DecodeJSON returns. None of them carries any input.
var (
	ErrSyntax         = errors.New("invalid JSON")
	ErrInvalidUTF8    = errors.New("invalid UTF-8")
	ErrDuplicateField = errors.New("duplicate JSON field")
	ErrNonFinite      = errors.New("non-finite JSON number")
	ErrDepth          = errors.New("JSON nested too deeply")
	ErrIntegerSize    = errors.New("JSON integer too large")
)

// DecodeJSONString is DecodeJSON for text.
func DecodeJSONString(raw string) (any, error) { return DecodeJSON([]byte(raw)) }

// DecodeJSON decodes exactly one JSON document. Objects with a repeated key
// (after unescaping) are an error at any depth. Input that is not valid UTF-8
// is an error, and so is a leading byte order mark. A lone surrogate escape
// (\ud800) decodes, as in Python, to its three-byte (WTF-8) form; use the
// rune helpers in this package to inspect such strings.
func DecodeJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, ErrInvalidUTF8
	}
	p := &parser{b: raw}
	p.space()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(p.b) {
		return nil, ErrSyntax
	}
	return v, nil
}

type parser struct {
	b []byte
	i int
	// keys are the skip mode's keys of the objects being checked, the
	// innermost last (skip.go).
	keys [][]byte
}

func (p *parser) space() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (any, error) {
	if p.i >= len(p.b) {
		return nil, ErrSyntax
	}
	switch c := p.b[p.i]; {
	case c == '{':
		return p.object(depth + 1)
	case c == '[':
		return p.array(depth + 1)
	case c == '"':
		return p.str()
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case p.literal("true"):
		return true, nil
	case p.literal("false"):
		return false, nil
	case p.literal("null"):
		return nil, nil
	case p.literal("NaN"), p.literal("Infinity"):
		return nil, ErrNonFinite
	}
	return nil, ErrSyntax
}

func (p *parser) literal(word string) bool {
	if len(p.b)-p.i >= len(word) && string(p.b[p.i:p.i+len(word)]) == word {
		p.i += len(word)
		return true
	}
	return false
}

func (p *parser) object(depth int) (any, error) {
	if depth > MaxDepth {
		return nil, ErrDepth
	}
	p.i++ // {
	result := map[string]any{}
	p.space()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return result, nil
	}
	for {
		p.space()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return nil, ErrSyntax
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		p.space()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return nil, ErrSyntax
		}
		p.i++
		p.space()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		if _, dup := result[key.(string)]; dup {
			return nil, ErrDuplicateField
		}
		result[key.(string)] = v
		p.space()
		if p.i >= len(p.b) {
			return nil, ErrSyntax
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return result, nil
		default:
			return nil, ErrSyntax
		}
	}
}

func (p *parser) array(depth int) (any, error) {
	if depth > MaxDepth {
		return nil, ErrDepth
	}
	p.i++ // [
	result := []any{}
	p.space()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return result, nil
	}
	for {
		p.space()
		v, err := p.value(depth)
		if err != nil {
			return nil, err
		}
		result = append(result, v)
		p.space()
		if p.i >= len(p.b) {
			return nil, ErrSyntax
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return result, nil
		default:
			return nil, ErrSyntax
		}
	}
}

func hexValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func (p *parser) hex4(at int) (rune, bool) {
	if at+4 > len(p.b) {
		return 0, false
	}
	var r rune
	for _, c := range p.b[at : at+4] {
		h := hexValue(c)
		if h < 0 {
			return 0, false
		}
		r = r<<4 | rune(h)
	}
	return r, true
}

// str parses a string starting at the opening quote.
func (p *parser) str() (any, error) {
	p.i++ // opening quote
	start := p.i
	// Fast path: no escapes.
	for p.i < len(p.b) {
		c := p.b[p.i]
		if c == '"' {
			s := string(p.b[start:p.i])
			p.i++
			return s, nil
		}
		if c == '\\' {
			break
		}
		if c < 0x20 {
			return nil, ErrSyntax
		}
		p.i++
	}
	out := append([]byte(nil), p.b[start:p.i]...)
	for p.i < len(p.b) {
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return string(out), nil
		case c < 0x20:
			return nil, ErrSyntax
		case c != '\\':
			out = append(out, c)
			p.i++
		default:
			if p.i+1 >= len(p.b) {
				return nil, ErrSyntax
			}
			e := p.b[p.i+1]
			p.i += 2
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, ok := p.hex4(p.i)
				if !ok {
					return nil, ErrSyntax
				}
				p.i += 4
				if r >= 0xD800 && r < 0xDC00 && p.i+6 <= len(p.b) && p.b[p.i] == '\\' && p.b[p.i+1] == 'u' {
					if low, ok := p.hex4(p.i + 2); ok && low >= 0xDC00 && low < 0xE000 {
						r = 0x10000 + (r-0xD800)<<10 + (low - 0xDC00)
						p.i += 6
					}
				}
				out = appendCodePoint(out, r)
			default:
				return nil, ErrSyntax
			}
		}
	}
	return nil, ErrSyntax
}

// scanNumber moves past a number and reports whether it has a fraction or an
// exponent. Every check that does not need the value is made here, so the
// skip mode makes it too; what it accepts, ParseFloat and SetString convert.
func (p *parser) scanNumber() (bool, error) {
	start := p.i
	if p.b[p.i] == '-' {
		p.i++
	}
	if p.i >= len(p.b) {
		return false, ErrSyntax
	}
	switch c := p.b[p.i]; {
	case c == '0':
		p.i++
	case c >= '1' && c <= '9':
		for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
			p.i++
		}
	case c == 'I': // -Infinity
		if p.literal("Infinity") {
			return false, ErrNonFinite
		}
		return false, ErrSyntax
	default:
		return false, ErrSyntax
	}
	isFloat := false
	if p.i+1 < len(p.b) && p.b[p.i] == '.' && p.b[p.i+1] >= '0' && p.b[p.i+1] <= '9' {
		isFloat = true
		p.i++
		for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
			p.i++
		}
	}
	if p.i < len(p.b) && (p.b[p.i] == 'e' || p.b[p.i] == 'E') {
		j := p.i + 1
		if j < len(p.b) && (p.b[j] == '+' || p.b[j] == '-') {
			j++
		}
		if j < len(p.b) && p.b[j] >= '0' && p.b[j] <= '9' {
			for j < len(p.b) && p.b[j] >= '0' && p.b[j] <= '9' {
				j++
			}
			isFloat = true
			p.i = j
		}
	}
	digits := p.i - start
	if p.b[start] == '-' {
		digits--
	}
	if !isFloat && digits > maxIntDigits {
		return false, ErrIntegerSize
	}
	return isFloat, nil
}

func (p *parser) number() (any, error) {
	start := p.i
	isFloat, err := p.scanNumber()
	if err != nil {
		return nil, err
	}
	text := string(p.b[start:p.i])
	if isFloat {
		f, err := strconv.ParseFloat(text, 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return nil, ErrSyntax
		}
		// Python's float() overflows to infinity without complaint; so does this.
		if math.IsNaN(f) {
			return nil, ErrSyntax
		}
		return f, nil
	}
	if n, err := strconv.ParseInt(text, 10, 64); err == nil {
		return n, nil
	}
	b, ok := new(big.Int).SetString(text, 10)
	if !ok {
		return nil, ErrSyntax
	}
	return b, nil
}
