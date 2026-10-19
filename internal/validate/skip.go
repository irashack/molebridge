package validate

import (
	"bytes"
	"unicode/utf8"
)

// The skip mode: DecodeJSON's checks without its values. A catalogue of
// several megabytes decodes into a tree several times its size, most of which
// the caller drops at once; the skip mode walks the parts nobody reads and
// makes the same checks on them (strict UTF-8, syntax, duplicate keys after
// unescaping, nesting depth, NaN and Infinity, integer size), in the same
// order, so a document is refused with the same error either way.

// CheckJSON returns the error DecodeJSON would return for raw, nil when it
// would decode, without building anything but the keys of the objects it
// checks for duplicates.
func CheckJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return ErrInvalidUTF8
	}
	p := &parser{b: raw}
	p.space()
	if err := p.skip(0); err != nil {
		return err
	}
	p.space()
	if p.i != len(p.b) {
		return ErrSyntax
	}
	return nil
}

// Plan says which members of a document's top-level object DecodeJSONMembers
// builds. A nil function selects nothing.
type Plan struct {
	// Keep: the member's value is built and kept in the result.
	Keep func(key string) bool
	// Each: for a member whose value is an array, a function that is given
	// each element, built, in turn, instead of the array being kept; the
	// result holds Streamed (the number of elements) under the key. Nil, or
	// a value that is not an array, falls through to Keep.
	Each func(key string) func(element any)
}

// Streamed stands in the result of DecodeJSONMembers for an array whose
// elements went to a Plan's Each function: it is the number of elements.
type Streamed int

// DecodeJSONMembers checks raw exactly as DecodeJSON does and returns the
// same error, but builds only what plan selects of the top-level object; it
// returns nil (and no error) for a document whose top level is not an object.
// The result has no entry for a member plan did not select.
//
// An Each function sees elements as they are read, so it may have seen some
// of a document that is then refused: on an error, drop what it collected.
func DecodeJSONMembers(raw []byte, plan Plan) (map[string]any, error) {
	if !utf8.Valid(raw) {
		return nil, ErrInvalidUTF8
	}
	p := &parser{b: raw}
	p.space()
	var result map[string]any
	var err error
	if p.i < len(p.b) && p.b[p.i] == '{' {
		result, err = p.members(plan)
	} else {
		err = p.skip(0)
	}
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(p.b) {
		return nil, ErrSyntax
	}
	return result, nil
}

// members is object(1) building only what plan selects.
func (p *parser) members(plan Plan) (map[string]any, error) {
	const depth = 1 // the top-level object, as value(0) would call object(1)
	p.i++           // {
	result := map[string]any{}
	p.space()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return result, nil
	}
	keys := p.newKeys()
	defer p.dropKeys(keys)
	for {
		p.space()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return nil, ErrSyntax
		}
		rawKey, err := p.key()
		if err != nil {
			return nil, err
		}
		p.space()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return nil, ErrSyntax
		}
		p.i++
		p.space()
		key := string(rawKey)
		var each func(any)
		if plan.Each != nil && p.i < len(p.b) && p.b[p.i] == '[' {
			each = plan.Each(key)
		}
		switch {
		case each != nil:
			n, err := p.stream(depth+1, each)
			if err != nil {
				return nil, err
			}
			result[key] = Streamed(n)
		case plan.Keep != nil && plan.Keep(key):
			v, err := p.value(depth)
			if err != nil {
				return nil, err
			}
			result[key] = v
		default:
			if err := p.skip(depth); err != nil {
				return nil, err
			}
		}
		if !p.addKey(&keys, rawKey) {
			return nil, ErrDuplicateField
		}
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

// stream is array(depth) handing each element to each instead of keeping it.
func (p *parser) stream(depth int, each func(any)) (int, error) {
	if depth > MaxDepth {
		return 0, ErrDepth
	}
	p.i++ // [
	p.space()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return 0, nil
	}
	n := 0
	for {
		p.space()
		v, err := p.value(depth)
		if err != nil {
			return 0, err
		}
		each(v)
		n++
		p.space()
		if p.i >= len(p.b) {
			return 0, ErrSyntax
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return n, nil
		default:
			return 0, ErrSyntax
		}
	}
}

// skip is value(depth) without the value.
func (p *parser) skip(depth int) error {
	if p.i >= len(p.b) {
		return ErrSyntax
	}
	switch c := p.b[p.i]; {
	case c == '{':
		return p.skipObject(depth + 1)
	case c == '[':
		return p.skipArray(depth + 1)
	case c == '"':
		return p.skipString()
	case c == '-' || (c >= '0' && c <= '9'):
		_, err := p.scanNumber()
		return err
	case p.literal("true"), p.literal("false"), p.literal("null"):
		return nil
	case p.literal("NaN"), p.literal("Infinity"):
		return ErrNonFinite
	}
	return ErrSyntax
}

func (p *parser) skipObject(depth int) error {
	if depth > MaxDepth {
		return ErrDepth
	}
	p.i++ // {
	p.space()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return nil
	}
	keys := p.newKeys()
	defer p.dropKeys(keys)
	for {
		p.space()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return ErrSyntax
		}
		key, err := p.key()
		if err != nil {
			return err
		}
		p.space()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return ErrSyntax
		}
		p.i++
		p.space()
		if err := p.skip(depth); err != nil {
			return err
		}
		if !p.addKey(&keys, key) {
			return ErrDuplicateField
		}
		p.space()
		if p.i >= len(p.b) {
			return ErrSyntax
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return nil
		default:
			return ErrSyntax
		}
	}
}

func (p *parser) skipArray(depth int) error {
	if depth > MaxDepth {
		return ErrDepth
	}
	p.i++ // [
	p.space()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return nil
	}
	for {
		p.space()
		if err := p.skip(depth); err != nil {
			return err
		}
		p.space()
		if p.i >= len(p.b) {
			return ErrSyntax
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return nil
		default:
			return ErrSyntax
		}
	}
}

// skipString is str() without the string: the same characters are refused.
func (p *parser) skipString() error {
	p.i++ // opening quote
	for p.i < len(p.b) {
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return nil
		case c < 0x20:
			return ErrSyntax
		case c != '\\':
			p.i++
		default:
			if p.i+1 >= len(p.b) {
				return ErrSyntax
			}
			e := p.b[p.i+1]
			p.i += 2
			switch e {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				// A high surrogate's low half is the next escape; on its own
				// it is checked the same way.
				if _, ok := p.hex4(p.i); !ok {
					return ErrSyntax
				}
				p.i += 4
			default:
				return ErrSyntax
			}
		}
	}
	return ErrSyntax
}

// key is an object key, unescaped as str() would: a slice of the input when
// it has no escapes, which is the common case and allocates nothing.
func (p *parser) key() ([]byte, error) {
	start := p.i
	for j := start + 1; j < len(p.b); j++ {
		switch c := p.b[j]; {
		case c == '"':
			p.i = j + 1
			return p.b[start+1 : j], nil
		case c == '\\':
			s, err := p.str()
			if err != nil {
				return nil, err
			}
			return []byte(s.(string)), nil
		case c < 0x20:
			return nil, ErrSyntax
		}
	}
	return nil, ErrSyntax
}

// linearKeys is the number of keys an object's duplicate check compares one
// by one; an object with more gets a map.
const linearKeys = 32

// objectKeys is one object's part of the parser's key stack: p.keys[base:].
type objectKeys struct {
	base int
	big  map[string]struct{}
}

// newKeys starts an object's keys on the stack, which every object being
// checked shares, so a server list's thousands of small objects allocate
// nothing for their keys.
func (p *parser) newKeys() objectKeys { return objectKeys{base: len(p.keys)} }

// dropKeys ends the object's keys.
func (p *parser) dropKeys(k objectKeys) { p.keys = p.keys[:k.base] }

// addKey records key and reports false when the object already has it.
func (p *parser) addKey(k *objectKeys, key []byte) bool {
	if k.big != nil {
		if _, dup := k.big[string(key)]; dup {
			return false
		}
		k.big[string(key)] = struct{}{}
		return true
	}
	for _, have := range p.keys[k.base:] {
		if bytes.Equal(have, key) {
			return false
		}
	}
	p.keys = append(p.keys, key)
	if len(p.keys)-k.base > linearKeys {
		k.big = make(map[string]struct{}, 2*linearKeys)
		for _, have := range p.keys[k.base:] {
			k.big[string(have)] = struct{}{}
		}
	}
	return true
}
