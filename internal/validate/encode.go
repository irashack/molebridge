package validate

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Pair is one member of an Obj.
type Pair struct {
	Key   string
	Value any
}

// Obj is a JSON object whose members are written in the order given, like a
// Python dict. A plain map[string]any is written with sorted keys instead.
type Obj []Pair

// Members builds an Obj from alternating keys and values:
// Members("a", 1, "b", nil). It panics on a malformed call, which is a
// programming error. (Composite literals of Pair would trip go vet outside this
// package.)
func Members(keyValues ...any) Obj {
	if len(keyValues)%2 != 0 {
		panic("validate.Members: odd number of arguments")
	}
	o := make(Obj, 0, len(keyValues)/2)
	for i := 0; i < len(keyValues); i += 2 {
		key, ok := keyValues[i].(string)
		if !ok {
			panic("validate.Members: key is not a string")
		}
		o = append(o, Pair{key, keyValues[i+1]})
	}
	return o
}

// Set returns o with key set to value, replacing it in place when present.
func (o Obj) Set(key string, value any) Obj {
	for i := range o {
		if o[i].Key == key {
			o[i].Value = value
			return o
		}
	}
	return append(o, Pair{key, value})
}

// ObjectMarshaler is implemented by types that know the member order Python
// wrote them in.
type ObjectMarshaler interface {
	JSONObject() Obj
}

// ErrNonFiniteFloat is returned for NaN and the infinities, which
// json.dump(allow_nan=False) refuses.
var ErrNonFiniteFloat = errors.New("out of range float values are not JSON compliant")

// MarshalJSON returns EncodeJSON's output.
func MarshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := EncodeJSON(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// EncodeJSON writes v the way Python's json.dump(v, allow_nan=False) does:
// ", " and ": " separators, no indentation, no trailing newline, and every
// character outside printable ASCII as a \u escape (a DEL too). It writes
// small chunks through a buffer, so a writer that fails or counts can stop a
// very large document early without it ever being held in memory as output.
//
// v may hold nil, bool, string, any integer or float type, *big.Int, slices,
// arrays, Obj, map[string]T (keys sorted), structs (fields in declaration
// order, named and omitted by their `json` tag), pointers, and values that
// implement ObjectMarshaler. A nil slice or map is null, a nil Obj is {}.
func EncodeJSON(w io.Writer, v any) error {
	e := &encoder{w: w, buf: make([]byte, 0, chunkSize)}
	if err := e.value(reflect.ValueOf(v), 0); err != nil {
		return err
	}
	e.flush()
	return e.err
}

// chunkSize is how much output the encoder holds before it hands it to the
// writer; the writer sees a failure within one chunk of its limit.
const chunkSize = 32 * 1024

// encoder buffers output and stops at the first write error.
type encoder struct {
	w       io.Writer
	buf     []byte
	err     error
	scratch [32]byte
}

func (e *encoder) flush() {
	if e.err == nil && len(e.buf) > 0 {
		_, e.err = e.w.Write(e.buf)
	}
	e.buf = e.buf[:0]
}

func (e *encoder) WriteString(s string) {
	e.buf = append(e.buf, s...)
	if len(e.buf) >= chunkSize {
		e.flush()
	}
}

func (e *encoder) WriteByte(c byte) error {
	e.buf = append(e.buf, c)
	if len(e.buf) >= chunkSize {
		e.flush()
	}
	return nil
}

func (e *encoder) Write(b []byte) {
	e.buf = append(e.buf, b...)
	if len(e.buf) >= chunkSize {
		e.flush()
	}
}

var (
	objMarshalerType = reflect.TypeOf((*ObjectMarshaler)(nil)).Elem()
	objType          = reflect.TypeOf(Obj(nil))
	bigIntType       = reflect.TypeOf((*big.Int)(nil))
)

func (e *encoder) value(v reflect.Value, depth int) error {
	if e.err != nil {
		return e.err
	}
	if depth > MaxDepth {
		return ErrDepth
	}
	if !v.IsValid() {
		e.WriteString("null")
		return e.err
	}
	if v.Type().Implements(objMarshalerType) && !(v.Kind() == reflect.Pointer && v.IsNil()) {
		return e.object(v.Interface().(ObjectMarshaler).JSONObject(), depth)
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			e.WriteString("null")
			return e.err
		}
		if v.Type() == bigIntType {
			e.WriteString(v.Interface().(*big.Int).String())
			return e.err
		}
		return e.value(v.Elem(), depth)
	case reflect.Bool:
		if v.Bool() {
			e.WriteString("true")
			return e.err
		}
		e.WriteString("false")
		return e.err
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		e.Write(strconv.AppendInt(e.scratch[:0], v.Int(), 10))
		return e.err
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		e.Write(strconv.AppendUint(e.scratch[:0], v.Uint(), 10))
		return e.err
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return ErrNonFiniteFloat
		}
		e.WriteString(FormatFloat(f))
		return e.err
	case reflect.String:
		return e.str(v.String())
	case reflect.Slice:
		if v.Type() == objType {
			// A nil Obj is an empty object, not null.
			return e.object(v.Interface().(Obj), depth)
		}
		if v.IsNil() {
			e.WriteString("null")
			return e.err
		}
		fallthrough
	case reflect.Array:
		e.WriteByte('[')
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				e.WriteString(", ")
			}
			if err := e.value(v.Index(i), depth+1); err != nil {
				return err
			}
		}
		return e.WriteByte(']')
	case reflect.Map:
		if v.IsNil() {
			e.WriteString("null")
			return e.err
		}
		if v.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("validate: unsupported map key type %s", v.Type().Key())
		}
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		pairs := make(Obj, 0, len(keys))
		for _, k := range keys {
			pairs = append(pairs, Pair{k.String(), v.MapIndex(k).Interface()})
		}
		return e.object(pairs, depth)
	case reflect.Struct:
		return e.structure(v, depth)
	}
	return fmt.Errorf("validate: unsupported type %s", v.Type())
}

func (e *encoder) object(o Obj, depth int) error {
	e.WriteByte('{')
	for i, p := range o {
		if i > 0 {
			e.WriteString(", ")
		}
		if err := e.str(p.Key); err != nil {
			return err
		}
		e.WriteString(": ")
		if err := e.value(reflect.ValueOf(p.Value), depth+1); err != nil {
			return err
		}
	}
	return e.WriteByte('}')
}

type field struct {
	name      string
	omitEmpty bool
	index     []int
}

func structFields(t reflect.Type, prefix []int) []field {
	var out []field
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		index := append(append([]int(nil), prefix...), i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" && f.Type.Kind() == reflect.Struct {
			out = append(out, structFields(f.Type, index)...)
			continue
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out = append(out, field{name, strings.Contains(opts, "omitempty"), index})
	}
	return out
}

func isEmpty(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Pointer:
		return v.IsNil()
	}
	return false
}

func (e *encoder) structure(v reflect.Value, depth int) error {
	e.WriteByte('{')
	first := true
	for _, f := range structFields(v.Type(), nil) {
		fv := v.FieldByIndex(f.index)
		if f.omitEmpty && isEmpty(fv) {
			continue
		}
		if !first {
			e.WriteString(", ")
		}
		first = false
		if err := e.str(f.name); err != nil {
			return err
		}
		e.WriteString(": ")
		if err := e.value(fv, depth+1); err != nil {
			return err
		}
	}
	return e.WriteByte('}')
}

const hexDigits = "0123456789abcdef"

func (e *encoder) u4(r rune) {
	e.WriteString(`\u`)
	e.WriteByte(hexDigits[r>>12&0xF])
	e.WriteByte(hexDigits[r>>8&0xF])
	e.WriteByte(hexDigits[r>>4&0xF])
	e.WriteByte(hexDigits[r&0xF])
}

// str writes s as Python's ensure_ascii encoder does.
func (e *encoder) str(s string) error {
	e.WriteByte('"')
	for len(s) > 0 {
		c := s[0]
		if c < utf8.RuneSelf {
			switch {
			case c == '"':
				e.WriteString(`\"`)
			case c == '\\':
				e.WriteString(`\\`)
			case c == '\n':
				e.WriteString(`\n`)
			case c == '\r':
				e.WriteString(`\r`)
			case c == '\t':
				e.WriteString(`\t`)
			case c == '\b':
				e.WriteString(`\b`)
			case c == '\f':
				e.WriteString(`\f`)
			case c < 0x20 || c == 0x7F:
				e.u4(rune(c))
			default:
				e.WriteByte(c)
			}
			s = s[1:]
			continue
		}
		r, size := NextRune(s)
		if r == utf8.RuneError && size == 1 {
			return errors.New("validate: string is not valid UTF-8")
		}
		if r >= 0x10000 {
			r -= 0x10000
			e.u4(0xD800 | r>>10&0x3FF)
			e.u4(0xDC00 | r&0x3FF)
		} else {
			e.u4(r)
		}
		s = s[size:]
	}
	return e.WriteByte('"')
}

// FormatFloat is Python's repr(float): the shortest text that reads back as
// the same number, in fixed notation for decimal exponents from -4 to 16 and
// scientific ("1e+16", "1.5e-05") outside it, and never an integer-looking
// "1" for a float (it is "1.0").
func FormatFloat(f float64) string {
	if f == 0 {
		if math.Signbit(f) {
			return "-0.0"
		}
		return "0.0"
	}
	s := strconv.FormatFloat(f, 'e', -1, 64) // d.ddde±XX
	sign := ""
	if s[0] == '-' {
		sign, s = "-", s[1:]
	}
	mantissa, exp, _ := strings.Cut(s, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	exponent, _ := strconv.Atoi(exp)
	decpt := exponent + 1
	switch {
	case decpt > 16 || decpt < -3:
		out := digits[:1]
		if len(digits) > 1 {
			out += "." + digits[1:]
		}
		e := exponent
		esign := "+"
		if e < 0 {
			esign, e = "-", -e
		}
		return fmt.Sprintf("%s%se%s%02d", sign, out, esign, e)
	case decpt <= 0:
		return sign + "0." + strings.Repeat("0", -decpt) + digits
	case decpt >= len(digits):
		return sign + digits + strings.Repeat("0", decpt-len(digits)) + ".0"
	default:
		return sign + digits[:decpt] + "." + digits[decpt:]
	}
}
