// Tests for molebridge/validate.py (decode_json, valid_key, valid_ipv4,
// valid_text) and for the JSON encoding the state files rely on
// (state.write_json_atomic's json.dump output). The golden files were made by
// running the Python code on the same inputs.
package validate

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"os"
	"strings"
	"testing"
)

type goldenJSON struct {
	Input  string  `json:"input"`
	Output *string `json:"output"`
}

func TestDecodeJSONGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/json_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []goldenJSON
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 500 {
		t.Fatalf("only %d golden cases", len(cases))
	}
	for _, c := range cases {
		v, err := DecodeJSONString(c.Input)
		if c.Output == nil {
			if err == nil {
				t.Errorf("%.60q: accepted, Python rejects", c.Input)
			}
			continue
		}
		if err != nil {
			t.Errorf("%.60q: rejected (%v), Python accepts", c.Input, err)
			continue
		}
		got, err := sortedJSON(v)
		if err != nil {
			t.Errorf("%.60q: encode: %v", c.Input, err)
			continue
		}
		if got != *c.Output {
			t.Errorf("%.60q:\n got %.200s\nwant %.200s", c.Input, got, *c.Output)
		}
	}
}

func sortedJSON(v any) (string, error) {
	b, err := MarshalJSON(v)
	return string(b), err
}

func TestDecodeJSONErrorsAreSpecific(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want error
	}{
		{`{"a":1,"a":2}`, ErrDuplicateField},
		{`[{"a":{"b":1,"b":1}}]`, ErrDuplicateField},
		{`{"a":1,"\u0061":2}`, ErrDuplicateField},
		{`{"value":NaN}`, ErrNonFinite},
		{`[Infinity]`, ErrNonFinite},
		{`-Infinity`, ErrNonFinite},
		{strings.Repeat("[", 1001) + strings.Repeat("]", 1001), ErrDepth},
		{strings.Repeat("[", 2000), ErrDepth},
		{strings.Repeat("1", 4301), ErrIntegerSize},
		{"\xff", ErrInvalidUTF8},
		{"\"\xed\xa0\x80\"", ErrInvalidUTF8}, // a surrogate written as UTF-8
		{"\ufeff{}", ErrSyntax},              // a byte order mark
		{`{} trailing`, ErrSyntax},
		{``, ErrSyntax},
	} {
		_, err := DecodeJSONString(tc.in)
		if !errors.Is(err, tc.want) {
			t.Errorf("%.40q: got %v, want %v", tc.in, err, tc.want)
		}
	}
	// A thousand levels is accepted.
	if _, err := DecodeJSONString(strings.Repeat("[", 1000) + strings.Repeat("]", 1000)); err != nil {
		t.Errorf("1000 levels: %v", err)
	}
	// Errors never echo the input.
	_, err := DecodeJSONString(`{"SECRET":1,"SECRET":2}`)
	if strings.Contains(err.Error(), "SECRET") {
		t.Errorf("error echoes input: %v", err)
	}
}

func TestDecodedTypes(t *testing.T) {
	v, err := DecodeJSONString(`{"i":5,"f":5.0,"e":1e2,"big":123456789012345678901234567890,"neg":-0,"t":true,"n":null,"s":"x","l":[1],"huge":1e999}`)
	if err != nil {
		t.Fatal(err)
	}
	m := v.(map[string]any)
	if n, ok := IsInt(m["i"]); !ok || n != 5 {
		t.Errorf("i: %v %v", n, ok)
	}
	for _, k := range []string{"f", "e", "t", "n", "s", "l", "big"} {
		if _, ok := IsInt(m[k]); ok {
			t.Errorf("%s is not an int", k)
		}
	}
	if !IsIntType(m["big"]) || IsIntType(m["f"]) || IsIntType(m["t"]) {
		t.Error("IsIntType")
	}
	if _, ok := m["big"].(*big.Int); !ok {
		t.Errorf("big: %T", m["big"])
	}
	if n, ok := m["neg"].(int64); !ok || n != 0 {
		t.Errorf("-0: %#v", m["neg"])
	}
	if f, ok := IsFloat(m["f"]); !ok || f != 5 {
		t.Error("float")
	}
	if f := m["huge"].(float64); !math.IsInf(f, 1) {
		t.Errorf("1e999 should overflow to +Inf as Python's does, got %v", f)
	}
	if _, ok := IsFloat(m["i"]); ok {
		t.Error("int is not a float")
	}
	if _, ok := IsInt(true); ok {
		t.Error("bool is not an int")
	}
}

func TestLoneSurrogatesSurviveDecodeAndEncode(t *testing.T) {
	v, err := DecodeJSONString(`["\ud800", "a\udc80b", "\ud83d\ude00", "\ud83d"]`)
	if err != nil {
		t.Fatal(err)
	}
	list := v.([]any)
	if RuneCount(list[0].(string)) != 1 || RuneCount(list[1].(string)) != 3 || RuneCount(list[2].(string)) != 1 {
		t.Errorf("rune counts: %v", list)
	}
	rs := Runes(list[1].(string))
	if len(rs) != 3 || rs[1] != 0xDC80 || !IsSurrogate(rs[1]) {
		t.Errorf("runes: %x", rs)
	}
	out, err := MarshalJSON(list)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `["\ud800", "a\udc80b", "\ud83d\ude00", "\ud83d"]` {
		t.Errorf("encoded: %s", out)
	}
	if ValidText(list[0]) != true {
		t.Error("a lone surrogate is >= 32, so valid_text accepts it")
	}
}

func TestValidKey(t *testing.T) {
	good := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	for _, tc := range []struct {
		in any
		ok bool
	}{
		{good, true},
		{"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", true},
		{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=", false}, // non-canonical trailing bits
		{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},  // no padding
		{good + "\n", false},
		{"AAAA", false},
		{"not a key", false},
		{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n", false},
		{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nAAA=", false}, // newline inside: base64 ignores it, re-encoding does not
		{5, false},
		{nil, false},
		{[]string{good}, false},
		{strings.Repeat("A", 42) + "Q=", true},
	} {
		if got := ValidKey(tc.in); got != tc.ok {
			t.Errorf("ValidKey(%#v) = %v", tc.in, got)
		}
	}
}

func TestValidIPv4(t *testing.T) {
	for _, tc := range []struct {
		in any
		ok bool
	}{
		{"198.51.100.1", true}, {"0.0.0.0", true}, {"255.255.255.255", true},
		{"198.51.100.01", false}, {"198.51.100.011", false}, {"198.51.100", false}, {"198.51.100.256", false},
		{" 198.51.100.1", false}, {"198.51.100.1 ", false}, {"198.51.100.1\n", false},
		{"2001:db8::1", false}, {"::ffff:198.51.100.1", false}, {"", false}, {nil, false}, {4, false},
		{"198.51.100.1/24", false}, {"example.test", false},
	} {
		if got := ValidIPv4(tc.in); got != tc.ok {
			t.Errorf("ValidIPv4(%#v) = %v", tc.in, got)
		}
	}
}

func TestValidText(t *testing.T) {
	for _, tc := range []struct {
		in any
		ok bool
	}{
		{"x", true}, {strings.Repeat("x", 256), true}, {strings.Repeat("x", 257), false},
		{strings.Repeat("é", 256), true}, {strings.Repeat("é", 257), false},
		{strings.Repeat("😀", 256), true}, {strings.Repeat("😀", 257), false},
		{"", false}, {"a\x00b", false}, {"a\nb", false}, {"a\x1fb", false}, {"a\x7fb", true}, {"a\u0085b", true},
		{nil, false}, {5, false}, {[]string{"x"}, false},
	} {
		if got := ValidText(tc.in); got != tc.ok {
			t.Errorf("ValidText(%.20q) = %v", tc.in, got)
		}
	}
}

func TestEncodeMatchesPython(t *testing.T) {
	type inner struct {
		A int    `json:"a"`
		B string `json:"b,omitempty"`
	}
	type sample struct {
		Name  string         `json:"name"`
		Count int            `json:"count"`
		Ptr   *int           `json:"ptr"`
		Skip  string         `json:"-"`
		Maybe *bool          `json:"maybe,omitempty"`
		List  []string       `json:"list"`
		Nil   []string       `json:"nil"`
		In    inner          `json:"in"`
		M     map[string]int `json:"m"`
	}
	one := 1
	got, err := MarshalJSON(sample{Name: "é\x7f<>&", Count: 3, Ptr: &one, Skip: "no", List: []string{"a", "b"},
		In: inner{A: 1}, M: map[string]int{"z": 1, "a": 2}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name": "\u00e9\u007f<>&", "count": 3, "ptr": 1, "list": ["a", "b"], "nil": null, "in": {"a": 1}, "m": {"a": 2, "z": 1}}`
	if string(got) != want {
		t.Errorf("\n got %s\nwant %s", got, want)
	}
	o := Obj{{"z", 1}, {"a", []any{}}, {"m", Obj{}}, {"f", 1.0}}
	got, err = MarshalJSON(o)
	if err != nil || string(got) != `{"z": 1, "a": [], "m": {}, "f": 1.0}` {
		t.Errorf("obj: %s %v", got, err)
	}
	o = o.Set("a", 5).Set("new", nil)
	got, _ = MarshalJSON(o)
	if string(got) != `{"z": 1, "a": 5, "m": {}, "f": 1.0, "new": null}` {
		t.Errorf("obj set: %s", got)
	}
}

func TestEncodeFloats(t *testing.T) {
	for _, tc := range []struct {
		f    float64
		want string
	}{
		{0, "0.0"}, {math.Copysign(0, -1), "-0.0"}, {1, "1.0"}, {100, "100.0"}, {1.5, "1.5"}, {1e15, "1000000000000000.0"},
		{1e16, "1e+16"}, {1.2345678901234568e+17, "1.2345678901234568e+17"}, {0.0001, "0.0001"}, {0.00001, "1e-05"},
		{1.5e-7, "1.5e-07"}, {5e-324, "5e-324"}, {1e22, "1e+22"}, {-2.5, "-2.5"}, {0.1, "0.1"},
		{123456789012345.0, "123456789012345.0"}, {1.7976931348623157e308, "1.7976931348623157e+308"},
	} {
		if got := FormatFloat(tc.f); got != tc.want {
			t.Errorf("FormatFloat(%v) = %s, want %s", tc.f, got, tc.want)
		}
	}
	for _, f := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := MarshalJSON(map[string]any{"x": f}); !errors.Is(err, ErrNonFiniteFloat) {
			t.Errorf("%v: %v", f, err)
		}
	}
}

func TestEncodeBigIntAndInvalidUTF8(t *testing.T) {
	v, _ := DecodeJSONString(`[123456789012345678901234567890]`)
	got, err := MarshalJSON(v)
	if err != nil || string(got) != `[123456789012345678901234567890]` {
		t.Errorf("%s %v", got, err)
	}
	if _, err := MarshalJSON("a\xffb"); err == nil {
		t.Error("invalid UTF-8 must not encode")
	}
}

type countingWriter struct {
	n, limit int
	writes   int
}

var errLimit = errors.New("limit")

func (w *countingWriter) Write(p []byte) (int, error) {
	w.writes++
	if w.n+len(p) > w.limit {
		return 0, errLimit
	}
	w.n += len(p)
	return len(p), nil
}

func TestEncodeStopsEarlyOnWriterError(t *testing.T) {
	big := make([]any, 200000)
	for i := range big {
		big[i] = strings.Repeat("x", 100)
	}
	w := &countingWriter{limit: 1000}
	if err := EncodeJSON(w, big); !errors.Is(err, errLimit) {
		t.Fatalf("got %v", err)
	}
	if w.writes != 1 {
		t.Errorf("encoder kept writing after the failure: %d writes", w.writes)
	}
	// One long string is cut into chunks, not buffered whole.
	w = &countingWriter{limit: 1000}
	if err := EncodeJSON(w, strings.Repeat("é", 1<<20)); !errors.Is(err, errLimit) || w.writes != 1 {
		t.Errorf("long string: %v after %d writes", err, w.writes)
	}
	var buf bytes.Buffer
	if err := EncodeJSON(&buf, strings.Repeat("é", 100000)); err != nil || buf.Len() != 100000*6+2 {
		t.Errorf("long string: %v %d", err, buf.Len())
	}
}

func FuzzDecodeJSON(f *testing.F) {
	raw, _ := os.ReadFile("testdata/json_golden.json")
	var cases []goldenJSON
	_ = json.Unmarshal(raw, &cases)
	for _, c := range cases {
		f.Add([]byte(c.Input))
	}
	f.Add([]byte(`{"a":[1,2,{"b":null}],"a":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := DecodeJSON(data)
		if err != nil {
			return
		}
		// What decodes encodes (the one exception is a non-finite float from
		// a literal such as 1e999), and what was encoded decodes to the same.
		enc, err := MarshalJSON(v)
		if err != nil {
			if errors.Is(err, ErrNonFiniteFloat) {
				return
			}
			t.Fatalf("decoded value does not encode: %v", err)
		}
		again, err := DecodeJSON(enc)
		if err != nil {
			t.Fatalf("encoded output does not decode: %v", err)
		}
		enc2, err := MarshalJSON(again)
		if err != nil || !bytes.Equal(enc, enc2) {
			t.Fatalf("encoding is not stable: %q vs %q (%v)", enc, enc2, err)
		}
	})
}
