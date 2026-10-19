package validate

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// skipCases are inputs whose errors the skip mode must reproduce exactly,
// beyond the golden file: each check, and checks that race (which error
// comes first).
var skipCases = []string{
	`{"a":1,"a":2}`,
	`{"a":1,"a":2}`,
	`{"\ud800":1,"\ud800":2}`,
	`{"😀":1,"` + "\U0001F600" + `":2}`,
	`{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9,"a":10}`,
	`{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"i":9,"j":10}`,
	`{"a":1,"b":2,"c":3,"d":4,"e":5,"f":6,"g":7,"h":8,"h":9}`,
	`[{"a":{"b":1,"b":1}}]`,
	`{"a":1,"a":[}`,          // the value's error comes before the duplicate
	`{"a":1,"a":NaN}`,        // likewise
	`{"a":{"b":1,"b":2},"a"`, // the inner duplicate first
	`{"abc":[1,2,{"x":1,"x":2}]}`,
	`{"abc":[1,2,3],"abc":[]}`,
	`{"ab":[1],"cd":{"e":[true,false,null]}}`,
	`{"value":NaN}`,
	`[Infinity]`,
	`-Infinity`,
	`[-Infinity]`,
	`-I`,
	`[1.]`,
	`[1.5e]`,
	`[1e+]`,
	`[01]`,
	`[-]`,
	`"\ud800\uZZZZ"`,
	`"\ud800\u"`,
	`"\x"`,
	"\"\t\"",
	`"\`,
	`{"\`,
	`{"a\"b":1,"a\"b":2}`,
	`{"a":}`,
	`{"a" 1}`,
	`{1:1}`,
	`{"a":1,}`,
	`[1,]`,
	`[1 2]`,
	strings.Repeat("[", 1001) + strings.Repeat("]", 1001),
	strings.Repeat("[", 1000) + strings.Repeat("]", 1000),
	`{"abc":` + strings.Repeat("[", 999) + strings.Repeat("]", 999) + `}`,
	`{"abc":` + strings.Repeat("[", 1000) + strings.Repeat("]", 1000) + `}`,
	`{"ab":` + strings.Repeat("[", 1000) + strings.Repeat("]", 1000) + `}`,
	strings.Repeat("1", 4301),
	"[" + strings.Repeat("1", 4301) + "]",
	"[-" + strings.Repeat("1", 4300) + "]",
	"[" + strings.Repeat("1", 4301) + ".5]",
	"[1e999, -1e999]",
	"\xff",
	"\"\xed\xa0\x80\"",
	"\ufeff{}",
	`{} trailing`,
	``,
	` `,
	`nul`,
	`{"abc":[1,2] , "ab" : "x" , "q":{"r":[{}]}}`,
}

func skipSeeds(t testing.TB) []string {
	raw, err := os.ReadFile("testdata/json_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []goldenJSON
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	out := append([]string(nil), skipCases...)
	// Objects past linearKeys, whose check moves to a map: a duplicate of a
	// key from before the move, of one after it, and none.
	var keys []string
	for i := range 40 {
		keys = append(keys, fmt.Sprintf(`"k%d":%d`, i, i))
	}
	many := strings.Join(keys, ",")
	out = append(out, "{"+many+"}", "{"+many+`,"k0":0}`, "{"+many+`,"k39":0}`, "{"+many+`,"k3":0}`,
		`{"abc":[{`+many+`},{`+many+`,"k1":1}]}`)
	for _, c := range cases {
		out = append(out, c.Input)
	}
	return out
}

// checkSkipMatches is the property both tests and the fuzzer assert:
// CheckJSON and DecodeJSONMembers refuse exactly what DecodeJSON refuses,
// with the same error, and build exactly the selected members.
func checkSkipMatches(t *testing.T, data []byte) {
	full, fullErr := DecodeJSON(data)
	if err := CheckJSON(data); err != fullErr {
		t.Fatalf("%.80q: CheckJSON %v, DecodeJSON %v", data, err, fullErr)
	}
	// Keys of even length are kept and keys of a length divisible by three
	// streamed, so some are both and some neither.
	streamed := map[string][]any{}
	plan := Plan{
		Keep: func(key string) bool { return len(key)%2 == 0 },
		Each: func(key string) func(any) {
			if len(key)%3 != 0 {
				return nil
			}
			return func(element any) { streamed[key] = append(streamed[key], element) }
		},
	}
	got, err := DecodeJSONMembers(data, plan)
	if err != fullErr {
		t.Fatalf("%.80q: DecodeJSONMembers %v, DecodeJSON %v", data, err, fullErr)
	}
	if err != nil {
		return
	}
	object, isObject := full.(map[string]any)
	if !isObject {
		if got != nil {
			t.Fatalf("%.80q: not an object, got %v", data, got)
		}
		return
	}
	want := 0
	for key, value := range object {
		list, isList := value.([]any)
		switch {
		case len(key)%3 == 0 && isList:
			want++
			if got[key] != Streamed(len(list)) || len(streamed[key]) != len(list) ||
				(len(list) > 0 && !reflect.DeepEqual(streamed[key], list)) {
				t.Fatalf("%.80q: %q streamed %v %v, want %v", data, key, got[key], streamed[key], list)
			}
		case len(key)%2 == 0:
			want++
			if !reflect.DeepEqual(got[key], value) {
				t.Fatalf("%.80q: %q is %v, want %v", data, key, got[key], value)
			}
		default:
			if _, present := got[key]; present {
				t.Fatalf("%.80q: %q was built", data, key)
			}
		}
	}
	if len(got) != want {
		t.Fatalf("%.80q: %d members, want %d", data, len(got), want)
	}
}

func TestSkipModeMatchesDecode(t *testing.T) {
	for _, in := range skipSeeds(t) {
		checkSkipMatches(t, []byte(in))
	}
}

func TestDecodeJSONMembers(t *testing.T) {
	var servers []any
	plan := Plan{
		Keep: func(key string) bool { return key == "version" },
		Each: func(key string) func(any) {
			if key != "servers" {
				return nil
			}
			return func(element any) { servers = append(servers, element) }
		},
	}
	got, err := DecodeJSONMembers([]byte(`{"servers":[{"a":1},2],"other":{"x":[1]},"version":1}`), plan)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"servers": Streamed(2), "version": int64(1)}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(servers, []any{map[string]any{"a": int64(1)}, int64(2)}) {
		t.Errorf("got %v and %v", got, servers)
	}
	// A streamed key whose value is not an array is left out like any other
	// member nobody keeps.
	got, err = DecodeJSONMembers([]byte(`{"servers":{"a":1}}`), plan)
	if err != nil || len(got) != 0 {
		t.Errorf("object under servers: %v %v", got, err)
	}
	// A duplicate between a skipped member and a kept one is still refused.
	if _, err := DecodeJSONMembers([]byte(`{"other":1,"version":1,"other":2}`), plan); err != ErrDuplicateField {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := DecodeJSONMembers([]byte(`{"other":{"x":1,"x":2},"version":1}`), plan); err != ErrDuplicateField {
		t.Errorf("nested duplicate in a skipped member: %v", err)
	}
	// Not an object: checked, nothing built.
	if got, err := DecodeJSONMembers([]byte(`[1,2]`), plan); got != nil || err != nil {
		t.Errorf("array: %v %v", got, err)
	}
	if _, err := DecodeJSONMembers([]byte(`[1,NaN]`), plan); err != ErrNonFinite {
		t.Errorf("array with NaN: %v", err)
	}
}

// The skip mode's allocations (the parser and its key stack) do not grow
// with the number of values or of small objects.
func TestCheckJSONAllocationsDoNotGrow(t *testing.T) {
	allocs := func(n int) float64 {
		doc := []byte(`{"servers":[` + strings.Repeat(`{"hostname":"relay.example.test","ips":["192.0.2.1","2001:db8::1"],"n":12,"f":1.5,"ok":true},`, n) +
			`{}],"version":1}`)
		return testing.AllocsPerRun(10, func() {
			if err := CheckJSON(doc); err != nil {
				t.Fatal(err)
			}
		})
	}
	if small, large := allocs(10), allocs(2000); large > small || large > 8 {
		t.Errorf("CheckJSON allocated %v times for 10 objects, %v for 2000", small, large)
	}
}

func FuzzDecodeJSONMembers(f *testing.F) {
	for _, in := range skipSeeds(f) {
		f.Add([]byte(in))
	}
	f.Fuzz(checkSkipMatches)
}
