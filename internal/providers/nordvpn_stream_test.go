package providers

import (
	"sort"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/validate"
)

// ParseNordCatalogBody reads each server as the list goes by and joins the
// servers to the tables after the document ends; these tests hold it to
// ParseNordCatalog on the decoded document, whatever order the members come
// in.

// inOrder encodes doc's members in the given order, then any others sorted.
func inOrder(doc map[string]any, first ...string) []byte {
	var o validate.Obj
	seen := map[string]bool{}
	for _, k := range first {
		if v, ok := doc[k]; ok {
			o = append(o, validate.Pair{Key: k, Value: v})
			seen[k] = true
		}
	}
	var rest []string
	for k := range doc {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		o = append(o, validate.Pair{Key: k, Value: doc[k]})
	}
	return mustMarshal(o)
}

// nordOrders are member orders to try: the tables before the servers, after
// them, and around them.
var nordOrders = [][]string{
	{"groups", "services", "locations", "technologies", "servers"},
	{"servers", "groups", "services", "locations", "technologies"},
	{"technologies", "locations", "servers", "services", "groups"},
	{"locations", "servers", "technologies"},
}

// sameNordResult checks that the body parser gives what the tree parser gives
// for raw: the same error text, or the same entries in the same order.
func sameNordResult(t *testing.T, label string, raw []byte) {
	t.Helper()
	decoded, decodeErr := validate.DecodeJSON(raw)
	got, err := ParseNordCatalogBody(raw, false)
	if decodeErr != nil {
		if err != decodeErr {
			t.Errorf("%s: body %v, decoder %v", label, err, decodeErr)
		}
		return
	}
	want, wantErr := ParseNordCatalog(decoded)
	if (err == nil) != (wantErr == nil) || (err != nil && err.Error() != wantErr.Error()) {
		t.Errorf("%s: body %v, tree %v", label, err, wantErr)
		return
	}
	if err != nil {
		return
	}
	if !equalStrings(names(got), names(want)) {
		t.Errorf("%s: body %v, tree %v", label, names(got), names(want))
		return
	}
	want.Each(func(name string, r *Relay) bool {
		g, _ := got.Get(name)
		if !sameJSON(t, g, r) {
			t.Errorf("%s: %s differs", label, name)
		}
		return true
	})
}

func TestNordBodyMatchesTheDecodedDocumentInAnyOrder(t *testing.T) {
	first := func(change func(server map[string]any)) func(map[string]any) {
		return func(doc map[string]any) { change(obj(list(doc["servers"])[0])) }
	}
	changes := map[string]func(doc map[string]any){
		"unchanged": func(map[string]any) {},
		"offline":   first(func(s map[string]any) { s["status"] = "offline" }),
		"twin": func(doc map[string]any) {
			doc["servers"] = append(list(doc["servers"]), clonePlain(obj(list(doc["servers"])[0])))
		},
		"twin of a dropped server": func(doc map[string]any) {
			twin := clonePlain(obj(list(doc["servers"])[0]))
			twin["status"] = "offline"
			doc["servers"] = append(list(doc["servers"]), twin)
		},
		"non-objects": func(doc map[string]any) {
			doc["servers"] = append(list(doc["servers"]), nil, "x", int64(5), []any{}, map[string]any{})
		},
		"no servers":         func(doc map[string]any) { doc["servers"] = []any{} },
		"servers an object":  func(doc map[string]any) { doc["servers"] = map[string]any{} },
		"servers missing":    func(doc map[string]any) { delete(doc, "servers") },
		"groups missing":     func(doc map[string]any) { delete(doc, "groups") },
		"locations a string": func(doc map[string]any) { doc["locations"] = "x" },
		"too many servers": func(doc map[string]any) {
			doc["servers"] = append(list(doc["servers"]), make([]any, nordMaxServers)...)
		},
		"too many services": func(doc map[string]any) { doc["services"] = make([]any, nordMaxTable+1) },
		"servers at the limit": func(doc map[string]any) {
			doc["servers"] = append(list(doc["servers"]), make([]any, nordMaxServers-len(list(doc["servers"])))...)
		},
		"no wireguard technology": func(doc map[string]any) {
			obj(list(doc["technologies"])[2])["identifier"] = "openvpn_xor"
		},
		"two wireguard rows": first(func(s map[string]any) {
			s["technologies"] = append(list(s["technologies"]), clonePlain(wireguardRow(s)))
		}),
		"wireguard row offline":   first(func(s map[string]any) { wireguardRow(s)["status"] = "offline" }),
		"wireguard row no key":    first(func(s map[string]any) { wireguardRow(s)["metadata"] = []any{} }),
		"technologies not a list": first(func(s map[string]any) { s["technologies"] = "x" }),
		"station differs":         first(func(s map[string]any) { s["station"] = "198.51.100.99" }),
		"two locations":           first(func(s map[string]any) { s["location_ids"] = append(list(s["location_ids"]), int64(1)) }),
		"unknown location":        first(func(s map[string]any) { s["location_ids"] = []any{int64(424242)} }),
		"group ids mistyped":      first(func(s map[string]any) { s["group_ids"] = []any{"1"} }),
		"load out of range":       first(func(s map[string]any) { s["load"] = int64(101) }),
		"no load":                 first(func(s map[string]any) { delete(s, "load") }),
		"virtual": first(func(s map[string]any) {
			s["specifications"] = []any{map[string]any{"identifier": "virtual_location",
				"values": []any{map[string]any{"value": "true"}}}}
		}),
		"malformed table rows": func(doc map[string]any) {
			doc["groups"] = append(list(doc["groups"]), nil, map[string]any{"id": "a", "identifier": "legacy_standard"})
			doc["locations"] = append(list(doc["locations"]), map[string]any{"id": int64(6), "country": "x"})
			doc["technologies"] = append(list(doc["technologies"]), map[string]any{"id": int64(9), "identifier": int64(4)})
		},
		"ambiguous service id": func(doc map[string]any) {
			doc["services"] = append(list(doc["services"]), clonePlain(obj(list(doc["services"])[0])))
		},
		"extra members": func(doc map[string]any) {
			doc["meta"] = map[string]any{"total": int64(3), "nested": []any{[]any{map[string]any{}}}}
		},
	}
	for label, change := range changes {
		doc := obj(clone(t, nordData(t)))
		change(doc)
		for _, order := range nordOrders {
			sameNordResult(t, label+" / "+strings.Join(order, ","), inOrder(doc, order...))
		}
	}
	for _, raw := range []string{`null`, `[]`, `"servers"`, `{}`, `{"servers":[]}`, `{"servers":[1,]}`,
		`{"servers":[],"servers":[]}`, `{"groups":[],"groups":[]}`, `{"servers":[{"a":1,"a":2}]}`,
		`{"meta":{"a":NaN},"servers":[]}`, "{\"servers\":[\"\xff\"]}"} {
		sameNordResult(t, raw, []byte(raw))
	}
}

// The fixture's servers come out the same with its tables first or last.
func TestNordTablesAfterTheServers(t *testing.T) {
	data := nordData(t)
	before, err := ParseNordCatalogBody(inOrder(data, nordOrders[0]...), false)
	if err != nil {
		t.Fatal(err)
	}
	after, err := ParseNordCatalogBody(inOrder(data, nordOrders[1]...), false)
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(names(before), []string{nordUS, nordDE}) || !equalStrings(names(after), names(before)) {
		t.Errorf("tables first %v, last %v", names(before), names(after))
	}
}

func FuzzNordBodyMatchesTheDecodedDocument(f *testing.F) {
	data := nordData(f)
	for _, order := range nordOrders {
		f.Add(inOrder(data, order...))
	}
	f.Add(readFixture(f, "nordvpn", "nordvpn-servers.json"))
	f.Add([]byte(`{"servers":[],"groups":[],"services":[],"locations":[],"technologies":[]}`))
	f.Fuzz(func(t *testing.T, raw []byte) { sameNordResult(t, "fuzz", raw) })
}
