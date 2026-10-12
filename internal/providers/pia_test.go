// Tests for molebridge/pia.py, ported from tools/test_pia.py (the catalogue
// section: test_region_catalogue_keeps_only_validated_fields,
// test_country_names_come_from_unprefixed_regions_and_known_prefixes,
// test_invalid_regions_are_dropped, test_duplicate_region_rejected,
// test_port_forward_only_catalogue, test_snapshot_of_another_provider_has_no_
// authority). The applier parts of test_pia.py (registration, rules, port
// forwarding, secrets) belong to the applier port.
package providers

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/validate"
)

const testRegion = "ex_example"

func testRegionJSON(changes map[string]any) map[string]any {
	r := map[string]any{"id": testRegion, "name": "EX Example City", "country": "EX", "offline": false,
		"port_forward": true, "geo": false, "auto_region": true, "dns": "example.test",
		"servers": map[string]any{
			"wg":   []any{map[string]any{"ip": "198.51.100.20", "cn": "example401"}},
			"meta": []any{map[string]any{"ip": "198.51.100.21", "cn": "example401"}}}}
	for k, v := range changes {
		r[k] = v
	}
	return r
}

func serverlist(t testing.TB, regions ...map[string]any) []byte {
	if len(regions) == 0 {
		regions = []map[string]any{testRegionJSON(nil)}
	}
	list := make([]any, len(regions))
	for i, r := range regions {
		list[i] = r
	}
	raw, err := json.Marshal(map[string]any{"groups": map[string]any{}, "regions": list})
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, []byte("\n\nSIGNATURE-NOT-JSON")...)
}

func TestRegionCatalogueKeepsOnlyValidatedFields(t *testing.T) {
	got, err := ParsePIACatalog(serverlist(t), false)
	if err != nil {
		t.Fatal(err)
	}
	found, ok := got.Get(testRegion)
	if !ok || got.Len() != 1 {
		t.Fatalf("%v", names(got))
	}
	want := &Relay{Shape: ShapePIA, Hostname: testRegion, Country: "EX", City: "Example City", LocationCode: "ex-ex_example",
		IPv4AddrIn: "198.51.100.21", PortForward: true, Geo: false, Servers: []Server{{"198.51.100.20", "example401"}}}
	if !sameJSON(t, found, want) {
		t.Errorf("got %+v", found)
	}
	raw, _ := jsonMarshal(found)
	if string(raw) != `{"hostname": "ex_example", "city": "Example City", "country": "EX", "location_code": "ex-ex_example", `+
		`"ipv4_addr_in": "198.51.100.21", "port_forward": true, "geo": false, "servers": [{"ip": "198.51.100.20", "cn": "example401"}]}` {
		t.Errorf("stored as %s", raw)
	}
	if PIADetails(found) != "port forwarding" {
		t.Errorf("details = %q", PIADetails(found))
	}
	// Without a meta server the first WireGuard server is the latency target.
	noMeta := testRegionJSON(map[string]any{"servers": map[string]any{"wg": []any{map[string]any{"ip": "198.51.100.20", "cn": "example401"}}}})
	got, _ = ParsePIACatalog(serverlist(t, noMeta), false)
	if r, _ := got.Get(testRegion); r.IPv4AddrIn != "198.51.100.20" {
		t.Errorf("latency target %s", r.IPv4AddrIn)
	}
	// A meta list that does not validate is ignored the same way.
	badMeta := testRegionJSON(map[string]any{"servers": map[string]any{
		"wg":   []any{map[string]any{"ip": "198.51.100.20", "cn": "example401"}},
		"meta": []any{map[string]any{"ip": "nope", "cn": "x"}}}})
	got, _ = ParsePIACatalog(serverlist(t, badMeta), false)
	if r, _ := got.Get(testRegion); r == nil || r.IPv4AddrIn != "198.51.100.20" {
		t.Errorf("bad meta: %+v", r)
	}
}

func TestCountryNamesComeFromUnprefixedRegionsAndKnownPrefixes(t *testing.T) {
	got, err := ParsePIACatalog(serverlist(t,
		testRegionJSON(map[string]any{"id": "ex_one", "name": "EX One"}),
		testRegionJSON(map[string]any{"id": "exland", "name": "Exampleland"}),
		testRegionJSON(map[string]any{"id": "uk_x", "name": "UK Example", "country": "GB"}),
		testRegionJSON(map[string]any{"id": "us_x", "name": "US East", "country": "US"})), false)
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string][2]string{
		"ex_one": {"Exampleland", "One"}, "exland": {"Exampleland", "Exampleland"},
		"uk_x": {"United Kingdom", "Example"}, "us_x": {"United States", "East"}} {
		r, ok := got.Get(id)
		if !ok || r.Country != want[0] || r.City != want[1] {
			t.Errorf("%s: %+v", id, r)
		}
	}
	// The shortest unprefixed name wins, whatever the order.
	got, _ = ParsePIACatalog(serverlist(t,
		testRegionJSON(map[string]any{"id": "ex_long", "name": "Exampleland Republic"}),
		testRegionJSON(map[string]any{"id": "ex_short", "name": "Exland"})), false)
	if r, _ := got.Get("ex_long"); r.Country != "Exland" {
		t.Errorf("shortest name: %+v", r)
	}
}

func TestInvalidRegionsAreDropped(t *testing.T) {
	wg := func(servers any) map[string]any { return map[string]any{"servers": map[string]any{"wg": servers}} }
	many := make([]any, 17)
	for i := range many {
		many[i] = map[string]any{"ip": "198.51.100.20", "cn": "x"}
	}
	for name, changes := range map[string]map[string]any{
		"offline": {"offline": true}, "offline null": {"offline": nil}, "option-like id": {"id": "--evil"}, "upper id": {"id": "A"},
		"long id": {"id": strings.Repeat("x", 49)}, "country": {"country": "example"}, "empty name": {"name": ""},
		"name with newline": {"name": "x\n"}, "port_forward string": {"port_forward": "yes"}, "geo null": {"geo": nil},
		"no servers": wg([]any{}), "bad ip": wg([]any{map[string]any{"ip": "198.51.100.999", "cn": "example401"}}),
		"bad cn": wg([]any{map[string]any{"ip": "198.51.100.20", "cn": "bad name"}}), "too many": wg(many),
		"servers is a list": {"servers": []any{}}, "long name": {"name": strings.Repeat("x", 65)},
		"prefix only": {"name": "EX "},
	} {
		got, err := ParsePIACatalog(serverlist(t, testRegionJSON(changes)), false)
		if err != nil || got.Len() != 0 {
			t.Errorf("%s: %v %v", name, names(got), err)
		}
	}
	// 16 servers is the limit, inclusive.
	got, _ := ParsePIACatalog(serverlist(t, testRegionJSON(wg(many[:16]))), false)
	if r, _ := got.Get(testRegion); r == nil || len(r.Servers) != 16 {
		t.Error("16 servers must be kept")
	}
}

func TestDuplicateRegionRejected(t *testing.T) {
	if _, err := ParsePIACatalog(serverlist(t, testRegionJSON(nil), testRegionJSON(nil)), false); err == nil {
		t.Error("duplicate accepted")
	}
}

func TestPortForwardOnlyCatalogue(t *testing.T) {
	raw := serverlist(t, testRegionJSON(nil), testRegionJSON(map[string]any{"id": "ex_nopf", "port_forward": false}))
	all, _ := ParsePIACatalog(raw, false)
	only, _ := ParsePIACatalog(raw, true)
	if !equalStrings(names(all), []string{testRegion, "ex_nopf"}) || !equalStrings(names(only), []string{testRegion}) {
		t.Errorf("%v %v", names(all), names(only))
	}
}

func TestPIACatalogShape(t *testing.T) {
	for name, body := range map[string]string{"not json": "nope", "empty": "", "no regions": `{}`, "regions not a list": `{"regions":{}}`,
		"signature first": "SIGNATURE\n{}", "duplicate key": `{"regions":[],"regions":[]}`} {
		if _, err := ParsePIACatalog([]byte(body), false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Only the first line is parsed, so a signature of any bytes may follow it.
	if got, err := ParsePIACatalog([]byte("{\"regions\":[]}\n\xff\xfe"), false); err != nil || got.Len() != 0 {
		t.Errorf("%v %v", got, err)
	}
}

func TestSnapshotOfAnotherProviderHasNoAuthority(t *testing.T) {
	entries, _ := ParsePIACatalog(serverlist(t), false)
	snapshot := func(extra map[string]any) any {
		m := map[string]any{"fetched_at": "2026-10-11T12:00:00Z", "provider": "pia", "relays": entries}
		for k, v := range extra {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return decoded(t, m)
	}
	if got := SnapshotRelays(snapshot(nil), "pia"); !equalStrings(names(got), []string{testRegion}) {
		t.Errorf("%v", names(got))
	}
	if SnapshotRelays(snapshot(nil), "mullvad").Len() != 0 {
		t.Error("a PIA snapshot read as Mullvad")
	}
	if SnapshotRelays(snapshot(map[string]any{"provider": "mullvad"}), "pia").Len() != 0 {
		t.Error("a Mullvad snapshot read as PIA")
	}
	// Pre-provider snapshots are Mullvad catalogues.
	if SnapshotRelays(snapshot(map[string]any{"provider": nil}), "pia").Len() != 0 {
		t.Error("a provider-less snapshot read as PIA")
	}
}

func TestValidatePIAEntryNeedsEveryField(t *testing.T) {
	good := map[string]any{"hostname": testRegion, "city": "C", "country": "EX", "location_code": "ex-x", "ipv4_addr_in": "198.51.100.21",
		"port_forward": true, "geo": false, "servers": []any{map[string]any{"ip": "198.51.100.20", "cn": "example401"}}}
	if ValidatePIAEntry(decoded(t, good)) == nil {
		t.Fatal("good entry rejected")
	}
	for field := range good {
		bad := map[string]any{}
		for k, v := range good {
			if k != field {
				bad[k] = v
			}
		}
		if ValidatePIAEntry(decoded(t, bad)) != nil {
			t.Errorf("accepted without %s", field)
		}
	}
	if ValidatePIAEntry(nil) != nil || ValidatePIAEntry([]any{}) != nil {
		t.Error("non-objects accepted")
	}
}

func FuzzParsePIACatalog(f *testing.F) {
	raw := serverlist(f)
	f.Add(raw)
	f.Add([]byte(`{"regions":[{"id":"a","name":"US East","country":"US","offline":false,"port_forward":true,"geo":false,"servers":{"wg":[{"ip":"198.51.100.1","cn":"x"}]}}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, pf := range []bool{false, true} {
			entries, err := ParsePIACatalog(data, pf)
			if err != nil {
				return
			}
			entries.Each(func(name string, r *Relay) bool {
				stored, err := validate.MarshalJSON(r)
				if err != nil {
					t.Fatal(err)
				}
				back := ValidatePIAEntry(decodeJSON(t, string(stored)))
				if back == nil || !sameJSON(t, back, r) || r.Hostname != name || (pf && !r.PortForward) {
					t.Fatalf("entry %q: %s", name, stored)
				}
				return true
			})
		}
	})
}
