// Tests for molebridge/nordvpn.py, ported from tools/test_nordvpn.py: the
// catalogue, hostname, server_for_endpoint and parse_insights sections. The
// rest of that file (tools/nordvpn-key.py) belongs to the tools port.
package providers

import (
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/validate"
)

const (
	nordUS    = "us9001.nordvpn.com"
	nordDE    = "de9002.nordvpn.com"
	nordUK    = "uk9003.nordvpn.com"
	nordUSKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	nordDEKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="
)

func nordData(t testing.TB) map[string]any {
	return obj(decodeJSON(t, string(readFixture(t, "nordvpn", "nordvpn-servers.json"))))
}

func nordLoad(t testing.TB, name string) any {
	return decodeJSON(t, string(readFixture(t, "nordvpn", name)))
}

func addGroup(data map[string]any, identifier string, id int64) int64 {
	data["groups"] = append(list(data["groups"]), map[string]any{"id": id, "identifier": identifier,
		"type": map[string]any{"id": int64(3), "identifier": "legacy_group_category"}})
	return id
}

type nordChange func(server, doc map[string]any)

// mutated is the catalogue with the first (US) server changed.
func mutated(t testing.TB, data map[string]any, change nordChange) map[string]any {
	data = obj(clone(t, data))
	change(obj(list(data["servers"])[0]), data)
	return data
}

func wireguardRow(server map[string]any) map[string]any {
	for _, raw := range list(server["technologies"]) {
		if row := obj(raw); row["id"] == int64(35) {
			return row
		}
	}
	panic("no wireguard row")
}

func onlyDE(t *testing.T, data map[string]any, change nordChange) {
	t.Helper()
	got, err := ParseNordCatalog(mutated(t, data, change))
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(names(got), []string{nordDE}) {
		t.Errorf("servers = %v", names(got))
	}
}

func TestNordFixtureKeepsStandardServersAndDropsDedicatedIP(t *testing.T) {
	got, err := ParseNordCatalog(nordData(t))
	if err != nil {
		t.Fatal(err)
	}
	if !equalStrings(names(got), []string{nordUS, nordDE}) {
		t.Fatalf("servers = %v", names(got))
	}
	us, _ := got.Get(nordUS)
	load := int64(12)
	want := &Relay{Shape: ShapeNordVPN, Hostname: nordUS, PublicKey: nordUSKey, IPv4AddrIn: "198.51.100.11", City: "Dallas",
		Country: "United States", CountryCode: "US", LocationCode: "us-dallas", Load: &load, Virtual: false}
	if !sameJSON(t, us, want) {
		t.Errorf("got %+v", us)
	}
	raw, _ := jsonMarshal(us)
	if string(raw) != `{"hostname": "us9001.nordvpn.com", "public_key": "`+nordUSKey+`", "ipv4_addr_in": "198.51.100.11", `+
		`"city": "Dallas", "country": "United States", "country_code": "US", "location_code": "us-dallas", "load": 12, "virtual": false}` {
		t.Errorf("stored as %s", raw)
	}
	de, _ := got.Get(nordDE)
	if de.CountryCode != "DE" || de.LocationCode != "de-berlin" || de.PublicKey != nordDEKey {
		t.Errorf("%+v", de)
	}
	got.Each(func(_ string, r *Relay) bool {
		if !validate.ValidKey(r.PublicKey) {
			t.Error("bad key kept")
		}
		return true
	})
	if NordDetails(us) != "load 12%" {
		t.Errorf("details = %q", NordDetails(us))
	}
}

func TestNordSharedLocationKeyIsKeptForEveryServer(t *testing.T) {
	data := obj(clone(t, nordData(t)))
	servers := list(data["servers"])
	twin := obj(clone(t, servers[0]))
	twin["hostname"], twin["station"], twin["id"] = "us9004.nordvpn.com", "198.51.100.14", int64(990004)
	obj(obj(list(twin["ips"])[0])["ip"])["ip"] = "198.51.100.14"
	data["servers"] = append(servers, twin)
	got, err := ParseNordCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := got.Get("us9004.nordvpn.com")
	b, _ := got.Get(nordUS)
	if a.PublicKey != b.PublicKey {
		t.Error("shared key lost")
	}
}

func TestNordIPv6EntriesAreIgnoredEntirely(t *testing.T) {
	got, err := ParseNordCatalog(mutated(t, nordData(t), func(server, _ map[string]any) {
		server["ips"] = append(list(server["ips"]),
			map[string]any{"type": "entry", "ip": map[string]any{"ip": "2001:db8::1", "version": int64(6)}},
			map[string]any{"type": "entry", "ip": map[string]any{"ip": "not even an address", "version": int64(6)}})
	}))
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := got.Get(nordUS); r.IPv4AddrIn != "198.51.100.11" {
		t.Error(r)
	}
}

func TestNordNonEntryRowsAreIgnored(t *testing.T) {
	got, err := ParseNordCatalog(mutated(t, nordData(t), func(server, _ map[string]any) {
		server["ips"] = append(list(server["ips"]),
			map[string]any{"type": "exit", "ip": map[string]any{"ip": "198.51.100.99", "version": int64(4)}}, "garbage")
	}))
	if err != nil || !got.Has(nordUS) {
		t.Errorf("%v %v", names(got), err)
	}
}

func TestNordDoubleVPNStyleHostnamesMatch(t *testing.T) {
	got, err := ParseNordCatalog(mutated(t, nordData(t), func(server, _ map[string]any) { server["hostname"] = "uk-nl10.nordvpn.com" }))
	if err != nil || !got.Has("uk-nl10.nordvpn.com") {
		t.Errorf("%v %v", names(got), err)
	}
}

func TestNordLoadIsKeptOnlyWhenWellFormed(t *testing.T) {
	for name, tc := range map[string]struct {
		load any
		want *int64
	}{
		"0": {int64(0), ptr(0)}, "100": {int64(100), ptr(100)}, "101": {int64(101), nil}, "-1": {int64(-1), nil},
		"string": {"5", nil}, "bool": {true, nil}, "float": {5.0, nil}, "null": {nil, nil},
	} {
		got, err := ParseNordCatalog(mutated(t, nordData(t), func(server, _ map[string]any) { server["load"] = tc.load }))
		if err != nil {
			t.Fatal(err)
		}
		us, _ := got.Get(nordUS)
		if (us.Load == nil) != (tc.want == nil) || (us.Load != nil && *us.Load != *tc.want) {
			t.Errorf("%s: load = %v", name, us.Load)
		}
		stored, _ := jsonMarshal(us)
		if strings.Contains(string(stored), `"load"`) != (tc.want != nil) {
			t.Errorf("%s: stored %s", name, stored)
		}
	}
	got, _ := ParseNordCatalog(mutated(t, nordData(t), func(server, _ map[string]any) { delete(server, "load") }))
	if us, _ := got.Get(nordUS); us.Load != nil {
		t.Error("missing load must be omitted")
	}
}

func ptr(n int64) *int64 { return &n }

func TestNordVirtualLocationSpecification(t *testing.T) {
	virtual := func(value string) nordChange {
		return func(server, _ map[string]any) {
			server["specifications"] = append(list(server["specifications"]),
				map[string]any{"identifier": "virtual_location", "values": []any{map[string]any{"value": value}}})
		}
	}
	for value, want := range map[string]bool{"true": true, "false": false} {
		got, _ := ParseNordCatalog(mutated(t, nordData(t), virtual(value)))
		if us, _ := got.Get(nordUS); us.Virtual != want {
			t.Errorf("%s: %v", value, us.Virtual)
		}
	}
	got, _ := ParseNordCatalog(mutated(t, nordData(t), func(server, _ map[string]any) {
		server["specifications"] = []any{"x", map[string]any{"identifier": "virtual_location", "values": "true"}}
	}))
	if us, _ := got.Get(nordUS); us.Virtual {
		t.Error("malformed specification counted")
	}
	// The first virtual_location row with a list of values decides.
	got, _ = ParseNordCatalog(mutated(t, nordData(t), func(server, _ map[string]any) {
		server["specifications"] = []any{
			map[string]any{"identifier": "virtual_location", "values": []any{map[string]any{"value": "false"}}},
			map[string]any{"identifier": "virtual_location", "values": []any{map[string]any{"value": "true"}}}}
	}))
	if us, _ := got.Get(nordUS); us.Virtual {
		t.Error("the first row decides")
	}
	us, _ := got.Get(nordUS)
	if NordDetails(&Relay{Virtual: true, Load: us.Load}) != "virtual location · load 12%" {
		t.Error("details")
	}
}

func TestNordLocationCodeIsASlug(t *testing.T) {
	got, err := ParseNordCatalog(mutated(t, nordData(t), func(_, doc map[string]any) {
		obj(obj(obj(list(doc["locations"])[0])["country"])["city"])["name"] = "St. John's / Newfoundland"
	}))
	if err != nil {
		t.Fatal(err)
	}
	if us, _ := got.Get(nordUS); us.LocationCode != "us-st-john-s-newfoundland" {
		t.Errorf("location code %q", us.LocationCode)
	}
	// Python lowers U+0130 to "i" and a combining dot, which the slug turns into a dash.
	got, _ = ParseNordCatalog(mutated(t, nordData(t), func(_, doc map[string]any) {
		obj(obj(obj(list(doc["locations"])[0])["country"])["city"])["name"] = "İstanbul"
	}))
	if us, _ := got.Get(nordUS); us.LocationCode != "us-i-stanbul" {
		t.Errorf("location code %q", us.LocationCode)
	}
}

func dropped() map[string]nordChange {
	setStatus := func(status any) nordChange { return func(server, _ map[string]any) { server["status"] = status } }
	setLocation := func(f func(country, city map[string]any)) nordChange {
		return func(_, doc map[string]any) {
			country := obj(obj(list(doc["locations"])[0])["country"])
			f(country, obj(country["city"]))
		}
	}
	hostname := func(v any) nordChange { return func(server, _ map[string]any) { server["hostname"] = v } }
	excluded := func(identifier string) nordChange {
		return func(server, doc map[string]any) {
			server["group_ids"] = append(list(server["group_ids"]), addGroup(doc, identifier, 500))
		}
	}
	metadataValue := func(v any) nordChange {
		return func(server, _ map[string]any) { obj(list(wireguardRow(server)["metadata"])[0])["value"] = v }
	}
	return map[string]nordChange{
		"offline": setStatus("offline"), "status missing": setStatus(nil),
		"no vpn service": func(server, _ map[string]any) { server["service_ids"] = []any{int64(5)} },
		"no wireguard row": func(server, _ map[string]any) {
			var rest []any
			for _, raw := range list(server["technologies"]) {
				if obj(raw)["id"] != int64(35) {
					rest = append(rest, raw)
				}
			}
			server["technologies"] = rest
		},
		"wireguard offline":        func(server, _ map[string]any) { wireguardRow(server)["status"] = "offline" },
		"wireguard without status": func(server, _ map[string]any) { delete(wireguardRow(server), "status") },
		"invalid key":              metadataValue("not a key"),
		"short key":                metadataValue("AAAA"),
		"non-canonical key":        metadataValue("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB="),
		"key not text":             metadataValue(int64(5)),
		"two keys": func(server, _ map[string]any) {
			row := wireguardRow(server)
			row["metadata"] = append(list(row["metadata"]), map[string]any{"name": "public_key", "value": nordDEKey})
		},
		"no key": func(server, _ map[string]any) {
			wireguardRow(server)["metadata"] = []any{map[string]any{"name": "other", "value": nordUSKey}}
		},
		"no metadata": func(server, _ map[string]any) { delete(wireguardRow(server), "metadata") },
		"metadata not a list": func(server, _ map[string]any) {
			wireguardRow(server)["metadata"] = map[string]any{"name": "public_key", "value": nordUSKey}
		},
		"two wireguard rows": func(server, _ map[string]any) {
			server["technologies"] = append(list(server["technologies"]), clonePlain(wireguardRow(server)))
		},
		"no location":          func(server, _ map[string]any) { server["location_ids"] = []any{} },
		"two locations":        func(server, _ map[string]any) { server["location_ids"] = []any{int64(79), int64(101)} },
		"unknown location":     func(server, _ map[string]any) { server["location_ids"] = []any{int64(12345)} },
		"location is a bool":   func(server, _ map[string]any) { server["location_ids"] = []any{true} },
		"location is text":     func(server, _ map[string]any) { server["location_ids"] = []any{"79"} },
		"location ids missing": func(server, _ map[string]any) { delete(server, "location_ids") },
		"blank country":        setLocation(func(c, _ map[string]any) { c["name"] = "" }),
		"no country name":      setLocation(func(c, _ map[string]any) { delete(c, "name") }),
		"lowercase code":       setLocation(func(c, _ map[string]any) { c["code"] = "us" }),
		"three letter code":    setLocation(func(c, _ map[string]any) { c["code"] = "USA" }),
		"blank city":           setLocation(func(_, c map[string]any) { c["name"] = "" }),
		"no city":              setLocation(func(c, _ map[string]any) { delete(c, "city") }),
		"city not text":        setLocation(func(_, c map[string]any) { c["name"] = int64(7) }),
		"long city":            setLocation(func(_, c map[string]any) { c["name"] = strings.Repeat("x", 257) }),
		"control character":    setLocation(func(_, c map[string]any) { c["name"] = "Dal\x00las" }),
		"newline":              setLocation(func(_, c map[string]any) { c["name"] = "Dal\nlas" }),
		"line separator":       setLocation(func(_, c map[string]any) { c["name"] = "Dal las" }),
		"lone surrogate":       setLocation(func(_, c map[string]any) { c["name"] = "Dal\xed\xa0\x80las" }),
		"city without letters": setLocation(func(_, c map[string]any) { c["name"] = "..." }),
		"duplicate location id": func(_, doc map[string]any) {
			second := clonePlain(obj(list(doc["locations"])[1]))
			second["id"] = int64(79)
			doc["locations"] = append(list(doc["locations"]), second)
		},
		"not standard": func(server, _ map[string]any) { server["group_ids"] = []any{int64(15), int64(21)} },
		"no groups":    func(server, _ map[string]any) { delete(server, "group_ids") },
		"dedicated ip": excluded("legacy_dedicated_ip"), "double vpn": excluded("legacy_double_vpn"),
		"onion": excluded("legacy_onion_over_vpn"), "obfuscated": excluded("legacy_obfuscated_servers"),
		"no entry ip": func(server, _ map[string]any) { server["ips"] = []any{} },
		"ipv6 only": func(server, _ map[string]any) {
			server["ips"] = []any{map[string]any{"type": "entry", "ip": map[string]any{"ip": "2001:db8::1", "version": int64(6)}}}
		},
		"two v4 entries": func(server, _ map[string]any) {
			server["ips"] = append(list(server["ips"]),
				map[string]any{"type": "entry", "ip": map[string]any{"ip": "198.51.100.12", "version": int64(4)}})
		},
		"invalid entry ip":       func(server, _ map[string]any) { obj(obj(list(server["ips"])[0])["ip"])["ip"] = "198.51.100.011" },
		"private entry ip":       nonPublicEntry("10.1.2.3"),
		"loopback entry ip":      nonPublicEntry("127.0.0.1"),
		"link-local entry ip":    nonPublicEntry("169.254.169.254"),
		"shared entry ip":        nonPublicEntry("100.64.0.1"),
		"version as text":        func(server, _ map[string]any) { obj(obj(list(server["ips"])[0])["ip"])["version"] = "4" },
		"entry ip not an object": func(server, _ map[string]any) { obj(list(server["ips"])[0])["ip"] = "x" },
		"ips not a list":         func(server, _ map[string]any) { server["ips"] = map[string]any{} },
		"station differs":        func(server, _ map[string]any) { server["station"] = "198.51.100.12" },
		"no station":             func(server, _ map[string]any) { delete(server, "station") },
		"station not text":       func(server, _ map[string]any) { server["station"] = int64(3) },
		"uppercase hostname":     hostname("US9001.nordvpn.com"), "foreign domain": hostname("us9001.example.net"),
		"subdomain": hostname("a.us9001.nordvpn.com"), "no digits": hostname("us.nordvpn.com"),
		"six digits": hostname("us123456.nordvpn.com"), "onion hostname": hostname("ch-onion1.nordvpn.com"),
		"trailing newline": hostname("us9001.nordvpn.com\n"), "hostname not text": hostname(int64(9001)),
	}
}

// nonPublicEntry moves the server's entry address, and its station with it,
// to a non-public address.
func nonPublicEntry(address string) nordChange {
	return func(server, _ map[string]any) {
		obj(obj(list(server["ips"])[0])["ip"])["ip"] = address
		server["station"] = address
	}
}

func clonePlain(m map[string]any) map[string]any {
	out, _ := validate.DecodeJSON(mustMarshal(m))
	return out.(map[string]any)
}

func mustMarshal(v any) []byte {
	raw, err := validate.MarshalJSON(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestNordServerIsDropped(t *testing.T) {
	for name, change := range dropped() {
		t.Run(name, func(t *testing.T) { onlyDE(t, nordData(t), change) })
	}
}

func TestNordWireguardTechnologyIsFoundByIdentifierNotByID(t *testing.T) {
	// Renumber the top-level row and the server's rows together.
	got, err := ParseNordCatalog(mutated(t, nordData(t), func(server, doc map[string]any) {
		obj(list(doc["technologies"])[2])["id"] = int64(77)
		wireguardRow(server)["id"] = int64(77)
		for _, other := range list(doc["servers"])[1:] {
			wireguardRow(obj(other))["id"] = int64(77)
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	// wireguardRow looks for id 35, so rebuild the lookup the test cannot do after renumbering.
	if !equalStrings(names(got), []string{nordUS, nordDE}) {
		t.Errorf("servers = %v", names(got))
	}
}

func TestNordWireguardRowWithTheWrongIdentifierIsNotWireguard(t *testing.T) {
	data := nordData(t)
	obj(list(data["technologies"])[2])["identifier"] = "openvpn_xor"
	if _, err := ParseNordCatalog(data); err == nil {
		t.Error("accepted")
	}
}

func TestNordVPNServiceIsFoundByIdentifierNotByID(t *testing.T) {
	data := nordData(t)
	obj(list(data["services"])[0])["identifier"] = "other"
	if _, err := ParseNordCatalog(data); err == nil {
		t.Error("accepted")
	}
}

func TestNordUnknownIDsInGroupIDsAreHarmless(t *testing.T) {
	got, err := ParseNordCatalog(mutated(t, nordData(t), func(server, _ map[string]any) {
		server["group_ids"] = append(list(server["group_ids"]), int64(99999))
	}))
	if err != nil || !got.Has(nordUS) {
		t.Errorf("%v %v", names(got), err)
	}
}

func TestNordDedicatedIPFixtureServerIsDropped(t *testing.T) {
	got, _ := ParseNordCatalog(nordData(t))
	if got.Has(nordUK) {
		t.Error("dedicated IP server kept")
	}
}

func TestNordNonObjectServersAreSkipped(t *testing.T) {
	data := nordData(t)
	data["servers"] = append(list(data["servers"]), nil, "x", int64(5), []any{}, map[string]any{})
	got, err := ParseNordCatalog(data)
	if err != nil || !equalStrings(names(got), []string{nordUS, nordDE}) {
		t.Errorf("%v %v", names(got), err)
	}
}

func TestNordDuplicateHostnameRaises(t *testing.T) {
	data := nordData(t)
	twin := clonePlain(obj(list(data["servers"])[0]))
	twin["id"] = int64(990009)
	data["servers"] = append(list(data["servers"]), twin)
	if _, err := ParseNordCatalog(data); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("got %v", err)
	}
}

func TestNordDuplicateHostnameOfADroppedServerIsNotAnError(t *testing.T) {
	data := nordData(t)
	twin := clonePlain(obj(list(data["servers"])[0]))
	twin["status"] = "offline"
	data["servers"] = append(list(data["servers"]), twin)
	got, err := ParseNordCatalog(data)
	if err != nil || !equalStrings(names(got), []string{nordUS, nordDE}) {
		t.Errorf("%v %v", names(got), err)
	}
}

func TestNordEmptyResultRaises(t *testing.T) {
	data := nordData(t)
	data["servers"] = []any{}
	if _, err := ParseNordCatalog(data); err == nil {
		t.Error("empty catalogue accepted")
	}
	data = nordData(t)
	for _, s := range list(data["servers"]) {
		obj(s)["status"] = "offline"
	}
	if _, err := ParseNordCatalog(data); err == nil {
		t.Error("all-offline catalogue accepted")
	}
}

func TestNordNonObjectDocumentRaises(t *testing.T) {
	for _, v := range []any{nil, []any{}, "servers", int64(5), true} {
		if _, err := ParseNordCatalog(v); err == nil {
			t.Errorf("%#v accepted", v)
		}
	}
}

func TestNordMissingOrMistypedTableRaises(t *testing.T) {
	for _, table := range []string{"servers", "groups", "services", "locations", "technologies"} {
		data := nordData(t)
		delete(data, table)
		if _, err := ParseNordCatalog(data); err == nil {
			t.Errorf("missing %s accepted", table)
		}
		for _, value := range []any{map[string]any{}, nil, "x", int64(3)} {
			data = nordData(t)
			data[table] = value
			if _, err := ParseNordCatalog(data); err == nil {
				t.Errorf("%s = %#v accepted", table, value)
			}
		}
	}
}

func TestNordOversizedTablesRaise(t *testing.T) {
	big := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = int64(i)
		}
		return out
	}
	data := nordData(t)
	data["servers"] = big(nordMaxServers + 1)
	if _, err := ParseNordCatalog(data); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("servers: %v", err)
	}
	for _, table := range []string{"groups", "services", "locations", "technologies"} {
		data = nordData(t)
		data[table] = big(nordMaxTable + 1)
		if _, err := ParseNordCatalog(data); err == nil || !strings.Contains(err.Error(), "too large") {
			t.Errorf("%s: %v", table, err)
		}
	}
	// Exactly at the limit is allowed.
	data = nordData(t)
	data["groups"] = append(list(data["groups"]), big(nordMaxTable-len(list(data["groups"])))...)
	if _, err := ParseNordCatalog(data); err != nil {
		t.Errorf("at the limit: %v", err)
	}
}

func TestNordMalformedTableRowsAreSkippedNotFatal(t *testing.T) {
	data := nordData(t)
	data["groups"] = append(list(data["groups"]), nil, "x", map[string]any{"id": "a", "identifier": "legacy_standard"},
		map[string]any{"id": true, "identifier": "x"})
	data["locations"] = append(list(data["locations"]), nil, map[string]any{"id": int64(5)}, map[string]any{"id": int64(6), "country": "x"})
	data["services"] = append(list(data["services"]), nil, map[string]any{"id": nil})
	data["technologies"] = append(list(data["technologies"]), nil, map[string]any{"id": int64(9), "identifier": int64(4)})
	got, err := ParseNordCatalog(data)
	if err != nil || !equalStrings(names(got), []string{nordUS, nordDE}) {
		t.Errorf("%v %v", names(got), err)
	}
}

func TestNordErrorsNeverEchoInput(t *testing.T) {
	data := nordData(t)
	secret := "SECRET-HOST-VALUE"
	servers := list(data["servers"])
	obj(servers[0])["hostname"], obj(servers[1])["status"], obj(servers[2])["hostname"] = secret, secret, secret
	// Make the document fail on a duplicate to get an error at all.
	data["servers"] = append(servers, clonePlain(obj(servers[1])))
	_, err := ParseNordCatalog(data)
	if err != nil && strings.Contains(err.Error(), "SECRET") {
		t.Errorf("error echoes input: %v", err)
	}
	for _, bad := range []any{map[string]any{"servers": secret}, secret} {
		if _, err := ParseNordCatalog(bad); err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Errorf("error for %v: %v", bad, err)
		}
	}
}

func TestNordConstants(t *testing.T) {
	if !strings.HasPrefix(NordServersURL, "https://api.nordvpn.com/v2/servers?") || !strings.Contains(NordServersURL, "limit=0") ||
		!strings.Contains(NordServersURL, "filters%5Bservers_technologies%5D%5Bidentifier%5D=wireguard_udp") ||
		strings.ContainsAny(NordServersURL, "[]") {
		t.Error(NordServersURL)
	}
	if NordMaxCatalogBytes != 32*1024*1024 || NordAddress != "10.5.0.2/32" || NordPort != 51820 ||
		NordInsightsURL != "https://api.nordvpn.com/v1/helpers/ips/insights" {
		t.Error("constants")
	}
}

func TestNordHostnamePattern(t *testing.T) {
	for _, name := range []string{"us9001.nordvpn.com", "uk-nl10.nordvpn.com", "de1.nordvpn.com", "ca12345.nordvpn.com"} {
		if !nordHostnameRE.MatchString(name) {
			t.Errorf("%s rejected", name)
		}
	}
	for _, name := range []string{"us.nordvpn.com", "usa1.nordvpn.com", "us1.nordvpn.com.evil.test", "us-1.nordvpn.com",
		"US1.nordvpn.com", "us1.nordvpn.net", "", "us1.nordvpn.com\n"} {
		if nordHostnameRE.MatchString(name) {
			t.Errorf("%q accepted", name)
		}
	}
}

func TestNordEndpointIdentifiesTheServerEvenWithSharedKeys(t *testing.T) {
	data := nordData(t)
	twin := clonePlain(obj(list(data["servers"])[0]))
	twin["hostname"], twin["station"] = "us9004.nordvpn.com", "198.51.100.14"
	obj(obj(list(twin["ips"])[0])["ip"])["ip"] = "198.51.100.14"
	data["servers"] = append(list(data["servers"]), twin)
	relays, err := ParseNordCatalog(data)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := relays.Get(nordUS)
	b, _ := relays.Get("us9004.nordvpn.com")
	if a.PublicKey != b.PublicKey {
		t.Error("keys differ")
	}
	for endpoint, want := range map[string]string{"198.51.100.11:51820": nordUS, "198.51.100.14:51820": "us9004.nordvpn.com",
		"198.51.100.22:51820": nordDE} {
		if got, ok := ServerForEndpoint(relays, endpoint); !ok || got != want {
			t.Errorf("%s: %q %v", endpoint, got, ok)
		}
	}
}

func TestNordUnknownEndpointOrWrongPortGivesNone(t *testing.T) {
	relays, _ := ParseNordCatalog(nordData(t))
	for _, endpoint := range []string{"198.51.100.99:51820", "198.51.100.11:51821", "198.51.100.11:1337"} {
		if got, ok := ServerForEndpoint(relays, endpoint); ok {
			t.Errorf("%s -> %s", endpoint, got)
		}
	}
}

func TestNordMalformedEndpointGivesNone(t *testing.T) {
	relays, _ := ParseNordCatalog(nordData(t))
	for _, endpoint := range []string{"(none)", "", "198.51.100.11", "198.51.100.11:", ":51820", "198.51.100.11:051820",
		"198.51.100.11:51820 ", " 198.51.100.11:51820", "198.51.100.11:51820\n", "[2001:db8::1]:51820", "2001:db8::1:51820",
		"198.51.100.011:51820", "us9001.nordvpn.com:51820"} {
		if got, ok := ServerForEndpoint(relays, endpoint); ok {
			t.Errorf("%q -> %s", endpoint, got)
		}
	}
}

func TestNordAmbiguousEndpointGivesNone(t *testing.T) {
	relays, _ := ParseNordCatalog(nordData(t))
	us, _ := relays.Get(nordUS)
	de, _ := relays.Get(nordDE)
	de.IPv4AddrIn = us.IPv4AddrIn
	if got, ok := ServerForEndpoint(relays, "198.51.100.11:51820"); ok {
		t.Errorf("ambiguous endpoint resolved to %s", got)
	}
	if _, ok := ServerForEndpoint(nil, "198.51.100.11:51820"); ok {
		t.Error("nil catalogue")
	}
	if _, ok := ServerForEndpoint(NewEntries(), "198.51.100.11:51820"); ok {
		t.Error("empty catalogue")
	}
}

func TestNordInsights(t *testing.T) {
	protected, err := ParseInsights(nordLoad(t, "nordvpn-insights-protected.json"))
	if err != nil {
		t.Fatal(err)
	}
	if protected.EgressIP != "198.51.100.11" || *protected.EgressCity != "Dallas" || *protected.EgressCountry != "United States" || !protected.ExitConfirmed {
		t.Errorf("%+v", protected)
	}
	raw, _ := jsonMarshal(protected)
	if string(raw) != `{"egress_ip": "198.51.100.11", "egress_city": "Dallas", "egress_country": "United States", "exit_confirmed": true}` {
		t.Errorf("stored as %s", raw)
	}
	unprotected, err := ParseInsights(nordLoad(t, "nordvpn-insights-unprotected.json"))
	if err != nil || unprotected.EgressIP != "203.0.113.84" || *unprotected.EgressCity != "Exampleville" || unprotected.ExitConfirmed {
		t.Errorf("%+v %v", unprotected, err)
	}
	doc := obj(nordLoad(t, "nordvpn-insights-unknown.json"))
	if doc["isp_asn"] != "Unknown" || doc["longitude"] != false {
		t.Fatal("fixture changed")
	}
	unknown, err := ParseInsights(doc)
	if err != nil || unknown.EgressIP != "198.51.100.7" || unknown.EgressCity != nil || unknown.EgressCountry != nil || unknown.ExitConfirmed {
		t.Errorf("%+v %v", unknown, err)
	}
	raw, _ = jsonMarshal(unknown)
	if string(raw) != `{"egress_ip": "198.51.100.7", "egress_city": null, "egress_country": null, "exit_confirmed": false}` {
		t.Errorf("stored as %s", raw)
	}
}

func insightsWith(t testing.TB, changes map[string]any) any {
	doc := obj(clone(t, nordLoad(t, "nordvpn-insights-protected.json")))
	for k, v := range changes {
		if v == "\x00absent" {
			delete(doc, k)
		} else {
			doc[k] = v
		}
	}
	return doc
}

func TestNordInsightsIgnoresUnusedFieldsWhateverTheirType(t *testing.T) {
	for _, field := range []string{"isp_asn", "longitude", "latitude", "isp", "state_code", "zip_code"} {
		for _, value := range []any{nil, []any{}, map[string]any{}, strings.Repeat("x", 1000), "\x00", 1.5, true} {
			got, err := ParseInsights(insightsWith(t, map[string]any{field: value}))
			if err != nil || !got.ExitConfirmed {
				t.Errorf("%s=%#v: %v", field, value, err)
			}
		}
	}
}

func TestNordInsightsProtectedMustBeABool(t *testing.T) {
	for _, protected := range []any{int64(1), int64(0), "true", "false", nil, []any{}, map[string]any{}, "\x00absent"} {
		if _, err := ParseInsights(insightsWith(t, map[string]any{"protected": protected})); err == nil {
			t.Errorf("protected=%#v accepted", protected)
		}
	}
}

func TestNordInsightsIPMustBeIPv4(t *testing.T) {
	for _, address := range []any{"2001:db8::1", "198.51.100.011", "198.51.100", "example.test", "", nil, int64(5), "198.51.100.7\n",
		" 198.51.100.7", "\x00absent"} {
		if _, err := ParseInsights(insightsWith(t, map[string]any{"ip": address})); err == nil {
			t.Errorf("ip=%#v accepted", address)
		}
	}
}

func TestNordInsightsTextIsChecked(t *testing.T) {
	for _, field := range []string{"city", "country", "country_code"} {
		for _, value := range []any{nil, int64(5), false, []any{}, "", strings.Repeat("x", 257), "a\x00b", "a\nb", "a\x7fb", "\x00absent"} {
			if _, err := ParseInsights(insightsWith(t, map[string]any{field: value})); err == nil {
				t.Errorf("%s=%#v accepted", field, value)
			}
		}
		// The limit is inclusive.
		if _, err := ParseInsights(insightsWith(t, map[string]any{field: strings.Repeat("x", 256)})); err != nil {
			t.Errorf("%s at the limit: %v", field, err)
		}
		// "Unknown" is accepted for each, and means nothing known.
		if _, err := ParseInsights(insightsWith(t, map[string]any{field: "Unknown"})); err != nil {
			t.Errorf("%s Unknown: %v", field, err)
		}
	}
	got, _ := ParseInsights(insightsWith(t, map[string]any{"city": strings.Repeat("x", 256)}))
	if len(*got.EgressCity) != 256 {
		t.Error("city kept whole")
	}
}

func TestNordInsightsNonObjectRaises(t *testing.T) {
	for _, v := range []any{nil, []any{}, "x", int64(5), true} {
		if _, err := ParseInsights(v); err == nil {
			t.Errorf("%#v accepted", v)
		}
	}
	_, err := ParseInsights(insightsWith(t, map[string]any{"city": "SECRET\x00VALUE"}))
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("error echoes input: %v", err)
	}
}

func TestNordValidateEntryRoundTrip(t *testing.T) {
	got, _ := ParseNordCatalog(nordData(t))
	got.Each(func(name string, r *Relay) bool {
		stored := decodeJSON(t, string(mustMarshal(r)))
		back := ValidateNordEntry(stored)
		if back == nil || !sameJSON(t, back, r) {
			t.Errorf("%s does not survive validation", name)
		}
		return true
	})
	us, _ := got.Get(nordUS)
	for field := range obj(decodeJSON(t, string(mustMarshal(us)))) {
		entry := obj(decodeJSON(t, string(mustMarshal(us))))
		delete(entry, field)
		if back := ValidateNordEntry(entry); (back == nil) == (field == "load") {
			t.Errorf("without %s: %v", field, back)
		}
	}
	for _, bad := range []map[string]any{{"virtual": "no"}, {"location_code": "US-dallas"}, {"location_code": "us-"}, {"country_code": "usa"},
		{"city": ""}, {"hostname": "US9001.nordvpn.com"}, {"public_key": "AAAA"}} {
		entry := obj(decodeJSON(t, string(mustMarshal(us))))
		for k, v := range bad {
			entry[k] = v
		}
		if ValidateNordEntry(entry) != nil {
			t.Errorf("%v accepted", bad)
		}
	}
	// A load outside 0..100 is dropped, not fatal.
	entry := obj(decodeJSON(t, string(mustMarshal(us))))
	entry["load"] = int64(101)
	if back := ValidateNordEntry(entry); back == nil || back.Load != nil {
		t.Errorf("load 101: %+v", back)
	}
}

func TestNordGroupRule(t *testing.T) {
	for name, tc := range map[string]struct {
		titles []string
		ok     bool
	}{
		"standard": {[]string{"Standard VPN servers"}, true}, "p2p+standard": {[]string{"P2P", "Standard VPN servers"}, true},
		"dedicated": {[]string{"Dedicated IP"}, false}, "standard+dedicated": {[]string{"Standard VPN servers", "Dedicated IP"}, false},
		"double": {[]string{"Double VPN"}, false}, "onion": {[]string{"Onion Over VPN"}, false},
		"obfuscated": {[]string{"Standard VPN servers", "Obfuscated Servers"}, false}, "p2p": {[]string{"P2P"}, false},
		"none": {nil, false},
	} {
		if SelectableByTitles(tc.titles) != tc.ok {
			t.Errorf("%s", name)
		}
	}
	// The same groups as the native catalogue, by title.
	for _, group := range NordExcludedGroups {
		if !NordExcludedTitles[NordGroupTitles[group]] {
			t.Errorf("%s missing", group)
		}
	}
	if len(NordExcludedTitles) != len(NordExcludedGroups) {
		t.Error("excluded titles")
	}
}

func FuzzParseNordCatalog(f *testing.F) {
	f.Add(readFixture(f, "nordvpn", "nordvpn-servers.json"))
	f.Add([]byte(`{"servers":[],"groups":[],"services":[],"locations":[],"technologies":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := ParseNordCatalogBody(data, false)
		if err != nil {
			return
		}
		if entries.Len() == 0 {
			t.Fatal("an empty catalogue must be an error")
		}
		entries.Each(func(name string, r *Relay) bool {
			back := ValidateNordEntry(decodeJSON(t, string(mustMarshal(r))))
			if back == nil || !sameJSON(t, back, r) || r.Hostname != name {
				t.Fatalf("entry %q does not survive validation", name)
			}
			return true
		})
	})
}

func FuzzParseInsights(f *testing.F) {
	for _, name := range []string{"nordvpn-insights-protected.json", "nordvpn-insights-unprotected.json", "nordvpn-insights-unknown.json"} {
		f.Add(readFixture(f, "nordvpn", name))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		doc, err := validate.DecodeJSON(data)
		if err != nil {
			return
		}
		got, err := ParseInsights(doc)
		if err != nil {
			return
		}
		if !validate.ValidIPv4(got.EgressIP) {
			t.Fatalf("bad ip kept: %q", got.EgressIP)
		}
		for _, s := range []*string{got.EgressCity, got.EgressCountry} {
			if s != nil && !cleanText(*s) {
				t.Fatalf("bad text kept: %q", *s)
			}
		}
	})
}
