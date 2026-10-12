// Tests for molebridge/mullvad.py (via molebridge/relays.py), ported from
// tools/test_runtime.py: test_remote_relay_validation, test_valid_relay_and_
// escaped_location, test_bad_relay_schema, test_duplicate_relays_rejected,
// test_optional_relay_attributes_kept_when_valid,
// test_malformed_optional_relay_attributes_dropped and
// test_failed_refresh_preserves_last_good_catalogue.
package providers

import (
	"os"
	"strings"
	"testing"
)

const (
	mullvadKey  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	mullvadHost = "se-sto-wg-001"
)

func mullvadEntry() map[string]any {
	return map[string]any{"hostname": mullvadHost, "public_key": mullvadKey, "ipv4_addr_in": "198.51.100.10",
		"city": "Example City", "country": "Example", "location_code": "se-sto"}
}

// mullvadPayload is the relay list with one active relay, changed by changes.
func mullvadPayload(t testing.TB, changes map[string]any) any {
	relay := mullvadEntry()
	relay["active"], relay["location"] = true, "se-sto"
	for k, v := range changes {
		if s, ok := v.(string); ok && s == "\x00absent" {
			delete(relay, k)
			continue
		}
		relay[k] = v
	}
	return decoded(t, map[string]any{
		"locations": map[string]any{"se-sto": map[string]any{"city": "Example City", "country": "Example"}},
		"wireguard": map[string]any{"relays": []any{relay}}})
}

func TestRemoteRelayValidation(t *testing.T) {
	for name, changes := range map[string]map[string]any{
		"inactive": {"active": false}, "option-like hostname": {"hostname": "--evil"}, "bad key": {"public_key": "bad"},
		"key with newline": {"public_key": mullvadKey + "\n"}, "bad address": {"ipv4_addr_in": "198.51.100.999"},
		"location is a list": {"location": []any{}}, "location absent": {"location": "\x00absent"},
		"hostname with newline": {"hostname": mullvadHost + "\n"},
	} {
		got, err := ParseMullvadResponse(mullvadPayload(t, changes))
		if err != nil || got.Len() != 0 {
			t.Errorf("%s: %v %v", name, names(got), err)
		}
	}
}

func TestValidRelayAndEscapedLocation(t *testing.T) {
	data := mullvadPayload(t, nil)
	obj(obj(obj(data)["locations"])["se-sto"])["city"] = "<script>not trusted</script>"
	got, err := ParseMullvadResponse(data)
	if err != nil {
		t.Fatal(err)
	}
	relay, _ := got.Get(mullvadHost)
	if relay.City != "<script>not trusted</script>" {
		t.Errorf("city = %q", relay.City)
	}
}

func TestBadRelaySchema(t *testing.T) {
	for name, bad := range map[string]string{
		"null": `null`, "list": `[]`, "empty": `{}`, "wireguard is a list": `{"locations":{},"wireguard":[]}`,
		"no relays": `{"locations":{},"wireguard":{}}`, "relays not a list": `{"locations":{},"wireguard":{"relays":{}}}`,
		"locations not a map": `{"locations":[],"wireguard":{"relays":[]}}`,
	} {
		if _, err := ParseMullvadResponse(decodeJSON(t, bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDuplicateRelaysRejected(t *testing.T) {
	data := mullvadPayload(t, nil)
	relays := list(obj(obj(data)["wireguard"])["relays"])
	obj(obj(data)["wireguard"])["relays"] = append(relays, relays...)
	if _, err := ParseMullvadResponse(data); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("got %v", err)
	}
}

func TestOptionalRelayAttributesKeptWhenValid(t *testing.T) {
	got, err := ParseMullvadResponse(mullvadPayload(t, map[string]any{"owned": true, "stboot": false, "provider": "Example Hosting"}))
	if err != nil {
		t.Fatal(err)
	}
	relay, _ := got.Get(mullvadHost)
	if relay.Owned == nil || !*relay.Owned || relay.Stboot == nil || *relay.Stboot || relay.HostingProvider != "Example Hosting" {
		t.Errorf("%+v", relay)
	}
	if owned, present := relay.Flag("owned"); !owned || !present {
		t.Error("Flag owned")
	}
	if stboot, present := relay.Flag("stboot"); stboot || !present {
		t.Error("Flag stboot")
	}
	if got := MullvadDetails(relay); got != "Example Hosting · Mullvad-owned" {
		t.Errorf("details = %q", got)
	}
	// What the snapshot stores reads back as the same entries.
	stored := decoded(t, map[string]any{"fetched_at": "2026-10-11T12:00:00Z", "relays": got})
	again := SnapshotRelays(stored, "mullvad")
	if r, ok := again.Get(mullvadHost); !ok || !sameJSON(t, r, relay) {
		t.Errorf("snapshot round trip: %+v", r)
	}
}

func TestMalformedOptionalRelayAttributesDropped(t *testing.T) {
	for name, changes := range map[string]map[string]any{
		"owned string": {"owned": "yes"}, "owned int": {"owned": 1}, "stboot null": {"stboot": nil}, "stboot 0": {"stboot": 0},
		"provider newline": {"provider": "Example\nHosting"}, "provider long": {"provider": strings.Repeat("x", 65)},
		"provider empty": {"provider": ""}, "provider list": {"provider": []any{"Example"}},
	} {
		got, err := ParseMullvadResponse(mullvadPayload(t, changes))
		if err != nil {
			t.Fatal(err)
		}
		relay, ok := got.Get(mullvadHost)
		if !ok {
			t.Errorf("%s: the relay itself must stay", name)
			continue
		}
		if relay.Owned != nil || relay.Stboot != nil || relay.HostingProvider != "" {
			t.Errorf("%s: kept %+v", name, relay)
		}
	}
	// The limit is 64 characters, inclusive.
	got, _ := ParseMullvadResponse(mullvadPayload(t, map[string]any{"provider": strings.Repeat("é", 64)}))
	if r, _ := got.Get(mullvadHost); r.HostingProvider == "" {
		t.Error("a 64 character provider must be kept")
	}
}

func TestMullvadEntryWithoutTheRequiredFieldsIsDropped(t *testing.T) {
	for _, field := range []string{"hostname", "public_key", "ipv4_addr_in", "city", "country", "location_code"} {
		entry := mullvadEntry()
		delete(entry, field)
		if ValidateMullvadEntry(decoded(t, entry)) != nil {
			t.Errorf("an entry without %s was accepted", field)
		}
	}
	if ValidateMullvadEntry(decoded(t, mullvadEntry())) == nil || ValidateMullvadEntry(nil) != nil || ValidateMullvadEntry("x") != nil {
		t.Error("entry validation")
	}
}

func TestMullvadSnapshotOrderAndBytes(t *testing.T) {
	data := mullvadPayload(t, map[string]any{"owned": true, "stboot": false, "provider": "Example Hosting"})
	entries, _ := ParseMullvadResponse(data)
	relay, _ := entries.Get(mullvadHost)
	raw, err := jsonMarshal(relay)
	if err != nil {
		t.Fatal(err)
	}
	// Python wrote the members in this order.
	want := `{"hostname": "se-sto-wg-001", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", ` +
		`"ipv4_addr_in": "198.51.100.10", "city": "Example City", "country": "Example", "location_code": "se-sto", ` +
		`"owned": true, "stboot": false, "provider": "Example Hosting"}`
	if string(raw) != want {
		t.Errorf("\n got %s\nwant %s", raw, want)
	}
}

func TestMullvadChipLabelAndDetails(t *testing.T) {
	if got := MullvadChipLabel("se-sto-wg-001"); got != "wg-001" {
		t.Error(got)
	}
	if got := MullvadChipLabel("odd"); got != "odd" {
		t.Error(got)
	}
	f := false
	r := &Relay{HostingProvider: "Example Hosting", Owned: &f, Stboot: &f}
	if got := MullvadDetails(r); got != "Example Hosting · rented" {
		t.Errorf("details = %q", got)
	}
	tr := true
	r.Stboot = &tr
	if got := MullvadDetails(r); got != "Example Hosting · rented · RAM-only" {
		t.Errorf("details = %q", got)
	}
	if MullvadDetails(&Relay{}) != "" {
		t.Error("empty details")
	}
}

func TestParseMullvadCatalogRejectsBadBodies(t *testing.T) {
	for _, body := range []string{"not json", "{}", `{"locations":{},"wireguard":{"relays":[]}}x`, `{"locations":{"a":1,"a":2},"wireguard":{"relays":[]}}`} {
		if _, err := ParseMullvadCatalog([]byte(body), false); err == nil {
			t.Errorf("%q accepted", body)
		}
	}
	// A valid but empty list parses; refusing an empty catalogue is the refresh's job.
	got, err := ParseMullvadCatalog([]byte(`{"locations":{},"wireguard":{"relays":[]}}`), false)
	if err != nil || got.Len() != 0 {
		t.Errorf("%v %v", got, err)
	}
}

func FuzzParseMullvadCatalog(f *testing.F) {
	f.Add([]byte(`{"locations":{"se-sto":{"city":"A","country":"B"}},"wireguard":{"relays":[{"hostname":"se-sto-wg-001","active":true,"location":"se-sto","public_key":"` + mullvadKey + `","ipv4_addr_in":"198.51.100.10"}]}}`))
	if raw, err := os.ReadFile(fixture(f, "gluetun", "servers.json")); err == nil {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := ParseMullvadCatalog(data, false)
		if err != nil {
			return
		}
		entries.Each(func(name string, r *Relay) bool {
			if r.Hostname != name || !mullvadHostnameRE.MatchString(name) {
				t.Fatalf("entry %q is %+v", name, r)
			}
			// What a parse produced survives the snapshot's own validation.
			stored, err := jsonMarshal(r)
			if err != nil {
				t.Fatal(err)
			}
			back := ValidateMullvadEntry(decodeJSON(t, string(stored)))
			if back == nil || !sameJSON(t, back, r) {
				t.Fatalf("parsed entry does not survive validation: %s", stored)
			}
			return true
		})
	})
}
