// Tests for molebridge/gluetun_catalog.py, ported from tools/test_gluetun_client.py
// (the catalogue sections: the fixtures, selection, snapshot, endpoint and
// peer tests). The control-server client tests in that file (applier/gluetun.py)
// belong to the applier port, and the three tests that need gluetun's own
// servers.json (GLUETUN_SERVERS_JSON) run only when that variable names it.
package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/irashack/molebridge/internal/validate"
)

const (
	gluetunKey      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	gluetunOtherKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="
	gluetunNow      = 1000
)

func gluetunFixture(t testing.TB) string { return fixture(t, "gluetun", "servers.json") }

func gluetunStorage(t testing.TB) map[string]any {
	return obj(decodeJSON(t, string(readFixture(t, "gluetun", "servers.json"))))
}

func writeStorage(t testing.TB, storage any) string {
	path := filepath.Join(t.TempDir(), "servers.json")
	if err := os.WriteFile(path, mustMarshal(storage), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestGluetunProviders(t *testing.T) {
	if got := strings.Join(GluetunSupportedProviders, ","); got != "fastestvpn,ivpn,mullvad,nordvpn,surfshark,windscribe" {
		t.Fatalf("supported providers: %s", got)
	}
	for _, provider := range GluetunSupportedProviders {
		relays, timestamp, err := ReadGluetunSnapshot(gluetunFixture(t), provider, gluetunNow)
		if err != nil {
			t.Fatalf("%s: %v", provider, err)
		}
		if timestamp != 900 || relays.Len() != 2 {
			t.Errorf("%s: %d relays, timestamp %d", provider, relays.Len(), timestamp)
		}
		again, err := ReadGluetunCatalog(gluetunFixture(t), provider, gluetunNow)
		if err != nil || !equalStrings(names(again), names(relays)) {
			t.Errorf("%s: ReadGluetunCatalog differs", provider)
		}
		_, filter := GluetunSelection(provider)
		relays.Each(func(id string, relay *Relay) bool {
			if id != relay.ID || relay.SelectionFilter != filter || relay.PublicKey != gluetunKey {
				t.Errorf("%s: %+v", provider, relay)
			}
			return true
		})
		if provider == "windscribe" {
			if r, _ := relays.Get("windscribe-one.example.test"); r.Country != "" {
				t.Errorf("windscribe country %q", r.Country)
			}
		}
		if provider == "fastestvpn" {
			if r, _ := relays.Get("fastestvpn-one.example.test"); r.City != "" {
				t.Errorf("fastestvpn city %q", r.City)
			}
		}
	}
}

func TestServersAPlainAccountCannotUseNeverReachTheCatalogue(t *testing.T) {
	// Dedicated IP, Double VPN and obfuscated servers are in the file, not the catalogue.
	nord, _ := ReadGluetunCatalog(gluetunFixture(t), "nordvpn", gluetunNow)
	if !equalStrings(names(nord), []string{"nordvpn-one.example.test", "nordvpn-two.example.test"}) {
		t.Errorf("nordvpn: %v", names(nord))
	}
	surf, _ := ReadGluetunCatalog(gluetunFixture(t), "surfshark", gluetunNow)
	if !equalStrings(names(surf), []string{"zz-one.prod.surfshark.com", "zz-two-st001.prod.surfshark.com"}) {
		t.Errorf("surfshark: %v", names(surf))
	}
}

func TestNordVPNSelectabilityMatchesTheNativeRule(t *testing.T) {
	for name, tc := range map[string]struct {
		categories any
		ok         bool
	}{
		"standard": {[]any{"Standard VPN servers"}, true}, "p2p+standard": {[]any{"P2P", "Standard VPN servers"}, true},
		"dedicated": {[]any{"Dedicated IP"}, false}, "standard+dedicated": {[]any{"Standard VPN servers", "Dedicated IP"}, false},
		"double": {[]any{"Double VPN"}, false}, "onion": {[]any{"Onion Over VPN"}, false},
		"obfuscated": {[]any{"Standard VPN servers", "Obfuscated Servers"}, false}, "p2p": {[]any{"P2P"}, false},
		"empty": {[]any{}, false}, "none": {nil, false}, "not strings": {[]any{int64(3)}, false},
	} {
		if got := GluetunSelectable("nordvpn", map[string]any{"categories": tc.categories}); got != tc.ok {
			t.Errorf("%s: %v", name, got)
		}
	}
	if !GluetunSelectable("mullvad", map[string]any{}) {
		t.Error("other providers carry no classes")
	}
	for host, ok := range map[string]bool{"zz-one.prod.surfshark.com": true, "zz-two-st001.prod.surfshark.com": true,
		"zz-one-zz-two.prod.surfshark.com": false, "zz-abcde.prod.surfshark.com": false, "zz-one.surfshark.com": false} {
		if GluetunSelectable("surfshark", map[string]any{"hostname": host}) != ok {
			t.Errorf("surfshark %s", host)
		}
	}
}

func TestGluetunRelayProjection(t *testing.T) {
	relays, err := ReadGluetunCatalog(gluetunFixture(t), "mullvad", gluetunNow)
	if err != nil {
		t.Fatal(err)
	}
	relay, _ := relays.Get("mullvad-one.example.test")
	region := "Example Region"
	want := &Relay{Shape: ShapeGluetun, ID: "mullvad-one.example.test", SelectionFilter: "hostnames",
		Hostname: "mullvad-one.example.test", PublicKey: gluetunKey, IPv4AddrIn: "198.51.100.5",
		IPv4Addrs: []string{"198.51.100.5", "198.51.100.50"}, IPv6Addrs: []string{"2001:db8::1", "2001:db8::2"},
		Country: "Example Country", City: "Example City", Region: &region,
		Categories: []string{"Standard", "Example Category"}}
	if !sameJSON(t, relay, want) {
		t.Errorf("got %s", mustMarshal(relay))
	}
	if string(mustMarshal(relay)) != `{"hostname": "mullvad-one.example.test", "public_key": "`+gluetunKey+`", "ipv4_addr_in": "198.51.100.5", `+
		`"ipv4_addrs": ["198.51.100.5", "198.51.100.50"], "ipv6_addrs": ["2001:db8::1", "2001:db8::2"], "city": "Example City", `+
		`"country": "Example Country", "region": "Example Region", "categories": ["Standard", "Example Category"], `+
		`"id": "mullvad-one.example.test", "selection_filter": "hostnames"}` {
		t.Errorf("stored as %s", mustMarshal(relay))
	}
	if GluetunDetails(relay) != "Example Region · Standard · Example Category" || GluetunChipLabel("a.b.c") != "a" {
		t.Errorf("details %q", GluetunDetails(relay))
	}
}

func TestBadGluetunSnapshot(t *testing.T) {
	for _, name := range []string{"duplicate.json", "truncated.json", "future.json"} {
		if _, _, err := ReadGluetunSnapshot(fixture(t, "gluetun", name), "mullvad", gluetunNow); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestMalformedGluetunEntriesAreSkipped(t *testing.T) {
	long := func(n int) string { return strings.Repeat("x", n) }
	repeat := func(v any, n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = v
		}
		return out
	}
	for _, tc := range []struct {
		field string
		value any
	}{
		{"vpn", "openvpn"}, {"wgpubkey", gluetunOtherKey[:len(gluetunOtherKey)-1]}, {"wgpubkey", int64(4)},
		{"hostname", "UPPER.example.test"}, {"hostname", "-bad.example.test"}, {"hostname", "bad-.example.test"},
		{"hostname", "a..test"}, {"hostname", long(64) + ".test"}, {"hostname", strings.Repeat("a.", 126) + "aa"},
		{"hostname", "bad.example.test\n"}, {"hostname", "a_test"},
		{"country", long(257)}, {"country", "\x00"}, {"city", "\x7f"}, {"city", "\u0085"},
		{"city", int64(4)}, {"city", "\u202e"}, {"city", "\xed\xa0\x80"},
		{"region", []any{"Example"}}, {"categories", "Standard"},
		{"categories", []any{long(257)}}, {"categories", []any{"\n"}}, {"categories", []any{int64(3)}},
		{"categories", repeat("Standard", 65)}, {"ips", []any{"2001:db8::1"}},
		{"ips", "198.51.100.1"}, {"ips", []any{nil, int64(4), "198.51.100.01"}},
		{"ips", repeat("198.51.100.1", 65)},
		// A server naming one non-public IPv4 address is refused whole.
		{"ips", []any{"10.0.0.1"}}, {"ips", []any{"198.51.100.1", "192.168.0.1"}}, {"ips", []any{"127.0.0.1"}},
		{"ips", []any{"169.254.169.254", "198.51.100.1"}}, {"ips", []any{"100.64.0.1"}},
	} {
		storage := gluetunStorage(t)
		servers := list(obj(storage["mullvad"])["servers"])[:2]
		obj(storage["mullvad"])["servers"] = servers
		obj(servers[0])[tc.field] = tc.value
		relays, err := ReadGluetunCatalog(writeStorage(t, storage), "mullvad", gluetunNow)
		if err != nil || !equalStrings(names(relays), []string{"mullvad-two.example.test"}) {
			t.Errorf("%s=%.30v: %v %v", tc.field, tc.value, names(relays), err)
		}
	}
	// At the limits, the entry stays.
	storage := gluetunStorage(t)
	servers := list(obj(storage["mullvad"])["servers"])[:2]
	obj(storage["mullvad"])["servers"] = servers
	obj(servers[0])["ips"] = repeat("198.51.100.1", 64)
	obj(servers[0])["country"] = long(256)
	obj(servers[0])["categories"] = repeat("Standard", 64)
	relays, err := ReadGluetunCatalog(writeStorage(t, storage), "mullvad", gluetunNow)
	if err != nil || relays.Len() != 2 {
		t.Errorf("limits: %v %v", names(relays), err)
	}
}

func TestBadKeyCannotHideDuplicate(t *testing.T) {
	storage := gluetunStorage(t)
	first := obj(list(obj(storage["mullvad"])["servers"])[0])
	second := clonePlain(first)
	second["wgpubkey"] = "invalid"
	obj(storage["mullvad"])["servers"] = []any{first, second}
	_, err := ReadGluetunCatalog(writeStorage(t, storage), "mullvad", gluetunNow)
	if !errors.Is(err, ErrGluetunDuplicate) {
		t.Errorf("got %v", err)
	}
}

func TestInvalidUppercaseHostnameCannotHideFilterCollision(t *testing.T) {
	storage := gluetunStorage(t)
	first := obj(list(obj(storage["mullvad"])["servers"])[0])
	second := clonePlain(first)
	second["hostname"] = strings.ToUpper(first["hostname"].(string))
	obj(storage["mullvad"])["servers"] = []any{first, second}
	_, err := ReadGluetunCatalog(writeStorage(t, storage), "mullvad", gluetunNow)
	if err == nil || err.Error() != "duplicate gluetun server identifier" {
		t.Errorf("got %v", err)
	}
	// Full case folding: "ss" and sharp s collide as they do in gluetun's casefold.
	for _, pair := range [][2]string{{"straße.example.test", "STRASSE.example.test"}, {"Km.example.test", "Km.example.test"}} {
		storage = gluetunStorage(t)
		a, b := clonePlain(first), clonePlain(first)
		a["hostname"], b["hostname"] = pair[0], pair[1]
		obj(storage["mullvad"])["servers"] = []any{a, b}
		if _, err := ReadGluetunCatalog(writeStorage(t, storage), "mullvad", gluetunNow); !errors.Is(err, ErrGluetunDuplicate) {
			t.Errorf("%q vs %q: %v", pair[0], pair[1], err)
		}
	}
	// A row for another VPN protocol does not count.
	storage = gluetunStorage(t)
	other := clonePlain(first)
	other["vpn"] = "openvpn"
	obj(storage["mullvad"])["servers"] = []any{first, other}
	if _, err := ReadGluetunCatalog(writeStorage(t, storage), "mullvad", gluetunNow); err != nil {
		t.Errorf("openvpn twin: %v", err)
	}
}

func TestProviderWithoutExactSelectionRejected(t *testing.T) {
	for _, provider := range []string{"airvpn", "custom", "protonvpn"} {
		_, err := ReadGluetunCatalog(gluetunFixture(t), provider, gluetunNow)
		if err == nil || err.Error() != GluetunRejectedProviders[provider] {
			t.Errorf("%s: %v", provider, err)
		}
	}
}

func TestAmbiguousProviderFixtures(t *testing.T) {
	storage := gluetunStorage(t)
	for _, provider := range []string{"airvpn", "protonvpn"} {
		servers := list(obj(storage[provider])["servers"])
		for _, field := range []string{"server_name", "hostname"} {
			seen := map[string]bool{}
			for _, s := range servers {
				seen[obj(s)[field].(string)] = true
			}
			if len(seen) >= len(servers) {
				t.Errorf("%s: %s is unique, the fixture is meant to repeat it", provider, field)
			}
		}
	}
}

func TestGluetunTimestamp(t *testing.T) {
	for name, timestamp := range map[string]any{"null": nil, "bool": true, "text": "900", "float": 900.0, "negative": int64(-1), "future": int64(1001)} {
		storage := gluetunStorage(t)
		obj(storage["mullvad"])["timestamp"] = timestamp
		_, err := ReadGluetunCatalog(writeStorage(t, storage), "mullvad", gluetunNow)
		if !errors.Is(err, ErrGluetunTimestamp) || !strings.Contains(err.Error(), "timestamp") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The timestamp may equal now, and 0 is a timestamp.
	for _, timestamp := range []int64{0, gluetunNow} {
		storage := gluetunStorage(t)
		obj(storage["mullvad"])["timestamp"] = timestamp
		if _, ts, err := ReadGluetunSnapshot(writeStorage(t, storage), "mullvad", gluetunNow); err != nil || ts != timestamp {
			t.Errorf("%d: %v", timestamp, err)
		}
	}
}

func TestInvalidGluetunStructure(t *testing.T) {
	block := func(m map[string]any) map[string]any { return map[string]any{"version": int64(1), "mullvad": m} }
	for name, data := range map[string]any{
		"list": []any{}, "empty": map[string]any{}, "version bool": map[string]any{"version": true},
		"version 2": map[string]any{"version": int64(2)}, "no block": map[string]any{"version": int64(1)},
		"block is a list":        map[string]any{"version": int64(1), "mullvad": []any{}},
		"no servers":             block(map[string]any{"version": int64(1), "timestamp": int64(900), "servers": []any{}}),
		"servers not a list":     block(map[string]any{"version": int64(1), "timestamp": int64(900), "servers": "x"}),
		"block version float":    block(map[string]any{"version": 1.0, "timestamp": int64(900), "servers": []any{}}),
		"block version big":      block(map[string]any{"version": int64(65536), "timestamp": int64(900), "servers": []any{}}),
		"block version negative": block(map[string]any{"version": int64(-1), "timestamp": int64(900), "servers": []any{}}),
		"null":                   nil,
	} {
		if _, err := ReadGluetunCatalog(writeStorage(t, data), "mullvad", gluetunNow); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestUnsupportedGluetunProvider(t *testing.T) {
	for _, provider := range []string{"pia", "private internet access", "Mullvad", ""} {
		_, err := ReadGluetunCatalog(gluetunFixture(t), provider, gluetunNow)
		if !errors.Is(err, ErrGluetunUnsupported) || !strings.Contains(err.Error(), "unsupported") {
			t.Errorf("%q: %v", provider, err)
		}
	}
}

func TestGluetunClock(t *testing.T) {
	data := gluetunStorage(t)
	for _, now := range []float64{-1} {
		if _, _, err := ParseGluetunCatalog(data, "mullvad", now); !errors.Is(err, ErrGluetunClock) {
			t.Errorf("now=%v: %v", now, err)
		}
	}
	nan := func() float64 { var z float64; return z / z }()
	if _, _, err := ParseGluetunCatalog(data, "mullvad", nan); !errors.Is(err, ErrGluetunClock) {
		t.Errorf("NaN clock: %v", err)
	}
	if _, _, err := ParseGluetunCatalog(data, "mullvad", 1e300); err != nil {
		t.Errorf("a huge clock is fine: %v", err)
	}
}

func TestBadGluetunJSONIsSanitized(t *testing.T) {
	for _, raw := range [][]byte{[]byte(`{"version":1,"version":1}`), {0xff}, []byte(`{"version":NaN}`),
		bytes.Repeat([]byte("["), 2000), []byte(`{} trailing`), []byte("\xef\xbb\xbf{}")} {
		path := filepath.Join(t.TempDir(), "servers.json")
		os.WriteFile(path, raw, 0o600)
		_, err := ReadGluetunCatalog(path, "mullvad", gluetunNow)
		if err == nil || err.Error() != "cannot read gluetun catalogue" {
			t.Errorf("%.20q: %v", raw, err)
		}
	}
	// Only the version and the selected provider's block are built; another
	// provider's block is checked as strictly, unbuilt, and a fault in it
	// still refuses the whole file.
	good := mustMarshal(gluetunStorage(t))
	write := func(raw []byte) string {
		path := filepath.Join(t.TempDir(), "servers.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if _, err := ReadGluetunCatalog(write(append([]byte(`{"example-other":{"servers":[]},`), good[1:]...)), "mullvad", gluetunNow); err != nil {
		t.Fatalf("the base document: %v", err)
	}
	for _, other := range []string{`{"servers":[{"a":1,"a":2}]}`, `{"servers":[NaN]}`, "{\"name\":\"\xff\"}",
		strings.Repeat("[", 1000) + strings.Repeat("]", 1000), `{"servers":[1` + strings.Repeat("0", 4300) + `]}`,
		`{"servers":[1,]}`} {
		raw := append([]byte(`{"example-other":`+other+`,`), good[1:]...)
		if _, err := ReadGluetunCatalog(write(raw), "mullvad", gluetunNow); err == nil || err.Error() != "cannot read gluetun catalogue" {
			t.Errorf("%.30q in another block: %v", other, err)
		}
	}
	for _, repeated := range []string{"mullvad", "ivpn", "\\u0069vpn"} {
		raw := append([]byte(`{"`+repeated+`":{},`), good[1:]...)
		if _, err := ReadGluetunCatalog(write(raw), "mullvad", gluetunNow); err == nil || err.Error() != "cannot read gluetun catalogue" {
			t.Errorf("a repeated %s block: %v", repeated, err)
		}
	}
	// The JSON null decodes, and is refused as a document, not as a read.
	path := filepath.Join(t.TempDir(), "servers.json")
	os.WriteFile(path, []byte("null"), 0o600)
	if _, err := ReadGluetunCatalog(path, "mullvad", gluetunNow); !errors.Is(err, ErrGluetunFormat) {
		t.Errorf("null: %v", err)
	}
}

func TestUnsafeGluetunCatalogueFile(t *testing.T) {
	for _, kind := range []string{"oversized", "symlink", "fifo", "directory", "missing"} {
		path := filepath.Join(t.TempDir(), "servers.json")
		switch kind {
		case "oversized":
			f, _ := os.Create(path)
			f.Truncate(GluetunMaxCatalogBytes + 1)
			f.Close()
		case "symlink":
			abs, _ := filepath.Abs(gluetunFixture(t))
			os.Symlink(abs, path)
		case "fifo":
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
		case "directory":
			os.Mkdir(path, 0o700)
		}
		_, err := ReadGluetunCatalog(path, "mullvad", gluetunNow)
		if err == nil || err.Error() != "cannot read gluetun catalogue" {
			t.Errorf("%s: %v", kind, err)
		}
	}
}

func TestTruncatedReadLeavesPreviousSnapshot(t *testing.T) {
	previous, _, err := ReadGluetunSnapshot(gluetunFixture(t), "mullvad", gluetunNow)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := previous
	if got, _, err := ReadGluetunSnapshot(fixture(t, "gluetun", "truncated.json"), "mullvad", gluetunNow); err == nil {
		snapshot = got
	}
	if snapshot != previous {
		t.Error("a failed read replaced the snapshot")
	}
}

func TestSharedKeyIsIdentifiedByEndpoint(t *testing.T) {
	for _, provider := range []string{"nordvpn", "windscribe"} {
		relays, _ := ReadGluetunCatalog(gluetunFixture(t), provider, gluetunNow)
		relays.Each(func(id string, relay *Relay) bool {
			for _, endpoint := range []string{relay.IPv4AddrIn, relay.IPv4AddrIn + ":51820"} {
				if got, ok := ServerForPeer(relays, gluetunKey, endpoint); !ok || got != id {
					t.Errorf("%s %s: %q", provider, endpoint, got)
				}
				if _, ok := ServerForPeer(relays, gluetunOtherKey, endpoint); ok {
					t.Errorf("%s %s: other key accepted", provider, endpoint)
				}
			}
			return true
		})
		if _, ok := ServerForPeer(relays, gluetunKey, "192.0.2.1:51820"); ok {
			t.Error("unknown address resolved")
		}
		ambiguous := NewEntries()
		relays.Each(func(id string, r *Relay) bool { ambiguous.Set(id, r.Copy()); return true })
		ids := ambiguous.Names()
		first, _ := ambiguous.Get(ids[0])
		second, _ := ambiguous.Get(ids[1])
		second.IPv4AddrIn, second.IPv4Addrs, second.PublicKey = first.IPv4AddrIn, []string{first.IPv4AddrIn}, gluetunOtherKey
		if got, ok := ServerForPeer(ambiguous, gluetunKey, first.IPv4AddrIn); ok {
			t.Errorf("an address listed twice resolved to %s", got)
		}
	}
}

func TestBadPeerEndpoint(t *testing.T) {
	relays, _ := ReadGluetunCatalog(gluetunFixture(t), "mullvad", gluetunNow)
	for _, endpoint := range []string{"", "example.test:51820", "198.51.100.5:0", "198.51.100.5:65536", "198.51.100.5:x",
		"[2001:db8::1]:51820", "198.51.100.5:1\n"} {
		if got, ok := ServerForPeer(relays, gluetunKey, endpoint); ok {
			t.Errorf("%q -> %s", endpoint, got)
		}
	}
	if _, ok := ServerForPeer(relays, "invalid", "198.51.100.5"); ok {
		t.Error("invalid key resolved")
	}
}

func TestEveryAddressOfAServerIdentifiesIt(t *testing.T) {
	// gluetun connects to any address of the selected server.
	relays, _ := ReadGluetunCatalog(gluetunFixture(t), "mullvad", gluetunNow)
	one := "mullvad-one.example.test"
	for _, endpoint := range []string{"198.51.100.5:51820", "198.51.100.50:51820", "198.51.100.50", "[2001:db8::2]:51820", "2001:db8::2"} {
		if got, ok := ServerForPeer(relays, gluetunKey, endpoint); !ok || got != one {
			t.Errorf("%s -> %q", endpoint, got)
		}
	}
	// 2001:db8::1 is listed for both Mullvad servers here, 2001:db8::2 for one.
	if _, ok := ServerForPeer(relays, gluetunKey, "[2001:db8::1]:51820"); ok {
		t.Error("shared address resolved")
	}
	if _, ok := ServerForPeer(relays, gluetunOtherKey, "[2001:db8::2]:51820"); ok {
		t.Error("wrong key resolved")
	}
}

func TestEndpointAddress(t *testing.T) {
	for _, tc := range []struct {
		endpoint, address string
	}{
		{"198.51.100.5:51820", "198.51.100.5"}, {"198.51.100.5", "198.51.100.5"},
		{"[2001:db8::2]:51820", "2001:db8::2"}, {"[2001:DB8::2]:51820", "2001:db8::2"}, {"2001:db8::2", "2001:db8::2"},
		{"[2001:db8::2]", "2001:db8::2"}, {"[198.51.100.5]:51820", ""}, {"[2001:db8::2]:0", ""},
		{"[2001:db8::2]:65536", ""}, {"[2001:db8::2]51820", ""}, {"2001:db8::2]:1", ""},
		{"[2001:db8::2%eth0]:1", ""}, {"198.51.100.05:1", ""}, {strings.Repeat("x", 65), ""}, {"", ""},
		{"[2001:db8::2]:123456", ""}, {"198.51.100.5:65535", "198.51.100.5"}, {"198.51.100.5:1", "198.51.100.5"},
	} {
		got, ok := EndpointAddress(tc.endpoint)
		if got != tc.address || ok != (tc.address != "") {
			t.Errorf("EndpointAddress(%q) = %q %v", tc.endpoint, got, ok)
		}
	}
}

func TestSnapshotEntriesKeepEveryAddress(t *testing.T) {
	relays, _ := ReadGluetunCatalog(gluetunFixture(t), "mullvad", gluetunNow)
	relay, _ := relays.Get("mullvad-one.example.test")
	stored := decodeJSON(t, string(mustMarshal(GluetunSnapshotEntry(relay))))
	entry := ValidateGluetunEntry(stored)
	if entry == nil || strings.Join(entry.IPv4Addrs, ",") != "198.51.100.5,198.51.100.50" || !sameJSON(t, entry, relay) {
		t.Fatalf("snapshot entry: %+v", entry)
	}
	for _, bad := range [][]any{{"198.51.100.50", "198.51.100.5"}, {}, {"198.51.100.5", "198.51.100.5"}, {"198.51.100.5", "x"},
		{"198.51.100.5", "10.0.0.5"}} {
		changed := obj(clone(t, stored))
		changed["ipv4_addrs"] = bad
		if ValidateGluetunEntry(changed) != nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestGluetunSnapshotEntryTakesRegionAsCountry(t *testing.T) {
	region := "Example Region"
	relay := &Relay{Shape: ShapeGluetun, Country: "", Region: &region}
	entry := GluetunSnapshotEntry(relay)
	if entry.Country != "Example Region" || entry.Region != nil || relay.Region == nil || relay.Country != "" {
		t.Errorf("%+v / %+v", entry, relay)
	}
	named := &Relay{Shape: ShapeGluetun, Country: "X", Region: &region}
	if e := GluetunSnapshotEntry(named); e.Country != "X" || e.Region == nil {
		t.Errorf("%+v", e)
	}
}

func TestValidateGluetunEntry(t *testing.T) {
	good := func() map[string]any {
		return map[string]any{"id": "a.example.test", "hostname": "a.example.test", "selection_filter": "hostnames",
			"public_key": gluetunKey, "ipv4_addr_in": "198.51.100.5", "ipv6_addrs": []any{}, "city": "", "country": ""}
	}
	if ValidateGluetunEntry(decoded(t, good())) == nil {
		t.Fatal("good entry rejected")
	}
	for name, change := range map[string]func(m map[string]any){
		"unknown key": func(m map[string]any) { m["extra"] = int64(1) }, "wrong filter": func(m map[string]any) { m["selection_filter"] = "names" },
		"id differs": func(m map[string]any) { m["id"] = "b.example.test" }, "bad key": func(m map[string]any) { m["public_key"] = "AAAA" },
		"bad hostname": func(m map[string]any) { m["hostname"] = "A.example.test"; m["id"] = "A.example.test" },
		"ipv6 in v4":   func(m map[string]any) { m["ipv4_addr_in"] = "2001:db8::1" }, "no ipv6 list": func(m map[string]any) { delete(m, "ipv6_addrs") },
		"private v4": func(m map[string]any) { m["ipv4_addr_in"] = "172.20.0.5" }, "loopback v4": func(m map[string]any) { m["ipv4_addr_in"] = "127.0.0.1" },
		"v4 in v6 list":   func(m map[string]any) { m["ipv6_addrs"] = []any{"198.51.100.1"} },
		"noncanonical v6": func(m map[string]any) { m["ipv6_addrs"] = []any{"2001:DB8::1"} },
		"too many v6": func(m map[string]any) {
			l := make([]any, 65)
			for i := range l {
				l[i] = "2001:db8::1"
			}
			m["ipv6_addrs"] = l
		},
		"no city": func(m map[string]any) { delete(m, "city") }, "country null": func(m map[string]any) { m["country"] = nil },
		"region list": func(m map[string]any) { m["region"] = []any{} }, "categories string": func(m map[string]any) { m["categories"] = "x" },
	} {
		m := good()
		change(m)
		if ValidateGluetunEntry(decoded(t, m)) != nil {
			t.Errorf("%s accepted", name)
		}
	}
	if ValidateGluetunEntry(nil) != nil {
		t.Error("nil accepted")
	}
	// Optional members stay optional, and absent ones stay absent.
	r := ValidateGluetunEntry(decoded(t, good()))
	if r.IPv4Addrs != nil || r.Categories != nil || r.Region != nil || r.IPv6Addrs == nil {
		t.Errorf("%+v", r)
	}
}

func TestGluetunHostnameAndServerNames(t *testing.T) {
	spec, _ := Lookup("gluetun-mullvad")
	for name, ok := range map[string]bool{"a": true, "a.b": true, "a-b.c-d.example": true, strings.Repeat("a", 63): true,
		strings.Repeat("a", 64): false, "-a": false, "a-": false, "A": false, "a..b": false, "a b": false, "": false, "a\n": false,
		strings.Repeat("a.", 126) + "a": true, strings.Repeat("a.", 127) + "a": false, "é": false} {
		if got := spec.ValidServerName(name); got != ok && len(name) <= 253 {
			t.Errorf("%q: %v", name, got)
		}
	}
	if spec.ValidServerName(nil) || spec.ValidServerName(5) {
		t.Error("non-strings accepted")
	}
	// 253 characters is the limit, even when each label fits.
	label := strings.Repeat("a", 63)
	if !ValidGluetunHostname(strings.Join([]string{label, label, label, strings.Repeat("a", 61)}, ".")) {
		t.Error("253 characters must be accepted")
	}
	if ValidGluetunHostname(strings.Join([]string{label, label, label, strings.Repeat("a", 62)}, ".")) {
		t.Error("254 characters must be refused")
	}
}

// -- gluetun's own servers.json, when a checkout is available --------------------

func TestReferenceCatalogueIDsSelectExactlyOneRow(t *testing.T) {
	path := os.Getenv("GLUETUN_SERVERS_JSON")
	if path == "" {
		t.Skip("GLUETUN_SERVERS_JSON not set")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skip(err)
	}
	var data map[string]json.RawMessage
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	for _, provider := range GluetunSupportedProviders {
		relays, err := ReadGluetunCatalog(path, provider, 1<<62)
		if err != nil || relays.Len() == 0 {
			t.Errorf("%s: %v", provider, err)
			continue
		}
		var block struct {
			Servers []map[string]any `json:"servers"`
		}
		json.Unmarshal(data[provider], &block)
		counts := map[string]int{}
		field, _ := GluetunSelection(provider)
		for _, entry := range block.Servers {
			if entry["vpn"] == "wireguard" {
				counts[casefold(entry[field].(string))]++
			}
		}
		for _, count := range counts {
			if count != 1 {
				t.Errorf("%s: a reference identifier repeats", provider)
				break
			}
		}
		relays.Each(func(id string, _ *Relay) bool {
			if counts[casefold(id)] != 1 {
				t.Errorf("%s: an identifier does not select one row", provider)
				return false
			}
			return true
		})
	}
}

func TestCasefold(t *testing.T) {
	for _, tc := range []struct{ a, b string }{
		{"Example.Test", "example.test"}, {"STRASSE", "straße"}, {"ǅ", "ǆ"}, {"Σ", "ς"}, {"K", "k"}, {"ﬁle", "FILE"},
		{"İ", "i̇"},
	} {
		if casefold(tc.a) != casefold(tc.b) {
			t.Errorf("%q and %q should fold alike", tc.a, tc.b)
		}
	}
	if casefold("a") == casefold("b") || casefold("ss") == casefold("s") {
		t.Error("distinct strings fold alike")
	}
}

func FuzzParseGluetunCatalog(f *testing.F) {
	f.Add(readFixture(f, "gluetun", "servers.json"))
	f.Add([]byte(`{"version":1,"mullvad":{"version":1,"timestamp":1,"servers":[]}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		data, err := validate.DecodeJSON(raw)
		if err != nil {
			return
		}
		for _, provider := range GluetunSupportedProviders {
			relays, _, err := ParseGluetunCatalog(data, provider, 1e12)
			if err != nil {
				continue
			}
			relays.Each(func(id string, r *Relay) bool {
				// What the reader returns the snapshot validator accepts, and
				// every address of a relay resolves back to it or to nothing.
				back := ValidateGluetunEntry(decodeJSON(t, string(mustMarshal(GluetunSnapshotEntry(r)))))
				if r.Country == "" && r.Region != nil && *r.Region != "" {
					return true
				}
				if back == nil || id != r.ID || r.ID != r.Hostname {
					t.Fatalf("%s: %q does not validate", provider, id)
				}
				for address := range RelayAddresses(r) {
					endpoint := address
					if strings.Contains(address, ":") {
						endpoint = "[" + address + "]:51820"
					}
					if got, ok := ServerForPeer(relays, r.PublicKey, endpoint); ok && got != id {
						t.Fatalf("%s: %s resolves to %s, not %s", provider, address, got, id)
					}
				}
				return true
			})
		}
	})
}

func FuzzEndpointAddress(f *testing.F) {
	for _, s := range []string{"198.51.100.5:51820", "[2001:db8::2]:51820", "2001:db8::2", "[::1]", "x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		address, ok := EndpointAddress(s)
		if !ok {
			return
		}
		again, ok := EndpointAddress(address)
		if !ok || again != address {
			t.Fatalf("%q -> %q, which does not hold: %q", s, address, again)
		}
	})
}
