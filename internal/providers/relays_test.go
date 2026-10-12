// Tests for molebridge/relays.py, ported from tools/test_providers.py
// (test_snapshot_of_another_provider_is_ignored, test_snapshot_limits_come_
// from_the_registry, test_oversized_snapshot_keeps_the_last_good_catalogue,
// test_readers_and_writer_agree_on_the_limit, the bounded-memory tests,
// test_early_bound_never_refuses_what_fits) and tools/test_runtime.py
// (test_failed_refresh_preserves_last_good_catalogue, test_refresh_recovery,
// test_panel_owned_catalogue_cannot_authorize_endpoint).
package providers

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/validate"
)

var epoch = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func clock(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestSnapshotOfAnotherProviderIsIgnored(t *testing.T) {
	for _, provider := range IDs() {
		var other string
		for _, p := range IDs() {
			if p != provider {
				other = p
				break
			}
		}
		snapshot := decoded(t, map[string]any{"fetched_at": validate.FormatTime(epoch), "provider": other,
			"relays": map[string]any{"x": map[string]any{"hostname": "x"}}})
		if SnapshotRelays(snapshot, provider).Len() != 0 {
			t.Errorf("%s read %s's snapshot", provider, other)
		}
		obj(snapshot)["provider"] = provider
		if SnapshotRelays(snapshot, provider).Len() != 0 {
			t.Errorf("%s accepted an entry that fails validation", provider)
		}
	}
	for _, bad := range []any{nil, "x", []any{}, map[string]any{}, map[string]any{"relays": []any{}}} {
		if SnapshotRelays(bad, "mullvad").Len() != 0 {
			t.Errorf("%#v", bad)
		}
	}
}

func TestSnapshotRelaysDropsEntriesKeyedByAnotherName(t *testing.T) {
	entry := mullvadEntry()
	snapshot := decoded(t, map[string]any{"fetched_at": validate.FormatTime(epoch), "relays": map[string]any{
		mullvadHost: entry, "se-sto-wg-002": entry, "se-sto-wg-000": mullvadEntry()}})
	// The third is keyed correctly only by chance of its name differing; it is dropped too.
	got := SnapshotRelays(snapshot, "mullvad")
	if !equalStrings(names(got), []string{mullvadHost}) {
		t.Errorf("%v", names(got))
	}
}

func TestOversizedSnapshotKeepsTheLastGoodCatalogue(t *testing.T) {
	for _, provider := range IDs() {
		dir := t.TempDir()
		catalog := NewRelayCatalog(dir, provider, false, clock(epoch))
		good := map[string]any{"fetched_at": validate.FormatTime(epoch), "provider": provider, "relays": map[string]any{}}
		if err := jsonfile.Write(catalog.Path, good, jsonfile.Options{Public: true}); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(catalog.Path)
		spec := mustGet(t, provider).Clone()
		spec.SnapshotMaxBytes = 1000
		big := NewEntries()
		for i := 0; i < 200; i++ {
			name := "name" + string(rune('a'+i%26)) + string(rune('a'+i/26))
			big.Set(name, &Relay{Shape: ShapeMullvad, Hostname: name})
		}
		spec.ParseCatalog = func([]byte, bool) (*Entries, error) { return big, nil }
		restore := Replace(spec)
		ok, err := catalog.Refresh(func() ([]byte, error) { return []byte("x"), nil })
		restore()
		if ok || err != nil {
			t.Errorf("%s: refresh = %v, %v", provider, ok, err)
		}
		after, _ := os.ReadFile(catalog.Path)
		if string(after) != string(before) {
			t.Errorf("%s: the last good catalogue changed", provider)
		}
		failure, _ := jsonfile.ReadObject(catalog.ErrorPath, 4096)
		if failure["message"] != "Relay refresh failed; retaining the last good catalogue." {
			t.Errorf("%s: %v", provider, failure)
		}
	}
}

func TestReadersAndWriterAgreeOnTheLimit(t *testing.T) {
	// A snapshot the writer accepts, the applier and the panel can read back.
	dir := t.TempDir()
	path := filepath.Join(dir, "relays.json")
	payload := validate.Members("fetched_at", validate.FormatTime(epoch), "provider", "nordvpn", "relays", validate.Obj{},
		"pad", strings.Repeat("x", 12*1024*1024))
	if err := jsonfile.Write(path, payload, jsonfile.Options{Public: true, MaxBytes: SnapshotLimit("nordvpn")}); err != nil {
		t.Fatal(err)
	}
	if got := ReadSnapshot(path, "nordvpn"); got == nil || len(got["pad"].(string)) != 12*1024*1024 {
		t.Error("the nordvpn reader cannot read what the writer accepted")
	}
	if ReadSnapshot(path, "mullvad") != nil {
		t.Error("the mullvad limit is smaller than the file")
	}
}

// bigEntries are NordVPN-shaped entries sharing one long text, so building
// them is cheap while serialising them is not (about 3 kB each).
func bigEntries(count int) *Entries {
	long := strings.Repeat("é", 250) // 1,500 bytes once JSON-escaped
	entries := NewEntries()
	for i := 0; i < count; i++ {
		name := "us" + strings.Repeat("x", 0) + itoa(i) + ".nordvpn.com"
		entries.Set(name, &Relay{Shape: ShapeNordVPN, Hostname: name, City: long, Country: long, CountryCode: "US", LocationCode: "us-x"})
	}
	return entries
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func allocated(action func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	action()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

func TestOversizedNordVPNRefreshKeepsLastGoodWithBoundedMemory(t *testing.T) {
	// 50,000 entries fail the early bound; 5,800 pass it (about 3.6 MB of text
	// counted once) but serialise past 16 MiB, so the encoder stops them.
	for _, count := range []int{50000, 5800} {
		dir := t.TempDir()
		good := map[string]any{"fetched_at": validate.FormatTime(epoch), "provider": "nordvpn", "relays": map[string]any{}}
		if err := jsonfile.Write(filepath.Join(dir, "relays.json"), good, jsonfile.Options{Public: true}); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(filepath.Join(dir, "relays.json"))
		entries := bigEntries(count)
		if got := SnapshotTooLarge(entries, SnapshotLimit("nordvpn")); got != (count == 50000) {
			t.Errorf("count %d: early bound = %v", count, got)
		}
		spec := mustGet(t, "nordvpn").Clone()
		spec.ParseCatalog = func([]byte, bool) (*Entries, error) { return entries, nil }
		restore := Replace(spec)
		catalog := NewRelayCatalog(dir, "nordvpn", false, clock(epoch))
		var ok bool
		var err error
		grown := allocated(func() { ok, err = catalog.Refresh(func() ([]byte, error) { return []byte("x"), nil }) })
		restore()
		if ok || err != nil || catalog.Relays.Len() != 0 {
			t.Errorf("count %d: %v %v %d", count, ok, err, catalog.Relays.Len())
		}
		// The document is never built as output: the encoder stops within a chunk
		// of the limit. (The 16 MiB it may have written went to a file, not the heap.)
		if grown > 24<<20 {
			t.Errorf("count %d: allocated %d MiB while refusing a document", count, grown>>20)
		}
		after, _ := os.ReadFile(filepath.Join(dir, "relays.json"))
		if string(after) != string(before) {
			t.Errorf("count %d: the last good catalogue changed", count)
		}
		failure, _ := jsonfile.ReadObject(filepath.Join(dir, "relay-error.json"), 4096)
		if failure["message"] != RefreshFailedMessage {
			t.Errorf("count %d: %v", count, failure)
		}
		entriesOnDisk, _ := os.ReadDir(dir)
		var got []string
		for _, e := range entriesOnDisk {
			got = append(got, e.Name())
		}
		sort.Strings(got)
		if !equalStrings(got, []string{"relay-error.json", "relays.json"}) {
			t.Errorf("count %d: files %v", count, got)
		}
	}
}

func TestEarlyBoundNeverRefusesWhatFits(t *testing.T) {
	entries := bigEntries(100)
	snapshot := validate.Members("fetched_at", validate.FormatTime(epoch), "provider", "nordvpn", "relays", entries)
	raw, err := validate.MarshalJSON(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if SnapshotTooLarge(entries, int64(len(raw))) {
		t.Error("the bound refused a document that fits")
	}
	if !SnapshotTooLarge(entries, 100*260) {
		t.Error("the bound missed an oversized document")
	}
	if SnapshotTooLarge(NewEntries(), 0) || SnapshotTooLarge(nil, 0) {
		t.Error("an empty catalogue is never too large")
	}
}

func fetchJSON(v any) func() ([]byte, error) {
	return func() ([]byte, error) { return validate.MarshalJSON(v) }
}

func TestFailedRefreshPreservesLastGoodCatalogue(t *testing.T) {
	for name, response := range map[string]string{"not json": "not json", "empty object": "{}",
		"no relays": `{"locations":{},"wireguard":{"relays":[]}}`} {
		dir := t.TempDir()
		write := func(c *RelayCatalog) {
			entries := NewEntries()
			r := ValidateMullvadEntry(decoded(t, mullvadEntry()))
			entries.Set(mullvadHost, r)
			if err := c.Publish(entries, nil); err != nil {
				t.Fatal(err)
			}
		}
		c := NewRelayCatalog(dir, "mullvad", false, clock(epoch))
		write(c)
		before, _ := os.ReadFile(c.Path)
		ok, err := c.Refresh(func() ([]byte, error) { return []byte(response), nil })
		after, _ := os.ReadFile(c.Path)
		if ok || err != nil || string(after) != string(before) {
			t.Errorf("%s: %v %v", name, ok, err)
		}
		if failure, _ := jsonfile.ReadObject(c.ErrorPath, 4096); failure["message"] == nil || failure["checked_at"] != "2026-10-11T12:00:00Z" {
			t.Errorf("%s: %v", name, failure)
		}
		if !c.Usable() || c.Relays.Len() != 1 {
			t.Errorf("%s: the last good catalogue is no longer in use", name)
		}
	}
	// A failing fetch is a failed refresh too.
	c := NewRelayCatalog(t.TempDir(), "mullvad", false, clock(epoch))
	if ok, err := c.Refresh(func() ([]byte, error) { return nil, errors.New("down") }); ok || err != nil {
		t.Errorf("fetch error: %v %v", ok, err)
	}
	if message := ReadSnapshot(c.ErrorPath, "mullvad"); message["message"] != RefreshFailedMessage {
		t.Errorf("%v", message)
	}
}

func TestRefreshRecovery(t *testing.T) {
	dir := t.TempDir()
	c := NewRelayCatalog(dir, "mullvad", false, clock(epoch))
	if c.Usable() {
		t.Error("an empty catalogue is usable")
	}
	c.RecordFailure(RefreshFailedMessage)
	ok, err := c.Refresh(fetchJSON(mullvadPayload(t, nil)))
	if !ok || err != nil || !c.Usable() {
		t.Fatalf("%v %v", ok, err)
	}
	if got, _ := jsonfile.ReadObject(c.ErrorPath, 4096); len(got) != 0 {
		t.Errorf("error record not cleared: %v", got)
	}
	info, _ := os.Stat(c.Path)
	errInfo, _ := os.Stat(c.ErrorPath)
	if info.Mode().Perm() != 0o644 || errInfo.Mode().Perm() != 0o644 {
		t.Errorf("modes %v %v", info.Mode(), errInfo.Mode())
	}
	raw, _ := os.ReadFile(c.Path)
	want := `{"fetched_at": "2026-10-11T12:00:00Z", "provider": "mullvad", "relays": {"se-sto-wg-001": {"hostname": "se-sto-wg-001", ` +
		`"public_key": "` + mullvadKey + `", "ipv4_addr_in": "198.51.100.10", "city": "Example City", "country": "Example", "location_code": "se-sto"}}}`
	if string(raw) != want {
		t.Errorf("\n got %s\nwant %s", raw, want)
	}
	// A new catalogue object reads the same snapshot back.
	again := NewRelayCatalog(dir, "mullvad", false, clock(epoch))
	if !again.Usable() || again.Relays.Len() != 1 || again.Snapshot["fetched_at"] != "2026-10-11T12:00:00Z" {
		t.Errorf("%+v", again.Snapshot)
	}
	// ...and finds it stale a day later, and for another provider empty.
	if NewRelayCatalog(dir, "mullvad", false, clock(epoch.Add(24*time.Hour+time.Second))).Usable() {
		t.Error("a stale snapshot is usable")
	}
	if !NewRelayCatalog(dir, "mullvad", false, clock(epoch.Add(24*time.Hour))).Usable() {
		t.Error("a day-old snapshot is still usable")
	}
	if NewRelayCatalog(dir, "pia", false, clock(epoch)).Relays.Len() != 0 {
		t.Error("another provider's snapshot is in use")
	}
}

func TestPanelOwnedCatalogueCannotAuthorizeEndpoint(t *testing.T) {
	// The applier reads state/applier/relays.json only; a catalogue in the
	// panel's directory is a different directory, so a catalogue made there is
	// not the applier's.
	root := t.TempDir()
	panelSnapshot := validate.Members("fetched_at", validate.FormatTime(epoch), "relays", validate.Members(mullvadHost, mullvadEntry()))
	if err := jsonfile.Write(filepath.Join(root, "panel", "relays.json"), panelSnapshot, jsonfile.Options{}); err != nil {
		t.Fatal(err)
	}
	if c := NewRelayCatalog(filepath.Join(root, "applier"), "mullvad", false, clock(epoch)); c.Relays.Len() != 0 || c.Usable() {
		t.Error("the applier's catalogue came from the panel's directory")
	}
}

func TestPortForwardOnlyCatalogueFiltersTheSnapshot(t *testing.T) {
	dir := t.TempDir()
	c := NewRelayCatalog(dir, "pia", false, clock(epoch))
	ok, err := c.Refresh(func() ([]byte, error) {
		return serverlist(t, testRegionJSON(nil), testRegionJSON(map[string]any{"id": "ex_nopf", "port_forward": false})), nil
	})
	if !ok || err != nil || c.Relays.Len() != 2 {
		t.Fatalf("%v %v", ok, err)
	}
	only := NewRelayCatalog(dir, "pia", true, clock(epoch))
	if !equalStrings(names(only.Relays), []string{testRegion}) {
		t.Errorf("%v", names(only.Relays))
	}
	// Providers without port forwarding have no usable entry in that mode.
	mdir := t.TempDir()
	m := NewRelayCatalog(mdir, "mullvad", false, clock(epoch))
	m.Refresh(fetchJSON(mullvadPayload(t, nil)))
	if NewRelayCatalog(mdir, "mullvad", true, clock(epoch)).Relays.Len() != 0 {
		t.Error("mullvad has no port forwarding")
	}
}

func TestPublishWithExtraMembersKeepsGluetunsOrder(t *testing.T) {
	dir := t.TempDir()
	c := NewRelayCatalog(dir, "gluetun-mullvad", false, clock(epoch))
	relays, _ := ReadGluetunCatalog(gluetunFixture(t), "mullvad", gluetunNow)
	entries := NewEntries()
	relays.Each(func(id string, r *Relay) bool { entries.Set(id, GluetunSnapshotEntry(r)); return true })
	if err := c.Publish(entries, validate.Members("source", "gluetun", "data_timestamp", "1970-01-01T00:15:00Z")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(c.Path)
	if !strings.HasPrefix(string(raw), `{"fetched_at": "2026-10-11T12:00:00Z", "provider": "gluetun-mullvad", "source": "gluetun", `+
		`"data_timestamp": "1970-01-01T00:15:00Z", "relays": {"mullvad-one.example.test": {`) {
		t.Errorf("%.220s", raw)
	}
	if c.Snapshot["data_timestamp"] != "1970-01-01T00:15:00Z" || c.Snapshot["source"] != "gluetun" {
		t.Errorf("%v", c.Snapshot)
	}
	back := NewRelayCatalog(dir, "gluetun-mullvad", false, clock(epoch))
	if back.Relays.Len() != 2 || !back.Usable() {
		t.Errorf("read back %d relays", back.Relays.Len())
	}
	r, _ := back.Relays.Get("mullvad-one.example.test")
	original, _ := entries.Get("mullvad-one.example.test")
	if !sameJSON(t, r, original) {
		t.Errorf("round trip: %s", mustMarshal(r))
	}
}
