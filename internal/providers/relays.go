package providers

import (
	"errors"
	"path/filepath"
	"sort"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/validate"
)

// The applier owns the relay catalogue; the panel can only read its snapshot.
//
// Each provider's file parses its own server list; the registry says which.
// This file keeps the validated snapshot (state/applier/relays.json) and the
// last good one when a refresh fails. A Mullvad catalogue lists relays, each
// with the WireGuard key and endpoint a switch applies. A PIA catalogue lists
// regions, each with the WireGuard servers the applier may register its key
// on. A NordVPN catalogue lists servers like Mullvad's, but servers in one
// location share a key.

const (
	// CatalogMaxAge is how long a snapshot counts as fresh (seconds).
	CatalogMaxAge = 24 * 60 * 60
	// RefreshIntervalS is how often the applier refreshes the catalogue.
	RefreshIntervalS = 6 * 60 * 60
)

// RefreshFailedMessage is what relay-error.json says after a failed refresh.
const RefreshFailedMessage = "Relay refresh failed; retaining the last good catalogue."

// CatalogURL is the registry's download URL for a provider.
func CatalogURL(provider string) string {
	if p, ok := Lookup(provider); ok {
		return p.CatalogURL
	}
	return ""
}

// SnapshotLimit is the provider's snapshot size limit, shared by the writer
// and both readers.
func SnapshotLimit(provider string) int64 {
	if p, ok := Lookup(provider); ok {
		return int64(p.SnapshotMaxBytes)
	}
	return DefaultCatalogBytes
}

// ReadSnapshot reads state/applier/relays.json (or the panel's copy): the
// decoded object, or nil when the file is missing, unsafe, too large or not
// strict JSON.
func ReadSnapshot(path, provider string) map[string]any {
	m, _ := jsonfile.ReadObject(path, SnapshotLimit(provider))
	return m
}

// SnapshotTooLarge reports whether the entries alone provably serialise past
// limit: every key and text value costs at least its length plus quotes and
// punctuation. It stops counting as soon as the bound passes the limit.
func SnapshotTooLarge(entries *Entries, limit int64) bool {
	var total int64
	big := false
	entries.Each(func(name string, entry *Relay) bool {
		total += int64(validate.RuneCount(name)) + 4
		for _, pair := range entry.JSONObject() {
			total += int64(validate.RuneCount(pair.Key)) + 4
			if s, ok := pair.Value.(string); ok {
				total += int64(validate.RuneCount(s))
			} else {
				total++
			}
		}
		if total > limit {
			big = true
			return false
		}
		return true
	})
	return big
}

// ValidateEntry is the provider's snapshot-entry validation. An unknown
// provider has none, so nothing validates.
func ValidateEntry(entry any, provider string) *Relay {
	p, ok := Lookup(provider)
	if !ok {
		return nil
	}
	return p.ValidateEntry(entry)
}

// ParseCatalog parses a provider's raw response body.
func ParseCatalog(raw []byte, provider string, portForwardOnly bool) (*Entries, error) {
	p, err := Get(provider)
	if err != nil {
		return nil, err
	}
	return p.ParseCatalog(raw, portForwardOnly)
}

// SnapshotRelays is the validated entries of a decoded snapshot for this
// provider. A snapshot of another provider has no authority here; one written
// before providers existed (no "provider" member) is a Mullvad catalogue. An
// entry whose key is not its hostname is dropped. The entries come back sorted
// by name: the decoded object has no order, and every reader sorts.
func SnapshotRelays(snapshot any, provider string) *Entries {
	entries := NewEntries()
	m, ok := asObject(snapshot)
	if !ok {
		return entries
	}
	relays, ok := asObject(m["relays"])
	if !ok {
		return entries
	}
	stored, present := m["provider"]
	if !present {
		stored = "mullvad"
	}
	if stored != provider {
		return entries
	}
	names := make([]string, 0, len(relays))
	for name := range relays {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if entry := ValidateEntry(relays[name], provider); entry != nil && name == entry.Hostname {
			entries.Set(name, entry)
		}
	}
	return entries
}

// RelayCatalog is the applier's view of the snapshot directory: relays.json and
// relay-error.json.
type RelayCatalog struct {
	Path            string
	ErrorPath       string
	Provider        string
	PortForwardOnly bool
	// Snapshot holds the snapshot's members other than the relays
	// ("fetched_at", "provider", and for gluetun "source" and
	// "data_timestamp"); empty when there is none.
	Snapshot map[string]any
	Relays   *Entries
	// Now is the clock; time.Now when nil.
	Now func() time.Time
	// Failure is why the last Refresh failed, nil after a success. It is
	// for the log: its text names a step or a file (netx's errors carry no
	// URL, the parsers' none of the input), never what was downloaded.
	Failure error
}

// NewRelayCatalog reads the snapshot in directory, if there is a valid one.
func NewRelayCatalog(directory, provider string, portForwardOnly bool, now func() time.Time) *RelayCatalog {
	c := &RelayCatalog{Path: filepath.Join(directory, "relays.json"), ErrorPath: filepath.Join(directory, "relay-error.json"),
		Provider: provider, PortForwardOnly: portForwardOnly, Now: now}
	snapshot := ReadSnapshot(c.Path, provider)
	c.Snapshot = map[string]any{}
	for k, v := range snapshot {
		if k != "relays" {
			c.Snapshot[k] = v
		}
	}
	c.Relays = SnapshotRelays(snapshot, provider)
	if portForwardOnly {
		c.Relays = c.Relays.Filter(func(_ string, r *Relay) bool {
			value, present := r.Flag("port_forward")
			return present && value
		})
	}
	return c
}

func (c *RelayCatalog) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Usable reports whether there are relays and the snapshot is recent.
func (c *RelayCatalog) Usable() bool {
	return c.Relays.Len() > 0 && validate.Recent(c.Snapshot["fetched_at"], CatalogMaxAge, c.now())
}

// Publish writes entries as the snapshot (fetched now, with the extra members
// after "provider", before "relays") and, only once that has succeeded, makes
// them the catalogue and clears the error record. A snapshot that cannot be
// read back would leave the panel, and a restarted applier, with no
// catalogue, so one over the provider's size limit is refused and the last
// good one stays: early when the entries alone are provably too large, and
// otherwise while encoding, before the output passes the limit.
func (c *RelayCatalog) Publish(entries *Entries, extra validate.Obj) error {
	limit := SnapshotLimit(c.Provider)
	if SnapshotTooLarge(entries, limit) {
		return errors.New("relay snapshot exceeds its size limit")
	}
	fetchedAt := validate.FormatTime(c.now())
	snapshot := validate.Members("fetched_at", fetchedAt, "provider", c.Provider)
	snapshot = append(snapshot, extra...)
	snapshot = append(snapshot, validate.Pair{Key: "relays", Value: entries})
	if err := jsonfile.Write(c.Path, snapshot, jsonfile.Options{Public: true, MaxBytes: limit}); err != nil {
		return err
	}
	c.Snapshot = map[string]any{"fetched_at": fetchedAt, "provider": c.Provider}
	for _, p := range extra {
		c.Snapshot[p.Key] = p.Value
	}
	c.Relays = entries
	return jsonfile.Write(c.ErrorPath, validate.Obj{}, jsonfile.Options{Public: true})
}

// RecordFailure writes relay-error.json with message. It never carries remote
// data, addresses or error bodies.
func (c *RelayCatalog) RecordFailure(message string) error {
	return jsonfile.Write(c.ErrorPath, validate.Members("message", message, "checked_at", validate.FormatTime(c.now())),
		jsonfile.Options{Public: true})
}

// Refresh downloads (through fetch) and publishes the catalogue. It returns
// true on success. On any failure the last good catalogue stays and the error
// record says so; the returned error is only about writing that record.
func (c *RelayCatalog) Refresh(fetch func() ([]byte, error)) (bool, error) {
	entries, err := c.fetchEntries(fetch)
	if err == nil {
		err = c.Publish(entries, nil)
	}
	c.Failure = err
	if err != nil {
		return false, c.RecordFailure(RefreshFailedMessage)
	}
	return true, nil
}

func (c *RelayCatalog) fetchEntries(fetch func() ([]byte, error)) (*Entries, error) {
	raw, err := fetch()
	if err != nil {
		return nil, err
	}
	entries, err := ParseCatalog(raw, c.Provider, c.PortForwardOnly)
	if err != nil {
		return nil, err
	}
	if entries.Len() == 0 {
		return nil, errors.New("relay list is empty")
	}
	return entries, nil
}
