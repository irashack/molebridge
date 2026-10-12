package providers

import (
	"errors"
	"strings"
	"sync"
)

// The registry: everything Molebridge knows per VPN provider, in one place.
// The applier, the panel and the setup helpers read it; nothing else keeps a
// per-provider table.
//
// Each provider's own file (mullvad.go, pia.go, nordvpn.go) parses its server
// list. The applier names its implementation of each provider elsewhere (the
// Python registry held a module path here; the Go registry holds no behavior
// that needs the applier). Adding a provider means a parser file and an entry
// below; docs/providers.md#adding-a-provider lists what each must do.
//
// The gluetun backend adds one entry per provider gluetun can select exactly
// (gluetun_catalog.go), with the id `gluetun-<gluetun's provider id>`: gluetun
// owns that tunnel and its server list, and the applier talks to gluetun's
// control server. Native entries are unaffected.

// Egress tiers, strongest first. "provider": the provider's own endpoint says
// the request arrived over its VPN. "tunnel": independent IP echo services
// through the tunnel agree on an address that is not the host's own, and it
// matches the selected server where the catalogue lists exit addresses.
const (
	TierProvider = "provider"
	TierTunnel   = "tunnel"
)

// Tiers lists the egress tiers, strongest first.
var Tiers = []string{TierProvider, TierTunnel}

// DefaultCatalogBytes is the default download cap, and the bound on reading a
// validated snapshot back.
const DefaultCatalogBytes = 10 * 1024 * 1024

// Backends.
const (
	BackendNative  = "native"
	BackendGluetun = "gluetun"
)

// Filter is a catalogue attribute the panel offers as a filter when it narrows
// the list.
type Filter struct {
	Attribute string
	Label     string
}

// Badge is shown on a server when the attribute is true.
type Badge struct {
	Attribute string
	Text      string
	Title     string
}

// Provider is one registry entry.
type Provider struct {
	ID    string
	Label string
	// ServerNamePattern is the pattern of a selectable name (a relay hostname
	// or a region id), as Python wrote it. The panel's script uses the same
	// text; ValidServerName is the check in Go.
	ServerNamePattern string
	serverName        func(string) bool
	CatalogURL        string
	// ParseCatalog parses the raw response body into {name: entry}; it returns
	// an error so the last good catalogue is kept.
	ParseCatalog func(raw []byte, portForwardOnly bool) (*Entries, error)
	// ValidateEntry validates a snapshot entry re-read from disk; nil if bad.
	ValidateEntry func(entry any) *Relay
	// AddressBeforeSwitch: one tunnel address valid on every server, set before
	// any switch (and present in the tunnel config), as opposed to an address
	// assigned per server.
	AddressBeforeSwitch bool
	// EgressTier is the strongest egress confirmation the provider supports.
	EgressTier string
	// IPv6: whether the tunnel can carry IPv6. Without it, forwarded IPv6
	// always hits the exit table's unreachable fallback.
	IPv6            bool
	CatalogMaxBytes int
	CatalogTimeoutS int
	// SnapshotMaxBytes bounds the validated snapshot (state/applier/
	// relays.json): the applier refuses to write a larger one, keeping the
	// last good catalogue, and the applier and panel refuse to read one.
	SnapshotMaxBytes int
	// SecretFiles are the account files the applier reads, relative to the
	// checkout (mode 0600).
	SecretFiles []string
	// Layout is the panel presentation: "tree" (country, city, server) or
	// "regions" (a flat list).
	Layout string
	// Filters are offered only when they narrow the list.
	Filters []Filter
	Badges  []Badge
	// ThemeColors are the (dark, light) browser chrome colours for the style.
	ThemeColors [2]string
	// ChipLabel is the short name on a server's button, Details a one-line
	// summary of the server.
	ChipLabel func(hostname string) string
	Details   func(info *Relay) string
	// Backend is "native" (Molebridge's own WireGuard container) or "gluetun"
	// (gluetun owns the tunnel), as GluetunProvider.
	Backend         string
	GluetunProvider string
	// Note is shown with the label in the panel, e.g. "via gluetun".
	Note string
	// EgressCheck is the native provider whose typed egress check this entry
	// reuses, or "" for the tunnel checks alone.
	EgressCheck string
	// Style: the panel styles an entry as this provider (its CSS data-provider);
	// empty means its own id.
	Style string
	// Accent: a provider whose colour the panel uses as the accent on that
	// style (its CSS data-accent), as gluetun's entries do; empty for none.
	Accent string
	// RegistrationLapses: the provider can forget a registration while the peer
	// stays the same (PIA): a handshake stale for 180 s or more then
	// re-registers the same server through the admission pipeline (decision D15).
	RegistrationLapses bool
}

// CSSID is the id the panel styles the entry as.
func (p *Provider) CSSID() string {
	if p.Style != "" {
		return p.Style
	}
	return p.ID
}

// ValidServerName reports whether value is a selectable name for this provider.
func (p *Provider) ValidServerName(value any) bool {
	s, ok := value.(string)
	return ok && p.serverName(s)
}

var (
	mu       sync.RWMutex
	registry map[string]*Provider
	order    []string
)

func defaultText(hostname string) string { return hostname }
func noDetails(*Relay) string            { return "" }

func init() {
	registry = map[string]*Provider{}
	add := func(p *Provider) {
		registry[p.ID] = p
		order = append(order, p.ID)
	}
	mullvad := &Provider{
		ID: "mullvad", Label: "Mullvad", ServerNamePattern: MullvadHostnamePattern,
		serverName: mullvadHostnameRE.MatchString,
		CatalogURL: MullvadRelaysURL, ParseCatalog: ParseMullvadCatalog, ValidateEntry: ValidateMullvadEntry,
		AddressBeforeSwitch: true, EgressTier: TierProvider, IPv6: true,
		CatalogMaxBytes: DefaultCatalogBytes, CatalogTimeoutS: 20, SnapshotMaxBytes: DefaultCatalogBytes,
		Layout:      "tree",
		Filters:     []Filter{{"owned", "Mullvad-owned"}, {"stboot", "RAM-only"}},
		ThemeColors: [2]string{"#192e45", "#e9eef3"}, ChipLabel: MullvadChipLabel, Details: MullvadDetails,
		Backend: BackendNative,
	}
	pia := &Provider{
		ID: "pia", Label: "PIA", ServerNamePattern: PIARegionPattern, serverName: piaRegionRE.MatchString,
		CatalogURL: PIAServerlistURL, ParseCatalog: ParsePIACatalog, ValidateEntry: ValidatePIAEntry,
		AddressBeforeSwitch: false, EgressTier: TierProvider, IPv6: false,
		CatalogMaxBytes: DefaultCatalogBytes, CatalogTimeoutS: 20, SnapshotMaxBytes: DefaultCatalogBytes,
		SecretFiles: []string{"secrets/pia/username", "secrets/pia/password"},
		Layout:      "regions", Filters: []Filter{{"port_forward", "Port forwarding"}}, RegistrationLapses: true,
		Badges:      []Badge{{"port_forward", "PF", "Port forwarding"}, {"geo", "virtual", "Virtual location"}},
		ThemeColors: [2]string{"#1c1e22", "#f2f4f5"}, Details: PIADetails, ChipLabel: defaultText,
		Backend: BackendNative,
	}
	nord := &Provider{
		ID: "nordvpn", Label: "NordVPN", ServerNamePattern: NordHostnamePattern, serverName: nordHostnameRE.MatchString,
		CatalogURL: NordServersURL, ParseCatalog: ParseNordCatalogBody, ValidateEntry: ValidateNordEntry,
		AddressBeforeSwitch: true, EgressTier: TierProvider, IPv6: false,
		CatalogMaxBytes: NordMaxCatalogBytes, CatalogTimeoutS: 60,
		// About 1.5 MB in 2026; long location names, escaped, can inflate it.
		SnapshotMaxBytes: nordSnapshotMaxBytes,
		Layout:           "tree",
		Badges:           []Badge{{"virtual", "virtual", "Virtual location"}},
		ThemeColors:      [2]string{"#161b26", "#eef2f8"}, ChipLabel: NordChipLabel, Details: NordDetails,
		Backend: BackendNative,
	}
	for _, p := range []*Provider{mullvad, pia, nord} {
		add(p)
	}
	// Native egress checks carry over to the same provider through gluetun. The
	// panel styles every gluetun entry as gluetun, with the provider's colour as
	// the accent.
	for _, name := range GluetunSupportedProviders {
		native := registry[name]
		ipv6 := false
		if native != nil {
			ipv6 = native.IPv6
		}
		tier, check := TierTunnel, ""
		if name == "mullvad" || name == "nordvpn" {
			tier, check = TierProvider, name
		}
		add(&Provider{
			ID: "gluetun-" + name, Label: GluetunLabels[name], ServerNamePattern: GluetunServerNamePattern,
			serverName: func(s string) bool { return ValidGluetunHostname(s) },
			CatalogURL: "", ParseCatalog: ParseGluetunUnavailable, ValidateEntry: ValidateGluetunEntry,
			// gluetun sets its own tunnel address; a switch may leave the
			// interface without one while gluetun restarts its tunnel.
			AddressBeforeSwitch: false, EgressTier: tier, IPv6: ipv6,
			CatalogMaxBytes: GluetunMaxCatalogBytes, CatalogTimeoutS: 20, SnapshotMaxBytes: 16 * 1024 * 1024,
			SecretFiles: []string{"secrets/gluetun/api_key"},
			Layout:      "tree",
			ThemeColors: [2]string{"#11181c", "#edf2f4"},
			ChipLabel:   GluetunChipLabel, Details: GluetunDetails,
			Backend: BackendGluetun, GluetunProvider: name, Note: "via gluetun",
			EgressCheck: check, Style: "gluetun", Accent: name,
		})
	}
}

// IDs lists the provider ids in registry order: the native providers, then
// the gluetun entries.
func IDs() []string {
	mu.RLock()
	defer mu.RUnlock()
	return append([]string(nil), order...)
}

// Lookup returns the entry for id.
func Lookup(id string) (*Provider, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[id]
	return p, ok
}

func unknownProviderError() error {
	return errors.New("PROVIDER must be one of: " + strings.Join(IDs(), ", "))
}

// Get returns the entry for id, or an error naming the valid ones.
func Get(id string) (*Provider, error) {
	if p, ok := Lookup(id); ok {
		return p, nil
	}
	return nil, unknownProviderError()
}

// FromEnv is the provider the PROVIDER setting selects; unset or empty means
// "mullvad". getenv has os.Getenv's signature.
func FromEnv(getenv func(string) string) (*Provider, error) {
	id := getenv("PROVIDER")
	if id == "" {
		id = "mullvad"
	}
	return Get(id)
}

// Native lists the ids of the providers Molebridge's own WireGuard container
// serves.
func Native() []string {
	var out []string
	for _, id := range IDs() {
		if p, _ := Lookup(id); p.Backend == BackendNative {
			out = append(out, id)
		}
	}
	return out
}

// Replace puts p in the registry under p.ID and returns a function that
// restores what was there. It exists for tests and for trial providers; a
// replaced id keeps its position, a new one goes last.
func Replace(p *Provider) (restore func()) {
	mu.Lock()
	defer mu.Unlock()
	previous, existed := registry[p.ID]
	registry[p.ID] = p
	if !existed {
		order = append(order, p.ID)
	}
	return func() {
		mu.Lock()
		defer mu.Unlock()
		if existed {
			registry[p.ID] = previous
			return
		}
		delete(registry, p.ID)
		for j, id := range order {
			if id == p.ID {
				order = append(order[:j], order[j+1:]...)
				break
			}
		}
	}
}

// Clone returns a copy of the entry that may be changed and passed to Replace.
func (p *Provider) Clone() *Provider {
	c := *p
	return &c
}

// Clone returns a copy of the registry's entry for id, for tests and trials
// that register a variant with Replace. It panics for an unknown id.
func Clone(id string) *Provider {
	p, err := Get(id)
	if err != nil {
		panic(err)
	}
	return p.Clone()
}

// SetServerName replaces the server-name check of a (cloned) entry.
func (p *Provider) SetServerName(pattern string, valid func(string) bool) {
	p.ServerNamePattern, p.serverName = pattern, valid
}
