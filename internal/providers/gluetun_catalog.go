package providers

import (
	"errors"
	"math"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/validate"
)

// Read gluetun v3.41.3's single-file catalogue without changing a snapshot.
//
// The parser is separate from file I/O so a later storage format can have its
// own reader. Callers retain their last good snapshot on error. `now` is Unix
// time in seconds; the returned timestamp belongs to the provider data, not to
// the time Molebridge read the file.

const (
	// GluetunMaxCatalogBytes bounds the file read.
	GluetunMaxCatalogBytes = 32 * 1024 * 1024
	gluetunMaxIPs          = 64
	gluetunMaxCategories   = 64
	// GluetunDataStaleSec: gluetun's data for a provider is dated when it last
	// changed. Older than this, the panel and the doctor call it stale.
	GluetunDataStaleSec = 30 * 24 * 60 * 60
)

const dnsNamePattern = `[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*`

// GluetunServerNamePattern is a hostname of at most 253 characters, as the
// pattern Python wrote (the panel's script uses the same text; it has a
// lookahead, which Go's regexp lacks, so ValidGluetunHostname checks it).
const GluetunServerNamePattern = `(?=.{1,253}$)` + dnsNamePattern

var (
	dnsNameRE  = regexp.MustCompile(`^(?:` + dnsNamePattern + `)$`)
	serverIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._#/-]{0,255}$`)
	// Servers an ordinary account key can use. gluetun lists every server its
	// updater finds, including ones a plain subscription can't connect to:
	//   - NordVPN: dedicated-IP, Double VPN, Onion Over VPN and obfuscated
	//     servers, told apart by their categories; the same rule as the native
	//     catalogue.
	//   - Surfshark: gluetun fetches its generic, double (multi-hop), static and
	//     obfuscated clusters into one list with nothing marking the kind. Only
	//     the generic (`xx-yyy.prod.surfshark.com`) and static-IP
	//     (`xx-yyy-st001...`) names, which every subscription can use, are kept.
	// Mullvad, IVPN, Windscribe and FastestVPN carry no such classes in
	// gluetun's WireGuard data.
	surfsharkSelectableRE = regexp.MustCompile(`^[a-z]{2}-[a-z]{2,4}(?:-st[0-9]{3})?\.prod\.surfshark\.com$`)
	endpointPortRE        = regexp.MustCompile(`^:[0-9]{1,5}$`)
	digitsRE              = regexp.MustCompile(`^[0-9]{1,5}$`)
)

// GluetunProviderKeys are the providers gluetun's file is read for, in the
// order of internal/constants/providers/providers.go:8-36. PIA's spaced key
// belongs to its OpenVPN storage; it is not a built-in WireGuard provider in
// this release.
var GluetunProviderKeys = []string{"airvpn", "custom", "fastestvpn", "ivpn", "mullvad", "nordvpn", "protonvpn",
	"surfshark", "windscribe"}

// gluetunSelection: (storage ID field, ServerSelection JSON filter). The
// storage ID must be unique across ALL WireGuard rows, even rows Molebridge
// cannot use: otherwise gluetun could pick a discarded row.
//
// AirVPN's public name generates TWO rows (IPv4 and IPv6) and its hostnames
// are regional. ProtonVPN names logical servers and hostnames physical
// servers; both fields repeat across its rows. Custom bypasses
// storage/filter.go entirely. For those three no single filter is exact.
var gluetunSelection = map[string][2]string{
	"airvpn": {"", ""}, "custom": {"", ""}, "fastestvpn": {"hostname", "hostnames"},
	"ivpn": {"hostname", "hostnames"}, "mullvad": {"hostname", "hostnames"},
	"nordvpn": {"hostname", "hostnames"}, "protonvpn": {"", ""},
	"surfshark": {"hostname", "hostnames"}, "windscribe": {"hostname", "hostnames"},
}

// GluetunSelection returns a provider's storage ID field and ServerSelection
// filter, empty for a provider with no exact single filter.
func GluetunSelection(provider string) (field, filter string) {
	s := gluetunSelection[provider]
	return s[0], s[1]
}

// GluetunSupportedProviders are the providers with an exact single filter, in
// gluetun's order.
var GluetunSupportedProviders = func() []string {
	var out []string
	for _, name := range GluetunProviderKeys {
		if gluetunSelection[name][0] != "" {
			out = append(out, name)
		}
	}
	return out
}()

// GluetunRejectedProviders says why a provider is refused.
var GluetunRejectedProviders = map[string]string{
	"airvpn":    "gluetun provider has no unique single-filter server identifier",
	"custom":    "gluetun custom provider does not support catalogue server selection",
	"protonvpn": "gluetun provider has no unique single-filter server identifier",
}

// GluetunLabels are the panel labels of the supported providers.
var GluetunLabels = map[string]string{"fastestvpn": "FastestVPN", "ivpn": "IVPN", "mullvad": "Mullvad",
	"nordvpn": "NordVPN", "surfshark": "Surfshark", "windscribe": "Windscribe"}

// The gluetun catalogue's errors. None carries any of the file's content.
var (
	ErrGluetunUnsupported = errors.New("unsupported gluetun provider")
	ErrGluetunClock       = errors.New("invalid catalogue clock")
	ErrGluetunFormat      = errors.New("invalid gluetun catalogue format")
	ErrGluetunBlock       = errors.New("invalid gluetun provider block")
	ErrGluetunTimestamp   = errors.New("invalid gluetun catalogue timestamp")
	ErrGluetunDuplicate   = errors.New("duplicate gluetun server identifier")
	ErrGluetunEmpty       = errors.New("gluetun catalogue is empty")
	ErrGluetunRead        = errors.New("cannot read gluetun catalogue")
	ErrGluetunNotDownload = errors.New("gluetun server lists are read from gluetun, not downloaded")
)

// GluetunSelectable reports whether an ordinary account key can use the
// server (see above).
func GluetunSelectable(provider string, entry map[string]any) bool {
	switch provider {
	case "nordvpn":
		list, ok := entry["categories"].([]any)
		if !ok {
			return false
		}
		titles := make([]string, 0, len(list))
		for _, v := range list {
			s, ok := v.(string)
			if !ok {
				return false
			}
			titles = append(titles, s)
		}
		return SelectableByTitles(titles)
	case "surfshark":
		host, _ := entry["hostname"].(string)
		return surfsharkSelectableRE.MatchString(host)
	}
	return true
}

// ValidGluetunHostname reports whether value is a DNS name of at most 253
// characters in the lower-case form gluetun's filters take.
func ValidGluetunHostname(value any) bool {
	s, ok := value.(string)
	return ok && len(s) <= 253 && dnsNameRE.MatchString(s)
}

// validGluetunServerID validates an exact ID filter, including its JSON value
// type.
func validGluetunServerID(value any, selectionFilter string) bool {
	switch selectionFilter {
	case "hostnames":
		return ValidGluetunHostname(value)
	case "names":
		s, ok := value.(string)
		return ok && serverIDRE.MatchString(s)
	case "numbers":
		n, ok := validate.IsInt(value)
		return ok && 0 < n && n <= 65535
	}
	return false
}

// gluetunText is gluetun's text check: a string of at most 256 characters, the
// empty string included, with no control, format or surrogate characters.
func gluetunText(value any) bool {
	s, ok := value.(string)
	if !ok || len(s) > 256*4 {
		return false
	}
	n := 0
	for len(s) > 0 {
		r, size := validate.NextRune(s)
		if validate.IsSurrogate(r) || unicode.In(r, unicode.Cc, unicode.Cf) {
			return false
		}
		s = s[size:]
		n++
	}
	return n <= 256
}

// casefold is Python's str.casefold: the full folding for the characters that
// have one, and the simple folding (the smallest member of the character's
// case orbit) for the rest.
func casefold(s string) string {
	var b strings.Builder
	for _, r := range s {
		if folded, ok := fullFolds[r]; ok {
			for _, f := range folded {
				b.WriteRune(foldOrbit(f))
			}
			continue
		}
		b.WriteRune(foldOrbit(r))
	}
	return b.String()
}

func foldOrbit(r rune) rune {
	least := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < least {
			least = f
		}
	}
	return least
}

func gluetunRelay(entry map[string]any) *Relay {
	key, ok := entry["wgpubkey"].(string)
	if !ok || len(key) != 44 || !validate.ValidKey(key) {
		return nil
	}
	// These fields have omitempty in internal/models/server.go:16-18.
	var country, city any = "", ""
	if v, ok := entry["country"]; ok {
		country = v
	}
	if v, ok := entry["city"]; ok {
		city = v
	}
	if !gluetunText(country) || !gluetunText(city) {
		return nil
	}
	ips, ok := entry["ips"].([]any)
	if !ok || len(ips) == 0 || len(ips) > gluetunMaxIPs {
		return nil
	}
	ipv4, ipv6 := []string{}, []string{}
	for _, raw := range ips {
		value, ok := raw.(string)
		if !ok || len(value) > 45 || strings.Contains(value, "%") {
			continue
		}
		address, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		found := &ipv4
		if address.Is6() {
			found = &ipv6
		}
		text := address.String()
		seen := false
		for _, f := range *found {
			seen = seen || f == text
		}
		if !seen {
			*found = append(*found, text)
		}
	}
	if len(ipv4) == 0 {
		return nil
	}
	// gluetun makes a connection candidate of every address of a selected
	// server and picks one at random (internal/provider/utils/connection.go),
	// so every address is kept for identifying the live peer. IPv4AddrIn, the
	// first, is the latency probe's target.
	relay := &Relay{Shape: ShapeGluetun, Hostname: entry["hostname"].(string), PublicKey: key,
		IPv4AddrIn: ipv4[0], IPv4Addrs: ipv4, IPv6Addrs: ipv6, City: city.(string), Country: country.(string)}
	if region, ok := entry["region"]; ok {
		if !gluetunText(region) {
			return nil
		}
		r := region.(string)
		relay.Region = &r
	}
	if categories, ok := entry["categories"]; ok {
		list, ok := gluetunTextList(categories)
		if !ok {
			return nil
		}
		relay.Categories = list
	}
	return relay
}

func gluetunTextList(value any) ([]string, bool) {
	list, ok := value.([]any)
	if !ok || len(list) > gluetunMaxCategories {
		return nil, false
	}
	out := make([]string, len(list))
	for i, v := range list {
		if !gluetunText(v) {
			return nil, false
		}
		out[i] = v.(string)
	}
	return out, true
}

// ParseGluetunCatalog validates the v3.41.3 storage object and returns the
// supported provider's relays (keyed by server id) and the provider data's
// own timestamp. now is the Unix time in seconds the timestamp must not pass.
func ParseGluetunCatalog(data any, provider string, now float64) (*Entries, int64, error) {
	known := false
	for _, k := range GluetunProviderKeys {
		known = known || k == provider
	}
	if !known {
		return nil, 0, ErrGluetunUnsupported
	}
	if message, rejected := GluetunRejectedProviders[provider]; rejected {
		return nil, 0, errors.New(message)
	}
	idField, selectionFilter := GluetunSelection(provider)
	if now < 0 || math.IsNaN(now) || math.IsInf(now, 0) {
		return nil, 0, ErrGluetunClock
	}
	top, ok := asObject(data)
	if v, isInt := validate.IsInt(top["version"]); !ok || !isInt || v != 1 {
		return nil, 0, ErrGluetunFormat
	}
	block, ok := asObject(top[provider])
	var servers []any
	if ok {
		version, isInt := validate.IsInt(block["version"])
		servers, ok = block["servers"].([]any)
		ok = ok && isInt && 0 <= version && version <= 65535
	}
	if !ok {
		return nil, 0, ErrGluetunBlock
	}
	timestamp, isInt := validate.IsInt(block["timestamp"])
	if !isInt || timestamp < 0 || float64(timestamp) > now {
		return nil, 0, ErrGluetunTimestamp
	}
	relays := NewEntries()
	seen := map[any]bool{}
	for _, raw := range servers {
		entry, ok := asObject(raw)
		if !ok || entry["vpn"] != "wireguard" {
			continue
		}
		serverID := entry[idField]
		// Count candidates before checking credentials, endpoint families or
		// hostname syntax. An uppercase or otherwise unusable row can still
		// match the same case-insensitive gluetun filter as a usable row.
		var token any
		if s, isString := serverID.(string); isString && len(s) <= 256*4 && validate.RuneCount(s) <= 256 {
			token = casefold(s)
		} else if n, isInt := validate.IsInt(serverID); isInt && selectionFilter == "numbers" {
			token = n
		} else {
			continue
		}
		if seen[token] {
			return nil, 0, ErrGluetunDuplicate
		}
		seen[token] = true
		if !validGluetunServerID(serverID, selectionFilter) || !ValidGluetunHostname(entry["hostname"]) {
			continue
		}
		relay := gluetunRelay(entry)
		if relay != nil && GluetunSelectable(provider, entry) {
			id := serverID.(string)
			relay.ID, relay.SelectionFilter = id, selectionFilter
			relays.Set(id, relay)
		}
	}
	if relays.Len() == 0 {
		return nil, 0, ErrGluetunEmpty
	}
	return relays, timestamp, nil
}

// ReadGluetunSnapshot reads gluetun's file and returns (relays, timestamp),
// refusing incomplete writes and unsafe files. The error is fixed text for
// anything wrong with the file itself, since JSON and OS errors can contain
// untrusted data or paths.
func ReadGluetunSnapshot(path, provider string, now float64) (*Entries, int64, error) {
	data, ok := jsonfile.ReadOK(path, GluetunMaxCatalogBytes)
	if !ok {
		return nil, 0, ErrGluetunRead
	}
	return ParseGluetunCatalog(data, provider, now)
}

// ReadGluetunCatalog is ReadGluetunSnapshot without the timestamp.
func ReadGluetunCatalog(path, provider string, now float64) (*Entries, error) {
	relays, _, err := ReadGluetunSnapshot(path, provider, now)
	return relays, err
}

// EndpointAddress is the canonical address of a WireGuard endpoint as
// `wg show endpoints` prints it ("198.51.100.1:51820", "[2001:db8::1]:51820")
// or a bare address, or "" and false.
func EndpointAddress(endpoint string) (string, bool) {
	if len(endpoint) == 0 || len(endpoint) > 64 {
		return "", false
	}
	var address, port string
	switch {
	case strings.HasPrefix(endpoint, "["):
		inside, rest, found := strings.Cut(endpoint[1:], "]")
		if !found || (rest != "" && !endpointPortRE.MatchString(rest)) {
			return "", false
		}
		address = inside
		if rest != "" {
			port = rest[1:]
		}
	case strings.Count(endpoint, ":") == 1:
		address, port, _ = strings.Cut(endpoint, ":")
		if !digitsRE.MatchString(port) {
			return "", false
		}
	default:
		address = endpoint
	}
	if port != "" {
		n, _ := strconv.Atoi(port)
		if n <= 0 || n >= 65536 {
			return "", false
		}
	}
	if strings.Contains(address, "%") {
		return "", false
	}
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		return "", false
	}
	if parsed.String() != strings.ToLower(address) || (strings.HasPrefix(endpoint, "[") && !parsed.Is6()) {
		return "", false
	}
	return parsed.String(), true
}

// RelayAddresses is every address of the server: its IPv4 addresses (or the
// one IPv4AddrIn) and its IPv6 addresses.
func RelayAddresses(relay *Relay) map[string]bool {
	out := map[string]bool{}
	if len(relay.IPv4Addrs) > 0 {
		for _, a := range relay.IPv4Addrs {
			out[a] = true
		}
	} else {
		out[relay.IPv4AddrIn] = true
	}
	for _, a := range relay.IPv6Addrs {
		out[a] = true
	}
	return out
}

// ServerForPeer resolves the live endpoint, IPv4 or IPv6, against every
// address of every server, then confirms the key, and returns the server's id.
//
// A key alone is insufficient: providers may share it across many servers. An
// address listed for more than one server stays unknown even if only one of
// them has the key.
func ServerForPeer(relays *Entries, publicKey, endpoint string) (string, bool) {
	if len(publicKey) != 44 || !validate.ValidKey(publicKey) {
		return "", false
	}
	address, ok := EndpointAddress(endpoint)
	if !ok {
		return "", false
	}
	var matches []*Relay
	relays.Each(func(_ string, relay *Relay) bool {
		if RelayAddresses(relay)[address] {
			matches = append(matches, relay)
		}
		return true
	})
	if len(matches) != 1 || matches[0].PublicKey != publicKey {
		return "", false
	}
	return matches[0].ID, true
}

// SearchSnapshotKeys are the members a gluetun snapshot entry may have.
var snapshotKeys = map[string]bool{"id": true, "hostname": true, "public_key": true, "ipv4_addr_in": true,
	"ipv4_addrs": true, "ipv6_addrs": true, "city": true, "country": true, "region": true, "categories": true,
	"selection_filter": true}

// GluetunSnapshotEntry is a reader relay as the applier publishes it. gluetun's
// Windscribe data names the country in `region` and has no `country`; the panel
// groups by country, so such an entry takes its region as its country.
func GluetunSnapshotEntry(relay *Relay) *Relay {
	entry := relay.Copy()
	if entry.Country == "" && entry.Region != nil && *entry.Region != "" {
		entry.Country = *entry.Region
		entry.Region = nil
	}
	return entry
}

func canonicalAddress(value any, version int) (string, bool) {
	s, ok := value.(string)
	if !ok || len(s) > 45 {
		return "", false
	}
	address, err := netip.ParseAddr(s)
	if err != nil || address.String() != s {
		return "", false
	}
	if (version == 4 && !address.Is4()) || (version == 6 && !address.Is6()) {
		return "", false
	}
	return s, true
}

func canonicalList(value any, version int, minLen int) ([]string, bool) {
	list, ok := value.([]any)
	if !ok || len(list) < minLen || len(list) > gluetunMaxIPs {
		return nil, false
	}
	out := make([]string, len(list))
	for i, v := range list {
		s, ok := canonicalAddress(v, version)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

// ValidateGluetunEntry checks a snapshot entry re-read from disk, or returns nil.
func ValidateGluetunEntry(entry any) *Relay {
	m, ok := asObject(entry)
	if !ok {
		return nil
	}
	for k := range m {
		if !snapshotKeys[k] {
			return nil
		}
	}
	if m["selection_filter"] != "hostnames" || m["id"] != m["hostname"] {
		return nil
	}
	key, isString := m["public_key"].(string)
	if !ValidGluetunHostname(m["hostname"]) || !isString || len(key) != 44 || !validate.ValidKey(key) {
		return nil
	}
	first, ok := canonicalAddress(m["ipv4_addr_in"], 4)
	if !ok {
		return nil
	}
	relay := &Relay{Shape: ShapeGluetun, Hostname: m["hostname"].(string), ID: m["id"].(string),
		SelectionFilter: "hostnames", PublicKey: key, IPv4AddrIn: first}
	if raw, present := m["ipv4_addrs"]; present {
		v4, ok := canonicalList(raw, 4, 1)
		if !ok || v4[0] != first {
			return nil
		}
		unique := map[string]bool{}
		for _, a := range v4 {
			unique[a] = true
		}
		if len(unique) != len(v4) {
			return nil
		}
		relay.IPv4Addrs = v4
	}
	v6, ok := canonicalList(m["ipv6_addrs"], 6, 0)
	if !ok {
		return nil
	}
	relay.IPv6Addrs = v6
	if !gluetunText(m["city"]) || !gluetunText(m["country"]) {
		return nil
	}
	relay.City, relay.Country = m["city"].(string), m["country"].(string)
	if raw, present := m["region"]; present {
		if !gluetunText(raw) {
			return nil
		}
		r := raw.(string)
		relay.Region = &r
	}
	if raw, present := m["categories"]; present {
		list, ok := gluetunTextList(raw)
		if !ok {
			return nil
		}
		relay.Categories = list
	}
	return relay
}

// ParseGluetunUnavailable is the registry placeholder: with gluetun the
// applier reads gluetun's own server list from disk and never downloads one.
func ParseGluetunUnavailable(raw []byte, portForwardOnly bool) (*Entries, error) {
	return nil, ErrGluetunNotDownload
}

// GluetunChipLabel is "relay.example.test" -> "relay".
func GluetunChipLabel(hostname string) string {
	label, _, _ := strings.Cut(hostname, ".")
	return label
}

// GluetunDetails joins the region and the categories with " · ".
func GluetunDetails(info *Relay) string {
	var parts []string
	if info.Region != nil && *info.Region != "" {
		parts = append(parts, *info.Region)
	}
	for _, c := range info.Categories {
		if c != "" {
			parts = append(parts, c)
		}
	}
	return strings.Join(parts, " · ")
}
