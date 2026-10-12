package providers

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/irashack/molebridge/internal/validate"
)

// NordVPN catalogue and egress parsing.
//
// NordVPN's server list and its egress check are untrusted input, like
// Mullvad's relay list. This file only parses; it fetches nothing and touches
// no tunnel. The caller keeps its last good catalogue when a parse returns an
// error.
//
// NordLynx server keys belong to a location, not a server, so many servers
// share one key. A server is therefore identified by the endpoint address of
// the live peer (ServerForEndpoint), never by its key.

// The v2 list, filtered server-side to WireGuard servers. The brackets are
// percent-encoded so curl needs no `-g`. The filtered response is about 8 MB.
const (
	NordServersURL       = "https://api.nordvpn.com/v2/servers?limit=0&filters%5Bservers_technologies%5D%5Bidentifier%5D=wireguard_udp"
	NordMaxCatalogBytes  = 32 * 1024 * 1024
	NordAddress          = "10.5.0.2/32" // every NordLynx server shares one tunnel address
	NordPort             = 51820         // and one port
	NordInsightsURL      = "https://api.nordvpn.com/v1/helpers/ips/insights"
	NordHostnamePattern  = `[a-z]{2}(-[a-z]{2})?[0-9]{1,5}\.nordvpn\.com`
	nordMaxServers       = 50000
	nordMaxTable         = 10000
	nordTextMax          = 256
	nordWireguard        = "wireguard_udp"
	nordVPNService       = "vpn"
	nordUnknown          = "Unknown"
	nordStandardGroup    = "legacy_standard"
	nordSnapshotMaxBytes = 16 * 1024 * 1024
)

var (
	nordHostnameRE     = regexp.MustCompile(`^(?:` + NordHostnamePattern + `)$`)
	nordCountryCodeRE  = regexp.MustCompile(`^[A-Z]{2}$`)
	nordLocationCodeRE = regexp.MustCompile(`^[a-z]{2}-[a-z0-9]+(?:-[a-z0-9]+)*$`)
	nordSlugRE         = regexp.MustCompile(`[^a-z0-9]+`)
)

// NordGroupTitles maps NordVPN's server group identifiers (in NordVPN's API,
// which the native catalogue reads) to their titles (which gluetun stores as
// the server's categories, internal/provider/nordvpn/updater/models.go at
// v3.41.3). A server must be in the standard group and in none of the
// excluded ones: dedicated IP servers need their own purchase, and the
// others need other connection settings.
var NordGroupTitles = map[string]string{
	"legacy_standard": "Standard VPN servers", "legacy_dedicated_ip": "Dedicated IP",
	"legacy_double_vpn": "Double VPN", "legacy_onion_over_vpn": "Onion Over VPN",
	"legacy_obfuscated_servers": "Obfuscated Servers"}

// NordExcludedGroups are the identifiers that rule a server out.
var NordExcludedGroups = []string{"legacy_dedicated_ip", "legacy_double_vpn", "legacy_onion_over_vpn",
	"legacy_obfuscated_servers"}

// NordStandardTitle is the title of the standard group; NordExcludedTitles
// are the titles of the excluded ones.
var (
	NordStandardTitle  = NordGroupTitles[nordStandardGroup]
	NordExcludedTitles = func() map[string]bool {
		out := map[string]bool{}
		for _, g := range NordExcludedGroups {
			out[NordGroupTitles[g]] = true
		}
		return out
	}()
)

// SelectableByTitles is the native rule on gluetun's category titles.
func SelectableByTitles(titles []string) bool {
	standard := false
	for _, title := range titles {
		if title == NordStandardTitle {
			standard = true
		}
		if NordExcludedTitles[title] {
			return false
		}
	}
	return standard
}

// cleanText: non-empty text of at most 256 characters with no control or
// surrogate characters.
func cleanText(v any) bool {
	s, ok := v.(string)
	if !ok || len(s) == 0 || len(s) > nordTextMax*4 {
		return false
	}
	n := 0
	for len(s) > 0 {
		r, size := validate.NextRune(s)
		if validate.IsSurrogate(r) || unicode.In(r, unicode.Cc, unicode.Zl, unicode.Zp) {
			return false
		}
		s = s[size:]
		n++
	}
	return n <= nordTextMax
}

// idMap is {id: valid(row)} for well-formed rows. An id that appears twice is
// ambiguous, so it resolves to nothing.
func idMap[T any](rows []any, valid func(map[string]any) (T, bool)) map[int64]T {
	result := map[int64]T{}
	ambiguous := map[int64]bool{}
	for _, raw := range rows {
		row, ok := asObject(raw)
		if !ok {
			continue
		}
		id, ok := validate.IsInt(row["id"])
		if !ok {
			continue
		}
		value, ok := valid(row)
		if !ok {
			continue
		}
		if _, seen := result[id]; seen {
			ambiguous[id] = true
		}
		result[id] = value
	}
	for id := range ambiguous {
		delete(result, id)
	}
	return result
}

func identifierOf(row map[string]any) (string, bool) {
	if cleanText(row["identifier"]) {
		return row["identifier"].(string), true
	}
	return "", false
}

type nordLocation struct{ country, countryCode, city string }

func locationOf(row map[string]any) (nordLocation, bool) {
	country, ok := asObject(row["country"])
	if !ok {
		return nordLocation{}, false
	}
	city, ok := asObject(country["city"])
	if !ok || !cleanText(country["name"]) || !cleanText(city["name"]) {
		return nordLocation{}, false
	}
	code, ok := country["code"].(string)
	if !ok || !nordCountryCodeRE.MatchString(code) {
		return nordLocation{}, false
	}
	return nordLocation{country["name"].(string), code, city["name"].(string)}, true
}

func intList(v any) ([]int64, bool) {
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]int64, len(list))
	for i, item := range list {
		n, ok := validate.IsInt(item)
		if !ok {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}

// pyLower is Python's str.lower() for what slug needs: Go's ToLower except for
// U+0130, which Python lowers to "i" and a combining dot.
func pyLower(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "İ", "i̇"))
}

func slug(text string) string {
	return strings.Trim(nordSlugRE.ReplaceAllString(pyLower(text), "-"), "-")
}

// entryAddress is the server's single IPv4 entry address. IPv6 rows are
// ignored.
func entryAddress(ips any) (string, bool) {
	list, ok := ips.([]any)
	if !ok {
		return "", false
	}
	var found []string
	for _, raw := range list {
		row, ok := asObject(raw)
		if !ok || row["type"] != "entry" {
			continue
		}
		address, ok := asObject(row["ip"])
		if !ok {
			return "", false
		}
		version, ok := validate.IsInt(address["version"])
		if !ok {
			return "", false
		}
		if version != 4 {
			continue
		}
		if !validate.ValidIPv4(address["ip"]) {
			return "", false
		}
		found = append(found, address["ip"].(string))
	}
	if len(found) != 1 {
		return "", false
	}
	return found[0], true
}

// wireguardKey is the public key of the server's one online WireGuard
// technology row.
func wireguardKey(technologies any, wireguardIDs map[int64]bool) (string, bool) {
	list, ok := technologies.([]any)
	if !ok {
		return "", false
	}
	var rows []map[string]any
	for _, raw := range list {
		row, ok := asObject(raw)
		if !ok {
			continue
		}
		if id, ok := validate.IsInt(row["id"]); ok && wireguardIDs[id] {
			rows = append(rows, row)
		}
	}
	if len(rows) != 1 || rows[0]["status"] != "online" {
		return "", false
	}
	metadata, ok := rows[0]["metadata"].([]any)
	if !ok {
		return "", false
	}
	var keys []any
	for _, raw := range metadata {
		if m, ok := asObject(raw); ok && m["name"] == "public_key" {
			keys = append(keys, m["value"])
		}
	}
	if len(keys) == 1 && validate.ValidKey(keys[0]) {
		return keys[0].(string), true
	}
	return "", false
}

func isVirtual(specifications any) bool {
	list, ok := specifications.([]any)
	if !ok {
		return false
	}
	for _, raw := range list {
		spec, ok := asObject(raw)
		if !ok || spec["identifier"] != "virtual_location" {
			continue
		}
		values, ok := spec["values"].([]any)
		if !ok {
			continue
		}
		for _, v := range values {
			if m, ok := asObject(v); ok && m["value"] == "true" {
				return true
			}
		}
		return false
	}
	return false
}

type nordTables struct {
	groups, services map[int64]string
	locations        map[int64]nordLocation
	wireguardIDs     map[int64]bool
}

func parseNordServer(raw any, t nordTables) *Relay {
	server, ok := asObject(raw)
	if !ok || server["status"] != "online" {
		return nil
	}
	host, ok := server["hostname"].(string)
	if !ok || !nordHostnameRE.MatchString(host) {
		return nil
	}
	groupIDs, ok1 := intList(server["group_ids"])
	serviceIDs, ok2 := intList(server["service_ids"])
	locationIDs, ok3 := intList(server["location_ids"])
	if !ok1 || !ok2 || !ok3 {
		return nil
	}
	vpn := false
	for _, id := range serviceIDs {
		if name, known := t.services[id]; known && name == nordVPNService {
			vpn = true
		}
	}
	if !vpn {
		return nil
	}
	standard := false
	for _, id := range groupIDs {
		name, known := t.groups[id]
		if !known {
			continue
		}
		if name == nordStandardGroup {
			standard = true
		}
		for _, excluded := range NordExcludedGroups {
			if name == excluded {
				return nil
			}
		}
	}
	if !standard {
		return nil
	}
	if len(locationIDs) != 1 {
		return nil
	}
	location, known := t.locations[locationIDs[0]]
	if !known {
		return nil
	}
	key, ok := wireguardKey(server["technologies"], t.wireguardIDs)
	address, ok2b := entryAddress(server["ips"])
	// The station is what a switch connects to; it must agree with the entry IP.
	if !ok || !ok2b || server["station"] != address {
		return nil
	}
	code := slug(location.city)
	if code == "" {
		return nil
	}
	relay := &Relay{Shape: ShapeNordVPN, Hostname: host, PublicKey: key, IPv4AddrIn: address,
		City: location.city, Country: location.country, CountryCode: location.countryCode,
		LocationCode: strings.ToLower(location.countryCode) + "-" + code}
	if load, ok := validate.IsInt(server["load"]); ok && 0 <= load && load <= 100 {
		relay.Load = &load
	}
	relay.Virtual = isVirtual(server["specifications"])
	return relay
}

// ParseNordCatalog reads the decoded `GET /v2/servers` response.
//
// It returns an error for a malformed document, a duplicate hostname or an
// empty result; the caller then keeps its last good catalogue.
func ParseNordCatalog(data any) (*Entries, error) {
	top, ok := asObject(data)
	if !ok {
		return nil, errors.New("catalogue is not an object")
	}
	lists := map[string][]any{}
	for _, k := range []string{"servers", "groups", "services", "locations", "technologies"} {
		list, ok := top[k].([]any)
		if !ok {
			return nil, errors.New("catalogue is missing a list")
		}
		lists[k] = list
	}
	if len(lists["servers"]) > nordMaxServers {
		return nil, errors.New("catalogue is too large")
	}
	for _, k := range []string{"groups", "services", "locations", "technologies"} {
		if len(lists[k]) > nordMaxTable {
			return nil, errors.New("catalogue is too large")
		}
	}
	tables := nordTables{
		groups:       idMap(lists["groups"], identifierOf),
		services:     idMap(lists["services"], identifierOf),
		locations:    idMap(lists["locations"], locationOf),
		wireguardIDs: map[int64]bool{},
	}
	for id, name := range idMap(lists["technologies"], identifierOf) {
		if name == nordWireguard {
			tables.wireguardIDs[id] = true
		}
	}
	entries := NewEntries()
	for _, server := range lists["servers"] {
		if relay := parseNordServer(server, tables); relay != nil {
			if entries.Has(relay.Hostname) {
				return nil, errors.New("duplicate relay hostname")
			}
			entries.Set(relay.Hostname, relay)
		}
	}
	if entries.Len() == 0 {
		return nil, errors.New("no usable servers")
	}
	return entries, nil
}

// ParseNordCatalogBody parses the raw response body. NordVPN has no port
// forwarding.
func ParseNordCatalogBody(raw []byte, portForwardOnly bool) (*Entries, error) {
	data, err := validate.DecodeJSON(raw)
	if err != nil {
		return nil, err
	}
	return ParseNordCatalog(data)
}

// ValidateNordEntry checks a relay as stored in the snapshot (what
// parseNordServer produced), or returns nil.
func ValidateNordEntry(entry any) *Relay {
	m, ok := asObject(entry)
	if !ok {
		return nil
	}
	host, ok := m["hostname"].(string)
	if !ok || !nordHostnameRE.MatchString(host) {
		return nil
	}
	if !validate.ValidKey(m["public_key"]) || !validate.ValidIPv4(m["ipv4_addr_in"]) {
		return nil
	}
	if !cleanText(m["city"]) || !cleanText(m["country"]) {
		return nil
	}
	countryCode, ok := m["country_code"].(string)
	if !ok || !nordCountryCodeRE.MatchString(countryCode) {
		return nil
	}
	code, ok := m["location_code"].(string)
	if !ok || validate.RuneCount(code) > nordTextMax || !nordLocationCodeRE.MatchString(code) {
		return nil
	}
	virtual, ok := m["virtual"].(bool)
	if !ok {
		return nil
	}
	relay := &Relay{Shape: ShapeNordVPN, Hostname: host, PublicKey: m["public_key"].(string),
		IPv4AddrIn: m["ipv4_addr_in"].(string), City: m["city"].(string), Country: m["country"].(string),
		CountryCode: countryCode, LocationCode: code, Virtual: virtual}
	if load, ok := validate.IsInt(m["load"]); ok && 0 <= load && load <= 100 {
		relay.Load = &load
	}
	return relay
}

// NordChipLabel is the short chip label: "us9001.nordvpn.com" -> "us9001".
func NordChipLabel(hostname string) string {
	label, _, _ := strings.Cut(hostname, ".")
	return label
}

// NordDetails is "virtual location · load 12%" where the catalogue says so.
func NordDetails(info *Relay) string {
	var parts []string
	if info.Virtual {
		parts = append(parts, "virtual location")
	}
	if info.Load != nil {
		parts = append(parts, "load "+strconv.FormatInt(*info.Load, 10)+"%")
	}
	return strings.Join(parts, " · ")
}

// ServerForEndpoint is the hostname of the one relay whose address and port
// are the live peer endpoint ("ip:port", as `wg show <interface> endpoints`
// prints it), or "" and false.
func ServerForEndpoint(relays *Entries, endpoint string) (string, bool) {
	cut := strings.LastIndex(endpoint, ":")
	address, port := "", endpoint
	if cut >= 0 {
		address, port = endpoint[:cut], endpoint[cut+1:]
	} else {
		port = ""
	}
	if port != strconv.Itoa(NordPort) || !validate.ValidIPv4(address) {
		return "", false
	}
	var matches []string
	relays.Each(func(name string, relay *Relay) bool {
		if relay.IPv4AddrIn == address {
			matches = append(matches, name)
		}
		return true
	})
	if len(matches) != 1 {
		return "", false
	}
	return matches[0], true
}

// Insights is the egress detail NordVPN's `ips/insights` call reports; a nil
// city or country is one NordVPN has no data on ("Unknown").
type Insights struct {
	EgressIP      string
	EgressCity    *string
	EgressCountry *string
	ExitConfirmed bool
}

// JSONObject implements validate.ObjectMarshaler.
func (i Insights) JSONObject() validate.Obj {
	return validate.Members("egress_ip", i.EgressIP, "egress_city", i.EgressCity,
		"egress_country", i.EgressCountry, "exit_confirmed", i.ExitConfirmed)
}

func insightText(value any) (*string, error) {
	if s, ok := value.(string); ok && s == nordUnknown {
		return nil, nil
	}
	if !cleanText(value) {
		return nil, errors.New("invalid egress text")
	}
	s := value.(string)
	return &s, nil
}

// ParseInsights reads the decoded `ips/insights` response.
//
// NordVPN answers with "Unknown" strings and mistyped numbers for an address
// it has no data on; only the fields used here are checked.
func ParseInsights(data any) (Insights, error) {
	m, ok := asObject(data)
	if !ok {
		return Insights{}, errors.New("egress response is not an object")
	}
	protected, isBool := m["protected"].(bool)
	if !isBool || !validate.ValidIPv4(m["ip"]) {
		return Insights{}, errors.New("invalid egress response")
	}
	city, err := insightText(m["city"])
	if err != nil {
		return Insights{}, err
	}
	country, err := insightText(m["country"])
	if err != nil {
		return Insights{}, err
	}
	// Checked like the others; the panel has no use for it.
	if _, err := insightText(m["country_code"]); err != nil {
		return Insights{}, err
	}
	return Insights{EgressIP: m["ip"].(string), EgressCity: city, EgressCountry: country, ExitConfirmed: protected}, nil
}
