package providers

import (
	"bytes"
	"errors"
	"regexp"
	"strings"

	"github.com/irashack/molebridge/internal/validate"
)

// PIA's region list: one entry per region, each with the WireGuard servers
// the applier may register its key on. PIA returns a server's key only from
// that authenticated registration. Untrusted input; this file only parses it.

// PIAServerlistURL serves the region list as JSON on its first line; a
// signature follows it.
const PIAServerlistURL = "https://serverlist.piaservers.net/vpninfo/servers/v6"

// PIARegionPattern is the pattern of a PIA region id, as Python wrote it.
const PIARegionPattern = `[a-z0-9][a-z0-9_-]{0,47}`

var (
	piaRegionRE  = regexp.MustCompile(`^(?:` + PIARegionPattern + `)$`)
	piaCountryRE = regexp.MustCompile(`^[A-Z]{2}$`)
	// The TLS name each server presents; the applier verifies it against PIA's CA.
	piaCNRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,62}$`)
)

// PIAMaxServers bounds the WireGuard servers kept per region.
const PIAMaxServers = 16

// PIANamePrefix: region names start with a country prefix ("US East"), except
// where PIA writes the whole country ("Morocco"). These prefixes differ from
// the code.
var PIANamePrefix = map[string]string{"GB": "UK"}

// PIACountryNames are the countries PIA lists only with a prefixed region name.
var PIACountryNames = map[string]string{"AU": "Australia", "CA": "Canada", "DE": "Germany", "ES": "Spain",
	"FI": "Finland", "FR": "France", "GB": "United Kingdom", "IL": "Israel",
	"IT": "Italy", "JP": "Japan", "NL": "Netherlands", "SE": "Sweden",
	"US": "United States"}

// ValidatePIAServers checks a region's server list (decoded JSON): one to
// PIAMaxServers objects with a canonical public IPv4 address
// (validate.ValidPublicIPv4) and a TLS name. It returns nil for anything
// else, so a region naming one private address is dropped whole.
func ValidatePIAServers(servers any) []Server {
	list, ok := servers.([]any)
	if !ok || len(list) == 0 || len(list) > PIAMaxServers {
		return nil
	}
	result := make([]Server, 0, len(list))
	for _, raw := range list {
		server, ok := asObject(raw)
		if !ok || !validate.ValidPublicIPv4(server["ip"]) {
			return nil
		}
		cn, ok := server["cn"].(string)
		if !ok || !piaCNRE.MatchString(cn) {
			return nil
		}
		result = append(result, Server{IP: server["ip"].(string), CN: cn})
	}
	return result
}

// ValidatePIAEntry checks a PIA region as stored in the snapshot. IPv4AddrIn
// is the latency target; switching uses only Servers.
func ValidatePIAEntry(entry any) *Relay {
	m, ok := asObject(entry)
	if !ok {
		return nil
	}
	name, ok := m["hostname"].(string)
	if !ok || !piaRegionRE.MatchString(name) {
		return nil
	}
	for _, k := range []string{"city", "country", "location_code"} {
		if !validate.ValidText(m[k]) {
			return nil
		}
	}
	if !validate.ValidPublicIPv4(m["ipv4_addr_in"]) {
		return nil
	}
	servers := ValidatePIAServers(m["servers"])
	portForward, ok1 := m["port_forward"].(bool)
	geo, ok2 := m["geo"].(bool)
	if servers == nil || !ok1 || !ok2 {
		return nil
	}
	return &Relay{Shape: ShapePIA, Hostname: name, City: m["city"].(string), Country: m["country"].(string),
		LocationCode: m["location_code"].(string), IPv4AddrIn: m["ipv4_addr_in"].(string),
		PortForward: portForward, Geo: geo, Servers: servers}
}

type piaRegion struct {
	id, country, name string
	portForward, geo  bool
	wg, meta          []Server
}

// piaNames gives (country name, place name) per region id, from PIA's display
// names.
func piaNames(regions []piaRegion) map[string][2]string {
	countries := map[string]string{}
	for k, v := range PIACountryNames {
		countries[k] = v
	}
	prefixOf := func(code string) string {
		if p, ok := PIANamePrefix[code]; ok {
			return p + " "
		}
		return code + " "
	}
	for _, region := range regions {
		code, name := region.country, region.name
		if !strings.HasPrefix(name, prefixOf(code)) {
			// An unprefixed name is the country itself; keep the shortest.
			if _, known := PIACountryNames[code]; !known {
				current, have := countries[code]
				limit := validate.RuneCount(name) + 1
				if have {
					limit = validate.RuneCount(current)
				}
				if validate.RuneCount(name) < limit {
					countries[code] = name
				}
			}
		}
	}
	names := map[string][2]string{}
	for _, region := range regions {
		code, name := region.country, region.name
		prefix := prefixOf(code)
		place := name
		if strings.HasPrefix(name, prefix) {
			place = name[len(prefix):]
		}
		country, ok := countries[code]
		if !ok {
			country = code
		}
		names[region.id] = [2]string{country, place}
	}
	return names
}

// ParsePIAResponse reads the decoded region list. Offline regions and regions
// that fail validation are skipped; with portForwardOnly, so are those
// without port forwarding. A repeated region id is an error.
func ParsePIAResponse(data any, portForwardOnly bool) (*Entries, error) {
	top, ok := asObject(data)
	var list []any
	if ok {
		list, ok = top["regions"].([]any)
	}
	if !ok {
		return nil, errors.New("missing regions list")
	}
	var regions []piaRegion
	for _, raw := range list {
		region, ok := asObject(raw)
		if !ok || region["offline"] != false {
			continue
		}
		id, ok := region["id"].(string)
		if !ok || !piaRegionRE.MatchString(id) {
			continue
		}
		country, ok := region["country"].(string)
		if !ok || !piaCountryRE.MatchString(country) {
			continue
		}
		if !validate.ValidText(region["name"]) || validate.RuneCount(region["name"].(string)) > 64 {
			continue
		}
		portForward, ok1 := region["port_forward"].(bool)
		geo, ok2 := region["geo"].(bool)
		if !ok1 || !ok2 {
			continue
		}
		if portForwardOnly && !portForward {
			continue
		}
		servers, _ := asObject(region["servers"])
		var wg, meta []Server
		if servers != nil {
			wg = ValidatePIAServers(servers["wg"])
			if _, isList := servers["meta"].([]any); isList {
				meta = ValidatePIAServers(servers["meta"])
			}
		}
		if wg == nil {
			continue
		}
		regions = append(regions, piaRegion{id: id, country: country, name: region["name"].(string),
			portForward: portForward, geo: geo, wg: wg, meta: meta})
	}
	names := piaNames(regions)
	entries := NewEntries()
	for _, region := range regions {
		name := names[region.id]
		// PIA's own tooling measures latency against the region's meta server.
		latency := region.wg
		if len(region.meta) > 0 {
			latency = region.meta
		}
		entry := ValidatePIAEntry(map[string]any{
			"hostname": region.id, "country": name[0], "city": name[1],
			"location_code": strings.ToLower(region.country) + "-" + region.id,
			"ipv4_addr_in":  latency[0].IP,
			"port_forward":  region.portForward, "geo": region.geo, "servers": serversJSON(region.wg)})
		if entry != nil {
			if entries.Has(entry.Hostname) {
				return nil, errors.New("duplicate region id")
			}
			entries.Set(entry.Hostname, entry)
		}
	}
	return entries, nil
}

func serversJSON(servers []Server) []any {
	out := make([]any, len(servers))
	for i, s := range servers {
		out[i] = map[string]any{"ip": s.IP, "cn": s.CN}
	}
	return out
}

// ParsePIACatalog parses the raw response body. Only its first line is JSON;
// the signature after it is not parsed.
func ParsePIACatalog(raw []byte, portForwardOnly bool) (*Entries, error) {
	if i := bytes.IndexByte(raw, '\n'); i >= 0 {
		raw = raw[:i]
	}
	data, err := validate.DecodeJSON(raw)
	if err != nil {
		return nil, err
	}
	return ParsePIAResponse(data, portForwardOnly)
}

// PIADetails is "port forwarding · virtual location" for the attributes the
// region has.
func PIADetails(info *Relay) string {
	var parts []string
	if info.PortForward {
		parts = append(parts, "port forwarding")
	}
	if info.Geo {
		parts = append(parts, "virtual location")
	}
	return strings.Join(parts, " · ")
}
