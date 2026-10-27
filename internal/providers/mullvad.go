package providers

import (
	"errors"
	"regexp"
	"strings"

	"github.com/irashack/molebridge/internal/validate"
)

// Mullvad's relay list: one entry per relay, each with the WireGuard key and
// endpoint a switch applies.

// MullvadRelaysURL is where the relay list comes from.
const MullvadRelaysURL = "https://api.mullvad.net/app/v1/relays"

// MullvadHostnamePattern is the pattern of a Mullvad relay name, as Python
// wrote it (the panel's script uses the same text).
const MullvadHostnamePattern = `[a-z0-9-]{1,40}-wg-[0-9]{3}`

var mullvadHostnameRE = regexp.MustCompile(`^(?:` + MullvadHostnamePattern + `)$`)

// MullvadOptionalFlags are the display attributes a relay may carry: owned
// means Mullvad-owned hardware, stboot that the relay runs from RAM.
var MullvadOptionalFlags = []string{"owned", "stboot"}

func asObject(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// ValidateMullvadEntry checks a relay as stored in the snapshot (decoded JSON)
// and returns it, or nil.
func ValidateMullvadEntry(entry any) *Relay {
	m, ok := asObject(entry)
	if !ok {
		return nil
	}
	host, ok := m["hostname"].(string)
	if !ok || !mullvadHostnameRE.MatchString(host) {
		return nil
	}
	if !validate.ValidKey(m["public_key"]) || !validate.ValidPublicIPv4(m["ipv4_addr_in"]) {
		return nil
	}
	for _, k := range []string{"city", "country", "location_code"} {
		if !validate.ValidText(m[k]) {
			return nil
		}
	}
	r := &Relay{Shape: ShapeMullvad, Hostname: host, PublicKey: m["public_key"].(string),
		IPv4AddrIn: m["ipv4_addr_in"].(string), City: m["city"].(string), Country: m["country"].(string),
		LocationCode: m["location_code"].(string)}
	// Optional display attributes: kept only when well formed, never required.
	if v, ok := m["owned"].(bool); ok {
		r.Owned = &v
	}
	if v, ok := m["stboot"].(bool); ok {
		r.Stboot = &v
	}
	if validate.ValidText(m["provider"]) && validate.RuneCount(m["provider"].(string)) <= 64 {
		r.HostingProvider = m["provider"].(string)
	}
	return r
}

// ParseMullvadResponse reads the decoded relay list. A relay that is not
// active, has no known location or fails validation is skipped; a repeated
// hostname is an error.
func ParseMullvadResponse(data any) (*Entries, error) {
	top, ok := asObject(data)
	if !ok {
		return nil, errors.New("missing locations map")
	}
	locations, ok := asObject(top["locations"])
	if !ok {
		return nil, errors.New("missing locations map")
	}
	wireguard, ok := asObject(top["wireguard"])
	var relays []any
	if ok {
		relays, ok = wireguard["relays"].([]any)
	}
	if !ok {
		return nil, errors.New("missing wireguard relays")
	}
	entries := NewEntries()
	for _, raw := range relays {
		relay, ok := asObject(raw)
		if !ok || relay["active"] != true {
			continue
		}
		code, ok := relay["location"].(string)
		if !ok {
			continue
		}
		loc, ok := asObject(locations[code])
		if !ok {
			continue
		}
		merged := make(map[string]any, len(relay)+3)
		for k, v := range relay {
			merged[k] = v
		}
		merged["city"], merged["country"], merged["location_code"] = loc["city"], loc["country"], code
		if entry := ValidateMullvadEntry(merged); entry != nil {
			if entries.Has(entry.Hostname) {
				return nil, errors.New("duplicate relay hostname")
			}
			entries.Set(entry.Hostname, entry)
		}
	}
	return entries, nil
}

// ParseMullvadCatalog parses the raw response body.
func ParseMullvadCatalog(raw []byte, portForwardOnly bool) (*Entries, error) {
	data, err := validate.DecodeJSON(raw)
	if err != nil {
		return nil, err
	}
	return ParseMullvadResponse(data)
}

// MullvadChipLabel is the short chip label: "se-sto-wg-001" -> "wg-001".
func MullvadChipLabel(hostname string) string {
	if marker := strings.LastIndex(hostname, "-wg-"); marker >= 0 {
		return hostname[marker+1:]
	}
	return hostname
}

// MullvadDetails is the hosting summary, such as
// "Example Hosting · rented · RAM-only".
func MullvadDetails(info *Relay) string {
	var parts []string
	if info.HostingProvider != "" {
		parts = append(parts, info.HostingProvider)
	}
	if info.Owned != nil {
		if *info.Owned {
			parts = append(parts, "Mullvad-owned")
		} else {
			parts = append(parts, "rented")
		}
	}
	if info.Stboot != nil && *info.Stboot {
		parts = append(parts, "RAM-only")
	}
	return strings.Join(parts, " · ")
}
