package relayproxy

import (
	"errors"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/providers"
)

// SocksPort is the port of Mullvad's relay proxies.
const SocksPort = 1080

// SocksDomain is the domain under which Mullvad names its relay proxies.
const SocksDomain = "relays.mullvad.net"

// resultMaxBytes bounds result.json, as its other readers do.
const resultMaxBytes = 16384

// The location refusals. They never carry the location.
var (
	ErrLocation = errors.New("relayproxy: invalid location")
	ErrNoServer = errors.New("relayproxy: no server for the location")
)

// mullvadRelayRE is a relay name the proxy name can be derived from: a
// country, a city, "wg" and a three-digit number. It is narrower than the
// catalogue's own pattern on purpose: a name outside it has no known proxy.
var mullvadRelayRE = regexp.MustCompile(`^([a-z]{2}-[a-z0-9]{2,12})-wg-([0-9]{3})$`)

// locationCodeRE is a catalogue location code: a country code, '-', and the
// city's code (for PIA the region id, which may hold '_' and '-').
var locationCodeRE = regexp.MustCompile(`^[a-z]{2}-[a-z0-9][a-z0-9_-]*$`)

// MullvadSocksName is the proxy host of a Mullvad WireGuard relay:
// "se-got-wg-001" becomes "se-got-wg-socks5-001.relays.mullvad.net". It is
// false for a name the derivation does not apply to.
func MullvadSocksName(relay string) (string, bool) {
	m := mullvadRelayRE.FindStringSubmatch(relay)
	if m == nil {
		return "", false
	}
	return m[1] + "-wg-socks5-" + m[2] + "." + SocksDomain, true
}

// server is one catalogue entry the proxy can use.
type server struct {
	name    string // the catalogue's name, such as "se-got-wg-001"
	city    string // the location code, lowercased: "se-got"
	country string // the code before it: "se"
	socks   string // Mullvad: the relay proxy's host name
}

// serverFrom is the catalogue entry as a server, or false when its location
// code is not one (or, for Mullvad, it has no derivable proxy).
func serverFrom(provider, name string, r *providers.Relay) (server, bool) {
	city := strings.ToLower(r.LocationCode)
	if len(city) > 64 || !locationCodeRE.MatchString(city) {
		return server{}, false
	}
	s := server{name: strings.ToLower(name), city: city, country: city[:2]}
	if provider == "mullvad" {
		socks, ok := MullvadSocksName(s.name)
		if !ok || !strings.HasPrefix(s.name, city+"-") {
			return server{}, false
		}
		s.socks = socks
	}
	return s, true
}

// catalog is the validated snapshot as servers, sorted by name, and the file
// identity it was read at.
type catalog struct {
	servers []server
	byName  map[string]int
	modTime time.Time
	size    int64
	loaded  bool
}

// loadCatalog reads the snapshot through providers.ReadSnapshot and
// providers.SnapshotRelays, so its validation is the catalogue's. A missing or
// invalid file is an empty catalogue.
func loadCatalog(path, provider string) catalog {
	c := catalog{byName: map[string]int{}, loaded: true}
	if info, err := os.Lstat(path); err == nil {
		c.modTime, c.size = info.ModTime(), info.Size()
	}
	entries := providers.SnapshotRelays(providers.ReadSnapshot(path, provider), provider)
	entries.Each(func(name string, r *providers.Relay) bool {
		if s, ok := serverFrom(provider, name, r); ok {
			if _, dup := c.byName[s.name]; !dup {
				c.byName[s.name] = len(c.servers)
				c.servers = append(c.servers, s)
			}
		}
		return true
	})
	sort.Slice(c.servers, func(i, j int) bool { return c.servers[i].name < c.servers[j].name })
	for i, s := range c.servers {
		c.byName[s.name] = i
	}
	return c
}

// stale reports whether the file at path is no longer the one c was read
// from.
func (c *catalog) stale(path string) bool {
	if !c.loaded {
		return true
	}
	info, err := os.Lstat(path)
	if err != nil {
		return !c.modTime.IsZero() || c.size != 0
	}
	return !info.ModTime().Equal(c.modTime) || info.Size() != c.size
}

// location is a parsed location: "any", a country ("se"), a city ("se-got")
// or a server name ("se-got-wg-001", a PIA region id, a NordVPN host name),
// which only the catalogue tells apart.
type location struct {
	any   bool
	value string
}

var locationRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// parseLocation checks a location and lowercases it (ASCII only, checked
// first, so no other character can fold into a match).
func parseLocation(text string) (location, error) {
	if !locationRE.MatchString(text) {
		return location{}, ErrLocation
	}
	text = strings.ToLower(text)
	if text == "any" {
		return location{any: true}, nil
	}
	return location{value: text}, nil
}

// matches reports whether s is in the location: every server for "any", the
// country's for a country code, the server itself for its name, and the
// city's for a location code.
func (l location) matches(s server) bool {
	return l.any || s.name == l.value || s.city == l.value || s.country == l.value
}

// currentServer is the exit's current server from its result.json, when it
// is a valid name for the provider, else "".
func currentServer(path, provider string) string {
	record, ok := jsonfile.ReadObject(path, resultMaxBytes)
	if !ok {
		return ""
	}
	p, ok := providers.Lookup(provider)
	if !ok || !p.ValidServerName(record["server"]) {
		return ""
	}
	return record["server"].(string)
}
