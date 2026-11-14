package applier

import (
	"path/filepath"
	"sort"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/validate"
)

// A selected server the provider retires would leave the exit refused until
// someone picks another. Instead the exit moves to another server in the same
// city, and says so in its record.
//
// Only a server this exit verified is moved: the exit remembers where that
// server was (city, country) while the catalogue still listed it. A name that
// was never verified here (a typing mistake in SERVER, a request for a server
// that never existed) stays refused, as before. With no other server in that
// city the request stays refused too. When the requested server is listed
// again, the exit returns to it.

// locationMaxBytes bounds location.json: three names and two flags.
const locationMaxBytes = 4096

// location is the last verified server and where it was, with the server that
// replaces it while the catalogue doesn't list it. The exit's own file
// (PrivateDir/location.json): the panel can't write it.
type location struct {
	Server, City, Country string
	// PortForward is true for a PIA region that forwards ports: its
	// replacement must too.
	PortForward bool
	Replacement string
}

func (l location) object() validate.Obj {
	return validate.Members("server", l.Server, "city", l.City, "country", l.Country,
		"port_forward", l.PortForward, "replacement", orNull(l.Replacement))
}

func (a *Applier) locationPath() string { return filepath.Join(a.privateDir, "location.json") }

// loadLocation reads location.json; anything malformed is no memory.
func (a *Applier) loadLocation() location {
	raw, _ := a.readJSON(a.locationPath(), locationMaxBytes).(map[string]any)
	server, _ := raw["server"].(string)
	city, _ := raw["city"].(string)
	country, _ := raw["country"].(string)
	if raw == nil || !a.spec.ValidServerName(server) || city == "" || country == "" ||
		validate.RuneCount(city) > ServerReportChars || validate.RuneCount(country) > ServerReportChars {
		return location{}
	}
	l := location{Server: server, City: city, Country: country}
	l.PortForward, _ = raw["port_forward"].(bool)
	if replacement, ok := raw["replacement"].(string); ok && a.spec.ValidServerName(replacement) && replacement != server {
		l.Replacement = replacement
	}
	return l
}

func (a *Applier) saveLocation(l location) error {
	if l == a.location {
		return nil
	}
	if err := jsonfile.Write(a.locationPath(), l.object(), jsonfile.Options{}); err != nil {
		return wrapIO(err)
	}
	a.location = l
	return nil
}

// verified records a verified server: where it is, for the day the provider
// retires it, then the provider's own bookkeeping. The replacement of a
// retired server is not remembered in its place, so the exit can return; a
// server someone then picks is.
func (a *Applier) verified(server string) error {
	if relay, ok := a.catalog.Relays().Get(server); ok && a.catalog.Usable() && relay.City != "" && relay.Country != "" &&
		!(a.target != nil && a.target.Replaces != "" && a.target.Server == server) {
		l := location{Server: server, City: relay.City, Country: relay.Country, PortForward: relay.PortForward}
		if l.Server != a.location.Server || l.City != a.location.City || l.Country != a.location.Country ||
			l.PortForward != a.location.PortForward || a.location.Replacement != "" {
			if err := a.saveLocation(l); err != nil {
				return err
			}
		}
	}
	return a.hooks.OnVerified(a, server)
}

// replacementFor is the server that stands in for a requested server the
// catalogue no longer lists, "" when the request stands as it is: listed,
// never verified here, or with no other server in its city. The choice is
// kept until it leaves the catalogue too or the requested server returns.
func (a *Applier) replacementFor(server string) string {
	l := a.location
	if server == "" || l.Server != server {
		return ""
	}
	if !a.catalog.Usable() {
		// Nothing can be judged without a fresh catalogue: the earlier
		// answer stands, and the gate holds every change meanwhile.
		return l.Replacement
	}
	relays := a.catalog.Relays()
	if relays.Has(server) {
		if l.Replacement != "" {
			a.log("applier: the requested server is in the catalogue again; returning to it")
			l.Replacement = ""
			a.keepLocation(l)
		}
		return ""
	}
	if l.Replacement != "" && relays.Has(l.Replacement) {
		return l.Replacement
	}
	var candidates []string
	for _, name := range relays.Names() {
		relay, _ := relays.Get(name)
		if name != server && relay.City == l.City && relay.Country == l.Country && (relay.PortForward || !l.PortForward) {
			candidates = append(candidates, name)
		}
	}
	previous := l.Replacement
	l.Replacement = nextAfter(candidates, server)
	if l.Replacement != previous {
		if l.Replacement == "" {
			a.log("applier: the requested server left the catalogue and its city has no other server; the request is refused")
		} else {
			a.log("applier: the requested server left the catalogue; moving to another server in the same city")
		}
		a.keepLocation(l)
	}
	return l.Replacement
}

// keepLocation saves the memory from where no error can be returned. A failed
// write is logged and the answer still used: the choice is a function of the
// catalogue, so the next pass makes the same one.
func (a *Applier) keepLocation(l location) {
	if err := a.saveLocation(l); err != nil {
		a.log("applier: the server's location could not be saved: " + truncateChars(err.Error(), IOFailureReportChars))
		a.location = l
	}
}

// nextAfter is the name following name in sorted order, wrapping to the
// first: the neighbour of the server that left, the same one on every pass.
func nextAfter(names []string, name string) string {
	if len(names) == 0 {
		return ""
	}
	sort.Strings(names)
	for _, candidate := range names {
		if candidate > name {
			return candidate
		}
	}
	return names[0]
}

// movedRecord is the record's "moved" member, nil when the target is the
// requested server itself.
func (a *Applier) movedRecord() any {
	if a.target == nil || a.target.Replaces == "" {
		return nil
	}
	return validate.Members("from", a.target.Replaces, "to", a.target.Server, "reason", "left-catalogue")
}
