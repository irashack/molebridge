package panel

// The state behind the Switchyard screenshots in docs/assets. The capture
// script (tools/screenshots/capture.js) runs this test, then serves each
// scene with the real panel binary:
//
//	MOLEBRIDGE_SCREENSHOT_STATE=/tmp/shots go test ./internal/panel -run TestWriteScreenshotState
//
// Every value is fictitious: documentation addresses, all-zero keys, server
// names in each provider's public naming pattern. The records are the test
// fixtures' schema2, so they follow the schema the tests check. Nothing here
// is asserted on.

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// shotCity is a place in the screenshot catalogues; lat and lon give the
// made-up latencies a believable shape.
type shotCity struct {
	country, city string
	lat, lon      float64
}

var shotPlaces = map[string]shotCity{
	"sto": {"Sweden", "Stockholm", 59.33, 18.07}, "got": {"Sweden", "Gothenburg", 57.71, 11.97},
	"chi": {"USA", "Chicago, IL", 41.88, -87.63}, "nyc": {"USA", "New York, NY", 40.71, -74.01},
	"dal": {"USA", "Dallas, TX", 32.78, -96.80}, "tor": {"Canada", "Toronto", 43.65, -79.38},
	"zrh": {"Switzerland", "Zurich", 47.37, 8.54}, "tyo": {"Japan", "Tokyo", 35.68, 139.69},
	"fra": {"Germany", "Frankfurt", 50.11, 8.68}, "lon": {"UK", "London", 51.51, -0.13},
	"ams": {"Netherlands", "Amsterdam", 52.37, 4.90}, "sea": {"USA", "Seattle, WA", 47.61, -122.33},
	"atl": {"USA", "Atlanta, GA", 33.75, -84.39},
}

// The countries as each provider's list names them.
var shotCountry = map[string]map[string]string{
	"pia":     {"USA": "United States", "UK": "United Kingdom"},
	"nordvpn": {"USA": "United States", "UK": "United Kingdom"},
	"surf":    {"USA": "United States", "UK": "United Kingdom"},
}

var shotCode = map[string]string{"Sweden": "se", "USA": "us", "Canada": "ca", "Switzerland": "ch", "Japan": "jp",
	"Germany": "de", "UK": "gb", "Netherlands": "nl"}

func shotCountryOf(style, country string) string {
	if named, ok := shotCountry[style][country]; ok {
		return named
	}
	return country
}

// shotCityName drops Mullvad's state suffix for the providers whose lists
// have none.
func shotCityName(c shotCity) string {
	city, _, _ := strings.Cut(c.city, ",")
	return city
}

type shotRelay struct {
	host, place string
	entry       map[string]any
}

// mullvadShots: Mullvad's names, cc-city-wg-NNN, in six countries so the
// list fits the screenshot; the gluetun copy has the
// same names and gluetun's members.
func mullvadShots(gluetun bool) []shotRelay {
	counts := []struct {
		place string
		n     int
	}{{"sto", 4}, {"got", 2}, {"chi", 3}, {"nyc", 3}, {"dal", 2}, {"tor", 2}, {"zrh", 2}, {"tyo", 2},
		{"fra", 3}}
	var out []shotRelay
	ip := 10
	for _, c := range counts {
		p := shotPlaces[c.place]
		code := shotCode[p.country]
		for i := 1; i <= c.n; i++ {
			host := code + "-" + c.place + fmt.Sprintf("-wg-%03d", i)
			addr := "198.51.100." + strconv.Itoa(ip)
			if gluetun {
				addr = "192.0.2." + strconv.Itoa(ip)
			}
			ip++
			var entry map[string]any
			if gluetun {
				entry = map[string]any{"id": host, "hostname": host, "public_key": validPubkey, "ipv4_addr_in": addr,
					"ipv6_addrs": []any{}, "city": p.city, "country": p.country, "selection_filter": "hostnames"}
			} else {
				entry = map[string]any{"hostname": host, "country": p.country, "city": p.city,
					"location_code": code + "-" + c.place, "public_key": validPubkey, "ipv4_addr_in": addr,
					"owned": i%2 == 1, "stboot": true}
			}
			out = append(out, shotRelay{host, c.place, entry})
		}
	}
	return out
}

// piaShots: PIA's region ids, each with one WireGuard server.
func piaShots() []shotRelay {
	regions := []struct{ id, place, cn string }{
		{"us_chicago", "chi", "chicago412"}, {"us_atlanta", "atl", "atlanta407"}, {"us_seattle", "sea", "seattle405"},
		{"us_texas", "dal", "dallas409"}, {"ca_toronto", "tor", "toronto411"}, {"uk", "lon", "london418"},
		{"de-frankfurt", "fra", "frankfurt403"}, {"nl_amsterdam", "ams", "amsterdam415"}, {"swiss", "zrh", "zurich402"},
		{"sweden", "sto", "stockholm404"}, {"japan", "tyo", "japan406"},
	}
	var out []shotRelay
	for i, r := range regions {
		p := shotPlaces[r.place]
		code := shotCode[p.country]
		addr := "198.51.100." + strconv.Itoa(100+i)
		city := shotCityName(p)
		if r.id == "us_texas" {
			city = "Texas"
		}
		out = append(out, shotRelay{r.id, r.place, map[string]any{"hostname": r.id,
			"country": shotCountryOf("pia", p.country), "city": city, "location_code": code + "-" + r.id,
			"ipv4_addr_in": addr, "port_forward": code != "us", "geo": false,
			"servers": []any{map[string]any{"ip": addr, "cn": r.cn}}}})
	}
	return out
}

// nordShots: NordVPN's ccNNNN.nordvpn.com names.
func nordShots() []shotRelay {
	sets := []struct {
		place, code, slug string
		first, n          int
	}{{"dal", "us", "dallas", 9001, 3}, {"chi", "us", "chicago", 9012, 3}, {"nyc", "us", "new-york", 9024, 3},
		{"tor", "ca", "toronto", 1601, 2}, {"lon", "uk", "london", 2201, 3}, {"fra", "de", "frankfurt", 1101, 3},
		{"ams", "nl", "amsterdam", 1001, 3}, {"sto", "se", "stockholm", 701, 2}, {"tyo", "jp", "tokyo", 801, 2}}
	var out []shotRelay
	ip := 150
	for _, s := range sets {
		p := shotPlaces[s.place]
		country := shotCode[p.country]
		for i := 0; i < s.n; i++ {
			host := s.code + strconv.Itoa(s.first+i) + ".nordvpn.com"
			out = append(out, shotRelay{host, s.place, map[string]any{"hostname": host, "public_key": validPubkey,
				"ipv4_addr_in": "198.51.100." + strconv.Itoa(ip), "city": shotCityName(p),
				"country": shotCountryOf("nordvpn", p.country), "country_code": strings.ToUpper(country),
				"location_code": country + "-" + s.slug, "load": (ip*7)%55 + 6, "virtual": false}})
			ip++
		}
	}
	return out
}

// surfsharkShots: Surfshark's cc-city.prod.surfshark.com names, as gluetun
// lists them.
func surfsharkShots() []shotRelay {
	sets := []struct{ name, place string }{{"us-chi", "chi"}, {"us-nyc", "nyc"}, {"us-dal", "dal"}, {"ca-tor", "tor"},
		{"uk-lon", "lon"}, {"de-fra", "fra"}, {"nl-ams", "ams"}, {"se-sto", "sto"}, {"ch-zur", "zrh"}, {"jp-tok", "tyo"}}
	var out []shotRelay
	for i, s := range sets {
		p := shotPlaces[s.place]
		host := s.name + ".prod.surfshark.com"
		out = append(out, shotRelay{host, s.place, map[string]any{"id": host, "hostname": host, "public_key": validPubkey,
			"ipv4_addr_in": "192.0.2." + strconv.Itoa(200+i), "ipv6_addrs": []any{}, "city": shotCityName(p),
			"country": shotCountryOf("surf", p.country), "selection_filter": "hostnames"}})
	}
	return out
}

// shotLatency is a believable round trip in ms from one place to another:
// a few ms locally, about 1 ms per 70 km beyond, with a small spread per
// server so a city's servers differ.
func shotLatency(from, to string, host string) float64 {
	a, b := shotPlaces[from], shotPlaces[to]
	rad := math.Pi / 180
	d := 2 * 6371 * math.Asin(math.Sqrt(math.Pow(math.Sin((b.lat-a.lat)*rad/2), 2)+
		math.Cos(a.lat*rad)*math.Cos(b.lat*rad)*math.Pow(math.Sin((b.lon-a.lon)*rad/2), 2)))
	spread := 0
	for _, c := range host {
		spread = (spread*31 + int(c)) % 7
	}
	return math.Round((4+d/70+float64(spread))*10) / 10
}

// shotExit is one exit of a scene.
type shotExit struct {
	id, provider, kind string
	relays             []shotRelay
	server             string
	egress             string
	configured         bool
}

func TestWriteScreenshotState(t *testing.T) {
	out := os.Getenv("MOLEBRIDGE_SCREENSHOT_STATE")
	if out == "" {
		t.Skip("MOLEBRIDGE_SCREENSHOT_STATE is not set")
	}
	// Checked a minute ago: inside StatusMaxAge while the scenes are taken.
	at := time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05Z")
	mullvad, gluetunMullvad := mullvadShots(false), mullvadShots(true)
	pia, nord, surf := piaShots(), nordShots(), surfsharkShots()
	scenes := map[string]struct {
		env   map[string]string
		exits []shotExit
	}{
		// docs/assets/switchyard.png: four exits, Mullvad open.
		"switchyard": {map[string]string{"PANEL_EXITS": "mullvad=mullvad, pia=pia, nordvpn=nordvpn, surfshark=gluetun-surfshark"},
			[]shotExit{
				{"mullvad", "mullvad", "overlay", mullvad, "us-chi-wg-001", "203.0.113.7", false},
				{"pia", "pia", "overlay", pia, "us_chicago", "203.0.113.42", false},
				{"nordvpn", "nordvpn", "overlay", nord, "us9001.nordvpn.com", "203.0.113.65", false},
				{"surfshark", "gluetun-surfshark", "overlay", surf, "us-chi.prod.surfshark.com", "203.0.113.118", false},
			}},
		// docs/assets/switchyard-gluetun.png: Mullvad through gluetun open.
		"switchyard-gluetun": {map[string]string{"PANEL_EXITS": "mullvad=mullvad, mullvad-gluetun=gluetun-mullvad, surfshark=gluetun-surfshark"},
			[]shotExit{
				{"mullvad", "mullvad", "overlay", mullvad, "us-chi-wg-001", "203.0.113.7", false},
				{"mullvad-gluetun", "gluetun-mullvad", "overlay", gluetunMullvad, "se-sto-wg-003", "203.0.113.29", false},
				{"surfshark", "gluetun-surfshark", "overlay", surf, "us-chi.prod.surfshark.com", "203.0.113.118", false},
			}},
		// docs/assets/switchyard-configured.png: one NordVPN exit pinned by SERVER.
		"switchyard-configured": {map[string]string{"PROVIDER": "nordvpn"},
			[]shotExit{{"", "nordvpn", "overlay", nord, "us9001.nordvpn.com", "203.0.113.65", true}}},
	}
	for name, scene := range scenes {
		dir := filepath.Join(out, name)
		latency := map[string]any{}
		for _, e := range scene.exits {
			base := dir
			if e.id != "" {
				base = filepath.Join(dir, e.id)
			}
			ex := ExitUnder(e.id, e.provider, "", base, e.kind)
			relays := map[string]any{}
			ms := map[string]any{}
			var from string
			var current map[string]any
			for _, r := range e.relays {
				if r.host == e.server {
					from, current = r.place, r.entry
				}
			}
			for _, r := range e.relays {
				relays[r.host] = r.entry
				ms[r.host] = shotLatency(from, r.place, r.host)
			}
			latency[e.id] = ms
			snapshot := map[string]any{"fetched_at": at, "provider": e.provider, "relays": relays}
			if e.provider == "gluetun-mullvad" || e.provider == "gluetun-surfshark" {
				snapshot["source"], snapshot["data_timestamp"] = "gluetun", at
			}
			mustWrite(t, ex.RelaysPath, snapshot)
			opts := recOpts{Provider: e.provider, Kind: e.kind, Server: e.server, At: at,
				Extra: map[string]any{"egress_ip": e.egress, "egress_ips": map[string]any{"4": e.egress},
					"egress_city": current["city"], "egress_country": current["country"]}}
			if e.configured {
				opts.Configured, opts.Source = e.server, "configured"
				opts.Extra["request_id"], opts.Extra["requested_server"] = nil, nil
			} else {
				mustWrite(t, ex.DesiredPath, request(e.server, requestID, at))
			}
			mustWrite(t, ex.ResultPath, schema2(opts))
		}
		env := map[string]string{"STATE_DIR": dir}
		for k, v := range scene.env {
			env[k] = v
		}
		raw, err := json.MarshalIndent(map[string]any{"env": env, "latency": latency}, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "scene.json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
