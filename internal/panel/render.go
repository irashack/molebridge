package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/irashack/molebridge/internal/countries"
	"github.com/irashack/molebridge/internal/panel/pystr"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
)

// Page rendering, ported from app.py. The HTML is built by hand with the
// escaping Python's html.escape does (pystr.Escape), so a page is the bytes
// the Python panel wrote for the same inputs, apart from the order in which
// the relay catalogue is walked (see the comment on sortedNames).

var esc = pystr.Escape

// staticTypes are the files /static/ serves, and their content types.
var staticTypes = []struct{ name, contentType string }{
	{"panel.css", "text/css; charset=utf-8"},
	{"panel.js", "text/javascript; charset=utf-8"},
	{"JetBrainsMono-Regular.woff2", "font/woff2"},
	{"apple-touch-icon.png", "image/png"},
	{"icon-192.png", "image/png"},
	{"icon-512.png", "image/png"},
}

// staticVersions is the first ten hex digits of each served file's SHA-256,
// the cache-busting ?v= of the page's links; "0" for a file that cannot be
// read.
func staticVersions(files fs.FS) map[string]string {
	versions := map[string]string{}
	for _, f := range staticTypes {
		raw, err := fs.ReadFile(files, f.name)
		if err != nil {
			versions[f.name] = "0"
			continue
		}
		sum := sha256.Sum256(raw)
		versions[f.name] = hex.EncodeToString(sum[:])[:10]
	}
	return versions
}

// fill substitutes «name» markers in a template. A marker without a value
// is a programming error.
func fill(template string, pairs ...string) string {
	var b strings.Builder
	rest := template
	for {
		open := strings.Index(rest, "«")
		if open < 0 {
			b.WriteString(rest)
			return b.String()
		}
		b.WriteString(rest[:open])
		rest = rest[open+len("«"):]
		closeAt := strings.Index(rest, "»")
		if closeAt < 0 {
			panic("panel: unterminated marker in template")
		}
		name := rest[:closeAt]
		rest = rest[closeAt+len("»"):]
		found := false
		for i := 0; i+1 < len(pairs); i += 2 {
			if pairs[i] == name {
				b.WriteString(pairs[i+1])
				found = true
				break
			}
		}
		if !found {
			panic("panel: template marker without a value: " + name)
		}
	}
}

// pyStr is str(value) for decoded JSON.
func pyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		if t == float64(int64(t)) && t < 1e16 && t > -1e16 {
			return strconv.FormatFloat(t, 'f', 1, 64)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	}
	return fmt.Sprint(v)
}

// orEmpty is `str(x or ”)` for decoded JSON: the empty string for anything
// falsy.
func orEmpty(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if !t {
			return ""
		}
	case int64:
		if t == 0 {
			return ""
		}
	case float64:
		if t == 0 {
			return ""
		}
	case map[string]any:
		if len(t) == 0 {
			return ""
		}
	case []any:
		if len(t) == 0 {
			return ""
		}
	}
	return pyStr(v)
}

// placeCode is the code a flag comes from: the catalogue's location code, or
// for a list that names countries only (gluetun's) the country's ISO code.
func placeCode(info *providers.Relay) string {
	if info.LocationCode != "" {
		return info.LocationCode
	}
	code, _ := countries.CodeFor(info.Country)
	return code
}

// flagEmoji is the regional-indicator flag of a location code such as
// "se-sto".
func flagEmoji(locationCode string) string {
	runes := []rune(locationCode)
	if len(runes) > 2 {
		runes = runes[:2]
	}
	code := []rune(strings.ToUpper(string(runes)))
	if len(code) != 2 {
		return ""
	}
	var b strings.Builder
	for _, c := range code {
		if c < 'A' || c > 'Z' {
			return ""
		}
		b.WriteRune(0x1F1E6 + c - 'A')
	}
	return b.String()
}

func relayLabel(spec *providers.Provider, hostname string) string { return spec.ChipLabel(hostname) }

func relayDetails(spec *providers.Provider, info *providers.Relay) string { return spec.Details(info) }

// relayAttributes is data-owned/data-stboot and the like, for the filters,
// only when the catalogue knows.
func relayAttributes(spec *providers.Provider, info *providers.Relay) string {
	var b strings.Builder
	for _, f := range spec.Filters {
		if value, present := info.Flag(f.Attribute); present {
			flag := "0"
			if value {
				flag = "1"
			}
			fmt.Fprintf(&b, ` data-%s="%s"`, f.Attribute, flag)
		}
	}
	return b.String()
}

// relayBadges are badges such as "PF" or "virtual" for what the catalogue
// says is true.
func relayBadges(spec *providers.Provider, info *providers.Relay) string {
	var b strings.Builder
	for _, badge := range spec.Badges {
		if value, present := info.Flag(badge.Attribute); present && value {
			fmt.Fprintf(&b, `<span class="badge" title="%s">%s</span>`, badge.Title, badge.Text)
		}
	}
	return b.String()
}

func relayTitle(spec *providers.Provider, hostname string, info *providers.Relay) string {
	if details := relayDetails(spec, info); details != "" {
		return hostname + " · " + details
	}
	return hostname
}

// relayData is the short label and summary the page script shows for a server
// outside its chip (Saved, Fastest, the current exit).
func relayData(spec *providers.Provider, hostname string, info *providers.Relay) string {
	return fmt.Sprintf(` data-label="%s" data-details="%s"`, esc(relayLabel(spec, hostname)), esc(relayDetails(spec, info)))
}

// field is _field: a member of a decoded object as escaped text, or the
// default when the object is empty or the member is null or absent.
func field(container map[string]any, key, fallback string) string {
	if len(container) == 0 {
		return fallback
	}
	value, present := container[key]
	if !present || value == nil {
		return fallback
	}
	return esc(pyStr(value))
}

// sortedNames lists a catalogue's names in order. Python walked the
// snapshot's own member order for the few places that depend on it (the
// word order of a data-search attribute); the decoded Go object has none, so
// names are taken in sorted order throughout.
func sortedNames(relays *providers.Entries) []string {
	names := relays.Names()
	sort.Strings(names)
	return names
}

func (s *Settings) colorScheme() string {
	if s.Theme == "auto" {
		return "dark light"
	}
	return s.Theme
}

// themeColorMeta is theme_color_meta.
func (s *Settings) themeColorMeta(provider string) string {
	dark, light := themeColor, themeColorLight
	if spec, ok := providers.Lookup(provider); ok && s.Style == "provider" {
		dark, light = spec.ThemeColors[0], spec.ThemeColors[1]
	}
	if s.Theme == "auto" {
		return `<meta name="theme-color" content="` + dark + `" media="(prefers-color-scheme: dark)">` + "\n" +
			`<meta name="theme-color" content="` + light + `" media="(prefers-color-scheme: light)">`
	}
	if s.Theme == "light" {
		return `<meta name="theme-color" content="` + light + `">`
	}
	return `<meta name="theme-color" content="` + dark + `">`
}

const (
	themeColor      = "#232638"
	themeColorLight = "#eff1f5"
)

// regionRows is a flat list of regions, one row each: how PIA presents its
// locations.
func regionRows(spec *providers.Provider, relays *providers.Entries, desiredServer string) string {
	type row struct {
		country, city, hostname string
		info                    *providers.Relay
	}
	var order []row
	relays.Each(func(hostname string, info *providers.Relay) bool {
		order = append(order, row{info.Country, info.City, hostname, info})
		return true
	})
	sort.Slice(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if x, y := strings.ToLower(a.country), strings.ToLower(b.country); x != y {
			return x < y
		}
		if x, y := strings.ToLower(a.city), strings.ToLower(b.city); x != y {
			return x < y
		}
		return a.hostname < b.hostname
	})
	var rows strings.Builder
	for _, r := range order {
		hn := esc(r.hostname)
		flag := flagEmoji(placeCode(r.info))
		current := ""
		if r.hostname == desiredServer {
			current = " is-current"
		}
		countryHTML := ""
		if r.country != r.city {
			countryHTML = ` <span class="subdue region-country">` + esc(r.country) + `</span>`
		}
		rows.WriteString(`<button type="submit" name="server" value="` + hn + `" class="relay region` + current + `" ` +
			`data-host="` + hn + `" data-city="` + esc(r.city) + `" data-country="` + esc(r.country) + `" ` +
			`data-flag="` + flag + `"` + relayAttributes(spec, r.info) + relayData(spec, r.hostname, r.info) + ` ` +
			`data-search="` + esc(strings.ToLower(r.country+" "+r.city+" "+r.hostname)) + `" ` +
			`title="` + esc(relayTitle(spec, r.hostname, r.info)) + `">` +
			`<span class="flag">` + flag + `</span>` +
			`<span class="region-place"><span class="relay-name">` + esc(r.city) + `</span>` + countryHTML + `</span>` +
			relayBadges(spec, r.info) + `<span class="region-action" data-arm-text></span><span class="ms" data-ms></span></button>`)
	}
	if rows.Len() == 0 {
		return `<p class="subdue">No relays available.</p>`
	}
	return `<div class="regions">` + rows.String() + `</div>`
}

// countryTree is countries, then cities, then relay chips: how Mullvad
// presents its locations. It returns the HTML and the number of countries.
func countryTree(spec *providers.Provider, relays *providers.Entries, desiredServer string, embed bool) (string, int) {
	grouped := map[string]map[string][]string{}
	codes := map[string]string{}
	for _, hostname := range sortedNames(relays) {
		info, _ := relays.Get(hostname)
		if grouped[info.Country] == nil {
			grouped[info.Country] = map[string][]string{}
		}
		grouped[info.Country][info.City] = append(grouped[info.Country][info.City], hostname)
		if _, seen := codes[info.Country]; !seen {
			codes[info.Country] = placeCode(info)
		}
	}
	countryNames := make([]string, 0, len(grouped))
	for country := range grouped {
		countryNames = append(countryNames, country)
	}
	sort.Strings(countryNames)

	var out strings.Builder
	for _, country := range countryNames {
		cities := grouped[country]
		cityNames := make([]string, 0, len(cities))
		count := 0
		isCurrent := false
		for city, hosts := range cities {
			cityNames = append(cityNames, city)
			count += len(hosts)
			for _, h := range hosts {
				if h == desiredServer {
					isCurrent = true
				}
			}
		}
		sort.Strings(cityNames)
		terms := []string{country}
		terms = append(terms, cityNames...)
		for _, city := range cityNames {
			terms = append(terms, cities[city]...)
		}
		var cityHTML strings.Builder
		for _, city := range cityNames {
			hosts := append([]string(nil), cities[city]...)
			sort.Strings(hosts)
			var chips strings.Builder
			for _, hostname := range hosts {
				hn := esc(hostname)
				current := ""
				if hostname == desiredServer {
					current = " is-current"
				}
				info, _ := relays.Get(hostname)
				chips.WriteString(`<button type="submit" name="server" value="` + hn + `" class="relay` + current + `" ` +
					`data-host="` + hn + `" data-city="` + esc(city) + `" data-country="` + esc(country) + `" ` +
					`data-flag="` + flagEmoji(placeCode(info)) + `"` + relayAttributes(spec, info) +
					relayData(spec, hostname, info) + ` ` +
					`title="` + esc(relayTitle(spec, hostname, info)) + `">` +
					`<span class="relay-name" data-arm-text>` + esc(relayLabel(spec, hostname)) + `</span>` +
					relayBadges(spec, info) + `<span class="ms" data-ms></span></button>`)
			}
			cityTerms := append([]string{country, city}, cities[city]...)
			cityHTML.WriteString(`<div class="city" data-search="` + esc(strings.ToLower(strings.Join(cityTerms, " "))) + `">` +
				`<div class="city-name">` + esc(city) + `<span class="ms" data-city-ms></span></div>` +
				`<div class="relays">` + chips.String() + `</div></div>`)
		}
		noun := "cities"
		if len(cities) == 1 {
			noun = "city"
		}
		citiesLabel := fmt.Sprintf("%d %s", len(cities), noun)
		currentClass, open := "", ""
		if isCurrent {
			currentClass = " is-current"
			if !embed {
				open = " open"
			}
		}
		out.WriteString(`<details class="country` + currentClass + `" data-country="` + esc(country) + `" ` +
			`data-search="` + esc(strings.ToLower(strings.Join(terms, " "))) + `"` + open + `>` +
			`<summary><span class="flag">` + flagEmoji(codes[country]) + `</span>` +
			`<span class="country-name">` + esc(country) + `</span>` +
			`<span class="subdue country-meta">` + citiesLabel + ` · ` + strconv.Itoa(count) + `</span>` +
			`<span class="ms" data-country-ms></span></summary>` +
			`<div class="cities">` + cityHTML.String() + `</div></details>`)
	}
	body := out.String()
	if body == "" {
		body = `<p class="subdue">No relays available.</p>`
	}
	return `<div class="countries">` + body + `</div>`, len(grouped)
}

// providerCSS is the provider style a page or tab takes: every gluetun entry
// takes gluetun's.
func providerCSS(provider string) string {
	if spec, ok := providers.Lookup(provider); ok {
		return spec.CSSID()
	}
	return provider
}

// providerAccent is a data-accent attribute naming the provider whose colour
// accents that style, as for a gluetun entry ("mullvad" through gluetun), or
// nothing.
func providerAccent(provider string) string {
	if spec, ok := providers.Lookup(provider); ok && spec.Accent != "" {
		return ` data-accent="` + esc(spec.Accent) + `"`
	}
	return ""
}

// providerNote is a short note after the provider's label, such as "via
// gluetun".
func providerNote(provider string) string {
	if spec, ok := providers.Lookup(provider); ok && spec.Note != "" {
		return ` <span class="provider-note">` + esc(spec.Note) + `</span>`
	}
	return ""
}

// serverListUpdate is the gluetun applier's one refresh of gluetun's server
// list after it starts.
var serverListUpdate = map[string]string{"updating": "; updating server list", "failed": "; server list update failed"}

// catalogueAgeText is "fetched <time>", and for a list read from gluetun the
// date of gluetun's provider data, which is what says how current it is.
func catalogueAgeText(relaysData map[string]any, fetchedAt string, now time.Time) string {
	data, isString := relaysData["data_timestamp"].(string)
	if relaysData == nil || relaysData["source"] != "gluetun" || !isString {
		return "fetched " + fetchedAt
	}
	age, ok := state.AgeSeconds(data, now)
	stale := ""
	if !ok || age > providers.GluetunDataStaleSec {
		stale = " (stale: older than 30 days)"
	}
	return "read " + fetchedAt + "; gluetun data from " + esc(data) + stale
}

// ExitSummary is what an exit tab shows: name, provider, state and where it
// exits.
type ExitSummary struct {
	ID       string
	Label    string
	Provider string
	State    string
	Status   string
	Place    string
}

// exitTabs is the Switchyard's exit picker: one tab per exit, in its
// provider's colours, with its state and, when connected, where it exits.
func exitTabs(summaries []ExitSummary, currentID string, embed bool) string {
	base := "/"
	if embed {
		base = "/embed"
	}
	var links strings.Builder
	for index, summary := range summaries {
		selected, current := "", ""
		if summary.ID == currentID {
			selected, current = " is-selected", ` aria-current="page"`
		}
		place := `<span class="exit-place" data-exit-place>` + esc(summary.Place) + `</span>`
		links.WriteString(`<a class="exit-tab` + selected + `" href="` + base + `?exit=` + esc(summary.ID) + `" ` +
			`data-exit="` + esc(summary.ID) + `" data-provider="` + esc(providerCSS(summary.Provider)) + `"` + providerAccent(summary.Provider) + ` ` +
			`title="` + esc(summary.Label) + `"` + current + `>` +
			`<span class="exit-track" aria-hidden="true">` + esc(fmt.Sprintf("%02d", index+1)) + `</span>` +
			`<svg class="track-switch" viewBox="0 0 56 48" fill="none" aria-hidden="true">` +
			`<path class="track-bed" d="M12 44V4M20 44V4M20 32L44 8M14 26L38 2"/>` +
			`<path class="track-stem" d="M16 44V28"/><path class="track-route" d="M16 28V4"/>` +
			`<circle cx="16" cy="30" r="3"/></svg>` +
			`<span class="exit-label">` + esc(summary.Label) + providerNote(summary.Provider) + `</span>` + place +
			`<span class="exit-health">` +
			`<span class="exit-dot dot-` + esc(summary.State) + `" data-exit-dot aria-hidden="true"></span>` +
			`<span data-exit-status>` + esc(summary.Status) + `</span></span></a>`)
	}
	return `<nav class="exit-tabs" aria-label="Exits">` + links.String() + `</nav>`
}

// IndexPage is what renderIndex draws one exit's page from.
type IndexPage struct {
	Exit   Exit
	Status ExitStatus
	// Relays are the validated catalogue; RelaysData is the snapshot it came
	// from (nil when there is none), for the fetch time and gluetun's data date.
	Relays     *providers.Entries
	RelaysData map[string]any
	FetchError string
	FetchErrAt string
	CSRFToken  string
	Embed      bool
	Exits      []ExitSummary
	User       *string // the signed-in name, nil without sign-in
	ShowHome   bool
}

// renderIndex is render_index_html: the page for one exit.
func (s *Server) renderIndex(p IndexPage) string {
	ex := p.Exit
	provider := ex.Provider
	spec, _ := providers.Lookup(provider)
	status := p.Status
	v := status.Verdict
	view := describe(s.exitView(ex, v), status.Result)
	state, sidecar := v.State, ex.Kind == "sidecar"
	desired := status.Desired
	result := status.Result
	configured, isConfigured := v.ConfiguredServer, v.ConfiguredServer != ""
	query := ""
	if ex.ID != "" {
		query = "?exit=" + esc(ex.ID)
	}
	embed := p.Embed

	relays := p.Relays
	if relays == nil {
		relays = providers.NewEntries()
	}
	fetchedAt := "never"
	if p.RelaysData != nil {
		if value, present := p.RelaysData["fetched_at"]; present {
			fetchedAt = esc(pyStr(value))
		}
	}

	desiredServer := configured
	if !isConfigured {
		desiredServer = orEmpty(desired["server"])
	}
	resultServer := orEmpty(result["server"])
	displayServer := resultServer
	if state == "applying" {
		displayServer = desiredServer
	}
	currentInfo, haveInfo := relays.Get(displayServer)

	var currentPlace, currentFlag string
	switch {
	case haveInfo:
		currentPlace = `<span class="current-city">` + esc(currentInfo.City) + `</span>` +
			`<span class="current-country"><span class="place-comma">, </span>` +
			esc(currentInfo.Country) + `</span>`
		currentFlag = flagEmoji(placeCode(currentInfo))
		if currentFlag == "" {
			currentFlag = "🌐"
		}
	case displayServer != "":
		currentPlace, currentFlag = esc(displayServer), ""
	default:
		currentPlace, currentFlag = "Awaiting verified server", ""
	}

	notes := ""
	if state == "applying" && resultServer != "" && resultServer != desiredServer {
		notes = `<p class="note">Leaving ` + esc(resultServer) + `. ` + esc(text.Drop[ex.Kind]) + `</p>`
	}
	retry := ""
	if !isConfigured && state == "failed" && relays.Has(desiredServer) {
		// Explicit form ownership also keeps retry working without JS.
		retry = ` <button type="submit" form="select-form" name="server" value="` + esc(desiredServer) + `" ` +
			`class="relay-switch" data-retry>Retry</button>`
	}
	if view.Note != "" {
		upcoming := ""
		if view.Next != "" {
			upcoming = `<br><span class="subdue small" data-next>` + esc(view.Next) + `</span>`
		}
		notes = `<p class="note note-negative">` + esc(view.Note) + retry + upcoming + `</p>`
	}

	token := esc(p.CSRFToken)
	var locationsHTML, locationsCount, placeholder string
	if spec.Layout == "regions" {
		locationsHTML = regionRows(spec, relays, desiredServer)
		noun := "regions"
		if relays.Len() == 1 {
			noun = "region"
		}
		locationsCount = fmt.Sprintf("%d %s", relays.Len(), noun)
		placeholder = "Filter region or country…"
	} else {
		var countryCount int
		locationsHTML, countryCount = countryTree(spec, relays, desiredServer, embed)
		locationsCount = fmt.Sprintf("%d countries", countryCount)
		placeholder = "Filter country, city or relay…"
	}

	var filterButtons strings.Builder
	for _, f := range spec.Filters {
		// Only where it would narrow the list: some relays have it, some do not.
		some, notAll := false, false
		relays.Each(func(_ string, info *providers.Relay) bool {
			if value, present := info.Flag(f.Attribute); present && value {
				some = true
			} else {
				notAll = true
			}
			return true
		})
		if some && notAll {
			filterButtons.WriteString(`<button type="button" class="filter-chip" data-attr-filter="` + f.Attribute + `" aria-pressed="false">` + f.Label + `</button>`)
		}
	}
	filtersToggle, filtersRow := "", ""
	if filterButtons.Len() > 0 {
		filtersToggle = `<button type="button" class="link-button small" data-filters-toggle ` +
			`aria-expanded="false" aria-controls="relay-filters" hidden>Filters</button>`
		filtersRow = `<div class="filter-row" id="relay-filters" hidden>` + filterButtons.String() + `</div>`
	}
	currentDetails := ""
	if haveInfo {
		currentDetails = relayDetails(spec, currentInfo)
	}
	forwardRow := ""
	// Only a provider with port forwarding (PIA) reports it.
	if result["port_forward"] == true {
		forwardRow = "\n        <dt>Forwarded port</dt><dd data-f=\"forwarded_port\">" + esc(view.Forwarded) + `</dd>`
	}
	// Every check, as the verdict states it; only `pass` reads as passed.
	var checkRows strings.Builder
	for _, check := range view.Checks {
		checkRows.WriteString("\n        <dt>" + esc(check.Label) + `</dt><dd data-check="` + esc(check.Name) +
			`" data-check-state="` + esc(check.State) + `">` + esc(check.Text) + `</dd>`)
	}

	errorHTML := ""
	if p.FetchError != "" {
		at := p.FetchErrAt
		if at == "" {
			at = "unknown"
		}
		errorHTML = `<p class="note note-negative">Relay refresh error: ` + esc(p.FetchError) + ` (at ` + esc(at) + `)</p>`
	}

	versions := s.versions
	returnTo := ""
	if embed {
		returnTo = "embed"
	}
	homeLink := ""
	if p.ShowHome && (strings.HasPrefix(s.Settings.HomeURL, "https://") || strings.HasPrefix(s.Settings.HomeURL, "http://")) {
		homeLink = `<a class="subdue back-link" href="` + esc(s.Settings.HomeURL) + `" target="_top">` +
			`← ` + esc(s.Settings.HomeLabel) + `</a>`
	}
	account := ""
	if p.User != nil {
		// Signing out needs the same CSRF token as a switch.
		account = `<form method="post" action="/logout" class="account">` +
			`<input type="hidden" name="csrf_token" value="` + esc(p.CSRFToken) + `">` +
			`<span class="subdue small account-name">` + esc(*p.User) + `</span>` +
			`<button type="submit" class="link-button small">Sign out</button></form>`
	}
	heading := ""
	if !embed {
		kicker := "Molebridge / exit control"
		if sidecar {
			kicker = "Molebridge / tunnel control"
		}
		heading = `<header class="page-header"><div class="brand">` +
			`<svg class="yard-mark" viewBox="0 0 40 40" fill="none" aria-hidden="true">` +
			`<path d="M10 34V6M18 34V25L32 11M18 6V14M7 10H21M7 17H15M7 24H15M7 31H21M24 14L30 20"/>` +
			`</svg><div><span class="brand-kicker">` + esc(kicker) + `</span>` +
			`<h1>` + esc(s.Settings.Title) + `</h1></div></div><div class="header-side">` + account + homeLink + `</div></header>`
	}
	tabs := ""
	if len(p.Exits) > 1 {
		tabs = exitTabs(p.Exits, ex.ID, embed)
	}
	openLink := ""
	if embed {
		openLink = `<a class="subdue small" href="/` + query + `" target="_blank" rel="noopener">Open panel ↗</a>`
	}
	noun := "exit"
	if sidecar {
		noun = "tunnel"
	}
	currentHeading := "Current " + noun
	if ex.ID != "" {
		currentHeading = esc(ex.Label) + " " + noun
	}
	title := esc(s.Settings.Title)
	if tabs != "" {
		title = esc(ex.Label) + " · " + esc(s.Settings.Title)
	}

	formOpen, formClose, configuredAttr, configurationNote, pin := "", "", "", "", ""
	if !isConfigured {
		formOpen = `<form method="post" action="/select" id="select-form">` +
			`<input type="hidden" name="csrf_token" value="` + token + `">` +
			`<input type="hidden" name="return" value="` + returnTo + `">` +
			`<input type="hidden" name="exit" value="` + esc(ex.ID) + `">`
		formClose = "</form>"
		pin = `<button type="button" class="link-button pin" data-pin aria-pressed="false" ` +
			`aria-label="Pin this server" title="Pin this server" hidden>☆</button>`
	} else {
		configuredAttr = ` data-configured="` + esc(configured) + `"`
		configurationNote = `<p class="note">Set in configuration: <strong>` + esc(configured) + `</strong>. ` +
			`Change SERVER in the exit configuration to choose another server.</p>`
	}
	switchingControls := "</div>"
	if !isConfigured {
		switchingControls = fill(switchingControlsTemplate,
			"hostLabel", esc(s.Settings.HostLabel), "filtersToggle", filtersToggle, "locationsCount", locationsCount,
			"placeholder", esc(placeholder), "filtersRow", filtersRow, "errorHTML", errorHTML,
			"locationsHTML", locationsHTML)
	}

	multi := ""
	if tabs != "" {
		multi = "1"
	}
	bodyClass := "full"
	if embed {
		bodyClass = "embed"
	}
	timeout, ok := state_SwitchTimeout(spec.Backend)
	if !ok {
		timeout = 60
	}
	request := ""
	if value, present := desired["request_id"]; present {
		request = esc(pyStr(value))
	}
	requested := ""
	if value, present := desired["requested_at"]; present {
		requested = esc(pyStr(value))
	}
	tierNote := ""
	if !view.TunnelOnly {
		tierNote = " hidden"
	}
	dtRequested := field(desired, "requested_at", "")
	relayCount := strconv.Itoa(relays.Len())
	detailsCell := esc(currentDetails)
	if detailsCell == "" {
		detailsCell = "(unknown)"
	}
	displayHost := displayServer
	if displayHost == "" {
		displayHost = "—"
	}

	return fill(indexTemplate,
		"theme", s.Settings.Theme, "style", s.Settings.Style, "cssID", esc(spec.CSSID()), "accent", providerAccent(provider),
		"colorScheme", s.Settings.colorScheme(), "themeColorMeta", s.Settings.themeColorMeta(provider),
		"shortTitle", esc(s.Settings.ShortTitle), "title", title,
		"vIcon", versions["icon-192.png"], "vTouch", versions["apple-touch-icon.png"], "vCSS", versions["panel.css"], "vJS", versions["panel.js"],
		"bodyClass", bodyClass, "configuredAttr", configuredAttr, "layout", spec.Layout,
		"pattern", esc(spec.ServerNamePattern), "exitID", esc(ex.ID), "kind", esc(ex.Kind), "textJSON", esc(textJSON),
		"timeout", strconv.Itoa(timeout), "checked", esc(orEmpty(result["checked_at"])), "multi", multi,
		"desired", esc(desiredServer), "request", request, "requested", requested, "actual", esc(resultServer), "state", state,
		"heading", heading, "tabs", tabs, "formOpen", formOpen,
		"currentHeading", currentHeading, "providerNote", providerNote(provider), "openLink", openLink,
		"connection", esc(view.Connection), "currentFlag", currentFlag, "currentPlace", currentPlace,
		"currentHost", esc(displayHost), "currentIP", esc(view.IP), "pin", pin, "label", esc(view.Label),
		"tierText", esc(text.Tier["tunnel"]), "tierHidden", tierNote,
		"configurationNote", configurationNote, "notes", notes,
		"fStatus", esc(view.Status), "fMessage", esc(view.Message), "fEgress", esc(view.Egress), "fEgressTier", esc(view.EgressTier),
		"forwardRow", forwardRow, "checkRows", checkRows.String(), "detailsCell", detailsCell,
		"fChecked", esc(view.CheckedAt), "dtRequested", dtRequested, "relayCount", relayCount,
		"catalogueAge", catalogueAgeText(p.RelaysData, fetchedAt, s.now()),
		"serverListUpdate", serverListUpdate[orEmptyString(result["server_list_update"])],
		"switchingControls", switchingControls, "formClose", formClose)
}

func orEmptyString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// state_SwitchTimeout is state.SwitchTimeouts for a backend.
func state_SwitchTimeout(backend string) (int, bool) {
	n, ok := state.SwitchTimeouts[backend]
	return n, ok
}

// RenderMessage is render_message_page: a small page for sign-in states:
// signed out, refused, unavailable. Everything shown is fixed text or a URL
// the panel built itself.
func (s *Server) RenderMessage(heading, message string, link *[2]string, embed bool) string {
	v := s.versions
	linkHTML := ""
	if link != nil {
		// From a dashboard frame, sign-in must open at top level: issuers
		// refuse to be framed, and a frame cannot set the session cookie.
		target := ""
		if embed {
			target = ` target="_blank" rel="noopener"`
		}
		linkHTML = `<p><a class="relay-switch" href="` + esc(link[0]) + `"` + target + `>` + esc(link[1]) + `</a></p>`
	}
	bodyClass := "full"
	if embed {
		bodyClass = "embed"
	}
	return fill(messageTemplate,
		"theme", s.Settings.Theme, "style", s.Settings.Style, "colorScheme", s.Settings.colorScheme(),
		"themeColorMeta", s.Settings.themeColorMeta(""), "heading", esc(heading), "title", esc(s.Settings.Title),
		"vIcon", v["icon-192.png"], "vCSS", v["panel.css"], "bodyClass", bodyClass, "message", esc(message), "link", linkHTML)
}

const switchingControlsTemplate = `<section class="widget" id="saved" hidden>
  <div class="widget-header"><h2>Saved</h2></div>
  <div class="widget-content">
    <ol class="fastest-list" data-saved></ol>
  </div>
</section>

<section class="widget" id="fastest" hidden>
  <div class="widget-header"><h2>Fastest from «hostLabel»</h2><button type="button" class="link-button small" data-retest>Retest</button></div>
  <div class="widget-content">
    <ol class="fastest-list" data-fastest><li class="subdue">Measuring…</li></ol>
  </div>
</section>

</div>
<section class="widget locations-widget">
  <div class="widget-header"><h2>Locations</h2>«filtersToggle»<span class="subdue small">«locationsCount»</span></div>
  <div class="widget-content">
    <input type="search" class="search" placeholder="«placeholder»" aria-label="Filter locations" data-filter autocomplete="off" hidden>
    «filtersRow»
    «errorHTML»
    «locationsHTML»
    <p class="empty-state" data-filter-empty role="status" hidden>No matching locations.<br><span class="subdue">Try another name or clear your filters.</span></p>
  </div>
</section>`

const indexTemplate = `<!DOCTYPE html>
<html lang="en" data-theme="«theme»" data-style="«style»" data-provider="«cssID»"«accent»>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="«colorScheme»">
«themeColorMeta»
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="«shortTitle»">
<title>«title»</title>
<!-- An authenticating proxy needs its session cookie, which manifest fetches omit by default. -->
<link rel="manifest" href="/manifest.webmanifest" crossorigin="use-credentials">
<link rel="icon" href="/static/icon-192.png?v=«vIcon»" type="image/png">
<link rel="apple-touch-icon" href="/static/apple-touch-icon.png?v=«vTouch»">
<link rel="stylesheet" href="/static/panel.css?v=«vCSS»">
<script src="/static/panel.js?v=«vJS»" defer></script>
</head>
<body class="«bodyClass»">
<main class="page"«configuredAttr» data-provider="«cssID»"«accent» data-layout="«layout»" data-server-pattern="«pattern»" data-exit="«exitID»" data-kind="«kind»" data-text="«textJSON»" data-switch-timeout="«timeout»" data-checked="«checked»" data-multi="«multi»" data-desired="«desired»" data-request="«request»" data-requested="«requested»" data-actual="«actual»" data-state="«state»">
«heading»
«tabs»
«formOpen»
<div class="switchboard">
<div class="overview">
<section class="widget current-widget">
  <div class="widget-header"><h2>«currentHeading»«providerNote»</h2>«openLink»</div>
  <div class="widget-content current">
    <div class="connection-heading"><span class="connection-light" aria-hidden="true"></span><span data-connection-label>«connection»</span></div>
    <div class="current-row">
      <span class="connection-orbit"><span class="flag flag-lg" data-current-flag>«currentFlag»</span></span>
      <div class="current-main">
        <div class="current-place" data-current-place>«currentPlace»</div>
        <div class="subdue small"><span data-current-host>«currentHost»</span> <span class="nowrap">· <span data-current-ip>«currentIP»</span> <button type="button" class="link-button copy-ip" data-copy-ip hidden>Copy</button></span></div>
      </div>
      «pin»
      <div class="current-side">
        <span class="pill pill-«state»" data-state-pill role="status" aria-live="polite">«label»</span>
        <time class="checked-ago subdue" data-checked-ago hidden></time>
        <span class="tier-note" data-tier-note title="No check by the provider itself; see Diagnostics"«tierHidden»>«tierText»</span>
        <span class="ms" data-current-ms></span>
      </div>
    </div>
    «configurationNote»
    <div data-notes>«notes»</div>
    <details class="diagnostics">
      <summary>Diagnostics</summary>
      <dl>
        <dt>Applier</dt><dd data-f="status">«fStatus»</dd>
        <dt>Message</dt><dd data-f="message">«fMessage»</dd>
        <dt>Egress</dt><dd data-f="egress">«fEgress»</dd>
        <dt>Egress confirmation</dt><dd data-f="egress_tier">«fEgressTier»</dd>«forwardRow»«checkRows»
        <dt>Server</dt><dd data-current-details>«detailsCell»</dd>
        <dt>Checked</dt><dd data-f="checked_at">«fChecked»</dd>
        <dt>Requested</dt><dd data-requested-at>«dtRequested»</dd>
        <dt>Relay list</dt><dd>«relayCount» relays, «catalogueAge»«serverListUpdate»</dd>
      </dl>
    </details>
  </div>
</section>

«switchingControls»
</div>
«formClose»
<div class="sr-only" aria-live="polite" data-announce></div>
</main>
</body>
</html>`

const messageTemplate = `<!DOCTYPE html>
<html lang="en" data-theme="«theme»" data-style="«style»">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="«colorScheme»">
«themeColorMeta»
<title>«heading» · «title»</title>
<link rel="icon" href="/static/icon-192.png?v=«vIcon»" type="image/png">
<link rel="stylesheet" href="/static/panel.css?v=«vCSS»">
</head>
<body class="«bodyClass»">
<main class="page">
<section class="widget notice-widget">
  <div class="widget-header"><h2>«heading»</h2></div>
  <div class="widget-content"><p>«message»</p>«link»</div>
</section>
</main>
</body>
</html>`
