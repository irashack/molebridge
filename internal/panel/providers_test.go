package panel

// Ported from panel/test_app.py: PiaPanelTests, MultiExitTests,
// EgressTierPanelTests, NordPanelTests and the exit-id cases of
// RegistryPanelTests.

import (
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
)

var piaRegion = map[string]any{
	"hostname": "ex_example", "country": "Exampleland", "city": "Example City", "location_code": "ex-ex_example",
	"ipv4_addr_in": "198.51.100.21", "port_forward": true, "geo": true,
	"servers": []any{map[string]any{"ip": "198.51.100.20", "cn": "example401"}},
}

func piaCatalogue(provider string) map[string]any {
	return map[string]any{"fetched_at": nowISO(), "provider": provider, "relays": map[string]any{"ex_example": piaRegion}}
}

func allowlist(provider string, names ...string) *providers.Entries {
	entries := providers.NewEntries()
	for _, name := range names {
		entries.Set(name, &providers.Relay{Hostname: name})
	}
	return entries
}

func TestRegionIDIsSelectableOnlyWhenListed(t *testing.T) { // PiaPanelTests
	h := newHarness(t, map[string]string{"PROVIDER": "pia"}, nil)
	desired := filepath.Join(t.TempDir(), "desired.json")
	if code, _ := h.srv.processSelect("ex_example", true, allowlist("pia", "ex_example"), desired, "pia"); code != 303 {
		t.Fatalf("code %d", code)
	}
	written, _ := state.ReadObject(desired, 4096)
	if written["server"] != "ex_example" {
		t.Fatalf("written = %v", written)
	}
	for _, bad := range []string{"ex_other", "se-sto-wg-001", "../x", "Ex"} {
		if code, _ := h.srv.processSelect(bad, true, allowlist("pia", "ex_example"), desired, "pia"); code != 400 {
			t.Errorf("%q: code %d", bad, code)
		}
	}
	if code, _ := h.srv.processSelect("", false, allowlist("pia", "ex_example"), desired, "pia"); code != 400 {
		t.Errorf("no server: code %d", code)
	}
}

func TestPageShowsRegionsAndProviderLabels(t *testing.T) {
	h := newHarness(t, map[string]string{"PROVIDER": "pia"}, nil)
	result := map[string]any{"checked_at": nowISO(), "status": "ok", "server": "ex_example", "routing_ok": true,
		"exit_confirmed": true, "provider": "pia", "port_forward": true, "forwarded_port": 43210}
	page := h.render(nil, result, piaCatalogue("pia"), nil)
	mustContain(t, page, `data-provider="pia"`, `value="ex_example"`, `<dd data-f="egress_tier">provider-confirmed</dd>`,
		`data-f="forwarded_port">43210<`, "port forwarding · virtual location")
	mustNotContain(t, page, "Mullvad")
}

func TestCatalogueOfAnotherProviderIsNotOffered(t *testing.T) { // PiaPanelTests, NordPanelTests
	for _, provider := range []string{"pia", "nordvpn"} {
		h := newHarness(t, map[string]string{"PROVIDER": provider}, nil)
		snapshot := piaCatalogue("mullvad")
		page := h.render(nil, nil, snapshot, nil)
		mustNotContain(t, page, `value="ex_example"`, "us9001")
		mustContain(t, page, "No relays available.")
	}
}

// -- MultiExitTests ----------------------------------------------------------------------

type multi struct {
	*harness
	home, away Exit
}

func newMulti(t *testing.T) *multi {
	t.Helper()
	h := newHarness(t, map[string]string{"PANEL_EXITS": "home=mullvad, away=pia:PIA Chicago"}, nil)
	m := &multi{h, h.exit("home"), h.exit("away")}
	mustWrite(t, m.home.RelaysPath, catalogue(relayEntry("se-sto-wg-001", nil)))
	mustWrite(t, m.away.RelaysPath, piaCatalogue("pia"))
	mustWrite(t, m.away.ResultPath, map[string]any{"server": "ex_example", "status": "ok", "checked_at": nowISO(),
		"routing_ok": true, "exit_confirmed": true, "provider": "pia"})
	return m
}

func (m *multi) selectServer(exitID, server, pageExit string) answer {
	if pageExit == "" {
		pageExit = exitID
	}
	page := m.get("/?exit="+pageExit, "", nil)
	nonce := page.Cookies["csrf_nonce"].Value
	token := csrfTokenInPage.FindStringSubmatch(page.Body)[1]
	return m.post("/select", [][2]string{{"server", server}, {"csrf_token", token}, {"exit", exitID}}, "csrf_nonce="+nonce, "")
}

func TestParseExits(t *testing.T) {
	m := newMulti(t)
	if m.home.ID != "home" || m.home.Provider != "mullvad" || m.home.Label != "Mullvad" ||
		m.away.ID != "away" || m.away.Provider != "pia" || m.away.Label != "PIA Chicago" {
		t.Fatalf("exits = %+v %+v", m.home, m.away)
	}
	if want := filepath.Join(m.dir, "away", "panel", "desired.json"); m.away.DesiredPath != want {
		t.Fatalf("DesiredPath = %q, want %q", m.away.DesiredPath, want)
	}
	if exits, err := ParseExits("", "/state"); err != nil || len(exits) != 0 {
		t.Fatalf("ParseExits('') = %v, %v", exits, err)
	}
	for _, bad := range []string{"home", "Home=mullvad", "../x=pia", "a=examplevpn", "a=pia,a=mullvad", "a=pia:" + strings.Repeat("x", 41), "a=pia:bad\x07label"} {
		if _, err := ParseExits(bad, "/state"); err == nil {
			t.Errorf("ParseExits(%q) accepted", bad)
		}
	}
}

func TestEachExitRendersInItsOwnLayoutWithTabs(t *testing.T) {
	m := newMulti(t)
	home := m.get("/?exit=home", "", nil).Body
	mustContain(t, home, `data-layout="tree"`, `value="se-sto-wg-001"`)
	mustNotContain(t, home, `value="ex_example"`)
	away := m.get("/?exit=away", "", nil).Body
	mustContain(t, away, `data-layout="regions"`, `data-provider="pia"`, `value="ex_example"`,
		`<input type="hidden" name="exit" value="away">`, `class="exit-tab is-selected" href="/?exit=away"`,
		`<span class="exit-place" data-exit-place>Example City</span>`)
	for _, page := range []string{home, away} {
		mustContain(t, page, `href="/?exit=home"`, `href="/?exit=away"`)
	}
}

func TestUnknownExitIs404Everywhere(t *testing.T) {
	m := newMulti(t)
	for _, path := range []string{"/?exit=nope", "/embed?exit=nope", "/api/status?exit=nope", "/api/latency?exit=nope",
		"/readyz?exit=nope", "/api/status", "/?exit=..%2Fhome"} {
		if a := m.get(path, "", nil); a.Status != 404 {
			t.Errorf("%s: %d", path, a.Status)
		}
	}
}

func TestSelectWritesOnlyTheNamedExitsRequest(t *testing.T) {
	m := newMulti(t)
	a := m.selectServer("away", "ex_example", "")
	if a.Status != 303 || a.Location() != "/?exit=away" {
		t.Fatalf("status %d location %q", a.Status, a.Location())
	}
	if readDesired(m.away)["server"] != "ex_example" || readDesired(m.home) != nil {
		t.Fatal("the wrong exit's request was written")
	}
	// A name from another exit's catalogue is refused.
	if a := m.selectServer("home", "ex_example", ""); a.Status != 400 || readDesired(m.home) != nil {
		t.Fatalf("status %d", a.Status)
	}
	if a := m.selectServer("elsewhere", "ex_example", "away"); a.Status != 400 {
		t.Fatalf("status %d", a.Status)
	}
}

func TestRememberedExitIsTheDefault(t *testing.T) {
	m := newMulti(t)
	a := m.get("/?exit=away", "", nil)
	if c := a.Cookies["molebridge_exit"]; c.Value != "away" || !c.Attrs["path=/"] {
		t.Fatalf("cookies = %v", a.Cookies)
	}
	// An address without ?exit= is redirected to one that names the exit, so
	// the page's own reloads cannot follow another tab's choice.
	if a := m.get("/", "molebridge_exit=away", nil); a.Status != 303 || a.Location() != "/?exit=away" {
		t.Fatalf("status %d location %q", a.Status, a.Location())
	}
	if a := m.get("/embed", "molebridge_exit=gone", nil); a.Status != 303 || a.Location() != "/embed?exit=home" {
		t.Fatalf("status %d location %q", a.Status, a.Location())
	}
	mustContain(t, m.get("/?exit=home", "molebridge_exit=away", nil).Body, `data-exit="home"`)
}

func TestStatusReadinessAndSummaries(t *testing.T) {
	m := newMulti(t)
	if view := jsonBody(t, m.get("/api/status?exit=away", "", nil))["view"].(map[string]any); view["state"] != "ok" {
		t.Fatalf("view = %v", view)
	}
	if m.get("/readyz?exit=away", "", nil).Status != 200 || m.get("/readyz", "", nil).Status != 503 {
		t.Fatal("readiness")
	}
	summaries := map[string]map[string]any{}
	for _, s := range jsonBody(t, m.get("/api/exits", "", nil))["exits"].([]any) {
		entry := s.(map[string]any)
		summaries[entry["id"].(string)] = entry
	}
	want := map[string]any{"id": "away", "label": "PIA Chicago", "provider": "pia", "state": "ok", "status": "connected", "place": "Example City"}
	if !reflect.DeepEqual(summaries["away"], want) || summaries["home"]["state"] != "unknown" {
		t.Fatalf("summaries = %v", summaries)
	}
}

func TestLatencyCacheIsPerExit(t *testing.T) {
	h := newSingleHarness(t, nil)
	var probed []string
	ms := 12.0
	h.srv.probe = func(ip string) *float64 { probed = append(probed, ip); return &ms }
	entries := func(ip string) *providers.Entries {
		e := providers.NewEntries()
		e.Set("x", &providers.Relay{Hostname: "x", IPv4AddrIn: ip})
		return e
	}
	h.srv.measureLatency(entries("198.51.100.1"), []string{"x"}, false, "home")
	h.srv.measureLatency(entries("198.51.100.2"), []string{"x"}, false, "away")
	if len(probed) != 2 {
		t.Fatalf("probed %v", probed)
	}
}

// -- EgressTierPanelTests -------------------------------------------------------------------

func tunnelProvider(t *testing.T) {
	t.Helper()
	spec := providers.Clone("mullvad")
	spec.ID, spec.Label, spec.EgressTier = "tunnelvpn", "Tunnel Example", providers.TierTunnel
	t.Cleanup(providers.Replace(spec))
}

func (h *harness) writeResult(changes map[string]any) {
	result := map[string]any{"server": "se-sto-wg-001", "status": "ok", "checked_at": nowISO(), "routing_ok": true, "netbird_native": true}
	for k, v := range changes {
		result[k] = v
	}
	mustWrite(h.t, h.srv.Single.ResultPath, result)
}

func viewOf(t *testing.T, h *harness) map[string]any {
	t.Helper()
	return jsonBody(t, h.get("/api/status", "", nil))["view"].(map[string]any)
}

func TestProviderConfirmedExitHasNoTunnelLabel(t *testing.T) {
	h := newSingleHarness(t, nil)
	h.writeResult(map[string]any{"exit_confirmed": true, "egress_tier": "provider"})
	want := map[string]any{"state": "ok", "label": "connected", "tier": "provider", "selection_mode": "panel", "configured_server": nil}
	if got := viewOf(t, h); !reflect.DeepEqual(got, want) {
		t.Fatalf("view = %v", got)
	}
	page := h.get("/", "", nil).Body
	mustContain(t, page, `data-tier-note title="No check by the provider itself; see Diagnostics" hidden>`, `<dd data-f="egress_tier">provider-confirmed</dd>`)
	if h.get("/readyz", "", nil).Status != 200 {
		t.Fatal("not ready")
	}
}

func TestTunnelVerifiedExitIsConnectedWithALabel(t *testing.T) {
	tunnelProvider(t)
	h := newHarness(t, map[string]string{"PROVIDER": "tunnelvpn"}, nil)
	h.writeResult(map[string]any{"exit_confirmed": false, "egress_tier": "tunnel"})
	want := map[string]any{"state": "ok", "label": "connected", "tier": "tunnel", "selection_mode": "panel", "configured_server": nil}
	if got := viewOf(t, h); !reflect.DeepEqual(got, want) {
		t.Fatalf("view = %v", got)
	}
	page := h.get("/", "", nil).Body
	mustContain(t, page, `data-tier-note title="No check by the provider itself; see Diagnostics">tunnel checks only<`, `<dd data-f="egress_tier">tunnel checks only</dd>`)
	if h.get("/readyz", "", nil).Status != 200 {
		t.Fatal("not ready")
	}
}

func TestTunnelTierIsRefusedForAProviderWithItsOwnCheck(t *testing.T) {
	h := newSingleHarness(t, nil)
	h.writeResult(map[string]any{"exit_confirmed": false, "egress_tier": "tunnel"})
	want := map[string]any{"state": "failed", "label": "verification failed", "tier": nil, "selection_mode": "panel", "configured_server": nil}
	if got := viewOf(t, h); !reflect.DeepEqual(got, want) {
		t.Fatalf("view = %v", got)
	}
	mustContain(t, h.get("/", "", nil).Body, `<dd data-f="egress_tier">not confirmed</dd>`, `Diagnostics" hidden>`)
	if h.get("/readyz", "", nil).Status != 503 {
		t.Fatal("ready")
	}
}

func TestUnconfirmedTunnelTierIsNotReady(t *testing.T) {
	tunnelProvider(t)
	h := newHarness(t, map[string]string{"PROVIDER": "tunnelvpn"}, nil)
	h.writeResult(map[string]any{"exit_confirmed": false, "egress_tier": nil})
	if h.get("/readyz", "", nil).Status != 503 {
		t.Fatal("ready")
	}
}

// -- NordPanelTests ----------------------------------------------------------------------------

func nordEntry(host, city, country, code, location string, load int, virtual bool, ip string) map[string]any {
	return map[string]any{"hostname": host, "public_key": validPubkey, "ipv4_addr_in": ip, "city": city, "country": country,
		"country_code": code, "location_code": location, "load": load, "virtual": virtual}
}

func nordCatalogue(provider string) map[string]any {
	entries := []map[string]any{
		nordEntry("us9001.nordvpn.com", "Dallas", "United States", "US", "us-dallas", 12, false, "198.51.100.11"),
		nordEntry("us9004.nordvpn.com", "Dallas", "United States", "US", "us-dallas", 12, false, "198.51.100.14"),
		nordEntry("bs9005.nordvpn.com", "Nassau", "Bahamas", "BS", "bs-nassau", 12, true, "198.51.100.15"),
	}
	relays := map[string]any{}
	for _, e := range entries {
		relays[e["hostname"].(string)] = e
	}
	return map[string]any{"fetched_at": nowISO(), "provider": provider, "relays": relays}
}

func TestHostnamesAreSelectableOnlyWhenListed(t *testing.T) {
	h := newHarness(t, map[string]string{"PROVIDER": "nordvpn"}, nil)
	desired := filepath.Join(t.TempDir(), "desired.json")
	listed := allowlist("nordvpn", "us9001.nordvpn.com")
	if code, _ := h.srv.processSelect("us9001.nordvpn.com", true, listed, desired, "nordvpn"); code != 303 {
		t.Fatalf("code %d", code)
	}
	if code, _ := h.srv.processSelect("us9002.nordvpn.com", true, listed, desired, "nordvpn"); code != 400 {
		t.Fatalf("code %d", code)
	}
	// Not a NordVPN name, even if a catalogue somehow listed it.
	for _, bad := range []string{"se-sto-wg-001", "ex_example", "US9001.nordvpn.com", "us9001.nordvpn.com.example.net", "../x"} {
		if code, _ := h.srv.processSelect(bad, true, allowlist("nordvpn", "us9001.nordvpn.com", bad), desired, "nordvpn"); code != 400 {
			t.Errorf("%q: code %d", bad, code)
		}
	}
}

func TestAllowlistReadsOnlyAFreshNordVPNCatalogue(t *testing.T) {
	h := newHarness(t, map[string]string{"PROVIDER": "nordvpn"}, nil)
	ex := h.srv.Single
	mustWrite(t, ex.RelaysPath, nordCatalogue("nordvpn"))
	got := h.srv.loadAllowlist(ex).Names()
	if len(got) != 3 {
		t.Fatalf("allowlist = %v", got)
	}
	for _, name := range []string{"us9001.nordvpn.com", "us9004.nordvpn.com", "bs9005.nordvpn.com"} {
		if !h.srv.loadAllowlist(ex).Has(name) {
			t.Errorf("%s not listed", name)
		}
	}
	mustWrite(t, ex.RelaysPath, nordCatalogue("mullvad"))
	if n := h.srv.loadAllowlist(ex).Len(); n != 0 {
		t.Fatalf("another provider's catalogue listed %d", n)
	}
	// A stale catalogue lists nothing.
	stale := nordCatalogue("nordvpn")
	stale["fetched_at"] = "2000-01-01T00:00:00Z"
	mustWrite(t, ex.RelaysPath, stale)
	if n := h.srv.loadAllowlist(ex).Len(); n != 0 {
		t.Fatalf("a stale catalogue listed %d", n)
	}
}

func TestPageGroupsServersByCountryAndCityAndLabelsVirtualLocations(t *testing.T) {
	h := newHarness(t, map[string]string{"PROVIDER": "nordvpn"}, nil)
	result := map[string]any{"checked_at": nowISO(), "status": "ok", "server": "us9001.nordvpn.com", "routing_ok": true,
		"netbird_native": true, "exit_confirmed": true, "egress_tier": "provider", "provider": "nordvpn",
		"egress_ip": "198.51.100.11", "egress_city": "Dallas", "egress_country": "United States"}
	page := h.render(nil, result, nordCatalogue("nordvpn"), nil)
	mustContain(t, page, `data-provider="nordvpn" data-layout="tree"`,
		`<dt>Egress confirmation</dt><dd data-f="egress_tier">provider-confirmed</dd>`,
		`<span class="country-name">United States</span>`, "2 countries", `<div class="city-name">Dallas`,
		`<span class="relay-name" data-arm-text>us9001</span><span class="ms"`,
		`<span class="relay-name" data-arm-text>bs9005</span><span class="badge" title="Virtual location">virtual</span>`,
		`title="bs9005.nordvpn.com · virtual location · load 12%"`, `title="us9001.nordvpn.com · load 12%"`,
		"Filter country, city or relay")
	mustNotContain(t, page, "data-attr-filter", "Mullvad", "Forwarded port")
}

func TestProviderStyleColours(t *testing.T) {
	h := newHarness(t, map[string]string{"PANEL_STYLE": "provider", "PANEL_THEME": "auto"}, nil)
	meta := h.srv.Settings.themeColorMeta("nordvpn")
	mustContain(t, meta, `content="#161b26" media="(prefers-color-scheme: dark)"`, `content="#eef2f8" media="(prefers-color-scheme: light)"`)
	css, err := readStatic("panel.css")
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, string(css), `:root[data-style="provider"][data-provider="nordvpn"] {`,
		`.exit-tab[data-provider="nordvpn"] { --exit-accent: var(--exit-nordvpn); }`)
	// The dashboard style keeps one palette.
	dashboard := newHarness(t, map[string]string{"PANEL_STYLE": "dashboard"}, nil)
	mustContain(t, dashboard.srv.Settings.themeColorMeta("nordvpn"), `content="#232638"`)
}

func TestSwitchTimeoutsAreTheAppliers(t *testing.T) {
	// The Python test compared these with the appliers' constants (60 and 90).
	if !reflect.DeepEqual(state.SwitchTimeouts, map[string]int{"native": 60, "gluetun": 90}) {
		t.Fatalf("SwitchTimeouts = %v", state.SwitchTimeouts)
	}
	h := newSingleHarness(t, nil)
	mustContain(t, h.render(nil, nil, nil, nil), `data-switch-timeout="60"`)
	g := newHarness(t, map[string]string{"PROVIDER": "gluetun-mullvad"}, nil)
	mustContain(t, g.render(nil, nil, nil, nil), `data-switch-timeout="90"`)
}

func TestFlagsComeFromTheCountryWhenThereIsNoLocationCode(t *testing.T) {
	if got := placeCode(&providers.Relay{LocationCode: "se-sto", Country: "Sweden"}); got != "se-sto" {
		t.Errorf("placeCode = %q", got)
	}
	if got := placeCode(&providers.Relay{Country: "United States"}); got != "US" {
		t.Errorf("placeCode = %q", got)
	}
	if got := placeCode(&providers.Relay{Country: "Atlantis"}); got != "" {
		t.Errorf("placeCode = %q", got)
	}
	if got := flagEmoji(placeCode(&providers.Relay{Country: "Netherlands"})); got != "\U0001F1F3\U0001F1F1" {
		t.Errorf("flag = %q", got)
	}
}

func TestGluetunStyleTakesTheProviderAsItsAccent(t *testing.T) {
	css, err := readStatic("panel.css")
	if err != nil {
		t.Fatal(err)
	}
	mustContain(t, string(css), `:root[data-style="provider"]:is([data-provider="gluetun"], :not([data-provider])) {`)
	for _, id := range providers.IDs() {
		spec, _ := providers.Lookup(id)
		if spec.Backend != providers.BackendGluetun {
			continue
		}
		if spec.CSSID() != "gluetun" || spec.Accent != spec.GluetunProvider {
			t.Errorf("%s: css %q accent %q", id, spec.CSSID(), spec.Accent)
		}
		mustContain(t, string(css), `:root[data-style="provider"][data-provider="gluetun"][data-accent="`+spec.Accent+`"] {`,
			`.exit-tab[data-accent="`+spec.Accent+`"] { --exit-accent: var(--exit-`+spec.Accent+`); }`)
	}
	h := newHarness(t, map[string]string{"PANEL_STYLE": "provider", "PANEL_THEME": "auto"}, nil)
	mustContain(t, h.srv.Settings.themeColorMeta("gluetun-mullvad"), `content="#11181c" media="(prefers-color-scheme: dark)"`)
}

func TestStatusViewAndReadinessUseNordVPNNames(t *testing.T) {
	desired := map[string]any{"server": "us9001.nordvpn.com", "requested_at": nowISO(), "request_id": strings.Repeat("a", 32)}
	result := map[string]any{"checked_at": nowISO(), "status": "ok", "server": "us9001.nordvpn.com", "routing_ok": true,
		"netbird_native": true, "exit_confirmed": true, "request_id": strings.Repeat("a", 32), "requested_server": "us9001.nordvpn.com"}
	h := newHarness(t, nil, nil)
	for _, tc := range []struct {
		provider string
		result   map[string]any
		state    string
		label    string
	}{
		{"nordvpn", result, "ok", "connected"},
		{"mullvad", result, "ok", "connected"},
		{"nordvpn", merge(result, map[string]any{"exit_confirmed": false}), "failed", "verification failed"},
	} {
		ex := Exit{ID: "x", Provider: tc.provider, Kind: "overlay"}
		v := h.srv.judge(ex, desired, tc.result).Verdict
		if v.State != tc.state || v.Label != tc.label {
			t.Errorf("%s: %s/%s, want %s/%s", tc.provider, v.State, v.Label, tc.state, tc.label)
		}
	}
}

func merge(base, changes map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range changes {
		out[k] = v
	}
	return out
}

var _ = url.QueryEscape
