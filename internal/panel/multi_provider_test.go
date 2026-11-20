package panel

// Multi-provider exits in the panel (docs/design/multi-provider.md, "The
// panel"): PANEL_EXITS with +, a single exit's PROVIDERS, the request
// written, and provider fields shown only while that provider is active.

import (
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/verdict"
)

// multiRecord is a multi-provider exit's schema-2 record with provider's
// tunnel in place, for a request of that provider's server.
func multiRecord(provider string, ids []string, extra map[string]any) map[string]any {
	r := schema2(recOpts{Provider: provider, Extra: extra})
	list := make([]any, len(ids))
	for i, id := range ids {
		list[i] = id
	}
	r["providers"] = list
	r["requested_provider"] = provider
	r["selection"].(map[string]any)["target_provider"] = provider
	return r
}

func multiRequest(provider, server string, id ...string) map[string]any {
	r := request(server, id...)
	r["provider"] = provider
	return r
}

func TestPanelExitsTakeAProviderSet(t *testing.T) {
	exits, err := ParseExits("both=mullvad+pia, all = mullvad + pia + nordvpn/overlay:Anywhere, home=mullvad", "/state")
	if err != nil {
		t.Fatal(err)
	}
	both, all, home := exits[0], exits[1], exits[2]
	if !slices.Equal(both.Providers, []string{"mullvad", "pia"}) || both.Provider != "mullvad" || both.Label != "Mullvad + PIA" ||
		both.Kind != "overlay" || !both.Multi() {
		t.Fatalf("both = %+v", both)
	}
	if !slices.Equal(all.Providers, []string{"mullvad", "pia", "nordvpn"}) || all.Label != "Anywhere" {
		t.Fatalf("all = %+v", all)
	}
	if home.Multi() || home.Providers != nil {
		t.Fatalf("home = %+v", home)
	}
	if relays, errs := both.CatalogFiles("pia"); relays != "/state/both/applier/relays-pia.json" || errs != "/state/both/applier/relay-error-pia.json" {
		t.Fatalf("catalogue files %q %q", relays, errs)
	}
	if relays, _ := home.CatalogFiles("mullvad"); relays != "/state/home/applier/relays.json" {
		t.Fatalf("single catalogue %q", relays)
	}
	for bad, want := range map[string]string{
		"a=mullvad+":                               providerSetBad,
		"a=+pia":                                   providerSetBad,
		"a=mullvad+mullvad":                        providerSetBad,
		"a=mullvad+examplevpn":                     providerSetBad,
		"a=mullvad+pia+nordvpn+mullvad":            providerSetBad,
		"a=mullvad+gluetun-mullvad":                "native providers only",
		"a=mullvad+pia/sidecar":                    "a multi-provider exit is an overlay exit",
		"a=mullvad+pia/":                           "a multi-provider exit is an overlay exit",
		"a=mullvad+pia:" + strings.Repeat("x", 41): "labels are at most 40",
	} {
		_, err := ParseExits(bad, "/state")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", bad, err, want)
		}
	}
}

func TestPanelAcceptsMultiProviderExits(t *testing.T) {
	if _, err := ParseExits("both=mullvad+pia", "/state"); err != nil {
		t.Fatalf("PANEL_EXITS: %v", err)
	}
	if cfg, err := ConfigFromEnv(map[string]string{"PROVIDERS": "mullvad,pia", "PROVIDER": "pia"}); err != nil || !cfg.Single.Multi() {
		t.Fatalf("PROVIDERS: %v", err)
	}
	// An empty PROVIDERS is unset, as Compose passes it.
	if cfg, err := ConfigFromEnv(map[string]string{"PROVIDERS": "", "PROVIDER": "pia"}); err != nil || cfg.Single.Multi() {
		t.Fatalf("empty PROVIDERS: %v", err)
	}
}

func TestSingleExitPanelReadsProvidersAsTheExitDoes(t *testing.T) {
	cfg, err := ConfigFromEnv(map[string]string{"PROVIDERS": "mullvad, pia,nordvpn", "PROVIDER": "pia", "STATE_DIR": "/state"})
	if err != nil {
		t.Fatal(err)
	}
	if s := cfg.Single; !slices.Equal(s.Providers, []string{"mullvad", "pia", "nordvpn"}) || s.Provider != "pia" ||
		s.Label != "Mullvad + PIA + NordVPN" || s.Kind != "overlay" {
		t.Fatalf("single = %+v", s)
	}
	for _, c := range []struct {
		env  map[string]string
		want string
	}{
		{map[string]string{"PROVIDERS": "mullvad,pia"}, "PROVIDER is required with PROVIDERS: the provider the tunnel starts on the first time"},
		{map[string]string{"PROVIDERS": "mullvad,pia", "PROVIDER": "nordvpn"}, "PROVIDER must be one of PROVIDERS"},
		{map[string]string{"PROVIDERS": "mullvad", "PROVIDER": "mullvad"}, "PROVIDERS must be two or three of mullvad, pia and nordvpn, comma-separated, each once"},
		{map[string]string{"PROVIDERS": "mullvad,mullvad", "PROVIDER": "mullvad"}, "PROVIDERS must be two or three of mullvad, pia and nordvpn, comma-separated, each once"},
		{map[string]string{"PROVIDERS": "mullvad,gluetun-mullvad", "PROVIDER": "mullvad"}, "PROVIDERS takes native providers only (mullvad, pia, nordvpn), not gluetun-mullvad"},
		{map[string]string{"PROVIDERS": "mullvad,pia", "PROVIDER": "mullvad", "EXIT_KIND": "sidecar"}, "PROVIDERS is for the overlay exit (EXIT_KIND=overlay); a sidecar carries one provider"},
		{map[string]string{"PROVIDERS": "mullvad,pia", "PROVIDER": "mullvad", "TUNNEL_BACKEND": "gluetun"}, "PROVIDERS needs TUNNEL_BACKEND=native: a gluetun exit carries one provider"},
		{map[string]string{"PROVIDERS": "mullvad,pia", "PROVIDER": "mullvad", "PANEL_PROXY_STATUS": "/proxy/proxy.json"}, "PANEL_PROXY_STATUS: this is a multi-provider exit; the proxy does not run beside one"},
		{map[string]string{"PANEL_EXITS": "both=mullvad+pia", "PANEL_PROXY_STATUS": "both=/proxy/proxy.json"}, "PANEL_PROXY_STATUS: 'both' is a multi-provider exit; the proxy does not run beside one"},
		{map[string]string{"PANEL_EXITS": "both=mullvad+pia", "PANEL_NETWORK_EXITS": "both"}, "PANEL_NETWORK_EXITS: 'both' is a multi-provider exit, which the network exchange does not carry"},
	} {
		if _, err := ConfigFromEnv(c.env); err == nil || err.Error() != c.want {
			t.Errorf("%v: %v, want %q", c.env, err, c.want)
		}
	}
}

// providerSet is a panel with a multi-provider exit (mullvad+pia) beside a
// single-provider one, every catalogue written.
type providerSet struct {
	*harness
	both, home Exit
}

func newProviderSet(t *testing.T) *providerSet {
	t.Helper()
	h := newHarness(t, map[string]string{"PANEL_EXITS": "home=mullvad, both=mullvad+pia"}, nil)
	p := &providerSet{h, h.exit("both"), h.exit("home")}
	mullvad, _ := p.both.CatalogFiles("mullvad")
	pia, _ := p.both.CatalogFiles("pia")
	mustWrite(t, mullvad, catalogue(relayEntry("se-sto-wg-001", nil)))
	mustWrite(t, pia, piaCatalogue("pia"))
	mustWrite(t, p.home.RelaysPath, catalogue(relayEntry("se-sto-wg-001", nil)))
	return p
}

func (p *providerSet) post(fields [][2]string) answer {
	p.t.Helper()
	nonce, token := p.pageTokens("", "both", "")
	return p.harness.post("/select", append([][2]string{{"csrf_token", token}, {"exit", "both"}}, fields...), "csrf_nonce="+nonce, "")
}

func TestPickingAServerWritesTheFourMemberRequest(t *testing.T) {
	p := newProviderSet(t)
	mustWrite(t, p.both.ResultPath, multiRecord("mullvad", p.both.Providers, nil))
	got := p.post([][2]string{{"provider", "pia"}, {"server", "ex_example"}})
	if got.Status != 303 || got.Location() != "/?exit=both" {
		t.Fatalf("select: %d %s %q", got.Status, got.Body, got.Location())
	}
	raw, err := os.ReadFile(p.both.DesiredPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(raw), `{"provider": "pia", "server": "ex_example", "requested_at": "`) {
		t.Fatalf("desired.json = %s", raw)
	}
	written := readDesired(p.both)
	request, ok := state.DesiredRequestFor(written, p.both.Providers)
	if !ok || request.Provider != "pia" || request.Server != "ex_example" || len(request.RequestID) != 32 || len(written) != 4 {
		t.Fatalf("request %+v %v from %v", request, ok, written)
	}
	// A single-provider reader refuses it as an invalid request.
	if _, ok := state.DesiredRequest(written, "pia"); ok {
		t.Fatal("a single-provider reader accepted the four-member request")
	}
	// The panel's own verdict now waits for the PIA tunnel.
	if v := p.srv.readStatus(p.both).Verdict; v.State != "applying" {
		t.Fatalf("after the request: %s %s", v.State, v.Label)
	}
}

func TestASwitchNeedsAProviderOfTheExitAndItsServer(t *testing.T) {
	p := newProviderSet(t)
	mustWrite(t, p.both.ResultPath, multiRecord("mullvad", p.both.Providers, nil))
	for _, c := range []struct {
		fields [][2]string
		code   int
		body   string
	}{
		{[][2]string{{"server", "se-sto-wg-001"}}, 400, "unknown provider"},
		{[][2]string{{"provider", "nordvpn"}, {"server", "us9001.nordvpn.com"}}, 400, "unknown provider"},
		{[][2]string{{"provider", "gluetun-mullvad"}, {"server", "se-sto-wg-001"}}, 400, "unknown provider"},
		// Another provider's server under this provider.
		{[][2]string{{"provider", "pia"}, {"server", "se-sto-wg-001"}}, 400, "unknown or unlisted server"},
		{[][2]string{{"provider", "mullvad"}, {"server", "ex_example"}}, 400, "unknown or unlisted server"},
		{[][2]string{{"provider", "mullvad"}, {"server", "se-got-wg-001"}}, 400, "unknown or unlisted server"},
		{[][2]string{{"provider", "pia"}}, 400, "unknown or unlisted server"},
	} {
		got := p.post(c.fields)
		if got.Status != c.code || got.Body != c.body {
			t.Errorf("%v: %d %q", c.fields, got.Status, got.Body)
		}
	}
	if readDesired(p.both) != nil {
		t.Fatal("a refused switch wrote a request")
	}
	// A stale catalogue offers nothing.
	pia, _ := p.both.CatalogFiles("pia")
	old := piaCatalogue("pia")
	old["fetched_at"] = "2000-01-01T00:00:00Z"
	mustWrite(t, pia, old)
	if got := p.post([][2]string{{"provider", "pia"}, {"server", "ex_example"}}); got.Status != 400 {
		t.Fatalf("stale catalogue: %d %s", got.Status, got.Body)
	}
}

func TestTheGateAndTheLockAreUnchanged(t *testing.T) {
	p := newProviderSet(t)
	mustWrite(t, p.both.ResultPath, multiRecord("mullvad", p.both.Providers, nil))
	mustWrite(t, p.both.DesiredPath, multiRequest("pia", "ex_example", strings.Repeat("b", 32)))
	if got := p.post([][2]string{{"provider", "mullvad"}, {"server", "se-sto-wg-001"}}); got.Status != 409 ||
		got.Body != "A switch is in progress; wait for it to finish." {
		t.Fatalf("applying: %d %s", got.Status, got.Body)
	}
	// The locked page offers no form, so take the tokens before the lock.
	if err := os.Remove(p.both.DesiredPath); err != nil {
		t.Fatal(err)
	}
	nonce, token := p.pageTokens("", "both", "")
	locked := multiRecord("pia", p.both.Providers, map[string]any{"configured_server": "pia/ex_example"})
	locked["request_id"], locked["requested_server"], locked["requested_provider"] = nil, nil, nil
	locked["selection"].(map[string]any)["source"] = "configured"
	mustWrite(t, p.both.ResultPath, locked)
	if got := p.harness.post("/select", [][2]string{{"csrf_token", token}, {"exit", "both"}, {"provider", "mullvad"},
		{"server", "se-sto-wg-001"}}, "csrf_nonce="+nonce, ""); got.Status != 403 {
		t.Fatalf("locked: %d %s", got.Status, got.Body)
	}
	page := p.get("/?exit=both", "", nil).Body
	mustContain(t, page, `Set in configuration: <strong>pia/ex_example</strong>`, `data-provider-line data-provider-label="PIA">Connected: PIA, ex_example</p>`,
		`<span class="current-city">Example City</span>`)
	mustNotContain(t, page, `id="select-form"`, `class="provider-switch"`)
}

func TestThePageListsAProviderAtATime(t *testing.T) {
	p := newProviderSet(t)
	mustWrite(t, p.both.ResultPath, multiRecord("mullvad", p.both.Providers, nil))
	mustWrite(t, p.both.DesiredPath, multiRequest("mullvad", "se-sto-wg-001"))

	// The provider in use by default, marked.
	page := p.get("/?exit=both", "", nil).Body
	mustContain(t, page,
		`data-shown-provider="mullvad" data-listed-provider="mullvad" data-foreign=""`,
		`<nav class="provider-switch" aria-label="Providers">`+
			`<a class="provider-tab is-selected" href="/?exit=both&amp;provider=mullvad" data-provider-tab="mullvad" data-provider="mullvad" aria-current="page">Mullvad <span class="provider-in-use">in use</span></a>`+
			`<a class="provider-tab" href="/?exit=both&amp;provider=pia" data-provider-tab="pia" data-provider="pia">PIA</a></nav>`,
		`<input type="hidden" name="provider" value="mullvad">`, `value="se-sto-wg-001" class="relay is-current"`,
		`data-provider-line data-provider-label="Mullvad">Connected: Mullvad, se-sto-wg-001</p>`, `data-layout="tree"`)
	mustNotContain(t, page, `value="ex_example"`, `data-provider-warning`)

	// Another provider's servers, with the warning before anything is posted.
	page = p.get("/?exit=both&provider=pia", "", nil).Body
	mustContain(t, page,
		`data-shown-provider="mullvad" data-listed-provider="pia" data-foreign="1"`,
		`<p class="note provider-warning" data-provider-warning>Picking a PIA server moves every device on this exit from Mullvad to PIA.</p>`,
		`<input type="hidden" name="provider" value="pia">`, `value="ex_example"`, `data-layout="regions"`,
		// The current exit is still Mullvad's, from Mullvad's catalogue.
		`<span class="current-city">Stockholm</span>`, `<html lang="en" data-theme="auto" data-style="provider" data-provider="mullvad"`)
	mustNotContain(t, page, `value="se-sto-wg-001"`, `is-current"`)

	// An unknown provider lists the one in use.
	if page := p.get("/?exit=both&provider=nordvpn", "", nil).Body; !strings.Contains(page, `data-listed-provider="mullvad"`) {
		t.Fatal("an unknown provider was listed")
	}
	// The embed's switch stays in the embed.
	mustContain(t, p.get("/embed?exit=both", "", nil).Body, `href="/embed?exit=both&amp;provider=pia"`)
}

func TestStatusLineAndFieldsFollowTheActiveProvider(t *testing.T) {
	p := newProviderSet(t)
	forwarding := map[string]any{"port_forward": true, "forwarded_port": 43210}
	mustWrite(t, p.both.ResultPath, multiRecord("pia", p.both.Providers, forwarding))
	mustWrite(t, p.both.DesiredPath, multiRequest("pia", "ex_example"))
	page := p.get("/?exit=both", "", nil).Body
	mustContain(t, page, `>Connected: PIA, ex_example</p>`, `<dt>Forwarded port</dt><dd data-f="forwarded_port">43210</dd>`,
		`data-shown-provider="pia" data-listed-provider="pia"`, `PIA <span class="provider-in-use">in use</span>`,
		`<span class="pill pill-ok" data-state-pill role="status" aria-live="polite">connected</span>`)
	status := payloadMap(t, p.srv.statusPayload(p.both, p.srv.readStatus(p.both)))
	if v := status["verdict"].(map[string]any); v["state"] != "ok" {
		t.Fatalf("verdict %v", v)
	}

	// Mullvad in use: no PIA field, whatever the record carries.
	mustWrite(t, p.both.ResultPath, multiRecord("mullvad", p.both.Providers, forwarding))
	mustWrite(t, p.both.DesiredPath, multiRequest("mullvad", "se-sto-wg-001"))
	page = p.get("/?exit=both", "", nil).Body
	mustContain(t, page, `>Connected: Mullvad, se-sto-wg-001</p>`)
	mustNotContain(t, page, "Forwarded port", `data-f="forwarded_port"`)
	// Not even on PIA's list.
	mustNotContain(t, p.get("/?exit=both&provider=pia", "", nil).Body, "Forwarded port")

	// While switching to PIA the line names the target.
	mustWrite(t, p.both.DesiredPath, multiRequest("pia", "ex_example", strings.Repeat("b", 32)))
	page = p.get("/?exit=both", "", nil).Body
	mustContain(t, page, `>Switching: PIA, ex_example</p>`, `data-shown-provider="pia"`, `Leaving se-sto-wg-001.`)

	// No record: no provider is named.
	if err := os.Remove(p.both.ResultPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p.both.DesiredPath); err != nil {
		t.Fatal(err)
	}
	page = p.get("/?exit=both", "", nil).Body
	mustContain(t, page, `data-provider-label="">Awaiting status</p>`, `data-foreign="1"`,
		`<p class="note provider-warning" data-provider-warning>Picking a Mullvad server moves every device on this exit to Mullvad.</p>`)
	mustNotContain(t, page, `provider-in-use`)
}

func TestMultiProviderVerdictsAndSummaries(t *testing.T) {
	p := newProviderSet(t)
	// Another exit's providers: provider mismatch.
	mustWrite(t, p.both.ResultPath, multiRecord("pia", []string{"mullvad", "pia", "nordvpn"}, nil))
	if v := p.srv.readStatus(p.both).Verdict; v.Label != "provider mismatch" {
		t.Fatalf("other providers: %s", v.Label)
	}
	// A record for the PIA request, but of the Mullvad tunnel.
	mustWrite(t, p.both.ResultPath, multiRecord("mullvad", p.both.Providers, map[string]any{"requested_provider": "pia",
		"requested_server": "ex_example"}))
	mustWrite(t, p.both.DesiredPath, multiRequest("pia", "ex_example"))
	if v := p.srv.readStatus(p.both).Verdict; v.State == "ok" {
		t.Fatalf("the Mullvad tunnel judged connected for a PIA request: %+v", v)
	}
	// A three-member request is the active provider's.
	mustWrite(t, p.both.ResultPath, multiRecord("pia", p.both.Providers, nil))
	mustWrite(t, p.both.DesiredPath, request("ex_example"))
	if v := p.srv.readStatus(p.both).Verdict; v.State != "ok" {
		t.Fatalf("three-member request: %s %s %v", v.State, v.Label, v.Reasons)
	}
	summary := p.srv.exitSummary(p.both, nil)
	if summary.Provider != "pia" || summary.Place != "Example City" || summary.Label != "Mullvad + PIA" {
		t.Fatalf("summary %+v", summary)
	}
	metrics := p.get("/metrics", "", nil).Body
	mustContain(t, metrics, `molebridge_exit_info{exit="both",provider="mullvad+pia",kind="overlay"} 1`,
		`molebridge_exit_info{exit="home",provider="mullvad",kind="overlay"} 1`)
	// A single-provider exit's record never stands for a multi-provider exit.
	mustWrite(t, p.both.ResultPath, schema2(recOpts{Provider: "pia"}))
	if v := p.srv.readStatus(p.both).Verdict; v.Label != "provider mismatch" {
		t.Fatalf("single-provider record: %s", v.Label)
	}
}

func TestOnePanelServesBothKinds(t *testing.T) {
	p := newProviderSet(t)
	mustWrite(t, p.home.ResultPath, schema2(recOpts{}))
	mustWrite(t, p.home.DesiredPath, request("se-sto-wg-001"))
	mustWrite(t, p.both.ResultPath, multiRecord("pia", p.both.Providers, nil))
	home := p.get("/?exit=home", "", nil).Body
	mustNotContain(t, home, "data-shown-provider", "provider-switch", "data-provider-line", `name="provider"`)
	mustContain(t, home, `href="/?exit=both"`, `<span class="exit-label">Mullvad + PIA</span>`)
	// The multi-provider exit's tab takes its active provider's colours.
	mustContain(t, home, `href="/?exit=both" data-exit="both" data-provider="pia"`)
	// A single-provider exit's switch is as before: three members.
	nonce, token := p.pageTokens("", "home", "")
	got := p.harness.post("/select", [][2]string{{"server", "se-sto-wg-001"}, {"csrf_token", token}, {"exit", "home"},
		{"provider", "pia"}}, "csrf_nonce="+nonce, "")
	if got.Status != 303 {
		t.Fatalf("single select: %d %s", got.Status, got.Body)
	}
	if written := readDesired(p.home); len(written) != 3 || written["provider"] != nil {
		t.Fatalf("single request = %v", written)
	}
}

func TestLatencyMeasuresTheListedProvider(t *testing.T) {
	p := newProviderSet(t)
	mustWrite(t, p.both.ResultPath, multiRecord("mullvad", p.both.Providers, nil))
	var probed []string
	p.srv.probe = func(ip string) *float64 { probed = append(probed, ip); ms := 5.0; return &ms }
	q := url.Values{"exit": {"both"}, "provider": {"pia"}, "hosts": {"ex_example,se-sto-wg-001"}}
	body := p.get("/api/latency?"+q.Encode(), "", nil).Body
	if !strings.Contains(body, `"ex_example": 5`) || strings.Contains(body, "se-sto-wg-001") {
		t.Fatalf("latency %s (probed %v)", body, probed)
	}
	q.Set("provider", "")
	body = p.get("/api/latency?"+q.Encode(), "", nil).Body
	if !strings.Contains(body, `"se-sto-wg-001": 5`) || strings.Contains(body, "ex_example") {
		t.Fatalf("latency of the provider in use %s", body)
	}
}

func TestMultiExitConfigIsTheVerdicts(t *testing.T) {
	p := newProviderSet(t)
	want, err := verdict.NewMultiExitConfig([]string{"mullvad", "pia"}, "mullvad", "overlay", "both")
	if err != nil {
		t.Fatal(err)
	}
	got := p.srv.exitConfig(p.both)
	if got.Provider != want.Provider || !slices.Equal(got.Providers, want.Providers) || got.Kind != want.Kind || got.ID != want.ID {
		t.Fatalf("exit config %+v, want %+v", got, want)
	}
	if relays, _ := p.both.CatalogFiles("mullvad"); filepath.Base(relays) != "relays-mullvad.json" {
		t.Fatalf("catalogue %s", relays)
	}
}
