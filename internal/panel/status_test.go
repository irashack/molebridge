package panel

// Ported from panel/test_status.py: the panel's status consumers, all from
// one verdict (internal/verdict, whose own judgments its tests cover): the
// page, /api/status with its deprecated `view` and diagnostic fields,
// /api/exits, /readyz, and the switch gate (D8). Also the exit kind in
// PANEL_EXITS and EXIT_KIND.

import (
	"encoding/json"
	"html"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

var projectionFields = []string{"routing_ok", "netbird_native", "exit_confirmed", "egress_tier", "handshake_age_s", "unreachable_fallback"}

// setupExit starts a panel with one named exit `x` of the given provider and
// kind, with its result and request on disk.
func setupExit(t *testing.T, provider, kind string, result, desired map[string]any) *harness {
	t.Helper()
	h := newHarness(t, map[string]string{"PANEL_EXITS": "x=" + provider + "/" + kind + ":Example"}, nil)
	ex := h.exit("x")
	mustWrite(t, ex.ResultPath, result)
	mustWrite(t, ex.DesiredPath, desired)
	return h
}

func TestEveryConsumerShowsTheOneVerdict(t *testing.T) {
	for _, name := range caseNames() {
		c := consumerCases[name]
		t.Run(name, func(t *testing.T) {
			result := c.record()
			h := setupExit(t, c.provider, c.kind, result, c.request())
			var configured any
			if result != nil {
				configured = result["configured_server"]
			}

			// /api/status: the verdict, and the old view kept whole.
			a := h.get("/api/status?exit=x", "", nil)
			payload := jsonBody(t, a)
			if a.Status != 200 {
				t.Fatalf("status %d", a.Status)
			}
			v := payload["verdict"].(map[string]any)
			var tier any
			if c.tier != "" {
				tier = c.tier
			}
			if v["state"] != c.state || v["label"] != c.label || v["tier"] != tier || v["kind"] != c.kind {
				t.Fatalf("verdict = %v, want %s/%s/%v/%s", v, c.state, c.label, tier, c.kind)
			}
			checks := v["checks"].(map[string]any)
			if len(checks) != len(verdict.CheckNames) {
				t.Fatalf("checks = %v", checks)
			}
			for _, n := range verdict.CheckNames {
				if _, ok := checks[n]; !ok {
					t.Fatalf("check %s missing", n)
				}
			}
			mode := "panel"
			if configured != nil {
				mode = "configuration"
			}
			wantView := map[string]any{"state": c.state, "label": c.label, "tier": tier, "selection_mode": mode, "configured_server": configured}
			if !reflect.DeepEqual(payload["view"], wantView) {
				t.Fatalf("view = %v, want %v", payload["view"], wantView)
			}

			// The deprecated diagnostic fields: derived for schema 2 only, and
			// a record's own fields are never overwritten.
			if got, _ := payload["result"].(map[string]any); result != nil {
				if result["schema"] == 2 {
					for _, f := range projectionFields {
						if _, ok := got[f]; !ok {
							t.Errorf("projection field %s missing", f)
						}
					}
				} else {
					for _, f := range projectionFields {
						if !reflect.DeepEqual(got[f], jsonRoundTrip(t, result[f])) {
							t.Errorf("%s = %v, record has %v", f, got[f], result[f])
						}
					}
				}
			}

			// The page, from the same verdict.
			page := h.get("/?exit=x", "", nil)
			if page.Status != 200 {
				t.Fatalf("page %d", page.Status)
			}
			mustContain(t, page.Body, `data-state="`+c.state+`"`,
				`data-state-pill role="status" aria-live="polite">`+html.EscapeString(c.label)+`</span>`)
			// html.EscapeString differs from html.escape on quotes, but no label has any.
			tunnelNote := strings.Contains(page.Body, `data-tier-note title="No check by the provider itself; see Diagnostics">`)
			if tunnelNote != (c.tier == "tunnel") {
				t.Errorf("tunnel note shown = %v for tier %q", tunnelNote, c.tier)
			}
			tierKey := c.tier
			if tierKey == "" {
				tierKey = "none"
			}
			mustContain(t, page.Body, `<dd data-f="egress_tier">`+text.Tier[tierKey]+`</dd>`)
			// Only a connected exit shows an egress address.
			shown := "—"
			if c.state == "ok" {
				shown = egressIP
			}
			mustContain(t, page.Body, `<span data-current-ip>`+shown+`</span>`)
			for n, st := range checks {
				mustContain(t, page.Body, `data-check="`+n+`" data-check-state="`+pyEscape(st.(string))+`">`)
			}

			// The exit tabs and readiness.
			summaries := jsonBody(t, h.get("/api/exits", "", nil))["exits"].([]any)
			summary := summaries[0].(map[string]any)
			if len(summaries) != 1 || summary["state"] != c.state || summary["status"] != c.label {
				t.Fatalf("summary = %v", summaries)
			}
			want := 503
			if c.state == "ok" {
				want = 200
			}
			if h.get("/readyz?exit=x", "", nil).Status != want || h.get("/readyz", "", nil).Status != want {
				t.Errorf("readiness is not %d", want)
			}
		})
	}
}

func pyEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#x27;").Replace(s)
}

// jsonRoundTrip is the value as a client would decode it.
func jsonRoundTrip(t *testing.T, v any) any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestThePageAndItsOwnTabShareOneRead(t *testing.T) {
	h := setupExit(t, "mullvad", "overlay", schema2(recOpts{}), request("se-sto-wg-001"))
	var mu sync.Mutex
	var reads []string
	h.srv.onRead = func(ex Exit) { mu.Lock(); reads = append(reads, ex.ID); mu.Unlock() }
	if a := h.get("/?exit=x", "", nil); a.Status != 200 {
		t.Fatalf("status %d", a.Status)
	}
	if !reflect.DeepEqual(reads, []string{"x"}) {
		t.Fatalf("status reads = %v", reads)
	}
}

func TestThePageCarriesTheWordingAndKindForItsScript(t *testing.T) {
	h := newSingleHarness(t, nil)
	page := h.render(nil, nil, nil, nil)
	attribute := strings.SplitN(strings.SplitN(page, ` data-text="`, 2)[1], `"`, 2)[0]
	var got, want any
	if err := json.Unmarshal([]byte(html.UnescapeString(attribute)), &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(textJSON), &want); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("data-text does not carry the wording table")
	}
	mustContain(t, page, ` data-kind="overlay" `)
	// The browser has no wording or tier logic of its own.
	script, err := readStatic("panel.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"egressTier", "exit_confirmed", "Secure connection", "provider-confirmed", "data.view"} {
		if strings.Contains(string(script), gone) {
			t.Errorf("panel.js holds %q", gone)
		}
	}
}

func TestTheWordingTableMatchesTheWordsTheServerUses(t *testing.T) {
	// textJSON is what json.dumps(TEXT) wrote; the parsed table drives the page.
	if text.Connection["overlay"]["applying"] != "Switching route" || text.Connection["sidecar"]["applying"] != "Switching server" ||
		text.Drop["sidecar"] != "Open connections through the tunnel will drop." || len(text.Reason) != 10 || len(text.Checks) != len(verdict.CheckNames) {
		t.Fatalf("wording = %+v", text)
	}
	for _, name := range verdict.CheckNames {
		if text.Checks[name] == "" {
			t.Errorf("no wording for check %s", name)
		}
	}
}

func TestAFailedExitShowsNoTierAndNoAddress(t *testing.T) {
	h := newSingleHarness(t, nil)
	result := legacy("ok", map[string]any{"egress_tier": "tunnel", "exit_confirmed": false})
	page := h.render(request("se-sto-wg-001"), result, nil, nil)
	// Mullvad has its own check: a tunnel tier isn't enough.
	mustContain(t, page, `data-state="failed"`, `<dd data-f="egress_tier">not confirmed</dd>`, `<span data-current-ip>—</span>`)
}

// -- sidecar wording -------------------------------------------------------------------

func sidecarPage(t *testing.T, result, desired map[string]any) string {
	h := setupExit(t, "gluetun-surfshark", "sidecar", result, desired)
	ex := h.exit("x")
	status := h.srv.readStatus(ex)
	return h.srv.renderIndex(IndexPage{Exit: ex, Status: status, CSRFToken: "tok"})
}

func TestASidecarIsATunnelAndSaysWhatItCouldntCheck(t *testing.T) {
	page := sidecarPage(t, unmeasurableSidecar(), request(serverOf("gluetun-surfshark")))
	mustContain(t, page, `<span class="brand-kicker">Molebridge / tunnel control</span>`,
		`<h2>Example tunnel <span class="provider-note">via gluetun</span></h2>`,
		`switched, egress unverified</span>`,
		`<p class="note note-negative">Switched; the egress couldn&#x27;t be compared with this host&#x27;s address.<br><span class="subdue small" data-next>Re-checking at 18:01:00 UTC.</span></p>`,
		`<dd data-check="traffic_protection" data-check-state="not-checked">not checked by Molebridge (gluetun&#x27;s firewall)</dd>`,
		`<dd data-check="routing" data-check-state="n/a">not applicable</dd>`,
		`<dd data-check="egress" data-check-state="fail">failed: this host&#x27;s address can&#x27;t be measured</dd>`,
		"Connection unverified")
	mustNotContain(t, page, "data-retry")
}

func TestASidecarSwitchDropsTunnelConnections(t *testing.T) {
	page := sidecarPage(t, schema2(recOpts{Provider: "gluetun-surfshark", Kind: "sidecar", Status: "applying"}),
		request("us-nyc.prod.surfshark.com", strings.Repeat("b", 32)))
	mustContain(t, page, `<span data-connection-label>Switching server</span>`,
		"Leaving us-chi.prod.surfshark.com. Open connections through the tunnel will drop.")
}

func TestAnOverlayKeepsItsExitWording(t *testing.T) {
	h := setupExit(t, "mullvad", "overlay", schema2(recOpts{Status: "applying"}), request("se-got-wg-001", strings.Repeat("b", 32)))
	ex := h.exit("x")
	page := h.srv.renderIndex(IndexPage{Exit: ex, Status: h.srv.readStatus(ex), CSRFToken: "tok"})
	mustContain(t, page, "Molebridge / exit control", "<h2>Example exit", "Switching route", "Open connections through the exit will drop.")
	single := newSingleHarness(t, nil)
	mustContain(t, single.render(nil, nil, nil, nil), "<h2>Current exit</h2>")
}

// -- the exit kind -----------------------------------------------------------------------

func TestPanelExitsTakeAnOptionalKind(t *testing.T) {
	exits, err := ParseExits("a=mullvad, b=gluetun-mullvad/sidecar:Side car, c=gluetun-ivpn/overlay, d=gluetun-surfshark/sidecar", "/state")
	if err != nil {
		t.Fatal(err)
	}
	label := func(p string) string { spec, _ := providers.Lookup(p); return spec.Label }
	want := [][4]string{{"a", "mullvad", "overlay", "Mullvad"}, {"b", "gluetun-mullvad", "sidecar", "Side car"},
		{"c", "gluetun-ivpn", "overlay", label("gluetun-ivpn")}, {"d", "gluetun-surfshark", "sidecar", label("gluetun-surfshark")}}
	for i, e := range exits {
		if got := [4]string{e.ID, e.Provider, e.Kind, e.Label}; got != want[i] {
			t.Errorf("exit %d = %v, want %v", i, got, want[i])
		}
	}
	_, err = ParseExits("a=mullvad/sidecar", "/state")
	if err == nil || err.Error() != "PANEL_EXITS: a sidecar exit needs a gluetun provider (gluetun-<name>/sidecar), in 'a=mullvad/sidecar'" {
		t.Fatalf("err = %v", err)
	}
	for _, bad := range []string{"a=gluetun-mullvad/tunnel", "a=gluetun-mullvad/", "a=gluetun-mullvad/Sidecar"} {
		if _, err := ParseExits(bad, "/state"); err == nil || !strings.HasPrefix(err.Error(), "PANEL_EXITS: the kind after / is overlay or sidecar") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestAnExitMessageQuotesTheEntryAsPythonDid(t *testing.T) {
	for entry, want := range map[string]string{
		"Home=mullvad": "PANEL_EXITS: exit ids are 1-32 of a-z, 0-9 and -, in 'Home=mullvad'",
		"a=it's=x":     `PANEL_EXITS: provider must be one of ` + strings.Join(providers.IDs(), ", ") + `, in "a=it's=x"`,
	} {
		if _, err := ParseExits(entry, "/state"); err == nil || err.Error() != want {
			t.Errorf("%q: %v", entry, err)
		}
	}
}

func TestASingleExitReadsExitKindAtStart(t *testing.T) {
	for _, tc := range []struct {
		env  map[string]string
		kind string
		err  string
	}{
		{map[string]string{"EXIT_KIND": "sidecar", "PROVIDER": "gluetun-mullvad"}, "sidecar", ""},
		{map[string]string{"EXIT_KIND": "", "PROVIDER": "mullvad"}, "overlay", ""},
		{map[string]string{"EXIT_KIND": "sidecar", "PROVIDER": "mullvad"}, "", "a sidecar exit needs a gluetun provider (PROVIDER=gluetun-<name>)"},
		{map[string]string{"EXIT_KIND": "tunnel"}, "", "EXIT_KIND must be overlay or sidecar"},
		// PANEL_EXITS names each exit's kind; EXIT_KIND is then unused.
		{map[string]string{"EXIT_KIND": "tunnel", "PANEL_EXITS": "a=mullvad"}, "", ""},
	} {
		cfg, err := ConfigFromEnv(tc.env)
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%v: %v", tc.env, err)
		case tc.err != "" && (err == nil || err.Error() != tc.err):
			t.Errorf("%v: err = %v, want %q", tc.env, err, tc.err)
		case tc.err == "" && len(cfg.Exits) == 0 && cfg.Single.Kind != tc.kind:
			t.Errorf("%v: kind %q, want %q", tc.env, cfg.Single.Kind, tc.kind)
		}
	}
}

func TestSettingsRefusals(t *testing.T) {
	for env, want := range map[string]string{
		"PROVIDER=examplevpn":                   "PROVIDER must be one of",
		"PANEL_EXITS=a=pia,a=mullvad":           "duplicate exit id 'a'",
		"PANEL_OIDC_CLIENT_ID=x":                "PANEL_OIDC_CLIENT_ID is set but PANEL_OIDC_ISSUER is not",
		"PANEL_OIDC_ISSUER=http://example.test": "PANEL_OIDC_ISSUER must be an https URL",
	} {
		k, v, _ := strings.Cut(env, "=")
		if _, err := ConfigFromEnv(map[string]string{k: v}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", env, err)
		}
	}
	cfg, err := ConfigFromEnv(map[string]string{})
	if err != nil || cfg.StateDir != "/state" || cfg.Single.DesiredPath != "/state/panel/desired.json" ||
		cfg.Settings.Title != "Switchyard" || cfg.Settings.HostLabel != "this exit" || cfg.Settings.HomeLabel != "Home" {
		t.Fatalf("defaults: %+v, %v", cfg, err)
	}
	cfg, err = ConfigFromEnv(map[string]string{"PANEL_TITLE": "", "PANEL_HOST_LABEL": "", "STATE_DIR": "/s"})
	if err != nil || cfg.Settings.Title != "Switchyard" || cfg.Settings.HostLabel != "" || cfg.Single.ResultPath != "/s/applier/result.json" {
		t.Fatalf("empty settings: %+v, %v", cfg.Settings, err)
	}
}

// -- the switch gate (D8) -------------------------------------------------------------------------

type gate struct {
	*harness
	ex           Exit
	nonce, token string
}

func newGate(t *testing.T, result, desired map[string]any) *gate {
	t.Helper()
	h := setupExit(t, "mullvad", "overlay", result, desired)
	ex := h.exit("x")
	mustWrite(t, ex.RelaysPath, catalogue(relayEntry("se-sto-wg-001", nil), relayEntry("se-got-wg-001", nil)))
	// A configured exit's page has no form, so no token: mint one as the
	// panel would have.
	nonce := newCSRFNonce()
	return &gate{h, ex, nonce, h.srv.csrfToken(nonce, "")}
}

func (g *gate) post(server, token string) answer {
	return g.harness.post("/select", [][2]string{{"server", server}, {"csrf_token", token}, {"exit", "x"}}, "csrf_nonce="+g.nonce, "")
}

const busyMessage = "A switch is in progress; wait for it to finish."

func TestASwitchInProgressRefusesAnother(t *testing.T) {
	for name, tc := range map[string]struct{ result, desired map[string]any }{
		"applying":                 {schema2(recOpts{Status: "applying"}), request("se-sto-wg-001")},
		"request not acknowledged": {schema2(recOpts{}), request("se-got-wg-001", strings.Repeat("b", 32))},
		"legacy applying":          {legacy("applying", nil), request("se-sto-wg-001")},
	} {
		t.Run(name, func(t *testing.T) {
			g := newGate(t, tc.result, tc.desired)
			before := readDesired(g.ex)
			a := g.post("se-got-wg-001", g.token)
			if a.Status != 409 || a.Body != busyMessage {
				t.Fatalf("%d %q", a.Status, a.Body)
			}
			if !reflect.DeepEqual(readDesired(g.ex), before) {
				t.Fatal("the request file changed")
			}
		})
	}
}

func TestGateOrderCSRFThenConfigurationThenSwitching(t *testing.T) {
	configured := schema2(recOpts{Status: "applying", Configured: "se-sto-wg-001", Source: "configured"})
	g := newGate(t, configured, nil)
	a := g.post("se-got-wg-001", strings.Repeat("0", 64))
	if a.Status != 403 || a.Body != "invalid or missing csrf token" {
		t.Fatalf("%d %q", a.Status, a.Body)
	}
	a = g.post("se-got-wg-001", g.token)
	if a.Status != 403 || a.Body != "Exit is set in configuration; change SERVER to choose another server." {
		t.Fatalf("%d %q", a.Status, a.Body)
	}
	if readDesired(g.ex) != nil {
		t.Fatal("a configured exit got a request")
	}
}

func TestOnlyAVisibleSwitchBlocks(t *testing.T) {
	for name, result := range map[string]map[string]any{
		"stale applying": schema2(recOpts{At: "2000-01-01T00:00:00Z", Status: "applying"}),
		"no status":      nil,
		"connected":      schema2(recOpts{}),
		"failed":         schema2(recOpts{Status: "failed", Checks: map[string]any{"egress": "fail"}}),
	} {
		t.Run(name, func(t *testing.T) {
			// Stale or missing status (unknown) doesn't block: the applier decides.
			g := newGate(t, result, request("se-sto-wg-001"))
			a := g.post("se-got-wg-001", g.token)
			if a.Status != 303 {
				t.Fatalf("%d %q", a.Status, a.Body)
			}
			if readDesired(g.ex)["server"] != "se-got-wg-001" {
				t.Fatalf("desired = %v", readDesired(g.ex))
			}
		})
	}
}

func TestConcurrentRequestsWriteOnce(t *testing.T) {
	// Six requests read the same connected snapshot; the lock lets only the
	// first write, and the others then see the switch it started.
	g := newGate(t, schema2(recOpts{}), request("se-sto-wg-001"))
	g.srv.assessed = func() { time.Sleep(200 * time.Millisecond) } // widen the window between assessing and writing
	servers := []string{"se-got-wg-001", "se-sto-wg-001", "se-got-wg-001", "se-sto-wg-001", "se-got-wg-001", "se-sto-wg-001"}
	statuses := make([]int, len(servers))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i, server := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			statuses[i] = g.post(server, g.token).Status
		}()
	}
	close(start)
	wg.Wait()
	counts := map[int]int{}
	for _, s := range statuses {
		counts[s]++
	}
	if counts[303] != 1 || counts[409] != 5 {
		t.Fatalf("statuses = %v", statuses)
	}
	written := readDesired(g.ex)["server"]
	if written != "se-got-wg-001" && written != "se-sto-wg-001" {
		t.Fatalf("desired = %v", written)
	}
}

func TestEachExitHasItsOwnLock(t *testing.T) {
	h := newHarness(t, map[string]string{"PANEL_EXITS": "a=mullvad,b=mullvad"}, nil)
	a, b := h.exit("a"), h.exit("b")
	la := h.srv.selectLock(a)
	if la != h.srv.selectLock(a) || la == h.srv.selectLock(b) {
		t.Fatal("locks are not per exit")
	}
}

var _ = validate.Members
