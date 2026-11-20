package panel

// Single-provider views, byte for byte: the pages, /api/status, /api/exits
// and /metrics of single-provider exits, as the panel served them before
// multi-provider exits (docs/design/multi-provider.md, the panel) were
// built. testdata/single_provider_golden.json was generated from the panel
// before that piece and must not change; regenerate it only for a deliberate
// change of a single-provider view:
//
//	go test ./internal/panel -run TestSingleProviderViewsAreUnchanged -update-single-golden

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

var updateSingleGolden = flag.Bool("update-single-golden", false, "rewrite testdata/single_provider_golden.json")

const goldenSingleFile = "testdata/single_provider_golden.json"

var (
	goldenNow = time.Date(2026, 11, 19, 18, 0, 10, 0, time.UTC)
	goldenAt  = "2026-11-19T18:00:00Z"
	// The CSRF token is keyed by a random secret, and the static assets'
	// versions follow their content: neither is a view's wording.
	goldenToken   = regexp.MustCompile(`name="csrf_token" value="[^"]*"`)
	goldenVersion = regexp.MustCompile(`\?v=[0-9a-zA-Z_-]+`)
)

func goldenNormalize(body string) string {
	body = goldenToken.ReplaceAllString(body, `name="csrf_token" value="TOKEN"`)
	return goldenVersion.ReplaceAllString(body, "?v=V")
}

func goldenRequest(server string) map[string]any {
	return map[string]any{"server": server, "requested_at": goldenAt, "request_id": requestID}
}

func goldenMullvad() map[string]any {
	c := catalogue(relayEntry("se-sto-wg-001", nil),
		relayEntry("se-got-wg-001", map[string]any{"city": "Gothenburg", "location_code": "se-got", "ipv4_addr_in": "198.51.100.12"}),
		relayEntry("de-ber-wg-002", map[string]any{"city": "Berlin", "country": "Germany", "location_code": "de-ber", "owned": true, "ipv4_addr_in": "198.51.100.13"}))
	c["fetched_at"] = goldenAt
	return c
}

func goldenPIA() map[string]any {
	c := piaCatalogue("pia")
	c["fetched_at"] = goldenAt
	return c
}

func goldenNord() map[string]any {
	c := nordCatalogue("nordvpn")
	c["fetched_at"] = goldenAt
	return c
}

func goldenCatalogue(provider string) map[string]any {
	switch provider {
	case "pia":
		return goldenPIA()
	case "nordvpn":
		return goldenNord()
	}
	return goldenMullvad()
}

// goldenExitFiles writes one exit's state under dir (dir/applier and
// dir/panel).
func goldenExitFiles(t *testing.T, dir, provider string, result, desired map[string]any) {
	t.Helper()
	mustWrite(t, filepath.Join(dir, "applier", "relays.json"), goldenCatalogue(provider))
	mustWrite(t, filepath.Join(dir, "applier", "result.json"), result)
	mustWrite(t, filepath.Join(dir, "panel", "desired.json"), desired)
}

// goldenServe answers one GET from a server whose clock is goldenNow.
func goldenServe(t *testing.T, env map[string]string, paths []string) map[string]string {
	t.Helper()
	cfg, err := ConfigFromEnv(env)
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	srv := NewServer(cfg, Options{Now: func() time.Time { return goldenNow }, Log: &syncBuffer{}})
	out := map[string]string{}
	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "127.0.0.1:8080"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		out[path] = rec.Result().Status + "\n" + goldenNormalize(rec.Body.String())
	}
	return out
}

// goldenCases are single-provider panels and what they are asked.
func goldenCases(t *testing.T) map[string]string {
	t.Helper()
	views := map[string]string{}
	add := func(name string, answers map[string]string) {
		for path, body := range answers {
			views[name+" "+path] = body
		}
	}
	rec := func(o recOpts) map[string]any {
		o.At = goldenAt
		r := schema2(o)
		r["requested_server"], r["request_id"] = r["server"], requestID
		return r
	}
	single := []string{"/", "/embed", "/api/status", "/readyz", "/metrics"}

	type one struct {
		name, provider, kind string
		result, desired      map[string]any
		extraEnv             map[string]string
	}
	ones := []one{
		{"mullvad-ok", "mullvad", "", rec(recOpts{}), goldenRequest("se-sto-wg-001"), nil},
		{"mullvad-applying", "mullvad", "", rec(recOpts{}), map[string]any{"server": "se-got-wg-001", "requested_at": goldenAt,
			"request_id": strings.Repeat("b", 32)}, nil},
		{"mullvad-failed", "mullvad", "", rec(recOpts{Status: "failed", Checks: map[string]any{"egress": "fail"}}), goldenRequest("se-sto-wg-001"), nil},
		{"mullvad-no-status", "mullvad", "", nil, nil, nil},
		{"mullvad-configured", "mullvad", "", func() map[string]any {
			r := rec(recOpts{Configured: "se-sto-wg-001", Source: "configured"})
			r["request_id"], r["requested_server"] = nil, nil
			return r
		}(), nil, nil},
		{"pia-forwarding", "pia", "", rec(recOpts{Provider: "pia", Extra: map[string]any{"port_forward": true, "forwarded_port": 43210}}),
			goldenRequest("ex_example"), nil},
		{"pia-sidecar", "pia", "sidecar", func() map[string]any {
			r := nativePIASidecar()
			r["checked_at"] = goldenAt
			for _, c := range r["checks"].(map[string]any) {
				if m, ok := c.(map[string]any); ok {
					if _, has := m["at"]; has {
						m["at"] = goldenAt
					}
				}
			}
			r["requested_server"], r["request_id"] = r["server"], requestID
			return r
		}(), goldenRequest("ex_example"), nil},
		{"nordvpn-ok", "nordvpn", "", rec(recOpts{Provider: "nordvpn"}), goldenRequest("us9001.nordvpn.com"), nil},
	}
	for _, o := range ones {
		dir := t.TempDir()
		goldenExitFiles(t, dir, o.provider, o.result, o.desired)
		env := map[string]string{"STATE_DIR": dir, "PROVIDER": o.provider}
		if o.kind != "" {
			env["EXIT_KIND"] = o.kind
		}
		add(o.name, goldenServe(t, env, single))
	}

	// PANEL_EXITS: every native provider, and a gluetun sidecar beside them.
	dir := t.TempDir()
	goldenExitFiles(t, filepath.Join(dir, "home"), "mullvad", rec(recOpts{}), goldenRequest("se-sto-wg-001"))
	goldenExitFiles(t, filepath.Join(dir, "away"), "pia",
		rec(recOpts{Provider: "pia", Extra: map[string]any{"port_forward": true, "forwarded_port": 43210}}), goldenRequest("ex_example"))
	goldenExitFiles(t, filepath.Join(dir, "nord"), "nordvpn", rec(recOpts{Provider: "nordvpn", Status: "failed",
		Checks: map[string]any{"handshake": "fail"}}), goldenRequest("us9001.nordvpn.com"))
	mustWrite(t, filepath.Join(dir, "side", "applier", "relays.json"), map[string]any{"fetched_at": goldenAt, "provider": "gluetun-mullvad",
		"source": "gluetun", "data_timestamp": goldenAt, "relays": goldenMullvad()["relays"]})
	add("exits", goldenServe(t, map[string]string{"STATE_DIR": dir,
		"PANEL_EXITS": "home=mullvad, away=pia:PIA Chicago, nord=nordvpn/overlay, side=gluetun-mullvad/sidecar:Downloads"},
		[]string{"/?exit=home", "/?exit=away", "/embed?exit=nord", "/?exit=side", "/api/status?exit=away", "/api/exits",
			"/readyz", "/metrics", "/api/status?exit=nord"}))
	return views
}

func TestSingleProviderViewsAreUnchanged(t *testing.T) {
	views := goldenCases(t)
	if *updateSingleGolden {
		raw, err := json.MarshalIndent(views, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenSingleFile, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(goldenSingleFile)
	if err != nil {
		t.Fatalf("%v (generate it with -update-single-golden)", err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		got, ok := views[name]
		if !ok {
			t.Errorf("%s: not served", name)
			continue
		}
		if got != want[name] {
			t.Errorf("%s changed:\n%s", name, firstDifference(want[name], got))
		}
	}
	if len(views) != len(want) {
		t.Errorf("%d views, the golden file has %d", len(views), len(want))
	}
}

// firstDifference shows where two texts part.
func firstDifference(want, got string) string {
	i := 0
	for i < len(want) && i < len(got) && want[i] == got[i] {
		i++
	}
	from := max(0, i-120)
	return "want …" + want[from:min(len(want), i+120)] + "…\n got …" + got[from:min(len(got), i+120)] + "…"
}
