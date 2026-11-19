package panel

// The proxy view (proxy.go): PANEL_PROXY_STATUS, /api/status's `proxy`, the
// page's section, and that none of it touches the exit's verdict.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

// proxyNow is the clock of every proxy test: five seconds after the
// fixtures' checked_at.
var proxyNow = time.Date(2026, 11, 19, 18, 0, 5, 0, time.UTC)

// proxyFixtures are testdata/proxy's files and what the proxy view makes of
// each: state, label, reasons.
var proxyFixtures = map[string]struct {
	state, label string
	reasons      []string
}{
	"ok":        {"ok", "serving", []string{}},
	"refusing":  {"refusing", "refusing", []string{"tunnel-not-ok"}},
	"stale":     {"unknown", "status stale", []string{"status-stale"}},
	"malformed": {"unknown", "invalid status record", []string{"invalid-record"}},
	"hostile":   {"failed", "listener down", []string{"listener-down"}},
	"missing":   {"unknown", "awaiting status", []string{"no-status"}},
}

// copyFixture puts testdata/proxy/<name>.json at path ("missing" puts
// nothing there).
func copyFixture(t *testing.T, name, path string) {
	t.Helper()
	if name == "missing" {
		return
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "proxy", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// proxyHarness is a panel with one Mullvad exit `x`, connected at proxyNow,
// with the proxy fixture beside it when withProxy is set.
func proxyHarness(t *testing.T, fixture string, withProxy bool) *harness {
	t.Helper()
	env := map[string]string{"PANEL_EXITS": "x=mullvad:Example"}
	var proxyPath string
	if withProxy {
		// STATE_DIR is the harness's own directory, made in newHarness; the
		// path only has to be absolute and clean here.
		proxyPath = filepath.Join(t.TempDir(), "x", "proxy", "proxy.json")
		env["PANEL_PROXY_STATUS"] = "x=" + proxyPath
	}
	h := newHarness(t, env, func(o *Options) { o.Now = func() time.Time { return proxyNow } })
	ex := h.exit("x")
	mustWrite(t, ex.ResultPath, schema2(recOpts{At: "2026-11-19T18:00:00Z"}))
	mustWrite(t, ex.DesiredPath, request(serverOf("mullvad"), requestID, "2026-11-19T17:59:50Z"))
	if withProxy {
		copyFixture(t, fixture, proxyPath)
	}
	return h
}

func decodeBody(t *testing.T, a answer) map[string]any {
	t.Helper()
	if a.Status != 200 {
		t.Fatalf("status %d: %s", a.Status, a.Body)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(a.Body), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestProxyStatusInAPIStatus(t *testing.T) {
	for name, want := range proxyFixtures {
		t.Run(name, func(t *testing.T) {
			h := proxyHarness(t, name, true)
			body := decodeBody(t, h.get("/api/status?exit=x", "", nil))
			proxy, ok := body["proxy"].(map[string]any)
			if !ok {
				t.Fatalf("no proxy in %s", body)
			}
			if proxy["guarantee"] != "opt-in" || proxy["state"] != want.state || proxy["label"] != want.label {
				t.Fatalf("proxy %v, want %s %q", proxy, want.state, want.label)
			}
			reasons := []string{}
			for _, r := range proxy["reasons"].([]any) {
				reasons = append(reasons, r.(string))
			}
			if !reflect.DeepEqual(reasons, want.reasons) {
				t.Fatalf("reasons %v, want %v", reasons, want.reasons)
			}
			if want.state == "unknown" {
				// Nothing of a record that failed validation is passed on.
				for _, key := range []string{"message", "tunnel", "checked_at", "listen", "sessions", "connections", "servers"} {
					if proxy[key] != nil {
						t.Fatalf("%s = %v for an unknown proxy", key, proxy[key])
					}
				}
			}
		})
	}
}

func TestProxyDetailsComeFromTheValidatedRecord(t *testing.T) {
	h := proxyHarness(t, "ok", true)
	proxy := decodeBody(t, h.get("/api/status?exit=x", "", nil))["proxy"].(map[string]any)
	raw, _ := json.Marshal(proxy)
	want := `{"checked_at":"2026-11-19T18:00:00Z","connections":{"failed":12,"open":7,"total":1204},` +
		`"guarantee":"opt-in","label":"serving","listen":"127.0.0.1:1080","message":"Serving.","reasons":[],` +
		`"servers":{"benched":[{"reason":"handshake timed out","server":"de-fra-wg-003","until":"2026-11-19T18:02:00Z"}],"known":512},` +
		`"sessions":3,"state":"ok","tunnel":"ok"}`
	if string(raw) != want {
		t.Fatalf("proxy\n%s\nwant\n%s", raw, want)
	}
}

// exitParts is /api/status without `proxy`.
func exitParts(t *testing.T, h *harness) map[string]any {
	t.Helper()
	body := decodeBody(t, h.get("/api/status?exit=x", "", nil))
	delete(body, "proxy")
	return body
}

func TestTheExitsVerdictIsTheSameWithOrWithoutTheProxy(t *testing.T) {
	without := proxyHarness(t, "", false)
	base := exitParts(t, without)
	if v := base["verdict"].(map[string]any); v["state"] != "ok" || v["label"] != "connected" {
		t.Fatalf("the fixture exit is not connected: %v", v)
	}
	if _, present := decodeBody(t, without.get("/api/status?exit=x", "", nil))["proxy"]; present {
		t.Fatal("proxy in /api/status without PANEL_PROXY_STATUS")
	}
	baseExits := without.get("/api/exits", "", nil).Body
	basePage := without.get("/?exit=x", "", nil).Body
	if strings.Contains(basePage, "data-proxy") {
		t.Fatal("a proxy view without PANEL_PROXY_STATUS")
	}
	exitPill := regexp.MustCompile(`<span class="pill pill-[a-z]+" data-state-pill[^>]*>[^<]*</span>`)
	for name := range proxyFixtures {
		t.Run(name, func(t *testing.T) {
			h := proxyHarness(t, name, true)
			if got := exitParts(t, h); !reflect.DeepEqual(got, base) {
				t.Fatalf("the exit's status changed with the proxy:\n%v\n%v", got, base)
			}
			if got := h.get("/api/exits", "", nil).Body; got != baseExits {
				t.Fatalf("/api/exits changed: %s", got)
			}
			if got := h.get("/readyz?exit=x", "", nil); got.Status != 200 {
				t.Fatalf("/readyz %d with the proxy %s", got.Status, name)
			}
			page := h.get("/?exit=x", "", nil).Body
			if exitPill.FindString(page) != exitPill.FindString(basePage) || exitPill.FindString(page) == "" {
				t.Fatalf("the exit's pill changed: %q", exitPill.FindString(page))
			}
			// The switch controls are all still there.
			for _, part := range []string{`id="select-form"`, `data-filter`, `id="fastest"`} {
				if strings.Count(page, part) != strings.Count(basePage, part) {
					t.Fatalf("%s changed with the proxy", part)
				}
			}
		})
	}
}

// proxySection is the page's proxy view.
func proxySection(t *testing.T, page string) string {
	t.Helper()
	start := strings.Index(page, `<section class="widget proxy-widget"`)
	if start < 0 {
		t.Fatal("no proxy view on the page")
	}
	end := strings.Index(page[start:], "</section>")
	return page[start : start+end]
}

func TestProxyViewOnThePage(t *testing.T) {
	h := proxyHarness(t, "ok", true)
	section := proxySection(t, h.get("/?exit=x", "", nil).Body)
	guarantee := strings.Index(section, `class="proxy-guarantee">Opt-in: connections sent to the proxy leave through the tunnel or fail; nothing else is covered.</p>`)
	if guarantee < 0 || guarantee > strings.Index(section, "<dl>") {
		t.Fatalf("the guarantee is not first:\n%s", section)
	}
	for _, want := range []string{
		`<span class="pill pill-ok" data-proxy-pill>serving</span>`,
		`<dd data-proxy-f="listen">127.0.0.1:1080</dd>`,
		`<dd data-proxy-f="sessions">3</dd>`,
		`<dd data-proxy-f="connections">7 open, 1204 total, 12 failed</dd>`,
		`<dd data-proxy-f="servers">512 known, 1 benched</dd>`,
		`<li><span class="bench-server">de-fra-wg-003</span><span class="bench-until subdue">until 18:02:00 UTC</span><span class="bench-reason">handshake timed out</span></li>`,
		`data-proxy-note hidden`,
	} {
		if !strings.Contains(section, want) {
			t.Fatalf("no %s in\n%s", want, section)
		}
	}
	// Read-only: no controls of any kind.
	for _, control := range []string{"<form", "<button", "<input", "<select", "<a "} {
		if strings.Contains(section, control) {
			t.Fatalf("a control (%s) in the proxy view", control)
		}
	}
	// The embed stays compact.
	if strings.Contains(h.get("/embed?exit=x", "", nil).Body, "data-proxy") {
		t.Fatal("the proxy view in the embed")
	}
}

func TestProxyViewStates(t *testing.T) {
	notes := map[string]string{
		"refusing":  `<p class="note" data-proxy-note>The exit&#x27;s verdict isn&#x27;t ok, so the proxy refuses new connections.</p>`,
		"stale":     `<p class="note note-negative" data-proxy-note>The proxy&#x27;s status is more than 30 seconds old.</p>`,
		"malformed": `<p class="note note-negative" data-proxy-note>proxy.json is malformed.</p>`,
		"missing":   `<p class="note note-negative" data-proxy-note>No proxy status yet: proxy.json is missing, or this panel can&#x27;t read it.</p>`,
	}
	for name, note := range notes {
		t.Run(name, func(t *testing.T) {
			want := proxyFixtures[name]
			section := proxySection(t, proxyHarness(t, name, true).get("/?exit=x", "", nil).Body)
			if !strings.Contains(section, note) {
				t.Fatalf("no %s in\n%s", note, section)
			}
			if !strings.Contains(section, fmt.Sprintf(`<span class="pill pill-%s" data-proxy-pill>%s</span>`, want.state, want.label)) {
				t.Fatalf("pill: %s", section)
			}
			if want.state == "unknown" {
				// Nothing from the file: every detail is unknown, no server is listed.
				if strings.Contains(section, "127.0.0.1") || strings.Contains(section, "de-fra-wg-003") ||
					!strings.Contains(section, `<dd data-proxy-f="sessions">—</dd>`) ||
					!strings.Contains(section, `data-proxy-benched-block hidden`) {
					t.Fatalf("details of an unknown proxy shown:\n%s", section)
				}
			}
		})
	}
}

func TestProxyViewEscapesEverything(t *testing.T) {
	h := proxyHarness(t, "hostile", true)
	page := h.get("/?exit=x", "", nil).Body
	section := proxySection(t, page)
	for _, raw := range []string{"<script", "<img", "</ul><", `" onmouseover`} {
		if strings.Contains(section, raw) {
			t.Fatalf("unescaped %q in\n%s", raw, section)
		}
	}
	for _, want := range []string{
		`&lt;script&gt;alert(1)&lt;/script&gt; &amp; &quot;quoted&quot;`,
		`127.0.0.1:1080&quot; onmouseover=&quot;alert(2)`,
		`&lt;img src=x onerror=alert(3)&gt;`,
		`&lt;/ul&gt;&lt;script&gt;alert(4)&lt;/script&gt;`,
	} {
		if !strings.Contains(section, want) {
			t.Fatalf("no %s in\n%s", want, section)
		}
	}
	// The page keeps to its one external script, and the CSP is unchanged.
	if n := strings.Count(page, "<script"); n != 1 || !strings.Contains(page, `<script src="/static/panel.js?v=`) {
		t.Fatalf("%d script elements", n)
	}
	without := proxyHarness(t, "", false)
	if a, b := h.get("/?exit=x", "", nil).Header.Get("Content-Security-Policy"), without.get("/?exit=x", "", nil).Header.Get("Content-Security-Policy"); a != b || a == "" {
		t.Fatalf("CSP %q, without the proxy %q", a, b)
	}
	if regexp.MustCompile(`<[^>]+\s(on[a-z]+|style)=`).MatchString(section) {
		t.Fatalf("an inline handler or style in\n%s", section)
	}
}

func TestProxyViewListsAtMostFiftyBenchedServers(t *testing.T) {
	h := proxyHarness(t, "ok", true)
	ex := h.exit("x")
	raw, err := os.ReadFile(ex.ProxyPath)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	var benched []any
	for i := 0; i < 53; i++ {
		benched = append(benched, map[string]any{"server": fmt.Sprintf("de-fra-wg-%03d", i+1), "until": "2026-11-19T18:02:00Z", "reason": "refused"})
	}
	record["servers"] = map[string]any{"known": 512, "benched": benched}
	// encoding/json writes the counts back as integers.
	out, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ex.ProxyPath, out, 0o600); err != nil {
		t.Fatal(err)
	}
	section := proxySection(t, h.get("/?exit=x", "", nil).Body)
	if n := strings.Count(section, `<span class="bench-server">`); n != 50 {
		t.Fatalf("%d benched servers listed", n)
	}
	if !strings.Contains(section, `<p class="subdue small" data-proxy-more>and 3 more</p>`) ||
		!strings.Contains(section, `512 known, 53 benched`) {
		t.Fatalf("no count of the rest:\n%s", section)
	}
}

func TestProxyStatusSetting(t *testing.T) {
	dir := t.TempDir()
	cfg, err := ConfigFromEnv(map[string]string{"STATE_DIR": dir, "PANEL_PROXY_STATUS": " /state/proxy/proxy.json "})
	if err != nil || cfg.Single.ProxyPath != "/state/proxy/proxy.json" {
		t.Fatalf("single exit: %v %+v", err, cfg)
	}
	cfg, err = ConfigFromEnv(map[string]string{"STATE_DIR": dir,
		"PANEL_EXITS":        "a=mullvad,b=pia/sidecar,c=nordvpn",
		"PANEL_PROXY_STATUS": "a=/state/a/proxy/proxy.json, b=/state/b/proxy/proxy.json"})
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{cfg.Exits[0].ProxyPath, cfg.Exits[1].ProxyPath, cfg.Exits[2].ProxyPath}; !reflect.DeepEqual(got,
		[]string{"/state/a/proxy/proxy.json", "/state/b/proxy/proxy.json", ""}) {
		t.Fatalf("paths %v", got)
	}
	cfg, err = ConfigFromEnv(map[string]string{"STATE_DIR": dir, "PANEL_EXITS": "a=mullvad"})
	if err != nil || cfg.Exits[0].ProxyPath != "" {
		t.Fatalf("unset: %v", err)
	}
	refused := []struct{ env map[string]string }{
		{map[string]string{"PANEL_PROXY_STATUS": "state/proxy/proxy.json"}},
		{map[string]string{"PANEL_PROXY_STATUS": "/state/../proxy.json"}},
		{map[string]string{"PANEL_PROXY_STATUS": "/"}},
		{map[string]string{"PROVIDER": "gluetun-mullvad", "PANEL_PROXY_STATUS": "/state/proxy/proxy.json"}},
		{map[string]string{"PANEL_EXITS": "a=mullvad", "PANEL_PROXY_STATUS": "/state/a/proxy/proxy.json"}},
		{map[string]string{"PANEL_EXITS": "a=mullvad", "PANEL_PROXY_STATUS": "b=/state/b/proxy/proxy.json"}},
		{map[string]string{"PANEL_EXITS": "a=mullvad", "PANEL_PROXY_STATUS": "a=/x.json,a=/y.json"}},
		{map[string]string{"PANEL_EXITS": "a=gluetun-mullvad", "PANEL_PROXY_STATUS": "a=/state/a/proxy/proxy.json"}},
		{map[string]string{"PANEL_EXITS": "a=mullvad", "PANEL_NETWORK_EXITS": "a", "PANEL_PROXY_STATUS": "a=/state/a/proxy/proxy.json"}},
	}
	for _, c := range refused {
		c.env["STATE_DIR"] = dir
		if _, err := ConfigFromEnv(c.env); err == nil || !strings.HasPrefix(err.Error(), "PANEL_PROXY_STATUS: ") {
			t.Errorf("%v: %v", c.env, err)
		}
	}
}

func TestSingleExitProxyView(t *testing.T) {
	proxyPath := filepath.Join(t.TempDir(), "proxy", "proxy.json")
	h := newHarness(t, map[string]string{"PANEL_PROXY_STATUS": proxyPath},
		func(o *Options) { o.Now = func() time.Time { return proxyNow } })
	copyFixture(t, "refusing", proxyPath)
	proxy := decodeBody(t, h.get("/api/status", "", nil))["proxy"].(map[string]any)
	if proxy["state"] != "refusing" {
		t.Fatalf("proxy %v", proxy)
	}
	if !strings.Contains(proxySection(t, h.get("/", "", nil).Body), "pill-refusing") {
		t.Fatal("no refusing pill")
	}
}
