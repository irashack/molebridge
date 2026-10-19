package panel

// Ported from panel/test_app.py: RenderEscapingTests, CsrfAndOriginUnitTests
// (the CSRF part; the allowlists are in hosts_test.go), ServerIntegrationTests,
// FramingAndRenderTests, SwitcherRenderTests, EmbedAndApiIntegrationTests,
// PwaTests, SigtermTests and RegistryPanelTests.

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
)

// relayEntry is a Mullvad catalogue entry as the applier writes it.
func relayEntry(hostname string, extra map[string]any) map[string]any {
	e := map[string]any{"hostname": hostname, "country": "Sweden", "city": "Stockholm", "location_code": "se-sto",
		"public_key": validPubkey, "ipv4_addr_in": "198.51.100.10"}
	for k, v := range extra {
		e[k] = v
	}
	return e
}

func catalogue(entries ...map[string]any) map[string]any {
	relays := map[string]any{}
	for _, e := range entries {
		relays[e["hostname"].(string)] = e
	}
	return map[string]any{"fetched_at": nowISO(), "relays": relays}
}

// render is render_index_html for a harness's single exit: the page for a
// request, a result and a catalogue (all may be nil).
func (h *harness) render(desired, result, snapshot map[string]any, change func(*IndexPage)) string {
	h.t.Helper()
	ex := h.srv.Single
	var d, r any
	if desired != nil {
		d = desired
	}
	if result != nil {
		r = result
	}
	page := IndexPage{Exit: ex, Status: h.srv.judge(ex, d, r), CSRFToken: "tok"}
	if snapshot != nil {
		page.RelaysData = snapshot
		page.Relays = providers.SnapshotRelays(snapshot, ex.Provider)
	}
	if change != nil {
		change(&page)
	}
	return h.srv.renderIndex(page)
}

func mustContain(t *testing.T, page string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(page, want) {
			t.Errorf("page does not contain %q", want)
		}
	}
}

func mustNotContain(t *testing.T, page string, unwanted ...string) {
	t.Helper()
	for _, bad := range unwanted {
		if strings.Contains(page, bad) {
			t.Errorf("page contains %q", bad)
		}
	}
}

func TestPageEscapesMaliciousCityName(t *testing.T) { // RenderEscapingTests
	h := newHarness(t, nil, nil)
	entry := relayEntry("se-sto-wg-001", map[string]any{"city": "<script>alert(1)</script>"})
	page := h.render(nil, nil, catalogue(entry), nil)
	mustNotContain(t, page, "<script>alert(1)</script>")
	mustContain(t, page, "&lt;script&gt;alert(1)&lt;/script&gt;")
}

func TestCSRFRoundTrip(t *testing.T) { // CsrfAndOriginUnitTests
	h := newHarness(t, nil, nil)
	nonce := newCSRFNonce()
	token := h.srv.csrfToken(nonce, "")
	if len(nonce) != 32 {
		t.Fatalf("nonce %q", nonce)
	}
	if !h.srv.verifyCSRF(nonce, true, token, "") {
		t.Error("a good token failed")
	}
	if h.srv.verifyCSRF(nonce, true, "wrong-token", "") {
		t.Error("a wrong token passed")
	}
	if h.srv.verifyCSRF("", false, token, "") {
		t.Error("a missing nonce passed")
	}
	if h.srv.verifyCSRF(nonce, true, "", "") {
		t.Error("a missing token passed")
	}
	if h.srv.verifyCSRF(nonce, true, strings.Repeat("é", 64), "") {
		t.Error("a non-hex token passed")
	}
	// A token bound to a session does not verify unbound, nor for another.
	bound := h.srv.csrfToken(nonce, "key-1")
	if h.srv.verifyCSRF(nonce, true, bound, "") || h.srv.verifyCSRF(nonce, true, bound, "key-2") || !h.srv.verifyCSRF(nonce, true, bound, "key-1") {
		t.Error("session binding is wrong")
	}
}

// -- ServerIntegrationTests ------------------------------------------------------

func newSingleHarness(t *testing.T, env map[string]string) *harness {
	t.Helper()
	h := newHarness(t, env, nil)
	mustWrite(t, h.srv.Single.RelaysPath, catalogue(relayEntry("se-sto-wg-001", map[string]any{"city": "Stockholm"})))
	return h
}

func (h *harness) indexTokens() (int, string, string) {
	h.t.Helper()
	page := h.get("/", "", nil)
	m := csrfTokenInPage.FindStringSubmatch(page.Body)
	if m == nil {
		h.t.Fatal("no token in the page")
	}
	return page.Status, page.Cookies["csrf_nonce"].Value, m[1]
}

func TestHealthz(t *testing.T) {
	h := newSingleHarness(t, nil)
	if a := h.get("/healthz", "", nil); a.Status != 200 || a.Body != "ok" {
		t.Fatalf("healthz = %d %q", a.Status, a.Body)
	}
}

func TestPostWithoutCSRFIsRejected(t *testing.T) {
	h := newSingleHarness(t, nil)
	if status, _, _ := h.indexTokens(); status != 200 {
		t.Fatalf("index = %d", status)
	}
	a := h.post("/select", [][2]string{{"server", "se-sto-wg-001"}}, "", "")
	if a.Status != 403 || readDesired(h.srv.Single) != nil {
		t.Fatalf("status %d, desired %v", a.Status, readDesired(h.srv.Single))
	}
}

func TestPostBadOriginIsRejected(t *testing.T) {
	h := newSingleHarness(t, nil)
	_, nonce, token := h.indexTokens()
	a := h.post("/select", [][2]string{{"server", "se-sto-wg-001"}, {"csrf_token", token}}, "csrf_nonce="+nonce, "https://evil.example.com")
	if a.Status != 403 || readDesired(h.srv.Single) != nil {
		t.Fatalf("status %d, desired %v", a.Status, readDesired(h.srv.Single))
	}
}

func TestPostUnlistedServerIsRejected(t *testing.T) {
	h := newSingleHarness(t, nil)
	_, nonce, token := h.indexTokens()
	a := h.post("/select", [][2]string{{"server", "not-in-allowlist-wg-999"}, {"csrf_token", token}}, "csrf_nonce="+nonce, "")
	if a.Status != 400 || readDesired(h.srv.Single) != nil {
		t.Fatalf("status %d, desired %v", a.Status, readDesired(h.srv.Single))
	}
}

// The page and the latency probes use the cached catalogue, which a new
// snapshot replaces even when it has the same size and modification time;
// a switch always reads the file itself.
func TestCachedCatalogueFollowsTheFileAndSwitchReadsItFresh(t *testing.T) {
	h := newSingleHarness(t, nil)
	ex := h.srv.Single
	_, nonce, token := h.indexTokens()
	mustContain(t, h.get("/", "", nil).Body, "se-sto-wg-001")
	mustWrite(t, ex.RelaysPath, catalogue(relayEntry("se-sto-wg-002", map[string]any{"city": "Stockholm"})))
	page := h.get("/", "", nil).Body
	mustContain(t, page, "se-sto-wg-002")
	mustNotContain(t, page, "se-sto-wg-001")
	if _, relays := h.srv.cachedSnapshot(ex); !relays.Has("se-sto-wg-002") || relays.Has("se-sto-wg-001") {
		t.Fatalf("cache kept the old catalogue")
	}
	// Plant the old catalogue as the current file's cache entry: a switch
	// must not trust it.
	h.srv.relayMu.Lock()
	entry := h.srv.relayCache[ex.RelaysPath]
	entry.relays = providers.SnapshotRelays(catalogue(relayEntry("se-sto-wg-001", nil)), "mullvad")
	h.srv.relayCache[ex.RelaysPath] = entry
	h.srv.relayMu.Unlock()
	mustContain(t, h.get("/", "", nil).Body, "se-sto-wg-001")
	a := h.post("/select", [][2]string{{"server", "se-sto-wg-001"}, {"csrf_token", token}}, "csrf_nonce="+nonce, "")
	if a.Status != 400 || readDesired(ex) != nil {
		t.Fatalf("status %d, desired %v", a.Status, readDesired(ex))
	}
}

func TestAFailedRequestWriteIsLogged(t *testing.T) {
	h := newSingleHarness(t, nil)
	_, nonce, token := h.indexTokens()
	// A directory where the request file goes: the rename over it fails.
	if err := os.MkdirAll(filepath.Join(h.srv.Single.DesiredPath, "occupied"), 0o755); err != nil {
		t.Fatal(err)
	}
	h.log.Reset()
	a := h.post("/select", [][2]string{{"server", "se-sto-wg-001"}, {"csrf_token", token}}, "csrf_nonce="+nonce, "")
	if a.Status != 500 || a.Body != "internal error" {
		t.Fatalf("status %d %q", a.Status, a.Body)
	}
	log := h.log.String()
	mustContain(t, log, "Z switch failed: cannot write the request file: rename ")
	mustContain(t, log, h.srv.Single.DesiredPath+": ")
	mustNotContain(t, log, token)
}

func TestMalformedOriginIsRejectedWithoutLoggingInput(t *testing.T) {
	h := newSingleHarness(t, nil)
	for _, origin := range []string{"http://[", "https://private.example.test"} {
		h.log.Reset()
		a := h.do("POST", "/select", nil, map[string]string{"Origin": origin, "Content-Length": "0"})
		if a.Status != 403 {
			t.Fatalf("origin %q: %d", origin, a.Status)
		}
		log := h.log.String()
		if strings.Contains(log, origin) || strings.Contains(log, "127.0.0.1") {
			t.Errorf("origin %q: the log repeats the request: %q", origin, log)
		}
	}
}

func TestUnpublishedHostIsMisdirectedAndNotLogged(t *testing.T) {
	// DNS rebinding: the browser reaches loopback under an attacker's name.
	h := newSingleHarness(t, nil)
	port := h.ts.Listener.Addr().(*net.TCPAddr).Port
	rebind := fmt.Sprintf("rebind.example.com:%d", port)
	for _, path := range []string{"/", "/embed", "/api/status", "/readyz", "/static/panel.js"} {
		h.log.Reset()
		a := h.get(path, "", map[string]string{"Host": rebind})
		if a.Status != 421 || strings.Contains(a.Body, "csrf_token") || strings.Contains(h.log.String(), "rebind.example.com") {
			t.Errorf("%s: %d, log %q", path, a.Status, h.log.String())
		}
	}
	if a := h.get("/healthz", "", map[string]string{"Host": rebind}); a.Status != 200 {
		t.Fatalf("healthz under another name: %d", a.Status)
	}
	_, nonce, token := h.indexTokens()
	a := h.do("POST", "/select", []byte("server=se-sto-wg-001&csrf_token="+token), map[string]string{
		"Host": rebind, "Content-Type": "application/x-www-form-urlencoded", "Cookie": "csrf_nonce=" + nonce,
		"Origin": "http://" + rebind, "X-Forwarded-Host": "127.0.0.1"})
	if a.Status != 421 || readDesired(h.srv.Single) != nil {
		t.Fatalf("POST under another name: %d", a.Status)
	}
}

func TestPublishedHostsIncludeAProxyUpstreamName(t *testing.T) {
	h := newSingleHarness(t, map[string]string{"PANEL_PUBLIC_HOSTS": "exit.example.test,host.docker.internal:8095"})
	for host, want := range map[string]int{"host.docker.internal:8095": 200, "host.docker.internal:8096": 421,
		"exit.example.test": 200, h.ts.Listener.Addr().String(): 200} {
		if a := h.get("/api/status", "", map[string]string{"Host": host}); a.Status != want {
			t.Errorf("Host %s: %d, want %d", host, a.Status, want)
		}
	}
}

func TestUnknownPathIsNotLogged(t *testing.T) {
	h := newSingleHarness(t, nil)
	h.log.Reset()
	a := h.get("/private.example.test?token=example", "", nil)
	log := h.log.String()
	if a.Status != 404 || strings.Contains(log, "private.example.test") || strings.Contains(log, "token=") || !strings.Contains(log, "(unknown route)") {
		t.Fatalf("status %d, log %q", a.Status, log)
	}
}

func TestRequestLogLine(t *testing.T) {
	h := newSingleHarness(t, nil)
	h.log.Reset()
	h.get("/api/status", "", nil)
	h.get("/healthz", "", nil)
	h.do("DELETE", "/", nil, nil)
	h.get("/api/status", "", map[string]string{"Host": "other.example.test"})
	lines := strings.Split(strings.TrimSpace(h.log.String()), "\n")
	want := []string{"GET /api/status 200", "(other method) / 501",
		"rejected request: host is not in PANEL_PUBLIC_HOSTS or loopback", "GET /api/status 421"}
	stamp := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z `)
	if len(lines) != len(want) {
		t.Fatalf("log = %q", lines)
	}
	for i, line := range lines {
		if !stamp.MatchString(line) || line[len("2006-01-02T15:04:05Z "):] != want[i] {
			t.Fatalf("line %d = %q, want <time> %s", i, line, want[i])
		}
	}
}

func TestRejectionLinesAreLoggedOnceAMinute(t *testing.T) {
	h := newSingleHarness(t, nil)
	h.log.Reset()
	const line = "rejected request: host is not in PANEL_PUBLIC_HOSTS or loopback"
	count := func() int { return strings.Count(h.log.String(), line) }
	for i := 0; i < 5; i++ {
		if a := h.get("/api/status", "", map[string]string{"Host": "scanner.example.test"}); a.Status != 421 {
			t.Fatalf("status %d", a.Status)
		}
	}
	if got := count(); got != 1 || strings.Count(h.log.String(), " 421\n") != 5 {
		t.Fatalf("log = %q", h.log.String())
	}
	// The origin line has its own budget.
	h.do("POST", "/select", nil, map[string]string{"Origin": "https://other.example.test", "Content-Length": "0"})
	mustContain(t, h.log.String(), "rejected POST: origin is not a published panel host\n")
	h.clock.Advance(59)
	h.get("/api/status", "", map[string]string{"Host": "scanner.example.test"})
	if count() != 1 {
		t.Fatalf("logged again within the minute: %q", h.log.String())
	}
	h.clock.Advance(2)
	h.get("/api/status", "", map[string]string{"Host": "scanner.example.test"})
	mustContain(t, h.log.String(), line+" (5 more not logged since the last such line)\n")
	h.clock.Advance(61)
	h.get("/api/status", "", map[string]string{"Host": "scanner.example.test"})
	lines := strings.Split(strings.TrimSpace(h.log.String()), "\n")
	if last := lines[len(lines)-2]; !strings.HasSuffix(last, "Z "+line) {
		t.Fatalf("after a quiet minute: %q", last)
	}
}

func TestPostOversizedBodyIsRejected(t *testing.T) {
	h := newSingleHarness(t, nil)
	_, nonce, token := h.indexTokens()
	body := "server=se-sto-wg-001&csrf_token=" + token + "&pad=" + strings.Repeat("x", 5000)
	a := h.do("POST", "/select", []byte(body), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Cookie": "csrf_nonce=" + nonce})
	if a.Status != 413 || readDesired(h.srv.Single) != nil {
		t.Fatalf("status %d", a.Status)
	}
}

func TestPostWithoutAContentLengthIsRefused(t *testing.T) {
	h := newSingleHarness(t, nil)
	conn, err := net.Dial("tcp", h.ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "POST /select HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var buf bytes.Buffer
	buf.ReadFrom(conn)
	if !strings.HasPrefix(buf.String(), "HTTP/1.1 411") {
		t.Fatalf("response %q", buf.String())
	}
}

func TestValidPostWritesDesiredJSONAtomically(t *testing.T) {
	h := newSingleHarness(t, nil)
	_, nonce, token := h.indexTokens()
	a := h.post("/select", [][2]string{{"server", "se-sto-wg-001"}, {"csrf_token", token}}, "csrf_nonce="+nonce, "http://"+h.ts.Listener.Addr().String())
	if a.Status != 303 || a.Location() != "/" {
		t.Fatalf("status %d location %q", a.Status, a.Location())
	}
	desired := readDesired(h.srv.Single)
	if desired["server"] != "se-sto-wg-001" || desired["requested_at"] == nil {
		t.Fatalf("desired = %v", desired)
	}
	if id, _ := desired["request_id"].(string); !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) {
		t.Fatalf("request_id = %v", desired["request_id"])
	}
	if len(desired) != 3 {
		t.Fatalf("desired = %v", desired)
	}
}

func TestReferrerPolicyKeepsOriginForSameSitePosts(t *testing.T) {
	h := newSingleHarness(t, nil)
	if got := h.get("/healthz", "", nil).Header.Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("Referrer-Policy = %q", got)
	}
}

func TestEveryResponseCarriesTheSecurityHeaders(t *testing.T) {
	h := newSingleHarness(t, nil)
	for _, path := range []string{"/", "/healthz", "/nope", "/api/status", "/static/panel.js", "/manifest.webmanifest"} {
		a := h.get(path, "", nil)
		if a.Header.Get("X-Content-Type-Options") != "nosniff" ||
			!strings.Contains(a.Header.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s: headers %v", path, a.Header)
		}
	}
}

// -- FramingAndRenderTests ----------------------------------------------------------

func TestFramingDeniedByDefault(t *testing.T) {
	h := newSingleHarness(t, nil)
	headers := h.srv.secHeaders
	if headers["X-Frame-Options"] != "DENY" || !strings.Contains(headers["Content-Security-Policy"], "frame-ancestors 'none'") {
		t.Fatalf("headers = %v", headers)
	}
}

func TestFramingAllowsOnlyConfiguredHTTPSOrigins(t *testing.T) {
	h := newSingleHarness(t, map[string]string{"PANEL_FRAME_ANCESTORS": "https://dashboard.example.test http://insecure.example *"})
	headers := h.srv.secHeaders
	if _, set := headers["X-Frame-Options"]; set {
		t.Error("X-Frame-Options is set")
	}
	if !strings.HasSuffix(headers["Content-Security-Policy"], "frame-ancestors https://dashboard.example.test") {
		t.Errorf("CSP = %q", headers["Content-Security-Policy"])
	}
}

func TestFlagEmoji(t *testing.T) {
	if got := flagEmoji("se-sto"); got != "\U0001F1F8\U0001F1EA" {
		t.Errorf("flagEmoji = %q", got)
	}
	for _, bad := range []string{"", "s", "1a", "é-x"} {
		if got := flagEmoji(bad); got != "" {
			t.Errorf("flagEmoji(%q) = %q", bad, got)
		}
	}
}

func TestEmbedPagePostsBackToEmbed(t *testing.T) {
	h := newSingleHarness(t, nil)
	page := h.render(map[string]any{"server": "x"}, nil, nil, func(p *IndexPage) { p.Embed = true })
	mustContain(t, page, `name="return" value="embed"`)
	mustNotContain(t, page, "<h1>")
}

// -- SwitcherRenderTests ---------------------------------------------------------------

func failedRecords() (map[string]any, map[string]any) {
	desired := map[string]any{"server": "se-sto-wg-001", "requested_at": nowISO(), "request_id": strings.Repeat("a", 32)}
	result := map[string]any{"status": "failed", "message": "Switch verification timed out.", "checked_at": nowISO(),
		"request_id": strings.Repeat("a", 32), "server": nil}
	return desired, result
}

func TestStatusPillIsLiveFromFirstRender(t *testing.T) {
	h := newSingleHarness(t, nil)
	page := h.render(nil, nil, nil, nil)
	mustContain(t, page, `data-state-pill role="status" aria-live="polite"`, "data-announce")
}

func TestRequestTimeIsExposedForProgress(t *testing.T) {
	h := newSingleHarness(t, nil)
	desired := map[string]any{"server": "se-sto-wg-001", "requested_at": "2026-01-01T00:00:00Z", "request_id": strings.Repeat("a", 32)}
	page := h.render(desired, nil, catalogue(relayEntry("se-sto-wg-001", nil)), nil)
	mustContain(t, page, `data-requested="2026-01-01T00:00:00Z"`)
}

func TestRetryOfferedForFailedCataloguedServer(t *testing.T) {
	h := newSingleHarness(t, nil)
	desired, result := failedRecords()
	page := h.render(desired, result, catalogue(relayEntry("se-sto-wg-001", nil)), nil)
	mustContain(t, page, `form="select-form" name="server" value="se-sto-wg-001"`, `data-retry>Retry</button>`)
}

func TestNoRetryWhenNotFailedOrNotCatalogued(t *testing.T) {
	h := newSingleHarness(t, nil)
	desired, result := failedRecords()
	desired["server"] = "no-where-wg-001"
	mustNotContain(t, h.render(desired, result, catalogue(relayEntry("se-sto-wg-001", nil)), nil), "data-retry")
	ok := map[string]any{"status": "ok", "routing_ok": true, "mullvad_exit_ip": true, "checked_at": nowISO(),
		"request_id": strings.Repeat("a", 32), "server": "se-sto-wg-001", "requested_server": "se-sto-wg-001"}
	failedDesired, _ := failedRecords()
	mustNotContain(t, h.render(failedDesired, ok, catalogue(relayEntry("se-sto-wg-001", nil)), nil), "data-retry")
}

func TestFailureMessageIsEscapedBesideRetry(t *testing.T) {
	h := newSingleHarness(t, nil)
	desired, result := failedRecords()
	result["message"] = "<img src=x onerror=alert(1)>"
	page := h.render(desired, result, catalogue(relayEntry("se-sto-wg-001", nil)), nil)
	mustNotContain(t, page, "<img src=x")
	mustContain(t, page, "&lt;img src=x onerror=alert(1)&gt;")
}

func TestRelayAttributesOnlyWhenKnown(t *testing.T) {
	h := newSingleHarness(t, nil)
	page := h.render(nil, nil, catalogue(relayEntry("se-sto-wg-001", nil)), nil)
	mustNotContain(t, page, "data-owned", "data-attr-filter", "data-filters-toggle")

	page = h.render(nil, nil, catalogue(
		relayEntry("se-sto-wg-001", map[string]any{"owned": true, "stboot": false, "provider": "<b>Example Hosting</b>"}),
		relayEntry("se-sto-wg-002", map[string]any{"owned": "yes"})), nil)
	mustContain(t, page, `data-owned="1" data-stboot="0"`, `data-attr-filter="owned"`, "data-filters-toggle",
		"&lt;b&gt;Example Hosting&lt;/b&gt; · Mullvad-owned")
	if n := strings.Count(page, "data-owned="); n != 1 {
		t.Errorf("data-owned appears %d times", n)
	}
	// No relay is RAM-only here, so that filter would hide everything.
	mustNotContain(t, page, `data-attr-filter="stboot"`, "<b>Example Hosting</b>")
}

func TestFiltersOfferedOnlyWhenTheyNarrowTheList(t *testing.T) {
	h := newSingleHarness(t, nil)
	every := catalogue(relayEntry("se-sto-wg-001", map[string]any{"stboot": true}), relayEntry("se-sto-wg-002", map[string]any{"stboot": true}))
	page := h.render(nil, nil, every, nil)
	mustContain(t, page, `data-stboot="1"`)
	mustNotContain(t, page, "data-attr-filter", "data-filters-toggle")

	mixed := catalogue(relayEntry("se-sto-wg-001", map[string]any{"stboot": true}), relayEntry("se-sto-wg-002", map[string]any{"stboot": false}))
	page = h.render(nil, nil, mixed, nil)
	mustContain(t, page, `data-attr-filter="stboot"`)
	mustNotContain(t, page, `data-attr-filter="owned"`)

	partlyKnown := catalogue(relayEntry("se-sto-wg-001", map[string]any{"owned": true}), relayEntry("se-sto-wg-002", nil))
	mustContain(t, h.render(nil, nil, partlyKnown, nil), `data-attr-filter="owned"`)
}

func TestFaviconAndUnbrokenAddress(t *testing.T) {
	h := newSingleHarness(t, nil)
	page := h.render(nil, nil, nil, nil)
	if !regexp.MustCompile(`<link rel="icon" href="/static/icon-192\.png\?v=\w+" type="image/png">`).MatchString(page) {
		t.Error("no favicon link")
	}
	mustContain(t, page, `<span class="nowrap">· <span data-current-ip>`)
}

func TestThemeSetting(t *testing.T) {
	for value, want := range map[string]string{"light": "light", "dark": "dark", "auto": "auto", "neon": "auto", "": "auto"} {
		if got := themeSetting(value); got != want {
			t.Errorf("themeSetting(%q) = %q", value, got)
		}
	}
	for _, theme := range []string{"light", "dark"} {
		h := newSingleHarness(t, map[string]string{"PANEL_THEME": theme})
		page := h.render(nil, nil, nil, nil)
		mustContain(t, page, `<html lang="en" data-theme="`+theme+`" `, `<meta name="color-scheme" content="`+theme+`">`)
	}
	page := newSingleHarness(t, map[string]string{"PANEL_THEME": "auto"}).render(nil, nil, nil, nil)
	mustContain(t, page, `<meta name="color-scheme" content="dark light">`, `media="(prefers-color-scheme: light)"`)
	if styleSetting("neon") != "provider" || styleSetting("dashboard") != "dashboard" {
		t.Error("styleSetting")
	}
}

// -- EmbedAndApiIntegrationTests ---------------------------------------------------------

func TestEmbedSelectRedirectsToEmbed(t *testing.T) {
	h := newSingleHarness(t, nil)
	page := h.get("/embed", "", nil)
	nonce := page.Cookies["csrf_nonce"].Value
	token := csrfTokenInPage.FindStringSubmatch(page.Body)[1]
	a := h.post("/select", [][2]string{{"server", "se-sto-wg-001"}, {"csrf_token", token}, {"return", "embed"}}, "csrf_nonce="+nonce, "")
	if a.Status != 303 || a.Location() != "/embed" {
		t.Fatalf("status %d location %q", a.Status, a.Location())
	}
}

func TestStatusAPI(t *testing.T) {
	h := newSingleHarness(t, nil)
	mustWrite(t, h.srv.Single.DesiredPath, map[string]any{"server": "se-sto-wg-001", "requested_at": "now"})
	a := h.get("/api/status", "", nil)
	var body map[string]any
	if err := json.Unmarshal([]byte(a.Body), &body); err != nil {
		t.Fatal(err)
	}
	if a.Status != 200 || a.Header.Get("Content-Type") != "application/json" || a.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("headers %v", a.Header)
	}
	// A request with a timestamp the panel cannot read is not a request, but
	// the file is still shown.
	if desired, _ := body["desired"].(map[string]any); desired["server"] != "se-sto-wg-001" {
		t.Fatalf("desired = %v", body["desired"])
	}
}

func jsonBody(t *testing.T, a answer) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal([]byte(a.Body), &body); err != nil {
		t.Fatalf("%v in %q", err, a.Body)
	}
	return body
}

func TestStaleSuccessIsUnknownInAPIHTMLAndReadiness(t *testing.T) {
	h := newSingleHarness(t, nil)
	mustWrite(t, h.srv.Single.ResultPath, map[string]any{"server": "se-sto-wg-001", "status": "ok",
		"checked_at": "2000-01-01T00:00:00Z", "routing_ok": true, "mullvad_exit_ip": true})
	if view := jsonBody(t, h.get("/api/status", "", nil))["view"].(map[string]any); view["state"] != "unknown" {
		t.Fatalf("view = %v", view)
	}
	mustContain(t, h.get("/", "", nil).Body, "status stale")
	if a := h.get("/readyz", "", nil); a.Status != 503 {
		t.Fatalf("readyz = %d", a.Status)
	}
	if a := h.get("/healthz", "", nil); a.Status != 200 {
		t.Fatalf("healthz = %d", a.Status)
	}
}

func TestFreshSuccessReadyWithoutDesiredFile(t *testing.T) {
	h := newSingleHarness(t, nil)
	mustWrite(t, h.srv.Single.ResultPath, map[string]any{"server": "se-sto-wg-001", "status": "ok",
		"checked_at": nowISO(), "routing_ok": true, "mullvad_exit_ip": true})
	if a := h.get("/readyz", "", nil); a.Status != 200 || a.Body != "ready" {
		t.Fatalf("readyz = %d %q", a.Status, a.Body)
	}
	page := h.get("/", "", nil).Body
	mustContain(t, page, "se-sto-wg-001")
	mustNotContain(t, page, "Awaiting verified server")
}

func TestPanelReadsTheCatalogueFromTheApplierMount(t *testing.T) {
	// Production's relays path is under the read-only applier mount.
	h := newSingleHarness(t, nil)
	if want := h.dir + "/applier/relays.json"; h.srv.Single.RelaysPath != want {
		t.Fatalf("RelaysPath = %q, want %q", h.srv.Single.RelaysPath, want)
	}
}

func TestStaticFilesAreAllowlisted(t *testing.T) {
	h := newSingleHarness(t, nil)
	if a := h.get("/static/panel.js", "", nil); a.Status != 200 || a.Header.Get("Content-Type") != "text/javascript; charset=utf-8" ||
		a.Header.Get("Cache-Control") != "public, max-age=86400" {
		t.Fatalf("panel.js: %d %v", a.Status, a.Header)
	}
	for _, path := range []string{"/static/app.py", "/static/../app.py", "/static/static.go", "/static/", "/static/panel.js/", "/static/panel%2ejs", "/static/JetBrainsMono-OFL.txt"} {
		if a := h.get(path, "", nil); a.Status != 404 {
			t.Errorf("%s: %d", path, a.Status)
		}
	}
	for name, want := range map[string]string{"panel.css": "text/css; charset=utf-8", "JetBrainsMono-Regular.woff2": "font/woff2",
		"icon-192.png": "image/png", "icon-512.png": "image/png", "apple-touch-icon.png": "image/png"} {
		if a := h.get("/static/"+name, "", nil); a.Status != 200 || a.Header.Get("Content-Type") != want {
			t.Errorf("%s: %d %q", name, a.Status, a.Header.Get("Content-Type"))
		}
	}
}

func TestStaticFilesAreServedAsTheyAreOnDisk(t *testing.T) {
	h := newSingleHarness(t, nil)
	for _, name := range []string{"panel.js", "panel.css", "icon-192.png"} {
		disk, err := readStatic(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := h.get("/static/"+name, "", nil).Body; got != string(disk) {
			t.Errorf("%s differs from panel/static/%s", name, name)
		}
	}
}

func TestStaticTextIsGzippedOnlyWhenAccepted(t *testing.T) {
	h := newSingleHarness(t, nil)
	disk, err := readStatic("panel.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, accept := range []string{"gzip", "br, gzip;q=0.5", "*", "gzip, deflate"} {
		a := h.get("/static/panel.js", "", map[string]string{"Accept-Encoding": accept})
		if a.Status != 200 || a.Header.Get("Content-Encoding") != "gzip" || a.Header.Get("Vary") != "Accept-Encoding" ||
			a.Header.Get("Content-Length") != strconv.Itoa(len(a.Body)) {
			t.Fatalf("%q: %d %v", accept, a.Status, a.Header)
		}
		zr, err := gzip.NewReader(strings.NewReader(a.Body))
		if err != nil {
			t.Fatal(err)
		}
		plainBody, err := io.ReadAll(zr)
		if err != nil || !bytes.Equal(plainBody, disk) {
			t.Fatalf("%q: the gzipped body is not panel.js (%v)", accept, err)
		}
	}
	for _, accept := range []string{"identity", "gzip;q=0", "br", "*;q=0", "gzip;q=0, *"} {
		a := h.get("/static/panel.js", "", map[string]string{"Accept-Encoding": accept})
		if a.Status != 200 || a.Header.Get("Content-Encoding") != "" || a.Header.Get("Vary") != "Accept-Encoding" || a.Body != string(disk) {
			t.Fatalf("%q: %d %v", accept, a.Status, a.Header)
		}
	}
	// Fonts and images are compressed already.
	for _, name := range []string{"JetBrainsMono-Regular.woff2", "icon-192.png"} {
		a := h.get("/static/"+name, "", map[string]string{"Accept-Encoding": "gzip"})
		if a.Header.Get("Content-Encoding") != "" || a.Header.Get("Vary") != "" {
			t.Fatalf("%s: %v", name, a.Header)
		}
	}
}

// Pages and API answers carry CSRF tokens and status; they are never
// compressed (BREACH).
func TestPagesAndAPIAreNeverCompressed(t *testing.T) {
	h := newSingleHarness(t, nil)
	for _, path := range []string{"/", "/embed", "/api/status", "/api/exits", "/manifest.webmanifest", "/readyz"} {
		a := h.get(path, "", map[string]string{"Accept-Encoding": "gzip"})
		if a.Header.Get("Content-Encoding") != "" {
			t.Fatalf("%s: %v", path, a.Header)
		}
	}
}

func TestVersionedStaticURLsAreImmutable(t *testing.T) {
	h := newSingleHarness(t, nil)
	page := h.get("/", "", nil).Body
	m := regexp.MustCompile(`/static/panel\.css\?v=(\w+)`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no versioned stylesheet in the page")
	}
	if a := h.get("/static/panel.css?v="+m[1], "", nil); a.Status != 200 || a.Header.Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("current version: %d %v", a.Status, a.Header)
	}
	for _, query := range []string{"", "?v=0123456789", "?v=" + m[1] + "&v=" + m[1], "?x=" + m[1]} {
		if a := h.get("/static/panel.css"+query, "", nil); a.Status != 200 || a.Header.Get("Cache-Control") != "public, max-age=86400" {
			t.Fatalf("%q: %d %v", query, a.Status, a.Header)
		}
	}
}

func TestStaticETagRevalidates(t *testing.T) {
	h := newSingleHarness(t, nil)
	for _, accept := range []string{"gzip", "identity"} {
		a := h.get("/static/panel.css", "", map[string]string{"Accept-Encoding": accept})
		etag := a.Header.Get("ETag")
		if !regexp.MustCompile(`^"[0-9a-f]{10}(-gzip)?"$`).MatchString(etag) {
			t.Fatalf("%s: ETag %q", accept, etag)
		}
		for _, match := range []string{etag, "W/" + etag, `"other", ` + etag, "*"} {
			b := h.get("/static/panel.css", "", map[string]string{"Accept-Encoding": accept, "If-None-Match": match})
			if b.Status != 304 || b.Body != "" || b.Header.Get("ETag") != etag || b.Header.Get("Cache-Control") == "" {
				t.Fatalf("%s, If-None-Match %q: %d %v", accept, match, b.Status, b.Header)
			}
		}
		if b := h.get("/static/panel.css", "", map[string]string{"Accept-Encoding": accept, "If-None-Match": `"0000000000"`}); b.Status != 200 {
			t.Fatalf("%s: other tag: %d", accept, b.Status)
		}
	}
	gz := h.get("/static/panel.css", "", map[string]string{"Accept-Encoding": "gzip"}).Header.Get("ETag")
	if b := h.get("/static/panel.css", "", map[string]string{"Accept-Encoding": "identity", "If-None-Match": gz}); b.Status != 200 {
		t.Fatalf("the gzip tag matched the identity body: %d", b.Status)
	}
}

func TestOtherMethodsAreNotSupported(t *testing.T) {
	h := newSingleHarness(t, nil)
	for _, method := range []string{"HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"} {
		a := h.do(method, "/", nil, nil)
		if a.Status != 501 || (method != "HEAD" && !strings.Contains(a.Body, "Unsupported method")) {
			t.Errorf("%s: %d %q", method, a.Status, a.Body)
		}
	}
}

// -- PwaTests --------------------------------------------------------------------------------

func TestManifestAndIconsAreDeclared(t *testing.T) {
	h := newSingleHarness(t, nil)
	page := h.render(nil, nil, nil, nil)
	mustContain(t, page, `rel="manifest" href="/manifest.webmanifest" crossorigin="use-credentials"`, `rel="apple-touch-icon"`, "viewport-fit=cover")
	manifest := jsonBody(t, h.get("/manifest.webmanifest", "", nil))
	if manifest["start_url"] != "/" || manifest["name"] != "Switchyard" || manifest["display"] != "standalone" {
		t.Fatalf("manifest = %v", manifest)
	}
	for _, icon := range manifest["icons"].([]any) {
		src := icon.(map[string]any)["src"].(string)
		a := h.get(src, "", nil)
		if a.Status != 200 || !strings.HasPrefix(a.Body, "\x89PNG") {
			t.Errorf("icon %s: %d", src, a.Status)
		}
	}
	mustContain(t, h.get("/", "", nil).Header.Get("Content-Security-Policy"), "manifest-src 'self'")
	// The same bytes json.dumps(WEB_MANIFEST) wrote.
	want := `{"name": "Switchyard", "short_name": "Switchyard", "start_url": "/", "scope": "/", "display": "standalone", ` +
		`"background_color": "#232638", "theme_color": "#232638", "icons": [{"src": "/static/icon-192.png", ` +
		`"sizes": "192x192", "type": "image/png"}, {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png"}]}`
	if got := h.get("/manifest.webmanifest", "", nil).Body; got != want {
		t.Errorf("manifest bytes:\n got %s\nwant %s", got, want)
	}
}

// -- SigtermTests --------------------------------------------------------------------------------

func TestServeStopsCleanlyOnShutdown(t *testing.T) {
	// The panel runs as a container's PID 1, which ignores SIGTERM without a
	// handler; the role turns SIGTERM into this context ending.
	h := newSingleHarness(t, nil)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- Serve(ctx, h.srv, listener, &bytes.Buffer{}) }()
	resp, err := http.Get("http://" + listener.Addr().String() + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v", err)
	}
	resp.Body.Close()
	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit status %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

// -- RegistryPanelTests -----------------------------------------------------------------------------

func TestServerPatternReachesTheBrowserForEveryProvider(t *testing.T) {
	for _, id := range providers.IDs() {
		t.Run(id, func(t *testing.T) {
			h := newHarness(t, map[string]string{"PROVIDER": id}, nil)
			page := h.render(nil, nil, nil, nil)
			spec, _ := providers.Lookup(id)
			m := regexp.MustCompile(`data-server-pattern="([^"]*)"`).FindStringSubmatch(page)
			if m == nil || html.UnescapeString(m[1]) != spec.ServerNamePattern {
				t.Fatalf("pattern %v", m)
			}
			mustContain(t, page, `data-layout="`+spec.Layout+`"`)
		})
	}
}

func TestPanelExitsAcceptOnlyRegisteredProviders(t *testing.T) {
	var parts []string
	for _, id := range providers.IDs() {
		parts = append(parts, id+"="+id)
	}
	exits, err := ParseExits(strings.Join(parts, ","), "/state")
	if err != nil {
		t.Fatal(err)
	}
	if len(exits) != len(providers.IDs()) {
		t.Fatalf("%d exits", len(exits))
	}
	for i, id := range providers.IDs() {
		spec, _ := providers.Lookup(id)
		if exits[i].Provider != id || exits[i].Label != spec.Label {
			t.Errorf("exit %d = %+v", i, exits[i])
		}
	}
	if _, err := ParseExits("a=examplevpn", "/state"); err == nil || !strings.Contains(err.Error(), "provider must be one of") {
		t.Fatalf("err = %v", err)
	}
}

var _ = strconv.Itoa
var _ = state.NowISO
