package panel

// Ported from panel/test_oidc.py: the panel with sign-in on (PanelAuthBase,
// SignedOutTests, SignInFlowTests, AccessTests, SwitchTests,
// ConfidentialClientPanelTests, NoSignInConfiguredTests,
// PlantedCookieOverHttpTests). The panel talks to an in-test fake issuer on
// loopback.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/panel/oidc"
	"github.com/irashack/molebridge/internal/panel/oidc/oidctest"
	"github.com/irashack/molebridge/internal/panel/pystr"
)

// blankServer asks selectAs for an empty server field.
const blankServer = "\x00blank"

const (
	publicURL    = "https://exit.example.test"
	selectServer = "se-got-wg-002"
)

type authPanel struct {
	*harness
	issuer *oidctest.Issuer
	mine   Exit
	a      Exit
	b      Exit
}

func tokenURLSafe() string {
	raw := make([]byte, 32)
	rand.Read(raw)
	return base64.RawURLEncoding.EncodeToString(raw)
}

func authEnv(issuer string, extra map[string]string) map[string]string {
	env := map[string]string{
		"PANEL_EXITS": "mine=mullvad,a=mullvad,b=pia", "PANEL_OIDC_ISSUER": issuer, "PANEL_OIDC_CLIENT_ID": oidctest.ClientID,
		"PANEL_PUBLIC_URL": publicURL, "PANEL_ADMIN_GROUPS": "admins", "PANEL_ACCESS": "friends-a=a,friends-b=b",
		"PANEL_HOME_URL": "https://home.example.test",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

// newAuthPanel is the panel with sign-in on: exits mine (Mullvad), a
// (Mullvad) and b (PIA), admin group `admins`, `friends-a` granted a and
// `friends-b` granted b.
func newAuthPanel(t *testing.T, extra map[string]string) *authPanel {
	t.Helper()
	clock := &oidctest.Clock{}
	issuer := oidctest.New(t, clock.Now)
	p := &authPanel{issuer: issuer}
	p.harness = newHarness(t, authEnv(issuer.URL, extra), func(o *Options) {
		o.AuthClock = clock.Now
		o.Now = nil // the status files use the real clock
	})
	p.clock = clock
	p.mine, p.a, p.b = p.exit("mine"), p.exit("a"), p.exit("b")
	p.writeCatalogues()
	return p
}

func (p *authPanel) writeCatalogues() {
	mullvad := func(host, code, ip string) map[string]any {
		return relayEntry(host, map[string]any{"location_code": code, "ipv4_addr_in": ip})
	}
	mustWrite(p.t, p.mine.RelaysPath, catalogue(mullvad("se-sto-wg-001", "se-sto", "198.51.100.10")))
	mustWrite(p.t, p.a.RelaysPath, catalogue(mullvad(selectServer, "se-got", "198.51.100.11")))
	mustWrite(p.t, p.b.RelaysPath, piaCatalogue("pia"))
	p.writeOK(p.a, "mullvad")
	p.writeOK(p.b, "pia")
}

func (p *authPanel) writeOK(ex Exit, provider string) {
	server := selectServer
	if provider == "pia" {
		server = "ex_example"
	}
	mustWrite(p.t, ex.ResultPath, map[string]any{"status": "ok", "checked_at": nowISO(), "routing_ok": true,
		"exit_confirmed": true, "provider": provider, "server": server})
}

// beginLogin starts a sign-in; the fake issuer learns the nonce.
func (p *authPanel) beginLogin(nextPath string) (answer, map[string]string) {
	p.t.Helper()
	a := p.get("/login?"+pystr.Encode(pystr.Pair{Key: "next", Value: nextPath}), "", nil)
	query := map[string]string{}
	if u, err := url.Parse(a.Location()); err == nil {
		for k := range u.Query() {
			query[k] = u.Query().Get(k)
		}
	}
	nonce := query["nonce"]
	p.issuer.Set(func(i *oidctest.Issuer) { i.Nonce = nonce })
	return a, query
}

func (p *authPanel) callback(query map[string]string, loginCookie, code string, extra ...[2]string) answer {
	p.t.Helper()
	if code == "" {
		code = "authcode-" + tokenURLSafe()[:16]
	}
	params := []pystr.Pair{{Key: "code", Value: code}, {Key: "state", Value: query["state"]}}
	for _, e := range extra {
		params = append(params, pystr.Pair{Key: e[0], Value: e[1]})
	}
	cookie := ""
	if loginCookie != "" {
		cookie = oidc.LoginCookie + "=" + loginCookie
	}
	return p.get("/auth/callback?"+pystr.Encode(params...), cookie, nil)
}

func (p *authPanel) signIn(groups []string, name, sub, nextPath string) string {
	p.t.Helper()
	p.issuer.Set(func(i *oidctest.Issuer) { i.Groups = groups; i.Username = name; i.Sub = sub })
	login, query := p.beginLogin(nextPath)
	if login.Status != 303 {
		p.t.Fatalf("login: %d %s", login.Status, login.Body)
	}
	done := p.callback(query, login.Cookies[oidc.LoginCookie].Value, "")
	if done.Status != 303 {
		p.t.Fatalf("callback: %d %s", done.Status, done.Body)
	}
	return oidc.SessionCookie + "=" + done.Cookies[oidc.SessionCookie].Value
}

func (p *authPanel) selectAs(cookie, exitID, server string, tokens *[2]string, origin string, extra ...[2]string) answer {
	p.t.Helper()
	var nonce, token string
	if tokens != nil {
		nonce, token = tokens[0], tokens[1]
	} else {
		nonce, token = p.pageTokens(cookie, "a", "/")
	}
	switch server {
	case "":
		server = selectServer
	case blankServer:
		server = ""
	}
	fields := [][2]string{{"server", server}, {"csrf_token", token}, {"exit", exitID}}
	fields = append(fields, extra...)
	return p.post("/select", fields, cookie+"; csrf_nonce="+nonce, origin)
}

func (p *authPanel) assertNoDesired(exits ...Exit) {
	p.t.Helper()
	if len(exits) == 0 {
		exits = p.srv.Exits
	}
	for _, ex := range exits {
		if _, err := os.Stat(ex.DesiredPath); err == nil {
			p.t.Errorf("%s was written", ex.ID)
		}
	}
}

func (p *authPanel) sessions() int { return p.srv.Auth.SessionCount() }

func queryOf(t *testing.T, location string) url.Values {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func eq[T comparable](t *testing.T, what string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

// -- SignedOutTests -----------------------------------------------------------------------

func TestFullPageRedirectsToTheCanonicalLoginURL(t *testing.T) {
	p := newAuthPanel(t, nil)
	a := p.get("/", "", nil)
	u, _ := url.Parse(a.Location())
	eq(t, "status", a.Status, 303)
	eq(t, "location", u.Scheme+"://"+u.Host+u.Path, "https://exit.example.test/login")
	eq(t, "next", u.Query().Get("next"), "/")
	eq(t, "next for an exit", queryOf(t, p.get("/?exit=a", "", nil).Location()).Get("next"), "/?exit=a")
	eq(t, "Cache-Control", a.Header.Get("Cache-Control"), "no-store")
	if _, set := a.Cookies["csrf_nonce"]; set {
		t.Error("a signed-out page set a CSRF cookie")
	}
}

func TestHostileExitValueDoesNotReachTheLoginURL(t *testing.T) {
	p := newAuthPanel(t, nil)
	for _, value := range []string{"../etc", "A", "a&next=https://evil.example.test", "%0d%0aX:y", strings.Repeat("x", 40)} {
		a := p.get("/?exit="+pystr.Quote(value), "", nil)
		eq(t, "status", a.Status, 303)
		eq(t, "next", queryOf(t, a.Location()).Get("next"), "/")
		if !strings.HasPrefix(a.Location(), "https://exit.example.test/login?") {
			t.Errorf("location %q", a.Location())
		}
	}
}

func TestEmbedShowsASignInLinkThatOpensANewTab(t *testing.T) {
	p := newAuthPanel(t, nil)
	a := p.get("/embed?exit=a", "", nil)
	eq(t, "status", a.Status, 200)
	link := regexp.MustCompile(`<a [^>]*href="([^"]+)"[^>]*>`).FindStringSubmatch(a.Body)
	if link == nil {
		t.Fatal("no link")
	}
	mustContain(t, link[0], `target="_blank"`, `rel="noopener"`)
	if !strings.HasPrefix(link[1], "https://exit.example.test/login?next=") {
		t.Errorf("href %q", link[1])
	}
	mustContain(t, a.Body, "Sign in")
	// Nothing about the exits is in the page.
	mustNotContain(t, a.Body, "data-exit=", "csrf_token", "Stockholm", `name="server"`)
}

func TestEveryAPIPathIs401JSON(t *testing.T) {
	p := newAuthPanel(t, nil)
	for _, path := range []string{"/api/exits", "/api/status?exit=a", "/api/status", "/api/latency?exit=a", "/api/latency?exit=nope", "/api/status?exit=b"} {
		a := p.get(path, "", nil)
		eq(t, path+" status", a.Status, 401)
		eq(t, path+" type", a.Header.Get("Content-Type"), "application/json")
		eq(t, path+" body", a.Body, `{"error": "sign in required"}`)
	}
}

func TestSelectIs401AndWritesNothing(t *testing.T) {
	p := newAuthPanel(t, nil)
	// Even with a token that would verify for an anonymous caller.
	nonce := newCSRFNonce()
	for _, exitID := range []string{"a", "b", "mine", "nope"} {
		a := p.post("/select", [][2]string{{"server", selectServer}, {"csrf_token", p.srv.csrfToken(nonce, "")}, {"exit", exitID}}, "csrf_nonce="+nonce, "")
		eq(t, "status", a.Status, 401)
	}
	p.assertNoDesired()
}

func TestHealthAndStaticNeedNoLogin(t *testing.T) {
	p := newAuthPanel(t, nil)
	if a := p.get("/healthz", "", nil); a.Status != 200 || a.Body != "ok" {
		t.Error("healthz")
	}
	eq(t, "css", p.get("/static/panel.css", "", nil).Status, 200)
	eq(t, "js", p.get("/static/panel.js", "", nil).Status, 200)
	m := p.get("/manifest.webmanifest", "", nil)
	eq(t, "manifest", m.Status, 200)
	eq(t, "start_url", jsonBody(t, m)["start_url"], any("/"))
	eq(t, "missing", p.get("/static/nope.css", "", nil).Status, 404)
}

func TestReadyzAggregateNeedsNoLogin(t *testing.T) {
	p := newAuthPanel(t, nil)
	eq(t, "before", p.get("/readyz", "", nil).Status, 503) // `mine` has no status yet
	p.writeOK(p.mine, "mullvad")
	a := p.get("/readyz", "", nil)
	if a.Status != 200 || a.Body != "ready" {
		t.Fatalf("%d %q", a.Status, a.Body)
	}
}

func TestReadyzDoesNotRevealWhichExitsExist(t *testing.T) {
	p := newAuthPanel(t, nil)
	nonexistent := p.get("/readyz?exit=zz-nope", "", nil)
	eq(t, "status", nonexistent.Status, 404)
	for _, id := range []string{"a", "b", "mine"} {
		if got := p.get("/readyz?exit="+id, "", nil); got.signature() != nonexistent.signature() {
			t.Errorf("exit %s is distinguishable: %d %q", id, got.Status, got.Body)
		}
	}
}

func TestLoginRelatedPagesAreReachableSignedOut(t *testing.T) {
	p := newAuthPanel(t, nil)
	eq(t, "signed-out", p.get("/signed-out", "", nil).Status, 200)
	eq(t, "login", p.get("/login", "", nil).Status, 303)
}

func TestLogoutWithoutASessionStillLandsOnSignedOut(t *testing.T) {
	p := newAuthPanel(t, nil)
	a := p.post("/logout", nil, "", "")
	eq(t, "status", a.Status, 303)
	eq(t, "location", a.Location(), publicURL+"/signed-out")
}

func TestUnknownSessionCookiesAreSignedOut(t *testing.T) {
	p := newAuthPanel(t, nil)
	for _, value := range []string{tokenURLSafe(), strings.Repeat("x", 43), "short", "", "a;b", `"quoted"`, "é"} {
		cookie := oidc.SessionCookie + "=" + value
		eq(t, "api "+value, p.get("/api/exits", cookie, nil).Status, 401)
		eq(t, "page "+value, p.get("/?exit=a", cookie, nil).Status, 303)
		nonce := newCSRFNonce()
		a := p.post("/select", [][2]string{{"server", selectServer}, {"csrf_token", p.srv.csrfToken(nonce, "")}, {"exit", "a"}}, cookie+"; csrf_nonce="+nonce, "")
		eq(t, "select "+value, a.Status, 401)
	}
	p.assertNoDesired()
}

func TestAnotherCookieNameIsNotASession(t *testing.T) {
	p := newAuthPanel(t, nil)
	session := p.signIn([]string{"friends-a"}, "jo", "user-1", "/")
	value := strings.SplitN(session, "=", 2)[1]
	// Without the __Host- prefix the cookie means nothing.
	eq(t, "unprefixed", p.get("/api/exits", "molebridge_session="+value, nil).Status, 401)
	eq(t, "prefixed", p.get("/api/exits", session, nil).Status, 200)
}

func TestASessionIdSmuggledInsideAnotherCookieIsIgnored(t *testing.T) { // PlantedCookieOverHttpTests
	p := newAuthPanel(t, nil)
	cookie := p.signIn([]string{"friends-a"}, "jo", "user-1", "/")
	eq(t, "real", p.get("/api/exits", cookie, nil).Status, 200)
	eq(t, "planted", p.get("/api/exits", "planted=x "+cookie, nil).Status, 401)
}

// -- SignInFlowTests ----------------------------------------------------------------------

func hasAll(attrs map[string]bool, wanted ...string) bool {
	for _, w := range wanted {
		if !attrs[w] {
			return false
		}
	}
	return true
}

func TestLoginRedirectsToTheIssuerWithALockedDownCookie(t *testing.T) {
	p := newAuthPanel(t, nil)
	a, query := p.beginLogin("/?exit=a")
	eq(t, "status", a.Status, 303)
	if !strings.HasPrefix(a.Location(), p.issuer.URL+"/authorize?") {
		t.Fatalf("location %q", a.Location())
	}
	eq(t, "redirect_uri", query["redirect_uri"], publicURL+"/auth/callback")
	eq(t, "challenge method", query["code_challenge_method"], "S256")
	c := a.Cookies[oidc.LoginCookie]
	if !strings.HasPrefix(oidc.LoginCookie, "__Host-") || !hasAll(c.Attrs, "secure", "httponly", "samesite=lax", "path=/", "max-age=600") {
		t.Fatalf("cookie %+v", c)
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,1000}\.[A-Za-z0-9_-]{43}$`).MatchString(c.Value) {
		t.Errorf("cookie value %q", c.Value)
	}
	for attr := range c.Attrs {
		if strings.HasPrefix(attr, "domain") {
			t.Error("the cookie has a Domain")
		}
	}
	if strings.Contains(a.Location(), c.Value) {
		t.Error("the cookie is sent to the issuer")
	}
	if strings.SplitN(c.Value, ".", 2)[0] == query["state"] {
		t.Error("the cookie body is the state")
	}
}

func TestLoginOverPlainHTTPIsSentToTheCanonicalHTTPSURLWithoutACookie(t *testing.T) {
	p := newAuthPanel(t, nil)
	for _, proto := range []string{"http", "HTTP", " http ", "ws", ""} {
		a := p.get("/login?next=%2F%3Fexit%3Da", "", map[string]string{"X-Forwarded-Proto": proto})
		eq(t, "status", a.Status, 303)
		eq(t, "location", a.Location(), publicURL+"/login?next=%2F%3Fexit%3Da&canonical=1")
		if len(a.Cookies) != 0 {
			t.Errorf("proto %q set cookies", proto)
		}
	}
	eq(t, "default next", p.get("/login", "", map[string]string{"X-Forwarded-Proto": "http"}).Location(), publicURL+"/login?next=%2F&canonical=1")
	// Hostile next is still reduced on the way.
	eq(t, "hostile next", p.get("/login?next=https://evil.example.test/", "", map[string]string{"X-Forwarded-Proto": "http"}).Location(),
		publicURL+"/login?next=%2F&canonical=1")
	eq(t, "issuer contacts", p.issuer.SeenRequests(), 0) // the issuer was never contacted
	// A signed-in browser that arrives over http is also sent to https first.
	session := p.signIn([]string{"friends-a"}, "jo", "user-1", "/")
	eq(t, "signed in", p.get("/login", session, map[string]string{"X-Forwarded-Proto": "http"}).Location(), publicURL+"/login?next=%2F&canonical=1")
}

func TestAProxyThatAlwaysSaysHTTPIsRedirectedOnceNotForever(t *testing.T) {
	p := newAuthPanel(t, nil)
	a := p.get("/login?next=%2F&canonical=1", "", map[string]string{"X-Forwarded-Proto": "http"})
	eq(t, "status", a.Status, 303)
	if !strings.HasPrefix(a.Location(), p.issuer.URL+"/authorize?") {
		t.Fatalf("location %q", a.Location())
	}
}

func TestLoginOverHTTPSOrWithoutTheHeaderStartsTheSignIn(t *testing.T) {
	p := newAuthPanel(t, nil)
	for _, headers := range []map[string]string{{"X-Forwarded-Proto": "https"}, {"X-Forwarded-Proto": "HTTPS"}, {"X-Forwarded-Proto": " https "}, nil} {
		a := p.get("/login", "", headers)
		eq(t, "status", a.Status, 303)
		if !strings.HasPrefix(a.Location(), p.issuer.URL+"/authorize?") {
			t.Errorf("headers %v: location %q", headers, a.Location())
		}
		if _, ok := a.Cookies[oidc.LoginCookie]; !ok {
			t.Errorf("headers %v: no login cookie", headers)
		}
	}
}

func TestLoginCookieIsSignedAndTamperingFails(t *testing.T) {
	p := newAuthPanel(t, nil)
	login, query := p.beginLogin("/")
	cookie := login.Cookies[oidc.LoginCookie].Value
	body, mac, _ := strings.Cut(cookie, ".")
	flipped := "B" + mac[1:]
	if mac[0] == 'B' {
		flipped = "A" + mac[1:]
	}
	for _, bad := range []string{body + "." + flipped, body + ".", "x." + mac, body} {
		eq(t, "tampered", p.callback(query, bad, "").Status, 400)
	}
	eq(t, "sessions", p.sessions(), 0)
	eq(t, "token requests", len(p.issuer.TokenRequests()), 0)
	eq(t, "untouched", p.callback(query, cookie, "").Status, 303)
}

func TestManyLoginsDoNotBreakSomeoneElsesSignIn(t *testing.T) {
	p := newAuthPanel(t, nil)
	// The rate limit is not what this is about: room for every request.
	p.srv.signInLimit = newTokenBucket(100, signInEvery)
	login, query := p.beginLogin("/")
	cookie := login.Cookies[oidc.LoginCookie].Value
	for i := 0; i < 30; i++ {
		eq(t, "login", p.get("/login", "", nil).Status, 303)
	}
	nonce := query["nonce"]
	p.issuer.Set(func(i *oidctest.Issuer) { i.Nonce = nonce })
	eq(t, "callback", p.callback(query, cookie, "").Status, 303)
}

func TestSignInStartedBeforeARestartFails(t *testing.T) {
	p := newAuthPanel(t, nil)
	login, query := p.beginLogin("/")
	cookie := login.Cookies[oidc.LoginCookie].Value
	p.srv.Auth = oidc.NewAuthenticator(p.srv.Settings.Auth, []string{"mine", "a", "b"}, p.clock.Now, nil)
	eq(t, "callback", p.callback(query, cookie, "").Status, 400)
}

func TestLoginWithHostileNextLandsOnTheRoot(t *testing.T) {
	p := newAuthPanel(t, nil)
	for _, bad := range []string{"https://evil.example.test/", "//evil.example.test", `/\evil`, "/static/x", "/?exit=A", "/embed?exit=a&x=1", "javascript:alert(1)"} {
		login, query := p.beginLogin(bad)
		done := p.callback(query, login.Cookies[oidc.LoginCookie].Value, "")
		eq(t, "next "+bad, done.Location(), publicURL+"/")
	}
}

func TestCallbackSetsLockedDownCookiesAndRedirectsToTheCanonicalURL(t *testing.T) {
	p := newAuthPanel(t, nil)
	login, query := p.beginLogin("/embed?exit=a")
	done := p.callback(query, login.Cookies[oidc.LoginCookie].Value, "")
	eq(t, "status", done.Status, 303)
	eq(t, "location", done.Location(), publicURL+"/embed?exit=a")
	cleared := done.Cookies[oidc.LoginCookie]
	if cleared.Value != "" || !cleared.Attrs["max-age=0"] {
		t.Errorf("login cookie not cleared: %+v", cleared)
	}
	session := done.Cookies[oidc.SessionCookie]
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(session.Value) ||
		!hasAll(session.Attrs, "secure", "httponly", "samesite=lax", "path=/", "max-age=3600") {
		t.Errorf("session cookie %+v", session)
	}
	for attr := range session.Attrs {
		if strings.HasPrefix(attr, "domain") {
			t.Error("the cookie has a Domain")
		}
	}
	eq(t, "Cache-Control", done.Header.Get("Cache-Control"), "no-store")
	eq(t, "sessions", p.sessions(), 1)
}

func TestCallbackOnTheIssuersRedirectWithASessionLandsOnThePanel(t *testing.T) {
	p := newAuthPanel(t, nil)
	session := p.signIn([]string{"friends-a"}, "jo", "user-1", "/?exit=a")
	a := p.get("/login?next=%2F%3Fexit%3Da", session, nil)
	eq(t, "status", a.Status, 303)
	eq(t, "location", a.Location(), publicURL+"/?exit=a")
}

func TestCallbackWithoutTheLoginCookieFails(t *testing.T) {
	p := newAuthPanel(t, nil)
	_, query := p.beginLogin("/")
	done := p.callback(query, "", "")
	eq(t, "status", done.Status, 400)
	if _, ok := done.Cookies[oidc.SessionCookie]; ok {
		t.Error("a session cookie was set")
	}
	eq(t, "sessions", p.sessions(), 0)
	eq(t, "token requests", len(p.issuer.TokenRequests()), 0)
}

func TestCallbackWithAMismatchedStateFailsAndBurnsTheSignIn(t *testing.T) {
	p := newAuthPanel(t, nil)
	login, query := p.beginLogin("/")
	cookie := login.Cookies[oidc.LoginCookie].Value
	done := p.callback(map[string]string{"state": "not-the-state"}, cookie, "")
	eq(t, "status", done.Status, 400)
	if _, ok := done.Cookies[oidc.SessionCookie]; ok {
		t.Error("a session cookie was set")
	}
	eq(t, "sessions", p.sessions(), 0)
	eq(t, "right state, too late", p.callback(query, cookie, "").Status, 400)
	eq(t, "sessions after", p.sessions(), 0)
	eq(t, "token requests", len(p.issuer.TokenRequests()), 0)
}

func TestCallbackWithAnotherBrowsersStateFails(t *testing.T) {
	p := newAuthPanel(t, nil)
	_, mine := p.beginLogin("/")
	login, _ := p.beginLogin("/")
	done := p.callback(mine, login.Cookies[oidc.LoginCookie].Value, "")
	eq(t, "status", done.Status, 400)
	eq(t, "sessions", p.sessions(), 0)
}

func TestCallbackWithAnIssuerErrorFailsWithoutEchoingIt(t *testing.T) {
	p := newAuthPanel(t, nil)
	login, query := p.beginLogin("/")
	cookie := login.Cookies[oidc.LoginCookie].Value
	done := p.get("/auth/callback?"+pystr.Encode(pystr.Pair{Key: "error", Value: "access_denied"},
		pystr.Pair{Key: "error_description", Value: "leak<script>x</script>"}, pystr.Pair{Key: "state", Value: query["state"]}),
		oidc.LoginCookie+"="+cookie, nil)
	eq(t, "status", done.Status, 403)
	mustNotContain(t, done.Body, "leak")
	if _, ok := done.Cookies[oidc.SessionCookie]; ok {
		t.Error("a session cookie was set")
	}
	eq(t, "login cookie", done.Cookies[oidc.LoginCookie].Value, "")
	eq(t, "sessions", p.sessions(), 0)
	// The attempt is burned even though the state was right.
	eq(t, "retry", p.callback(query, cookie, "").Status, 400)
}

func TestCallbackReplayFails(t *testing.T) {
	p := newAuthPanel(t, nil)
	login, query := p.beginLogin("/")
	cookie := login.Cookies[oidc.LoginCookie].Value
	eq(t, "first", p.callback(query, cookie, "authcode-replayed").Status, 303)
	eq(t, "second", p.callback(query, cookie, "authcode-replayed").Status, 400)
	eq(t, "sessions", p.sessions(), 1)
}

func TestCallbackWithoutACodeFails(t *testing.T) {
	p := newAuthPanel(t, nil)
	login, query := p.beginLogin("/")
	done := p.get("/auth/callback?"+pystr.Encode(pystr.Pair{Key: "state", Value: query["state"]}),
		oidc.LoginCookie+"="+login.Cookies[oidc.LoginCookie].Value, nil)
	eq(t, "status", done.Status, 400)
	eq(t, "sessions", p.sessions(), 0)
}

func TestAccountInNoGrantedGroupIsRefusedWithNoSession(t *testing.T) {
	p := newAuthPanel(t, nil)
	p.issuer.Set(func(i *oidctest.Issuer) { i.Groups = []string{"strangers"} })
	login, query := p.beginLogin("/")
	done := p.callback(query, login.Cookies[oidc.LoginCookie].Value, "")
	eq(t, "status", done.Status, 403)
	mustContain(t, strings.ToLower(done.Body), "not allowed")
	if _, ok := done.Cookies[oidc.SessionCookie]; ok {
		t.Error("a session cookie was set")
	}
	eq(t, "sessions", p.sessions(), 0)
}

func TestIssuerProblemAtLoginIsA503Page(t *testing.T) {
	p := newAuthPanel(t, nil)
	p.issuer.Close()
	a := p.get("/login", "", nil)
	eq(t, "status", a.Status, 503)
	mustContain(t, a.Body, "Try again")
	if _, ok := a.Cookies[oidc.LoginCookie]; ok {
		t.Error("a login cookie was set")
	}
}

func TestIssuerProblemAtTheCallbackIsA400Page(t *testing.T) {
	p := newAuthPanel(t, nil)
	login, query := p.beginLogin("/")
	p.issuer.Set(func(i *oidctest.Issuer) { i.TokenStatus = 500; i.TokenBody = []byte("leak-me-please") })
	done := p.callback(query, login.Cookies[oidc.LoginCookie].Value, "")
	eq(t, "status", done.Status, 400)
	mustNotContain(t, done.Body, "leak-me")
	mustNotContain(t, p.log.String(), "leak-me")
	eq(t, "sessions", p.sessions(), 0)
}

// -- AccessTests --------------------------------------------------------------------------

type accessPanel struct {
	*authPanel
	friend, admin string
}

func newAccessPanel(t *testing.T) *accessPanel {
	p := newAuthPanel(t, nil)
	friend := p.signIn([]string{"friends-a"}, "friend-a", "u-friend", "/")
	admin := p.signIn([]string{"admins"}, "boss", "u-admin", "/")
	return &accessPanel{p, friend, admin}
}

// assertSameAsNonexistent checks that asking for another exit looks exactly
// like asking for one that does not exist.
func (p *accessPanel) assertSameAsNonexistent(request func(exitID string) answer, status int, others ...string) {
	p.t.Helper()
	if len(others) == 0 {
		others = []string{"b", "mine"}
	}
	baseline := request("nope-zz")
	eq(p.t, "baseline status", baseline.Status, status)
	for _, other := range others {
		got := request(other)
		if got.Status != baseline.Status || got.Body != baseline.Body || got.signature() != baseline.signature() {
			p.t.Errorf("exit %s is distinguishable: %d %q", other, got.Status, got.Body)
		}
		if _, ok := got.Cookies["csrf_nonce"]; ok {
			p.t.Errorf("exit %s set a CSRF cookie", other)
		}
		if _, ok := got.Cookies["molebridge_exit"]; ok {
			p.t.Errorf("exit %s set an exit cookie", other)
		}
	}
}

func TestOtherExitsAreIndistinguishableFromNonexistentOnEveryGETPath(t *testing.T) {
	p := newAccessPanel(t)
	for _, prefix := range []string{"/", "/embed", "/api/status", "/api/latency", "/readyz"} {
		p.assertSameAsNonexistent(func(id string) answer { return p.get(prefix+"?exit="+id, p.friend, nil) }, 404)
	}
}

func TestOtherExitsAreIndistinguishableFromNonexistentOnSelect(t *testing.T) {
	p := newAccessPanel(t)
	n, tok := p.pageTokens(p.friend, "a", "/")
	tokens := [2]string{n, tok}
	p.assertSameAsNonexistent(func(id string) answer { return p.selectAs(p.friend, id, "", &tokens, "") }, 400)
	p.assertNoDesired()
}

func TestSelectWithAnotherExitsServerNameIsAlsoRefusedAlike(t *testing.T) {
	p := newAccessPanel(t)
	n, tok := p.pageTokens(p.friend, "a", "/")
	tokens := [2]string{n, tok}
	baseline := p.selectAs(p.friend, "nope-zz", "se-sto-wg-001", &tokens, "")
	for _, other := range []string{"mine", "b"} {
		got := p.selectAs(p.friend, other, "se-sto-wg-001", &tokens, "")
		if got.Status != baseline.Status || got.Body != baseline.Body {
			t.Errorf("%s: %d %q", other, got.Status, got.Body)
		}
	}
	p.assertNoDesired()
}

func TestUnparsableExitValuesAreRefusedAlike(t *testing.T) {
	p := newAccessPanel(t)
	n, tok := p.pageTokens(p.friend, "a", "/")
	tokens := [2]string{n, tok}
	baseline := p.selectAs(p.friend, "nope-zz", "", &tokens, "")
	for _, value := range []string{"", "../a", "A", "a ", " a", "a\x00", "mine,b", "a/../b"} {
		got := p.selectAs(p.friend, value, "", &tokens, "")
		if got.Status != baseline.Status || got.Body != baseline.Body {
			t.Errorf("exit %q: %d %q", value, got.Status, got.Body)
		}
	}
	p.assertNoDesired()
}

func TestSelectWithoutAnExitFieldIsRefused(t *testing.T) {
	p := newAccessPanel(t)
	nonce, token := p.pageTokens(p.friend, "a", "/")
	a := p.post("/select", [][2]string{{"server", selectServer}, {"csrf_token", token}}, p.friend+"; csrf_nonce="+nonce, "")
	eq(t, "status", a.Status, 400)
	p.assertNoDesired()
}

func exitIDs(t *testing.T, a answer) []string {
	t.Helper()
	var ids []string
	for _, e := range jsonBody(t, a)["exits"].([]any) {
		ids = append(ids, e.(map[string]any)["id"].(string))
	}
	return ids
}

func TestAPIExitsListsOnlyGrantedExits(t *testing.T) {
	p := newAccessPanel(t)
	eq(t, "friend", strings.Join(exitIDs(t, p.get("/api/exits", p.friend, nil)), ","), "a")
	eq(t, "admin", strings.Join(exitIDs(t, p.get("/api/exits", p.admin, nil)), ","), "mine,a,b")
}

func TestPageShowsNoOtherExit(t *testing.T) {
	p := newAccessPanel(t)
	for _, path := range []string{"/?exit=a", "/embed?exit=a"} {
		a := p.get(path, p.friend, nil)
		eq(t, "status", a.Status, 200)
		mustNotContain(t, a.Body, `class="exit-tab`, `data-multi="1"`, "exit=b", "exit=mine", `data-exit="b"`, `data-exit="mine"`,
			"ex_example", "se-sto-wg-001", "Exampleland", "PIA")
		mustContain(t, a.Body, `data-exit="a"`, selectServer)
	}
}

func TestRootRedirectsToTheGrantedExitEvenIfTheCookieNamesAnother(t *testing.T) {
	p := newAccessPanel(t)
	for _, other := range []string{"b", "mine", "nope"} {
		for path, target := range map[string]string{"/": "/?exit=a", "/embed": "/embed?exit=a"} {
			a := p.get(path, p.friend+"; molebridge_exit="+other, nil)
			if a.Status != 303 || a.Location() != target {
				t.Errorf("cookie %s, %s: %d %q", other, path, a.Status, a.Location())
			}
		}
	}
	eq(t, "no cookie", p.get("/", p.friend, nil).Location(), "/?exit=a")
}

func TestRootRedirectForAdminFollowsTheCookie(t *testing.T) {
	p := newAccessPanel(t)
	eq(t, "b", p.get("/", p.admin+"; molebridge_exit=b", nil).Location(), "/?exit=b")
	eq(t, "gone", p.get("/", p.admin+"; molebridge_exit=gone", nil).Location(), "/?exit=mine")
}

func TestGrantedPageSetsTheExitCookieOnlyForTheGrantedExit(t *testing.T) {
	p := newAccessPanel(t)
	a := p.get("/?exit=a", p.friend, nil)
	eq(t, "exit cookie", a.Cookies["molebridge_exit"].Value, "a")
}

func TestPageCookiesAreSecureWithSignInOn(t *testing.T) {
	p := newAccessPanel(t)
	a := p.get("/?exit=a", p.friend, nil)
	for _, name := range []string{"csrf_nonce", "molebridge_exit"} {
		if !hasAll(a.Cookies[name].Attrs, "secure", "httponly", "samesite=strict", "path=/") {
			t.Errorf("%s: %+v", name, a.Cookies[name])
		}
	}
}

func TestFriendCanReadStatusAndLatencyOfTheGrantedExit(t *testing.T) {
	p := newAccessPanel(t)
	view := jsonBody(t, p.get("/api/status?exit=a", p.friend, nil))["verdict"].(map[string]any)
	eq(t, "state", view["state"], any("ok"))
	eq(t, "latency", p.get("/api/latency?exit=a", p.friend, nil).Body, `{"latency": {}}`)
	eq(t, "readyz", p.get("/readyz?exit=a", p.friend, nil).Status, 200)
}

func TestAdminReachesEveryExitAndNonexistentIsStill404(t *testing.T) {
	p := newAccessPanel(t)
	for _, id := range []string{"mine", "a", "b"} {
		eq(t, "page "+id, p.get("/?exit="+id, p.admin, nil).Status, 200)
		eq(t, "status "+id, p.get("/api/status?exit="+id, p.admin, nil).Status, 200)
	}
	eq(t, "page", p.get("/?exit=nope-zz", p.admin, nil).Status, 404)
	eq(t, "readyz", p.get("/readyz?exit=nope-zz", p.admin, nil).Status, 404)
}

func TestAdminPageHasAllTabsAndTheHomeLink(t *testing.T) {
	p := newAccessPanel(t)
	page := p.get("/?exit=a", p.admin, nil).Body
	eq(t, "tabs", strings.Count(page, `class="exit-tab`), 4) // 3 tabs, 1 is also is-selected
	for _, id := range []string{"mine", "a", "b"} {
		mustContain(t, page, `href="/?exit=`+id+`"`)
	}
	mustContain(t, page, `href="https://home.example.test"`, "boss")
}

func TestNonAdminPageHasNoHomeLink(t *testing.T) {
	p := newAccessPanel(t)
	for _, path := range []string{"/?exit=a", "/embed?exit=a"} {
		mustNotContain(t, p.get(path, p.friend, nil).Body, "home.example.test")
	}
}

func TestUserInTwoGroupsSeesBothExitsAndNoMore(t *testing.T) {
	p := newAccessPanel(t)
	both := p.signIn([]string{"friends-a", "friends-b"}, "both", "u-both", "/")
	eq(t, "listed", strings.Join(exitIDs(t, p.get("/api/exits", both, nil)), ","), "a,b")
	eq(t, "mine", p.get("/?exit=mine", both, nil).Status, 404)
	page := p.get("/?exit=b", both, nil).Body
	eq(t, "tabs", strings.Count(page, `class="exit-tab`), 3)
	mustNotContain(t, page, "exit=mine")
}

func TestRepeatedGroupInPanelAccessGrantsSeveralExitsOverHTTP(t *testing.T) {
	p := newAuthPanel(t, map[string]string{"PANEL_ACCESS": "family=a, family=b"})
	friend := p.signIn([]string{"family"}, "fam", "u-fam", "/")
	eq(t, "listed", strings.Join(exitIDs(t, p.get("/api/exits", friend, nil)), ","), "a,b")
}

func TestPageShowsTheAccountAndASignOutForm(t *testing.T) {
	p := newAccessPanel(t)
	page := p.get("/?exit=a", p.friend, nil).Body
	mustContain(t, page, `action="/logout"`, "friend-a")
	eq(t, "tokens", strings.Count(page, `name="csrf_token"`), 2)
}

func TestAccountNameIsEscapedAndReduced(t *testing.T) {
	p := newAccessPanel(t)
	weird := p.signIn([]string{"friends-a"}, "<img src=x onerror=alert(1)>", "u-weird", "/")
	page := p.get("/?exit=a", weird, nil).Body
	mustNotContain(t, page, "<img src=x", "onerror=alert(1)>")
}

// -- SwitchTests -----------------------------------------------------------------------------

func newSwitchPanel(t *testing.T) *accessPanel {
	p := newAccessPanel(t)
	p.log.Reset()
	return p
}

func TestValidSelectOnTheGrantedExitWritesOnlyThatExitAndLogsIt(t *testing.T) {
	p := newSwitchPanel(t)
	a := p.selectAs(p.friend, "a", "", nil, "")
	eq(t, "status", a.Status, 303)
	eq(t, "location", a.Location(), "/?exit=a")
	eq(t, "written", readDesired(p.a)["server"], any(selectServer))
	p.assertNoDesired(p.mine, p.b)
	mustContain(t, p.log.String(), "switch: user=friend-a sub=u-friend exit=a server="+selectServer+"\n")
}

func TestSelectReturnsToEmbed(t *testing.T) {
	p := newSwitchPanel(t)
	a := p.selectAs(p.friend, "a", "", nil, "", [2]string{"return", "embed"})
	eq(t, "location", a.Location(), "/embed?exit=a")
}

func TestUnlistedServerIsRefusedAndNotLoggedAsASwitch(t *testing.T) {
	p := newSwitchPanel(t)
	for _, server := range []string{"se-sto-wg-001", "ex_example", "nope", blankServer} {
		eq(t, "server "+server, p.selectAs(p.friend, "a", server, nil, "").Status, 400)
	}
	if server := p.selectAs(p.friend, "a", "se-sto-wg-001", nil, ""); server.Status != 400 {
		t.Fatal("unlisted server accepted")
	}
	p.assertNoDesired()
	mustNotContain(t, p.log.String(), "switch:")
}

func TestAdminCanSwitchAnyExit(t *testing.T) {
	p := newSwitchPanel(t)
	bn, bt := p.pageTokens(p.admin, "b", "/")
	mn, mt := p.pageTokens(p.admin, "mine", "/")
	eq(t, "b", p.selectAs(p.admin, "b", "ex_example", &[2]string{bn, bt}, "").Status, 303)
	eq(t, "mine", p.selectAs(p.admin, "mine", "se-sto-wg-001", &[2]string{mn, mt}, "").Status, 303)
	eq(t, "b written", readDesired(p.b)["server"], any("ex_example"))
	eq(t, "mine written", readDesired(p.mine)["server"], any("se-sto-wg-001"))
	p.assertNoDesired(p.a)
	mustContain(t, p.log.String(), "switch: user=boss sub=u-admin exit=b server=ex_example\n", "switch: user=boss sub=u-admin exit=mine server=se-sto-wg-001\n")
}

func TestLogCarriesNoCredentials(t *testing.T) {
	p := newSwitchPanel(t)
	code := "authcode-must-not-be-logged"
	p.issuer.Set(func(i *oidctest.Issuer) { i.Groups = []string{"friends-a"}; i.Username = "logcheck" })
	login, query := p.beginLogin("/")
	loginID := login.Cookies[oidc.LoginCookie].Value
	done := p.callback(query, loginID, code)
	sessionID := done.Cookies[oidc.SessionCookie].Value
	cookie := oidc.SessionCookie + "=" + sessionID
	nonce, token := p.pageTokens(cookie, "a", "/")
	p.selectAs(cookie, "a", "", &[2]string{nonce, token}, "")
	p.post("/logout", [][2]string{{"csrf_token", token}}, cookie+"; csrf_nonce="+nonce, "")
	p.get("/auth/callback?code="+code+"&state=x", oidc.LoginCookie+"="+loginID, nil)
	form := p.issuer.TokenRequests()[len(p.issuer.TokenRequests())-1].Form
	idToken := p.issuer.LastToken()
	secrets := []string{code, oidctest.AccessToken, idToken, sessionID, loginID, token, nonce, query["state"], query["nonce"],
		form["code_verifier"], query["code_challenge"], strings.Split(idToken, ".")[1]}
	log := p.log.String()
	mustContain(t, log, "user=logcheck")
	for _, value := range secrets {
		if value == "" || strings.Contains(log, value) {
			t.Errorf("the log holds %q", value)
		}
	}
}

func TestCSRFTokenOfAnotherSessionIsRefused(t *testing.T) {
	p := newSwitchPanel(t)
	other := p.signIn([]string{"friends-a"}, "other", "u-other", "/")
	nonce, token := p.pageTokens(p.friend, "a", "/")
	fields := [][2]string{{"server", selectServer}, {"csrf_token", token}, {"exit", "a"}}
	eq(t, "another session", p.post("/select", fields, other+"; csrf_nonce="+nonce, "").Status, 403)
	p.assertNoDesired()
	// The same token with its own session works.
	eq(t, "own session", p.post("/select", fields, p.friend+"; csrf_nonce="+nonce, "").Status, 303)
}

func TestTokenNotBoundToASessionIsRefused(t *testing.T) {
	p := newSwitchPanel(t)
	nonce := newCSRFNonce()
	a := p.post("/select", [][2]string{{"server", selectServer}, {"csrf_token", p.srv.csrfToken(nonce, "")}, {"exit", "a"}}, p.friend+"; csrf_nonce="+nonce, "")
	eq(t, "status", a.Status, 403)
	p.assertNoDesired()
}

func TestAdminsTokenDoesNotWorkForAFriend(t *testing.T) {
	p := newSwitchPanel(t)
	nonce, token := p.pageTokens(p.admin, "b", "/")
	a := p.post("/select", [][2]string{{"server", selectServer}, {"csrf_token", token}, {"exit", "a"}}, p.friend+"; csrf_nonce="+nonce, "")
	eq(t, "status", a.Status, 403)
	p.assertNoDesired()
}

func TestMissingCSRFIsRefusedWithSignIn(t *testing.T) {
	p := newSwitchPanel(t)
	a := p.post("/select", [][2]string{{"server", selectServer}, {"exit", "a"}}, p.friend, "")
	eq(t, "status", a.Status, 403)
	p.assertNoDesired()
}

func TestOriginCheckUsesThePublicHost(t *testing.T) {
	p := newSwitchPanel(t)
	eq(t, "evil", p.selectAs(p.friend, "a", "", nil, "https://evil.example.test").Status, 403)
	p.assertNoDesired()
	eq(t, "public", p.selectAs(p.friend, "a", "", nil, "https://exit.example.test").Status, 303)
}

func TestLogoutNeedsTheCSRFToken(t *testing.T) {
	p := newSwitchPanel(t)
	nonce, token := p.pageTokens(p.friend, "a", "/")
	eq(t, "no token", p.post("/logout", nil, p.friend+"; csrf_nonce="+nonce, "").Status, 403)
	eq(t, "bad token", p.post("/logout", [][2]string{{"csrf_token", strings.Repeat("f", 64)}}, p.friend+"; csrf_nonce="+nonce, "").Status, 403)
	other := p.signIn([]string{"friends-a"}, "other", "u-other", "/")
	eq(t, "other session", p.post("/logout", [][2]string{{"csrf_token", token}}, other+"; csrf_nonce="+nonce, "").Status, 403)
	eq(t, "friend still in", p.get("/api/exits", p.friend, nil).Status, 200)
	eq(t, "other still in", p.get("/api/exits", other, nil).Status, 200)
}

func TestLogoutEndsTheSessionAndRedirectsToSignedOut(t *testing.T) {
	p := newSwitchPanel(t)
	nonce, token := p.pageTokens(p.friend, "a", "/")
	a := p.post("/logout", [][2]string{{"csrf_token", token}}, p.friend+"; csrf_nonce="+nonce, "")
	eq(t, "status", a.Status, 303)
	eq(t, "location", a.Location(), publicURL+"/signed-out")
	c := a.Cookies[oidc.SessionCookie]
	if c.Value != "" || !c.Attrs["max-age=0"] {
		t.Errorf("cookie %+v", c)
	}
	eq(t, "api", p.get("/api/exits", p.friend, nil).Status, 401)
	eq(t, "page", p.get("/?exit=a", p.friend, nil).Status, 303)
	after := p.post("/select", [][2]string{{"server", selectServer}, {"csrf_token", token}, {"exit", "a"}}, p.friend+"; csrf_nonce="+nonce, "")
	eq(t, "select", after.Status, 401)
	p.assertNoDesired()
	mustContain(t, p.log.String(), "signed out: user=friend-a")
	// The other session is untouched.
	eq(t, "admin", p.get("/api/exits", p.admin, nil).Status, 200)
}

func TestSignedOutPageOffersSignInOnTheCanonicalAddress(t *testing.T) {
	p := newSwitchPanel(t)
	a := p.get("/signed-out", "", nil)
	eq(t, "status", a.Status, 200)
	mustContain(t, a.Body, `href="`+publicURL+`/login?next=%2F"`)
}

func TestExpiredSessionIsSignedOut(t *testing.T) {
	p := newSwitchPanel(t)
	ttl := float64(p.srv.Settings.Auth.SessionTTL)
	p.clock.Advance(ttl - 5)
	eq(t, "before", p.get("/api/exits", p.friend, nil).Status, 200)
	p.clock.Advance(10)
	eq(t, "after", p.get("/api/exits", p.friend, nil).Status, 401)
	a := p.get("/?exit=a", p.friend, nil)
	eq(t, "page", a.Status, 303)
	if !strings.HasPrefix(a.Location(), publicURL+"/login?") {
		t.Errorf("location %q", a.Location())
	}
	embed := p.get("/embed?exit=a", p.friend, nil)
	eq(t, "embed", embed.Status, 200) // the sign-in link page
	mustNotContain(t, embed.Body, "csrf_token")
	nonce := newCSRFNonce()
	sel := p.post("/select", [][2]string{{"server", selectServer}, {"csrf_token", strings.Repeat("f", 64)}, {"exit", "a"}}, p.friend+"; csrf_nonce="+nonce, "")
	eq(t, "select", sel.Status, 401)
	eq(t, "admin", p.get("/api/exits", p.admin, nil).Status, 401)
	p.assertNoDesired()
}

func TestTokenFromBeforeExpiryDoesNotSwitchAfterIt(t *testing.T) {
	p := newSwitchPanel(t)
	nonce, token := p.pageTokens(p.friend, "a", "/")
	p.clock.Advance(float64(p.srv.Settings.Auth.SessionTTL) + 1)
	a := p.post("/select", [][2]string{{"server", selectServer}, {"csrf_token", token}, {"exit", "a"}}, p.friend+"; csrf_nonce="+nonce, "")
	eq(t, "status", a.Status, 401)
	p.assertNoDesired()
}

// -- ConfidentialClientPanelTests -------------------------------------------------------------

func TestSecretFileIsUsedForTheTokenRequestOnly(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "client-secret")
	if err := os.WriteFile(secret, []byte("panel-test-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := newAuthPanel(t, map[string]string{"PANEL_OIDC_CLIENT_SECRET_FILE": secret})
	session := p.signIn([]string{"friends-a"}, "jo", "user-1", "/")
	requests := p.issuer.TokenRequests()
	if !strings.HasPrefix(requests[len(requests)-1].Headers.Get("Authorization"), "Basic ") {
		t.Error("no Basic authorization")
	}
	mustNotContain(t, p.log.String(), "panel-test-secret-value")
	mustNotContain(t, p.get("/?exit=a", session, nil).Body, "panel-test-secret-value")
}

// -- NoSignInConfiguredTests ---------------------------------------------------------------------

// newOpenPanel is the same panel without PANEL_OIDC_ISSUER: exactly as it was
// before sign-in existed.
func newOpenPanel(t *testing.T) *authPanel {
	t.Helper()
	p := &authPanel{}
	p.harness = newHarness(t, map[string]string{"PANEL_EXITS": "mine=mullvad,a=mullvad,b=pia", "PANEL_HOME_URL": "https://home.example.test"}, nil)
	p.mine, p.a, p.b = p.exit("mine"), p.exit("a"), p.exit("b")
	p.writeCatalogues()
	return p
}

func TestSignInRoutesDoNotExist(t *testing.T) {
	p := newOpenPanel(t)
	for _, path := range []string{"/login", "/login?next=%2F", "/auth/callback", "/auth/callback?code=x&state=y", "/signed-out"} {
		if a := p.get(path, "", nil); a.Status != 404 || a.Body != "not found" {
			t.Errorf("%s: %d %q", path, a.Status, a.Body)
		}
	}
	if a := p.post("/logout", nil, "", ""); a.Status != 404 || a.Body != "not found" {
		t.Errorf("logout: %d %q", a.Status, a.Body)
	}
	eq(t, "logout with token", p.post("/logout", [][2]string{{"csrf_token", strings.Repeat("f", 64)}}, "csrf_nonce=x", "").Status, 404)
}

func TestEverythingIsOpenToAnyoneWhoReachesThePanel(t *testing.T) {
	p := newOpenPanel(t)
	eq(t, "b", p.get("/?exit=b", "", nil).Status, 200)
	eq(t, "embed", p.get("/embed?exit=mine", "", nil).Status, 200)
	eq(t, "status", p.get("/api/status?exit=a", "", nil).Status, 200)
	eq(t, "exits", strings.Join(exitIDs(t, p.get("/api/exits", "", nil)), ","), "mine,a,b")
	eq(t, "readyz", p.get("/readyz?exit=b", "", nil).Status, 200)
	eq(t, "unknown readyz", p.get("/readyz?exit=nope-zz", "", nil).Status, 404)
	eq(t, "remembered", p.get("/", "molebridge_exit=b", nil).Location(), "/?exit=b")
}

func TestPageHasNoAccountFormAndKeepsTheHomeLink(t *testing.T) {
	p := newOpenPanel(t)
	page := p.get("/?exit=a", "", nil).Body
	mustNotContain(t, page, "/logout", `class="account"`)
	mustContain(t, page, `href="https://home.example.test"`)
	eq(t, "tabs", strings.Count(page, `class="exit-tab`), 4)
}

func TestSelectWorksWithAnUnboundTokenAndLogsNoUser(t *testing.T) {
	p := newOpenPanel(t)
	nonce, token := p.pageTokens("", "a", "/")
	a := p.post("/select", [][2]string{{"server", selectServer}, {"csrf_token", token}, {"exit", "a"}}, "csrf_nonce="+nonce, "")
	eq(t, "status", a.Status, 303)
	eq(t, "location", a.Location(), "/?exit=a")
	eq(t, "written", readDesired(p.a)["server"], any(selectServer))
	mustNotContain(t, p.log.String(), "switch:")
}

func TestPageCookiesAreNotMarkedSecure(t *testing.T) {
	p := newOpenPanel(t)
	a := p.get("/?exit=a", "", nil)
	for _, name := range []string{"csrf_nonce", "molebridge_exit"} {
		attrs := a.Cookies[name].Attrs
		if attrs["secure"] || !hasAll(attrs, "httponly", "samesite=strict", "path=/") {
			t.Errorf("%s: %+v", name, a.Cookies[name])
		}
	}
}

func TestForwardedProtoMeansNothing(t *testing.T) {
	p := newOpenPanel(t)
	eq(t, "status", p.get("/login", "", map[string]string{"X-Forwarded-Proto": "http"}).Status, 404)
}

func TestASessionCookieMeansNothing(t *testing.T) {
	p := newOpenPanel(t)
	eq(t, "status", p.get("/api/exits", oidc.SessionCookie+"="+tokenURLSafe(), nil).Status, 200)
}

var _ = json.Marshal
