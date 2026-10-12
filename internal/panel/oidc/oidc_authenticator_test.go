package oidc

// Ported from panel/test_oidc.py: AuthenticatorTests, ReviewFindingTests
// (the Authenticator parts) and UserAgentTests.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/irashack/molebridge/internal/panel/oidc/oidctest"
)

const notStarted = "callback: this browser did not start a sign-in, or it expired"

type authFixture struct {
	t      *testing.T
	clock  *oidctest.Clock
	issuer *oidctest.Issuer
	config *Config
	auth   *Authenticator
}

func newAuthFixture(t *testing.T) *authFixture {
	t.Helper()
	f := &authFixture{t: t, clock: &oidctest.Clock{}}
	f.issuer = oidctest.New(t, f.clock.Now)
	f.config = cfg(t, envFor(f.issuer.URL, nil))
	f.auth = NewAuthenticator(f.config, testExitIDs, f.clock.Now, nil)
	return f
}

// begin starts a sign-in and returns the login cookie and the authorization
// URL's query; the fake issuer learns the nonce, as the test would copy it.
func (f *authFixture) begin(nextPath string) (string, map[string]string) {
	f.t.Helper()
	cookie, target, err := f.auth.Begin(nextPath)
	if err != nil {
		f.t.Fatalf("Begin: %v", err)
	}
	return cookie, f.recordNonce(target)
}

func (f *authFixture) recordNonce(target string) map[string]string {
	u, err := url.Parse(target)
	if err != nil {
		f.t.Fatal(err)
	}
	query := map[string]string{}
	for k := range u.Query() {
		query[k] = u.Query().Get(k)
	}
	f.issuer.Set(func(i *oidctest.Issuer) { i.Nonce = query["nonce"] })
	return query
}

func (f *authFixture) signIn(groups []string, sub string) (string, *Session, string, error) {
	f.t.Helper()
	f.issuer.Set(func(i *oidctest.Issuer) { i.Groups = groups; i.Sub = sub })
	cookie, query := f.begin("/")
	return f.auth.Finish(cookie, query["state"], "code-0001")
}

func (f *authFixture) mustSignIn(groups []string, sub string) (string, *Session) {
	f.t.Helper()
	id, session, _, err := f.signIn(groups, sub)
	if err != nil {
		f.t.Fatalf("sign-in: %v", err)
	}
	return id, session
}

func (f *authFixture) assertNotStarted(cookie, state string) {
	f.t.Helper()
	_, _, _, err := f.auth.Finish(cookie, state, "code-0001")
	if err == nil || err.Error() != notStarted {
		f.t.Fatalf("Finish = %v, want %q", err, notStarted)
	}
}

func (f *authFixture) assertAuthError(prefix string, err error) {
	f.t.Helper()
	var ae *AuthError
	if !errors.As(err, &ae) || !strings.HasPrefix(ae.Msg, prefix) {
		f.t.Fatalf("error %v, want an AuthError starting %q", err, prefix)
	}
}

func (f *authFixture) sessionCount() int {
	f.auth.mu.Lock()
	defer f.auth.mu.Unlock()
	return len(f.auth.sessions)
}

func (f *authFixture) consumedCount() int {
	f.auth.mu.Lock()
	defer f.auth.mu.Unlock()
	return f.auth.consumed.Len()
}

// sealRaw signs arbitrary cookie contents with the Authenticator's key.
func (f *authFixture) sealRaw(raw []byte) string {
	body := b64url(raw)
	return body + "." + f.auth.sign(body)
}

func (f *authFixture) sealed(overrides map[string]any) string {
	fields := map[string]any{"state": strings.Repeat("st", 16), "next_path": "/", "created": int64(f.auth.now())}
	for k, v := range overrides {
		fields[k] = v
	}
	raw, _ := json.Marshal(fields)
	return f.sealRaw(raw)
}

func TestAuthorizationURL(t *testing.T) {
	f := newAuthFixture(t)
	cookie, query := f.begin("/?exit=a")
	if !validLoginCookie(cookie) {
		t.Fatalf("login cookie %q is not well formed", cookie)
	}
	for k, want := range map[string]string{"response_type": "code", "client_id": oidctest.ClientID,
		"redirect_uri": testPublicURL + "/auth/callback", "scope": DefaultScopes, "code_challenge_method": "S256"} {
		if query[k] != want {
			t.Errorf("%s = %q, want %q", k, query[k], want)
		}
	}
	if len(query["state"]) < 32 || len(query["nonce"]) < 32 || query["state"] == query["nonce"] {
		t.Errorf("state %q nonce %q", query["state"], query["nonce"])
	}
	_, target, err := f.auth.Begin("/")
	if u, perr := url.Parse(target); err != nil || perr != nil || u.Path != "/authorize" {
		t.Errorf("authorization URL %q: %v %v", target, err, perr)
	}
}

func TestSignInSendsPKCEVerifierAndCreatesASession(t *testing.T) {
	f := newAuthFixture(t)
	loginID, query := f.begin("/embed?exit=a")
	sessionID, session, nextPath, err := f.auth.Finish(loginID, query["state"], "code-0001")
	if err != nil {
		t.Fatal(err)
	}
	req := f.issuer.TokenRequests()[0]
	for k, want := range map[string]string{"grant_type": "authorization_code", "code": "code-0001",
		"redirect_uri": testPublicURL + "/auth/callback", "client_id": oidctest.ClientID} {
		if req.Form[k] != want {
			t.Errorf("form %s = %q, want %q", k, req.Form[k], want)
		}
	}
	if PKCEChallenge(req.Form["code_verifier"]) != query["code_challenge"] {
		t.Error("the verifier does not answer the challenge")
	}
	if req.Headers.Get("Authorization") != "" {
		t.Error("a public client sent a secret")
	}
	if nextPath != "/embed?exit=a" {
		t.Errorf("next path = %q", nextPath)
	}
	if session.Sub != "user-1" || session.Name != "jo" || session.Admin || !session.Exits.Equal(NewSet("a")) ||
		!session.Groups.Equal(NewSet("friends-a")) {
		t.Errorf("session = %+v", session)
	}
	if f.auth.Session(sessionID) != session {
		t.Error("lookup returns another session")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(sessionID) || sessionID == loginID || strings.Contains(sessionID, query["nonce"]) {
		t.Errorf("session id %q", sessionID)
	}
}

func TestAdminSessionGetsEveryExit(t *testing.T) {
	f := newAuthFixture(t)
	_, session := f.mustSignIn([]string{"admins"}, "user-1")
	if !session.Admin || !session.Exits.Equal(NewSet(testExitIDs...)) {
		t.Fatalf("session = %+v", session)
	}
}

func TestClientSecretIsSentAsBasicAuth(t *testing.T) {
	f := newAuthFixture(t)
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("s3cr3t/value+x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := cfg(t, envFor(f.issuer.URL, o("PANEL_OIDC_CLIENT_SECRET_FILE", path)))
	f.auth = NewAuthenticator(config, testExitIDs, f.clock.Now, nil)
	f.mustSignIn([]string{"friends-a"}, "user-1")
	pair := url.QueryEscape(oidctest.ClientID) + ":" + strings.ReplaceAll(url.QueryEscape("s3cr3t/value+x"), "+", "%20")
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(pair))
	if got := f.issuer.TokenRequests()[0].Headers.Get("Authorization"); got != want {
		t.Fatalf("Authorization = %q, want %q", got, want)
	}
}

func TestPendingSignInIsConsumedOnce(t *testing.T) {
	f := newAuthFixture(t)
	loginID, query := f.begin("/")
	if _, _, _, err := f.auth.Finish(loginID, query["state"], "code-0001"); err != nil {
		t.Fatal(err)
	}
	f.assertNotStarted(loginID, query["state"]) // replay of the same callback
	if n := len(f.issuer.TokenRequests()); n != 1 {
		t.Fatalf("%d token requests", n)
	}
}

func TestWrongStateFailsAndUsesUpTheSignIn(t *testing.T) {
	f := newAuthFixture(t)
	for _, bad := range []string{"wrong", ""} {
		loginID, query := f.begin("/")
		_, _, _, err := f.auth.Finish(loginID, bad, "code-0001")
		if err == nil || err.Error() != "callback: the sign-in state does not match" {
			t.Fatalf("state %q: %v", bad, err)
		}
		// The correct state no longer helps: the attempt was used up.
		f.assertNotStarted(loginID, query["state"])
	}
	if len(f.issuer.TokenRequests()) != 0 || f.sessionCount() != 0 {
		t.Fatal("a refused sign-in reached the issuer or made a session")
	}
}

func TestStateFromAnotherSignInFails(t *testing.T) {
	f := newAuthFixture(t)
	first, _ := f.begin("/")
	_, second := f.begin("/")
	if _, _, _, err := f.auth.Finish(first, second["state"], "code-0001"); err == nil {
		t.Fatal("another sign-in's state accepted")
	}
}

func TestMissingOrBadLoginIDOrCode(t *testing.T) {
	f := newAuthFixture(t)
	loginID, query := f.begin("/")
	for _, bad := range []string{"", "short", strings.Repeat("x", 43), strings.Repeat("é", 43), "a.b", "." + strings.Repeat("A", 43),
		strings.Repeat("A", 2049) + "." + strings.Repeat("A", 43), loginID + "A"} {
		f.assertNotStarted(bad, query["state"])
	}
	for _, bad := range []string{"", strings.Repeat("c", 4097)} {
		loginID, query := f.begin("/")
		_, _, _, err := f.auth.Finish(loginID, query["state"], bad)
		if err == nil || !strings.Contains(err.Error(), "no code") {
			t.Fatalf("code %q: %v", bad[:min(len(bad), 5)], err)
		}
	}
}

func TestExpiredPendingSignInFails(t *testing.T) {
	f := newAuthFixture(t)
	loginID, query := f.begin("/")
	f.clock.Advance(LoginTTL + 1)
	_, _, _, err := f.auth.Finish(loginID, query["state"], "code-0001")
	f.assertAuthError("callback:", err)
	if len(f.issuer.TokenRequests()) != 0 {
		t.Fatal("an expired sign-in reached the issuer")
	}
}

func TestPendingSignInStillValidJustBeforeExpiry(t *testing.T) {
	f := newAuthFixture(t)
	loginID, query := f.begin("/")
	f.clock.Advance(LoginTTL - 5)
	if _, _, _, err := f.auth.Finish(loginID, query["state"], "code-0001"); err != nil {
		t.Fatal(err)
	}
}

func TestSessionExpiresAfterSessionTTLAndGroupsAreReadAgain(t *testing.T) {
	f := newAuthFixture(t)
	sessionID, session := f.mustSignIn([]string{"friends-a"}, "user-1")
	ttl := float64(f.config.SessionTTL)
	f.clock.Advance(ttl - 5)
	if f.auth.Session(sessionID) != session {
		t.Fatal("session gone early")
	}
	f.clock.Advance(10)
	if f.auth.Session(sessionID) != nil {
		t.Fatal("session outlived its lifetime")
	}
	f.auth.mu.Lock()
	_, kept := f.auth.sessions[sessionID]
	f.auth.mu.Unlock()
	if kept {
		t.Fatal("expired session kept")
	}
	// Removed from the group at the issuer: the next sign-in is refused.
	_, _, _, err := f.signIn([]string{"someone-elses"}, "user-1")
	f.assertAuthError("access:", err)
}

func TestSessionExpiresExactlyAtTheTTL(t *testing.T) {
	f := newAuthFixture(t)
	sessionID, _ := f.mustSignIn([]string{"friends-a"}, "user-1")
	f.clock.Advance(float64(f.config.SessionTTL) + 0.001)
	if f.auth.Session(sessionID) != nil {
		t.Fatal("session outlived its lifetime")
	}
}

func TestGroupsGrantingNothingGetNoSession(t *testing.T) {
	f := newAuthFixture(t)
	for _, groups := range [][]string{{"strangers"}, {}, {"Admins"}, {"friends-a "}} {
		_, _, _, err := f.signIn(groups, "user-1")
		f.assertAuthError("access:", err)
	}
	if f.sessionCount() != 0 {
		t.Fatal("a session was made")
	}
	if len(f.issuer.UserinfoRequests()) != 0 { // an empty claim is an answer, not a gap
		t.Fatal("userinfo was asked")
	}
}

func TestUserinfoFallbackWhenTheIDTokenHasNoGroupsClaim(t *testing.T) {
	f := newAuthFixture(t)
	f.issuer.Set(func(i *oidctest.Issuer) { i.IncludeGroups = false; i.UserinfoGroups = []string{"friends-b"} })
	_, session := f.mustSignIn(nil, "user-1")
	if !session.Exits.Equal(NewSet("b")) {
		t.Fatalf("exits = %v", session.Exits.Sorted())
	}
	if got := f.issuer.UserinfoRequests()[0].Headers.Get("Authorization"); got != "Bearer "+oidctest.AccessToken {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestUserinfoWithAnotherSubjectIsRefused(t *testing.T) {
	f := newAuthFixture(t)
	other := "someone-else"
	f.issuer.Set(func(i *oidctest.Issuer) {
		i.IncludeGroups = false
		i.UserinfoSub = &other
		i.UserinfoGroups = []string{"admins"}
	})
	_, _, _, err := f.signIn([]string{"friends-a"}, "user-1")
	f.assertAuthError("userinfo:", err)
	if f.sessionCount() != 0 {
		t.Fatal("a session was made")
	}
}

func TestUserinfoWithoutGroupsOrWithoutEndpointIsRefused(t *testing.T) {
	f := newAuthFixture(t)
	f.issuer.Set(func(i *oidctest.Issuer) { i.IncludeGroups = false; i.UserinfoIncludeGrps = false })
	_, _, _, err := f.signIn([]string{"friends-a"}, "user-1")
	if err == nil || !strings.Contains(err.Error(), "no groups claim") {
		t.Fatalf("err = %v", err)
	}
	// No userinfo endpoint advertised: nowhere else to look.
	f.issuer.Set(func(i *oidctest.Issuer) { i.AdvertiseUserinfo = false })
	f.auth = NewAuthenticator(f.config, testExitIDs, f.clock.Now, nil)
	_, _, _, err = f.signIn([]string{"friends-a"}, "user-1")
	f.assertAuthError("token:", err)
	if f.sessionCount() != 0 {
		t.Fatal("a session was made")
	}
}

func TestCustomGroupsClaim(t *testing.T) {
	f := newAuthFixture(t)
	config := cfg(t, envFor(f.issuer.URL, o("PANEL_OIDC_GROUPS_CLAIM", "roles")))
	f.auth = NewAuthenticator(config, testExitIDs, f.clock.Now, nil)
	f.issuer.Set(func(i *oidctest.Issuer) {
		i.IncludeGroups = false
		i.ClaimsExtra = map[string]any{"roles": []string{"friends-b"}}
	})
	_, session := f.mustSignIn([]string{"friends-a"}, "user-1")
	if !session.Exits.Equal(NewSet("b")) {
		t.Fatalf("exits = %v", session.Exits.Sorted())
	}
}

func TestMalformedGroupsClaimIsRefusedInASignIn(t *testing.T) {
	f := newAuthFixture(t)
	f.issuer.Set(func(i *oidctest.Issuer) { i.ClaimsExtra = map[string]any{"groups": map[string]any{"friends-a": true}} })
	if _, _, _, err := f.signIn([]string{"friends-a"}, "user-1"); err == nil {
		t.Fatal("a malformed groups claim made a session")
	}
}

func TestIDTokenProblemsLeaveNoSession(t *testing.T) {
	f := newAuthFixture(t)
	now := f.auth.now()
	for claim, value := range map[string]any{"iss": "https://other.example.test", "aud": "other", "exp": now - 9999,
		"iat": now + 9999, "nonce": "not-mine"} {
		f.issuer.Set(func(i *oidctest.Issuer) { i.ClaimsExtra = map[string]any{claim: value} })
		if _, _, _, err := f.signIn([]string{"friends-a"}, "user-1"); err == nil {
			t.Errorf("claim %s: a session was made", claim)
		}
	}
	f.issuer.Set(func(i *oidctest.Issuer) {
		i.ClaimsExtra = map[string]any{}
		i.ClaimsDrop = map[string]bool{"sub": true}
	})
	if _, _, _, err := f.signIn([]string{"friends-a"}, "user-1"); err == nil {
		t.Error("a token without a subject made a session")
	}
	if f.sessionCount() != 0 {
		t.Fatal("a session was made")
	}
}

func TestIssuerFailuresGiveFixedMessagesWithoutTheResponseBody(t *testing.T) {
	f := newAuthFixture(t)
	f.issuer.Set(func(i *oidctest.Issuer) {
		i.TokenStatus = 500
		i.TokenBody = []byte(`{"error_description": "leak-me-please", "id_token": "leak-me-too"}`)
	})
	_, _, _, err := f.signIn([]string{"friends-a"}, "user-1")
	if err == nil || err.Error() != "token: the issuer answered HTTP 500" {
		t.Fatalf("err = %v", err)
	}
	f.issuer.Set(func(i *oidctest.Issuer) { i.TokenStatus = 200 })
	for _, tc := range []struct{ body, fragment string }{
		{"leak-me-please", "not valid JSON"}, {`["leak-me-please"]`, "not a JSON object"},
		{`{"a": 1, "a": 2}`, "not valid JSON"}, {strings.Repeat("x", MaxResponseBytes+10), "too large"},
	} {
		f.issuer.Set(func(i *oidctest.Issuer) { i.TokenBody = []byte(tc.body) })
		_, _, _, err := f.signIn([]string{"friends-a"}, "user-1")
		if err == nil || !strings.Contains(err.Error(), tc.fragment) || strings.Contains(err.Error(), "leak-me") {
			t.Fatalf("body %.12q: err = %v", tc.body, err)
		}
	}
	f.issuer.Set(func(i *oidctest.Issuer) { i.TokenBody = []byte(`{"access_token": "x"}`) })
	_, _, _, err = f.signIn([]string{"friends-a"}, "user-1")
	if err == nil || !strings.Contains(err.Error(), "no ID token") {
		t.Fatalf("err = %v", err)
	}
}

func TestUnreachableIssuer(t *testing.T) {
	f := newAuthFixture(t)
	dead := oidctest.New(t, f.clock.Now)
	deadURL := dead.URL
	// Close it so nothing listens there; the cleanup closing again is harmless.
	dead.Close()
	config := cfg(t, envFor(deadURL, nil))
	auth := NewAuthenticator(config, testExitIDs, f.clock.Now, nil)
	_, _, err := auth.Begin("/")
	if err == nil || err.Error() != "discovery: the issuer could not be reached" {
		t.Fatalf("err = %v", err)
	}
}

func TestDiscoveryIsCachedThenRefreshed(t *testing.T) {
	f := newAuthFixture(t)
	f.begin("/")
	f.begin("/")
	if hits := f.issuer.DiscoveryHitCount(); hits != 1 {
		t.Fatalf("hits = %d", hits)
	}
	f.clock.Advance(DiscoveryTTL + 1)
	f.begin("/")
	if hits := f.issuer.DiscoveryHitCount(); hits != 2 {
		t.Fatalf("hits = %d", hits)
	}
}

func TestSessionLookupRejectsJunkAndEndRemoves(t *testing.T) {
	f := newAuthFixture(t)
	sessionID, _ := f.mustSignIn([]string{"friends-a"}, "user-1")
	for _, junk := range []string{"", "short", strings.Repeat("x", 43), sessionID + "x", sessionID[:len(sessionID)-1], strings.Repeat("é", 43)} {
		if f.auth.Session(junk) != nil {
			t.Errorf("junk %q found a session", junk)
		}
	}
	if f.auth.Session(sessionID) == nil {
		t.Fatal("session lost")
	}
	f.auth.End("unknown")
	f.auth.End("")
	if f.auth.Session(sessionID) == nil {
		t.Fatal("session ended by another id")
	}
	f.auth.End(sessionID)
	if f.auth.Session(sessionID) != nil {
		t.Fatal("session survived End")
	}
}

func TestDiscardUsesUpAPendingSignIn(t *testing.T) {
	f := newAuthFixture(t)
	loginID, query := f.begin("/")
	f.auth.Discard(loginID)
	f.auth.Discard("")
	f.auth.Discard("junk")
	f.assertNotStarted(loginID, query["state"])
	if len(f.issuer.TokenRequests()) != 0 {
		t.Fatal("a discarded sign-in reached the issuer")
	}
}

func TestTamperedCookiesFail(t *testing.T) {
	f := newAuthFixture(t)
	loginID, query := f.begin("/")
	body, mac, _ := strings.Cut(loginID, ".")
	otherBody, _, _ := strings.Cut(f.sealed(nil), ".")
	flipped := "B" + mac[1:]
	if mac[0] == 'B' {
		flipped = "A" + mac[1:]
	}
	for label, cookie := range map[string]string{
		"body changed": otherBody + "." + mac, "mac changed": body + "." + flipped, "mac cut": body + "." + mac[:len(mac)-1],
		"mac emptied": body + ".", "body emptied": "." + mac, "mac swapped with body": mac + "." + body,
		"two macs": loginID + "." + mac,
	} {
		t.Run(label, func(t *testing.T) { f.assertNotStarted(cookie, query["state"]) })
	}
	// The untouched cookie still works: tampering did not use it up.
	if _, _, _, err := f.auth.Finish(loginID, query["state"], "code-0001"); err != nil {
		t.Fatal(err)
	}
}

func TestAlteringTheEmbeddedFieldsFails(t *testing.T) {
	f := newAuthFixture(t)
	loginID, query := f.begin("/")
	body, mac, _ := strings.Cut(loginID, ".")
	raw, err := b64urlDecode(body)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["next_path"] = "/embed?exit=b"
	forgedRaw, _ := json.Marshal(fields)
	f.assertNotStarted(b64url(forgedRaw)+"."+mac, query["state"])
}

func TestCookieFromAnotherAuthenticatorFails(t *testing.T) {
	f := newAuthFixture(t)
	other := NewAuthenticator(f.config, testExitIDs, f.clock.Now, nil)
	cookie, target, err := other.Begin("/")
	if err != nil {
		t.Fatal(err)
	}
	query := f.recordNonce(target)
	f.assertNotStarted(cookie, query["state"])
	if len(f.issuer.TokenRequests()) != 0 {
		t.Fatal("a foreign cookie reached the issuer")
	}
	if _, _, _, err := other.Finish(cookie, query["state"], "code-0001"); err != nil { // it works where it was made
		t.Fatal(err)
	}
}

func TestAProcessRestartInvalidatesPendingSignIns(t *testing.T) {
	f := newAuthFixture(t)
	loginID, query := f.begin("/")
	restarted := NewAuthenticator(f.config, testExitIDs, f.clock.Now, nil)
	if _, _, _, err := restarted.Finish(loginID, query["state"], "code-0001"); err == nil {
		t.Fatal("a pending sign-in survived a restart")
	}
}

func TestSignedCookiesWithBadContentsFail(t *testing.T) {
	f := newAuthFixture(t)
	now := int64(f.auth.now())
	for label, raw := range map[string]string{
		"future":      f.sealedJSON(`"created":` + itoa(now+1000)),
		"ancient":     f.sealedJSON(`"created":` + itoa(now-10*86400)),
		"negative":    f.sealedJSON(`"created":-5`),
		"string time": f.sealedJSON(`"created":"` + itoa(now) + `"`),
		"float time":  f.sealedJSON(`"created":` + itoa(now) + `.5`),
		"null time":   f.sealedJSON(`"created":null`),
		"bool time":   f.sealedJSON(`"created":true`),
	} {
		t.Run(label, func(t *testing.T) { f.assertNotStarted(raw, strings.Repeat("st", 16)) })
	}
	// Correctly signed but not the right shape.
	for label, raw := range map[string]string{
		"extra field":    `{"state":"s","nonce":"n","verifier":"v","next_path":"/","created":` + itoa(now) + `,"admin":true}`,
		"missing field":  `{"state":"s","nonce":"n"}`,
		"not an object":  `[1,2]`,
		"duplicate keys": `{"state": "s", "state": "t"}`,
	} {
		t.Run(label, func(t *testing.T) { f.assertNotStarted(f.sealRaw([]byte(raw)), "") })
	}
}

func (f *authFixture) sealedJSON(created string) string {
	return f.sealRaw([]byte(`{"state":"` + strings.Repeat("st", 16) + `","next_path":"/",` + created + `}`))
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestExpiredCookieFailsAndIsNotAcceptedLate(t *testing.T) {
	f := newAuthFixture(t)
	loginID, query := f.begin("/")
	f.clock.Advance(LoginTTL + 2)
	f.assertNotStarted(loginID, query["state"])
	if len(f.issuer.TokenRequests()) != 0 {
		t.Fatal("an expired cookie reached the issuer")
	}
}

func TestManySignInsDoNotDisturbAnotherBrowsersPendingSignIn(t *testing.T) {
	f := newAuthFixture(t)
	victim, victimQuery := f.begin("/")
	for i := 0; i < 3000; i++ {
		if _, _, err := f.auth.Begin("/"); err != nil {
			t.Fatal(err)
		}
	}
	if f.sessionCount() != 0 {
		t.Fatal("sessions were made")
	}
	f.issuer.Set(func(i *oidctest.Issuer) { i.Nonce = victimQuery["nonce"] })
	_, session, _, err := f.auth.Finish(victim, victimQuery["state"], "code-0001")
	if err != nil || session.Sub != "user-1" {
		t.Fatalf("Finish = %v, %v", session, err)
	}
}

func TestTheReplayMemoryIsBounded(t *testing.T) {
	f := newAuthFixture(t)
	f.auth.Limits.MaxConsumedLogins = 3
	for i := 0; i < 10; i++ {
		loginID, _ := f.begin("/")
		f.auth.Discard(loginID)
		if n := f.consumedCount(); n > 3 {
			t.Fatalf("%d remembered sign-ins", n)
		}
	}
}

func TestOneSubjectsSignInsReplaceTheirOwnOldestSessionOnly(t *testing.T) {
	f := newAuthFixture(t)
	f.auth.Limits.MaxSessionsPerSubject = 2
	bystander, _ := f.mustSignIn([]string{"friends-a"}, "bystander")
	var ids []string
	for i := 0; i < 4; i++ {
		f.clock.Advance(1)
		id, _ := f.mustSignIn([]string{"friends-a"}, "busy")
		ids = append(ids, id)
	}
	if f.auth.Session(bystander) == nil {
		t.Fatal("the bystander lost a session")
	}
	var live []bool
	for _, id := range ids {
		live = append(live, f.auth.Session(id) != nil)
	}
	if live[0] || live[1] || !live[2] || !live[3] {
		t.Fatalf("live = %v", live)
	}
	if n := f.sessionCount(); n != 3 {
		t.Fatalf("%d sessions", n)
	}
	// Another subject is not affected by the first one's churn.
	other, _ := f.mustSignIn([]string{"friends-a"}, "other")
	if f.auth.Session(other) == nil || f.auth.Session(ids[3]) == nil {
		t.Fatal("a session was lost")
	}
}

func TestSessionsAreCappedByEvictingTheOldest(t *testing.T) {
	f := newAuthFixture(t)
	f.auth.Limits.MaxSessions = 2
	var ids []string
	for i := 0; i < 3; i++ {
		f.clock.Advance(1)
		id, _ := f.mustSignIn([]string{"friends-a"}, "user-"+string(rune('0'+i)))
		ids = append(ids, id)
	}
	if n := f.sessionCount(); n != 2 {
		t.Fatalf("%d sessions", n)
	}
	if f.auth.Session(ids[0]) != nil || f.auth.Session(ids[1]) == nil || f.auth.Session(ids[2]) == nil {
		t.Fatal("the wrong session was evicted")
	}
}

func TestExpiredEntriesArePrunedNotKept(t *testing.T) {
	f := newAuthFixture(t)
	loginID, query := f.begin("/")
	if _, _, _, err := f.auth.Finish(loginID, query["state"], "code-0001"); err != nil {
		t.Fatal(err)
	}
	if n := f.consumedCount(); n != 1 {
		t.Fatalf("consumed = %d", n)
	}
	f.clock.Advance(float64(f.config.SessionTTL + LoginTTL + 1))
	f.begin("/")
	cookie, _ := f.begin("/")
	f.auth.Discard(cookie)
	if n := f.consumedCount(); n != 1 {
		t.Fatalf("consumed = %d", n)
	}
	// Expired sessions go at the next completed sign-in.
	loginID, query = f.begin("/")
	if _, _, _, err := f.auth.Finish(loginID, query["state"], "code-0002"); err != nil {
		t.Fatal(err)
	}
	if n := f.sessionCount(); n != 1 {
		t.Fatalf("sessions = %d", n)
	}
}

func TestLoginCookieCarriesNoNonceOrVerifier(t *testing.T) { // ReviewFindingTests
	f := newAuthFixture(t)
	cookie, query := f.begin("/")
	body, _, _ := strings.Cut(cookie, ".")
	raw, err := b64urlDecode(body)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 || fields["state"] == nil || fields["next_path"] == nil || fields["created"] == nil {
		t.Fatalf("fields = %v", fields)
	}
	if strings.Contains(cookie, query["nonce"]) {
		t.Fatal("the nonce is in the cookie")
	}
}

func TestNonASCIIStateIsRefusedNotCrashed(t *testing.T) { // ReviewFindingTests
	f := newAuthFixture(t)
	cookie, _ := f.begin("/")
	if _, _, _, err := f.auth.Finish(cookie, strings.Repeat("é", 43), "code-0001"); err == nil {
		t.Fatal("a non-ASCII state was accepted")
	}
}

type countingTransport struct{ calls atomic.Int32 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return nil, errors.New("unreachable")
}

func TestADiscoveryFailureIsNotRetriedForEveryRequest(t *testing.T) { // ReviewFindingTests
	clock := &oidctest.Clock{}
	transport := &countingTransport{}
	config := cfg(t, envFor("https://unreachable.invalid", nil))
	auth := NewAuthenticator(config, testExitIDs, clock.Now, &http.Client{Transport: transport})
	for i := 0; i < 3; i++ {
		if _, err := auth.discover(); err == nil {
			t.Fatal("discovery succeeded")
		}
	}
	if n := transport.calls.Load(); n != 1 {
		t.Fatalf("%d calls", n)
	}
	clock.Advance(DiscoveryRetryS + 1)
	if _, err := auth.discover(); err == nil {
		t.Fatal("discovery succeeded")
	}
	if n := transport.calls.Load(); n != 2 {
		t.Fatalf("%d calls", n)
	}
}

func TestConsumedStatesExpireFromTheOldestEnd(t *testing.T) { // ReviewFindingTests
	f := newAuthFixture(t)
	for i := 0; i < 3; i++ {
		cookie, _ := f.begin("/")
		f.auth.Discard(cookie)
	}
	if n := f.consumedCount(); n != 3 {
		t.Fatalf("consumed = %d", n)
	}
	f.clock.Advance(LoginTTL + 1)
	cookie, _ := f.begin("/")
	f.auth.Discard(cookie)
	if n := f.consumedCount(); n != 1 {
		t.Fatalf("consumed = %d", n)
	}
}

func TestEveryIssuerRequestNamesThePanel(t *testing.T) { // UserAgentTests
	f := newAuthFixture(t)
	f.mustSignIn([]string{"friends-a"}, "user-1")
	if len(f.issuer.RequestsSeen()) == 0 {
		t.Fatal("the issuer saw nothing")
	}
	for _, r := range f.issuer.RequestsSeen() {
		if got := r.Headers.Get("User-Agent"); got != "molebridge-panel" {
			t.Errorf("%s: User-Agent = %q", r.Path, got)
		}
	}
}

func TestIssuerClientDoesNotFollowRedirectsOrUseAProxy(t *testing.T) {
	// The Python opener refused redirects and ignored the environment's proxy.
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	var followed atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/target", http.StatusFound) })
	mux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		followed.Add(1)
		_, _ = w.Write([]byte("{}"))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	client := NewIssuerClient()
	if tr := client.Transport.(*http.Transport); tr.Proxy != nil {
		t.Fatal("a proxy is configured")
	}
	_, err := httpJSON(client, server.URL+"/start", nil, nil, "discovery")
	if err == nil || err.Error() != "discovery: the issuer answered HTTP 302" {
		t.Fatalf("err = %v", err)
	}
	if followed.Load() != 0 {
		t.Fatal("the redirect was followed")
	}
	// An insecure URL is refused before any connection.
	_, err = httpJSON(client, "http://192.0.2.1/x", nil, nil, "token")
	if err == nil || err.Error() != "token: the issuer named an insecure URL" {
		t.Fatalf("err = %v", err)
	}
}
