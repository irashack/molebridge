package oidc

// Ported from panel/test_oidc.py: ConfigTests, DiscoveryTests, IdTokenTests
// and GroupsAndNamesTests.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/panel/oidc/oidctest"
)

func cfg(t *testing.T, env map[string]string) *Config {
	t.Helper()
	c, err := ConfigFromEnv(env, testExitIDs)
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	return c
}

func assertRejects(t *testing.T, fragment string, env map[string]string) {
	t.Helper()
	_, err := ConfigFromEnv(env, testExitIDs)
	if err == nil {
		t.Fatalf("expected a refusal containing %q", fragment)
	}
	if fragment != "" && !strings.Contains(err.Error(), fragment) {
		t.Fatalf("error %q does not contain %q", err, fragment)
	}
}

func TestConfigNoIssuerMeansNoSignIn(t *testing.T) {
	for _, env := range []map[string]string{{}, {"PANEL_OIDC_ISSUER": "   "},
		// Settings that only matter with sign-in do not count as setting it up.
		{"PANEL_SESSION_TTL": "600", "PANEL_OIDC_SCOPES": "x"}} {
		c, err := ConfigFromEnv(env, testExitIDs)
		if c != nil || err != nil {
			t.Fatalf("ConfigFromEnv(%v) = %v, %v", env, c, err)
		}
	}
}

func TestConfigSignInSettingsWithoutAnIssuerAreAnError(t *testing.T) {
	for _, kv := range [][2]string{{"PANEL_OIDC_CLIENT_ID", oidctest.ClientID}, {"PANEL_ACCESS", "friends-a=a"},
		{"PANEL_ADMIN_GROUPS", "admins"}, {"PANEL_PUBLIC_URL", testPublicURL}} {
		t.Run(kv[0], func(t *testing.T) {
			assertRejects(t, kv[0], map[string]string{kv[0]: kv[1]})
		})
	}
}

func TestConfigAcceptsAValidConfig(t *testing.T) {
	c := cfg(t, envFor(testIssuer, nil))
	if c.Issuer != testIssuer || c.ClientID != oidctest.ClientID || c.PublicURL != testPublicURL {
		t.Fatalf("config = %+v", c)
	}
	if c.RedirectURI() != testPublicURL+"/auth/callback" {
		t.Fatalf("RedirectURI = %q", c.RedirectURI())
	}
	if host, port := c.PublicHost(); host != "exit.example.test" || port != 0 {
		t.Fatalf("PublicHost = %q, %d", host, port)
	}
	if c.Scopes != DefaultScopes || c.GroupsClaim != "groups" || c.SessionTTL != DefaultSessionTTL || c.ClientSecret != nil {
		t.Fatalf("config = %+v", c)
	}
	if !c.AdminGroups.Equal(NewSet("admins")) {
		t.Fatalf("AdminGroups = %v", c.AdminGroups)
	}
	if len(c.Access) != 2 || !c.Access["friends-a"].Equal(NewSet("a")) || !c.Access["friends-b"].Equal(NewSet("b")) {
		t.Fatalf("Access = %v", c.Access)
	}
}

func TestConfigPublicURLTrailingSlashIsDroppedAndPortKept(t *testing.T) {
	if got := cfg(t, envFor(testIssuer, o("PANEL_PUBLIC_URL", "https://exit.example.test/"))).PublicURL; got != testPublicURL {
		t.Fatalf("PublicURL = %q", got)
	}
	c := cfg(t, envFor(testIssuer, o("PANEL_PUBLIC_URL", "https://exit.example.test:8443")))
	if host, port := c.PublicHost(); host != "exit.example.test" || port != 8443 {
		t.Fatalf("PublicHost = %q, %d", host, port)
	}
}

func TestConfigLoopbackHTTPIssuerIsAllowedButNoOtherHTTP(t *testing.T) {
	for _, ok := range []string{"http://127.0.0.1:9000", "http://localhost:9000"} {
		if got := cfg(t, envFor(ok, nil)).Issuer; got != ok {
			t.Fatalf("Issuer = %q", got)
		}
	}
	for _, bad := range []string{"http://idp.example.test", "http://192.0.2.10", "ftp://idp.example.test", "idp.example.test",
		"https://user:pw@idp.example.test", "https://idp.example.test#frag", "https://idp.example.test?x=1"} {
		t.Run(bad, func(t *testing.T) { assertRejects(t, "PANEL_OIDC_ISSUER", envFor(bad, nil)) })
	}
}

func TestConfigClientIDIsRequired(t *testing.T) {
	for _, value := range []string{"\x00", "", "   ", strings.Repeat("x", 256), "bad\x07id"} {
		t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
			assertRejects(t, "PANEL_OIDC_CLIENT_ID", envFor(testIssuer, o("PANEL_OIDC_CLIENT_ID", value)))
		})
	}
}

func TestConfigPublicURLMustBeABareHTTPSOrigin(t *testing.T) {
	for _, bad := range []string{"\x00", "", "  ", "exit.example.test", "http://exit.example.test",
		"https://exit.example.test/panel", "https://exit.example.test/?x=1", "https://exit.example.test?x=1",
		"https://exit.example.test#f", "ftp://exit.example.test", "https://u:p@exit.example.test"} {
		t.Run(fmt.Sprintf("%q", bad), func(t *testing.T) {
			assertRejects(t, "PANEL_PUBLIC_URL", envFor(testIssuer, o("PANEL_PUBLIC_URL", bad)))
		})
	}
}

func TestConfigScopesMustIncludeOpenID(t *testing.T) {
	assertRejects(t, "openid", envFor(testIssuer, o("PANEL_OIDC_SCOPES", "profile email groups")))
	assertRejects(t, "openid", envFor(testIssuer, o("PANEL_OIDC_SCOPES", "")))
	if got := cfg(t, envFor(testIssuer, o("PANEL_OIDC_SCOPES", "  groups   openid "))).Scopes; got != "groups openid" {
		t.Fatalf("Scopes = %q", got)
	}
}

func TestConfigNeedsAtLeastOneGroup(t *testing.T) {
	assertRejects(t, "at least one group", envFor(testIssuer, o("PANEL_ADMIN_GROUPS", "\x00", "PANEL_ACCESS", "\x00")))
	assertRejects(t, "at least one group", envFor(testIssuer, o("PANEL_ADMIN_GROUPS", "  , ", "PANEL_ACCESS", "")))
	if got := cfg(t, envFor(testIssuer, o("PANEL_ADMIN_GROUPS", "\x00"))).AdminGroups; len(got) != 0 {
		t.Fatalf("AdminGroups = %v", got)
	}
	if got := cfg(t, envFor(testIssuer, o("PANEL_ACCESS", "\x00"))).Access; len(got) != 0 {
		t.Fatalf("Access = %v", got)
	}
}

func TestConfigAdminGroupNamesAreValidated(t *testing.T) {
	assertRejects(t, "PANEL_ADMIN_GROUPS", envFor(testIssuer, o("PANEL_ADMIN_GROUPS", "two words")))
	assertRejects(t, "PANEL_ADMIN_GROUPS", envFor(testIssuer, o("PANEL_ADMIN_GROUPS", strings.Repeat("x", 129))))
	if got := cfg(t, envFor(testIssuer, o("PANEL_ADMIN_GROUPS", "admins, ops"))).AdminGroups; !got.Equal(NewSet("admins", "ops")) {
		t.Fatalf("AdminGroups = %v", got)
	}
}

func TestConfigAccessMustNameRealExitsAndBeWellFormed(t *testing.T) {
	assertRejects(t, "not an exit", envFor(testIssuer, o("PANEL_ACCESS", "friends-a=zz")))
	assertRejects(t, "not an exit", envFor(testIssuer, o("PANEL_ACCESS", "friends-a=")))
	assertRejects(t, "not an exit", envFor(testIssuer, o("PANEL_ACCESS", "friends-a=a,friends-b=nope")))
	for _, bad := range []string{"friends", "=a", "two words=a", "g=h=a"} {
		t.Run(bad, func(t *testing.T) { assertRejects(t, "PANEL_ACCESS", envFor(testIssuer, o("PANEL_ACCESS", bad))) })
	}
	// Nothing to grant in a panel with no PANEL_EXITS.
	if _, err := ConfigFromEnv(envFor(testIssuer, nil), nil); err == nil {
		t.Fatal("expected a refusal without exits")
	}
}

func TestConfigRepeatedGroupGrantsSeveralExits(t *testing.T) {
	c := cfg(t, envFor(testIssuer, o("PANEL_ACCESS", "family=a, family=b ,friends-a=a")))
	if !c.Access["family"].Equal(NewSet("a", "b")) || !c.Access["friends-a"].Equal(NewSet("a")) {
		t.Fatalf("Access = %v", c.Access)
	}
}

func TestConfigSessionTTLBounds(t *testing.T) {
	if got := cfg(t, envFor(testIssuer, o("PANEL_SESSION_TTL", "300"))).SessionTTL; got != 300 {
		t.Fatalf("SessionTTL = %d", got)
	}
	if got := cfg(t, envFor(testIssuer, o("PANEL_SESSION_TTL", fmt.Sprint(MaxSessionTTL)))).SessionTTL; got != MaxSessionTTL {
		t.Fatalf("SessionTTL = %d", got)
	}
	for _, bad := range []string{"299", "0", "-5", fmt.Sprint(MaxSessionTTL + 1), "99999999999999999999999"} {
		t.Run(bad, func(t *testing.T) { assertRejects(t, "between", envFor(testIssuer, o("PANEL_SESSION_TTL", bad))) })
	}
	for _, bad := range []string{"abc", "", "1.5", "1h"} {
		t.Run(bad, func(t *testing.T) { assertRejects(t, "whole number", envFor(testIssuer, o("PANEL_SESSION_TTL", bad))) })
	}
	// Python's int() takes a sign, surrounding whitespace and single underscores.
	if got := cfg(t, envFor(testIssuer, o("PANEL_SESSION_TTL", " +1_000 "))).SessionTTL; got != 1000 {
		t.Fatalf("SessionTTL = %d", got)
	}
}

func TestConfigClientSecretFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "secret")
	if err := os.WriteFile(good, []byte("  not-a-real-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := cfg(t, envFor(testIssuer, o("PANEL_OIDC_CLIENT_SECRET_FILE", good)))
	if c.ClientSecret == nil || *c.ClientSecret != "not-a-real-secret" {
		t.Fatalf("ClientSecret = %v", c.ClientSecret)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertRejects(t, "is empty", envFor(testIssuer, o("PANEL_OIDC_CLIENT_SECRET_FILE", empty)))
	assertRejects(t, "cannot be read: No such file or directory", envFor(testIssuer, o("PANEL_OIDC_CLIENT_SECRET_FILE", filepath.Join(dir, "missing"))))
	assertRejects(t, "cannot be read: Is a directory", envFor(testIssuer, o("PANEL_OIDC_CLIENT_SECRET_FILE", dir)))
	binary := filepath.Join(dir, "binary")
	if err := os.WriteFile(binary, []byte{0xff, 0xfe}, 0o600); err != nil {
		t.Fatal(err)
	}
	assertRejects(t, "cannot be read", envFor(testIssuer, o("PANEL_OIDC_CLIENT_SECRET_FILE", binary)))
	// The message names the problem, never the file's content.
	_, err := ConfigFromEnv(envFor(testIssuer, o("PANEL_OIDC_CLIENT_SECRET_FILE", empty)), testExitIDs)
	if strings.Contains(strings.ReplaceAll(err.Error(), "SECRET_FILE", ""), "secret") {
		t.Fatalf("error names the secret: %v", err)
	}
}

func TestConfigExitsFor(t *testing.T) {
	c := cfg(t, envFor(testIssuer, o("PANEL_ACCESS", "family=a,family=b,friends-a=a")))
	everything := NewSet(testExitIDs...)
	for _, tc := range []struct {
		groups Set
		admin  bool
		exits  Set
	}{
		{NewSet("admins"), true, everything},
		{NewSet("admins", "friends-a"), true, everything},
		{NewSet("friends-a"), false, NewSet("a")},
		{NewSet("family"), false, NewSet("a", "b")},
		{NewSet("friends-a", "family"), false, NewSet("a", "b")},
		{NewSet("strangers"), false, NewSet()},
		{NewSet(), false, NewSet()},
		// Group names match exactly.
		{NewSet("Admins", "FRIENDS-A"), false, NewSet()},
	} {
		admin, exits := c.ExitsFor(tc.groups, testExitIDs)
		if admin != tc.admin || !exits.Equal(tc.exits) {
			t.Errorf("ExitsFor(%v) = %v, %v", tc.groups.Sorted(), admin, exits.Sorted())
		}
	}
}

// -- discovery -----------------------------------------------------------------

func discoveryDoc(overrides map[string]any) map[string]any {
	doc := map[string]any{
		"issuer": testIssuer, "authorization_endpoint": testIssuer + "/authorize", "token_endpoint": testIssuer + "/token",
		"userinfo_endpoint": testIssuer + "/userinfo", "code_challenge_methods_supported": []any{"S256", "plain"},
	}
	for k, v := range overrides {
		if v == nil {
			delete(doc, k)
		} else {
			doc[k] = v
		}
	}
	return doc
}

func TestDiscoveryGoodDocument(t *testing.T) {
	endpoints, err := ParseDiscovery(discoveryDoc(nil), testIssuer)
	want := Endpoints{testIssuer + "/authorize", testIssuer + "/token", testIssuer + "/userinfo"}
	if err != nil || endpoints != want {
		t.Fatalf("ParseDiscovery = %+v, %v", endpoints, err)
	}
}

func TestDiscoveryIssuerMustMatch(t *testing.T) {
	for _, other := range []any{"https://other.example.test", testIssuer + "/", nil, 5.0} {
		if _, err := ParseDiscovery(discoveryDoc(map[string]any{"issuer": other}), testIssuer); err == nil {
			t.Errorf("issuer %v accepted", other)
		}
	}
}

func TestDiscoveryEndpointsMustBeHTTPS(t *testing.T) {
	for _, key := range []string{"authorization_endpoint", "token_endpoint"} {
		for _, bad := range []any{"http://idp.example.test/x", "javascript:alert(1)", nil, 7.0, "https://u:p@idp.example.test/x"} {
			if _, err := ParseDiscovery(discoveryDoc(map[string]any{key: bad}), testIssuer); err == nil {
				t.Errorf("%s=%v accepted", key, bad)
			}
		}
	}
}

func TestDiscoveryInsecureUserinfoIsDroppedNotTrusted(t *testing.T) {
	for _, bad := range []any{"http://idp.example.test/userinfo", 5.0, nil} {
		endpoints, err := ParseDiscovery(discoveryDoc(map[string]any{"userinfo_endpoint": bad}), testIssuer)
		if err != nil || endpoints.Userinfo != "" {
			t.Errorf("userinfo %v: %+v, %v", bad, endpoints, err)
		}
	}
}

func TestDiscoveryPKCES256IsRequiredWhenTheListIsGiven(t *testing.T) {
	for _, methods := range []any{[]any{"plain"}, []any{}} {
		if _, err := ParseDiscovery(discoveryDoc(map[string]any{"code_challenge_methods_supported": methods}), testIssuer); err == nil {
			t.Errorf("methods %v accepted", methods)
		}
	}
	// Not advertised: allowed.
	if _, err := ParseDiscovery(discoveryDoc(map[string]any{"code_challenge_methods_supported": nil}), testIssuer); err != nil {
		t.Errorf("unadvertised methods refused: %v", err)
	}
}

func TestDiscoveryHTTPSIssuerNeverAcceptsHTTPEndpoints(t *testing.T) { // ReviewFindingTests
	doc := map[string]any{"issuer": testIssuer, "authorization_endpoint": testIssuer + "/authorize",
		"token_endpoint": "http://127.0.0.1:9/token"}
	if _, err := ParseDiscovery(doc, testIssuer); err == nil {
		t.Fatal("http token endpoint accepted")
	}
	doc["token_endpoint"] = testIssuer + "/token"
	doc["userinfo_endpoint"] = "http://127.0.0.1:9/userinfo"
	endpoints, err := ParseDiscovery(doc, testIssuer)
	if err != nil || endpoints.Userinfo != "" {
		t.Fatalf("ParseDiscovery = %+v, %v", endpoints, err)
	}
}

// -- ID token ------------------------------------------------------------------

const (
	tokenNow   = 1_700_000_000.0
	tokenNonce = "nonce-123"
)

// absent marks a claim to leave out (Python's Ellipsis).
type absentClaim struct{}

var absent = absentClaim{}

func tokenClaims(overrides map[string]any) map[string]any {
	claims := map[string]any{"iss": testIssuer, "aud": oidctest.ClientID, "sub": "user-1", "exp": tokenNow + 300,
		"iat": tokenNow, "nonce": tokenNonce}
	for k, v := range overrides {
		if v == absent {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	return claims
}

func checkToken(token any, nonce string) (map[string]any, error) {
	if nonce == "" {
		nonce = tokenNonce
	}
	return IDTokenClaims(token, testIssuer, oidctest.ClientID, nonce, tokenNow)
}

func assertRefused(t *testing.T, token any, fragment string) {
	t.Helper()
	_, err := checkToken(token, "")
	if err == nil {
		t.Fatalf("token accepted")
	}
	if _, ok := err.(*AuthError); !ok {
		t.Fatalf("error %T is not an AuthError", err)
	}
	if fragment != "" && !strings.Contains(err.Error(), fragment) {
		t.Fatalf("error %q does not contain %q", err, fragment)
	}
}

func mk(t *testing.T, overrides map[string]any) string {
	t.Helper()
	return oidctest.MakeToken(t, tokenClaims(overrides), nil, "c2ln")
}

func TestIDTokenAcceptsAGoodToken(t *testing.T) {
	claims, err := checkToken(mk(t, nil), "")
	if err != nil || claims["sub"] != "user-1" || claims["iss"] != testIssuer {
		t.Fatalf("claims = %v, %v", claims, err)
	}
}

func TestIDTokenWrongIssuer(t *testing.T) {
	assertRefused(t, mk(t, map[string]any{"iss": "https://other.example.test"}), "another issuer")
	assertRefused(t, mk(t, map[string]any{"iss": absent}), "another issuer")
	assertRefused(t, mk(t, map[string]any{"iss": testIssuer + "/"}), "another issuer")
}

func TestIDTokenWrongAudience(t *testing.T) {
	for _, aud := range []any{"someone-else", absent, []any{}, 12, []any{map[string]any{"x": 1}}} {
		assertRefused(t, mk(t, map[string]any{"aud": aud}), "another client")
	}
}

func TestIDTokenSeveralAudiencesNeedAMatchingAzp(t *testing.T) {
	both := []any{oidctest.ClientID, "other-client"}
	assertRefused(t, mk(t, map[string]any{"aud": both}), "another client")
	assertRefused(t, mk(t, map[string]any{"aud": both, "azp": "other-client"}), "another client")
	assertRefused(t, mk(t, map[string]any{"aud": both, "azp": 5}), "another client")
	if _, err := checkToken(mk(t, map[string]any{"aud": both, "azp": oidctest.ClientID}), ""); err != nil {
		t.Fatal(err)
	}
}

func TestIDTokenAzpThatIsPresentMustMatch(t *testing.T) {
	assertRefused(t, mk(t, map[string]any{"azp": "other-client"}), "another client")
	if _, err := checkToken(mk(t, map[string]any{"azp": oidctest.ClientID}), ""); err != nil {
		t.Fatal(err)
	}
}

func TestIDTokenExpiryWithBoundedSkew(t *testing.T) {
	assertRefused(t, mk(t, map[string]any{"exp": tokenNow - ClockSkewS - 1}), "expired")
	if _, err := checkToken(mk(t, map[string]any{"exp": tokenNow - ClockSkewS + 1}), ""); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []any{absent, "9999999999", nil, true, []any{1}} {
		assertRefused(t, mk(t, map[string]any{"exp": bad}), "expired")
	}
}

func TestIDTokenIssueTimeInTheFuture(t *testing.T) {
	assertRefused(t, mk(t, map[string]any{"iat": tokenNow + ClockSkewS + 1}), "future")
	if _, err := checkToken(mk(t, map[string]any{"iat": tokenNow + ClockSkewS - 1}), ""); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []any{absent, "1", nil, true} {
		assertRefused(t, mk(t, map[string]any{"iat": bad}), "future")
	}
}

func TestIDTokenNonceMustMatch(t *testing.T) {
	for _, bad := range []any{"other", absent, nil, 12345} {
		assertRefused(t, mk(t, map[string]any{"nonce": bad}), "does not belong")
	}
	if _, err := checkToken(mk(t, map[string]any{"nonce": ""}), "x"); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("empty nonce: %v", err)
	}
}

func TestIDTokenSubjectIsRequired(t *testing.T) {
	for _, bad := range []any{absent, "", nil, 5, []any{"u"}, strings.Repeat("x", 256)} {
		assertRefused(t, mk(t, map[string]any{"sub": bad}), "no subject")
	}
	if _, err := checkToken(mk(t, map[string]any{"sub": strings.Repeat("x", 255)}), ""); err != nil {
		t.Fatal(err)
	}
}

func TestIDTokenUnsignedTokensAreRefused(t *testing.T) {
	for _, header := range []any{map[string]any{"alg": "none"}, map[string]any{"alg": "None"}, map[string]any{"alg": "NONE"},
		map[string]any{"alg": ""}, map[string]any{}, map[string]any{"typ": "JWT"}, map[string]any{"alg": nil}} {
		assertRefused(t, oidctest.MakeToken(t, tokenClaims(nil), header, "c2ln"), "unsigned")
	}
	assertRefused(t, oidctest.MakeToken(t, tokenClaims(nil), nil, ""), "unsigned")
}

func TestIDTokenMalformedTokens(t *testing.T) {
	good := mk(t, nil)
	parts := strings.Split(good, ".")
	head, body, sig := parts[0], parts[1], parts[2]
	for _, bad := range []string{"", "abc", "a.b", good + ".extra", head + "." + body, "." + body + "." + sig, head + ".." + sig} {
		assertRefused(t, bad, "")
	}
	assertRefused(t, head+"."+body+"+/=."+sig, "malformed") // not base64url
	assertRefused(t, "!!!."+body+"."+sig, "malformed")
	if len(body)%4 == 0 {
		assertRefused(t, head+"."+body+"A."+sig, "")
	} else {
		assertRefused(t, head+"."+body+"AAAA."+sig, "")
	}
	assertRefused(t, head+".A."+sig, "malformed") // impossible base64 length
	assertRefused(t, oidctest.B64(t, []byte("not json"))+"."+body+"."+sig, "malformed")
	assertRefused(t, head+"."+oidctest.B64(t, []byte("not json"))+"."+sig, "malformed")
	assertRefused(t, head+"."+oidctest.B64(t, []byte{0xff, 0xfe})+"."+sig, "malformed")
	assertRefused(t, head+"."+oidctest.B64(t, []any{1, 2})+"."+sig, "malformed") // claims not an object
	assertRefused(t, oidctest.B64(t, []any{1})+"."+body+"."+sig, "malformed")    // header not an object
	assertRefused(t, head+"."+oidctest.B64(t, []byte("null"))+"."+sig, "malformed")
}

func TestIDTokenDuplicateKeysAreRefused(t *testing.T) {
	claims := oidctest.B64(t, tokenClaims(nil))
	_ = claims
	raw := `{"iss": "` + testIssuer + `", "aud": "` + oidctest.ClientID + `", "sub": "user-1", "sub": "admin", "exp": 1700000300, "iat": 1700000000, "nonce": "` + tokenNonce + `"}`
	assertRefused(t, oidctest.B64(t, map[string]any{"alg": "RS256"})+"."+oidctest.B64(t, []byte(raw))+".c2ln", "malformed")
	head := []byte(`{"alg": "RS256", "alg": "none"}`)
	assertRefused(t, oidctest.B64(t, head)+"."+oidctest.B64(t, tokenClaims(nil))+".c2ln", "malformed")
}

func TestIDTokenNonStringAndOversizedInput(t *testing.T) {
	for _, bad := range []any{nil, 123, []byte("a.b.c"), map[string]any{"id_token": "x"}, []any{"a", "b", "c"}, 1.5, true} {
		assertRefused(t, bad, "no ID token")
	}
	assertRefused(t, strings.Repeat("a", 64*1024+1), "no ID token")
}

// -- groups and names ----------------------------------------------------------

func TestGroupsFrom(t *testing.T) {
	for _, tc := range []struct {
		claims  map[string]any
		claim   string
		present bool
		want    Set
	}{
		{map[string]any{}, "groups", false, nil},
		{map[string]any{"roles": []any{"x"}}, "groups", false, nil},
		{map[string]any{"groups": "solo"}, "groups", true, NewSet("solo")},
		{map[string]any{"groups": []any{"a", "b", "a"}}, "groups", true, NewSet("a", "b")},
		{map[string]any{"groups": []any{}}, "groups", true, NewSet()},
		{map[string]any{"groups": []any{"a", ""}}, "groups", true, NewSet("a")},
		{map[string]any{"roles": []any{"r"}}, "roles", true, NewSet("r")},
	} {
		got, present, err := GroupsFrom(tc.claims, tc.claim)
		if err != nil || present != tc.present || (tc.present && !got.Equal(tc.want)) {
			t.Errorf("GroupsFrom(%v, %q) = %v, %v, %v", tc.claims, tc.claim, got, present, err)
		}
	}
}

func TestMalformedGroupsAreRefused(t *testing.T) {
	long := make([]any, MaxGroups+1)
	for i := range long {
		long[i] = "g"
	}
	for _, bad := range []any{nil, 5.0, true, map[string]any{"a": 1}, []any{"a", 1.0}, []any{"a", nil}, []any{[]any{"a"}},
		[]any{map[string]any{"name": "a"}}, 1.5, long} {
		if _, _, err := GroupsFrom(map[string]any{"groups": bad}, "groups"); err == nil {
			t.Errorf("groups %v accepted", bad)
		}
	}
}

func TestDisplayNamePreferenceAndSanitising(t *testing.T) {
	for _, tc := range []struct {
		claims map[string]any
		want   string
	}{
		{map[string]any{"preferred_username": "jo", "email": "jo@example.test", "sub": "s"}, "jo"},
		{map[string]any{"email": "jo@example.test", "sub": "s"}, "jo@example.test"},
		{map[string]any{"sub": "s-1"}, "s-1"},
		{map[string]any{}, "unknown"},
		{map[string]any{"preferred_username": 5.0, "sub": "s"}, "s"},
		{map[string]any{"preferred_username": "   ", "sub": "s"}, "s"},
	} {
		if got := DisplayName(tc.claims); got != tc.want {
			t.Errorf("DisplayName(%v) = %q, want %q", tc.claims, got, tc.want)
		}
	}
}

func TestDisplayNameRemovesOddCharacters(t *testing.T) {
	name := DisplayName(map[string]any{"preferred_username": "jo\nFAKE admin=yes <b>&\"\x1b[31m"})
	if !regexp.MustCompile(`^[A-Za-z0-9._@+-]+$`).MatchString(name) {
		t.Fatalf("name = %q", name)
	}
	for _, c := range "\n\r<>&\"\x1b ='" {
		if strings.ContainsRune(name, c) {
			t.Fatalf("name %q holds %q", name, c)
		}
	}
	for _, r := range DisplayName(map[string]any{"preferred_username": "Zoë Ünal"}) {
		if r > 0x7f {
			t.Fatal("non-ASCII name")
		}
	}
}

func TestDisplayNameIsCappedAndNeverBlank(t *testing.T) {
	if got := DisplayName(map[string]any{"preferred_username": strings.Repeat("x", 500)}); len(got) != 64 {
		t.Fatalf("len = %d", len(got))
	}
	if got := DisplayName(map[string]any{"preferred_username": "!!!", "email": "a@example.test"}); got != "a@example.test" {
		t.Fatalf("name = %q", got)
	}
	if got := DisplayName(map[string]any{"preferred_username": "???", "sub": "***"}); got != "unknown" {
		t.Fatalf("name = %q", got)
	}
	if got := DisplayName(map[string]any{"preferred_username": "_"}); got != "unknown" {
		t.Fatalf("name = %q", got)
	}
}

func TestLogSafe(t *testing.T) {
	if got := LogSafe("a b\nc"); got != "a_b_c" {
		t.Fatalf("LogSafe = %q", got)
	}
	if got := LogSafe(""); got != "-" {
		t.Fatalf("LogSafe = %q", got)
	}
	if got := LogSafe(strings.Repeat("é", 100)); len(got) != 64 {
		t.Fatalf("LogSafe length = %d", len(got))
	}
}
