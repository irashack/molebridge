package oidc

// Fuzz targets for what the issuer sends: the strict JSON reader, the ID
// token checks and the pending sign-in cookie.

import (
	"testing"

	"github.com/irashack/molebridge/internal/panel/oidc/oidctest"
)

func FuzzLoads(f *testing.F) {
	for _, seed := range []string{`{"a": 1}`, `{"a": 1, "a": 2}`, `[1, 2.5, "x", null, true]`, `{"a": {"b": [{"c": 1e999}]}}`, "\xff", ``, `{}{}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if v, err := loads(raw); err != nil && v != nil {
			t.Fatalf("value %v with error %v", v, err)
		}
	})
}

func FuzzIDTokenClaims(f *testing.F) {
	f.Add("a.b.c")
	f.Add("eyJhbGciOiJSUzI1NiJ9.e30.c2ln")
	f.Add("")
	f.Fuzz(func(t *testing.T, token string) {
		claims, err := IDTokenClaims(token, testIssuer, oidctest.ClientID, "nonce", 1_700_000_000)
		if err == nil && claims["iss"] != testIssuer {
			t.Fatalf("accepted a token from %v", claims["iss"])
		}
	})
}

func FuzzOpenLoginCookie(f *testing.F) {
	f.Add("a.b")
	f.Add("")
	auth := NewAuthenticator(&Config{SessionTTL: 3600}, nil, nil, nil)
	f.Fuzz(func(t *testing.T, cookie string) {
		if _, err := auth.open(cookie); err == nil {
			t.Fatalf("a forged cookie opened: %q", cookie)
		}
	})
}
