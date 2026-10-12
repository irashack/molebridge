package panel

// Ported from panel/test_oidc.py (StrictCookieTests) and checked against
// Python's http.cookies: testdata/cookies.json holds what get_cookie and
// get_cookie_strict returned for each header when it was generated with
// Python 3.14 (python3 over the same functions as panel/app.py).

import (
	"encoding/json"
	"os"
	"testing"
)

type cookieCase struct {
	Header string             `json:"header"`
	Loose  map[string]*string `json:"loose"`
	Strict map[string]*string `json:"strict"`
}

func TestCookiesMatchPython(t *testing.T) {
	raw, err := os.ReadFile("testdata/cookies.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []cookieCase
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 40 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, c := range cases {
		for name, want := range c.Loose {
			got, ok := getCookie(c.Header, name)
			if (want == nil) == ok || (want != nil && got != *want) {
				t.Errorf("getCookie(%q, %q) = %q, %v; Python gave %v", c.Header, name, got, ok, deref(want))
			}
		}
		for name, want := range c.Strict {
			got, ok := getCookieStrict(c.Header, name)
			if (want == nil) == ok || (want != nil && got != *want) {
				t.Errorf("getCookieStrict(%q, %q) = %q, %v; Python gave %v", c.Header, name, got, ok, deref(want))
			}
		}
	}
}

func deref(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

const sessionCookieName = "__Host-molebridge_session"

func TestAPlantedCookieCannotStandInForAHostCookie(t *testing.T) {
	name := sessionCookieName
	for _, tc := range []struct {
		header string
		want   string
		ok     bool
	}{
		{name + "=REAL", "REAL", true},
		{"a=b; " + name + "=REAL; c=d", "REAL", true},
		// SimpleCookie would read these as a session cookie named `name`.
		{"a=x " + name + "=EVIL", "", false},
		{name + "=REAL; " + name + "=EVIL", "", false},
		{name, "", false},
		{name + "=REAL; a=x " + name + "=EVIL", "REAL", true},
	} {
		got, ok := getCookieStrict(tc.header, name)
		if got != tc.want || ok != tc.ok {
			t.Errorf("getCookieStrict(%q) = %q, %v", tc.header, got, ok)
		}
	}
}

func TestAReservedWordOrStrayQuoteDoesNotSignAnyoneOut(t *testing.T) {
	name := sessionCookieName
	for _, header := range []string{"Path=/; " + name + "=REAL", "version=1; " + name + "=REAL", `a=b"c; ` + name + "=REAL"} {
		if got, ok := getCookieStrict(header, name); !ok || got != "REAL" {
			t.Errorf("getCookieStrict(%q) = %q, %v", header, got, ok)
		}
	}
}
