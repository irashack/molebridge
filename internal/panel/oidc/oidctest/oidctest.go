// Package oidctest is a fake OpenID Connect issuer on loopback and the token
// helpers the panel's sign-in tests share (the FakeIssuer, FakeClock,
// make_token and b64 of panel/test_oidc.py). It makes no connection beyond
// 127.0.0.1.
package oidctest

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ClientID is the client id the tests register.
const ClientID = "switchyard-test"

// AccessToken is the access token the fake issuer hands out.
const AccessToken = "at-not-a-real-token-7f3a"

func B64(t testing.TB, data any) string {
	t.Helper()
	raw, ok := data.([]byte)
	if !ok {
		var err error
		if raw, err = json.Marshal(data); err != nil {
			t.Fatal(err)
		}
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func MakeToken(t testing.TB, claims any, header any, signature string) string {
	t.Helper()
	if header == nil {
		header = map[string]any{"alg": "RS256"}
	}
	return strings.Join([]string{B64(t, header), B64(t, claims), signature}, ".")
}

// fakeClock is real time plus an offset the test advances, so tokens the
// fake issuer stamps with real time stay valid while sessions and sign-ins
// age.
type Clock struct {
	mu     sync.Mutex
	offset time.Duration
}

func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.offset)
}

func (c *Clock) Advance(seconds float64) {
	c.mu.Lock()
	c.offset += time.Duration(seconds * float64(time.Second))
	c.mu.Unlock()
}

// issuerRequest is one request the fake issuer saw.
type Request struct {
	Path    string
	Form    map[string]string
	Headers http.Header
}

// fakeIssuer serves discovery, token and userinfo on 127.0.0.1.
type Issuer struct {
	mu sync.Mutex

	Clock               func() time.Time
	Nonce               string
	Groups              []string
	IncludeGroups       bool
	Sub                 string
	Username            string
	ClaimsExtra         map[string]any
	ClaimsDrop          map[string]bool
	AdvertiseUserinfo   bool
	UserinfoSub         *string
	UserinfoGroups      []string
	UserinfoIncludeGrps bool
	TokenStatus         int
	TokenBody           []byte
	DiscoveryHits       int
	Requests            []Request
	LastIDToken         string

	server *httptest.Server
	URL    string
}

func New(t testing.TB, clock func() time.Time) *Issuer {
	t.Helper()
	if clock == nil {
		clock = time.Now
	}
	f := &Issuer{
		Clock: clock, Groups: []string{"friends-a"}, IncludeGroups: true, Sub: "user-1", Username: "jo",
		ClaimsExtra: map[string]any{}, ClaimsDrop: map[string]bool{}, AdvertiseUserinfo: true,
		UserinfoGroups: []string{"friends-a"}, UserinfoIncludeGrps: true, TokenStatus: 200,
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	f.URL = f.server.URL
	t.Cleanup(f.server.Close)
	return f
}

func (f *Issuer) sendJSON(w http.ResponseWriter, obj any, status int) {
	raw, _ := json.Marshal(obj)
	f.sendRaw(w, raw, status)
}

func (f *Issuer) sendRaw(w http.ResponseWriter, data []byte, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func (f *Issuer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	form := map[string]string{}
	if r.Method == http.MethodPost {
		raw, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(raw))
		for k := range values {
			form[k] = values.Get(k)
		}
	}
	f.Requests = append(f.Requests, Request{r.URL.RequestURI(), form, r.Header.Clone()})
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/.well-known/openid-configuration":
		f.DiscoveryHits++
		doc := map[string]any{
			"issuer": f.URL, "authorization_endpoint": f.URL + "/authorize", "token_endpoint": f.URL + "/token",
			"code_challenge_methods_supported": []string{"S256"},
		}
		if f.AdvertiseUserinfo {
			doc["userinfo_endpoint"] = f.URL + "/userinfo"
		}
		f.sendJSON(w, doc, 200)
	case r.Method == http.MethodGet && r.URL.Path == "/userinfo":
		sub := f.Sub
		if f.UserinfoSub != nil {
			sub = *f.UserinfoSub
		}
		info := map[string]any{"sub": sub}
		if f.UserinfoIncludeGrps {
			info["groups"] = f.UserinfoGroups
		}
		f.sendJSON(w, info, 200)
	case r.Method == http.MethodPost && r.URL.Path == "/token":
		if f.TokenBody != nil || f.TokenStatus != 200 {
			body := f.TokenBody
			if body == nil {
				body = []byte("{}")
			}
			f.sendRaw(w, body, f.TokenStatus)
			return
		}
		now := float64(f.Clock().UnixNano()) / 1e9
		claims := map[string]any{
			"iss": f.URL, "aud": ClientID, "sub": f.Sub, "exp": now + 300, "iat": now,
			"nonce": f.Nonce, "preferred_username": f.Username,
		}
		if f.IncludeGroups {
			claims["groups"] = f.Groups
		}
		for k, v := range f.ClaimsExtra {
			claims[k] = v
		}
		for k := range f.ClaimsDrop {
			delete(claims, k)
		}
		raw, _ := json.Marshal(claims)
		f.LastIDToken = strings.Join([]string{
			base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`)),
			base64.RawURLEncoding.EncodeToString(raw), "c2ln"}, ".")
		f.sendJSON(w, map[string]any{"id_token": f.LastIDToken, "access_token": AccessToken, "token_type": "Bearer"}, 200)
	default:
		f.sendJSON(w, map[string]any{}, 404)
	}
}

func (f *Issuer) Set(fn func(f *Issuer)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *Issuer) TokenRequests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Request
	for _, r := range f.Requests {
		if r.Path == "/token" {
			out = append(out, r)
		}
	}
	return out
}

func (f *Issuer) UserinfoRequests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Request
	for _, r := range f.Requests {
		if r.Path == "/userinfo" {
			out = append(out, r)
		}
	}
	return out
}

// Close stops the server.
func (f *Issuer) Close() { f.server.Close() }

// DiscoveryHitCount is how many times discovery was fetched.
func (f *Issuer) DiscoveryHitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.DiscoveryHits
}

// RequestsSeen is a copy of every request the issuer received.
func (f *Issuer) RequestsSeen() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Request(nil), f.Requests...)
}

// LastToken is the ID token the issuer most recently handed out.
func (f *Issuer) LastToken() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.LastIDToken
}

// SeenRequests is how many requests the issuer received.
func (f *Issuer) SeenRequests() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.Requests)
}
