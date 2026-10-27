package panel

// The bounds on anonymous sign-in traffic: one token bucket for /login and
// /auth/callback, the token exchanges in flight, and their log lines.

import (
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/panel/oidc"
	"github.com/irashack/molebridge/internal/panel/oidc/oidctest"
)

func TestTokenBucket(t *testing.T) {
	start := time.Unix(1000, 0)
	b := newTokenBucket(3, 2*time.Second)
	for i := 0; i < 3; i++ {
		if ok, _ := b.take(start); !ok {
			t.Fatalf("request %d of the burst refused", i)
		}
	}
	if ok, retry := b.take(start); ok || retry != 2 {
		t.Fatalf("over the burst: %v, Retry-After %d", ok, retry)
	}
	if ok, retry := b.take(start.Add(1500 * time.Millisecond)); ok || retry != 1 {
		t.Fatalf("before the refill: %v, Retry-After %d", ok, retry)
	}
	if ok, _ := b.take(start.Add(2 * time.Second)); !ok {
		t.Fatal("one token after two seconds")
	}
	// Idle time refills to the burst, never past it.
	later := start.Add(time.Hour)
	for i := 0; i < 3; i++ {
		if ok, _ := b.take(later); !ok {
			t.Fatalf("refilled request %d refused", i)
		}
	}
	if ok, _ := b.take(later); ok {
		t.Fatal("refilled past the burst")
	}
	// A clock that steps back neither refills nor breaks the bucket.
	if ok, retry := b.take(start); ok || retry < 1 {
		t.Fatalf("clock stepped back: %v, Retry-After %d", ok, retry)
	}
}

func TestSignInRequestsBeyondTheBucketGet429(t *testing.T) {
	p := newAuthPanel(t, nil)
	mono := &oidctest.Clock{}
	p.srv.mono = mono.Now
	p.srv.signInLimit = newTokenBucket(3, signInEvery)
	p.log.Reset()
	for i := 0; i < 3; i++ {
		eq(t, "login", p.get("/login", "", nil).Status, 303)
	}
	refused := p.get("/login?next=/embed", "", nil)
	eq(t, "status", refused.Status, 429)
	eq(t, "Retry-After", refused.Header.Get("Retry-After"), "2")
	eq(t, "Cache-Control", refused.Header.Get("Cache-Control"), "no-store")
	mustContain(t, refused.Body, "Too many sign-ins", "Try again in a minute.")
	// The callback draws from the same bucket, and nothing reaches the issuer.
	eq(t, "callback", p.get("/auth/callback?code=x&state=y", "", nil).Status, 429)
	eq(t, "token requests", len(p.issuer.TokenRequests()), 0)
	// Other routes are not limited.
	eq(t, "healthz", p.get("/healthz", "", nil).Status, 200)
	const line = "refused sign-in request: too many sign-in requests"
	if n := strings.Count(p.log.String(), line); n != 1 {
		t.Fatalf("%d refusal lines: %q", n, p.log.String())
	}
	mono.Advance(2)
	eq(t, "after the refill", p.get("/login", "", nil).Status, 303)
}

func TestACallbackFindingTheExchangesBusyKeepsItsSignIn(t *testing.T) {
	p := newAuthPanel(t, nil)
	login, query := p.beginLogin("/")
	cookie := login.Cookies[oidc.LoginCookie].Value
	p.log.Reset()
	p.srv.Auth.Limits.MaxTokenExchanges = 0
	busy := p.callback(query, cookie, "")
	eq(t, "status", busy.Status, 429)
	eq(t, "Retry-After", busy.Header.Get("Retry-After"), "5")
	if _, cleared := busy.Cookies[oidc.LoginCookie]; cleared {
		t.Fatal("the pending sign-in's cookie was cleared")
	}
	eq(t, "token requests", len(p.issuer.TokenRequests()), 0)
	mustContain(t, p.log.String(), "refused sign-in callback: too many sign-ins are talking to the identity provider\n")
	// Once a place is free the same callback completes.
	p.srv.Auth.Limits.MaxTokenExchanges = 4
	eq(t, "retried", p.callback(query, cookie, "").Status, 303)
}

func TestSignInFailureLinesAreLoggedOnceAMinute(t *testing.T) {
	p := newAuthPanel(t, nil)
	p.log.Reset()
	for i := 0; i < 5; i++ {
		eq(t, "callback", p.get("/auth/callback?code=x&state=y", "", nil).Status, 400)
	}
	line := "sign-in failed: " + "callback: this browser did not start a sign-in, or it expired"
	if n := strings.Count(p.log.String(), line); n != 1 {
		t.Fatalf("%d failure lines: %q", n, p.log.String())
	}
	// Another reason has its own budget.
	eq(t, "refused", p.get("/auth/callback?error=access_denied", "", nil).Status, 403)
	mustContain(t, p.log.String(), "sign-in failed: access: the identity provider refused the sign-in\n")
}
