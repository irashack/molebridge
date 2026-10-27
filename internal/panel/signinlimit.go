package panel

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Anyone who reaches the panel can call /login and /auth/callback, and a
// pair of them with a junk code is a POST to the issuer's token endpoint as
// this panel's client. Some issuers throttle or lock out a client after
// enough failures, which would lock out everyone. One bucket for the whole
// process bounds the rate; oidc's MaxTokenExchanges bounds how many talk to
// the issuer at once. A flood can still keep real people from signing in
// while it lasts, but not for longer, and sessions already signed in are
// untouched.
const (
	// signInBurst requests at once, then one every signInEvery: a person's
	// sign-in takes two or three (the canonical redirect, /login, the
	// callback).
	signInBurst = 30
	signInEvery = 2 * time.Second
	// busyRetryAfter is Retry-After while the token exchanges are all in use;
	// each takes at most oidc.HTTPTimeout and usually well under a second.
	busyRetryAfter = 5
)

// tokenBucket is a token bucket on the panel's monotonic clock.
type tokenBucket struct {
	mu     sync.Mutex
	burst  float64
	every  time.Duration
	tokens float64
	last   time.Time
}

func newTokenBucket(burst int, every time.Duration) *tokenBucket {
	return &tokenBucket{burst: float64(burst), every: every, tokens: float64(burst)}
}

// take spends one token, or says how many whole seconds until there is one.
func (b *tokenBucket) take(now time.Time) (ok bool, retryAfter int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.last.IsZero() && now.After(b.last) {
		b.tokens = math.Min(b.burst, b.tokens+float64(now.Sub(b.last))/float64(b.every))
	}
	if b.last.IsZero() || now.After(b.last) {
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) * float64(b.every))
	return false, max(1, int(math.Ceil(wait.Seconds())))
}

// signInAdmitted spends a token for a sign-in request, or answers 429 and
// says so in the log at most once a minute.
func (s *Server) signInAdmitted(w http.ResponseWriter, r *http.Request, nextPath string) bool {
	ok, retryAfter := s.signInLimit.take(s.mono())
	if ok {
		return true
	}
	s.logLimited("refused sign-in request: too many sign-in requests")
	s.sendTooManySignIns(w, r, nextPath, retryAfter)
	return false
}

// sendTooManySignIns is the 429 page for a sign-in request turned away.
func (s *Server) sendTooManySignIns(w http.ResponseWriter, r *http.Request, nextPath string, retryAfter int) {
	body := s.RenderMessage("Too many sign-ins", "The panel is turning away sign-ins for a moment. Try again in a minute.",
		&[2]string{s.loginURL(nextPath), "Try again"}, false)
	s.send(w, r, htmlReply(429, body, [2]string{"Retry-After", strconv.Itoa(retryAfter)}))
}
