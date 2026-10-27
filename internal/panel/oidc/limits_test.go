package oidc

// The token exchanges in flight are bounded: anyone can start a sign-in and
// send its callback a junk code.

import (
	"sync"
	"testing"

	"github.com/irashack/molebridge/internal/panel/oidc/oidctest"
)

func TestTokenExchangesInFlightAreBounded(t *testing.T) {
	f, g := gatedFixture(t, "/token")
	f.auth.Limits.MaxTokenExchanges = 2
	type started struct{ cookie, state string }
	var logins []started
	for i := 0; i < 3; i++ {
		cookie, query := f.begin("/")
		logins = append(logins, started{cookie, query["state"]})
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, _, errs[i] = f.auth.Finish(logins[i].cookie, logins[i].state, "junk-code")
		}(i)
	}
	<-g.arrived
	<-g.arrived
	// Both places are taken: the third callback is answered at once, without
	// a request to the issuer and without using up its sign-in.
	if _, _, _, err := f.auth.Finish(logins[2].cookie, logins[2].state, "junk-code"); err != ErrBusy {
		t.Fatalf("third Finish = %v, want ErrBusy", err)
	}
	close(g.open)
	wg.Wait()
	if n := len(f.issuer.TokenRequests()); n != 2 {
		t.Fatalf("%d token requests, want 2", n)
	}
	// The places are given back, and the refused sign-in can still finish.
	f.issuer.Set(func(i *oidctest.Issuer) { i.Groups = []string{"friends-a"} })
	if _, session, _, err := f.auth.Finish(logins[2].cookie, logins[2].state, "code-0001"); err != nil || session == nil {
		t.Fatalf("retried Finish = %v", err)
	}
	if f.auth.exchanges != 0 {
		t.Fatalf("%d places still held", f.auth.exchanges)
	}
}
