package oidc

// One discovery fetch at a time, and a gate that holds the requests for one
// issuer path, which the limit tests share.

import (
	"net/http"
	"sync"
	"testing"

	"github.com/irashack/molebridge/internal/panel/oidc/oidctest"
)

// gate holds every request for one path until it is opened, and says when
// each arrives.
type gate struct {
	path    string
	arrived chan struct{}
	open    chan struct{}
}

func newGate(path string) *gate {
	return &gate{path: path, arrived: make(chan struct{}, 64), open: make(chan struct{})}
}

func (g *gate) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Path == g.path {
		g.arrived <- struct{}{}
		<-g.open
	}
	return http.DefaultTransport.RoundTrip(r)
}

func gatedFixture(t *testing.T, path string) (*authFixture, *gate) {
	t.Helper()
	g := newGate(path)
	f := &authFixture{t: t, clock: &oidctest.Clock{}}
	f.issuer = oidctest.New(t, f.clock.Now)
	f.config = cfg(t, envFor(f.issuer.URL, nil))
	f.auth = NewAuthenticator(f.config, testExitIDs, f.clock.Now, &http.Client{Transport: g})
	return f, g
}

func TestAnExpiredDiscoveryIsFetchedOnceForConcurrentRequests(t *testing.T) {
	f, g := gatedFixture(t, "/.well-known/openid-configuration")
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = f.auth.discover()
		}(i)
	}
	<-g.arrived
	close(g.open)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	if hits := f.issuer.DiscoveryHitCount(); hits != 1 {
		t.Fatalf("%d discovery fetches, want 1", hits)
	}
	// After the TTL the same holds for the refresh.
	f.clock.Advance(DiscoveryTTL + 1)
	g.open = make(chan struct{})
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = f.auth.discover()
		}(i)
	}
	<-g.arrived
	close(g.open)
	wg.Wait()
	if hits := f.issuer.DiscoveryHitCount(); hits != 2 {
		t.Fatalf("%d discovery fetches, want 2", hits)
	}
}

func TestWaitersShareAFailedDiscovery(t *testing.T) {
	f, g := gatedFixture(t, "/.well-known/openid-configuration")
	f.issuer.Close()
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = f.auth.discover()
		}(i)
	}
	<-g.arrived
	close(g.open)
	wg.Wait()
	for i, err := range errs {
		if err == nil {
			t.Fatalf("request %d succeeded", i)
		}
	}
	if f.auth.discovering != nil {
		t.Fatal("the fetch is still marked running")
	}
}
