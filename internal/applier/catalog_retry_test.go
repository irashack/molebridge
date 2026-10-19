package applier

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"weak"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

// refreshing is a Mullvad applier whose downloads answer from fetch, with its
// catalogue due now.
func refreshing(t *testing.T, fetch func() ([]byte, error)) (*Applier, *kernel) {
	t.Helper()
	dir := t.TempDir()
	writeSnapshot(t, dir, "", map[string]any{testHost: mullvadEntry(testHost, testKey)})
	k := newKernel(t)
	o := &overridden{Provider: NewMullvad(), fetch: func(context.Context) ([]byte, error) { return fetch() }}
	a := newApplier(t, k, dir, o, "")
	a.nextCatalog = 0
	return a, k
}

// due runs the catalogue upkeep when it is due and returns the wait it set.
func due(t *testing.T, a *Applier, k *kernel) float64 {
	t.Helper()
	k.now = a.nextCatalog
	if err := a.DefaultMaintainCatalog(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a.nextCatalog - k.now
}

func TestFailedRefreshesBackOffAndASuccessStartsOver(t *testing.T) {
	failure := errors.New("netx: request timed out")
	a, k := refreshing(t, func() ([]byte, error) { return nil, failure })
	var waits []float64
	for range 9 {
		waits = append(waits, due(t, a, k))
	}
	want := []float64{60, 120, 240, 480, 960, 1920, 3600, 3600, 3600}
	for i := range want {
		if waits[i] != want[i] {
			t.Fatalf("waits %v, want %v", waits, want)
		}
	}
	// One line for the failure, however often it repeats.
	if len(k.logs) != 1 || k.logs[0] != "applier: relay catalogue refresh failed: netx: request timed out" {
		t.Fatalf("logs %q", k.logs)
	}
	// A different failure is logged once too, and keeps backing off.
	failure = errors.New("netx: request failed")
	if wait := due(t, a, k); wait != 3600 || len(k.logs) != 2 ||
		k.logs[1] != "applier: relay catalogue refresh failed: netx: request failed" {
		t.Fatalf("%v %q", wait, k.logs)
	}
	if m := readState(t, a.directory+"/relay-error.json"); m["message"] != providers.RefreshFailedMessage {
		t.Errorf("error record %v", m)
	}
	// A success logs that, waits the full interval and resets the backoff.
	a.hooks.(*overridden).fetch = func(context.Context) ([]byte, error) { return mullvadPayload(nil), nil }
	if wait := due(t, a, k); wait != providers.RefreshIntervalS || len(k.logs) != 3 ||
		k.logs[2] != "applier: relay catalogue refreshed again" {
		t.Fatalf("%v %q", wait, k.logs)
	}
	a.hooks.(*overridden).fetch = func(context.Context) ([]byte, error) { return nil, failure }
	if wait := due(t, a, k); wait != 60 || len(k.logs) != 4 {
		t.Fatalf("after a success: %v %q", wait, k.logs)
	}
}

func TestAParseFailureIsLoggedWithoutTheInput(t *testing.T) {
	a, k := refreshing(t, func() ([]byte, error) { return []byte(`{"SECRET":1,"SECRET":2}`), nil })
	due(t, a, k)
	if len(k.logs) != 1 || k.logs[0] != "applier: relay catalogue refresh failed: duplicate JSON field" {
		t.Fatalf("logs %q", k.logs)
	}
}

// The backoff never puts a retry past the moment a fresh catalogue goes stale.
func TestARetryIsNotPutOffPastTheCatalogueAge(t *testing.T) {
	a, k := refreshing(t, func() ([]byte, error) { return nil, errors.New("netx: request failed") })
	a.catalogRetry = CatalogRetryMaxSec
	snapshot(a).Snapshot["fetched_at"] = validate.FormatTime(time.Now().Add(-(providers.CatalogMaxAge - 600) * time.Second))
	if wait := due(t, a, k); wait < 595 || wait > 600 {
		t.Errorf("ten minutes before it goes stale: %v", wait)
	}
	snapshot(a).Snapshot["fetched_at"] = validate.FormatTime(time.Now().Add(-(providers.CatalogMaxAge - 10) * time.Second))
	if wait := due(t, a, k); wait != CatalogRetrySec {
		t.Errorf("ten seconds before: %v", wait)
	}
	// A stale catalogue authorizes no switch: the backoff stops at five minutes.
	staleCatalogue(a)
	if wait := due(t, a, k); wait != CatalogRetryUnusableMaxSec {
		t.Errorf("stale: %v", wait)
	}
	a.catalogRetry = 0
	var waits []float64
	for range 5 {
		waits = append(waits, due(t, a, k))
	}
	if want := []float64{60, 120, 240, 300, 300}; !slices.Equal(waits, want) {
		t.Errorf("stale waits %v, want %v", waits, want)
	}
	if !strings.HasPrefix(k.logs[0], "applier: relay catalogue refresh failed: ") || len(k.logs) != 1 {
		t.Errorf("logs %q", k.logs)
	}
}

// The catalogue's signature is cached, and follows the catalogue: a name
// added in place or a new catalogue changes it, the same names do not.
func TestCatalogueSignatureFollowsTheCatalogue(t *testing.T) {
	a, _, _ := mullvadSetup(t)
	first := a.releaseSignature("catalogue")
	if first == "" || a.releaseSignature("catalogue") != first {
		t.Fatalf("signature %q", first)
	}
	addRelay(a, "se-got-wg-001", testKey)
	second := a.releaseSignature("catalogue")
	if second == first || second == "" {
		t.Fatalf("a new name: %q", second)
	}
	// The same names in a new catalogue sign the same.
	copied := snapshot(a).Relays.Filter(func(string, *providers.Relay) bool { return true })
	snapshot(a).Relays = copied
	if got := a.releaseSignature("catalogue"); got != second {
		t.Fatalf("same names: %q, want %q", got, second)
	}
	snapshot(a).Relays = copied.Filter(func(name string, _ *providers.Relay) bool { return name == testHost })
	if got := a.releaseSignature("catalogue"); got != first {
		t.Fatalf("back to one name: %q, want %q", got, first)
	}
	staleCatalogue(a)
	if got := a.releaseSignature("catalogue"); got != "" {
		t.Fatalf("stale: %q", got)
	}
}

// The cache does not keep a replaced catalogue alive.
func TestCatalogueSignatureHoldsNoOldCatalogue(t *testing.T) {
	a, _, _ := mullvadSetup(t)
	old := weak.Make(snapshot(a).Relays)
	if a.releaseSignature("catalogue") == "" {
		t.Fatal("no signature")
	}
	snapshot(a).Relays = snapshot(a).Relays.Filter(func(string, *providers.Relay) bool { return true })
	runtime.GC()
	runtime.GC()
	if old.Value() != nil {
		t.Error("the replaced catalogue is still reachable")
	}
}
