package applier

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

var infinity = math.Inf(1)

// overridden is a provider with some hooks replaced, the way the Python tests
// monkeypatched a method of the applier.
type overridden struct {
	Provider
	fetch      func(ctx context.Context) ([]byte, error)
	serverFor  func(ctx context.Context, a *Applier, keys []string) (string, error)
	applyRelay func(ctx context.Context, a *Applier, relay *providers.Relay, keys []string) error
}

func (o *overridden) FetchCatalog(ctx context.Context, a *Applier) ([]byte, error) {
	if o.fetch != nil {
		return o.fetch(ctx)
	}
	return o.Provider.FetchCatalog(ctx, a)
}

func (o *overridden) ServerFor(ctx context.Context, a *Applier, keys []string) (string, error) {
	if o.serverFor != nil {
		return o.serverFor(ctx, a, keys)
	}
	return o.Provider.ServerFor(ctx, a, keys)
}

func (o *overridden) ApplyRelay(ctx context.Context, a *Applier, relay *providers.Relay, keys []string) error {
	if o.applyRelay != nil {
		return o.applyRelay(ctx, a, relay, keys)
	}
	return o.Provider.ApplyRelay(ctx, a, relay, keys)
}

// mullvadSetup is the Python `runtime` fixture: a Mullvad applier with one
// listed relay.
func mullvadSetup(t testing.TB) (*Applier, *kernel, string) {
	t.Helper()
	dir := t.TempDir()
	writeSnapshot(t, dir, "", map[string]any{testHost: mullvadEntry(testHost, testKey)})
	k := newKernel(t)
	return newApplier(t, k, dir, NewMullvad(), ""), k, dir
}

// mullvadPayload is the relay list with one active relay.
func mullvadPayload(changes map[string]any) []byte {
	relay := mullvadEntry(testHost, testKey)
	relay["active"], relay["location"] = true, "se-sto"
	for k, v := range changes {
		relay[k] = v
	}
	raw, err := validate.MarshalJSON(map[string]any{
		"locations": map[string]any{"se-sto": map[string]any{"city": "Example City", "country": "Example"}},
		"wireguard": map[string]any{"relays": []any{relay}}})
	if err != nil {
		panic(err)
	}
	return raw
}

func snapshot(a *Applier) *providers.RelayCatalog { return a.catalog.(*nativeCatalog).inner }

func staleCatalogue(a *Applier) {
	snapshot(a).Snapshot["fetched_at"] = validate.FormatTime(time.Now().Add(-86401 * time.Second))
}

func addRelay(a *Applier, host, key string) {
	relay := mullvadEntry(host, key)
	entry := providers.ValidateMullvadEntry(relay)
	snapshot(a).Relays.Set(host, entry)
}

func contains2(s, sub string) bool { return strings.Contains(s, sub) }

func isURL(substr string) func(r netx.Request) bool {
	return func(r netx.Request) bool { return strings.Contains(r.URL, substr) }
}
