// Tests ported from tools/test_providers.py, the applier parts: the registry
// supplies the catalogue's URL, cap and timeout and the address model to the
// applier, and an unknown provider or a sidecar with a native provider stops
// it at start. The registry's own tests are internal/providers'.
package applier

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
)

func TestCatalogueFetchTakesURLCapAndTimeoutFromTheRegistry(t *testing.T) {
	for _, provider := range nativeProviders {
		a, k := native(t, provider, "")
		var seen netx.Request
		k.handler = func(r netx.Request) (netx.Response, error) {
			seen = r
			return netx.Response{Status: 200, Body: []byte("x")}, nil
		}
		raw, err := a.hooks.FetchCatalog(context.Background(), a)
		spec, _ := providers.Lookup(provider)
		if err != nil || string(raw) != "x" {
			t.Fatalf("%s: %q %v", provider, raw, err)
		}
		if seen.URL != spec.CatalogURL || seen.MaxBytes != int64(spec.CatalogMaxBytes) ||
			seen.Timeout != time.Duration(spec.CatalogTimeoutS)*time.Second || seen.AllowHTTP || !strings.HasPrefix(seen.URL, "https://") {
			t.Errorf("%s: %+v", provider, seen)
		}
	}
}

func TestApplierAddressModelComesFromTheRegistry(t *testing.T) {
	for _, provider := range nativeProviders {
		a, k := native(t, provider, "")
		spec, _ := providers.Lookup(provider)
		var asked []bool
		o := &routingProbe{Provider: a.hooks, asked: &asked}
		a.hooks = o
		k.overlayPresent = false // the gate stops at the routing check
		desire(t, a, requestAt(serverNames[provider], nil))
		mustTick(t, a)
		if len(asked) == 0 || asked[0] != spec.AddressBeforeSwitch {
			t.Errorf("%s: gate asked with requireAddress %v, registry says %v", provider, asked, spec.AddressBeforeSwitch)
		}
	}
}

type routingProbe struct {
	Provider
	asked *[]bool
}

func (p *routingProbe) RoutingStatus(ctx context.Context, a *Applier, requireAddress bool) (bool, bool) {
	*p.asked = append(*p.asked, requireAddress)
	return p.Provider.RoutingStatus(ctx, a, requireAddress)
}

func TestProviderForBuildsEachNativeProvider(t *testing.T) {
	exit := Exit{Overlay: testOverlay4}
	for _, id := range nativeProviders {
		p, err := ProviderFor(id, exit, func(string) string { return "" })
		if err != nil || p.ID() != id {
			t.Errorf("%s: %v", id, err)
		}
	}
	if _, err := ProviderFor("examplevpn", exit, func(string) string { return "" }); err == nil ||
		!strings.HasPrefix(err.Error(), "PROVIDER must be one of") {
		t.Errorf("unknown: %v", err)
	}
	if _, err := ProviderFor("pia", exit, func(k string) string {
		return map[string]string{"PIA_PORT_FORWARD": "on"}[k]
	}); err == nil {
		t.Error("PIA's settings not read")
	}
	if _, err := ProviderFor("gluetun-mullvad", exit, func(string) string { return "" }); err == nil {
		t.Error("gluetun built here")
	}
}

func TestNewStopsAnUnknownProviderAndKind(t *testing.T) {
	k := newKernel(t)
	if _, err := New(Config{StateDir: t.TempDir(), Exit: k.exit, Provider: BaseProvider{Name: "examplevpn"}, System: k}); err == nil ||
		!strings.HasPrefix(err.Error(), "PROVIDER must be one of") {
		t.Errorf("unknown provider: %v", err)
	}
	k.exit.Kind = "sidecar"
	// 0.9.0: a sidecar with a native provider is the native sidecar.
	if _, err := New(Config{StateDir: t.TempDir(), Exit: k.exit, Provider: NewMullvad(), System: k}); err != nil {
		t.Errorf("native sidecar: %v", err)
	}
	k.exit.Kind = "bridge"
	if _, err := New(Config{StateDir: t.TempDir(), Exit: k.exit, Provider: NewMullvad(), System: k}); err == nil ||
		err.Error() != "EXIT_KIND must be overlay or sidecar" {
		t.Errorf("unknown kind: %v", err)
	}
	if _, err := New(Config{StateDir: t.TempDir(), Exit: k.exit}); err == nil {
		t.Error("no provider or system")
	}
}
