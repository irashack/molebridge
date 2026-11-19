package applier

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/irashack/molebridge/internal/failover"
	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
)

// The provider set (docs/design/multi-provider.md, step 2).

func TestProviderSetRefusesWhatAMultiProviderExitIsNot(t *testing.T) {
	k := newKernel(t)
	mullvad, nord := NewMullvad(), NewNordVPN()
	// A gluetun registry entry's id, without the gluetun machinery.
	gluetun := BaseProvider{Name: "gluetun-ivpn"}
	cases := map[string]Config{
		"four providers":      {Provider: mullvad, Providers: []Provider{mullvad, nord, NewMullvad(), NewNordVPN()}},
		"a repeat":            {Provider: mullvad, Providers: []Provider{mullvad, NewMullvad()}},
		"a gluetun provider":  {Provider: mullvad, Providers: []Provider{mullvad, gluetun}},
		"a sidecar":           {Provider: mullvad, Providers: []Provider{mullvad, nord}, Exit: Exit{Kind: "sidecar"}},
		"failover":            {Provider: mullvad, Providers: []Provider{mullvad, nord}, Failover: failover.Config{Mode: failover.ModeSameCity}},
		"a stranger to start": {Provider: NewPIA(PIAConfig{}), Providers: []Provider{mullvad, nord}},
		"one, not Provider":   {Provider: mullvad, Providers: []Provider{nord}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			cfg.StateDir, cfg.System, cfg.BootID = t.TempDir(), k, testBoot
			if cfg.Exit.Kind == "" {
				cfg.Exit = k.exit
			} else {
				e := k.exit
				e.Kind = cfg.Exit.Kind
				cfg.Exit = e
			}
			if _, err := New(cfg); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestASingleProviderExitIsASetOfOne(t *testing.T) {
	a, _, dir := mullvadSetup(t)
	set := a.Providers()
	if ids := set.IDs(); len(ids) != 1 || ids[0] != "mullvad" || set.Active() != "mullvad" || a.multiProvider() {
		t.Fatalf("%v %s", ids, set.Active())
	}
	if set.Catalog("mullvad") != a.catalog || set.Hooks("mullvad") != a.hooks || set.Catalog("pia") != nil {
		t.Fatal("the set's catalogue or hooks are not the applier's")
	}
	if err := set.SetActive("mullvad"); err != nil {
		t.Fatal(err)
	}
	if err := set.SetActive("pia"); err == nil {
		t.Fatal("a single-provider exit changed provider")
	}
	if _, err := os.Stat(filepath.Join(dir, "applier", "tunnel-provider.json")); !os.IsNotExist(err) {
		t.Fatalf("tunnel-provider.json on a single-provider exit: %v", err)
	}
	// Providers naming the provider alone is the same exit.
	k := newKernel(t)
	p := NewMullvad()
	b, err := New(Config{StateDir: dir, Exit: k.exit, Provider: p, Providers: []Provider{p}, System: k, BootID: testBoot})
	if err != nil || b.multiProvider() {
		t.Fatal(err)
	}
}

func TestAMultiProviderExitHoldsOnlyTheActiveCatalogue(t *testing.T) {
	m := newMulti(t, "", "pia", allThree, nil)
	a := m.a
	set := a.Providers()
	if ids := strings.Join(set.IDs(), ","); ids != "mullvad,pia,nordvpn" || set.Active() != "pia" {
		t.Fatalf("%s %s", ids, set.Active())
	}
	if a.hooks != m.providers["pia"] || a.spec.ID != "pia" || !a.catalog.Usable() || !a.catalog.Relays().Has(piaRegion) {
		t.Fatal("the applier's provider is not the active one")
	}
	if len(a.set.loaded) != 0 {
		t.Fatalf("inactive catalogues resident at start: %v", a.set.loaded)
	}
	// Another provider's catalogue is read from its own file when asked
	// for, and dropped again.
	nord := set.Catalog("nordvpn")
	if nord == nil || !nord.Usable() || !nord.Relays().Has(nordUS) || nord.Relays().Has(piaRegion) {
		t.Fatal("NordVPN's catalogue")
	}
	if set.Catalog("nordvpn") != nord {
		t.Fatal("read twice within a pass")
	}
	a.set.release("")
	if len(a.set.loaded) != 0 {
		t.Fatal("not released")
	}
	if set.Catalog("protonvpn") != nil || set.Hooks("protonvpn") != nil {
		t.Fatal("a provider outside the set")
	}
}

func TestSetActivePersistsBeforeTheProviderChanges(t *testing.T) {
	m := newMulti(t, "", "mullvad", allThree, nil)
	a := m.a
	path := filepath.Join(m.dir, "applier", "tunnel-provider.json")
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("written before any change")
	}
	mullvadCatalog := a.catalog
	if err := a.Providers().SetActive("nordvpn"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != `{"provider": "nordvpn"}` {
		t.Fatalf("%q %v", raw, err)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("tunnel-provider.json is %v", info.Mode())
	}
	if a.Providers().Active() != "nordvpn" || a.hooks != m.providers["nordvpn"] || a.spec.ID != "nordvpn" ||
		!a.catalog.Relays().Has(nordUS) || a.live.Load().(liveHooks).Provider != m.providers["nordvpn"] {
		t.Fatal("the applier's provider did not follow")
	}
	if a.Providers().Catalog("mullvad") == mullvadCatalog {
		t.Fatal("the previous provider's catalogue stayed resident")
	}
	if !m.k.logged("the tunnel's provider is now NordVPN") {
		t.Fatalf("%v", m.k.logs)
	}
	if err := a.Providers().SetActive("protonvpn"); err == nil || a.Providers().Active() != "nordvpn" {
		t.Fatal("a provider outside the set")
	}

	// A restart starts on the provider the tunnel was last made for.
	again := newMulti(t, m.dir, "mullvad", allThree, nil)
	if again.a.Providers().Active() != "nordvpn" || again.a.spec.ID != "nordvpn" {
		t.Fatalf("restarted on %s", again.a.Providers().Active())
	}
	// Anything but one provider of the set is no memory.
	for _, bad := range []string{`{"provider": "protonvpn"}`, `{"provider": "pia", "x": 1}`, `["pia"]`, `{"provider": 1}`} {
		writeFile(t, path, bad, 0o600)
		if got := newMulti(t, m.dir, "mullvad", allThree, nil).a.Providers().Active(); got != "mullvad" {
			t.Errorf("%s: started on %s", bad, got)
		}
	}
}

func TestEachProviderKeepsItsOwnFiles(t *testing.T) {
	m := newMulti(t, "", "mullvad", allThree, nil)
	a := m.a
	// The catalogue a refresh writes is the provider's own; relays.json is
	// never written.
	a.hooks = &overridden{Provider: a.hooks, fetch: func(context.Context) ([]byte, error) { return mullvadPayload(nil), nil }}
	a.nextCatalog = 0
	if err := a.DefaultMaintainCatalog(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.dir, "applier", "relays.json")); !os.IsNotExist(err) {
		t.Fatal("relays.json written on a multi-provider exit")
	}
	snapshot := jsonfile.Read(filepath.Join(m.dir, "applier", "relays-mullvad.json"), 1<<20)
	if snapshot == nil {
		t.Fatal("relays-mullvad.json")
	}
	// Location memory is per provider.
	if err := a.verified(testHost); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.dir, "applier", "location-mullvad.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(m.dir, "applier", "location.json")); !os.IsNotExist(err) {
		t.Fatal("location.json on a multi-provider exit")
	}
	if err := a.Providers().SetActive("nordvpn"); err != nil {
		t.Fatal(err)
	}
	if a.location.Server != "" {
		t.Fatalf("NordVPN inherited Mullvad's location: %+v", a.location)
	}
	if err := a.Providers().SetActive("mullvad"); err != nil {
		t.Fatal(err)
	}
	if a.location.Server != testHost {
		t.Fatalf("Mullvad's location lost: %+v", a.location)
	}
}

func TestInactiveCataloguesRefreshOneAtATimeAndLeaveMemory(t *testing.T) {
	m := newMulti(t, "", "pia", allThree, nil)
	a, k := m.a, m.k
	fetched := map[string]int{}
	mullvadSpec, _ := providers.Get("mullvad")
	nordSpec, _ := providers.Get("nordvpn")
	k.handler = func(req netx.Request) (netx.Response, error) {
		switch req.URL {
		case mullvadSpec.CatalogURL:
			fetched["mullvad"]++
			return netx.Response{Status: 200, Body: mullvadPayload(nil)}, nil
		case nordSpec.CatalogURL:
			fetched["nordvpn"]++
			return netx.Response{}, errInjected
		}
		return k.defaultHandler(req)
	}
	for id := range a.schedules {
		a.schedules[id] = catalogSchedule{}
	}
	if err := a.maintainInactive(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if fetched["mullvad"] != 1 || fetched["nordvpn"] != 0 {
		t.Fatalf("first pass fetched %v", fetched)
	}
	if len(a.set.loaded) != 0 {
		t.Fatal("the refreshed catalogue stayed in memory")
	}
	if s := a.schedules["mullvad"]; !s.usable || s.next <= k.now {
		t.Fatalf("Mullvad's schedule %+v", s)
	}
	if err := a.maintainInactive(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if fetched["nordvpn"] != 1 || fetched["mullvad"] != 1 {
		t.Fatalf("second pass fetched %v", fetched)
	}
	if s := a.schedules["nordvpn"]; s.retry != CatalogRetrySec || s.failure == "" {
		t.Fatalf("NordVPN's schedule %+v", s)
	}
	if !k.logged("relay catalogue (NordVPN) refresh failed") {
		t.Fatalf("%v", k.logs)
	}
	// Each on its own schedule: nothing more is due.
	if err := a.maintainInactive(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if fetched["nordvpn"] != 1 || fetched["mullvad"] != 1 {
		t.Fatalf("third pass fetched %v", fetched)
	}
	// A catalogue the pass needs (the target's provider) stays read.
	a.schedules["mullvad"] = catalogSchedule{}
	if err := a.maintainInactive(context.Background(), "mullvad"); err != nil {
		t.Fatal(err)
	}
	if a.set.loaded["mullvad"] == nil {
		t.Fatal("the target provider's catalogue was dropped")
	}
}

// Healthy runs on another goroutine than a change of provider.
func TestHealthyReadsTheActiveProviderWithoutARace(t *testing.T) {
	m := newMulti(t, "", "mullvad", allThree, nil)
	withPublished(m.a, m.dir)
	m.a.inspect(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 50 {
			m.a.Healthy(context.Background())
		}
	}()
	for i := range 50 {
		if err := m.a.Providers().SetActive(allThree[i%3]); err != nil {
			t.Error(err)
		}
	}
	wg.Wait()
}
