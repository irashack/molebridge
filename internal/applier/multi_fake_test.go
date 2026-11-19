package applier

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/validate"
)

// The multi-provider exit's fixture: one fake kernel whose tunnel interface
// is "vpn", the three native providers' catalogues in their own files, PIA's
// secrets and API, and the tunnel in place as the starting provider's.

const multiExitIf = "vpn"

// multiExit is a multi-provider applier and what it runs on.
type multiExit struct {
	a   *Applier
	k   *kernel
	pia *piaAPI
	dir string
	// providers are the hooks given to the applier, by id.
	providers map[string]Provider
	tunnels   *fakeTunnels
}

// fakeTunnels is the exit's side of a change of provider on the fake
// kernel: Replace puts the tunnel in the state the provider's config brings
// it up in (tunnelAs), with the peer given.
type fakeTunnels struct {
	k *kernel
	// replaced are the providers Replace was asked for, in order.
	replaced []string
	// fail, when set, is what Replace returns, before changing anything.
	fail error
	// active is what the applier had persisted as active when Replace ran.
	active []string
	a      *Applier
}

func (f *fakeTunnels) PublicKey(provider string) (string, error) {
	if provider == "pia" {
		return piaOurKey, nil
	}
	return otherKey, nil
}

func (f *fakeTunnels) Replace(_ context.Context, provider string, peer PeerConfig) error {
	f.k.record("Replace %s", provider)
	f.replaced = append(f.replaced, provider)
	if f.a != nil {
		f.active = append(f.active, f.a.set.active)
	}
	if f.fail != nil {
		return f.fail
	}
	tunnelAs(f.k, provider)
	f.k.keys = nil
	if peer.PublicKey != "" {
		f.k.keys = []string{peer.PublicKey}
		f.k.endpoints[peer.PublicKey] = peer.Endpoint
	}
	return nil
}

func writeSnapshotFile(t testing.TB, dir, file, provider string, relays any) {
	t.Helper()
	snapshot := validate.Members("fetched_at", validate.FormatTime(time.Now()))
	if provider != "" {
		snapshot = append(snapshot, validate.Pair{Key: "provider", Value: provider})
	}
	snapshot = append(snapshot, validate.Pair{Key: "relays", Value: relays})
	if err := jsonfile.Write(filepath.Join(dir, "applier", file), snapshot, jsonfile.Options{Public: true}); err != nil {
		t.Fatal(err)
	}
}

// multiCatalogues writes every provider's catalogue as a multi-provider exit
// keeps them.
func multiCatalogues(t testing.TB, dir string) {
	writeSnapshotFile(t, dir, "relays-mullvad.json", "", map[string]any{testHost: mullvadEntry(testHost, testKey),
		otherHost: mullvadEntry(otherHost, otherKey)})
	writeSnapshotFile(t, dir, "relays-nordvpn.json", "nordvpn", nordCatalogue(t))
	writeSnapshotFile(t, dir, "relays-pia.json", "pia", piaEntries(t))
}

// tunnelAs puts the fake kernel's tunnel in the state a provider's tunnel
// starts in: Mullvad on testHost with its config's addresses and pairs,
// NordVPN on its address with no peer, PIA with no address and no peer.
func tunnelAs(k *kernel, provider string) {
	k.tunnelPresent = true
	k.endpoints = map[string]string{}
	switch provider {
	case "mullvad":
		k.keys = []string{testKey}
		k.addrs = []netip.Addr{mustAddr(tunnel4), mustAddr(tunnel6)}
		k.rules = map[int][]Rule{}
		for _, a := range k.addrs {
			k.rules[family(a)] = append(k.rules[family(a)], Rule{Priority: 94, Src: a.String(), SrcLen: -1, IPProto: 1, Table: 51821},
				Rule{Priority: 98, Src: a.String(), SrcLen: -1, IPProto: 1, Action: "unreachable"})
		}
		k.publicKey = otherKey
	case "nordvpn":
		k.keys = nil
		k.addrs = []netip.Addr{mustAddr(nordTunnel)}
		k.rules = map[int][]Rule{4: {
			{Priority: 94, Src: nordTunnel, SrcLen: -1, IPProto: 1, Table: 51821},
			{Priority: 98, Src: nordTunnel, SrcLen: -1, IPProto: 1, Action: "unreachable"}}}
		k.publicKey = otherKey
	case "pia":
		k.keys = nil
		k.addrs = nil
		k.rules = map[int][]Rule{}
		k.publicKey = piaOurKey
	}
}

// newMulti builds a multi-provider applier over ids, starting on start, in
// dir (a fresh one when empty). configure may change the Config first.
func newMulti(t testing.TB, dir string, start string, ids []string, configure func(*Config)) *multiExit {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
		multiCatalogues(t, dir)
	}
	secrets := filepath.Join(dir, "secrets")
	writeFile(t, filepath.Join(secrets, "username"), piaUsername+"\n", 0o600)
	writeFile(t, filepath.Join(secrets, "password"), piaPassword, 0o600)
	k := newKernel(t)
	k.exit.ExitIf = multiExitIf
	k.namespaceNets = []netip.Prefix{netip.MustParsePrefix("10.89.0.0/24")}
	k.insights = []any{map[string]any{"ip": "198.51.100.11", "country": "United States", "city": "Dallas",
		"country_code": "US", "protected": true}}
	tunnelAs(k, start)
	api := newPIAAPI(t, k)
	// PIA's API on the PIA fake, everything else (Mullvad's and NordVPN's
	// checks) on the kernel's own.
	k.handler = func(req netx.Request) (netx.Response, error) {
		if req.URL == PIATokenURL || req.URL == PIAStatusURL || req.ConnectAddr != "" {
			return api.fetch(req)
		}
		return k.defaultHandler(req)
	}
	m := &multiExit{k: k, pia: api, dir: dir, providers: map[string]Provider{}, tunnels: &fakeTunnels{k: k}}
	var list []Provider
	for _, id := range ids {
		var p Provider
		switch id {
		case "mullvad":
			p = NewMullvad()
		case "nordvpn":
			p = NewNordVPN()
		case "pia":
			p = NewPIA(PIAConfig{SecretsDir: secrets, Choose: func(int) int { return 0 }, RootCAs: api.pool})
		}
		m.providers[id] = p
		list = append(list, p)
	}
	cfg := Config{StateDir: dir, Exit: k.exit, Provider: m.providers[start], Providers: list, Tunnels: m.tunnels,
		System: k, BootID: testBoot,
		Monotonic: k.clock, Sleep: k.sleep, Log: func(s string) { k.logs = append(k.logs, s) }}
	if configure != nil {
		configure(&cfg)
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.tunnels.a = a
	a.nextCatalog = infinity
	for _, id := range ids {
		if id != a.set.active {
			a.schedules[id] = catalogSchedule{next: infinity, usable: true}
		}
	}
	a.ownerCheck = func() validate.Obj {
		return validate.Members("state", "pass", "at", validate.FormatTime(time.Now()))
	}
	m.a = a
	return m
}

var allThree = []string{"mullvad", "pia", "nordvpn"}

// targetOf is a request of each provider's server in the fixture's
// catalogues, naming its provider.
func targetOf(provider string) map[string]any {
	server := map[string]string{"mullvad": testHost, "nordvpn": nordUS, "pia": piaRegion}[provider]
	return requestAt(server, map[string]any{"provider": provider, "request_id": strings.Repeat("2", 32)})
}
