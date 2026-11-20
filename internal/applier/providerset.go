package applier

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime/debug"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
)

// A multi-provider exit (docs/design/multi-provider.md) is one NetBird peer
// that can carry Mullvad, PIA or NordVPN, one at a time. Its applier holds a
// provider set: every provider's hooks and catalogue, one of them active,
// the provider of the tunnel in place. A single-provider exit is a set of
// one with today's file names, and nothing about it changes.
//
// The applier's hooks, catalog and spec fields are always the active
// provider's: activate re-points them when the active provider changes, so
// the code that inspects the tunnel in place reads them as before. What a
// change to another provider needs of that provider (its catalogue at the
// gate, its hooks to enter its tunnel) comes from the set.

// ProviderSet is the providers an applier holds, one of them active.
type ProviderSet interface {
	// IDs are the providers in PROVIDERS order.
	IDs() []string
	// Active is the provider of the tunnel in place.
	Active() string
	// Hooks are a provider's hooks, nil for one outside the set.
	Hooks(id string) Provider
	// Catalog is a provider's catalogue, nil for one outside the set. The
	// active provider's is resident; another's is read from its snapshot on
	// disk when asked for and dropped again once nothing needs it.
	Catalog(id string) Catalog
	// SetActive makes id the active provider and persists it
	// (tunnel-provider.json) before anything else changes, so a restart,
	// and the exit's recovery, bring up its tunnel.
	SetActive(id string) error
}

// MaxProviders is the most providers a multi-provider exit holds: the three
// native ones.
const MaxProviders = 3

// tunnelProviderMaxBytes bounds tunnel-provider.json: one provider id.
const tunnelProviderMaxBytes = 256

// catalogSchedule is one provider's catalogue refresh state: when the next
// refresh is due, the backoff after a failure, when the last one ran, the
// failure last logged and, for a provider whose catalogue isn't resident,
// whether it was usable when last read.
type catalogSchedule struct {
	next, retry, tried float64
	failure            string
	usable             bool
}

type providerSet struct {
	a      *Applier
	ids    []string
	hooks  map[string]Provider
	active string
	multi  bool
	// loaded are inactive providers' catalogues read from disk, kept until
	// release.
	loaded map[string]Catalog
}

func (s *providerSet) IDs() []string  { return append([]string(nil), s.ids...) }
func (s *providerSet) Active() string { return s.active }

func (s *providerSet) Hooks(id string) Provider { return s.hooks[id] }

func (s *providerSet) Catalog(id string) Catalog {
	if id == s.active {
		return s.a.catalog
	}
	hooks := s.hooks[id]
	if hooks == nil {
		return nil
	}
	if c, ok := s.loaded[id]; ok {
		return c
	}
	c := hooks.MakeCatalog(s.a)
	s.loaded[id] = c
	return c
}

func (s *providerSet) SetActive(id string) error {
	if s.hooks[id] == nil {
		return fmt.Errorf("applier: %q is not one of this exit's providers", id)
	}
	if !s.multi {
		// A set of one: its provider is always active, and nothing is
		// written.
		return nil
	}
	if err := jsonfile.Write(s.a.tunnelProviderPath(), validate.Members("provider", id), jsonfile.Options{}); err != nil {
		return wrapIO(err)
	}
	s.a.activate(id)
	return nil
}

// release drops the inactive catalogues read from disk, all but keep's.
func (s *providerSet) release(keep string) {
	freed := false
	for id := range s.loaded {
		if id != keep {
			delete(s.loaded, id)
			freed = true
		}
	}
	if freed {
		// The snapshot was up to 16 MiB of JSON decoded whole.
		debug.FreeOSMemory()
	}
}

// Providers is the applier's provider set.
func (a *Applier) Providers() ProviderSet { return a.set }

// multiProvider is true on a multi-provider exit.
func (a *Applier) multiProvider() bool { return a.set != nil && a.set.multi }

func (a *Applier) tunnelProviderPath() string {
	return filepath.Join(a.privateDir, TunnelProviderFile)
}

// TunnelProviderFile is the file, in the applier's private directory, that
// names a multi-provider exit's active provider: {"provider": id}.
const TunnelProviderFile = "tunnel-provider.json"

// TunnelProviderPath is tunnel-provider.json for a state directory and a
// private directory ("" is <stateDir>/applier), as the applier writes it.
func TunnelProviderPath(stateDir, privateDir string) string {
	if privateDir == "" {
		privateDir = filepath.Join(stateDir, "applier")
	}
	return filepath.Join(privateDir, TunnelProviderFile)
}

// ReadTunnelProvider is the provider tunnel-provider.json at path names,
// when it is one of ids; ok is false for a missing, unreadable or foreign
// file, which a multi-provider exit treats as no record (it starts on
// PROVIDER).
func ReadTunnelProvider(path string, ids []string) (string, bool) {
	return tunnelProviderFrom(state.ReadJSON(path, tunnelProviderMaxBytes), func(id string) bool {
		for _, v := range ids {
			if v == id {
				return true
			}
		}
		return false
	})
}

// tunnelProviderFrom is the provider a decoded tunnel-provider.json names:
// exactly one member, a provider in the set.
func tunnelProviderFrom(v any, inSet func(string) bool) (string, bool) {
	raw, _ := v.(map[string]any)
	if id, ok := raw["provider"].(string); ok && len(raw) == 1 && inSet(id) {
		return id, true
	}
	return "", false
}

// newProviderSet checks a configuration's providers and builds the set. One
// provider (Providers empty, or naming only it) is a set of one; two or three
// are a multi-provider exit: native providers only, distinct, on an overlay
// exit, with the configured Provider among them.
func newProviderSet(a *Applier, cfg Config) (*providerSet, error) {
	s := &providerSet{a: a, hooks: map[string]Provider{}, loaded: map[string]Catalog{}}
	if len(cfg.Providers) <= 1 {
		if len(cfg.Providers) == 1 && cfg.Providers[0].ID() != cfg.Provider.ID() {
			return nil, errors.New("applier: the provider is not the one in the set")
		}
		s.ids = []string{cfg.Provider.ID()}
		s.hooks[cfg.Provider.ID()] = cfg.Provider
		s.active = cfg.Provider.ID()
		return s, nil
	}
	if len(cfg.Providers) > MaxProviders {
		return nil, fmt.Errorf("applier: a multi-provider exit holds at most %d providers", MaxProviders)
	}
	if cfg.Exit.Kind != "" && cfg.Exit.Kind != "overlay" {
		return nil, errors.New("applier: a multi-provider exit is an overlay exit")
	}
	if cfg.Failover.On() {
		// Failover stays within one provider (the design's decision 7), and
		// is built for single-provider exits only so far.
		return nil, errors.New("applier: automatic failover is for single-provider exits")
	}
	for _, p := range cfg.Providers {
		if p == nil {
			return nil, errors.New("applier: a provider in the set is missing")
		}
		spec, err := providers.Get(p.ID())
		if err != nil {
			return nil, err
		}
		if spec.Backend != providers.BackendNative {
			return nil, fmt.Errorf("applier: %s is not a native provider; a multi-provider exit takes native providers only", p.ID())
		}
		if s.hooks[p.ID()] != nil {
			return nil, fmt.Errorf("applier: %s is in the set twice", p.ID())
		}
		s.ids = append(s.ids, p.ID())
		s.hooks[p.ID()] = p
	}
	if s.hooks[cfg.Provider.ID()] == nil {
		return nil, errors.New("applier: the starting provider is not one of the set's")
	}
	s.multi = true
	s.active = cfg.Provider.ID()
	// Later starts use the provider the tunnel was last made for, not the
	// starting one, so a restart doesn't move everyone (decision 8).
	if id, ok := tunnelProviderFrom(a.readJSON(a.tunnelProviderPath(), tunnelProviderMaxBytes),
		func(id string) bool { return s.hooks[id] != nil }); ok {
		s.active = id
	}
	return s, nil
}

// catalogFiles are the names of a provider's catalogue and its error record
// in the applier's directory: relays.json and relay-error.json on a
// single-provider exit, as always; relays-<id>.json and
// relay-error-<id>.json on a multi-provider exit, which writes no
// relays.json, so a reader that expects one provider's catalogue there finds
// none rather than the wrong provider's servers.
func (a *Applier) catalogFiles(provider string) (string, string) {
	if a.multiProvider() {
		return "relays-" + provider + ".json", "relay-error-" + provider + ".json"
	}
	return "relays.json", "relay-error.json"
}

// nativeCatalog is a native provider's catalogue in the applier's directory.
func (a *Applier) nativeCatalog(provider string, portForwardOnly bool) Catalog {
	file, errorFile := a.catalogFiles(provider)
	return NativeCatalogFiles(filepath.Join(a.directory, file), filepath.Join(a.directory, errorFile), provider,
		portForwardOnly, a.wall)
}

// activate makes id the active provider in memory: its hooks, catalogue,
// spec, refresh schedule and location memory become the applier's, and the
// previous provider's catalogue leaves memory (it stays on disk). Only
// SetActive calls it, after persisting.
func (a *Applier) activate(id string) {
	s := a.set
	old := s.active
	if old == id {
		return
	}
	a.schedules[old] = catalogSchedule{next: a.nextCatalog, retry: a.catalogRetry, tried: a.catalogTried,
		failure: a.catalogFailure, usable: a.catalog.Usable()}
	a.locations[old] = a.location
	catalog := s.Catalog(id)
	delete(s.loaded, id)
	s.active = id
	a.hooks, a.catalog = s.hooks[id], catalog
	a.spec, _ = providers.Get(id)
	a.live.Store(liveHooks{a.hooks})
	next := a.schedules[id]
	delete(a.schedules, id)
	a.nextCatalog, a.catalogRetry, a.catalogTried, a.catalogFailure = next.next, next.retry, next.tried, next.failure
	if l, ok := a.locations[id]; ok {
		a.location = l
		delete(a.locations, id)
	} else {
		a.location = a.loadLocation()
	}
	a.log("applier: the tunnel's provider is now " + a.spec.Label)
	debug.FreeOSMemory()
}

// liveHooks boxes the active provider's hooks for Healthy, which runs on
// another goroutine than the one that changes them.
type liveHooks struct{ Provider }

// maintainInactive refreshes, on a multi-provider exit, at most one inactive
// provider's catalogue per pass, when its schedule says so: read from disk,
// refreshed, written, and dropped from memory again unless keep (the
// target's provider) needs it. One refresh at a time keeps the peak at one
// provider's parse.
func (a *Applier) maintainInactive(ctx context.Context, keep string) error {
	if !a.multiProvider() {
		return nil
	}
	now := a.clock()
	for _, id := range a.set.ids {
		if id == a.set.active {
			continue
		}
		s := a.schedules[id]
		due := s.next
		if !s.usable {
			due = min(due, s.tried+CatalogRetryUnusableMaxSec)
		}
		if now < due {
			continue
		}
		hooks := a.set.hooks[id]
		catalog := a.set.Catalog(id)
		spec, _ := providers.Get(id)
		a.refreshing = spec
		err := a.refreshCatalog(ctx, catalog, func() ([]byte, error) { return hooks.FetchCatalog(ctx, a) }, &s, spec.Label)
		a.refreshing = nil
		s.usable = catalog.Usable()
		a.schedules[id] = s
		if id != keep {
			a.set.release(keep)
		}
		return err
	}
	return nil
}
