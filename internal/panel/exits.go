package panel

import (
	"path/filepath"
	"strings"
)

// Exit is one exit the panel controls: its provider, its kind and its state
// files. The panel writes only DesiredPath; the rest belong to that exit's
// applier.
type Exit struct {
	ID       string
	Provider string
	Label    string
	// Providers is a multi-provider exit's providers, in order; nil for a
	// single-provider exit (Multi).
	Providers []string

	DesiredPath    string
	ResultPath     string
	RelaysPath     string
	RelayErrorPath string

	// Kind is "overlay" (a NetBird exit) or "sidecar" (an ordinary gluetun
	// other containers share): the operator's configuration, never the
	// record's.
	Kind string

	// Network is whether the exit is reached through the network exchange
	// (PANEL_NETWORK_EXITS): its files are the exchange's copies, and LinkPath,
	// the exchange's link state, decides whether they may be judged at all.
	Network  bool
	LinkPath string

	// ProxyPath is the proxy's status file beside this exit
	// (PANEL_PROXY_STATUS), read only for the proxy view; "" when none is
	// configured. It never feeds the exit's verdict.
	ProxyPath string
}

// ExitUnder is Exit.under: the exit whose state is stateDir/panel and
// stateDir/applier.
func ExitUnder(id, provider, label, stateDir, kind string) Exit {
	return Exit{
		ID: id, Provider: provider, Label: label,
		DesiredPath:    filepath.Join(stateDir, "panel", "desired.json"),
		ResultPath:     filepath.Join(stateDir, "applier", "result.json"),
		RelaysPath:     filepath.Join(stateDir, "applier", "relays.json"),
		RelayErrorPath: filepath.Join(stateDir, "applier", "relay-error.json"),
		Kind:           kind,
	}
}

// Multi reports a multi-provider exit (PANEL_EXITS id=mullvad+pia+nordvpn,
// or a single exit's PROVIDERS): Providers names its two or three providers
// in order, and Provider is the first of them (for a single exit, PROVIDER,
// the one it starts on), only a fallback while no record names the active
// one.
func (e Exit) Multi() bool { return len(e.Providers) > 1 }

// Has reports whether provider is one of a multi-provider exit's.
func (e Exit) Has(provider string) bool {
	for _, p := range e.Providers {
		if p == provider {
			return true
		}
	}
	return false
}

// CatalogFiles are a provider's catalogue and its error record: the exit's
// RelaysPath and RelayErrorPath on a single-provider exit, and on a
// multi-provider exit relays-<provider>.json and relay-error-<provider>.json
// beside them, as its applier writes them (it writes no relays.json).
func (e Exit) CatalogFiles(provider string) (relays, relayError string) {
	if !e.Multi() {
		return e.RelaysPath, e.RelayErrorPath
	}
	dir := filepath.Dir(e.RelaysPath)
	return filepath.Join(dir, "relays-"+provider+".json"), filepath.Join(dir, "relay-error-"+provider+".json")
}

// MetricsProvider is the provider metrics name: the provider, or a
// multi-provider exit's providers joined by +, as PANEL_EXITS writes them.
func (e Exit) MetricsProvider() string {
	if e.Multi() {
		return strings.Join(e.Providers, "+")
	}
	return e.Provider
}
