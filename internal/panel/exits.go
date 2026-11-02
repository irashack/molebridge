package panel

import "path/filepath"

// Exit is one exit the panel controls: its provider, its kind and its state
// files. The panel writes only DesiredPath; the rest belong to that exit's
// applier.
type Exit struct {
	ID       string
	Provider string
	Label    string

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
