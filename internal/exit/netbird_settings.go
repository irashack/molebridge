package exit

import (
	"encoding/csv"
	"strings"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/nbprofile"
)

// NetBird's settings, the way in's part of LoadSettings (settings.go): the
// image check, made before any other setting, and the overlay's checks, made
// after the tunnel's. LoadSettings keeps the order and calls these at those
// two points; what they check is NetBird's.

// CoreImageRefusal is the one line a NetBird exit started from the image
// without NetBird prints.
const CoreImageRefusal = prefix + "EXIT_KIND=overlay (the default) runs NetBird, and this image has no NetBird client: " +
	"use ghcr.io/irashack/molebridge for a NetBird exit (molebridge-core is for the sidecars)"

// needNetBird refuses a NetBird exit when the image has no NetBird client in
// the environment's PATH.
func needNetBird(env map[string]string) error {
	var path []string
	if v, ok := env["PATH"]; ok {
		path = []string{"PATH=" + v}
	}
	if _, err := lookPath("netbird", path); err != nil {
		return &Refusal{Line: CoreImageRefusal}
	}
	return nil
}

// loadNetBird checks an overlay exit's NetBird settings and its stored
// profile, and keeps what the exit needs of them in s (NB, NBPaths,
// NoIdentity, and the gluetun backend's FwmarkGrace and WatchLog).
func (s *Settings) loadNetBird(env map[string]string, cfg contract.Config, o LoadOptions) error {
	// NetBird creates the interface the contract guards; the two names
	// are one setting in compose.yaml and must stay one.
	// (An empty NB_INTERFACE_NAME is NetBird settings' refusal below.)
	if name, set := env["NB_INTERFACE_NAME"]; !set || name != "" {
		if name == "" {
			name = contract.DefaultOverlayIf
		}
		if name != cfg.OverlayIf {
			return refuse("NB_INTERFACE_NAME (%s) must equal OVERLAY_IF (%s), the interface the routing contract guards", name, cfg.OverlayIf)
		}
	}
	paths := o.NBPaths
	backend := nbprofile.BackendWireGuard
	if cfg.IsGluetun() {
		backend = nbprofile.BackendGluetun
	}
	// The environment the gate saw: the routing settings' defaults for the
	// interface names.
	nbEnv := withDefaults(env, map[string]string{"EXIT_IF": cfg.ExitIf})
	nb, err := nbprofile.CheckAll(nbEnv, backend, paths)
	if err != nil {
		return verbatim(err)
	}
	s.NB = nb
	if paths.StateDir == "" {
		paths = nbprofile.DefaultPaths(nb.StateDir)
	}
	s.NBPaths = paths
	res, err := nbprofile.CheckBlacklist(paths, cfg.ExitIf)
	if err != nil {
		return verbatim(err)
	}
	s.NoIdentity = res.NoIdentity
	if res.NoIdentity {
		// First enrollment (D25). With no stored profile there is nothing to
		// check yet, and the profile NetBird writes on its first `netbird up`
		// takes its interface blacklist from this setting
		// (--extra-iface-blacklist), so without it the new peer would offer
		// the tunnel interface's address as a connection candidate. It must
		// name the tunnel interface by NetBird's own rule: an entry matches
		// every interface whose name starts with it.
		//
		// There is deliberately no kernel fence beyond this. The blacklist
		// governs which local addresses NetBird's own ICE candidates may use;
		// it does not decide what is forwarded for clients, which the routing
		// contract already confines. The worker still reads the profile again
		// after `netbird up` and stops NetBird if the entry is not effective.
		entries, err := netbirdExtraBlacklist(env)
		if err != nil {
			return err
		}
		if !coversInterface(entries, cfg.ExitIf) {
			return refuse("NetBird has no stored profile yet, so NB_EXTRA_IFACE_BLACKLIST must name the tunnel interface %s (compose.yaml sets it to EXIT_IF); the new profile's interface blacklist is built from it", cfg.ExitIf)
		}
	}
	if cfg.IsGluetun() {
		s.FwmarkGrace = nb.FwmarkGrace
		s.WatchLog = nb.WatchLog
	}
	return nil
}

// netbirdExtraBlacklist is the list `netbird up` ends up with for
// --extra-iface-blacklist when the environment sets it, read as NetBird 0.82.1
// reads it (client/cmd/root.go SetFlagsFromEnvVars, spf13/pflag's
// StringSliceVar): for the old WT_ name and then the NB_ name, a variable that
// is present (even empty) is given to the flag, whose value is Go's
// encoding/csv reading of the text, one record, no trimming, no lazy quotes;
// the first value replaces the default and the second is appended to it. A
// value NetBird cannot parse is logged by NetBird and ignored, so it names no
// interface at all: here it is a refusal.
//
// An empty entry is refused too. NetBird compares with strings.HasPrefix, to
// which an empty entry is a prefix of every name, so it would blacklist every
// interface, the overlay's own addresses included, and leave NetBird unable to
// connect; nobody writes it on purpose.
func netbirdExtraBlacklist(env map[string]string) ([]string, error) {
	var out []string
	for _, name := range []string{"WT_EXTRA_IFACE_BLACKLIST", "NB_EXTRA_IFACE_BLACKLIST"} {
		v, set := env[name]
		if !set {
			continue
		}
		entries, err := readAsCSV(v)
		if err != nil {
			return nil, refuse("%s is not a list NetBird can read (comma-separated, with CSV quoting); NetBird would ignore it", name)
		}
		for _, e := range entries {
			if e == "" {
				return nil, refuse("%s has an empty entry, which NetBird reads as every interface", name)
			}
		}
		out = append(out, entries...)
	}
	return out, nil
}

// readAsCSV is pflag's: the empty text is an empty list, anything else is the
// first record of an encoding/csv reader with its defaults.
func readAsCSV(val string) ([]string, error) {
	if val == "" {
		return []string{}, nil
	}
	return csv.NewReader(strings.NewReader(val)).Read()
}

// coversInterface applies NetBird's blacklist rule to parsed entries: an entry
// matches an interface whose name begins with it
// (client/internal/stdnet/filter.go, strings.HasPrefix).
func coversInterface(entries []string, iface string) bool {
	for _, entry := range entries {
		if entry != "" && strings.HasPrefix(iface, entry) {
			return true
		}
	}
	return false
}
