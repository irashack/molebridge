package panel

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/irashack/molebridge/internal/buildgate"
	"github.com/irashack/molebridge/internal/exchange"
	"github.com/irashack/molebridge/internal/panel/oidc"
	"github.com/irashack/molebridge/internal/panel/pystr"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/verdict"
)

var exitIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ParseExits parses PANEL_EXITS: comma-separated `id=provider[/kind][:label]`,
// kind being overlay (the default) or sidecar (a gluetun provider's, or since
// 0.9.0 a native provider's: the native sidecar). A multi-provider exit is
// `id=mullvad+pia+nordvpn[/overlay][:label]`: two or three native providers
// joined by + (no provider id contains it), overlay only, accepted only where
// multi-provider exits are switched on (buildgate.MultiProvider). Each exit's
// state is $STATE_DIR/<id>/panel and $STATE_DIR/<id>/applier. Empty means one
// exit whose state is $STATE_DIR itself (no exits are returned).
func ParseExits(raw, stateDir string) ([]Exit, error) {
	return parseExits(raw, stateDir, buildgate.MultiProvider)
}

// parseExits is ParseExits with multi-provider exits switched on or off:
// this package's tests cover them in the release build too.
func parseExits(raw, stateDir string, multiAvailable bool) ([]Exit, error) {
	var exits []Exit
	for _, piece := range strings.Split(raw, ",") {
		entry := pystr.Strip(piece)
		if entry == "" {
			continue
		}
		exitID, rest, sep := strings.Cut(entry, "=")
		provider, label, _ := strings.Cut(rest, ":")
		// No provider id contains '/'.
		provider, kind, slash := strings.Cut(provider, "/")
		exitID, provider, label, kind = pystr.Strip(exitID), pystr.Strip(provider), pystr.Strip(label), pystr.Strip(kind)
		repr := pystr.Repr(entry)
		if !sep || !exitIDRE.MatchString(exitID) {
			return nil, fmt.Errorf("PANEL_EXITS: exit ids are 1-32 of a-z, 0-9 and -, in %s", repr)
		}
		var set []string
		if strings.Contains(provider, "+") {
			if !multiAvailable {
				return nil, fmt.Errorf("PANEL_EXITS: %s, in %s", multiProviderUnavailable, repr)
			}
			var err error
			if set, err = parseProviderSet(strings.Split(provider, "+")); err != nil {
				return nil, fmt.Errorf("PANEL_EXITS: %v, in %s", err, repr)
			}
			if slash && kind != "overlay" {
				return nil, fmt.Errorf("PANEL_EXITS: a multi-provider exit is an overlay exit, in %s", repr)
			}
			provider = set[0]
		}
		spec, known := providers.Lookup(provider)
		if !known {
			return nil, fmt.Errorf("PANEL_EXITS: provider must be one of %s, in %s", strings.Join(providers.IDs(), ", "), repr)
		}
		if slash && kind != "overlay" && kind != "sidecar" {
			return nil, fmt.Errorf("PANEL_EXITS: the kind after / is overlay or sidecar, in %s", repr)
		}
		if kind == "" {
			kind = "overlay"
		}
		if label == "" {
			label = spec.Label
			if set != nil {
				label = setLabel(set)
			}
		}
		if utf8.RuneCountInString(label) > 40 || !pystr.IsPrintable(label) {
			return nil, fmt.Errorf("PANEL_EXITS: labels are at most 40 printable characters, in %s", repr)
		}
		for _, e := range exits {
			if e.ID == exitID {
				return nil, fmt.Errorf("PANEL_EXITS: duplicate exit id %s", pystr.Repr(exitID))
			}
		}
		ex := ExitUnder(exitID, provider, label, joinPath(stateDir, exitID), kind)
		ex.Providers = set
		exits = append(exits, ex)
	}
	return exits, nil
}

// multiProviderUnavailable is the refusal of a multi-provider exit while
// they are switched off in this build, worded as the exit's.
const multiProviderUnavailable = "multi-provider exits are not available in this release yet; see docs/design/multi-provider.md"

// providerSetBad is the refusal of a provider set that isn't two or three
// distinct native providers.
const providerSetBad = "a multi-provider exit takes two or three of mullvad, pia and nordvpn, each once"

// parseProviderSet checks a multi-provider exit's providers as the exit
// checks PROVIDERS: two or three of mullvad, pia and nordvpn, each once.
func parseProviderSet(parts []string) ([]string, error) {
	var ids []string
	for _, part := range parts {
		id := pystr.Strip(part)
		spec, ok := providers.Lookup(id)
		if ok && spec.Backend != providers.BackendNative {
			return nil, &nativeOnly{id}
		}
		if !ok || slices.Contains(ids, id) {
			return nil, errors.New(providerSetBad)
		}
		ids = append(ids, id)
	}
	if len(ids) < 2 || len(ids) > verdict.MaxProviders {
		return nil, errors.New(providerSetBad)
	}
	return ids, nil
}

// nativeOnly refuses a gluetun provider in a provider set.
type nativeOnly struct{ id string }

func (e *nativeOnly) Error() string {
	return "a multi-provider exit takes native providers only (mullvad, pia, nordvpn), not " + e.id
}

// setLabel is a multi-provider exit's default label: its providers' labels
// joined by " + ".
func setLabel(ids []string) string {
	labels := make([]string, len(ids))
	for i, id := range ids {
		spec, _ := providers.Lookup(id)
		labels[i] = spec.Label
	}
	return strings.Join(labels, " + ")
}

// providersEnvMax bounds PROVIDERS, as the exit does: three ids, commas and
// some spaces.
const providersEnvMax = 64

// singleProviders reads a single-exit panel's PROVIDERS the way the exit
// does (internal/exit's parseProviders): set, the exit is a multi-provider
// exit, refused with EXIT_KIND=sidecar or TUNNEL_BACKEND=gluetun, with
// PROVIDER required and one of them. Empty is unset, as Compose passes it.
func singleProviders(env map[string]string, multiAvailable bool) ([]string, error) {
	list := env["PROVIDERS"]
	if list == "" {
		return nil, nil
	}
	if !multiAvailable {
		return nil, errors.New("PROVIDERS is set, but " + multiProviderUnavailable)
	}
	if env["TUNNEL_BACKEND"] == "gluetun" {
		return nil, errors.New("PROVIDERS needs TUNNEL_BACKEND=native: a gluetun exit carries one provider")
	}
	if kind := env["EXIT_KIND"]; kind != "" && kind != "overlay" {
		return nil, errors.New("PROVIDERS is for the overlay exit (EXIT_KIND=overlay); a sidecar carries one provider")
	}
	bad := errors.New("PROVIDERS must be two or three of mullvad, pia and nordvpn, comma-separated, each once")
	if len(list) > providersEnvMax {
		return nil, bad
	}
	ids, err := parseProviderSet(strings.Split(list, ","))
	if err != nil {
		var native *nativeOnly
		if errors.As(err, &native) {
			return nil, errors.New("PROVIDERS takes native providers only (mullvad, pia, nordvpn), not " + native.id)
		}
		return nil, bad
	}
	switch provider := env["PROVIDER"]; {
	case provider == "":
		return nil, errors.New("PROVIDER is required with PROVIDERS: the provider the tunnel starts on the first time")
	case !slices.Contains(ids, provider):
		return nil, errors.New("PROVIDER must be one of PROVIDERS")
	}
	return ids, nil
}

// joinPath is Path(a) / b without cleaning a: STATE_DIR is used as given.
func joinPath(dir, name string) string {
	return strings.TrimRight(dir, "/") + "/" + name
}

// Config is everything the panel reads from its environment.
type Config struct {
	Settings *Settings
	StateDir string
	// Exits is PANEL_EXITS; empty means a single-exit panel, described by
	// Single.
	Exits  []Exit
	Single Exit
}

// ConfigFromEnv reads and checks the panel's settings: every PANEL_*
// variable, STATE_DIR, PROVIDER, EXIT_KIND and PANEL_EXITS, with the
// defaults and refusals app.py had. An error stops the panel at start.
func ConfigFromEnv(env map[string]string) (*Config, error) {
	return configFromEnv(env, buildgate.MultiProvider)
}

// configFromEnv is ConfigFromEnv with multi-provider exits switched on or
// off.
func configFromEnv(env map[string]string, multiAvailable bool) (*Config, error) {
	getenv := func(name string) string { return env[name] }
	provider, err := state.ProviderFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	stateDir := envDefault(env, "STATE_DIR", "/state")
	exits, err := parseExits(env["PANEL_EXITS"], stateDir, multiAvailable)
	if err != nil {
		return nil, err
	}
	// A single-exit panel's kind, as its applier's EXIT_KIND. PANEL_EXITS
	// names each exit's kind itself, and this is then unused.
	exitKind := envOr(env, "EXIT_KIND", "overlay")
	if len(exits) == 0 {
		// Refuses an unknown kind at start.
		if _, err := verdict.NewExitConfig(provider, exitKind, ""); err != nil {
			return nil, err
		}
	}
	spec, _ := providers.Lookup(provider)
	single := ExitUnder("", provider, spec.Label, stateDir, exitKind)
	if len(exits) == 0 {
		set, err := singleProviders(env, multiAvailable)
		if err != nil {
			return nil, err
		}
		if set != nil {
			// PROVIDER is the provider the exit starts on, one of the set.
			single.Providers = set
			single.Label = setLabel(set)
		}
	}

	settings := presentation(env)
	ids := make([]string, len(exits))
	for i, e := range exits {
		ids[i] = e.ID
	}
	auth, err := oidc.ConfigFromEnv(env, ids)
	if err != nil {
		return nil, err
	}
	settings.Auth = auth
	var signIn *hostPort
	if auth != nil {
		host, port := auth.PublicHost()
		if port == 0 {
			port = -1
		}
		signIn = &hostPort{host, port}
	}
	settings.PublicHosts, err = parsePublicHosts(env["PANEL_PUBLIC_HOSTS"], signIn)
	if err != nil {
		return nil, err
	}
	if len(exits) == 0 && single.Provider == "" {
		return nil, errors.New("panel: no provider")
	}
	if err := markNetworkExits(env["PANEL_NETWORK_EXITS"], exits, stateDir); err != nil {
		return nil, err
	}
	if err := setProxyStatus(env["PANEL_PROXY_STATUS"], exits, &single); err != nil {
		return nil, err
	}
	return &Config{Settings: settings, StateDir: stateDir, Exits: exits, Single: single}, nil
}

// markNetworkExits reads PANEL_NETWORK_EXITS, the comma-separated ids of the
// exits reached through the network exchange; each must be in PANEL_EXITS.
func markNetworkExits(raw string, exits []Exit, stateDir string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	for _, id := range strings.Split(raw, ",") {
		id = strings.TrimSpace(id)
		found := false
		for i := range exits {
			if exits[i].ID == id {
				if exits[i].Multi() {
					// The exchange carries one provider's requests and
					// catalogue; the exit refuses EXCHANGE_URL with PROVIDERS.
					return fmt.Errorf("PANEL_NETWORK_EXITS: %s is a multi-provider exit, which the network exchange does not carry", pystr.Repr(id))
				}
				exits[i].Network = true
				exits[i].LinkPath = filepath.Join(stateDir, id, exchange.LinkFile)
				found = true
			}
		}
		if !found {
			return fmt.Errorf("PANEL_NETWORK_EXITS: %s is not an exit in PANEL_EXITS", pystr.Repr(id))
		}
	}
	return nil
}

// setProxyStatus reads PANEL_PROXY_STATUS, the proxy status files the panel
// shows beside their exits: for a single-exit panel the absolute path of
// proxy.json, and with PANEL_EXITS comma-separated `id=path` entries. Only an
// exit of a native provider has a proxy, and an exit reached through the
// network exchange cannot: the exchange does not carry proxy.json.
func setProxyStatus(raw string, exits []Exit, single *Exit) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	native := func(id, provider string) error {
		if verdict.BackendOf(provider) != providers.BackendNative {
			return fmt.Errorf("PANEL_PROXY_STATUS: the proxy runs only beside an exit of a native provider (mullvad, pia, nordvpn), and %s is %s", id, pystr.Repr(provider))
		}
		return nil
	}
	if len(exits) == 0 {
		path := pystr.Strip(raw)
		if !proxyPathOK(path) {
			return fmt.Errorf("PANEL_PROXY_STATUS: the path of proxy.json must be absolute and clean, in %s", pystr.Repr(path))
		}
		if err := native("this exit", single.Provider); err != nil {
			return err
		}
		if single.Multi() {
			return errors.New("PANEL_PROXY_STATUS: this is a multi-provider exit; " + proxyMultiReason)
		}
		single.ProxyPath = path
		return nil
	}
	seen := map[string]bool{}
	for _, piece := range strings.Split(raw, ",") {
		entry := pystr.Strip(piece)
		if entry == "" {
			continue
		}
		id, path, sep := strings.Cut(entry, "=")
		id, path = pystr.Strip(id), pystr.Strip(path)
		if !sep || !proxyPathOK(path) {
			return fmt.Errorf("PANEL_PROXY_STATUS: with PANEL_EXITS, entries are id=/absolute/path/proxy.json, in %s", pystr.Repr(entry))
		}
		if seen[id] {
			return fmt.Errorf("PANEL_PROXY_STATUS: duplicate exit id %s", pystr.Repr(id))
		}
		seen[id] = true
		found := false
		for i := range exits {
			if exits[i].ID != id {
				continue
			}
			found = true
			if err := native(pystr.Repr(id), exits[i].Provider); err != nil {
				return err
			}
			if exits[i].Multi() {
				return fmt.Errorf("PANEL_PROXY_STATUS: %s is a multi-provider exit; %s", pystr.Repr(id), proxyMultiReason)
			}
			if exits[i].Network {
				return fmt.Errorf("PANEL_PROXY_STATUS: %s is reached through the network exchange, which does not carry proxy.json", pystr.Repr(id))
			}
			exits[i].ProxyPath = path
		}
		if !found {
			return fmt.Errorf("PANEL_PROXY_STATUS: %s is not an exit in PANEL_EXITS", pystr.Repr(id))
		}
	}
	return nil
}

// proxyMultiReason is why a multi-provider exit has no proxy: the proxy
// refuses PROVIDERS at start, since its provider would be wrong after a
// switch.
const proxyMultiReason = "the proxy does not run beside one"

// proxyPathOK: an absolute, clean path of printable characters.
func proxyPathOK(path string) bool {
	return strings.HasPrefix(path, "/") && filepath.Clean(path) == path && path != "/" &&
		len(path) <= 4096 && pystr.IsPrintable(path)
}
