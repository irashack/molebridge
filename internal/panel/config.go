package panel

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/irashack/molebridge/internal/panel/oidc"
	"github.com/irashack/molebridge/internal/panel/pystr"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/verdict"
)

var exitIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ParseExits parses PANEL_EXITS: comma-separated `id=provider[/kind][:label]`,
// kind being overlay (the default) or sidecar (a gluetun provider's, or since
// 0.9.0 a native provider's: the native sidecar). Each exit's state is
// $STATE_DIR/<id>/panel and $STATE_DIR/<id>/applier. Empty means one exit
// whose state is $STATE_DIR itself (no exits are returned).
func ParseExits(raw, stateDir string) ([]Exit, error) {
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
		}
		if utf8.RuneCountInString(label) > 40 || !pystr.IsPrintable(label) {
			return nil, fmt.Errorf("PANEL_EXITS: labels are at most 40 printable characters, in %s", repr)
		}
		for _, e := range exits {
			if e.ID == exitID {
				return nil, fmt.Errorf("PANEL_EXITS: duplicate exit id %s", pystr.Repr(exitID))
			}
		}
		exits = append(exits, ExitUnder(exitID, provider, label, joinPath(stateDir, exitID), kind))
	}
	return exits, nil
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
	getenv := func(name string) string { return env[name] }
	provider, err := state.ProviderFromEnv(getenv)
	if err != nil {
		return nil, err
	}
	stateDir := envDefault(env, "STATE_DIR", "/state")
	exits, err := ParseExits(env["PANEL_EXITS"], stateDir)
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
	settings.PublicHosts = parsePublicHosts(env["PANEL_PUBLIC_HOSTS"], signIn)
	if len(exits) == 0 && single.Provider == "" {
		return nil, errors.New("panel: no provider")
	}
	return &Config{Settings: settings, StateDir: stateDir, Exits: exits, Single: single}, nil
}
