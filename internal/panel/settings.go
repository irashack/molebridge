package panel

import (
	"regexp"

	"github.com/irashack/molebridge/internal/panel/oidc"
	"github.com/irashack/molebridge/internal/panel/pystr"
)

// Settings are the panel's process-lifetime configuration, read once from
// the environment. Presentation settings never affect switching.
type Settings struct {
	Title      string // PANEL_TITLE
	ShortTitle string // PANEL_SHORT_TITLE
	HostLabel  string // PANEL_HOST_LABEL
	HomeURL    string // PANEL_HOME_URL
	HomeLabel  string // PANEL_HOME_LABEL
	Theme      string // PANEL_THEME: auto, dark or light
	Style      string // PANEL_STYLE: provider or dashboard

	// FrameAncestors are the https origins allowed to frame the panel.
	FrameAncestors []string
	// PublicHosts are the names the panel may be asked for (PANEL_PUBLIC_HOSTS
	// and the sign-in public URL's host); loopback is always allowed.
	PublicHosts []hostPort

	// Auth is nil without PANEL_OIDC_ISSUER: the panel has no login.
	Auth *oidc.Config
}

// themeSetting: auto follows the viewer's system setting; anything
// unrecognised is auto.
func themeSetting(value string) string {
	switch value {
	case "auto", "dark", "light":
		return value
	}
	return "auto"
}

// styleSetting: provider dresses each exit in its provider's colours;
// dashboard keeps one neutral palette that matches Glance-family dashboards.
func styleSetting(value string) string {
	switch value {
	case "provider", "dashboard":
		return value
	}
	return "provider"
}

var frameAncestorRE = regexp.MustCompile(`^https://[a-z0-9.-]+$`)

// frameAncestors parses PANEL_FRAME_ANCESTORS: whitespace-separated origins,
// of which only https origins are kept.
func frameAncestors(raw string) []string {
	var out []string
	for _, origin := range pystr.Fields(raw) {
		if origin = pystr.Strip(origin); frameAncestorRE.MatchString(origin) {
			out = append(out, origin)
		}
	}
	return out
}

// envOr is os.environ.get(name) or fallback: an unset or empty value takes
// the fallback.
func envOr(env map[string]string, name, fallback string) string {
	if v := env[name]; v != "" {
		return v
	}
	return fallback
}

// envDefault is os.environ.get(name, fallback): only an unset value takes
// the fallback.
func envDefault(env map[string]string, name, fallback string) string {
	if v, ok := env[name]; ok {
		return v
	}
	return fallback
}

// presentation reads the settings that do not depend on the exits.
func presentation(env map[string]string) *Settings {
	return &Settings{
		Title:          envOr(env, "PANEL_TITLE", "Switchyard"),
		ShortTitle:     envOr(env, "PANEL_SHORT_TITLE", "Switchyard"),
		HostLabel:      envDefault(env, "PANEL_HOST_LABEL", "this exit"),
		HomeURL:        envDefault(env, "PANEL_HOME_URL", ""),
		HomeLabel:      envDefault(env, "PANEL_HOME_LABEL", "Home"),
		Theme:          themeSetting(envDefault(env, "PANEL_THEME", "auto")),
		Style:          styleSetting(envDefault(env, "PANEL_STYLE", "provider")),
		FrameAncestors: frameAncestors(env["PANEL_FRAME_ANCESTORS"]),
	}
}
