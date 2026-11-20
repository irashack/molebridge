// Package initmenu is the init role: the menu of ways in
// (docs/design/menu.md#the-menu). It asks for a provider, the ways in and the
// extras on a terminal, or reads the same answers from a file, refuses the
// combinations that don't exist, and writes a Compose file and an .env built
// from the shipped Compose forms' services, settings and image pins. It
// writes EXIT_KIND and TUNNEL_BACKEND exactly as the shipped forms do and
// changes nothing about what they mean.
package initmenu

import (
	"bufio"
	"bytes"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/tools/privfile"
	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/routing"
)

// The ways in and the extras, as the answers file and the prompts name them.
const (
	WayNetBird      = "netbird-exit"
	WaySidecar      = "sidecar"
	WayProxy        = "proxy"
	ExtraSwitchyard = "switchyard"
	ExtraPortSync   = "port-sync"
)

// Ways and Extras list the names in the order init writes and prints them.
var (
	Ways   = []string{WayNetBird, WaySidecar, WayProxy}
	Extras = []string{ExtraSwitchyard, ExtraPortSync}
)

// The forms: which shipped Compose file a plan's services come from.
const (
	FormOverlay        = "overlay"         // compose.yaml
	FormGluetunOverlay = "gluetun-overlay" // compose.gluetun.yaml
	FormGluetunSidecar = "gluetun-sidecar" // compose.sidecar.yaml
	FormNativeSidecar  = "native-sidecar"  // compose.native-sidecar.yaml
)

// SourceFile names the shipped Compose file of each form.
var SourceFile = map[string]string{
	FormOverlay:        "compose.yaml",
	FormGluetunOverlay: "compose.gluetun.yaml",
	FormGluetunSidecar: "compose.sidecar.yaml",
	FormNativeSidecar:  "compose.native-sidecar.yaml",
}

// project is each form's Compose project name, as its shipped file has it.
var project = map[string]string{
	FormOverlay:        "molebridge",
	FormGluetunOverlay: "molebridge",
	FormGluetunSidecar: "molebridge-sidecar",
	FormNativeSidecar:  "molebridge-native-sidecar",
}

// MaxAnswers bounds the answers file.
const MaxAnswers = 4096

// maxLine bounds one answer typed on the terminal.
const maxLine = 1024

// The output files, relative to --out.
const (
	ComposeFile   = "compose.yaml"
	EnvFile       = ".env"
	PreflightFile = "routing/gluetun-preflight"
)

//go:embed compose.tmpl env.tmpl
var templateFS embed.FS

var (
	composeT = template.Must(template.New("compose.tmpl").Option("missingkey=error").ParseFS(templateFS, "compose.tmpl"))
	envT     = template.Must(template.New("env.tmpl").Option("missingkey=error").ParseFS(templateFS, "env.tmpl"))
)

// Answers are the choices, from the terminal or the answers file.
type Answers struct {
	// Provider is one provider, or, for a multi-provider exit, two or three
	// native providers comma-separated ("mullvad,nordvpn"), the first being
	// the one the tunnel starts on.
	Provider string
	WaysIn   []string
	Extras   []string
}

// Plan is a combination init can write.
type Plan struct {
	Answers
	Form            string
	GluetunProvider string // gluetun's own id for a gluetun-<id> provider
	// Providers is set on a multi-provider exit only: the providers in the
	// order given, PROVIDER the first (docs/design/multi-provider.md).
	Providers  []string
	Proxy      bool
	Switchyard bool
	PortSync   bool
	// Images, when set, replace compose.tmpl's Molebridge pins.
	Images Images
}

// Refusal is an answer or combination init refuses, with a message for the
// person who gave it.
type Refusal string

func (r Refusal) Error() string { return string(r) }

func refuse(format string, a ...any) error { return Refusal(fmt.Sprintf(format, a...)) }

// usage is the line a wrong argument prints.
const usage = "usage: molebridge init --out DIR [--answers FILE] [--image REF --core-image REF] [--force]"

// helpText is the usage text.
const helpText = `Usage: molebridge init --out DIR [--answers FILE] [--image REF --core-image REF] [--force]

EXPERIMENTAL. Asks for the provider, the ways in and the extras, or reads
the same answers from FILE, and writes DIR/compose.yaml and DIR/.env (and,
for a gluetun provider, DIR/routing/gluetun-preflight). The services,
settings and image pins are those of the Compose files in the source this
binary was built from. It never overwrites a file unless --force is given.

  provider   mullvad, pia, nordvpn, or gluetun-<id> for a provider gluetun
             drives (gluetun-fastestvpn, gluetun-ivpn, gluetun-mullvad,
             gluetun-nordvpn, gluetun-surfshark, gluetun-windscribe)
             or, for a multi-provider NetBird exit (experimental), two or
             three of mullvad, pia, nordvpn, comma-separated, the first
             being where the tunnel starts: "mullvad,nordvpn"
  ways in    one or more of netbird-exit, sidecar, proxy (the proxy: with
             a native provider, on top of netbird-exit or sidecar)
  extras     none, or switchyard, port-sync (port-sync: PIA with sidecar)

The answers file is JSON, at most 4096 bytes, with exactly these members
(extras may be left out):

  {"schema": 1, "provider": "pia", "ways_in": ["sidecar"],
   "extras": ["switchyard", "port-sync"]}

The source a release is built from pins the release before it, so the
Molebridge pins init writes may be an older release's. Give the two images
you verified, and every Molebridge image init writes is one of them:

  --image REF       ghcr.io/irashack/molebridge:<tag>@sha256:<digest>
  --core-image REF  ghcr.io/irashack/molebridge-core:<tag>@sha256:<digest>

Both or neither, with the same tag (vX.Y.Z or vX.Y.Z-rc.N) and each with
its index digest (64 lowercase hex digits). The answers file may give them
instead, as "image" and "core_image"; if both give them, they must match.

docs/setup.md#molebridge-init says what to do with the result.
`

// gluetunIDs lists gluetun-<id> for every provider init offers through gluetun.
func gluetunIDs() []string {
	var out []string
	for _, name := range providers.GluetunSupportedProviders {
		out = append(out, "gluetun-"+name)
	}
	return out
}

// providerChoices is the list printed in a refusal and a prompt.
func providerChoices() string {
	return strings.Join(providers.Native(), ", ") + ", or one of " + strings.Join(gluetunIDs(), ", ")
}

// providerPrompt is the first question.
func providerPrompt() string {
	return "Provider (" + providerChoices() + "; or, for a NetBird exit that switches between them, " +
		"two or three of " + strings.Join(providers.Native(), ", ") + ", comma-separated): "
}

// Plan checks the answers and returns the combination to write, or a
// Refusal saying why it doesn't exist.
func (a Answers) Plan() (Plan, error) {
	p := Plan{Answers: a}
	if strings.Contains(a.Provider, ",") {
		return a.planMulti()
	}
	prov, ok := providers.Lookup(a.Provider)
	if !ok {
		if name, gluetun := strings.CutPrefix(a.Provider, "gluetun-"); gluetun {
			if why, rejected := providers.GluetunRejectedProviders[name]; rejected {
				return p, refuse("provider %s is not offered: %s.", a.Provider, why)
			}
		}
		return p, refuse("provider %q is not one Molebridge knows: choose %s.", a.Provider, providerChoices())
	}
	native := prov.Backend == providers.BackendNative
	if err := checkNames("way in", a.WaysIn, Ways); err != nil {
		return p, err
	}
	if err := checkNames("extra", a.Extras, Extras); err != nil {
		return p, err
	}
	if len(a.WaysIn) == 0 {
		return p, refuse("choose at least one way in: %s.", strings.Join(Ways, ", "))
	}
	netbird := slices.Contains(a.WaysIn, WayNetBird)
	sidecar := slices.Contains(a.WaysIn, WaySidecar)
	p.Proxy = slices.Contains(a.WaysIn, WayProxy)
	p.Switchyard = slices.Contains(a.Extras, ExtraSwitchyard)
	p.PortSync = slices.Contains(a.Extras, ExtraPortSync)
	switch {
	case netbird && sidecar:
		return p, refuse("netbird-exit and sidecar can't share one exit: the NetBird exit is " +
			"EXIT_KIND=overlay and the sidecar EXIT_KIND=sidecar, and init writes one exit. " +
			"Choose one of them; the other needs a Compose project of its own.")
	case p.Proxy && !native:
		return p, refuse("the proxy needs a native provider (%s): it runs in the namespace of "+
			"a tunnel Molebridge brings up itself, and with %s the tunnel is gluetun's.",
			strings.Join(providers.Native(), ", "), a.Provider)
	case p.Proxy && !netbird && !sidecar:
		return p, refuse("the proxy runs in the network namespace of a native exit: choose " +
			"netbird-exit or sidecar with it.")
	case p.PortSync && a.Provider != "pia":
		return p, refuse("port-sync follows PIA's forwarded port: it needs provider pia, not %s.", a.Provider)
	case p.PortSync && !sidecar:
		return p, refuse("port-sync runs in the native sidecar's namespace, beside your " +
			"qBittorrent: it needs the sidecar way in.")
	}
	switch {
	case native && netbird:
		p.Form = FormOverlay
	case native:
		p.Form = FormNativeSidecar
	case netbird:
		p.Form = FormGluetunOverlay
	default:
		p.Form = FormGluetunSidecar
	}
	if !native {
		p.GluetunProvider = prov.GluetunProvider
	}
	return p, nil
}

// planMulti checks a multi-provider exit: two or three native providers, a
// NetBird exit, and no sidecar, proxy or port-sync, as the exit's own
// settings require (docs/design/multi-provider.md#settings-files-and-credentials).
func (a Answers) planMulti() (Plan, error) {
	p := Plan{Answers: a}
	native := providers.Native()
	names := strings.Split(a.Provider, ",")
	for i, name := range names {
		names[i] = strings.TrimSpace(name)
		if names[i] == "" {
			return p, refuse("provider %q has an empty name in it.", a.Provider)
		}
	}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			return p, refuse("provider %s is listed twice.", name)
		}
		seen[name] = true
		if slices.Contains(native, name) {
			continue
		}
		if _, ok := providers.Lookup(name); ok {
			return p, refuse("a multi-provider exit takes only providers Molebridge drives itself (%s): "+
				"with %s the tunnel is gluetun's, and gluetun runs one provider.", strings.Join(native, ", "), name)
		}
		return p, refuse("provider %q is not one Molebridge knows: a multi-provider exit takes two or three of %s.",
			name, strings.Join(native, ", "))
	}
	if len(names) > 3 {
		return p, refuse("a multi-provider exit takes two or three providers, not %d.", len(names))
	}
	if err := checkNames("way in", a.WaysIn, Ways); err != nil {
		return p, err
	}
	if err := checkNames("extra", a.Extras, Extras); err != nil {
		return p, err
	}
	if len(a.WaysIn) == 0 {
		return p, refuse("choose at least one way in: %s.", strings.Join(Ways, ", "))
	}
	switch {
	case slices.Contains(a.WaysIn, WaySidecar):
		return p, refuse("a multi-provider exit is a NetBird exit only: the sidecar runs one provider " +
			"(the exit refuses PROVIDERS with EXIT_KIND=sidecar). Choose netbird-exit, or one provider for the sidecar.")
	case slices.Contains(a.WaysIn, WayProxy):
		return p, refuse("the proxy can't run on a multi-provider exit: it serves one provider's tunnel " +
			"and refuses to start with PROVIDERS set. Leave the proxy out, or choose one provider.")
	case slices.Contains(a.Extras, ExtraPortSync):
		return p, refuse("port-sync runs in the native sidecar's namespace, beside your " +
			"qBittorrent: it needs the sidecar way in, which a multi-provider exit doesn't have.")
	}
	p.Providers = names
	p.Switchyard = slices.Contains(a.Extras, ExtraSwitchyard)
	p.Form = FormOverlay
	return p, nil
}

// Multi reports whether the plan is a multi-provider exit.
func (p Plan) Multi() bool { return len(p.Providers) > 1 }

func checkNames(kind string, got, known []string) error {
	seen := map[string]bool{}
	for _, name := range got {
		if !slices.Contains(known, name) {
			return refuse("%q is not a %s: choose from %s.", name, kind, strings.Join(known, ", "))
		}
		if seen[name] {
			return refuse("%s is listed twice.", name)
		}
		seen[name] = true
	}
	return nil
}

// ParseAnswers reads an answers file: ParseAnswersFile without the images.
func ParseAnswers(raw []byte) (Answers, error) {
	a, _, err := ParseAnswersFile(raw)
	return a, err
}

// ParseAnswersFile reads an answers file: one JSON object with "schema": 1,
// "provider", "ways_in", optionally "extras", and optionally both of "image"
// and "core_image", nothing else. Duplicate keys, unknown members, wrong
// types and image references ParseImages refuses are refused.
func ParseAnswersFile(raw []byte) (Answers, Images, error) {
	a, obj, err := parseAnswers(raw)
	if err != nil {
		return a, Images{}, err
	}
	var refs [2]*string
	for i, key := range []string{"image", "core_image"} {
		v, present := obj[key]
		if !present {
			continue
		}
		s, ok := v.(string)
		if !ok {
			return a, Images{}, refuse("the answers file's %s must be a string.", key)
		}
		refs[i] = &s
	}
	img, err := ParseImages("the answers file's image", refs[0], "the answers file's core_image", refs[1])
	return a, img, err
}

func parseAnswers(raw []byte) (Answers, map[string]any, error) {
	var a Answers
	if len(raw) > MaxAnswers {
		return a, nil, refuse("the answers file is larger than %d bytes.", MaxAnswers)
	}
	v, err := validate.DecodeJSON(raw)
	if err != nil {
		return a, nil, refuse("the answers file is not valid JSON: %v.", err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return a, nil, refuse("the answers file must hold one JSON object.")
	}
	for key := range obj {
		if !slices.Contains([]string{"schema", "provider", "ways_in", "extras", "image", "core_image"}, key) {
			return a, nil, refuse("the answers file has an unknown member %q: only schema, provider, ways_in, extras, image and core_image.", key)
		}
	}
	if n, ok := validate.IsInt(obj["schema"]); !ok || n != 1 {
		return a, nil, refuse(`the answers file must say "schema": 1.`)
	}
	s, ok := obj["provider"].(string)
	if !ok || s == "" || len(s) > 64 {
		return a, nil, refuse("the answers file's provider must be a name such as \"mullvad\".")
	}
	a.Provider = s
	if a.WaysIn, err = stringList(obj, "ways_in", true); err != nil {
		return a, nil, err
	}
	if a.Extras, err = stringList(obj, "extras", false); err != nil {
		return a, nil, err
	}
	return a, obj, nil
}

// The repositories of the two Molebridge images.
const (
	MolebridgeRepo = "ghcr.io/irashack/molebridge"
	CoreRepo       = "ghcr.io/irashack/molebridge-core"
)

// Images are the two Molebridge images init writes in place of compose.tmpl's
// pins: both of one release, each by tag and index digest.
type Images struct {
	Molebridge string // ghcr.io/irashack/molebridge:<tag>@sha256:<digest>
	Core       string // ghcr.io/irashack/molebridge-core:<tag>@sha256:<digest>
	Tag        string // their tag
}

var (
	releaseTagRE = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$`)
	digestRE     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	// molebridgePinRE matches a Compose image line that pins either
	// Molebridge image; group 1 is everything before the reference.
	molebridgePinRE = regexp.MustCompile(`(?m)^(\s+image: )ghcr\.io/irashack/molebridge(-core)?:([A-Za-z0-9._-]+)@sha256:[0-9a-f]{64}$`)
)

// checkImage returns the tag of ref, which must be exactly
// repo:<tag>@sha256:<64 lowercase hex digits>, or a Refusal saying what is
// wrong with it. what names where ref came from.
func checkImage(what, ref, repo string) (string, error) {
	if ref == "" {
		return "", refuse("%s is empty: give %s:<tag>@sha256:<digest>.", what, repo)
	}
	bad := func(format string, a ...any) error {
		return refuse("%s %q is not %s:<tag>@sha256:<digest>: %s.", what, ref, repo, fmt.Sprintf(format, a...))
	}
	for _, r := range ref {
		if r <= ' ' || r >= 0x7f {
			return "", bad("it holds a space, a control character or a non-ASCII character")
		}
	}
	name, digest, hasDigest := strings.Cut(ref, "@")
	gotRepo, tag, hasTag := name, "", false
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		gotRepo, tag, hasTag = name[:i], name[i+1:], true
	}
	switch {
	case gotRepo != repo:
		return "", bad("the repository is %s, not %s", gotRepo, repo)
	case !hasTag || tag == "":
		return "", bad("it has no tag; give the release's tag, such as v0.14.1, before the digest")
	case !releaseTagRE.MatchString(tag):
		return "", bad("the tag %s is not a release tag such as v0.14.1 or a candidate tag such as v0.14.1-rc.1", tag)
	case !hasDigest:
		return "", bad("it has no digest; init needs the index digest from the release notes, not a tag alone")
	case !digestRE.MatchString(digest):
		return "", bad("the digest must be sha256: and 64 lowercase hexadecimal digits")
	}
	return tag, nil
}

// ParseImages checks a pair of image references, the Molebridge image and
// the core image; nil is a reference not given. Neither gives no Images;
// both must be valid and have one tag.
func ParseImages(whatImage string, image *string, whatCore string, core *string) (Images, error) {
	if image == nil && core == nil {
		return Images{}, nil
	}
	if image == nil || core == nil {
		return Images{}, refuse("%s and %s go together: give both, the two images of one release.", whatImage, whatCore)
	}
	tag, err := checkImage(whatImage, *image, MolebridgeRepo)
	if err != nil {
		return Images{}, err
	}
	coreTag, err := checkImage(whatCore, *core, CoreRepo)
	if err != nil {
		return Images{}, err
	}
	if tag != coreTag {
		return Images{}, refuse("%s has tag %s but %s has tag %s: give the two images of one release.", whatImage, tag, whatCore, coreTag)
	}
	return Images{Molebridge: *image, Core: *core, Tag: tag}, nil
}

// PinnedTag is the tag compose.tmpl pins the Molebridge images at.
func PinnedTag() string {
	raw, _ := templateFS.ReadFile("compose.tmpl")
	if m := molebridgePinRE.FindSubmatch(raw); m != nil {
		return string(m[3])
	}
	return ""
}

// pinsNotice is what init says on stderr when it wrote compose.tmpl's pins.
// version is the binary's own (`molebridge version`); when it is a release
// or candidate tag of another release than the pins', the line says so.
func pinsNotice(version, pinned string) string {
	line := "molebridge init: compose.yaml pins the Molebridge images at " + pinned +
		", the pins of the source this binary was built from"
	release, _, rc := strings.Cut(version, "-rc.")
	if releaseTagRE.MatchString(version) && release != pinned {
		this := release
		if rc {
			this += " (built as " + version + ")"
		}
		line += ": this is " + this + "; the pins are " + pinned + "'s."
	} else {
		line += ", possibly an older release."
	}
	return line + " To pin the release you verified, pass --image and --core-image (docs/setup.md#molebridge-init)."
}

func stringList(obj map[string]any, key string, required bool) ([]string, error) {
	v, present := obj[key]
	if !present {
		if required {
			return nil, refuse("the answers file needs %s, a list of names.", key)
		}
		return []string{}, nil
	}
	list, ok := v.([]any)
	if !ok || len(list) > 8 {
		return nil, refuse("the answers file's %s must be a list of at most 8 names.", key)
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok || s == "" || len(s) > 64 {
			return nil, refuse("the answers file's %s must hold only names.", key)
		}
		out = append(out, s)
	}
	return out, nil
}

// services lists the services of a plan, in the order they are written.
func (p Plan) services() []string {
	var out []string
	switch p.Form {
	case FormOverlay:
		out = []string{"exit"}
	case FormGluetunOverlay:
		out = []string{"gluetun", "exit"}
	case FormGluetunSidecar:
		out = []string{"gluetun", "exit", "example-app"}
	case FormNativeSidecar:
		out = []string{"exit", "example-app"}
		if p.PortSync {
			out = append(out, "port-sync")
		}
	}
	if p.Switchyard {
		out = append(out, "switchyard")
	}
	return out
}

// Services lists the names of the services the plan writes, the proxy
// included.
func (p Plan) Services() []string {
	out := p.services()
	if p.Proxy {
		out = append(out, "proxy")
	}
	return out
}

// envData is what the templates see.
type envData struct {
	Plan
	Project         string
	DefaultProvider string
	PanelHosts      string
	PanelExits      bool
	// Start is PROVIDER: the provider, or a multi-provider exit's first.
	Start string
	// ProviderList is PROVIDERS, on a multi-provider exit.
	ProviderList string
	// PIA is set when pia is the provider or one of them.
	PIA bool
}

func (p Plan) data() envData {
	d := envData{Plan: p, Project: project[p.Form], Start: p.Provider, PIA: p.Provider == "pia"}
	if p.Multi() {
		d.Start, d.ProviderList = p.Providers[0], strings.Join(p.Providers, ",")
		d.PIA = slices.Contains(p.Providers, "pia")
	}
	switch p.Form {
	case FormOverlay:
		d.DefaultProvider, d.PanelHosts, d.PanelExits = "mullvad", "exit.example.net", true
	case FormGluetunOverlay:
		d.PanelHosts = "exit.example.net"
	case FormNativeSidecar:
		d.DefaultProvider = "pia"
	}
	return d
}

// Block renders one service block of compose.tmpl, as init writes it.
func Block(name string, p Plan) (string, error) {
	var b bytes.Buffer
	if err := composeT.ExecuteTemplate(&b, name, p.data()); err != nil {
		return "", err
	}
	return strings.TrimPrefix(b.String(), "\n"), nil
}

func joinOrNone(list []string) string {
	if len(list) == 0 {
		return "none"
	}
	return strings.Join(list, ", ")
}

// Render returns the files of a plan, by their path under --out.
func Render(p Plan) (map[string][]byte, error) {
	var c bytes.Buffer
	provider, multi := p.Provider, ""
	if p.Multi() {
		provider = strings.Join(p.Providers, ", ") + " (a multi-provider exit)"
		multi = `# The exit differs from it in two things: it passes PROVIDERS, and it
# mounts one tunnel config per provider instead of the tunnel/wg_confs
# directory (docs/configuration.md#multi-provider-exit; experimental).
`
	}
	if p.Images.Tag != "" {
		multi += `# The Molebridge images are not that file's pins: they are the ` + p.Images.Tag + `
# images init was given (--image and --core-image, or the answers file).
`
	}
	fmt.Fprintf(&c, `# Written by `+"`molebridge init`"+` (experimental, docs/setup.md#molebridge-init).
#   provider: %s
#   ways in:  %s
#   extras:   %s
# The services are those of %s in the Molebridge source
# of the same release, with its settings and image pins; that file's
# comments say more.
%s# Your settings are in .env beside this file.
#
# Secrets live in the mode-0600 files under ./tunnel and ./secrets; never
# print them or paste `+"`docker compose config`"+` output anywhere.
name: %s

services:
`, provider, strings.Join(p.WaysIn, ", "), joinOrNone(p.Extras), SourceFile[p.Form], multi, project[p.Form])
	for i, svc := range p.services() {
		block, err := Block(p.Form+"/"+svc, p)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			c.WriteString("\n")
		}
		c.WriteString(block)
	}
	if p.Proxy {
		block, err := Block("proxy", p)
		if err != nil {
			return nil, err
		}
		c.WriteString("\n" + block)
	}
	if p.Switchyard {
		c.WriteString("\nnetworks:\n  panel:\n")
	}
	var volumes []string
	switch p.Form {
	case FormOverlay:
		volumes = []string{"netbird-data"}
	case FormGluetunOverlay:
		volumes = []string{"netbird-data", "gluetun-data", "gluetun-servers"}
	case FormGluetunSidecar:
		volumes = []string{"gluetun-data", "gluetun-servers"}
	}
	if len(volumes) > 0 {
		c.WriteString("\nvolumes:\n")
		for _, v := range volumes {
			fmt.Fprintf(&c, "  %s:\n", v)
		}
	}
	compose := c.Bytes()
	if p.Images.Tag != "" {
		compose = molebridgePinRE.ReplaceAllFunc(compose, func(line []byte) []byte {
			m := molebridgePinRE.FindSubmatch(line)
			if len(m[2]) > 0 {
				return append(append([]byte{}, m[1]...), p.Images.Core...)
			}
			return append(append([]byte{}, m[1]...), p.Images.Molebridge...)
		})
	}
	var e bytes.Buffer
	if err := envT.ExecuteTemplate(&e, p.Form, p.data()); err != nil {
		return nil, err
	}
	files := map[string][]byte{ComposeFile: compose, EnvFile: e.Bytes()}
	if p.GluetunProvider != "" {
		files[PreflightFile] = routing.GluetunPreflight
	}
	return files, nil
}

// fileMode is each output file's mode: the preflight is a script gluetun runs.
func fileMode(name string) os.FileMode {
	if name == PreflightFile {
		return 0o755
	}
	return 0o644
}

// Options are the role's streams and its test seams.
type Options struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	// Terminal reports whether Stdin is a terminal to ask on.
	Terminal func() bool
	// Version is the release the binary was built as (`molebridge
	// version`), for the line about the pins.
	Version string
}

// Defaults are the process's own streams.
func Defaults(stdin *os.File, stdout, stderr io.Writer) Options {
	return Options{Stdin: stdin, Stdout: stdout, Stderr: stderr, Terminal: func() bool {
		info, err := stdin.Stat()
		return err == nil && info.Mode()&os.ModeCharDevice != 0
	}}
}

// Main is the init role.
func Main(args []string, o Options) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := fs.String("out", "", "")
	answersPath := fs.String("answers", "", "")
	force := fs.Bool("force", false, "")
	image := fs.String("image", "", "")
	coreImage := fs.String("core-image", "", "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			io.WriteString(o.Stdout, helpText)
			return 0
		}
		fmt.Fprintf(o.Stderr, "molebridge init: %v\n", err)
		fmt.Fprintln(o.Stderr, usage)
		return 2
	}
	if fs.NArg() != 0 || *out == "" {
		fmt.Fprintln(o.Stderr, usage)
		return 2
	}
	var imageRef, coreRef *string
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "image":
			imageRef = image
		case "core-image":
			coreRef = coreImage
		}
	})
	images, err := ParseImages("--image", imageRef, "--core-image", coreRef)
	if err != nil {
		fmt.Fprintf(o.Stderr, "molebridge init: %v\n", err)
		return 2
	}
	var a Answers
	if *answersPath != "" {
		raw, err := readBounded(*answersPath)
		var fileImages Images
		if err == nil {
			a, fileImages, err = ParseAnswersFile(raw)
		}
		if err == nil && fileImages.Tag != "" {
			if images.Tag != "" && images != fileImages {
				err = refuse("--image and --core-image name other images than the answers file's image and core_image: give them in one place.")
			}
			images = fileImages
		}
		if err != nil {
			fmt.Fprintf(o.Stderr, "molebridge init: %v\n", err)
			return 1
		}
	} else {
		if o.Terminal == nil || !o.Terminal() {
			fmt.Fprintln(o.Stderr, "molebridge init: no terminal to ask on; pass --answers FILE (docs/setup.md#molebridge-init).")
			return 2
		}
		var err error
		if a, err = ask(o); err != nil {
			fmt.Fprintf(o.Stderr, "molebridge init: %v\n", err)
			return 1
		}
	}
	p, err := a.Plan()
	if err != nil {
		fmt.Fprintf(o.Stderr, "molebridge init: %v\n", err)
		return 1
	}
	p.Images = images
	files, err := Render(p)
	if err != nil {
		fmt.Fprintf(o.Stderr, "molebridge init: %v\n", err)
		return 1
	}
	if err := write(*out, files, *force); err != nil {
		fmt.Fprintf(o.Stderr, "molebridge init: %v\n", err)
		return 1
	}
	names := []string{ComposeFile, EnvFile}
	if _, ok := files[PreflightFile]; ok {
		names = append(names, PreflightFile)
	}
	for i, n := range names {
		names[i] = filepath.Join(*out, n)
	}
	fmt.Fprintf(o.Stdout, "Wrote %s: the services of %s with %s.\n", strings.Join(names, ", "),
		SourceFile[p.Form], strings.Join(p.Services(), ", "))
	fmt.Fprintln(o.Stdout, "Next: edit .env, then follow docs/setup.md#molebridge-init for the secrets and state directories.")
	if p.Multi() {
		confs := make([]string, len(p.Providers))
		for i, name := range p.Providers {
			confs[i] = "tunnel/wg_confs/" + name + ".conf"
		}
		fmt.Fprintf(o.Stdout, "This multi-provider exit needs a tunnel config for each provider: %s.\n", strings.Join(confs, ", "))
	}
	if images.Tag == "" {
		fmt.Fprintln(o.Stderr, pinsNotice(o.Version, PinnedTag()))
	}
	return 0
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, refuse("can't read the answers file: %v.", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxAnswers+1))
	if err != nil {
		return nil, refuse("can't read the answers file: %v.", err)
	}
	return raw, nil
}

// write checks every output path first, so a refusal writes nothing.
func write(dir string, files map[string][]byte, force bool) error {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return err
		case !info.Mode().IsRegular():
			return refuse("%s exists and is not a regular file; remove it first.", path)
		case !force:
			return refuse("%s exists; pass --force to replace it, or choose another --out.", path)
		}
	}
	for _, name := range names {
		if err := privfile.Write(filepath.Join(dir, name), files[name], fileMode(name)); err != nil {
			return err
		}
	}
	return nil
}

// ask puts the three questions on the terminal. An unknown name asks again,
// up to three times; whether the combination exists is Plan's to say.
func ask(o Options) (Answers, error) {
	in := bufio.NewReaderSize(o.Stdin, maxLine)
	var a Answers
	question := func(prompt string, check func(string) error) (string, error) {
		for range 3 {
			fmt.Fprint(o.Stdout, prompt)
			line, err := readLine(in)
			if err != nil {
				return "", err
			}
			if err := check(line); err != nil {
				fmt.Fprintln(o.Stdout, err)
				continue
			}
			return line, nil
		}
		return "", refuse("no usable answer after three tries.")
	}
	fmt.Fprintln(o.Stdout, "molebridge init (experimental): three questions, then a compose.yaml and an .env.")
	prov, err := question(providerPrompt(), func(s string) error {
		list := splitList(s)
		if len(list) == 0 {
			return refuse("choose a provider.")
		}
		for _, name := range list {
			if _, ok := providers.Lookup(name); !ok {
				return refuse("%q is not a provider init offers.", name)
			}
		}
		return nil
	})
	if err != nil {
		return a, err
	}
	a.Provider = strings.Join(splitList(prov), ",")
	ways, err := question("Ways in, comma-separated ("+strings.Join(Ways, ", ")+"): ", func(s string) error {
		list := splitList(s)
		if len(list) == 0 {
			return refuse("choose at least one way in.")
		}
		return checkNames("way in", list, Ways)
	})
	if err != nil {
		return a, err
	}
	a.WaysIn = splitList(ways)
	extras, err := question("Extras, comma-separated, or empty for none ("+strings.Join(Extras, ", ")+"): ", func(s string) error {
		return checkNames("extra", splitList(s), Extras)
	})
	if err != nil {
		return a, err
	}
	a.Extras = splitList(extras)
	return a, nil
}

func splitList(s string) []string {
	out := []string{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		out = append(out, strings.ToLower(part))
	}
	return out
}

// readLine reads one line of at most maxLine bytes, without its newline.
func readLine(in *bufio.Reader) (string, error) {
	line, err := in.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		return "", refuse("that answer is longer than %d bytes.", maxLine)
	case errors.Is(err, io.EOF) && len(line) == 0:
		return "", refuse("no answer: the input ended.")
	case err != nil && !errors.Is(err, io.EOF):
		return "", err
	}
	s := strings.TrimSpace(string(line))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return "", refuse("that answer holds a control character.")
		}
	}
	return s, nil
}
