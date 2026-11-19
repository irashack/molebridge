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
	Provider string
	WaysIn   []string
	Extras   []string
}

// Plan is a combination init can write.
type Plan struct {
	Answers
	Form            string
	GluetunProvider string // gluetun's own id for a gluetun-<id> provider
	Proxy           bool
	Switchyard      bool
	PortSync        bool
}

// Refusal is an answer or combination init refuses, with a message for the
// person who gave it.
type Refusal string

func (r Refusal) Error() string { return string(r) }

func refuse(format string, a ...any) error { return Refusal(fmt.Sprintf(format, a...)) }

// Help is the usage text.
const Help = `Usage: molebridge init --out DIR [--answers FILE] [--force]

EXPERIMENTAL. Asks for the provider, the ways in and the extras, or reads
the same answers from FILE, and writes DIR/compose.yaml and DIR/.env (and,
for a gluetun provider, DIR/routing/gluetun-preflight). The services,
settings and image pins are those of the Compose files shipped with this
release. It never overwrites a file unless --force is given.

  provider   mullvad, pia, nordvpn, or gluetun-<id> for a provider gluetun
             drives (gluetun-fastestvpn, gluetun-ivpn, gluetun-mullvad,
             gluetun-nordvpn, gluetun-surfshark, gluetun-windscribe)
  ways in    one or more of netbird-exit, sidecar, proxy
             (proxy: native providers only, beside netbird-exit or sidecar)
  extras     none, or switchyard, port-sync (port-sync: PIA with sidecar)

The answers file is JSON, at most 4096 bytes, with exactly these members
(extras may be left out):

  {"schema": 1, "provider": "pia", "ways_in": ["sidecar", "proxy"],
   "extras": ["switchyard", "port-sync"]}

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

// Plan checks the answers and returns the combination to write, or a
// Refusal saying why it doesn't exist.
func (a Answers) Plan() (Plan, error) {
	p := Plan{Answers: a}
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

// ParseAnswers reads an answers file: one JSON object with "schema": 1,
// "provider", "ways_in" and optionally "extras", nothing else. Duplicate
// keys, unknown members and wrong types are refused.
func ParseAnswers(raw []byte) (Answers, error) {
	var a Answers
	if len(raw) > MaxAnswers {
		return a, refuse("the answers file is larger than %d bytes.", MaxAnswers)
	}
	v, err := validate.DecodeJSON(raw)
	if err != nil {
		return a, refuse("the answers file is not valid JSON: %v.", err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return a, refuse("the answers file must hold one JSON object.")
	}
	for key := range obj {
		if !slices.Contains([]string{"schema", "provider", "ways_in", "extras"}, key) {
			return a, refuse("the answers file has an unknown member %q: only schema, provider, ways_in and extras.", key)
		}
	}
	if n, ok := validate.IsInt(obj["schema"]); !ok || n != 1 {
		return a, refuse(`the answers file must say "schema": 1.`)
	}
	s, ok := obj["provider"].(string)
	if !ok || s == "" || len(s) > 64 {
		return a, refuse("the answers file's provider must be a name such as \"mullvad\".")
	}
	a.Provider = s
	if a.WaysIn, err = stringList(obj, "ways_in", true); err != nil {
		return a, err
	}
	if a.Extras, err = stringList(obj, "extras", false); err != nil {
		return a, err
	}
	return a, nil
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
}

func (p Plan) data() envData {
	d := envData{Plan: p, Project: project[p.Form]}
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
	fmt.Fprintf(&c, `# Written by `+"`molebridge init`"+` (experimental, docs/setup.md#molebridge-init).
#   provider: %s
#   ways in:  %s
#   extras:   %s
# The services are those of %s in the Molebridge source
# of the same release, with its settings and image pins; that file's
# comments say more.
# Your settings are in .env beside this file.
#
# Secrets live in the mode-0600 files under ./tunnel and ./secrets; never
# print them or paste `+"`docker compose config`"+` output anywhere.
name: %s

services:
`, p.Provider, strings.Join(p.WaysIn, ", "), joinOrNone(p.Extras), SourceFile[p.Form], project[p.Form])
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
	var e bytes.Buffer
	if err := envT.ExecuteTemplate(&e, p.Form, p.data()); err != nil {
		return nil, err
	}
	files := map[string][]byte{ComposeFile: c.Bytes(), EnvFile: e.Bytes()}
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
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			io.WriteString(o.Stdout, Help)
			return 0
		}
		fmt.Fprintf(o.Stderr, "molebridge init: %v\n", err)
		fmt.Fprintln(o.Stderr, "usage: molebridge init --out DIR [--answers FILE] [--force]")
		return 2
	}
	if fs.NArg() != 0 || *out == "" {
		fmt.Fprintln(o.Stderr, "usage: molebridge init --out DIR [--answers FILE] [--force]")
		return 2
	}
	var a Answers
	if *answersPath != "" {
		raw, err := readBounded(*answersPath)
		if err == nil {
			a, err = ParseAnswers(raw)
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
	prov, err := question("Provider ("+providerChoices()+"): ", func(s string) error {
		if _, ok := providers.Lookup(strings.ToLower(s)); !ok {
			return refuse("%q is not a provider init offers.", s)
		}
		return nil
	})
	if err != nil {
		return a, err
	}
	a.Provider = strings.ToLower(prov)
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
