package initmenu

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/routing"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata/")

// root is the repository root, where the shipped Compose files are.
const root = "../../.."

func TestParseAnswers(t *testing.T) {
	a, err := ParseAnswers([]byte(`{"schema": 1, "provider": "pia", "ways_in": ["sidecar", "proxy"], "extras": ["port-sync"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.Provider != "pia" || !slices.Equal(a.WaysIn, []string{"sidecar", "proxy"}) || !slices.Equal(a.Extras, []string{"port-sync"}) {
		t.Fatalf("parsed %+v", a)
	}
	a, err = ParseAnswers([]byte(`{"schema":1,"provider":"mullvad","ways_in":["netbird-exit"]}`))
	if err != nil || a.Extras == nil || len(a.Extras) != 0 {
		t.Fatalf("extras left out: %+v %v", a, err)
	}
	for name, raw := range map[string]string{
		"not JSON":         `{"schema":1,`,
		"trailing data":    `{"schema":1,"provider":"pia","ways_in":["sidecar"]} {}`,
		"duplicate key":    `{"schema":1,"provider":"pia","provider":"mullvad","ways_in":["sidecar"]}`,
		"not an object":    `["pia"]`,
		"unknown member":   `{"schema":1,"provider":"pia","ways_in":["sidecar"],"server":"x"}`,
		"no schema":        `{"provider":"pia","ways_in":["sidecar"]}`,
		"schema 2":         `{"schema":2,"provider":"pia","ways_in":["sidecar"]}`,
		"schema as text":   `{"schema":"1","provider":"pia","ways_in":["sidecar"]}`,
		"schema as float":  `{"schema":1.0,"provider":"pia","ways_in":["sidecar"]}`,
		"no provider":      `{"schema":1,"ways_in":["sidecar"]}`,
		"empty provider":   `{"schema":1,"provider":"","ways_in":["sidecar"]}`,
		"provider number":  `{"schema":1,"provider":7,"ways_in":["sidecar"]}`,
		"no ways_in":       `{"schema":1,"provider":"pia"}`,
		"ways_in a string": `{"schema":1,"provider":"pia","ways_in":"sidecar"}`,
		"ways_in numbers":  `{"schema":1,"provider":"pia","ways_in":[1]}`,
		"extras null":      `{"schema":1,"provider":"pia","ways_in":["sidecar"],"extras":null}`,
		"empty name":       `{"schema":1,"provider":"pia","ways_in":[""]}`,
		"long list":        `{"schema":1,"provider":"pia","ways_in":["a","b","c","d","e","f","g","h","i"]}`,
		"invalid UTF-8":    "{\"schema\":1,\"provider\":\"pi\xff\",\"ways_in\":[\"sidecar\"]}",
		"too large":        `{"schema":1,"provider":"pia","ways_in":["sidecar"]}` + strings.Repeat(" ", MaxAnswers),
	} {
		if _, err := ParseAnswers([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		} else if _, ok := err.(Refusal); !ok {
			t.Errorf("%s: %T, not a Refusal", name, err)
		}
	}
}

func TestPlanRefusals(t *testing.T) {
	for _, c := range []struct {
		a    Answers
		want string
	}{
		{Answers{"expressvpn", []string{WayNetBird}, nil}, `provider "expressvpn" is not one Molebridge knows`},
		{Answers{"gluetun-airvpn", []string{WayNetBird}, nil}, "provider gluetun-airvpn is not offered: gluetun provider has no unique"},
		{Answers{"gluetun-custom", []string{WaySidecar}, nil}, "provider gluetun-custom is not offered"},
		{Answers{"mullvad", nil, nil}, "choose at least one way in"},
		{Answers{"mullvad", []string{"vpn"}, nil}, `"vpn" is not a way in`},
		{Answers{"mullvad", []string{WayNetBird, WayNetBird}, nil}, "netbird-exit is listed twice"},
		{Answers{"mullvad", []string{WayNetBird}, []string{"grafana"}}, `"grafana" is not a extra`},
		{Answers{"mullvad", []string{WayNetBird}, []string{ExtraSwitchyard, ExtraSwitchyard}}, "switchyard is listed twice"},
		{Answers{"mullvad", []string{WayNetBird, WaySidecar}, nil}, "netbird-exit and sidecar can't share one exit"},
		{Answers{"gluetun-nordvpn", []string{WayNetBird, WaySidecar}, nil}, "netbird-exit and sidecar can't share one exit"},
		{Answers{"gluetun-nordvpn", []string{WayNetBird, WayProxy}, nil}, "the proxy needs a native provider"},
		{Answers{"gluetun-mullvad", []string{WaySidecar, WayProxy}, nil}, "with gluetun-mullvad the tunnel is gluetun's"},
		{Answers{"mullvad", []string{WayProxy}, nil}, "the proxy runs in the network namespace of a native exit"},
		{Answers{"mullvad", []string{WaySidecar}, []string{ExtraPortSync}}, "port-sync follows PIA's forwarded port: it needs provider pia, not mullvad"},
		{Answers{"gluetun-nordvpn", []string{WaySidecar}, []string{ExtraPortSync}}, "it needs provider pia"},
		{Answers{"pia", []string{WayNetBird}, []string{ExtraPortSync}}, "port-sync runs in the native sidecar's namespace"},
		{Answers{"pia", []string{WayNetBird, WayProxy}, []string{ExtraPortSync}}, "it needs the sidecar way in"},
	} {
		_, err := c.a.Plan()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: got %v, want %q", c.a, err, c.want)
		}
	}
}

// subsets lists every subset of names, the empty one first.
func subsets(names []string) [][]string {
	out := [][]string{{}}
	for _, n := range names {
		for _, s := range out {
			out = append(out, append(slices.Clone(s), n))
		}
	}
	return out
}

func allProviders() []string {
	out := providers.Native()
	for _, name := range providers.GluetunProviderKeys {
		out = append(out, "gluetun-"+name)
	}
	return append(out, "wireguard")
}

// TestEveryCombination tries every provider and every set of ways in and
// extras. init accepts exactly 52 combinations
// (each native provider with netbird-exit or sidecar, each with or without
// the proxy, with or without Switchyard: 24; PIA's sidecar with port-sync:
// 4 more; each of the six gluetun providers with netbird-exit or sidecar,
// with or without Switchyard: 24). tools/check-compose.sh checks the same
// number.
func TestEveryCombination(t *testing.T) {
	if got := combinations(t); got != 52 {
		t.Fatalf("init accepts %d combinations, want 52", got)
	}
}

func combinations(t *testing.T) int {
	accepted := 0
	for _, prov := range allProviders() {
		for _, ways := range subsets(Ways) {
			for _, extras := range subsets(Extras) {
				p, err := Answers{prov, ways, extras}.Plan()
				if err != nil {
					continue
				}
				accepted++
				files, err := Render(p)
				if err != nil {
					t.Fatalf("%+v: %v", p.Answers, err)
				}
				compose := string(files[ComposeFile])
				for _, svc := range p.Services() {
					if strings.Count(compose, "\n  "+svc+":\n") != 1 {
						t.Errorf("%+v: service %s not written once", p.Answers, svc)
					}
				}
				services := regexp.MustCompile(`(?m)^  ([a-z-]+):$`).FindAllStringSubmatch(compose, -1)
				written := map[string]bool{}
				for _, m := range services {
					written[m[1]] = true
				}
				for _, extra := range []string{"switchyard", "port-sync", "proxy"} {
					if written[extra] != slices.Contains(p.Services(), extra) {
						t.Errorf("%+v: %s written %v", p.Answers, extra, written[extra])
					}
				}
				if strings.Contains(compose, "{{") || strings.Contains(compose, "<no value>") {
					t.Errorf("%+v: template text left in the output", p.Answers)
				}
				if !strings.Contains(compose, "\nname: "+project[p.Form]+"\n") {
					t.Errorf("%+v: no project name", p.Answers)
				}
				seen := map[string]bool{}
				for _, line := range strings.Split(string(files[EnvFile]), "\n") {
					key, _, ok := strings.Cut(line, "=")
					if !ok || strings.HasPrefix(line, "#") {
						continue
					}
					if seen[key] {
						t.Errorf("%+v: .env sets %s twice", p.Answers, key)
					}
					seen[key] = true
					if !strings.Contains(compose, "${"+key+":") && !strings.HasPrefix(key, "COMPOSE_") {
						t.Errorf("%+v: .env sets %s, which compose.yaml does not read", p.Answers, key)
					}
				}
				_, preflight := files[PreflightFile]
				if preflight != strings.HasPrefix(prov, "gluetun-") {
					t.Errorf("%+v: preflight written %v", p.Answers, preflight)
				}
			}
		}
	}
	return accepted
}

// shippedBlocks splits a Compose file's services into their blocks of
// lines, the way compose.tmpl holds them.
func shippedBlocks(t *testing.T, file string) map[string][]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, file))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	in, cur := false, ""
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "services:" {
			in = true
			continue
		}
		if in && line != "" && line[0] != ' ' && line[0] != '#' {
			in = false
		}
		if !in {
			continue
		}
		if m := regexp.MustCompile(`^  ([a-z-]+):$`).FindStringSubmatch(line); m != nil {
			cur = m[1]
		}
		if cur != "" {
			out[cur] = append(out[cur], line)
		}
	}
	return out
}

// meaningful drops what Compose ignores (comments, blank lines) and the
// build key, which init never writes.
func meaningful(lines []string) []string {
	var out []string
	inBuild := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if line == "    build:" {
			inBuild = true
			continue
		}
		if inBuild && strings.HasPrefix(line, "      ") {
			continue
		}
		inBuild = false
		out = append(out, line)
	}
	return out
}

// TestBlocksMatchShippedFiles fails when a service init writes and the same
// service in the shipped Compose file differ in anything Compose reads:
// image and pin, command, capabilities, settings, mounts, limits. Only the
// three deliberate differences compose.tmpl names are allowed. The proxy's
// block is held to compose.proxy.yaml.
func TestBlocksMatchShippedFiles(t *testing.T) {
	overlay := shippedBlocks(t, "compose.yaml")
	for form, file := range SourceFile {
		shipped := shippedBlocks(t, file)
		p := Plan{Form: form}
		names := []string{}
		for name := range shipped {
			names = append(names, name)
		}
		if len(names) == 0 {
			t.Fatalf("%s: no services found", file)
		}
		for _, name := range names {
			want := meaningful(shipped[name])
			switch {
			case form == FormNativeSidecar && name == "port-sync":
				want = slices.DeleteFunc(want, func(l string) bool { return l == "    profiles: [port-sync]" })
			case form == FormGluetunOverlay && name == "switchyard":
				// compose.gluetun.yaml extends compose.yaml's panel and
				// replaces its PROVIDER.
				var provider string
				for _, l := range want {
					if strings.HasPrefix(l, "      PROVIDER: ") {
						provider = l
					}
				}
				if provider == "" {
					t.Fatalf("compose.gluetun.yaml's switchyard sets no PROVIDER")
				}
				want = nil
				for _, l := range meaningful(overlay["switchyard"]) {
					if strings.HasPrefix(l, "      PROVIDER: ") {
						l = provider
					}
					want = append(want, l)
				}
			}
			block, err := Block(form+"/"+name, p)
			if err != nil {
				t.Errorf("%s: no block for %s's %s: %v", form, file, name, err)
				continue
			}
			got := meaningful(strings.Split(strings.TrimRight(block, "\n"), "\n"))
			if !slices.Equal(got, want) {
				t.Errorf("%s/%s drifted from %s:\n%s", form, name, file, lineDiff(want, got))
			}
		}
		// And no block init has for this form is missing from the shipped file.
		for _, tmpl := range composeT.Templates() {
			if svc, ok := strings.CutPrefix(tmpl.Name(), form+"/"); ok && shipped[svc] == nil {
				t.Errorf("compose.tmpl has %s, which %s doesn't", tmpl.Name(), file)
			}
		}
	}
	// The proxy: compose.proxy.yaml, the overlay file for compose.yaml and
	// compose.native-sidecar.yaml, is the block as the overlay form renders
	// it, and has no other service.
	proxyFile := shippedBlocks(t, "compose.proxy.yaml")
	if len(proxyFile) != 1 || proxyFile["proxy"] == nil {
		t.Fatalf("compose.proxy.yaml must hold exactly the proxy service")
	}
	block, err := Block("proxy", Plan{Form: FormOverlay})
	if err != nil {
		t.Fatal(err)
	}
	want := meaningful(proxyFile["proxy"])
	got := meaningful(strings.Split(strings.TrimRight(block, "\n"), "\n"))
	if !slices.Equal(got, want) {
		t.Errorf("proxy drifted from compose.proxy.yaml:\n%s", lineDiff(want, got))
	}
}

func lineDiff(want, got []string) string {
	var b strings.Builder
	for i := 0; i < len(want) || i < len(got); i++ {
		var w, g string
		if i < len(want) {
			w = want[i]
		}
		if i < len(got) {
			g = got[i]
		}
		if w != g {
			b.WriteString("  shipped: " + w + "\n  init:    " + g + "\n")
			break
		}
	}
	return b.String()
}

var pinRE = regexp.MustCompile(`([a-z0-9.]+/[a-z0-9/_-]+):([A-Za-z0-9._-]+)@(sha256:[0-9a-f]{64})`)

// TestProxyPins: the proxy runs the native sidecar's molebridge-core, pinned
// exactly as the shipped files pin it.
func TestProxyPins(t *testing.T) {
	block, err := Block("proxy", Plan{Form: FormOverlay})
	if err != nil {
		t.Fatal(err)
	}
	var exit string
	for _, l := range shippedBlocks(t, "compose.native-sidecar.yaml")["exit"] {
		if strings.HasPrefix(l, "    image: ") {
			exit = l
		}
	}
	if exit == "" || !strings.Contains(block, "\n"+exit+"\n") {
		t.Fatalf("the proxy's image is not the native sidecar exit's %q", exit)
	}
	raw, _ := templateFS.ReadFile("compose.tmpl")
	tags := map[string]bool{}
	for _, m := range pinRE.FindAllStringSubmatch(string(raw), -1) {
		if strings.HasPrefix(m[1], "ghcr.io/irashack/molebridge") {
			tags[m[2]] = true
		}
	}
	if len(tags) != 1 {
		t.Fatalf("compose.tmpl pins Molebridge at %v, want one tag", tags)
	}
}

func envSettings(text string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if key, value, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
			out[key] = value
		}
	}
	return out
}

// TestEnvMatchesExamples: the .env init writes has the settings of the
// form's example, with the example's values except the ones the answers
// decide, and nothing else but the proxy's.
func TestEnvMatchesExamples(t *testing.T) {
	examples := map[string]string{
		FormOverlay: ".env.example", FormGluetunOverlay: ".env.gluetun.example",
		FormGluetunSidecar: ".env.sidecar.example", FormNativeSidecar: ".env.native-sidecar.example",
	}
	full := map[string]Answers{
		FormOverlay:        {"pia", []string{WayNetBird, WayProxy}, []string{ExtraSwitchyard}},
		FormGluetunOverlay: {"gluetun-ivpn", []string{WayNetBird}, []string{ExtraSwitchyard}},
		FormGluetunSidecar: {"gluetun-ivpn", []string{WaySidecar}, []string{ExtraSwitchyard}},
		FormNativeSidecar:  {"pia", []string{WaySidecar, WayProxy}, []string{ExtraSwitchyard, ExtraPortSync}},
	}
	decided := map[string]bool{"PROVIDER": true, "EXIT_IF": true, "GLUETUN_PROVIDER": true, "PIA_PORT_FORWARD": true}
	for form, file := range examples {
		raw, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		example := envSettings(string(raw))
		p, err := full[form].Plan()
		if err != nil || p.Form != form {
			t.Fatalf("%s: %+v %v", form, p, err)
		}
		files, err := Render(p)
		if err != nil {
			t.Fatal(err)
		}
		got := envSettings(string(files[EnvFile]))
		for key, value := range got {
			want, ok := example[key]
			switch {
			case strings.HasPrefix(key, "PROXY_"):
			case !ok:
				t.Errorf("%s: init writes %s, which %s doesn't have", form, key, file)
			case !decided[key] && value != want:
				t.Errorf("%s: init writes %s=%s, %s has %s", form, key, value, file, want)
			}
		}
		for key := range example {
			if _, ok := got[key]; !ok && key != "COMPOSE_FILE" {
				t.Errorf("%s: %s sets %s, which init doesn't write", form, file, key)
			}
		}
		if got["PROVIDER"] != "" && (got["PROVIDER"] != p.Provider || got["EXIT_IF"] != p.Provider) {
			t.Errorf("%s: PROVIDER and EXIT_IF are %s and %s", form, got["PROVIDER"], got["EXIT_IF"])
		}
		if p.GluetunProvider != "" && got["GLUETUN_PROVIDER"] != p.GluetunProvider {
			t.Errorf("%s: GLUETUN_PROVIDER is %s", form, got["GLUETUN_PROVIDER"])
		}
	}
	// Without Switchyard there are no panel settings; port-sync turns PIA's
	// forwarding on.
	p, _ := Answers{"pia", []string{WaySidecar}, []string{ExtraPortSync}}.Plan()
	files, _ := Render(p)
	env := envSettings(string(files[EnvFile]))
	if _, ok := env["PANEL_PORT"]; ok || env["PIA_PORT_FORWARD"] != "on" || env["PORT_SYNC_URL"] == "" {
		t.Errorf("pia sidecar with port-sync, no panel: %v", env)
	}
	p, _ = Answers{"nordvpn", []string{WaySidecar}, nil}.Plan()
	files, _ = Render(p)
	env = envSettings(string(files[EnvFile]))
	if _, ok := env["PIA_PORT_FORWARD"]; ok {
		t.Errorf("nordvpn sidecar has PIA settings: %v", env)
	}
}

// TestGolden compares whole outputs with testdata/, pins replaced by <pin>
// (the release automation moves them; TestBlocksMatchShippedFiles checks
// them). go test -run TestGolden -update rewrites the files.
func TestGolden(t *testing.T) {
	for name, a := range map[string]Answers{
		"mullvad-netbird-switchyard":   {"mullvad", []string{WayNetBird}, []string{ExtraSwitchyard}},
		"nordvpn-netbird-proxy":        {"nordvpn", []string{WayNetBird, WayProxy}, nil},
		"pia-sidecar-proxy-all":        {"pia", []string{WaySidecar, WayProxy}, []string{ExtraSwitchyard, ExtraPortSync}},
		"mullvad-sidecar":              {"mullvad", []string{WaySidecar}, nil},
		"gluetun-nordvpn-netbird-yard": {"gluetun-nordvpn", []string{WayNetBird}, []string{ExtraSwitchyard}},
		"gluetun-ivpn-sidecar":         {"gluetun-ivpn", []string{WaySidecar}, nil},
	} {
		p, err := a.Plan()
		if err != nil {
			t.Fatal(err)
		}
		files, err := Render(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{ComposeFile, EnvFile} {
			got := pinRE.ReplaceAll(files[f], []byte("$1:<pin>"))
			path := filepath.Join("testdata", name+"."+strings.TrimPrefix(f, ".")+".golden")
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (go test -run TestGolden -update writes it)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s differs from %s:\n%s", name, path,
					lineDiff(strings.Split(string(want), "\n"), strings.Split(string(got), "\n")))
			}
		}
	}
}

func run(t *testing.T, stdin string, terminal bool, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Main(args, Options{Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb,
		Terminal: func() bool { return terminal }})
	return code, out.String(), errb.String()
}

func writeAnswers(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "answers.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMainWritesAndRefusesToOverwrite(t *testing.T) {
	out := filepath.Join(t.TempDir(), "stack")
	answers := writeAnswers(t, `{"schema":1,"provider":"gluetun-nordvpn","ways_in":["netbird-exit"],"extras":["switchyard"]}`)
	code, stdout, stderr := run(t, "", false, "--out", out, "--answers", answers)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if !strings.Contains(stdout, "the services of compose.gluetun.yaml with gluetun, exit, switchyard") {
		t.Errorf("stdout: %s", stdout)
	}
	for name, mode := range map[string]os.FileMode{ComposeFile: 0o644, EnvFile: 0o644, PreflightFile: 0o755} {
		info, err := os.Stat(filepath.Join(out, name))
		if err != nil || info.Mode().Perm() != mode {
			t.Errorf("%s: %v %v", name, info, err)
		}
	}
	got, _ := os.ReadFile(filepath.Join(out, PreflightFile))
	if !bytes.Equal(got, routing.GluetunPreflight) {
		t.Error("the preflight is not routing/gluetun-preflight")
	}
	before, _ := os.ReadFile(filepath.Join(out, ComposeFile))

	other := writeAnswers(t, `{"schema":1,"provider":"gluetun-nordvpn","ways_in":["sidecar"]}`)
	code, _, stderr = run(t, "", false, "--out", out, "--answers", other)
	if code != 1 || !strings.Contains(stderr, "exists; pass --force to replace it") {
		t.Fatalf("overwrite: exit %d: %s", code, stderr)
	}
	after, _ := os.ReadFile(filepath.Join(out, ComposeFile))
	if !bytes.Equal(before, after) {
		t.Fatal("a refused run changed compose.yaml")
	}
	code, _, stderr = run(t, "", false, "--out", out, "--answers", other, "--force")
	after, _ = os.ReadFile(filepath.Join(out, ComposeFile))
	if code != 0 || bytes.Equal(before, after) || !strings.Contains(string(after), "name: molebridge-sidecar\n") {
		t.Fatalf("--force: exit %d: %s", code, stderr)
	}

	// A symbolic link is never replaced, even with --force.
	linked := t.TempDir()
	target := filepath.Join(t.TempDir(), "elsewhere")
	os.WriteFile(target, []byte("keep"), 0o644)
	os.Symlink(target, filepath.Join(linked, EnvFile))
	code, _, stderr = run(t, "", false, "--out", linked, "--answers", other, "--force")
	if code != 1 || !strings.Contains(stderr, "is not a regular file") {
		t.Fatalf("symlink: exit %d: %s", code, stderr)
	}
	if kept, _ := os.ReadFile(target); string(kept) != "keep" {
		t.Fatal("the link's target changed")
	}
	if _, err := os.Stat(filepath.Join(linked, ComposeFile)); err == nil {
		t.Fatal("a refused run wrote compose.yaml")
	}
}

func TestMainRefusals(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{nil, 2, "usage: molebridge init --out DIR"},
		{[]string{"--answers", "x"}, 2, "usage:"},
		{[]string{"--out", dir, "extra"}, 2, "usage:"},
		{[]string{"--bogus"}, 2, "flag provided but not defined"},
		{[]string{"--out", dir}, 2, "no terminal to ask on; pass --answers FILE"},
		{[]string{"--out", dir, "--answers", filepath.Join(dir, "missing.json")}, 1, "can't read the answers file"},
		{[]string{"--out", dir, "--answers", writeAnswers(t, `{"schema":1,"provider":"gluetun-nordvpn","ways_in":["proxy","netbird-exit"]}`)}, 1,
			"molebridge init: the proxy needs a native provider"},
		{[]string{"--out", dir, "--answers", writeAnswers(t, `{"schema":1}`)}, 1, "provider must be a name"},
	} {
		code, _, stderr := run(t, "", false, c.args...)
		if code != c.code || !strings.Contains(stderr, c.want) {
			t.Errorf("%v: exit %d, %q; want %d, %q", c.args, code, stderr, c.code, c.want)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("refusals wrote %v", entries)
	}
	code, stdout, _ := run(t, "", false, "--help")
	if code != 0 || !strings.Contains(stdout, `"ways_in"`) {
		t.Errorf("--help: %d %s", code, stdout)
	}
}

func TestMainAsks(t *testing.T) {
	out := t.TempDir()
	// An unknown name is asked again; then the same answers as a file.
	code, stdout, stderr := run(t, "expressvpn\nPIA\nsidecar, vpn\nsidecar proxy\n\n", true, "--out", out)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, `"expressvpn" is not a provider init offers`) || !strings.Contains(stdout, `"vpn" is not a way in`) {
		t.Errorf("no second question: %s", stdout)
	}
	compose, _ := os.ReadFile(filepath.Join(out, ComposeFile))
	p, _ := Answers{"pia", []string{WaySidecar, WayProxy}, []string{}}.Plan()
	files, _ := Render(p)
	if !bytes.Equal(compose, files[ComposeFile]) {
		t.Error("the asked answers wrote something else than the same answers from a file")
	}

	for name, c := range map[string]struct{ stdin, want string }{
		"three wrong":   {"a\nb\nc\n", "no usable answer after three tries"},
		"input ends":    {"mullvad\n", "no answer: the input ended"},
		"too long":      {strings.Repeat("x", 2*maxLine) + "\n", "longer than 1024 bytes"},
		"control":       {"mull\x1bvad\n", "control character"},
		"impossible":    {"mullvad\nnetbird-exit,sidecar\n\n", "can't share one exit"},
		"empty ways in": {"mullvad\n\n\n\n", "no usable answer"},
	} {
		code, _, stderr := run(t, c.stdin, true, "--out", t.TempDir())
		if code != 1 || !strings.Contains(stderr, c.want) {
			t.Errorf("%s: exit %d, %q", name, code, stderr)
		}
	}
}
