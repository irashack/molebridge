package initmenu

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestOffersMultiProvider: the exit accepts PROVIDERS, and init offers it
// on the terminal and in --help.
func TestOffersMultiProvider(t *testing.T) {
	if code, out, _ := run(t, "", false, "--help"); code != 0 || !strings.Contains(out, `"mullvad,nordvpn"`) {
		t.Errorf("--help: %d %s", code, out)
	}
	out := t.TempDir()
	code, stdout, stderr := run(t, "Mullvad, NordVPN\nnetbird-exit\nswitchyard\n", true, "--out", out)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, "for a NetBird exit that switches between them, two or three of mullvad, pia, nordvpn, comma-separated): ") {
		t.Errorf("the prompt doesn't offer several providers: %s", stdout)
	}
	if !strings.Contains(stdout, "needs a tunnel config for each provider: tunnel/wg_confs/mullvad.conf, tunnel/wg_confs/nordvpn.conf.\n") {
		t.Errorf("no word on the tunnel configs: %s", stdout)
	}
	compose, _ := os.ReadFile(filepath.Join(out, ComposeFile))
	p, err := Answers{"mullvad,nordvpn", []string{WayNetBird}, []string{ExtraSwitchyard}}.Plan()
	if err != nil {
		t.Fatal(err)
	}
	files, _ := Render(p)
	if !bytes.Equal(compose, files[ComposeFile]) {
		t.Error("the asked answers wrote something else than the same answers from a file")
	}
	code, stdout, _ = run(t, "mullvad,expressvpn\nmullvad,pia\nnetbird-exit\n\n", true, "--out", t.TempDir())
	if code != 0 || !strings.Contains(stdout, `"expressvpn" is not a provider init offers`) {
		t.Errorf("an unknown name among several: exit %d, %s", code, stdout)
	}
}

func TestMultiProviderRefusals(t *testing.T) {
	for _, c := range []struct {
		a    Answers
		want string
	}{
		{Answers{"mullvad,nordvpn", []string{WaySidecar}, nil}, "a multi-provider exit is a NetBird exit only: the sidecar runs one provider"},
		{Answers{"mullvad,nordvpn", []string{WayNetBird, WaySidecar}, nil}, "a multi-provider exit is a NetBird exit only"},
		{Answers{"pia,nordvpn", []string{WayNetBird, WayProxy}, nil}, "the proxy can't run on a multi-provider exit"},
		{Answers{"pia,nordvpn", []string{WayProxy}, nil}, "the proxy can't run on a multi-provider exit"},
		{Answers{"pia,mullvad", []string{WayNetBird}, []string{ExtraPortSync}}, "port-sync runs in the native sidecar's namespace"},
		{Answers{"mullvad,gluetun-nordvpn", []string{WayNetBird}, nil}, "with gluetun-nordvpn the tunnel is gluetun's, and gluetun runs one provider"},
		{Answers{"gluetun-mullvad,gluetun-nordvpn", []string{WayNetBird}, nil}, "takes only providers Molebridge drives itself"},
		{Answers{"mullvad,expressvpn", []string{WayNetBird}, nil}, `provider "expressvpn" is not one Molebridge knows`},
		{Answers{"mullvad,mullvad", []string{WayNetBird}, nil}, "provider mullvad is listed twice"},
		{Answers{"mullvad,pia,nordvpn,mullvad", []string{WayNetBird}, nil}, "provider mullvad is listed twice"},
		{Answers{"mullvad,", []string{WayNetBird}, nil}, `provider "mullvad," has an empty name in it`},
		{Answers{"mullvad,pia", nil, nil}, "choose at least one way in"},
		{Answers{"mullvad,pia", []string{"vpn"}, nil}, `"vpn" is not a way in`},
	} {
		_, err := c.a.Plan()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: got %v, want %q", c.a, err, c.want)
		}
	}
}

// TestMultiProviderOutput: PROVIDERS in the order given, PROVIDER the first,
// EXIT_IF=vpn, PIA's settings when pia is in the set, and one read-only
// tunnel-config mount per provider in place of the directory.
func TestMultiProviderOutput(t *testing.T) {
	for _, c := range []struct {
		provider string
		pia      bool
	}{
		{"nordvpn,mullvad", false},
		{"mullvad,pia,nordvpn", true},
		{"pia,nordvpn", true},
	} {
		p, err := Answers{c.provider, []string{WayNetBird}, nil}.Plan()
		if err != nil {
			t.Fatal(err)
		}
		names := strings.Split(c.provider, ",")
		if p.Form != FormOverlay || !slices.Equal(p.Providers, names) || !slices.Equal(p.Services(), []string{"exit"}) {
			t.Fatalf("%s: %+v", c.provider, p)
		}
		files, err := Render(p)
		if err != nil {
			t.Fatal(err)
		}
		env := envSettings(string(files[EnvFile]))
		if env["PROVIDERS"] != c.provider || env["PROVIDER"] != names[0] || env["EXIT_IF"] != "vpn" {
			t.Errorf("%s: PROVIDERS=%s PROVIDER=%s EXIT_IF=%s", c.provider, env["PROVIDERS"], env["PROVIDER"], env["EXIT_IF"])
		}
		if _, ok := env["PIA_PORT_FORWARD"]; ok != c.pia {
			t.Errorf("%s: PIA_PORT_FORWARD written %v", c.provider, ok)
		}
		if strings.Contains(string(files[EnvFile]), "PIA's login") != c.pia {
			t.Errorf("%s: the credentials note doesn't match the set", c.provider)
		}
		compose := string(files[ComposeFile])
		if strings.Contains(compose, "./tunnel/wg_confs:/config/wg_confs") {
			t.Errorf("%s: the tunnel/wg_confs directory is mounted", c.provider)
		}
		if strings.Count(compose, "target: /config/wg_confs/") != len(names) {
			t.Errorf("%s: not one tunnel-config mount per provider", c.provider)
		}
		for _, name := range names {
			mount := "      - type: bind\n        source: ./tunnel/wg_confs/" + name + ".conf\n" +
				"        target: /config/wg_confs/" + name + ".conf\n        read_only: true\n" +
				"        bind:\n          create_host_path: false\n"
			if !strings.Contains(compose, mount) {
				t.Errorf("%s: no read-only mount of %s.conf", c.provider, name)
			}
		}
		if !strings.Contains(compose, `      PROVIDERS: "${PROVIDERS:?`) {
			t.Errorf("%s: compose.yaml doesn't pass PROVIDERS", c.provider)
		}
	}
	// A single provider is written as before: no PROVIDERS anywhere.
	p, _ := Answers{"mullvad", []string{WayNetBird}, nil}.Plan()
	files, _ := Render(p)
	if p.Multi() || strings.Contains(string(files[ComposeFile]), "PROVIDERS") || strings.Contains(string(files[EnvFile]), "PROVIDERS") {
		t.Error("a single-provider exit mentions PROVIDERS")
	}
}

func TestGoldenMultiProvider(t *testing.T) {
	golden(t, "multi-mullvad-pia-netbird-yard", Answers{"mullvad,pia", []string{WayNetBird}, []string{ExtraSwitchyard}})
	golden(t, "multi-nordvpn-mullvad-pia-netbird", Answers{"nordvpn,mullvad,pia", []string{WayNetBird}, nil})
}
