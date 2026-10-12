package exit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/nbprofile"
)

const zeroKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

const mullvadConf = `# test
[Interface]
PrivateKey = ` + zeroKey + `
Address = 203.0.113.2/32
MTU = 1420
Table = off
PostUp = ip route replace default dev %i table 51821
PreDown = ip route del default dev %i table 51821

[Peer]
PublicKey = ` + zeroKey + `
Endpoint = 198.51.100.10:51820
AllowedIPs = 0.0.0.0/0
`

type fixture struct {
	dir  string
	env  map[string]string
	opts LoadOptions
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "wg_confs")
	state := filepath.Join(dir, "state")
	nb := filepath.Join(dir, "netbird")
	for _, d := range []string{conf, filepath.Join(state, "applier"), nb} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(conf, "mullvad.conf"), []byte(mullvadConf), 0o600); err != nil {
		t.Fatal(err)
	}
	return &fixture{dir: dir, env: map[string]string{
		"TUNNEL_BACKEND": "native", "EXIT_KIND": "overlay", "PROVIDER": "mullvad", "EXIT_IF": "mullvad",
		"OVERLAY_CIDR": "192.0.2.0/24", "OVERLAY_IF": "wt0", "NB_INTERFACE_NAME": "wt0",
		"NB_DISABLE_USERSPACE_ROUTING": "true", "NB_EXTRA_IFACE_BLACKLIST": "mullvad", "NB_STATE_DIR": nb, "STATE_DIR": state, "TUNNEL_CONF_DIR": conf,
		"MOLEBRIDGE_RUN_DIR": filepath.Join(dir, "run"),
	}, opts: LoadOptions{NBPaths: nbprofile.Paths{StateDir: nb}}}
}

func (f *fixture) load() (*Settings, error) { return LoadSettings(f.env, f.opts) }

func TestSettingsAcceptAGoodNativeEnvironment(t *testing.T) {
	f := newFixture(t)
	s, err := f.load()
	if err != nil {
		t.Fatal(err)
	}
	if !s.Native() || !s.Overlay() || s.Kind() != "overlay" || s.BackendName() != "native" {
		t.Errorf("%+v", s.Routing)
	}
	if s.Grace != 30*time.Second || s.Interval != 30*time.Second || s.Conf == nil || !s.NoIdentity {
		t.Errorf("grace %v interval %v conf %v noidentity %v", s.Grace, s.Interval, s.Conf, s.NoIdentity)
	}
	// "wireguard" is the alias of "native".
	f.env["TUNNEL_BACKEND"] = "wireguard"
	if _, err := f.load(); err != nil {
		t.Errorf("wireguard alias: %v", err)
	}
	delete(f.env, "TUNNEL_BACKEND")
	if _, err := f.load(); err != nil {
		t.Errorf("default backend: %v", err)
	}
}

func TestSettingsRefusals(t *testing.T) {
	tests := []struct {
		name string
		mod  func(f *fixture)
		want string
	}{
		{"unknown backend", func(f *fixture) { f.env["TUNNEL_BACKEND"] = "docker" }, "molebridge-exit: TUNNEL_BACKEND must be native or gluetun"},
		{"unknown kind", func(f *fixture) { f.env["EXIT_KIND"] = "edge" }, "molebridge-exit: EXIT_KIND must be overlay or sidecar"},
		{"native with a gluetun provider", func(f *fixture) { f.env["PROVIDER"] = "gluetun-mullvad" }, "molebridge-exit: PROVIDER must be mullvad, pia or nordvpn"},
		{"unknown provider", func(f *fixture) { f.env["PROVIDER"] = "acme" }, "molebridge-exit: PROVIDER must be mullvad, pia or nordvpn"},
		{"gluetun with a native provider", func(f *fixture) { f.env["TUNNEL_BACKEND"] = "gluetun" },
			"molebridge-exit: TUNNEL_BACKEND=gluetun needs a gluetun provider (PROVIDER=gluetun-<name>)"},
		{"no overlay range", func(f *fixture) { delete(f.env, "OVERLAY_CIDR") }, "molebridge-exit: OVERLAY_CIDR must be an IPv4 CIDR"},
		{"same interface twice", func(f *fixture) { f.env["EXIT_IF"] = "wt0" }, "molebridge-exit: overlay and exit interfaces must differ"},
		{"interval too small", func(f *fixture) { f.env["ROUTING_RECONCILE_INTERVAL"] = "1" }, "molebridge-exit: ROUTING_RECONCILE_INTERVAL must be 2..60 seconds"},
		{"interval too large", func(f *fixture) { f.env["ROUTING_RECONCILE_INTERVAL"] = "61" }, "molebridge-exit: ROUTING_RECONCILE_INTERVAL must be 2..60 seconds"},
		{"grace 4", func(f *fixture) { f.env["GUARD_GRACE"] = "4" }, "molebridge-exit: GUARD_GRACE must be 5..30 seconds"},
		{"grace 31", func(f *fixture) { f.env["GUARD_GRACE"] = "31" }, "molebridge-exit: GUARD_GRACE must be 5..30 seconds"},
		{"grace 05", func(f *fixture) { f.env["GUARD_GRACE"] = "05" }, "molebridge-exit: GUARD_GRACE must be 5..30 seconds"},
		{"grace text", func(f *fixture) { f.env["GUARD_GRACE"] = "soon" }, "molebridge-exit: GUARD_GRACE must be 5..30 seconds"},
		{"missing tunnel config", func(f *fixture) { os.Remove(filepath.Join(f.env["TUNNEL_CONF_DIR"], "mullvad.conf")) },
			"mullvad.conf is missing; regenerate it with prepare-config (docs/setup.md)"},
		{"overlay name differs", func(f *fixture) { f.env["NB_INTERFACE_NAME"] = "nb0" },
			"molebridge-exit: NB_INTERFACE_NAME (nb0) must equal OVERLAY_IF (wt0), the interface the routing contract guards"},
		{"netbird needs kernel routing", func(f *fixture) { f.env["NB_DISABLE_USERSPACE_ROUTING"] = "false" },
			`NetBird gate: refusing to start NetBird: NB_DISABLE_USERSPACE_ROUTING must be "true" (compose.yaml sets it)`},
		{"rosenpass", func(f *fixture) { f.env["NB_ENABLE_ROSENPASS"] = "true" },
			"NetBird gate: refusing to start NetBird: NB_ENABLE_ROSENPASS is set; Rosenpass cannot work on this exit"},
		{"profile without the tunnel excluded", func(f *fixture) {
			p := filepath.Join(f.env["NB_STATE_DIR"], "default.json")
			os.WriteFile(p, []byte(`{"WgIface":"wt0","IFaceBlackList":["docker0"]}`), 0o600)
		}, "does not exclude the tunnel interface mullvad"},
		{"state directory missing", func(f *fixture) { os.RemoveAll(filepath.Join(f.env["STATE_DIR"], "applier")) },
			"molebridge-exit: the state directory "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			tt.mod(f)
			_, err := f.load()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
			if r, ok := err.(*Refusal); !ok || strings.Contains(r.Line, zeroKey) {
				t.Errorf("not a refusal line: %v", err)
			}
		})
	}
}

func TestFirstEnrollmentNeedsTheTunnelOnTheBlacklistSetting(t *testing.T) {
	want := "NB_EXTRA_IFACE_BLACKLIST must name the tunnel interface mullvad"
	for _, tt := range []struct {
		value string
		ok    bool
	}{
		{"mullvad", true}, {"mull", true}, {"docker0,mullvad", true}, {"m", true}, {"wg,mullvad", true},
		{"", false}, {"docker0", false}, {"mullvad0", false}, {"Mullvad", false}, {" mullvad", false}, {",", false},
	} {
		f := newFixture(t)
		f.env["NB_EXTRA_IFACE_BLACKLIST"] = tt.value
		_, err := f.load()
		if tt.ok && err != nil {
			t.Errorf("%q: %v", tt.value, err)
		}
		if !tt.ok && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%q: %v", tt.value, err)
		}
	}
	// With a stored profile the setting is not consulted: the profile is.
	f := newFixture(t)
	delete(f.env, "NB_EXTRA_IFACE_BLACKLIST")
	p := filepath.Join(f.env["NB_STATE_DIR"], "default.json")
	if err := os.WriteFile(p, []byte(`{"WgIface":"wt0","IFaceBlackList":["wg","mullvad"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.load(); err != nil {
		t.Errorf("an enrolled peer: %v", err)
	}
}

func TestGraceAndIntervalOverrides(t *testing.T) {
	f := newFixture(t)
	f.env["GUARD_GRACE"] = "5"
	f.env["ROUTING_RECONCILE_INTERVAL"] = "2"
	s, err := f.load()
	if err != nil || s.Grace != 5*time.Second || s.Interval != 2*time.Second {
		t.Fatalf("%v %v", s, err)
	}
}

func TestWriteChecksCreateAndProbeTheStateDirectory(t *testing.T) {
	f := newFixture(t)
	os.RemoveAll(filepath.Join(f.env["STATE_DIR"], "applier"))
	if _, err := f.load(); err == nil {
		t.Fatal("check-config must not create the directory")
	}
	if _, err := os.Stat(filepath.Join(f.env["STATE_DIR"], "applier")); err == nil {
		t.Fatal("a read-only load created the directory")
	}
	f.opts.WriteChecks = true
	if _, err := f.load(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Join(f.env["STATE_DIR"], "applier"))
	if len(entries) != 0 {
		t.Errorf("the probe file was left: %v", entries)
	}
}

func TestSidecarSettings(t *testing.T) {
	f := newFixture(t)
	f.env = map[string]string{"EXIT_KIND": "sidecar", "TUNNEL_BACKEND": "gluetun", "PROVIDER": "gluetun-mullvad", "EXIT_IF": "wg0",
		"STATE_DIR": f.env["STATE_DIR"], "GUARD_GRACE": "10"}
	s, err := f.load()
	if err != nil {
		t.Fatal(err)
	}
	if s.Overlay() || s.Native() || s.Kind() != "sidecar" || s.Grace != 10*time.Second || s.Conf != nil {
		t.Errorf("%+v", s)
	}
	f.env["PROVIDER"] = "mullvad"
	if _, err := f.load(); err == nil {
		t.Error("a sidecar with a native provider")
	}
}

func TestChildEnvironments(t *testing.T) {
	env := map[string]string{
		"NB_SETUP_KEY": "SETUPVALUE", "NB_HOSTNAME": "x", "WT_FOO": "1", "GATUS_TOKEN": "TOKENVALUE", "PATH": "/bin",
		"PIA_USER": "u", "TZ": "UTC", "HOME": "/root", "STATE_DIR": "/state",
	}
	nb := strings.Join(ChildEnvNetBird(env, "/run/tmp", true), "\n")
	if strings.Contains(strings.Join(ChildEnvNetBird(env, "/run/tmp", false), "\n"), "SETUPVALUE") {
		t.Error("only `netbird up` gets the setup key")
	}
	if c := strings.Join(CleanupEnv(env), "\n"); strings.Contains(c, "TOKENVALUE") || strings.Contains(c, "SETUPVALUE") || strings.Contains(c, "STATE_DIR") {
		t.Errorf("the cleanup gets interface names only: %s", c)
	}
	for _, bad := range []string{"GATUS_TOKEN", "TOKENVALUE", "PIA_USER", "STATE_DIR"} {
		if strings.Contains(nb, bad) {
			t.Errorf("NetBird must not get %s", bad)
		}
	}
	for _, good := range []string{"NB_SETUP_KEY=SETUPVALUE", "NB_HOSTNAME=x", "WT_FOO=1", "PATH=/bin", "TZ=UTC", "HOME=/root",
		"TMPDIR=/run/tmp", "NB_LOG_FILE=console,/var/log/netbird/client.log"} {
		if !strings.Contains(nb, good) {
			t.Errorf("NetBird should get %s\n%s", good, nb)
		}
	}
	w := strings.Join(WorkerEnv(env), "\n")
	if strings.Contains(w, "NB_SETUP_KEY") || strings.Contains(w, "SETUPVALUE") {
		t.Error("the worker must not get the setup key")
	}
	if !strings.Contains(w, "GATUS_TOKEN=TOKENVALUE") || !strings.Contains(w, "NB_HOSTNAME=x") {
		t.Error("the worker gets the rest")
	}
	if got := watchLogPath(map[string]string{}); got != "/var/log/netbird/client.log" {
		t.Errorf("default log: %q", got)
	}
	if got := watchLogPath(map[string]string{"NB_LOG_FILE": "console"}); got != "" {
		t.Errorf("console only: %q", got)
	}
}
