package exit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

// A multi-provider exit's settings (docs/design/multi-provider.md, step 6):
// PROVIDERS, one config per provider, EXIT_IF's default, the refusals and
// the provider a start comes back on.

// multiFixture is the native overlay fixture as a multi-provider exit of
// ids, starting on start, each provider's config in <provider>.conf.
func multiFixture(t *testing.T, ids []string, start string) *fixture {
	t.Helper()
	f := newFixture(t)
	if err := os.Remove(filepath.Join(f.dir, "wg_confs", "mullvad.conf")); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		f.writeConf(t, id, testConfs[id])
	}
	f.env["PROVIDERS"] = strings.Join(ids, ",")
	f.env["PROVIDER"] = start
	delete(f.env, "EXIT_IF")
	f.env["NB_EXTRA_IFACE_BLACKLIST"] = "vpn"
	return f
}

func (f *fixture) writeConf(t *testing.T, name, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "wg_confs", name+".conf"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) writeTunnelProvider(t *testing.T, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(f.dir, "state", "applier", "tunnel-provider.json"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAMultiProviderExitLoadsEveryProvidersConfig(t *testing.T) {
	f := multiFixture(t, []string{"mullvad", "pia", "nordvpn"}, "pia")
	f.writeConf(t, "extra", "x")
	s, err := f.load()
	if err != nil {
		t.Fatal(err)
	}
	if !s.MultiProvider() || !reflect.DeepEqual(s.Providers, []string{"mullvad", "pia", "nordvpn"}) ||
		s.Provider != "pia" || s.StartProvider != "pia" {
		t.Fatalf("providers %v provider %s start %s", s.Providers, s.Provider, s.StartProvider)
	}
	if s.Conf != nil || len(s.Confs) != 3 {
		t.Fatalf("conf %v confs %v", s.Conf, s.Confs)
	}
	// Each config parsed with its own provider's grammar.
	for id, want := range map[string]string{"mullvad": "an IPv4 address", "pia": "no address (the exit sets it)", "nordvpn": "an IPv4 address"} {
		c := s.ConfOf(id)
		if c == nil || string(c.Provider) != id || c.Families() != want {
			t.Errorf("%s: %v", id, c)
		}
	}
	if s.ConfOf("gluetun-mullvad") != nil {
		t.Error("a provider outside the set has a config")
	}
	// One interface, vpn by default, in the environment every child sees.
	if s.Routing.ExitIf != "vpn" || s.Env["EXIT_IF"] != "vpn" {
		t.Fatalf("exit_if %s env %q", s.Routing.ExitIf, s.Env["EXIT_IF"])
	}
	if _, set := f.env["EXIT_IF"]; set {
		t.Error("the caller's environment was changed")
	}
	if !contains(CleanupEnv(s.Env), "EXIT_IF=vpn") {
		t.Errorf("cleanup %v", CleanupEnv(s.Env))
	}
	// Only extra.conf is another config; the providers' are the exit's.
	if s.OtherConfs != 1 {
		t.Errorf("other confs %d", s.OtherConfs)
	}
	if got := strings.Join(s.ConfNames(), ","); got != "mullvad.conf,pia.conf,nordvpn.conf" {
		t.Errorf("names %s", got)
	}
}

func TestAMultiProviderExitKeepsAnExplicitInterfaceName(t *testing.T) {
	f := multiFixture(t, []string{"mullvad", "nordvpn"}, "mullvad")
	f.env["EXIT_IF"] = "tun-exit"
	f.env["NB_EXTRA_IFACE_BLACKLIST"] = "tun-exit"
	s, err := f.load()
	if err != nil {
		t.Fatal(err)
	}
	if s.Routing.ExitIf != "tun-exit" || len(s.Confs) != 2 {
		t.Fatalf("%s %v", s.Routing.ExitIf, s.Confs)
	}
	// The interface's own name is not a config the exit reads.
	f.writeConf(t, "tun-exit", mullvadConf)
	if s, err = f.load(); err != nil || s.OtherConfs != 1 {
		t.Fatalf("%v %d", err, s.OtherConfs)
	}
}

func TestAMultiProviderExitStartsOnTheLastActiveProvider(t *testing.T) {
	ids := []string{"mullvad", "pia", "nordvpn"}
	for _, c := range []struct{ file, want string }{
		{`{"provider":"nordvpn"}`, "nordvpn"},
		{`{"provider":"pia"}`, "pia"},
		{`{"provider":"gluetun-mullvad"}`, "mullvad"},
		{`{"provider":"nordvpn","extra":1}`, "mullvad"},
		{`["nordvpn"]`, "mullvad"},
		{`not json`, "mullvad"},
	} {
		f := multiFixture(t, ids, "mullvad")
		f.writeTunnelProvider(t, c.file)
		s, err := f.load()
		if err != nil {
			t.Fatal(err)
		}
		if s.StartProvider != c.want || s.Provider != "mullvad" {
			t.Errorf("%s: start %s provider %s", c.file, s.StartProvider, s.Provider)
		}
	}
	// A provider no longer in PROVIDERS is ignored.
	f := multiFixture(t, []string{"mullvad", "pia"}, "pia")
	f.writeTunnelProvider(t, `{"provider":"nordvpn"}`)
	if s, err := f.load(); err != nil || s.StartProvider != "pia" {
		t.Fatalf("%v %v", err, s)
	}
	// PRIVATE_STATE_DIR is where the applier keeps it.
	f = multiFixture(t, ids, "mullvad")
	private := filepath.Join(f.dir, "private")
	if err := os.Mkdir(private, 0o700); err != nil {
		t.Fatal(err)
	}
	f.env["PRIVATE_STATE_DIR"] = private
	f.writeTunnelProvider(t, `{"provider":"pia"}`)
	if err := os.WriteFile(filepath.Join(private, "tunnel-provider.json"), []byte(`{"provider":"nordvpn"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, err := f.load(); err != nil || s.StartProvider != "nordvpn" {
		t.Fatalf("%v %v", err, s)
	}
}

func TestMultiProviderRefusals(t *testing.T) {
	cases := []struct {
		name string
		edit func(f *fixture)
		want string
	}{
		{"gluetun backend", func(f *fixture) { f.env["TUNNEL_BACKEND"] = "gluetun" }, "PROVIDERS needs TUNNEL_BACKEND=native"},
		{"sidecar", func(f *fixture) { f.env["EXIT_KIND"] = "sidecar" }, "PROVIDERS is for the overlay exit"},
		{"gluetun provider", func(f *fixture) { f.env["PROVIDERS"] = "mullvad,gluetun-mullvad" }, "native providers only"},
		{"one provider", func(f *fixture) { f.env["PROVIDERS"] = "mullvad" }, "two or three"},
		{"repeat", func(f *fixture) { f.env["PROVIDERS"] = "mullvad,mullvad" }, "two or three"},
		{"unknown", func(f *fixture) { f.env["PROVIDERS"] = "mullvad,example" }, "two or three"},
		{"empty member", func(f *fixture) { f.env["PROVIDERS"] = "mullvad,,pia" }, "two or three"},
		{"four", func(f *fixture) { f.env["PROVIDERS"] = "mullvad,pia,nordvpn,mullvad" }, "two or three"},
		{"too long", func(f *fixture) { f.env["PROVIDERS"] = "mullvad," + strings.Repeat(" ", 80) + "pia" }, "two or three"},
		{"no provider", func(f *fixture) { delete(f.env, "PROVIDER") }, "PROVIDER is required with PROVIDERS"},
		{"provider outside", func(f *fixture) { f.env["PROVIDERS"] = "pia,nordvpn" }, "PROVIDER must be one of PROVIDERS"},
		{"failover", func(f *fixture) { f.env["FAILOVER"] = "on" }, "FAILOVER is for single-provider exits"},
		{"failover servers", func(f *fixture) { f.env["FAILOVER"] = "same-city" }, "FAILOVER is for single-provider exits"},
		{"missing config", func(f *fixture) { _ = os.Remove(filepath.Join(f.dir, "wg_confs", "nordvpn.conf")) }, "nordvpn.conf is missing"},
		{"another provider's config", func(f *fixture) { f.writeConf(t, "pia", mullvadConf) }, "pia.conf is not supported"},
		{"exchange", func(f *fixture) {
			f.env["EXCHANGE_URL"] = "https://exchange.example.net/"
			f.env["EXCHANGE_EXIT_ID"] = "exit-1"
			f.env["EXCHANGE_TOKEN"] = strings.Repeat("t", 32)
		}, "EXCHANGE_URL is not supported on a multi-provider exit"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := multiFixture(t, []string{"mullvad", "pia", "nordvpn"}, "mullvad")
			c.edit(f)
			_, err := f.load()
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			if !strings.HasPrefix(err.Error(), prefix) {
				t.Errorf("not a refusal line: %v", err)
			}
		})
	}
	// FAILOVER=off is no failover, and accepted.
	f := multiFixture(t, []string{"mullvad", "pia"}, "mullvad")
	f.env["FAILOVER"] = "off"
	if _, err := f.load(); err != nil {
		t.Fatal(err)
	}
	// An empty PROVIDERS, as Compose passes an unset variable, is a
	// single-provider exit.
	f = newFixture(t)
	f.env["PROVIDERS"] = ""
	if s, err := f.load(); err != nil || s.MultiProvider() || s.Conf == nil {
		t.Fatalf("%v %v", err, s)
	}
}

func TestAMultiProviderStartingRecord(t *testing.T) {
	ids := []string{"mullvad", "pia", "nordvpn"}
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	for _, start := range ids {
		f := multiFixture(t, ids, "mullvad")
		f.env["PIA_PORT_FORWARD"] = "true"
		f.writeTunnelProvider(t, `{"provider":"`+start+`"}`)
		s, err := f.load()
		if err != nil {
			t.Fatal(err)
		}
		rec := StartingRecord(s, at)
		if rec["provider"] != start || !reflect.DeepEqual(rec["providers"], []any{"mullvad", "pia", "nordvpn"}) ||
			rec["requested_provider"] != nil || rec["selection"].(map[string]any)["target_provider"] != nil {
			t.Fatalf("%s: %v", start, rec)
		}
		if _, ok := rec["requested_provider"]; !ok {
			t.Errorf("%s: no requested_provider", start)
		}
		_, forward := rec["port_forward"]
		if forward != (start == "pia") {
			t.Errorf("%s: port_forward %v", start, rec["port_forward"])
		}
		// Published in the order every reader orders it, and a reader of
		// this exit judges it unknown, as a starting record.
		ordered := verdict.OrderRecord(rec, "overlay", "native")
		raw, err := validate.MarshalJSON(ordered)
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, p := range ordered {
			keys = append(keys, p.Key)
		}
		if !strings.HasPrefix(strings.Join(keys, ","), "schema,kind,backend,provider,providers,status,message,checked_at,server,requested_server,requested_provider,configured_server,request_id,selection,") {
			t.Errorf("%s: %v", start, keys)
		}
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatal(err)
		}
		exit, err := verdict.NewMultiExitConfig(ids, "mullvad", "overlay", "")
		if err != nil {
			t.Fatal(err)
		}
		if v := verdict.Assess(exit, rec, verdict.TargetFor(exit, rec, nil), at); v.State != "unknown" {
			t.Errorf("%s: %+v", start, v)
		}
		// A single-provider reader says provider mismatch.
		single, _ := verdict.NewExitConfig(start, "overlay", "")
		if v := verdict.Assess(single, rec, verdict.TargetForPanel(rec, nil, start), at); v.Label != "provider mismatch" {
			t.Errorf("%s single reader: %+v", start, v)
		}
		// The supervisor accepts it as this exit's.
		sup := &Supervisor{s: s}
		if err := sup.checkRecord(rec); err != nil {
			t.Errorf("%s: %v", start, err)
		}
	}
}

func TestTheSupervisorAcceptsOnlyThisExitsProviders(t *testing.T) {
	f := multiFixture(t, []string{"mullvad", "nordvpn"}, "mullvad")
	s, err := f.load()
	if err != nil {
		t.Fatal(err)
	}
	sup := &Supervisor{s: s}
	good := StartingRecord(s, time.Now())
	if err := sup.checkRecord(good); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(map[string]any){
		"provider outside":   func(r map[string]any) { r["provider"] = "pia" },
		"no providers":       func(r map[string]any) { delete(r, "providers") },
		"providers reorderd": func(r map[string]any) { r["providers"] = []any{"nordvpn", "mullvad"} },
		"providers more":     func(r map[string]any) { r["providers"] = []any{"mullvad", "nordvpn", "pia"} },
		"providers string":   func(r map[string]any) { r["providers"] = "mullvad,nordvpn" },
	} {
		rec := StartingRecord(s, time.Now())
		edit(rec)
		if err := sup.checkRecord(rec); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A single-provider exit's supervisor refuses a multi-provider record
	// of another provider, as before.
	single, err := newFixture(t).load()
	if err != nil {
		t.Fatal(err)
	}
	good["provider"] = "nordvpn"
	if err := (&Supervisor{s: single}).checkRecord(good); err == nil {
		t.Error("a single-provider supervisor accepted another provider's record")
	}
}
