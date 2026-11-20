// A single-provider exit's settings, child environments and starting record
// stay byte for byte as they were before multi-provider exits
// (docs/design/multi-provider.md, rule 2), for each native provider and
// with EXIT_IF set or left to its default. The applier's files and records
// are locked by internal/applier/single_provider_test.go and its golden
// records; this locks what the exit itself derives from its settings. The
// golden (testdata/single_provider_exit_golden.json) was generated before
// PROVIDERS existed and is never regenerated to make a change pass.
package exit

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/validate"
)

var updateSingleExit = flag.Bool("update-single-provider-exit", false, "rewrite testdata/single_provider_exit_golden.json")

const piaTestConf = "[Interface]\nPrivateKey = " + zeroKey + "\nMTU = 1420\nTable = off\n" +
	"PostUp = ip route replace default dev %i table 51821\nPreDown = ip route del default dev %i table 51821\n"

const nordTestConf = "[Interface]\nPrivateKey = " + zeroKey + "\nAddress = 10.5.0.2/32\nMTU = 1420\nTable = off\n" +
	"PostUp = ip route replace default dev %i table 51821\nPreDown = ip route del default dev %i table 51821\n"

var testConfs = map[string]string{"mullvad": mullvadConf, "pia": piaTestConf, "nordvpn": nordTestConf}

// singleExitView is what the exit derives from a single-provider
// environment, with the fixture's directory replaced by <dir>.
func singleExitView(t *testing.T, provider string, exitIfSet bool) map[string]any {
	t.Helper()
	f := newFixture(t)
	exitIf := "mullvad"
	if exitIfSet {
		exitIf = provider
		f.env["EXIT_IF"] = provider
		f.env["NB_EXTRA_IFACE_BLACKLIST"] = provider
	} else {
		delete(f.env, "EXIT_IF")
	}
	f.env["PROVIDER"] = provider
	if err := os.WriteFile(filepath.Join(f.dir, "wg_confs", exitIf+".conf"), []byte(testConfs[provider]), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "wg_confs", "extra.conf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.env["PIA_PORT_FORWARD"] = "true"
	f.env["EXCHANGE_URL"] = "https://exchange.example.net/"
	f.env["EXCHANGE_EXIT_ID"] = "exit-1"
	f.env["EXCHANGE_TOKEN"] = strings.Repeat("t", 32)
	s, err := f.load()
	if err != nil {
		t.Fatalf("%s: %v", provider, err)
	}
	clean := func(v string) string { return strings.ReplaceAll(v, f.dir, "<dir>") }
	cleanAll := func(list []string) []any {
		out := []any{}
		for _, v := range list {
			out = append(out, clean(v))
		}
		return out
	}
	starting, err := validate.MarshalJSON(StartingRecord(s, time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"provider":        s.Provider,
		"exit_if":         s.Routing.ExitIf,
		"conf":            fmt.Sprintf("%s families %s, owner %s", clean(s.ConfDir), s.Conf.Families(), s.Conf.RuleOwner()),
		"other_confs":     s.OtherConfs,
		"cleanup_env":     cleanAll(CleanupEnv(s.Env)),
		"exchange_env":    cleanAll(ExchangeEnv(s)),
		"starting_record": clean(string(starting)),
	}
}

func TestSingleProviderExitStaysByteForByte(t *testing.T) {
	got := map[string]any{}
	for _, provider := range []string{"mullvad", "pia", "nordvpn"} {
		for _, set := range []bool{true, false} {
			name := provider + "_exit_if_default"
			if set {
				name = provider + "_exit_if_set"
			}
			got[name] = singleExitView(t, provider, set)
		}
	}
	path := filepath.Join("testdata", "single_provider_exit_golden.json")
	gotRaw, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if *updateSingleExit {
		if err := os.WriteFile(path, append(gotRaw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != string(gotRaw)+"\n" {
		var golden map[string]any
		if err := json.Unmarshal(want, &golden); err != nil {
			t.Fatal(err)
		}
		for name, v := range got {
			a, _ := json.Marshal(v)
			b, _ := json.Marshal(golden[name])
			if string(a) != string(b) {
				t.Errorf("%s:\n got %s\nwant %s", name, a, b)
			}
		}
		t.Error("the single-provider exit changed")
	}
}
