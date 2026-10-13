// Tests for molebridge/state.py. The golden files were generated from
// 0.7.0's Python implementation at commit d553f25 (run on the same inputs) and are
// now fixed. Ported: test_request_names_are_provider_
// specific (tools/test_pia.py), the egress_tier checks of tools/test_egress.py
// (test_tunnel_tier_counts_only_for_a_provider_without_its_own_check and
// test_provider_tier_keeps_meaning_provider_confirmed; their status_view
// halves are in internal/verdict), test_invalid_unicode_setting_keeps_status_
// bounded_and_readable (tools/test_server_setting.py; its applier half is the
// applier port's), and the read/write checks of tools/test_runtime.py and
// tools/test_providers.py, which internal/jsonfile carries in full.
package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

func decode(t testing.TB, text string) any {
	t.Helper()
	v, err := validate.DecodeJSONString(text)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestConfiguredServerMatchesPython(t *testing.T) {
	raw, err := os.ReadFile("testdata/configured_server_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Input  string  `json:"input"`
		Output *string `json:"output"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 300 {
		t.Fatalf("%d cases", len(cases))
	}
	for _, c := range cases {
		value := decode(t, c.Input)
		got, ok := ConfiguredServer(map[string]any{"configured_server": value})
		if c.Output == nil {
			if ok {
				t.Errorf("%q: got %q, Python has none", c.Input, got)
			}
			continue
		}
		if !ok || got != *c.Output {
			t.Errorf("%.60q:\n got %q (%v)\nwant %q", c.Input, got, ok, *c.Output)
		}
	}
}

func TestConfiguredServerBounds(t *testing.T) {
	for _, bad := range []any{nil, "x", []any{}, map[string]any{}, map[string]any{"configured_server": nil},
		map[string]any{"configured_server": ""}, map[string]any{"configured_server": int64(5)}, map[string]any{"other": "x"}} {
		if got, ok := ConfiguredServer(bad); ok {
			t.Errorf("%#v -> %q", bad, got)
		}
	}
	// The emoji status stays bounded and readable.
	got, ok := ConfiguredServer(map[string]any{"configured_server": strings.Repeat("😀", 4096)})
	if !ok || validate.RuneCount(got) != 256 {
		t.Errorf("%d characters", validate.RuneCount(got))
	}
	// An escaped name is shown escaped, and it is still a lock.
	if got, _ := ConfiguredServer(map[string]any{"configured_server": "a\x00b\xed\xa0\x80"}); got != `a\x00b\ud800` {
		t.Errorf("%q", got)
	}
}

func TestDesiredRequestMatchesPython(t *testing.T) {
	raw, err := os.ReadFile("testdata/desired_request_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Input    json.RawMessage `json:"input"`
		Provider string          `json:"provider"`
		Output   json.RawMessage `json:"output"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for _, c := range cases {
		input := decode(t, string(c.Input))
		got, ok := DesiredRequest(input, c.Provider)
		if string(c.Output) == "null" {
			if ok {
				t.Errorf("%s / %s: accepted %+v", c.Input, c.Provider, got)
			}
			continue
		}
		accepted++
		want := decode(t, string(c.Output)).(map[string]any)
		if !ok || got.Server != want["server"] || got.RequestedAt != want["requested_at"] {
			t.Errorf("%s / %s: %+v %v", c.Input, c.Provider, got, ok)
			continue
		}
		if id, _ := want["request_id"].(string); got.RequestID != id {
			t.Errorf("%s / %s: id %q", c.Input, c.Provider, got.RequestID)
		}
	}
	if accepted < 10 {
		t.Errorf("only %d accepted requests in the golden file", accepted)
	}
}

func req(server, id string) map[string]any {
	m := map[string]any{"server": server, "requested_at": NowISO()}
	if id != "" {
		m["request_id"] = id
	}
	return m
}

func TestRequestNamesAreProviderSpecific(t *testing.T) {
	if _, ok := DesiredRequest(req("ex_example", strings.Repeat("1", 32)), "pia"); !ok {
		t.Error("pia rejects its region")
	}
	if _, ok := DesiredRequest(req("ex_example", strings.Repeat("1", 32)), "mullvad"); ok {
		t.Error("mullvad accepts a PIA region")
	}
	if _, ok := DesiredRequest(req("se-sto-wg-001", strings.Repeat("1", 32)), "mullvad"); !ok {
		t.Error("mullvad rejects its relay")
	}
	if _, ok := DesiredRequest(req("Bad", ""), "pia"); ok {
		t.Error("an upper-case name")
	}
}

func TestRequestTokenAndObject(t *testing.T) {
	r, ok := DesiredRequest(map[string]any{"server": "se-sto-wg-001", "requested_at": "2026-10-11T12:00:00Z"}, "mullvad")
	if !ok || RequestToken(r) != "se-sto-wg-001@2026-10-11T12:00:00Z" {
		t.Errorf("%+v", r)
	}
	raw, _ := validate.MarshalJSON(r)
	if string(raw) != `{"server": "se-sto-wg-001", "requested_at": "2026-10-11T12:00:00Z"}` {
		t.Errorf("%s", raw)
	}
	r.RequestID = strings.Repeat("a", 32)
	raw, _ = validate.MarshalJSON(r)
	if RequestToken(r) != r.RequestID || string(raw) != `{"server": "se-sto-wg-001", "requested_at": "2026-10-11T12:00:00Z", "request_id": "`+r.RequestID+`"}` {
		t.Errorf("%s", raw)
	}
}

func TestEgressTier(t *testing.T) {
	// A made-up registry entry for a provider without a typed egress check.
	spec := providers.Clone("mullvad")
	spec.ID, spec.Label, spec.EgressTier = "tunnelvpn", "Tunnel Example", providers.TierTunnel
	restore := providers.Replace(spec)
	defer restore()
	okResult := func(changes map[string]any) map[string]any {
		m := map[string]any{"status": "ok", "checked_at": NowISO(), "routing_ok": true, "netbird_native": true,
			"server": "se-sto-wg-001", "exit_confirmed": false, "egress_tier": "tunnel"}
		for k, v := range changes {
			m[k] = v
		}
		return m
	}
	if EgressTier(okResult(nil), "tunnelvpn") != "tunnel" {
		t.Error("tunnel tier for tunnelvpn")
	}
	for _, provider := range []string{"mullvad", "pia", "examplevpn"} {
		if got := EgressTier(okResult(nil), provider); got != "" {
			t.Errorf("%s: %q", provider, got)
		}
	}
	for _, tier := range []any{nil, "TUNNEL", "provider", 5} {
		if got := EgressTier(okResult(map[string]any{"egress_tier": tier}), "tunnelvpn"); got != "" {
			t.Errorf("egress_tier=%v: %q", tier, got)
		}
	}
	for _, provider := range []string{"mullvad", "pia", "tunnelvpn"} {
		if got := EgressTier(okResult(map[string]any{"exit_confirmed": true, "egress_tier": "provider"}), provider); got != "provider" {
			t.Errorf("%s: %q", provider, got)
		}
	}
	// Results written before tiers existed.
	if EgressTier(map[string]any{"exit_confirmed": true}, "mullvad") != "provider" ||
		EgressTier(map[string]any{"mullvad_exit_ip": true}, "mullvad") != "provider" ||
		EgressTier(map[string]any{"exit_confirmed": false, "mullvad_exit_ip": true}, "mullvad") != "" {
		t.Error("legacy confirmation")
	}
	if ExitConfirmed(map[string]any{"exit_confirmed": 1}) || ExitConfirmed(map[string]any{}) {
		t.Error("only a true confirms")
	}
}

func TestTimesAndConstants(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	if age, ok := AgeSeconds("2026-10-11T11:59:50Z", now); !ok || age != 10 {
		t.Errorf("%v %v", age, ok)
	}
	if !Recent("2026-10-11T11:57:30Z", StatusMaxAge, now) || Recent("2026-10-11T11:57:29Z", StatusMaxAge, now) || Recent("2026-10-11T12:00:01Z", StatusMaxAge, now) {
		t.Error("Recent")
	}
	if StatusMaxAge != 150 || SwitchTimeouts["native"] != 60 || SwitchTimeouts["gluetun"] != 90 || CatalogMaxAge != 86400 || MaxCatalogBytes != 10<<20 {
		t.Error("constants")
	}
	if got := NowISO(); len(got) != 20 || !strings.HasSuffix(got, "Z") {
		t.Errorf("NowISO = %q", got)
	}
	if id, err := ProviderFromEnv(func(string) string { return "" }); err != nil || id != "mullvad" {
		t.Errorf("%q %v", id, err)
	}
	if _, err := ProviderFromEnv(func(string) string { return "nope" }); err == nil {
		t.Error("unknown provider")
	}
}

func TestFileHelpersAreTheSharedOnes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a", "b.json")
	if err := WriteJSONAtomic(path, validate.Members("x", int64(1)), true, 1000); err != nil {
		t.Fatal(err)
	}
	if m, ok := ReadObject(path, 1000); !ok || m["x"] != int64(1) {
		t.Errorf("%v", m)
	}
	if ReadJSON(path, 5) != nil {
		t.Error("limit ignored")
	}
	if err := WriteJSONAtomic(path, strings.Repeat("y", 100), false, 50); err != ErrSizeLimit {
		t.Errorf("got %v", err)
	}
	if ReadJSON(path, 1000) == nil {
		t.Error("the old file must stay")
	}
	if !ValidServerName("se-sto-wg-001", "mullvad") || ValidServerName("se-sto-wg-001", "nope") || ValidServerName(5, "mullvad") {
		t.Error("ValidServerName")
	}
}
