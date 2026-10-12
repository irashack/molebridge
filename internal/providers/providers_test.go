// Tests for molebridge/providers.py, ported from tools/test_providers.py:
// test_registry_ids_and_lookup, test_every_entry_is_complete (the registry
// half; the applier half needs the applier port), test_mullvad_and_pia_keep_
// their_settings, test_nordvpn_entry_is_mullvad_shaped_ipv4_only_with_its_own_
// cap, and the compatibility-name checks that survive. The applier tests in
// that file (fetch parameters, address model, main(), routing init) and
// state.PROVIDERS and friends (which Go has only here) are not ported.
package providers

import (
	"regexp"
	"strings"
	"testing"
)

func TestRegistryIDsAndLookup(t *testing.T) {
	ids := IDs()
	if ids[0] != "mullvad" || ids[1] != "pia" || ids[2] != "nordvpn" {
		t.Errorf("order: %v", ids)
	}
	if want := "mullvad,pia,nordvpn,gluetun-fastestvpn,gluetun-ivpn,gluetun-mullvad,gluetun-nordvpn,gluetun-surfshark,gluetun-windscribe"; strings.Join(ids, ",") != want {
		t.Errorf("ids = %v", ids)
	}
	native := regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)
	for _, key := range ids {
		spec, err := Get(key)
		if err != nil || spec.ID != key {
			t.Fatalf("%s: %v", key, err)
		}
		if spec.Backend == BackendNative {
			if !native.MatchString(key) {
				t.Errorf("native id %q", key)
			}
		} else if spec.Backend != BackendGluetun || key != "gluetun-"+spec.GluetunProvider {
			t.Errorf("gluetun id %q", key)
		}
		if again, ok := Lookup(key); !ok || again != spec {
			t.Errorf("Lookup(%s)", key)
		}
	}
	getenv := func(env map[string]string) func(string) string { return func(k string) string { return env[k] } }
	for _, env := range []map[string]string{{}, {"PROVIDER": ""}} {
		if p, err := FromEnv(getenv(env)); err != nil || p.ID != "mullvad" {
			t.Errorf("FromEnv(%v) = %v %v", env, p, err)
		}
	}
	if p, err := FromEnv(getenv(map[string]string{"PROVIDER": "pia"})); err != nil || p.ID != "pia" {
		t.Error("FromEnv pia")
	}
	for _, bad := range []string{"examplevpn", "Mullvad", " pia"} {
		_, err := Get(bad)
		if err == nil || !strings.HasPrefix(err.Error(), "PROVIDER must be one of: mullvad, pia, nordvpn") {
			t.Errorf("Get(%q): %v", bad, err)
		}
		if _, err := FromEnv(getenv(map[string]string{"PROVIDER": bad})); err == nil {
			t.Errorf("FromEnv(%q)", bad)
		}
	}
	if got := Native(); strings.Join(got, ",") != "mullvad,pia,nordvpn" {
		t.Errorf("Native() = %v", got)
	}
}

func TestEveryEntryIsComplete(t *testing.T) {
	color := regexp.MustCompile(`^#[0-9a-f]{6}$`)
	for _, key := range IDs() {
		spec, _ := Get(key)
		if spec.Label == "" || (spec.EgressTier != TierProvider && spec.EgressTier != TierTunnel) ||
			(spec.Layout != "tree" && spec.Layout != "regions") {
			t.Errorf("%s: %+v", key, spec)
		}
		if spec.Backend == BackendNative {
			if !strings.HasPrefix(spec.CatalogURL, "https://") {
				t.Errorf("%s: catalogue URL %q", key, spec.CatalogURL)
			}
		} else {
			// The gluetun backend reads gluetun's own list and downloads nothing.
			if spec.CatalogURL != "" || spec.Note != "via gluetun" {
				t.Errorf("%s: %q %q", key, spec.CatalogURL, spec.Note)
			}
			if _, err := spec.ParseCatalog([]byte("{}"), false); err == nil {
				t.Errorf("%s: parsed a download", key)
			}
		}
		if spec.CatalogMaxBytes <= 0 || spec.CatalogTimeoutS <= 0 || spec.SnapshotMaxBytes <= 0 {
			t.Errorf("%s: limits", key)
		}
		for _, path := range spec.SecretFiles {
			if strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
				t.Errorf("%s: secret path %q", key, path)
			}
		}
		allowed := map[string]bool{"owned": true, "stboot": true, "port_forward": true, "geo": true, "virtual": true}
		for _, b := range spec.Badges {
			if !allowed[b.Attribute] || b.Text == "" || b.Title == "" {
				t.Errorf("%s: badge %+v", key, b)
			}
		}
		for _, f := range spec.Filters {
			if !allowed[f.Attribute] || f.Label == "" {
				t.Errorf("%s: filter %+v", key, f)
			}
		}
		for _, c := range spec.ThemeColors {
			if !color.MatchString(c) {
				t.Errorf("%s: colour %q", key, c)
			}
		}
		if spec.ValidateEntry == nil || spec.ChipLabel == nil || spec.Details == nil || spec.ServerNamePattern == "" {
			t.Errorf("%s: missing hook", key)
		}
		if spec.CSSID() == "" {
			t.Errorf("%s: no css id", key)
		}
	}
}

func TestMullvadAndPIAKeepTheirSettings(t *testing.T) {
	mullvad, _ := Get("mullvad")
	pia, _ := Get("pia")
	if mullvad.Label != "Mullvad" || !mullvad.AddressBeforeSwitch || !mullvad.IPv6 || mullvad.Layout != "tree" {
		t.Errorf("%+v", mullvad)
	}
	if pia.Label != "PIA" || pia.AddressBeforeSwitch || pia.IPv6 || pia.Layout != "regions" || !pia.RegistrationLapses || mullvad.RegistrationLapses {
		t.Errorf("%+v", pia)
	}
	if mullvad.CatalogURL != "https://api.mullvad.net/app/v1/relays" || pia.CatalogURL != "https://serverlist.piaservers.net/vpninfo/servers/v6" {
		t.Error("URLs")
	}
	if mullvad.CatalogMaxBytes != 10*1024*1024 || pia.CatalogMaxBytes != 10*1024*1024 || mullvad.CatalogTimeoutS != 20 || pia.CatalogTimeoutS != 20 {
		t.Error("limits")
	}
	if mullvad.EgressTier != "provider" || pia.EgressTier != "provider" {
		t.Error("tiers")
	}
	if strings.Join(pia.SecretFiles, ",") != "secrets/pia/username,secrets/pia/password" || len(mullvad.SecretFiles) != 0 {
		t.Error("secret files")
	}
	if mullvad.ChipLabel("se-sto-wg-001") != "wg-001" {
		t.Error("chip label")
	}
	if len(mullvad.Filters) != 2 || mullvad.Filters[0] != (Filter{"owned", "Mullvad-owned"}) || mullvad.Filters[1] != (Filter{"stboot", "RAM-only"}) {
		t.Errorf("filters %+v", mullvad.Filters)
	}
	if len(pia.Badges) != 2 || pia.Badges[0] != (Badge{"port_forward", "PF", "Port forwarding"}) || pia.Badges[1] != (Badge{"geo", "virtual", "Virtual location"}) {
		t.Errorf("badges %+v", pia.Badges)
	}
}

func TestNordVPNEntryIsMullvadShapedIPv4OnlyWithItsOwnCap(t *testing.T) {
	spec, _ := Get("nordvpn")
	if spec.Label != "NordVPN" || !spec.AddressBeforeSwitch || spec.IPv6 || spec.Layout != "tree" || spec.EgressTier != "provider" || len(spec.SecretFiles) != 0 {
		t.Errorf("%+v", spec)
	}
	if spec.CatalogURL != NordServersURL || spec.CatalogMaxBytes != NordMaxCatalogBytes || NordMaxCatalogBytes != 32*1024*1024 || spec.CatalogTimeoutS != 60 {
		t.Error("catalogue settings")
	}
	if !spec.ValidServerName("us9001.nordvpn.com") || !spec.ValidServerName("uk-nl10.nordvpn.com") ||
		spec.ValidServerName("se-sto-wg-001") || spec.ValidServerName("us9001") {
		t.Error("server names")
	}
	if spec.ChipLabel("us9001.nordvpn.com") != "us9001" {
		t.Error("chip label")
	}
	// Only this provider's download cap grew.
	for _, id := range Native() {
		other, _ := Get(id)
		if id != "nordvpn" && other.CatalogMaxBytes != DefaultCatalogBytes {
			t.Errorf("%s: cap %d", id, other.CatalogMaxBytes)
		}
	}
}

func TestGluetunEntriesFollowTheirNativeProvider(t *testing.T) {
	for _, name := range GluetunSupportedProviders {
		spec, _ := Get("gluetun-" + name)
		native, hasNative := Lookup(name)
		if spec.Label != GluetunLabels[name] || spec.Style != "gluetun" || spec.CSSID() != "gluetun" || spec.Accent != name ||
			spec.AddressBeforeSwitch || spec.GluetunProvider != name || spec.SnapshotMaxBytes != 16*1024*1024 ||
			spec.CatalogMaxBytes != GluetunMaxCatalogBytes || strings.Join(spec.SecretFiles, ",") != "secrets/gluetun/api_key" {
			t.Errorf("%s: %+v", name, spec)
		}
		if hasNative && (spec.IPv6 != native.IPv6) {
			t.Errorf("%s: ipv6", name)
		}
		if !hasNative && spec.IPv6 {
			t.Errorf("%s: ipv6 without a native provider", name)
		}
		wantTier, wantCheck := "tunnel", ""
		if name == "mullvad" || name == "nordvpn" {
			wantTier, wantCheck = "provider", name
		}
		if spec.EgressTier != wantTier || spec.EgressCheck != wantCheck {
			t.Errorf("%s: %s %s", name, spec.EgressTier, spec.EgressCheck)
		}
		if !spec.ValidServerName("relay.example.test") || spec.ValidServerName("Relay.example.test") {
			t.Errorf("%s: server names", name)
		}
	}
}

func TestServerNamesAreProviderSpecific(t *testing.T) {
	// From tools/test_pia.py test_request_names_are_provider_specific and
	// tools/test_server_setting.py's NAMES.
	names := map[string]string{"mullvad": "se-sto-wg-001", "pia": "ex_example", "nordvpn": "us9001.nordvpn.com", "gluetun-ivpn": "two.example.test"}
	for provider, good := range names {
		spec, _ := Get(provider)
		if !spec.ValidServerName(good) {
			t.Errorf("%s rejects %q", provider, good)
		}
		for _, bad := range []string{"", "--bad", good + "\n", "bad name", "<script>", strings.Repeat("x", 4096), "Bad", "../x"} {
			if bad != good && spec.ValidServerName(bad) {
				t.Errorf("%s accepts %q", provider, bad)
			}
		}
	}
	// ex_example is a PIA region id, not a Mullvad hostname, and the reverse.
	mullvad, _ := Get("mullvad")
	pia, _ := Get("pia")
	nord, _ := Get("nordvpn")
	if mullvad.ValidServerName("ex_example") || !pia.ValidServerName("ex_example") || nord.ValidServerName("ex_example") ||
		mullvad.ValidServerName("us9001.nordvpn.com") || pia.ValidServerName("us9001.nordvpn.com") {
		t.Error("names must be provider specific")
	}
	// A PIA region id is any short lower-case word, so a Mullvad hostname fits it too.
	if !pia.ValidServerName("se-sto-wg-001") {
		t.Error("pia region pattern")
	}
}

func TestReplaceRestores(t *testing.T) {
	before := IDs()
	trial := mustGet(t, "mullvad").Clone()
	trial.ID, trial.EgressTier = "tunnelvpn", TierTunnel
	restore := Replace(trial)
	if p, ok := Lookup("tunnelvpn"); !ok || p.EgressTier != TierTunnel || len(IDs()) != len(before)+1 {
		t.Error("not registered")
	}
	restore()
	if _, ok := Lookup("tunnelvpn"); ok || strings.Join(IDs(), ",") != strings.Join(before, ",") {
		t.Errorf("not restored: %v", IDs())
	}
	// Replacing an existing entry keeps its place and restores it.
	changed := mustGet(t, "pia").Clone()
	changed.Label = "Changed"
	restore = Replace(changed)
	if mustGet(t, "pia").Label != "Changed" || strings.Join(IDs(), ",") != strings.Join(before, ",") {
		t.Error("replace")
	}
	restore()
	if mustGet(t, "pia").Label != "PIA" {
		t.Error("restore")
	}
}

func mustGet(t testing.TB, id string) *Provider {
	t.Helper()
	p, err := Get(id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSnapshotLimitsComeFromTheRegistry(t *testing.T) {
	if SnapshotLimit("mullvad") != DefaultCatalogBytes || SnapshotLimit("pia") != DefaultCatalogBytes ||
		SnapshotLimit("nordvpn") != 16*1024*1024 || SnapshotLimit("examplevpn") != DefaultCatalogBytes {
		t.Error("limits")
	}
	for _, id := range IDs() {
		if SnapshotLimit(id) != int64(mustGet(t, id).SnapshotMaxBytes) {
			t.Errorf("%s", id)
		}
	}
	if CatalogURL("pia") == "" || CatalogURL("examplevpn") != "" {
		t.Error("CatalogURL")
	}
}
