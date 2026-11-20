package verdict

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
)

// Multi-provider exits (docs/design/multi-provider.md, "The status record
// and the verdict"). testdata/multiprovider_golden.json holds records as a
// multi-provider exit writes them (providers mullvad, pia, nordvpn), each
// with the panel's request, the verdict a reader configured for that exit
// must give, and the verdict a reader from before multi-provider exits,
// configured for each single provider, gives.

type verdictWant struct {
	State   string   `json:"state"`
	Label   string   `json:"label"`
	Reasons []string `json:"reasons"`
}

type multiCase struct {
	Name       string          `json:"name"`
	Raw        json.RawMessage `json:"record"`
	RawDesired json.RawMessage `json:"desired"`
	Record     map[string]any  `json:"-"`
	Desired    any             `json:"-"`
	Want       verdictWant     `json:"want"`
	// Old is by the single provider the old reader is configured for.
	Old map[string]verdictWant `json:"old"`
}

func multiGolden(t *testing.T) ([]string, []multiCase) {
	t.Helper()
	raw, err := os.ReadFile("testdata/multiprovider_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Providers []string    `json:"providers"`
		Cases     []multiCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Cases) < 15 {
		t.Fatalf("%d cases", len(file.Cases))
	}
	for i := range file.Cases {
		c := &file.Cases[i]
		record, err := validate.DecodeJSON(c.Raw)
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		c.Record = record.(map[string]any)
		if c.Desired, err = validate.DecodeJSON(c.RawDesired); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if len(c.Old) != 3 {
			t.Fatalf("%s: old readers %v", c.Name, c.Old)
		}
	}
	return file.Providers, file.Cases
}

func same3(v Verdict, w verdictWant) bool {
	return v.State == w.State && v.Label == w.Label && reflect.DeepEqual(v.Reasons, w.Reasons)
}

func TestMultiProviderGoldenRecords(t *testing.T) {
	ids, cases := multiGolden(t)
	reasons := map[string]bool{}
	for _, c := range cases {
		// Whichever provider the reader's own PROVIDER names: it is only
		// where the exit started.
		for _, start := range ids {
			exit, err := NewMultiExitConfig(ids, start, "overlay", "")
			if err != nil {
				t.Fatal(err)
			}
			v := Assess(exit, c.Record, TargetFor(exit, c.Record, c.Desired), now)
			if !same3(v, c.Want) {
				t.Errorf("%s (started on %s): got %s/%s %v, want %s/%s %v", c.Name, start, v.State, v.Label, v.Reasons,
					c.Want.State, c.Want.Label, c.Want.Reasons)
			}
			for _, r := range v.Reasons {
				reasons[r] = true
			}
		}
		// A single-provider reader today is configured wrongly for this
		// exit, and says so.
		for _, id := range ids {
			single, _ := NewExitConfig(id, "overlay", "")
			if v := Assess(single, c.Record, TargetForPanel(c.Record, c.Desired, id), now); v.Label != "provider mismatch" {
				t.Errorf("%s: a %s reader got %s/%s", c.Name, id, v.State, v.Label)
			}
		}
	}
	for _, r := range []string{"not-requested-provider", "not-configured-provider", "provider-mismatch"} {
		if !reasons[r] {
			t.Errorf("no golden record gives %s", r)
		}
	}
}

// withoutMultiProviderMembers is a record with the members a multi-provider
// exit adds taken out: the same evidence, as a single-provider exit writes
// it.
func withoutMultiProviderMembers(record map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range record {
		if k != "providers" && k != "requested_provider" {
			out[k] = v
		}
	}
	if selection, ok := record["selection"].(map[string]any); ok {
		trimmed := map[string]any{}
		for k, v := range selection {
			if k != "target_provider" {
				trimmed[k] = v
			}
		}
		out["selection"] = trimmed
	}
	return out
}

// TestOldReadersAreNeverMisledByAMultiProviderExit judges every golden record
// with the rules as they were before multi-provider exits (the provider
// match and the target agreement, copies below; the panel's request read by
// state.DesiredRequest, as it was) for a reader of each single provider, and
// requires the verdict recorded for it. Beyond the recorded verdicts: a
// record of another provider is always a provider mismatch, and a record
// of the reader's own provider gets exactly the verdict a single-provider
// exit's record with the same evidence gets today. So an old reader is
// never connected on another provider than its own, and never misled
// about its own.
func TestOldReadersAreNeverMisledByAMultiProviderExit(t *testing.T) {
	_, cases := multiGolden(t)
	judgedAs, agreement = judgedAsBeforeMultiProvider, targetDisagreementBeforeMultiProvider
	defer func() { judgedAs, agreement = judgedAsProvider, targetDisagreement }()
	type judged struct {
		name, reader string
		record       map[string]any
		desired      any
		got          Verdict
	}
	var all []judged
	for _, c := range cases {
		for reader, want := range c.Old {
			exit, err := NewExitConfig(reader, "overlay", "")
			if err != nil {
				t.Fatal(err)
			}
			v := Assess(exit, c.Record, TargetForPanel(c.Record, c.Desired, reader), now)
			if !same3(v, want) {
				t.Errorf("%s: an old %s reader got %s/%s %v, want %s/%s %v", c.Name, reader, v.State, v.Label, v.Reasons,
					want.State, want.Label, want.Reasons)
			}
			if c.Record["provider"] != reader && v.Label != "provider mismatch" {
				t.Errorf("%s: an old %s reader says %s/%s on %v's record", c.Name, reader, v.State, v.Label, c.Record["provider"])
			}
			all = append(all, judged{c.Name, reader, c.Record, c.Desired, v})
		}
	}
	// Today's rules, for the same evidence without the new members.
	judgedAs, agreement = judgedAsProvider, targetDisagreement
	for _, j := range all {
		if j.record["provider"] != j.reader {
			continue
		}
		exit, _ := NewExitConfig(j.reader, "overlay", "")
		plain := withoutMultiProviderMembers(j.record)
		v := Assess(exit, plain, TargetForPanel(plain, j.desired, j.reader), now)
		if v.State != j.got.State || v.Label != j.got.Label || !reflect.DeepEqual(v.Reasons, j.got.Reasons) {
			t.Errorf("%s: an old %s reader got %s/%s %v, a single-provider record with the same evidence %s/%s %v",
				j.name, j.reader, j.got.State, j.got.Label, j.got.Reasons, v.State, v.Label, v.Reasons)
		}
	}
}

// judgedAsBeforeMultiProvider is the provider match of Assess's rule 4 as it
// was before multi-provider exits (commit 5ec23cf).
func judgedAsBeforeMultiProvider(exit ExitConfig, record map[string]any) (ExitConfig, bool) {
	return exit, record["provider"] == exit.Provider && record["backend"] == exit.Backend()
}

// targetDisagreementBeforeMultiProvider is targetDisagreement, movedFrom,
// onBackup and failoverFor as they were before multi-provider exits (commit
// 5ec23cf), kept so the test above judges with a reader that doesn't know
// the new members.
func targetDisagreementBeforeMultiProvider(record map[string]any, target Target, selection map[string]any, configured string, hasConfigured bool) string {
	movedFrom := func(record map[string]any, requested string) bool {
		moved, ok := object(record["moved"])
		if !ok || requested == "" {
			return false
		}
		to, isString := moved["to"].(string)
		return isString && to != "" && moved["from"] == requested && record["server"] == to
	}
	onBackup := func(record, selection map[string]any) (string, bool) {
		member, isObject := object(record["failover"])
		if !isObject {
			return "", false
		}
		from, _ := member["from"].(string)
		to, _ := member["to"].(string)
		phase := member["phase"]
		if from == "" || to == "" || from == to || record["server"] != to || (phase != "on-backup" && phase != "trying") ||
			selection["source"] != "failover" {
			return "", false
		}
		return from, true
	}
	failoverFor := func(record, selection map[string]any, expected string) bool {
		from, ok := onBackup(record, selection)
		if !ok || expected == "" {
			return false
		}
		if from == expected {
			return true
		}
		moved, isObject := object(record["moved"])
		return isObject && moved["from"] == expected && moved["to"] == from
	}
	server := record["server"]
	if target.Source == "configured" || hasConfigured {
		expected := configured
		if target.Source == "configured" {
			expected = target.Server
		}
		if server == expected || movedFrom(record, expected) || failoverFor(record, selection, expected) {
			return ""
		}
		return "not-configured-server"
	}
	if target.Source == "panel" {
		if record["requested_server"] == target.Server && (server == target.Server || movedFrom(record, target.Server) ||
			failoverFor(record, selection, target.Server)) {
			return ""
		}
		return "not-requested-server"
	}
	if target.Server != "" {
		if server == target.Server || failoverFor(record, selection, target.Server) {
			return ""
		}
		return "not-target-server"
	}
	if source, isString := selection["source"].(string); isString && contains([]string{"restore", "reconverge", "retry", "operator-retry", "failover"}, source) {
		if same(server, selection["target"]) {
			return ""
		}
		return "not-target-server"
	}
	return ""
}

// -- the readers' configuration and the target ------------------------------------

var three = []string{"mullvad", "pia", "nordvpn"}

func multiRecord(t testing.TB, provider, server string, changes map[string]any) map[string]any {
	families := map[string][]string{"mullvad": {"4", "6"}, "pia": {"4"}, "nordvpn": {"4"}}[provider]
	r := record(t, opts{provider: provider, server: server, families: families}, map[string]any{
		"providers": []any{"mullvad", "pia", "nordvpn"}, "requested_provider": provider})
	r["selection"].(map[string]any)["target_provider"] = provider
	for k, v := range changes {
		r[k] = v
	}
	return settle(t, r).(map[string]any)
}

func multiRequest(provider, server string) any {
	return map[string]any{"provider": provider, "server": server, "requested_at": "2026-10-11T11:59:50Z", "request_id": requestIDHex}
}

func TestNewMultiExitConfigRefusesWhatAMultiProviderExitIsNot(t *testing.T) {
	if c, err := NewMultiExitConfig(three, "pia", "", "x"); err != nil || c.Kind != "overlay" || !c.MultiProvider() || c.Provider != "pia" {
		t.Fatalf("%+v %v", c, err)
	}
	for name, args := range map[string]struct {
		ids            []string
		provider, kind string
	}{
		"one":              {[]string{"mullvad"}, "mullvad", ""},
		"four":             {[]string{"mullvad", "pia", "nordvpn", "mullvad"}, "mullvad", ""},
		"a repeat":         {[]string{"mullvad", "mullvad"}, "mullvad", ""},
		"gluetun":          {[]string{"mullvad", "gluetun-protonvpn"}, "mullvad", ""},
		"unknown":          {[]string{"mullvad", "examplevpn"}, "mullvad", ""},
		"a sidecar":        {[]string{"mullvad", "pia"}, "mullvad", "sidecar"},
		"start outside it": {[]string{"mullvad", "pia"}, "nordvpn", ""},
	} {
		if _, err := NewMultiExitConfig(args.ids, args.provider, args.kind, ""); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAMultiProviderReaderNeedsItsOwnProviders(t *testing.T) {
	exit, _ := NewMultiExitConfig(three, "mullvad", "", "")
	desired := multiRequest("pia", "us_chicago")
	ok := multiRecord(t, "pia", "us_chicago", nil)
	if v := Assess(exit, ok, TargetFor(exit, ok, desired), now); v.State != "ok" || v.Tier != "provider" {
		t.Fatalf("%+v", v)
	}
	for name, providers := range map[string]any{
		"another order": []any{"pia", "mullvad", "nordvpn"},
		"fewer":         []any{"mullvad", "pia"},
		"absent":        "\x00absent",
		"null":          nil,
		"not a list":    "mullvad,pia,nordvpn",
	} {
		r := multiRecord(t, "pia", "us_chicago", nil)
		if providers == "\x00absent" {
			delete(r, "providers")
		} else {
			r["providers"] = providers
		}
		if v := Assess(exit, r, TargetFor(exit, r, desired), now); v.Label != "provider mismatch" {
			t.Errorf("%s: %+v", name, v)
		}
	}
	// A legacy record is no multi-provider exit's.
	legacy := map[string]any{"provider": "pia", "status": "ok", "checked_at": at(5), "server": "us_chicago"}
	if v := Assess(exit, settle(t, legacy), Target{}, now); v.Label != "provider mismatch" {
		t.Errorf("legacy: %+v", v)
	}
	// Each check is judged against the record's provider: PIA's tunnel
	// with Mullvad's IPv6 family expected is still PIA's to judge.
	r := multiRecord(t, "nordvpn", "us9001.nordvpn.com", nil)
	if v := Assess(exit, r, TargetFor(exit, r, multiRequest("nordvpn", "us9001.nordvpn.com")), now); v.State != "ok" {
		t.Errorf("nordvpn: %+v", v)
	}
}

func TestTheTargetsProviderMustBeTheRecords(t *testing.T) {
	exit, _ := NewMultiExitConfig(three, "mullvad", "", "")
	// The request is PIA's; the record acknowledges it but is Mullvad's.
	r := multiRecord(t, "mullvad", host, map[string]any{"requested_provider": "pia", "requested_server": "us_chicago"})
	if v := Assess(exit, r, TargetFor(exit, r, multiRequest("pia", "us_chicago")), now); v.State != "failed" || reasonsOf(v) != "not-requested-provider" {
		t.Errorf("panel: %+v", v)
	}
	// The record doesn't acknowledge the request's provider.
	r = multiRecord(t, "pia", "us_chicago", map[string]any{"requested_provider": "nordvpn"})
	if v := Assess(exit, r, TargetFor(exit, r, multiRequest("pia", "us_chicago")), now); v.State != "failed" || reasonsOf(v) != "not-requested-provider" {
		t.Errorf("unacknowledged provider: %+v", v)
	}
	// The SERVER lock.
	r = multiRecord(t, "mullvad", host, map[string]any{"configured_server": "pia/us_chicago", "requested_provider": nil,
		"requested_server": nil, "request_id": nil})
	if v := Assess(exit, r, TargetFor(exit, r, nil), now); v.State != "failed" || reasonsOf(v) != "not-configured-provider" {
		t.Errorf("configured: %+v", v)
	}
	if v := Assess(exit, r, Target{Server: "us_chicago", Source: "configured", Provider: "pia"}, now); reasonsOf(v) != "not-configured-provider" {
		t.Errorf("the exit's own SERVER: %+v", v)
	}
	if v := Assess(exit, r, Target{Server: host, Source: "configured", Provider: "mullvad"}, now); v.State != "ok" {
		t.Errorf("the exit's own SERVER, on it: %+v", v)
	}
	r = multiRecord(t, "pia", "us_chicago", map[string]any{"configured_server": "pia/us_chicago", "requested_provider": nil,
		"requested_server": nil, "request_id": nil})
	if v := Assess(exit, r, TargetFor(exit, r, nil), now); v.State != "ok" || v.ConfiguredServer != "pia/us_chicago" {
		t.Errorf("configured, on it: %+v", v)
	}
	// An unreadable lock still locks, and nothing agrees with it.
	r["configured_server"] = "us_chicago"
	if v := Assess(exit, r, TargetFor(exit, r, nil), now); v.State != "failed" || reasonsOf(v) != "not-configured-server" {
		t.Errorf("unreadable lock: %+v", v)
	}
	// The applier's own resolved target.
	r = multiRecord(t, "mullvad", host, nil)
	if v := Assess(exit, r, Target{Server: host, Source: "restore", Provider: "mullvad"}, now); v.State != "ok" {
		t.Errorf("resolved: %+v", v)
	}
	if v := Assess(exit, r, Target{Server: "us_chicago", Source: "restore", Provider: "pia"}, now); reasonsOf(v) != "not-target-server" {
		t.Errorf("resolved elsewhere: %+v", v)
	}
	// No target of the reader's own: the selection agrees with itself.
	r = multiRecord(t, "mullvad", host, nil)
	r["selection"].(map[string]any)["source"] = "restore"
	if v := Assess(exit, r, Target{}, now); v.State != "ok" {
		t.Errorf("self: %+v", v)
	}
	r["selection"].(map[string]any)["target_provider"] = "pia"
	if v := Assess(exit, r, Target{}, now); reasonsOf(v) != "not-target-server" {
		t.Errorf("self, another provider: %+v", v)
	}
}

func TestTargetForReadsTheRequestAsTheExitDoes(t *testing.T) {
	exit, _ := NewMultiExitConfig(three, "mullvad", "", "")
	r := multiRecord(t, "pia", "us_chicago", nil)
	got := TargetFor(exit, r, multiRequest("nordvpn", "us9001.nordvpn.com"))
	if got.Source != "panel" || got.Provider != "nordvpn" || got.Server != "us9001.nordvpn.com" || got.Request.Provider != "nordvpn" {
		t.Errorf("named: %+v", got)
	}
	// Three members: the record's provider's, when valid for it.
	three := map[string]any{"server": "us_chicago", "requested_at": "2026-10-11T11:59:50Z", "request_id": requestIDHex}
	if got := TargetFor(exit, r, three); got.Provider != "pia" || got.Server != "us_chicago" {
		t.Errorf("three members: %+v", got)
	}
	three["server"] = "us9001.nordvpn.com"
	if got := TargetFor(exit, r, three); got.Source != "" {
		t.Errorf("three members, another provider's server: %+v", got)
	}
	if got := TargetFor(exit, r, multiRequest("examplevpn", "us_chicago")); got.Source != "" {
		t.Errorf("outside the set: %+v", got)
	}
	// A single-provider reader's target is TargetForPanel's.
	single, _ := NewExitConfig("pia", "overlay", "")
	if got := TargetFor(single, r, multiRequest("pia", "us_chicago")); got.Source != "" {
		t.Errorf("a four-member request for a single-provider reader: %+v", got)
	}
	if !reflect.DeepEqual(TargetFor(single, r, request("us_chicago")), TargetForPanel(r, request("us_chicago"), "pia")) {
		t.Error("single-provider TargetFor")
	}
	// The request is the state package's, so its token is the record's
	// request_id.
	if got := TargetFor(exit, r, multiRequest("pia", "us_chicago")); state.RequestToken(*got.Request) != requestIDHex {
		t.Errorf("%+v", got.Request)
	}
}

func TestSplitTarget(t *testing.T) {
	for in, want := range map[string]string{
		"pia/us_chicago": "pia us_chicago", "nordvpn/us9001.nordvpn.com": "nordvpn us9001.nordvpn.com",
		"mullvad/" + host: "mullvad " + host, "us_chicago": "", "pia/": "", "pia/us9001.nordvpn.com": "", "examplevpn/us_chicago": "",
		"pia/us_chicago/x": "",
	} {
		p, s, ok := SplitTarget(in, three)
		got := ""
		if ok {
			got = p + " " + s
		}
		if got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestTheOrderPlacesTheNewMembers(t *testing.T) {
	r := multiRecord(t, "pia", "us_chicago", nil)
	var keys []string
	for _, p := range OrderRecord(r, "overlay", "native")[:13] {
		keys = append(keys, p.Key)
	}
	if strings.Join(keys, ",") != "schema,kind,backend,provider,providers,status,message,checked_at,server,requested_server,requested_provider,configured_server,request_id" {
		t.Errorf("%v", keys)
	}
}
