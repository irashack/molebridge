package applier

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

// The status record of a multi-provider exit (docs/design/multi-provider.md,
// step 5): schema 2 with providers, requested_provider and
// selection.target_provider; provider is the tunnel's in place.

func decodedRequest(t testing.TB, request map[string]any) any {
	t.Helper()
	raw, err := validate.MarshalJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	v, err := validate.DecodeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// memberKeys are a record's member names in order.
func memberKeys(r *Record) []string {
	var keys []string
	for _, p := range r.members {
		keys = append(keys, p.Key)
	}
	return keys
}

func TestAMultiProviderRecordNamesItsProviders(t *testing.T) {
	for _, from := range allThree {
		for _, to := range allThree {
			if from == to {
				continue
			}
			t.Run(from+"_to_"+to, func(t *testing.T) {
				var published []*Record
				m := newMulti(t, "", from, allThree, func(c *Config) {
					c.Publish = func(r *Record) error { published = append(published, r); return nil }
				})
				request := targetOf(to)
				r := m.a.switchTo(t, request)
				if status(r) != "ok" {
					t.Fatalf("%s: %s", status(r), message(r))
				}
				rec := m.a.judged(r).Decoded()
				if !reflect.DeepEqual(rec["providers"], []any{"mullvad", "pia", "nordvpn"}) || rec["provider"] != to ||
					rec["requested_provider"] != to || rec["selection"].(map[string]any)["target_provider"] != to {
					t.Fatalf("record %v", rec)
				}
				keys := strings.Join(memberKeys(r), ",")
				if !strings.HasPrefix(keys, "schema,kind,backend,provider,providers,status,message,checked_at,server,requested_server,requested_provider,configured_server,request_id,selection,") {
					t.Fatalf("members %s", keys)
				}
				var selection []string
				for _, p := range r.Get("selection").(validate.Obj) {
					selection = append(selection, p.Key)
				}
				if strings.Join(selection, ",") != "source,outcome,attempt,target,target_provider,next_action,next_action_at" {
					t.Fatalf("selection %v", selection)
				}
				// The order the supervisor publishes in is the same, up to
				// the members it sorts.
				ordered := verdict.OrderRecord(rec, "overlay", "native")
				var orderedKeys []string
				for _, p := range ordered[:14] {
					orderedKeys = append(orderedKeys, p.Key)
				}
				if !strings.HasPrefix(keys, strings.Join(orderedKeys, ",")+",") {
					t.Fatalf("published as %v", orderedKeys)
				}
				// The applying record names the old provider: Replace hadn't
				// run when it was published.
				applying := published[0].Decoded()
				if applying["status"] != "applying" || applying["provider"] != from ||
					applying["selection"].(map[string]any)["target_provider"] != to {
					t.Fatalf("applying %v", applying)
				}
				// Every reader configured for this exit says connected; a
				// single-provider reader of either provider says provider
				// mismatch.
				exit := m.a.exitConfig()
				if v := verdict.Assess(exit, rec, verdict.TargetFor(exit, rec, decodedRequest(t, request)), time.Now()); v.State != "ok" {
					t.Fatalf("multi-provider reader: %+v", v)
				}
				if v := verdict.Assess(exit, rec, m.a.resolve(true).target(), time.Now()); v.State != "ok" {
					t.Fatalf("the applier's own target: %+v", v)
				}
				for _, id := range []string{from, to} {
					single, _ := verdict.NewExitConfig(id, "overlay", "")
					if v := verdict.Assess(single, rec, verdict.TargetForPanel(rec, decodedRequest(t, request), id), time.Now()); v.Label != "provider mismatch" {
						t.Fatalf("%s reader: %+v", id, v)
					}
				}
			})
		}
	}
}

func TestARecordBeforeTheChangeDisagreesWithTheTarget(t *testing.T) {
	m := newMulti(t, "", "mullvad", allThree, nil)
	m.pia.addkeyBad = true
	request := targetOf("pia")
	desire(t, m.a, request)
	mustTick(t, m.a)
	// Still Mullvad's tunnel, healthy, the target PIA's.
	r := m.a.judged(m.a.inspect(t)).Decoded()
	if r["provider"] != "mullvad" || r["requested_provider"] != "pia" || r["selection"].(map[string]any)["target_provider"] != "pia" {
		t.Fatalf("record %v", r)
	}
	exit := m.a.exitConfig()
	v := verdict.Assess(exit, r, verdict.TargetFor(exit, r, decodedRequest(t, request)), time.Now())
	if v.State == "ok" {
		t.Fatalf("%+v", v)
	}
	t.Logf("%s %v", v.Label, v.Reasons)
	if v := verdict.Assess(exit, r, m.a.resolve(true).target(), time.Now()); v.State == "ok" {
		t.Fatalf("the applier's own target: %+v", v)
	}
}

func TestAMultiProviderRequestWithoutAProviderIsRecordedAsTheActiveOnes(t *testing.T) {
	m := newMulti(t, "", "nordvpn", allThree, nil)
	request := requestAt(nordUS, map[string]any{"request_id": strings.Repeat("5", 32)})
	r := m.a.switchTo(t, request)
	rec := m.a.judged(r).Decoded()
	if status(r) != "ok" || rec["requested_provider"] != "nordvpn" {
		t.Fatalf("%s %v", status(r), rec)
	}
	exit := m.a.exitConfig()
	if v := verdict.Assess(exit, rec, verdict.TargetFor(exit, rec, decodedRequest(t, request)), time.Now()); v.State != "ok" {
		t.Fatalf("%+v", v)
	}
}

func TestAConfiguredMultiProviderRecord(t *testing.T) {
	m := newMulti(t, "", "mullvad", allThree, func(c *Config) { c.Server = "nordvpn/" + nordUS })
	r := mustTick(t, m.a)
	rec := m.a.judged(r).Decoded()
	if status(r) != "ok" || rec["configured_server"] != "nordvpn/"+nordUS ||
		rec["selection"].(map[string]any)["target_provider"] != "nordvpn" {
		t.Fatalf("%s %v", status(r), rec)
	}
	exit := m.a.exitConfig()
	if v := verdict.Assess(exit, rec, verdict.TargetFor(exit, rec, nil), time.Now()); v.State != "ok" || v.ConfiguredServer != "nordvpn/"+nordUS {
		t.Fatalf("%+v", v)
	}
	if v := verdict.Assess(exit, rec, m.a.resolve(true).target(), time.Now()); v.State != "ok" {
		t.Fatalf("the applier's own target: %+v", v)
	}
}
