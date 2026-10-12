// The status records the Python applier published for fixed scenarios
// (testdata/records_golden.json, generated from the Python applier at the
// commit before this port with its own test fakes), compared byte for byte
// with the Go applier's after the supervisor's owner_record check is in
// place: member order, nesting, null and empty values, messages and the
// selection record. Timestamps are replaced by a placeholder on both sides.
package applier

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"

	"github.com/irashack/molebridge/internal/validate"
)

var timestampRE = regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`)

func normalized(s string) string { return timestampRE.ReplaceAllString(s, "<time>") }

func recordText(t testing.TB, a *Applier, r *Record) string {
	t.Helper()
	if r == nil {
		t.Fatal("no record")
	}
	raw, err := validate.MarshalJSON(a.judged(r))
	if err != nil {
		t.Fatal(err)
	}
	return normalized(string(raw))
}

func TestRecordsMatchThePythonApplierByteForByte(t *testing.T) {
	raw, err := os.ReadFile("testdata/records_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]string
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	scenarios := map[string]func(t *testing.T) (*Applier, *Record){
		"mullvad_inspect": func(t *testing.T) (*Applier, *Record) {
			a, _, _ := mullvadSetup(t)
			return a, a.inspect(t)
		},
		"mullvad_switch": func(t *testing.T) (*Applier, *Record) {
			a, _, _ := mullvadSetup(t)
			return a, a.switchTo(t, requestAt(testHost, nil))
		},
		"mullvad_unanswered": func(t *testing.T) (*Applier, *Record) {
			a, k, _ := mullvadSetup(t)
			k.egressOK = false
			return a, a.inspect(t)
		},
		"mullvad_pending_stale": func(t *testing.T) (*Applier, *Record) {
			a, _, _ := mullvadSetup(t)
			staleCatalogue(a)
			return a, a.switchTo(t, requestAt(testHost, nil))
		},
		"mullvad_rejected": func(t *testing.T) (*Applier, *Record) {
			a, _, _ := mullvadSetup(t)
			desire(t, a, requestAt("xx-xxx-wg-999", nil))
			return a, mustTick(t, a)
		},
		"mullvad_mutation_failed": func(t *testing.T) (*Applier, *Record) {
			a, k, _ := mullvadSetup(t)
			addRelay(a, otherHost, otherKey)
			k.keys = []string{otherKey}
			k.failSet = true
			desire(t, a, requestAt(testHost, nil))
			return a, mustTick(t, a)
		},
		"mullvad_unverified": func(t *testing.T) (*Applier, *Record) {
			a, k, _ := mullvadSetup(t)
			k.egressOK = false
			desire(t, a, requestAt(testHost, nil))
			return a, mustTick(t, a)
		},
		"mullvad_configured": func(t *testing.T) (*Applier, *Record) {
			a, _ := native(t, "mullvad", testHost)
			return a, mustTick(t, a)
		},
		"mullvad_invalid_desired": func(t *testing.T) (*Applier, *Record) {
			a, _, _ := mullvadSetup(t)
			desire(t, a, requestAt("--bad", map[string]any{"request_id": nil}))
			return a, mustTick(t, a)
		},
		"nord_fresh": func(t *testing.T) (*Applier, *Record) {
			a, _, _ := nordSetup(t)
			return a, a.inspect(t)
		},
		"nord_switch": func(t *testing.T) (*Applier, *Record) {
			a, _, _ := nordSetup(t)
			return a, a.switchTo(t, nordRequest(nordUS, nil))
		},
		"pia_unregistered": func(t *testing.T) (*Applier, *Record) {
			a, _, _, _, _ := piaSetup(t, false)
			return a, a.inspect(t)
		},
		"pia_forward_bound": func(t *testing.T) (*Applier, *Record) {
			a, _, _, _, _ := piaSetup(t, true)
			piaDesire(t, a)
			mustTick(t, a)
			return a, a.inspect(t)
		},
		"pia_switch": func(t *testing.T) (*Applier, *Record) {
			a, _, _, _, _ := piaSetup(t, false)
			return a, a.switchTo(t, piaRequest(nil))
		},
		"tunnel_tier": func(t *testing.T) (*Applier, *Record) {
			a, _, _ := tunnelSetup(t)
			return a, a.inspect(t)
		},
	}
	for name, run := range gluetunGoldenScenarios() {
		scenarios[name] = run
	}
	if len(scenarios) != len(golden) {
		t.Errorf("%d scenarios, %d golden records", len(scenarios), len(golden))
	}
	for name, run := range scenarios {
		want, ok := golden[name]
		if !ok {
			t.Errorf("%s: no golden record", name)
			continue
		}
		a, r := run(t)
		if got := recordText(t, a, r); got != normalized(want) {
			t.Errorf("%s differs:\n go: %s\npy: %s", name, got, normalized(want))
		}
	}
}
