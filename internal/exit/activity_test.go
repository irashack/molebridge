package exit

import (
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
)

func TestRoutingActivityMembers(t *testing.T) {
	at := time.Date(2026, 10, 10, 17, 59, 30, 0, time.UTC)
	raw, err := validate.MarshalJSON(RoutingActivity{Repairs: 2, LastRepair: at, Events: 40, Relevant: 12, Lost: 1, Periodic: 30})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"repairs": 2, "last_repair_at": "2026-10-10T17:59:30Z", "events": 40, "relevant_events": 12, "events_lost": 1, "periodic_passes": 30}`
	if string(raw) != want {
		t.Fatalf("%s", raw)
	}
	if v := (RoutingActivity{}).JSONObject(); v[1].Key != "last_repair_at" || v[1].Value != nil {
		t.Fatalf("no repair yet: %v", v)
	}
}

// The examples in docs/examples carry the member the worker writes, under
// the same names (the applier's test builds them without this package).
func TestTheExamplesCarryTheRoutingActivityMembers(t *testing.T) {
	var names []string
	for _, p := range (RoutingActivity{}).JSONObject() {
		names = append(names, p.Key)
	}
	sort.Strings(names)
	for _, name := range []string{"result-overlay-native.json", "result-overlay-gluetun.json", "result-sidecar-native.json"} {
		record, ok := state.ReadObject(filepath.Join("..", "..", "docs", "examples", name), 16384)
		if !ok {
			t.Fatalf("%s is unreadable", name)
		}
		member, ok := record["routing_activity"].(map[string]any)
		if !ok {
			t.Fatalf("%s has no routing_activity", name)
		}
		var got []string
		for k := range member {
			got = append(got, k)
		}
		sort.Strings(got)
		if len(got) != len(names) {
			t.Fatalf("%s: %v, want %v", name, got, names)
		}
		for i := range got {
			if got[i] != names[i] {
				t.Fatalf("%s: %v, want %v", name, got, names)
			}
		}
	}
}
