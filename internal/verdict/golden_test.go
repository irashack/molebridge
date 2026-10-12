package verdict

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"

	"github.com/irashack/molebridge/internal/validate"
)

// TestAssessMatchesPython compares with the Python assess of 0.7.0 (commit
// d553f25), run on records mutated at random; the golden is now fixed
// (testdata/assess_golden.json: 330 records, the outcomes of 12,000 capped per
// verdict) and requires the same verdict, reasons, checks and legacy projection
// from this port. Records the Python code cannot judge (it raises TypeError on an
// unhashable member of expected_families) are not in the file; the port calls
// them an invalid record.
func TestAssessMatchesPython(t *testing.T) {
	raw, err := os.ReadFile("testdata/assess_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Provider string          `json:"provider"`
		Kind     string          `json:"kind"`
		Record   json.RawMessage `json:"record"`
		Desired  json.RawMessage `json:"desired"`
		Target   *struct {
			Server *string `json:"server"`
			Source *string `json:"source"`
		} `json:"target"`
		Verdict    json.RawMessage `json:"verdict"`
		Projection json.RawMessage `json:"projection"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 300 {
		t.Fatalf("%d cases", len(cases))
	}
	states := map[string]int{}
	for i, c := range cases {
		record, err := validate.DecodeJSON(c.Record)
		if err != nil {
			t.Fatal(err)
		}
		desired, _ := validate.DecodeJSON(c.Desired)
		exit, err := NewExitConfig(c.Provider, c.Kind, "")
		if err != nil {
			t.Fatal(err)
		}
		target := TargetForPanel(record, desired, c.Provider)
		if c.Target != nil {
			target = Target{}
			if c.Target.Server != nil {
				target.Server = *c.Target.Server
			}
			if c.Target.Source != nil {
				target.Source = *c.Target.Source
			}
		}
		got := Assess(exit, record, target, now)
		states[got.State+"/"+got.Label]++
		gotJSON, err := validate.MarshalJSON(got)
		if err != nil {
			t.Fatal(err)
		}
		var gotValue, wantValue any
		json.Unmarshal(gotJSON, &gotValue)
		json.Unmarshal(c.Verdict, &wantValue)
		if !reflect.DeepEqual(gotValue, wantValue) {
			t.Errorf("case %d (%s/%s):\nrecord %s\n got %s\nwant %s", i, c.Provider, c.Kind, c.Record, gotJSON, c.Verdict)
			continue
		}
		projection, ok := LegacyProjection(record, got)
		var projValue, wantProj any
		if ok {
			projJSON, _ := validate.MarshalJSON(projection)
			json.Unmarshal(projJSON, &projValue)
		} else {
			projValue = map[string]any{}
		}
		json.Unmarshal(c.Projection, &wantProj)
		if !reflect.DeepEqual(projValue, wantProj) {
			t.Errorf("case %d projection:\n got %v\nwant %v", i, projValue, wantProj)
		}
	}
	if len(states) < 10 {
		t.Errorf("the golden file covers only %d outcomes: %v", len(states), states)
	}
}
