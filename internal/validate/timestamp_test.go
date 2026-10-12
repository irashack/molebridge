// Tests for the timestamp helpers of molebridge/state.py (now_iso,
// age_seconds, recent) and molebridge/verdict.py (_parse_time, _fresh).
package validate

import (
	"encoding/json"
	"math"
	"os"
	"testing"
	"time"
)

func TestTimestampsMatchPython(t *testing.T) {
	raw, err := os.ReadFile("testdata/time_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Now   string `json:"now"`
		Nanos int    `json:"now_nanos"`
		Cases []struct {
			Value  string   `json:"value"`
			Age    *float64 `json:"age"`
			Strict *float64 `json:"strict_age"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	base, ok := ParseTime(golden.Now)
	if !ok {
		t.Fatal("bad golden now")
	}
	now := base.Add(time.Duration(golden.Nanos))
	accepted := 0
	for _, c := range golden.Cases {
		age, ok := AgeSeconds(c.Value, now)
		if (c.Age == nil) == ok || (ok && math.Abs(age-*c.Age) > 1e-6) {
			t.Errorf("AgeSeconds(%q) = %v %v, Python %v", c.Value, age, ok, deref(c.Age))
		}
		if ok {
			accepted++
		}
		when, ok := ParseTime(c.Value)
		if (c.Strict == nil) == ok || (ok && math.Abs(secondsBetween(now, when)-*c.Strict) > 1e-6) {
			t.Errorf("ParseTime(%q) = %v %v, Python %v", c.Value, when, ok, deref(c.Strict))
		}
	}
	if accepted < 50 {
		t.Errorf("golden file exercises too few accepted timestamps: %d", accepted)
	}
}

func TestTimestampNonStrings(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	for _, v := range []any{nil, 5, 5.0, true, []string{"x"}, map[string]any{}} {
		if _, ok := AgeSeconds(v, now); ok {
			t.Errorf("AgeSeconds(%#v)", v)
		}
		if _, ok := ParseTime(v); ok {
			t.Errorf("ParseTime(%#v)", v)
		}
		if Recent(v, 150, now) || Fresh(v, now, 150) {
			t.Errorf("Recent/Fresh(%#v)", v)
		}
	}
}

func TestFormatTimeAndRecent(t *testing.T) {
	loc := time.FixedZone("x", 3600)
	now := time.Date(2026, 10, 11, 13, 0, 7, 0, loc)
	if got := FormatTime(now); got != "2026-10-11T12:00:07Z" {
		t.Errorf("FormatTime = %s", got)
	}
	at := func(s int) string { return FormatTime(now.Add(-time.Duration(s) * time.Second)) }
	for _, tc := range []struct {
		value  string
		recent bool
	}{{at(0), true}, {at(150), true}, {at(151), false}, {at(-1), false}, {at(-3600), false}, {"broken", false}} {
		if got := Recent(tc.value, 150, now); got != tc.recent {
			t.Errorf("Recent(%q) = %v", tc.value, got)
		}
		if got := Fresh(tc.value, now, 150); got != tc.recent {
			t.Errorf("Fresh(%q) = %v", tc.value, got)
		}
	}
	// A zero now means the wall clock.
	if !Recent(FormatTime(time.Now()), 5, time.Time{}) {
		t.Error("zero now should use the current time")
	}
}

func deref(f *float64) any {
	if f == nil {
		return nil
	}
	return *f
}
