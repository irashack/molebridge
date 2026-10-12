// Tests for molebridge/countries.py. The Python module has no test file of its
// own; the golden table was dumped from NAME_TO_CODE, and the lookups below
// cover what the panel relies on (code_for, used by panel/app.py).
package countries

import (
	"encoding/json"
	"os"
	"testing"
)

func TestTableMatchesPython(t *testing.T) {
	raw, err := os.ReadFile("testdata/names_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden map[string]string
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	if Count() != len(golden) {
		t.Errorf("table has %d names, Python has %d", Count(), len(golden))
	}
	for name, code := range golden {
		if got, ok := CodeFor(name); !ok || got != code {
			t.Errorf("CodeFor(%q) = %q, %v; want %q", name, got, ok, code)
		}
	}
}

func TestCodeFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		code string
		ok   bool
	}{
		{"United States", "US", true}, {"  united states ", "US", true}, {"USA", "US", true}, {"UK", "GB", true},
		{"Great Britain", "GB", true}, {"Cote d'Ivoire", "CI", true}, {"Czechia", "CZ", true},
		{"Bosnia", "BA", true}, {"Atlantis", "", false}, {"", "", false}, {"United", "", false},
		{"\x1fGermany\x1f", "DE", true}, {" Germany", "DE", true},
		{"İceland", "", false}, // Python lower() gives "i" plus a combining dot
	} {
		code, ok := CodeFor(tc.name)
		if code != tc.code || ok != tc.ok {
			t.Errorf("CodeFor(%q) = %q, %v", tc.name, code, ok)
		}
	}
}
