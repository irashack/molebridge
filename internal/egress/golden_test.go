package egress

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/irashack/molebridge/internal/validate"
)

// TestMatchesPython compares ParseEcho and the route classification with the
// Python functions on generated inputs (testdata/golden.json: blanks of every
// kind around IPv4 and IPv6 forms, and route destinations). They agree on all of
// them; the two places Go is stricter than some Python versions (a scoped IPv6
// address, an IPv4-mapped loopback) are not among them.
func TestMatchesPython(t *testing.T) {
	raw, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var golden struct {
		Echo []struct {
			Raw    string  `json:"raw"`
			Family int     `json:"family"`
			Out    *string `json:"out"`
		} `json:"echo"`
		Routes []struct {
			Route json.RawMessage `json:"route"`
			Out   bool            `json:"out"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for _, c := range golden.Echo {
		got, err := ParseEcho(c.Raw, c.Family)
		if c.Out == nil {
			if err == nil {
				t.Errorf("ParseEcho(%q, %d) = %q, Python refuses", c.Raw, c.Family, got)
			}
			continue
		}
		accepted++
		if err != nil || got != *c.Out {
			t.Errorf("ParseEcho(%q, %d) = %q, %v; Python %q", c.Raw, c.Family, got, err, *c.Out)
		}
	}
	if accepted < 20 {
		t.Errorf("only %d accepted answers in the golden file", accepted)
	}
	for _, c := range golden.Routes {
		route, err := validate.DecodeJSON(c.Route)
		if err != nil {
			t.Fatal(err)
		}
		if got := HostLacksIPv6([]any{route}, []any{}, ignore); got != c.Out {
			t.Errorf("route %s: %v, Python %v", c.Route, got, c.Out)
		}
	}
}
