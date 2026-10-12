package providers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/irashack/molebridge/internal/validate"
)

// fixtures are shared with the Python tests: tools/fixtures/.
func fixture(t testing.TB, parts ...string) string {
	t.Helper()
	return filepath.Join(append([]string{"..", "..", "tools", "fixtures"}, parts...)...)
}

func readFixture(t testing.TB, parts ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(fixture(t, parts...))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// decoded turns Go values into what the strict decoder would have produced
// (int64, float64, map[string]any, []any), by encoding and decoding them.
func decoded(t testing.TB, v any) any {
	t.Helper()
	raw, err := validate.MarshalJSON(v)
	if err != nil {
		t.Fatal(err)
	}
	out, err := validate.DecodeJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func decodeJSON(t testing.TB, text string) any {
	t.Helper()
	v, err := validate.DecodeJSONString(text)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// clone deep-copies decoded JSON.
func clone(t testing.TB, v any) any { return decoded(t, v) }

func obj(v any) map[string]any { return v.(map[string]any) }
func list(v any) []any         { return v.([]any) }

func names(e *Entries) []string { return e.Names() }

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func jsonMarshal(v any) ([]byte, error) { return validate.MarshalJSON(v) }

// sameJSON reports whether two entries store identically.
func sameJSON(t testing.TB, a, b *Relay) bool {
	t.Helper()
	x, err1 := jsonMarshal(a)
	y, err2 := jsonMarshal(b)
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	return string(x) == string(y)
}
