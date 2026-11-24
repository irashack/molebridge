package state

// Fuzz targets for the state files both sides read: the panel's request
// (state/panel/desired.json, written by the panel, read by the exit) and the
// status record's configured server (written by the exit, rendered by the
// panel). Whatever the bytes, nothing panics; an accepted request is one the
// exit can select and survives the panel's own encoding unchanged; and a
// configured server is short and printable before anything renders it.

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"unicode"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

func FuzzDesiredRequest(f *testing.F) {
	for _, seed := range []string{
		`{"server":"se-sto-wg-001","requested_at":"2026-01-01T00:00:00Z"}`,
		`{"server":"se-sto-wg-001","requested_at":"2026-01-01T00:00:00Z","request_id":"0123456789abcdef0123456789abcdef"}`,
		`{"provider":"nordvpn","server":"nl1.nordvpn.com","requested_at":"2026-01-01T00:00:00+00:00"}`,
		`{"provider":"pia","server":"nl_amsterdam","requested_at":"2026-01-01T00:00:00Z","request_id":null}`,
		`{"server":"../../x","requested_at":"2026-01-01T00:00:00Z"}`,
		`{"server":"se-sto-wg-001","server":"x","requested_at":"2026-01-01T00:00:00Z"}`,
		`{"server":"se-sto-wg-001","requested_at":1e999}`,
		`{"server":"se-sto-wg-001\u0000","requested_at":"2026-01-01T00:00:00Z"}`,
		`[]`, `null`, `"x"`, `{}`,
	} {
		f.Add([]byte(seed))
	}
	ids := providers.IDs()
	f.Fuzz(func(t *testing.T, raw []byte) {
		value, err := validate.DecodeJSON(raw)
		if err != nil {
			return
		}
		for _, id := range ids {
			if request, ok := DesiredRequest(value, id); ok {
				if !ValidServerName(request.Server, id) || request.Provider != "" {
					t.Fatalf("accepted %+v for %s", request, id)
				}
				roundTrip(t, request, func(v any) (Request, bool) { return DesiredRequest(v, id) })
				if RequestToken(request) == "" {
					t.Fatalf("empty token for %+v", request)
				}
			}
		}
		if request, ok := DesiredRequestFor(value, ids); ok {
			valid := false
			for _, id := range ids {
				if (request.Provider == "" || request.Provider == id) && ValidServerName(request.Server, id) {
					valid = true
				}
			}
			if !valid {
				t.Fatalf("multi-provider request %+v names no valid server", request)
			}
			roundTrip(t, request, func(v any) (Request, bool) { return DesiredRequestFor(v, ids) })
		}
		if m, ok := value.(map[string]any); ok {
			for _, id := range ids {
				switch EgressTier(m, id) {
				case "", providers.TierProvider, providers.TierTunnel:
				default:
					t.Fatalf("unknown tier for %s", raw)
				}
			}
		}
	})
}

// roundTrip encodes request as the panel writes it and reads it back as the
// exit does.
func roundTrip(t *testing.T, request Request, read func(any) (Request, bool)) {
	t.Helper()
	encoded, err := validate.MarshalJSON(request.JSONObject())
	if err != nil {
		t.Fatalf("encode %+v: %v", request, err)
	}
	decoded, err := validate.DecodeJSON(encoded)
	if err != nil {
		t.Fatalf("decode %s: %v", encoded, err)
	}
	again, ok := read(decoded)
	if !ok || !reflect.DeepEqual(again, request) {
		t.Fatalf("round trip of %+v gave %+v (%v) via %s", request, again, ok, encoded)
	}
}

func FuzzConfiguredServer(f *testing.F) {
	for _, seed := range []string{
		`{"configured_server":"se-sto-wg-001"}`,
		`{"configured_server":"\ud800x"}`,
		`{"configured_server":"a\u0007b‮"}`,
		`{"configured_server":""}`,
		`{"configured_server":7}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		value, err := validate.DecodeJSON(raw)
		if err != nil {
			return
		}
		shown, ok := ConfiguredServer(value)
		if !ok {
			return
		}
		count := 0
		for _, r := range shown {
			count++
			if !unicode.IsPrint(r) {
				t.Fatalf("configured server %q holds unprintable %U", shown, r)
			}
		}
		if count > 256 {
			t.Fatalf("configured server is %d characters", count)
		}
	})
}

// FuzzStateFileRoundTrip writes whatever a reader accepts and reads it back:
// the exit and the panel both read files the other side wrote with the same
// functions, so a value one accepts must come back unchanged.
func FuzzStateFileRoundTrip(f *testing.F) {
	for _, seed := range []string{`{"a":[1,2.5,"x",null,true]}`, `{"é":"😀"}`, `{"n":1e300,"m":-0}`, `{}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 16<<10 {
			return
		}
		value, err := validate.DecodeJSON(raw)
		if err != nil {
			return
		}
		if _, isObject := value.(map[string]any); !isObject {
			return
		}
		path := filepath.Join(t.TempDir(), "result.json")
		if err := WriteJSONAtomic(path, value, true, 64<<10); err != nil {
			// Like Python, the reader overflows 1e999 to infinity and the
			// writer refuses it (allow_nan=False); no writer copies a number
			// from untrusted input into a state file.
			if errors.Is(err, validate.ErrNonFiniteFloat) {
				return
			}
			t.Fatalf("write %s: %v", raw, err)
		}
		back, ok := ReadObject(path, 64<<10)
		if !ok {
			written, _ := os.ReadFile(path)
			t.Fatalf("read back refused %s (written as %s)", raw, written)
		}
		if !reflect.DeepEqual(back, value) {
			t.Fatalf("round trip changed %#v to %#v", value, back)
		}
	})
}
