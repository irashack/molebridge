package panel

// The panel renders three files the exit writes (result.json, relays.json)
// or a request it wrote itself and someone else may have replaced
// (desired.json). The exit is trusted and validates what it writes, but the
// panel must still not let a hostile or corrupted file run script in the
// browser, break the JSON API or crash a request: a compromised provider
// catalogue, a hand-edited state directory or a bug on the exit's side ends
// at a wrong or refused view, never more.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// marker is markup that must never reach a page unescaped.
const marker = `<mbx onerror=x>`

var stateViews = []string{"/", "/embed", "/api/status", "/api/exits", "/metrics", "/readyz"}

// serveState writes the three files (nil leaves one out) under a fresh state
// directory and asks a single-exit panel for path.
func serveState(t testing.TB, provider string, result, desired, relays []byte, path string) *httptest.ResponseRecorder {
	t.Helper()
	dir := t.(interface{ TempDir() string }).TempDir()
	for name, data := range map[string][]byte{
		filepath.Join(dir, "applier", "result.json"): result,
		filepath.Join(dir, "panel", "desired.json"):  desired,
		filepath.Join(dir, "applier", "relays.json"): relays,
	} {
		if data == nil {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := ConfigFromEnv(map[string]string{"STATE_DIR": dir, "PROVIDER": provider})
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	srv := NewServer(cfg, Options{Now: func() time.Time { return goldenNow }, Log: &syncBuffer{}})
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "127.0.0.1:8080"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// checkView is what holds for every answer, whatever the files said.
func checkView(t testing.TB, path string, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code >= 500 && path != "/readyz" {
		t.Fatalf("%s: %s answered %d", what, path, rec.Code)
	}
	body := rec.Body.String()
	contentType := rec.Header().Get("Content-Type")
	switch {
	case strings.HasPrefix(contentType, "text/html"):
		if strings.Contains(strings.ToLower(body), "<mbx") {
			t.Fatalf("%s: %s rendered the markup unescaped", what, path)
		}
	case strings.HasPrefix(contentType, "application/json"):
		if !json.Valid(rec.Body.Bytes()) {
			t.Fatalf("%s: %s answered invalid JSON: %.200s", what, path, body)
		}
		if strings.Contains(body, "<mbx") {
			// Browsers never sniff application/json with nosniff, but the
			// encoder escapes < anyway (ensure_ascii and < are both fine).
			if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("%s: %s carries markup without nosniff", what, path)
			}
		}
	case strings.HasPrefix(contentType, "text/plain"):
		if strings.Contains(body, "\x00") {
			t.Fatalf("%s: %s answered a NUL", what, path)
		}
	}
}

// goldenFiles is a working single exit's three files for provider.
func goldenFiles(t testing.TB, provider string) (result, desired, relays []byte) {
	t.Helper()
	o := recOpts{At: goldenAt}
	server := map[string]string{"mullvad": "se-sto-wg-001", "pia": "ex_example", "nordvpn": "us9001.nordvpn.com"}[provider]
	if provider != "mullvad" {
		o.Provider = provider
	}
	r := schema2(o)
	r["requested_server"], r["request_id"] = r["server"], requestID
	enc := func(v any) []byte {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	return enc(r), enc(goldenRequest(server)), enc(goldenCatalogue(provider))
}

// TestPanelEscapesEveryStateString puts markup into each string of each
// state file in turn and renders every view: a systematic version of the
// fuzz target below, which only finds what its mutations reach.
func TestPanelEscapesEveryStateString(t *testing.T) {
	if testing.Short() {
		t.Skip("renders every view once per string")
	}
	shown := 0 // pages that showed the markup, escaped
	for _, provider := range []string{"mullvad", "pia", "nordvpn"} {
		result, desired, relays := goldenFiles(t, provider)
		files := [][]byte{result, desired, relays}
		for which := range files {
			var doc any
			if err := json.Unmarshal(files[which], &doc); err != nil {
				t.Fatal(err)
			}
			count := 0
			var walk func(node any, set func(any))
			render := func() {
				count++
				changed, err := json.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				in := [][]byte{result, desired, relays}
				in[which] = changed
				for _, path := range stateViews {
					rec := serveState(t, provider, in[0], in[1], in[2], path)
					checkView(t, path, rec, provider+" file "+[]string{"result", "desired", "relays"}[which]+" "+string(changed))
					if strings.Contains(rec.Body.String(), "&lt;mbx") {
						shown++
					}
				}
			}
			walk = func(node any, set func(any)) {
				switch n := node.(type) {
				case string:
					set(marker)
					render()
					set(n + marker)
					render()
					set(n)
				case map[string]any:
					for k, child := range n {
						walk(child, func(x any) { n[k] = x })
					}
				case []any:
					for i := range n {
						walk(n[i], func(x any) { n[i] = x })
					}
				}
			}
			walk(doc, func(any) {})
			if count == 0 {
				t.Fatalf("%s: no strings in file %d", provider, which)
			}
		}
	}
	if shown == 0 {
		t.Fatal("no page showed any of the markup: the test renders nothing it changes")
	}
	t.Logf("%d pages showed the markup, escaped", shown)
}

func FuzzPanelStateFiles(f *testing.F) {
	for _, provider := range []string{"mullvad", "pia", "nordvpn"} {
		result, desired, relays := goldenFiles(f, provider)
		f.Add(provider, result, desired, relays, uint8(0))
		f.Add(provider, []byte(strings.Replace(string(result), `"ok"`, `"`+marker+`"`, 1)), desired, relays, uint8(2))
		f.Add(provider, result, []byte(`{"server":"`+marker+`","requested_at":"2026-11-19T18:00:00Z"}`), relays, uint8(0))
		f.Add(provider, []byte(`{"status":"failed","message":"`+marker+`","checked_at":"2026-11-19T18:00:00Z"}`), []byte(nil), relays, uint8(1))
		f.Add(provider, []byte(`{"configured_server":"\ud800`+marker+`"}`), []byte(nil), []byte(nil), uint8(0))
	}
	f.Fuzz(func(t *testing.T, provider string, result, desired, relays []byte, view uint8) {
		if provider != "mullvad" && provider != "pia" && provider != "nordvpn" {
			return
		}
		if len(result)+len(desired)+len(relays) > 64<<10 {
			return
		}
		path := stateViews[int(view)%len(stateViews)]
		checkView(t, path, serveState(t, provider, result, desired, relays, path), "fuzz")
	})
}
