package panel

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// selectPanel is a single Mullvad exit with a fresh catalogue, on the golden
// clock, and its state directory.
func selectPanel(t testing.TB) (*Server, string) {
	t.Helper()
	result, _, relays := goldenFiles(t, "mullvad")
	dir := t.(interface{ TempDir() string }).TempDir()
	for name, data := range map[string][]byte{"applier/result.json": result, "applier/relays.json": relays} {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := ConfigFromEnv(map[string]string{"STATE_DIR": dir, "PROVIDER": "mullvad"})
	if err != nil {
		t.Fatal(err)
	}
	return NewServer(cfg, Options{Now: func() time.Time { return goldenNow }, Log: &syncBuffer{}}), dir
}

func postSelect(srv *Server, body []byte, cookie, origin, host string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/select", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// A client sends it; without it the panel answers 411 before anything.
	req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	req.Header.Set("Cookie", cookie)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	req.Host = host
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// FuzzSelectNeedsTheToken posts whatever a cross-site page or a client
// without the page's token can send: any body, cookie, Origin and Host. The
// CSRF token is an HMAC under the panel's own secret, so without one the
// panel never writes desired.json, whatever else the request holds.
func FuzzSelectNeedsTheToken(f *testing.F) {
	const field = "csrf_" + "token"
	const nonce = "csrf_" + "nonce"
	f.Add([]byte("server=se-got-wg-001&"+field+"=x"), nonce+"=x", "http://127.0.0.1:8080", "127.0.0.1:8080")
	f.Add([]byte("server=se-got-wg-001&"+field+"=&exit="), nonce+"=", "", "127.0.0.1:8080")
	f.Add([]byte("server=se-got-wg-001&server=de-ber-wg-002&"+field+"=a.b"), nonce+"=a; "+nonce+"=b", "null", "127.0.0.1")
	f.Add([]byte(field+"=x.y&server=se-got-wg-001"), "__Host-"+nonce+"=x", "https://other.example.test", "other.example.test")
	f.Fuzz(func(t *testing.T, body []byte, cookie, origin, host string) {
		if len(body) > 4096 {
			return
		}
		srv, dir := selectPanel(t)
		rec := postSelect(srv, body, cookie, origin, host)
		if _, err := os.Stat(filepath.Join(dir, "panel", "desired.json")); err == nil {
			t.Fatalf("a POST without the page's token wrote desired.json (answer %d)", rec.Code)
		}
	})
}

// TestSelectFuzzPanelCanWrite keeps the fuzz target honest: the same panel,
// asked with the nonce and token from its own page, does write desired.json,
// so the target's "never" is about the token, not a panel that can't write.
func TestSelectFuzzPanelCanWrite(t *testing.T) {
	srv, dir := selectPanel(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "127.0.0.1:8080"
	page := httptest.NewRecorder()
	srv.ServeHTTP(page, req)
	var cookie string
	for _, c := range page.Result().Cookies() {
		if c.Name == srv.csrfCookieName() {
			cookie = c.Name + "=" + c.Value
		}
	}
	m := csrfTokenInPage.FindStringSubmatch(page.Body.String())
	if cookie == "" || m == nil {
		t.Fatalf("the page gave no nonce or token (%d)", page.Code)
	}
	body := []byte("server=se-got-wg-001&csrf_" + "token=" + m[1])
	rec := postSelect(srv, body, cookie, "http://127.0.0.1:8080", "127.0.0.1:8080")
	if _, err := os.Stat(filepath.Join(dir, "panel", "desired.json")); err != nil {
		t.Fatalf("a POST with the page's token wrote nothing (answer %d %s)", rec.Code, rec.Body.String())
	}
}
