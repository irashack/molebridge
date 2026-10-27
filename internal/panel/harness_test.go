package panel

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/panel/oidc/oidctest"
	"github.com/irashack/molebridge/internal/state"
)

// syncBuffer is a log destination the server and the test both touch.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncBuffer) Reset() {
	b.mu.Lock()
	b.buf.Reset()
	b.mu.Unlock()
}

// harness is a panel on loopback with its own state directory, log and
// clock.
type harness struct {
	t      *testing.T
	dir    string
	srv    *Server
	ts     *httptest.Server
	log    *syncBuffer
	clock  *oidctest.Clock
	client *http.Client
}

// newHarness starts a panel from an environment (STATE_DIR is set to a
// fresh directory unless given). Probing is replaced by probe, which may be
// nil.
func newHarness(t *testing.T, env map[string]string, opt func(*Options)) *harness {
	t.Helper()
	h := &harness{t: t, dir: t.TempDir(), log: &syncBuffer{}, clock: &oidctest.Clock{}}
	full := map[string]string{"STATE_DIR": h.dir}
	for k, v := range env {
		full[k] = v
	}
	cfg, err := ConfigFromEnv(full)
	if err != nil {
		t.Fatalf("ConfigFromEnv: %v", err)
	}
	options := Options{Now: h.clock.Now, Log: h.log}
	if opt != nil {
		opt(&options)
	}
	h.srv = NewServer(cfg, options)
	h.ts = httptest.NewServer(h.srv)
	t.Cleanup(h.ts.Close)
	h.client = &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{DisableKeepAlives: true},
		Timeout:       10 * time.Second,
	}
	return h
}

// exit returns the configured exit with this id.
func (h *harness) exit(id string) Exit {
	h.t.Helper()
	for _, e := range h.srv.Exits {
		if e.ID == id {
			return e
		}
	}
	h.t.Fatalf("no exit %q", id)
	return Exit{}
}

// answer is one response from the panel.
type answer struct {
	Status  int
	Body    string
	Header  http.Header
	Cookies map[string]setCookie
}

type setCookie struct {
	Value string
	Attrs map[string]bool // lower case, max-age as "max-age=N"
}

func (a answer) Location() string { return a.Header.Get("Location") }

// signature is what must be identical between two answers that may not
// differ: status, body and every header but Date.
func (a answer) signature() string {
	var keys []string
	for k, vs := range a.Header {
		if strings.EqualFold(k, "Date") {
			continue
		}
		for _, v := range vs {
			keys = append(keys, k+": "+v)
		}
	}
	sort.Strings(keys)
	return strings.Join(append([]string{strconv.Itoa(a.Status), a.Body}, keys...), "\n")
}

func (h *harness) do(method, path string, body []byte, header map[string]string) answer {
	h.t.Helper()
	req, err := http.NewRequest(method, h.ts.URL+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	// The request target is sent as given (no cleaning of ".." or "//").
	if u, perr := url.Parse(h.ts.URL + path); perr == nil {
		req.URL = u
	}
	for k, v := range header {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	a := answer{Status: resp.StatusCode, Body: string(data), Header: resp.Header, Cookies: map[string]setCookie{}}
	for _, line := range resp.Header.Values("Set-Cookie") {
		parts := strings.Split(line, ";")
		name, value, _ := strings.Cut(strings.TrimSpace(parts[0]), "=")
		attrs := map[string]bool{}
		for _, p := range parts[1:] {
			attrs[strings.ToLower(strings.TrimSpace(p))] = true
		}
		a.Cookies[name] = setCookie{value, attrs}
	}
	return a
}

func (h *harness) get(path, cookie string, header map[string]string) answer {
	h.t.Helper()
	merged := map[string]string{}
	for k, v := range header {
		merged[k] = v
	}
	if cookie != "" {
		merged["Cookie"] = cookie
	}
	return h.do("GET", path, nil, merged)
}

// post sends a form; fields keep their order.
func (h *harness) post(path string, fields [][2]string, cookie, origin string) answer {
	h.t.Helper()
	var pairs []string
	for _, f := range fields {
		pairs = append(pairs, url.QueryEscape(f[0])+"="+url.QueryEscape(f[1]))
	}
	header := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	if cookie != "" {
		header["Cookie"] = cookie
	}
	if origin != "" {
		header["Origin"] = origin
	}
	return h.do("POST", path, []byte(strings.Join(pairs, "&")), header)
}

var csrfTokenInPage = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// pageTokens loads an exit's page and returns the CSRF nonce and token.
func (h *harness) pageTokens(cookie, exitID, path string) (string, string) {
	h.t.Helper()
	if path == "" {
		path = "/"
	}
	page := h.get(path+"?exit="+exitID, cookie, nil)
	if page.Status != 200 {
		h.t.Fatalf("page %s?exit=%s: %d %s", path, exitID, page.Status, page.Body)
	}
	m := csrfTokenInPage.FindStringSubmatch(page.Body)
	if m == nil {
		h.t.Fatalf("no CSRF token in the page")
	}
	return page.Cookies[h.srv.csrfCookieName()].Value, m[1]
}

// readDesired reads an exit's request file, nil when there is none.
func readDesired(ex Exit) map[string]any {
	m, _ := state.ReadObject(ex.DesiredPath, 4096)
	return m
}

// readStatic reads a file of panel/static from disk.
func readStatic(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join("..", "..", "panel", "static", name))
}
