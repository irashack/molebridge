// Tests ported from tools/test_gluetun_client.py, the control-server part
// (from API_KEY / FakeRun down): the loopback-only client, its authorized
// routes, the exact selection body, the bounded answers and the key's
// handling. The catalogue, endpoint and fixture tests of that file are
// internal/providers'; the role-file tests (test_auth_config, test_bad_auth_role)
// are internal/gluetunauth's, and the key-file reader's own cases
// (test_restrictive_key_mode, test_exposed_key_mode, test_special_key_mode,
// test_bad_key_file, test_key_newline, test_unsafe_key_file) are exercised
// there; here the client is checked to refuse an exposed file.
//
// Not ported, because the argument cannot be wrong in Go's types: the
// selection filter as a list, a dict or None (test_invalid_id_or_filter_refused
// rows 3 and 4 and 1: the empty string is None), a relay without an id as a
// missing key (the empty string is the same), a lone surrogate in a Go string,
// and the curl command line (test_loopback_client's argv assertions are the
// netx.Request assertions below). The temporary header file is gone: the key is
// one request header (assertNoKeyAnywhere checks it reaches nothing else).
//
// Nothing here leaves loopback: the fake is a FetchFunc, and the end-to-end
// tests talk to an httptest server on 127.0.0.1.
package applier

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
)

const apiKey = "AAAAAAAA-example-api-key"

// fakeControl is the Python FakeRun: it records the requests and answers.
type fakeControl struct {
	response string
	err      error
	requests []netx.Request
}

func (f *fakeControl) fetch(_ context.Context, req netx.Request) (netx.Response, error) {
	f.requests = append(f.requests, req)
	if f.err != nil {
		return netx.Response{}, f.err
	}
	return netx.Response{Status: 200, Body: []byte(f.response)}, nil
}

func keyFile(t testing.TB) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "api-key")
	if err := os.WriteFile(path, []byte(apiKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func clientFor(t testing.TB, baseURL string, f *fakeControl) *GluetunClient {
	t.Helper()
	c, err := NewGluetunClient(baseURL, keyFile(t), f.fetch)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const loopback = "http://127.0.0.1:8000"

// assertBounds is test_loopback_client's argv checks: no proxy and no redirect
// (netx guarantees both), plain HTTP, the 2 s connect, the 10 s total and the
// answer cap, and the key in the header only.
func assertBounds(t testing.TB, f *fakeControl) {
	t.Helper()
	if len(f.requests) == 0 {
		t.Fatal("no request")
	}
	for _, r := range f.requests {
		if !r.AllowHTTP || r.MaxBytes != GluetunMaxResponseBytes || r.Timeout != 10*time.Second ||
			r.ConnectTimeout != 2*time.Second || r.AnyStatus || r.RootCAs != nil {
			t.Errorf("request bounds %+v", r)
		}
		if r.Header["X-API-Key"] != apiKey {
			t.Errorf("key header %q", r.Header["X-API-Key"])
		}
		if strings.Contains(r.URL, apiKey) || strings.Contains(string(r.Body), apiKey) || r.UserAgent != "" {
			t.Errorf("key in the URL or body: %+v", r)
		}
	}
}

func TestLoopbackClient(t *testing.T) {
	for _, url := range []string{"http://127.0.0.1:8000", "http://[::1]:8000", "http://127.0.0.1:1", "http://[::1]:65535"} {
		f := &fakeControl{response: `{"status":"running"}`}
		c := clientFor(t, url, f)
		status, err := c.VPNStatus(context.Background())
		if err != nil || status != "running" {
			t.Fatalf("%s: %q %v", url, status, err)
		}
		if f.requests[0].URL != url+"/v1/vpn/status" || f.requests[0].Method != "GET" {
			t.Errorf("%s: %+v", url, f.requests[0])
		}
		assertBounds(t, f)
	}
}

func TestBadBaseURL(t *testing.T) {
	for _, url := range []string{"", "https://127.0.0.1:8000", "http://localhost:8000", "http://192.0.2.1:8000",
		"http://127.0.0.2:8000", "http://127.0.0.1", "http://127.0.0.1:0", "http://127.0.0.1:65536",
		"http://127.0.0.1:08000", "http://127.0.0.1:8000/", "http://127.0.0.1:8000?x=1", "http://127.0.0.1:8000#x",
		"http://127.0.0.1:8000\n", "http://user@127.0.0.1:8000", "http://[::ffff:127.0.0.1]:8000",
		"http://[::1%zone]:8000", "http://[::1]:8000/path"} {
		f := &fakeControl{}
		if _, err := NewGluetunClient(url, keyFile(t), f.fetch); err != ErrGluetunURL || err.Error() != "invalid gluetun control URL" {
			t.Errorf("%q: %v", url, err)
		}
		if len(f.requests) != 0 {
			t.Errorf("%q: made a request", url)
		}
	}
	// The URL is judged before the key file is read.
	if _, err := NewGluetunClient("http://localhost:1", filepath.Join(t.TempDir(), "missing"), nil); err != ErrGluetunURL {
		t.Errorf("url first: %v", err)
	}
}

func TestExposedKeyModeIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o700} {
		path := keyFile(t)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := NewGluetunClient(loopback, path, nil); err == nil || err.Error() != "cannot read gluetun API key" {
			t.Errorf("%o: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o600, 0o400} {
		path := keyFile(t)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := NewGluetunClient(loopback, path, nil); err != nil {
			t.Errorf("%o: %v", mode, err)
		}
	}
}

func TestSettingsAndOtherRoutesAreRefused(t *testing.T) {
	for _, c := range []struct{ method, path string }{{"GET", "/v1/vpn/settings"}, {"GET", "/v1/vpn/settings?x=1"},
		{"GET", "/v1/openvpn/settings"}, {"PUT", "/v1/vpn/status"}, {"PUT", "/v1/updater/settings"},
		{"GET", "/v1/updater/status/../../vpn/settings"}, {"GET", "http://example.test/"},
		{"GET", "/v1/publicip/ip/../vpn/settings"}} {
		f := &fakeControl{}
		_, err := clientFor(t, loopback, f).request(context.Background(), c.method, c.path, nil, c.method == "PUT")
		if err == nil || err.Error() != "gluetun control route refused" {
			t.Errorf("%s %s: %v", c.method, c.path, err)
		}
		if len(f.requests) != 0 {
			t.Errorf("%s %s: made a request", c.method, c.path)
		}
	}
	// A body goes with PUT and only PUT.
	f := &fakeControl{}
	c := clientFor(t, loopback, f)
	if _, err := c.request(context.Background(), "GET", "/v1/vpn/status", []byte("{}"), true); err == nil {
		t.Error("a GET with a body")
	}
	if _, err := c.request(context.Background(), "PUT", "/v1/vpn/settings", nil, false); err == nil {
		t.Error("a PUT without a body")
	}
	if len(f.requests) != 0 {
		t.Error("made a request")
	}
}

func selectionBody(filter string, id any) map[string]any {
	selection := map[string]any{}
	for _, name := range []string{"hostnames", "countries", "regions", "cities", "names", "numbers", "categories", "isps"} {
		selection[name] = []any{}
	}
	for _, name := range []string{"owned_only", "free_only", "premium_only", "stream_only", "multi_hop_only",
		"port_forward_only", "secure_core_only", "tor_only"} {
		selection[name] = false
	}
	selection[filter] = []any{id}
	return map[string]any{"provider": map[string]any{"server_selection": selection}}
}

func TestExactSelectionBody(t *testing.T) {
	for _, c := range []struct {
		id     any
		filter string
	}{{"relay.example.test", "hostnames"}, {"ExampleNode", "names"}, {"EX#26", "names"}, {"EX-CORE#2", "names"},
		{26, "numbers"}} {
		for _, useRelay := range []bool{true, false} {
			if useRelay && c.filter == "numbers" {
				continue // a relay's id is a string; a number is selected by SelectServer alone
			}
			f := &fakeControl{response: "VPN settings updated\r\n\x00\x7f\u0085\u202e"}
			client := clientFor(t, loopback, f)
			var outcome string
			var err error
			if useRelay {
				relay := &providers.Relay{ID: c.id.(string), SelectionFilter: c.filter, Hostname: "attribute.example.test",
					PublicKey: testKey}
				outcome, err = client.SelectRelay(context.Background(), relay, "")
			} else {
				outcome, err = client.SelectServer(context.Background(), c.id, c.filter)
			}
			if err != nil || outcome != "VPN settings updated" {
				t.Fatalf("%v %s: %q %v", c.id, c.filter, outcome, err)
			}
			r := f.requests[0]
			if r.Method != "PUT" || r.URL != loopback+"/v1/vpn/settings" || r.Header["Content-Type"] != "application/json" {
				t.Errorf("request %+v", r)
			}
			var got map[string]any
			if err := json.Unmarshal(r.Body, &got); err != nil {
				t.Fatal(err)
			}
			want := selectionBody(c.filter, c.id)
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(want)
			if string(gotJSON) != string(wantJSON) {
				t.Errorf("body %s, want %s", gotJSON, wantJSON)
			}
			// json.dumps(separators=(',', ':')): no space outside a string.
			if strings.Contains(strings.ReplaceAll(string(r.Body), c.filter, ""), ": ") || strings.Contains(string(r.Body), ", ") {
				t.Errorf("not compact: %s", r.Body)
			}
			assertBounds(t, f)
		}
	}
}

func TestSelectionBodyKeepsPythonsMemberOrder(t *testing.T) {
	f := &fakeControl{response: "ok"}
	if _, err := clientFor(t, loopback, f).SelectServer(context.Background(), "relay.example.test", "hostnames"); err != nil {
		t.Fatal(err)
	}
	want := `{"provider":{"server_selection":{"countries":[],"regions":[],"cities":[],"names":[],"numbers":[],` +
		`"categories":[],"isps":[],"hostnames":["relay.example.test"],"owned_only":false,"free_only":false,` +
		`"premium_only":false,"stream_only":false,"multi_hop_only":false,"port_forward_only":false,` +
		`"secure_core_only":false,"tor_only":false}}}`
	if string(f.requests[0].Body) != want {
		t.Errorf("body %s", f.requests[0].Body)
	}
}

func TestSelectionRejectsAHostnameBeforeIO(t *testing.T) {
	for _, host := range []string{"", "relay.example.test\n", "Bad.example.test", strings.Repeat("x", 254), `example.test"`,
		"a..test", "-bad.test"} {
		f := &fakeControl{}
		_, err := clientFor(t, loopback, f).SelectServer(context.Background(), host, "hostnames")
		if err == nil || err.Error() != "invalid gluetun server selection" || len(f.requests) != 0 {
			t.Errorf("%q: %v", host, err)
		}
	}
}

func TestInvalidIDOrFilterIsRefused(t *testing.T) {
	for _, c := range []struct {
		id     any
		filter string
	}{{"relay.example.test", ""}, {"relay.example.test", "countries"}, {"EX#1\n", "names"}, {"\x00", "names"},
		{strings.Repeat("x", 257), "names"}, {"", "names"}, {"EX\u202e#1", "names"}, {"26", "numbers"},
		{true, "numbers"}, {0, "numbers"}, {65536, "numbers"}, {nil, "hostnames"}, {1.5, "numbers"}} {
		f := &fakeControl{}
		_, err := clientFor(t, loopback, f).SelectServer(context.Background(), c.id, c.filter)
		if err == nil || err.Error() != "invalid gluetun server selection" || len(f.requests) != 0 {
			t.Errorf("%#v %q: %v", c.id, c.filter, err)
		}
	}
}

func TestInvalidRelayIsRefused(t *testing.T) {
	for _, relay := range []*providers.Relay{{}, {Hostname: "relay.example.test"},
		{ID: "relay.example.test", SelectionFilter: "countries"}, nil} {
		f := &fakeControl{}
		_, err := clientFor(t, loopback, f).SelectRelay(context.Background(), relay, "")
		if err == nil || err.Error() != "invalid gluetun server selection" || len(f.requests) != 0 {
			t.Errorf("%+v: %v", relay, err)
		}
	}
}

func TestConflictingRelayFilterIsRefused(t *testing.T) {
	f := &fakeControl{}
	relay := &providers.Relay{ID: "relay.example.test", SelectionFilter: "hostnames"}
	_, err := clientFor(t, loopback, f).SelectRelay(context.Background(), relay, "names")
	if err == nil || err.Error() != "conflicting gluetun server selection filter" || len(f.requests) != 0 {
		t.Errorf("%v", err)
	}
	// The same filter named twice is fine.
	f.response = "ok"
	if _, err := clientFor(t, loopback, f).SelectRelay(context.Background(), relay, "hostnames"); err != nil {
		t.Error(err)
	}
}

func TestInvalidSelectionOutcome(t *testing.T) {
	for _, outcome := range []string{"", "\n\x00", strings.Repeat("x", GluetunMaxOutcomeChars+1)} {
		f := &fakeControl{response: outcome}
		_, err := clientFor(t, loopback, f).SelectServer(context.Background(), "relay.example.test", "hostnames")
		if err == nil || err.Error() != "invalid gluetun selection outcome" {
			t.Errorf("%q: %v", outcome, err)
		}
	}
	// The limit is in characters, not bytes: 1024 two-byte characters are fine.
	f := &fakeControl{response: strings.Repeat("é", GluetunMaxOutcomeChars)}
	if _, err := clientFor(t, loopback, f).SelectServer(context.Background(), "relay.example.test", "hostnames"); err != nil {
		t.Error(err)
	}
}

func TestVPNStatuses(t *testing.T) {
	for _, status := range VPNStatuses {
		f := &fakeControl{response: `{"status":"` + status + `"}`}
		got, err := clientFor(t, loopback, f).VPNStatus(context.Background())
		if err != nil || got != status {
			t.Errorf("%s: %q %v", status, got, err)
		}
		assertBounds(t, f)
	}
	if len(VPNStatuses) != 6 {
		t.Error("statuses")
	}
}

func TestBadStatusResponse(t *testing.T) {
	for _, raw := range []string{"{}", "[]", "null", "broken input", `{"status":"running","status":"stopped"}`,
		`{"status":true}`, `{"status":"unknown"}`, `{"status":"RUNNING"}`, `{"status":"running\n"}`, `{"status":NaN}`,
		strings.Repeat("[", 2000)} {
		f := &fakeControl{response: raw}
		if _, err := clientFor(t, loopback, f).VPNStatus(context.Background()); err == nil {
			t.Errorf("%.30q accepted", raw)
		}
	}
}

func TestPublicIP(t *testing.T) {
	for _, address := range []string{"198.51.100.20", "2001:db8::20"} {
		f := &fakeControl{response: `{"public_ip":"` + address + `","city":"Example City"}`}
		got, err := clientFor(t, "http://[::1]:8000", f).PublicIP(context.Background())
		if err != nil || got != address {
			t.Errorf("%s: %q %v", address, got, err)
		}
		if f.requests[0].URL != "http://[::1]:8000/v1/publicip/ip" {
			t.Errorf("url %s", f.requests[0].URL)
		}
		assertBounds(t, f)
	}
}

func TestBadPublicIP(t *testing.T) {
	for _, value := range []string{`null`, `true`, `[]`, `4`, `"198.51.100.01"`, `"198.51.100.20:8000"`,
		`"198.51.100.20\n"`, `"2001:DB8::20"`, `"2001:db8::20%zone"`, `"2001:db8::20/64"`, `"bad"`,
		`"` + strings.Repeat("x", 256) + `"`} {
		f := &fakeControl{response: `{"public_ip":` + value + `}`}
		_, err := clientFor(t, loopback, f).PublicIP(context.Background())
		if err == nil || err.Error() != "invalid gluetun public IP" {
			t.Errorf("%s: %v", value, err)
		}
	}
}

func TestInvalidRawResponse(t *testing.T) {
	for name, body := range map[string]string{"too large": strings.Repeat("x", GluetunMaxResponseBytes+1),
		"not UTF-8": "{\"status\":\"\xff\"}"} {
		f := &fakeControl{response: body}
		_, err := clientFor(t, loopback, f).VPNStatus(context.Background())
		if err == nil || err.Error() != "gluetun control request failed" {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestRunFailureIsSanitized(t *testing.T) {
	for _, cause := range []error{errors.New(apiKey), netx.ErrTimeout, netx.ErrStatus, netx.ErrTooLarge, netx.ErrTransport} {
		f := &fakeControl{err: cause}
		_, err := clientFor(t, loopback, f).VPNStatus(context.Background())
		if err == nil || err.Error() != "gluetun control request failed" || strings.Contains(err.Error(), apiKey) ||
			errors.Unwrap(err) != nil {
			t.Errorf("%v: %v", cause, err)
		}
	}
	// A canceled context is the caller's, not a failed request.
	f := &fakeControl{err: netx.ErrCanceled}
	if _, err := clientFor(t, loopback, f).VPNStatus(context.Background()); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled: %v", err)
	}
}

func TestUpdaterStatusAndStart(t *testing.T) {
	f := &fakeControl{response: `{"status":"completed"}`}
	c := clientFor(t, loopback, f)
	if got, err := c.UpdaterStatus(context.Background()); err != nil || got != "completed" {
		t.Fatalf("%q %v", got, err)
	}
	if r := f.requests[len(f.requests)-1]; r.URL != loopback+"/v1/updater/status" || r.Method != "GET" {
		t.Errorf("%+v", r)
	}
	f.response = "{\"outcome\":\"running\"}\n"
	if got, err := c.StartUpdate(context.Background()); err != nil || got != "running" {
		t.Fatalf("%q %v", got, err)
	}
	r := f.requests[len(f.requests)-1]
	if r.Method != "PUT" || r.URL != loopback+"/v1/updater/status" || string(r.Body) != `{"status":"running"}` {
		t.Errorf("%+v", r)
	}
	for _, bad := range []string{`{"outcome":""}`, `{"outcome":"x\u0007"}`, "already running",
		`{"outcome":` + strings.Repeat(`"x`, 40) + `"}`, `{"status":"running"}`} {
		f.response = bad
		if _, err := c.StartUpdate(context.Background()); err == nil || err.Error() != "invalid gluetun updater outcome" {
			t.Errorf("%.30q: %v", bad, err)
		}
	}
	f.response = `{"status":"bogus"}`
	if _, err := c.UpdaterStatus(context.Background()); err == nil || err.Error() != "invalid gluetun updater status" {
		t.Errorf("bogus: %v", err)
	}
}

// -- end to end over loopback, through the real netx client ------------------------------------

// control starts a server on 127.0.0.1 and a client for it. The httptest URL
// is exactly the form the client accepts.
func control(t *testing.T, handler http.HandlerFunc) *GluetunClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	c, err := NewGluetunClient(server.URL, keyFile(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEndToEndSelectionOverLoopback(t *testing.T) {
	var method, path, key, contentType, body string
	c := control(t, func(w http.ResponseWriter, r *http.Request) {
		method, path, key, contentType = r.Method, r.URL.Path, r.Header.Get("X-API-Key"), r.Header.Get("Content-Type")
		raw := make([]byte, 4096)
		n, _ := r.Body.Read(raw)
		body = string(raw[:n])
		w.Write([]byte("settings updated\n"))
	})
	outcome, err := c.SelectServer(context.Background(), "relay.example.test", "hostnames")
	if err != nil || outcome != "settings updated" {
		t.Fatalf("%q %v", outcome, err)
	}
	if method != "PUT" || path != "/v1/vpn/settings" || key != apiKey || contentType != "application/json" ||
		!strings.Contains(body, `"hostnames":["relay.example.test"]`) {
		t.Errorf("%s %s key=%q ct=%q body=%q", method, path, key, contentType, body)
	}
}

func TestEndToEndStatusAndFailures(t *testing.T) {
	answers := map[string]func(http.ResponseWriter){
		"/v1/vpn/status":     func(w http.ResponseWriter) { w.Write([]byte(`{"status":"running"}`)) },
		"/v1/updater/status": func(w http.ResponseWriter) { http.Error(w, "boom", http.StatusInternalServerError) },
		"/v1/publicip/ip": func(w http.ResponseWriter) {
			w.Write([]byte(`{"public_ip":"` + strings.Repeat("1", GluetunMaxResponseBytes) + `"}`))
		},
	}
	c := control(t, func(w http.ResponseWriter, r *http.Request) { answers[r.URL.Path](w) })
	if status, err := c.VPNStatus(context.Background()); err != nil || status != "running" {
		t.Errorf("status %q %v", status, err)
	}
	// An HTTP error status is a failed request (curl -f); the body is not read.
	if _, err := c.UpdaterStatus(context.Background()); err != ErrGluetunRequest {
		t.Errorf("500: %v", err)
	}
	// An answer past the cap is a failed request.
	if _, err := c.PublicIP(context.Background()); err != ErrGluetunRequest {
		t.Errorf("large: %v", err)
	}
}

func TestEndToEndRedirectIsNotFollowed(t *testing.T) {
	var followed atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed.Add(1)
		w.Write([]byte(`{"status":"running"}`))
	}))
	defer other.Close()
	c := control(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/v1/vpn/status", http.StatusFound)
	})
	// curl without -L returns the redirect page, which is no status.
	if _, err := c.VPNStatus(context.Background()); err == nil {
		t.Error("a redirect answered a status")
	}
	if followed.Load() != 0 {
		t.Error("the redirect was followed, with the key")
	}
}

func TestEndToEndDuplicateKeysAreRefused(t *testing.T) {
	c := control(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"running","status":"stopped"}`))
	})
	if _, err := c.VPNStatus(context.Background()); err == nil || err.Error() != "invalid gluetun JSON response" {
		t.Errorf("%v", err)
	}
}
