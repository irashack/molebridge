package exchange

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
)

const (
	testToken = "0123456789abcdef0123456789abcdef"
	testID    = "mullvad"
	request   = `{"server": "se-sto-wg-001", "requested_at": "2026-11-02T10:00:00Z", "request_id": "0123456789abcdef0123456789abcdef"}`
	record    = `{"schema": 2, "status": "ok", "server": "de-fra-wg-001"}`
	relays    = `{"fetched_at": "2026-11-02T09:00:00Z", "provider": "mullvad", "relays": {}}`
)

// rig is an exchange and one exit's client, the client's requests handed
// straight to the server's handler.
type rig struct {
	t      *testing.T
	server *Server
	client *Client
	exit   Exit
	exitSt string
	puts   []string
	now    time.Time
	skew   time.Duration
}

func newRig(t *testing.T) *rig {
	t.Helper()
	root := t.TempDir()
	r := &rig{t: t, now: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}
	r.exit = Exit{ID: testID, Provider: "mullvad", Dir: filepath.Join(root, "panel-side", testID)}
	tokens := filepath.Join(root, "tokens")
	write(t, filepath.Join(tokens, testID), testToken+"\n")
	r.server = &Server{Exits: map[string]Exit{testID: r.exit}, TokensDir: tokens, Now: func() time.Time { return r.now }}
	r.exitSt = filepath.Join(root, "exit-side")
	r.client = &Client{URL: "http://exchange.test:8097/", ExitID: testID, Token: testToken, StateDir: r.exitSt,
		Provider: "mullvad", Fetch: r.fetch, Now: func() time.Time { return r.now.Add(r.skew) }}
	return r
}

func (r *rig) fetch(_ context.Context, req netx.Request) (netx.Response, error) {
	hr := httptest.NewRequest(req.Method, req.URL, bytes.NewReader(req.Body))
	for k, v := range req.Header {
		hr.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.server.ServeHTTP(rec, hr)
	if req.Method == "PUT" {
		r.puts = append(r.puts, req.URL[strings.LastIndex(req.URL, "/")+1:])
	}
	return netx.Response{Status: rec.Code, Body: rec.Body.Bytes(), Header: rec.Header()}, nil
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (r *rig) publish(name, content string) {
	write(r.t, filepath.Join(r.exitSt, "applier", name), content)
}

func TestRoundCarriesBothWays(t *testing.T) {
	r := newRig(t)
	write(t, r.exit.DesiredPath(), request)
	r.publish(FileResult, record)
	r.publish(FileRelays, relays)
	r.publish(FileRelayError, `{}`)
	r.skew = 3 * time.Second
	if err := r.client.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := jsonfile.ReadObject(filepath.Join(r.exitSt, "panel", "desired.json"), DesiredLimit)
	if got["server"] != "se-sto-wg-001" || got["request_id"] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("desired.json on the exit = %v", got)
	}
	for _, name := range Files {
		if a, b := read(t, r.exit.CopyPath(name)), read(t, filepath.Join(r.exitSt, "applier", name)); a != b {
			t.Fatalf("copy of %s = %q, want %q", name, a, b)
		}
	}
	if info, _ := os.Stat(r.exit.CopyPath(FileResult)); info.Mode().Perm() != 0o644 {
		t.Fatalf("copy mode = %v", info.Mode().Perm())
	}
	link, _ := jsonfile.ReadObject(r.exit.LinkPath(), LinkLimit)
	if link["last_contact_at"] != "2026-11-02T12:00:00Z" || link["clock_offset_s"] != 3.0 || link["exit"] != testID {
		t.Fatalf("link state = %v", link)
	}
	if files, _ := link["files"].(map[string]any); len(files) != 3 {
		t.Fatalf("link files = %v", link["files"])
	}

	// Nothing changed: the next round sends nothing.
	r.puts = nil
	if err := r.client.Round(context.Background()); err != nil || len(r.puts) != 0 {
		t.Fatalf("second round: err %v, puts %v", err, r.puts)
	}
	// Only the changed file goes.
	r.publish(FileResult, `{"schema": 2, "status": "applying"}`)
	if err := r.client.Round(context.Background()); err != nil || len(r.puts) != 1 || r.puts[0] != FileResult {
		t.Fatalf("third round: err %v, puts %v", err, r.puts)
	}
}

func TestRestartedExchangeIsRefilled(t *testing.T) {
	r := newRig(t)
	r.publish(FileResult, record)
	r.publish(FileRelays, relays)
	if err := r.client.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(r.exit.Dir, "applier")); err != nil {
		t.Fatal(err)
	}
	r.server = &Server{Exits: r.server.Exits, TokensDir: r.server.TokensDir, Now: r.server.Now}
	r.puts = nil
	if err := r.client.Round(context.Background()); err != nil || len(r.puts) != 2 {
		t.Fatalf("err %v, puts %v", err, r.puts)
	}
}

func TestNoRequestKeepsTheExitsOwn(t *testing.T) {
	r := newRig(t)
	own := filepath.Join(r.exitSt, "panel", "desired.json")
	write(t, own, request)
	if err := r.client.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if read(t, own) != request {
		t.Fatal("the exit's request was changed with no request at the exchange")
	}
}

func TestInvalidRequestIsRefusedButFilesGo(t *testing.T) {
	r := newRig(t)
	write(t, r.exit.DesiredPath(), `{"server": "../../etc", "requested_at": "2026-11-02T10:00:00Z"}`)
	r.publish(FileResult, record)
	err := r.client.Round(context.Background())
	if !errors.Is(err, ErrRequest) {
		t.Fatalf("err = %v, want ErrRequest", err)
	}
	if _, err := os.Stat(filepath.Join(r.exitSt, "panel", "desired.json")); !os.IsNotExist(err) {
		t.Fatal("an invalid request was written")
	}
	if read(t, r.exit.CopyPath(FileResult)) != record {
		t.Fatal("the status record wasn't sent")
	}
}

func TestWrongTokenAndUnknownExit(t *testing.T) {
	r := newRig(t)
	r.publish(FileResult, record)
	r.client.Token = strings.Repeat("x", 32)
	var status StatusError
	if err := r.client.Round(context.Background()); !errors.As(err, &status) || status.Status != 401 {
		t.Fatalf("wrong token: %v", err)
	}
	r.client.Token, r.client.ExitID = testToken, "other"
	if err := r.client.Round(context.Background()); !errors.As(err, &status) || status.Status != 401 {
		t.Fatalf("unknown exit: %v", err)
	}
	if _, err := os.Stat(r.exit.LinkPath()); !os.IsNotExist(err) {
		t.Fatal("a refused request was counted as contact")
	}
}

func TestTokenFileRules(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{"short": "abc\n", "space": strings.Repeat("a", 20) + " " + strings.Repeat("b", 20), "good": testToken + "\n"}
	for name, content := range cases {
		write(t, filepath.Join(dir, name), content)
	}
	if err := os.Symlink(filepath.Join(dir, "good"), filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{"short": false, "space": false, "good": true, "link": false, "missing": false} {
		if _, ok := ReadToken(filepath.Join(dir, name)); ok != want {
			t.Errorf("ReadToken(%s) = %v, want %v", name, ok, want)
		}
	}
}

func TestServerRefusesBadFiles(t *testing.T) {
	r := newRig(t)
	put := func(name, body, hash string) int {
		hr := httptest.NewRequest("PUT", "/v1/exits/"+testID+"/files/"+name, strings.NewReader(body))
		hr.Header.Set("Authorization", "Bearer "+testToken)
		if hash != "" {
			hr.Header.Set(SHA256Header, hash)
		}
		rec := httptest.NewRecorder()
		r.server.ServeHTTP(rec, hr)
		return rec.Code
	}
	big := `{"x": "` + strings.Repeat("a", ResultLimit) + `"}`
	for _, c := range []struct {
		name, file, body, hash string
		want                   int
	}{
		{"too large", FileResult, big, "", http.StatusRequestEntityTooLarge},
		{"not an object", FileResult, `[1]`, "", http.StatusBadRequest},
		{"duplicate keys", FileResult, `{"a": 1, "a": 2}`, "", http.StatusBadRequest},
		{"bad UTF-8", FileResult, "{\"a\": \"\xff\"}", "", http.StatusBadRequest},
		{"hash mismatch", FileResult, record, Hash([]byte("other")), http.StatusBadRequest},
		{"unknown file", "attempt.json", `{}`, "", http.StatusNotFound},
		{"good", FileResult, record, Hash([]byte(record)), http.StatusNoContent},
	} {
		if got := put(c.file, c.body, c.hash); got != c.want {
			t.Errorf("%s: status %d, want %d", c.name, got, c.want)
		}
	}
	if _, err := os.Stat(r.exit.CopyPath("attempt.json")); !os.IsNotExist(err) {
		t.Fatal("an unknown file was written")
	}

	hr := httptest.NewRequest("POST", "/v1/exits/"+testID, nil)
	hr.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	r.server.ServeHTTP(rec, hr)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}
}

func TestClientRefusesBadAnswers(t *testing.T) {
	for name, body := range map[string]string{
		"not JSON":       `nope`,
		"wrong schema":   `{"schema": 2, "desired": null, "have": {}}`,
		"extra member":   `{"schema": 1, "desired": null, "have": {}, "x": 1}`,
		"desired array":  `{"schema": 1, "desired": [], "have": {}}`,
		"bad hash":       `{"schema": 1, "desired": null, "have": {"result.json": "zz"}}`,
		"unknown file":   `{"schema": 1, "desired": null, "have": {"attempt.json": "` + strings.Repeat("0", 64) + `"}}`,
		"missing member": `{"schema": 1, "have": {}}`,
	} {
		if _, _, err := parseAnswer([]byte(body)); !errors.Is(err, ErrAnswer) {
			t.Errorf("%s: err %v", name, err)
		}
	}
	if _, have, err := parseAnswer([]byte(`{"schema": 1, "desired": null, "have": {}}`)); err != nil || len(have) != 0 {
		t.Fatalf("good answer: %v", err)
	}
}

func TestRequestsCarryMarkAndNoTokenInURL(t *testing.T) {
	r := newRig(t)
	r.client.SocketMark = 0x1bd00
	var seen []netx.Request
	inner := r.client.Fetch
	r.client.Fetch = func(ctx context.Context, req netx.Request) (netx.Response, error) {
		seen = append(seen, req)
		return inner(ctx, req)
	}
	r.publish(FileResult, record)
	if err := r.client.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, req := range seen {
		if req.SocketMark != 0x1bd00 || !req.MarkResolver || strings.Contains(req.URL, testToken) {
			t.Fatalf("request %s: mark %#x, resolver %v", req.URL, req.SocketMark, req.MarkResolver)
		}
		if req.URL != "http://exchange.test:8097/v1/exits/mullvad" && req.URL != "http://exchange.test:8097/v1/exits/mullvad/files/result.json" {
			t.Fatalf("URL %s", req.URL)
		}
	}
}

// The same round over a real loopback connection, with netx's client.
func TestRoundOverLoopback(t *testing.T) {
	r := newRig(t)
	ts := httptest.NewServer(r.server)
	defer ts.Close()
	r.client.URL = ts.URL
	r.client.Fetch = netx.Client{}.Fetch
	write(t, r.exit.DesiredPath(), request)
	r.publish(FileResult, record)
	r.publish(FileRelays, relays)
	if err := r.client.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	if read(t, r.exit.CopyPath(FileRelays)) != relays {
		t.Fatal("the catalog didn't arrive")
	}
	if _, ok := jsonfile.ReadObject(filepath.Join(r.exitSt, "panel", "desired.json"), DesiredLimit); !ok {
		t.Fatal("the request didn't arrive")
	}
}

func TestLinkJudgment(t *testing.T) {
	r := newRig(t)
	if l, ok := ReadLink(r.exit.LinkPath()); ok {
		t.Fatal("a link state before any contact")
	} else if reason, _ := Judge(l, ok, r.now); reason != "exit-unreachable" {
		t.Fatalf("no link state: %q", reason)
	}
	r.publish(FileResult, record)
	if err := r.client.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	l, ok := ReadLink(r.exit.LinkPath())
	if reason, _ := Judge(l, ok, r.now.Add(10*time.Second)); reason != "" {
		t.Fatalf("fresh link: %q", reason)
	}
	if reason, _ := Judge(l, ok, r.now.Add(16*time.Second)); reason != "exit-unreachable" {
		t.Fatalf("16 s without contact: %q", reason)
	}
	r.skew = -11 * time.Second
	if err := r.client.Round(context.Background()); err != nil {
		t.Fatal(err)
	}
	l, ok = ReadLink(r.exit.LinkPath())
	if reason, _ := Judge(l, ok, r.now); reason != "clock-skew" || *l.Offset != -11 {
		t.Fatalf("skewed: %q %v", reason, l.Offset)
	}
	write(t, r.exit.LinkPath(), `{"schema": 1, "last_contact_at": "yesterday", "clock_offset_s": null}`)
	if _, ok := ReadLink(r.exit.LinkPath()); ok {
		t.Fatal("a malformed link state was read")
	}
}

func TestPathLikeExitIDsAreRefused(t *testing.T) {
	r := newRig(t)
	for _, id := range []string{"..", "../tokens", "%2e%2e", "MULLVAD", ""} {
		hr := httptest.NewRequest("GET", "/v1/exits/"+id, nil)
		hr.Header.Set("Authorization", "Bearer "+testToken)
		rec := httptest.NewRecorder()
		r.server.ServeHTTP(rec, hr)
		if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusNotFound {
			t.Errorf("id %q: status %d", id, rec.Code)
		}
	}
}
