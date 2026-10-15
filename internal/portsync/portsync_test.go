package portsync

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/validate"
)

var epoch = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

const (
	testUser     = "alice"
	testPassword = "correct-horse-PASSWORD"
	testSID      = "SESSIONCOOKIE0123"
)

// fakeQB is a qBittorrent Web API v2 that checks Host and Referer the way the
// real one does.
type fakeQB struct {
	mu         sync.Mutex
	server     *httptest.Server
	needLogin  bool
	listenPort int
	sid        string // the cookie value currently valid
	cookieName string
	loginBody  string // when set, the login answer instead of the real check
	loginCode  int
	nologinSID bool // login answers Ok. without a cookie

	logins    int
	gets      int
	posts     []string // json form fields of setPreferences
	badHost   int      // requests whose Host or Referer did not match
	cookies   []string // Cookie header of each API request
	loginSeen []url.Values
}

func newFakeQB(t *testing.T, needLogin bool, listenPort int) *fakeQB {
	q := &fakeQB{needLogin: needLogin, listenPort: listenPort, cookieName: "SID"}
	q.server = httptest.NewServer(http.HandlerFunc(q.handle))
	t.Cleanup(q.server.Close)
	return q
}

func (q *fakeQB) handle(w http.ResponseWriter, r *http.Request) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if r.Host != strings.TrimPrefix(q.server.URL, "http://") || r.Header.Get("Referer") != q.server.URL {
		q.badHost++
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	switch r.URL.Path {
	case "/api/v2/auth/login":
		q.logins++
		r.ParseForm()
		q.loginSeen = append(q.loginSeen, r.PostForm)
		if q.loginCode != 0 {
			w.WriteHeader(q.loginCode)
			fmt.Fprint(w, q.loginBody)
			return
		}
		if r.PostForm.Get("username") != testUser || r.PostForm.Get("password") != testPassword {
			fmt.Fprint(w, "Fails.")
			return
		}
		if !q.nologinSID {
			q.sid = fmt.Sprintf("%s%d", testSID, q.logins)
			http.SetCookie(w, &http.Cookie{Name: q.cookieName, Value: q.sid, Path: "/", HttpOnly: true})
		}
		fmt.Fprint(w, "Ok.")
		return
	}
	cookie := r.Header.Get("Cookie")
	q.cookies = append(q.cookies, cookie)
	if q.needLogin && (q.sid == "" || cookie != q.cookieName+"="+q.sid) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/api/v2/app/preferences":
		q.gets++
		fmt.Fprintf(w, `{"listen_port":%d,"upnp":true,"random_port":true}`, q.listenPort)
	case "/api/v2/app/setPreferences":
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		r.ParseForm()
		q.posts = append(q.posts, r.PostForm.Get("json"))
		var port int
		fmt.Sscanf(r.PostForm.Get("json"), `{"listen_port":%d`, &port)
		q.listenPort = port
	default:
		http.NotFound(w, r)
	}
}

type env struct {
	t     *testing.T
	dir   string
	now   time.Time
	log   *bytes.Buffer
	qb    *fakeQB
	sync  *Syncer
	creds bool
}

// newEnv builds a Syncer against q, with credentials files when creds is set.
func newEnv(t *testing.T, q *fakeQB, creds bool) *env {
	dir := t.TempDir()
	e := &env{t: t, dir: dir, now: epoch, log: &bytes.Buffer{}, qb: q, creds: creds}
	s := Settings{Client: "qbittorrent", URL: q.server.URL, StateDir: filepath.Join(dir, "state"), Interval: 10 * time.Millisecond}
	if creds {
		s.UsernameFile = filepath.Join(dir, "user")
		s.PasswordFile = filepath.Join(dir, "pass")
		os.WriteFile(s.UsernameFile, []byte(testUser+"\n"), 0o600)
		os.WriteFile(s.PasswordFile, []byte(testPassword+"\n"), 0o600)
	}
	e.sync = &Syncer{Settings: s, HTTP: netx.Client{}, Now: func() time.Time { return e.now }, Log: e.log}
	return e
}

func (e *env) record(fields string) {
	path := filepath.Join(e.dir, "state", "applier", "result.json")
	os.MkdirAll(filepath.Dir(path), 0o755)
	if err := os.WriteFile(path, []byte(fields), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) sidecar(port string, age time.Duration) {
	e.record(fmt.Sprintf(`{"kind":"sidecar","checked_at":%q,"forwarded_port":%s}`, validate.FormatTime(e.now.Add(-age)), port))
}

func (e *env) step() { e.sync.Step(context.Background()) }

func (e *env) logged() string { return e.log.String() }

func TestLoginThenPortAlreadyRight(t *testing.T) {
	q := newFakeQB(t, true, 51820)
	e := newEnv(t, q, true)
	e.sidecar("51820", time.Second)
	e.step()
	e.step()
	if q.logins != 1 || q.gets != 2 || len(q.posts) != 0 {
		t.Errorf("logins=%d gets=%d posts=%v", q.logins, q.gets, q.posts)
	}
	if e.logged() != "" || q.badHost != 0 {
		t.Errorf("log %q badHost %d", e.logged(), q.badHost)
	}
	// Credentials arrive without the trailing newline.
	if q.loginSeen[0].Get("username") != testUser || q.loginSeen[0].Get("password") != testPassword {
		t.Errorf("login form %v", q.loginSeen[0])
	}
}

func TestPortChangedPostsExactlyOnce(t *testing.T) {
	q := newFakeQB(t, true, 6881)
	e := newEnv(t, q, true)
	e.sidecar("48211", time.Second)
	e.step()
	if len(q.posts) != 1 || q.posts[0] != `{"listen_port":48211,"random_port":false,"upnp":false}` {
		t.Fatalf("posts %q", q.posts)
	}
	if want := "molebridge-port-sync: qBittorrent listens on 6881; set to 48211\n"; e.logged() != want {
		t.Errorf("log %q", e.logged())
	}
	// The next pass finds it right and says nothing more.
	e.step()
	if len(q.posts) != 1 || strings.Count(e.logged(), "\n") != 1 {
		t.Errorf("posts %q log %q", q.posts, e.logged())
	}
}

func TestChangeIsLoggedEveryTime(t *testing.T) {
	q := newFakeQB(t, false, 6881)
	e := newEnv(t, q, false)
	e.sidecar("40000", time.Second)
	e.step()
	e.sidecar("40001", time.Second)
	e.step()
	want := "molebridge-port-sync: qBittorrent listens on 6881; set to 40000\n" +
		"molebridge-port-sync: qBittorrent listens on 40000; set to 40001\n"
	if e.logged() != want || len(q.posts) != 2 {
		t.Errorf("log %q posts %q", e.logged(), q.posts)
	}
}

func TestNoLoginBypass(t *testing.T) {
	q := newFakeQB(t, false, 6881)
	e := newEnv(t, q, false)
	e.sidecar("40000", time.Second)
	e.step()
	if q.logins != 0 || len(q.posts) != 1 || q.badHost != 0 {
		t.Errorf("logins=%d posts=%q badHost=%d", q.logins, q.posts, q.badHost)
	}
	for _, c := range q.cookies {
		if c != "" {
			t.Errorf("cookie sent without a login: %q", c)
		}
	}
}

func TestNoLoginRefusedBy403(t *testing.T) {
	q := newFakeQB(t, true, 6881)
	e := newEnv(t, q, false)
	e.sidecar("40000", time.Second)
	e.step()
	want := "molebridge-port-sync: qBittorrent refused the request (HTTP 403); it needs the login: set PORT_SYNC_USERNAME_FILE and PORT_SYNC_PASSWORD_FILE\n"
	if e.logged() != want || len(q.posts) != 0 {
		t.Errorf("log %q posts %q", e.logged(), q.posts)
	}
}

func TestWrongCredentials(t *testing.T) {
	q := newFakeQB(t, true, 6881)
	e := newEnv(t, q, true)
	os.WriteFile(e.sync.Settings.PasswordFile, []byte("wrong-PASSWORD\n"), 0o600)
	e.sidecar("40000", time.Second)
	e.step()
	want := "molebridge-port-sync: qBittorrent refused the user name or password\n"
	if e.logged() != want || len(q.posts) != 0 || q.gets != 0 {
		t.Errorf("log %q posts %q gets %d", e.logged(), q.posts, q.gets)
	}
	if strings.Contains(e.logged(), "wrong-PASSWORD") {
		t.Error("password logged")
	}
}

func TestLoginBannedAndOddAnswers(t *testing.T) {
	for _, c := range []struct {
		name     string
		code     int
		body     string
		noCookie bool
		want     string
	}{
		{"banned", 403, "Your IP address has been banned after too many failed authentication attempts.", false,
			"qBittorrent refused the login (HTTP 403); it may have banned this address after failed logins"},
		{"server error", 500, "", false, "qBittorrent answered the login with HTTP 500"},
		{"odd body", 200, "<html>", false, "qBittorrent answered the login with an unexpected body"},
		{"no cookie", 0, "", true, "qBittorrent accepted the login but sent no session cookie"},
	} {
		t.Run(c.name, func(t *testing.T) {
			q := newFakeQB(t, true, 6881)
			q.loginCode, q.loginBody, q.nologinSID = c.code, c.body, c.noCookie
			e := newEnv(t, q, true)
			e.sidecar("40000", time.Second)
			e.step()
			if want := Prefix + c.want + "\n"; e.logged() != want {
				t.Errorf("log %q, want %q", e.logged(), want)
			}
			if len(q.posts) != 0 {
				t.Errorf("posts %q", q.posts)
			}
		})
	}
}

func TestSessionLostThenLoginAgain(t *testing.T) {
	q := newFakeQB(t, true, 6881)
	e := newEnv(t, q, true)
	e.sidecar("40000", time.Second)
	e.step() // logs in, sets 40000
	q.mu.Lock()
	q.sid = "SERVER-FORGOT-THE-SESSION" // qBittorrent restarted: the old cookie is dead
	q.listenPort = 6881
	q.mu.Unlock()
	e.step()
	if q.logins != 2 {
		t.Errorf("logins=%d", q.logins)
	}
	if len(q.posts) != 2 {
		t.Errorf("posts %q", q.posts)
	}
	if strings.Contains(e.logged(), testSID) || strings.Contains(e.logged(), testPassword) {
		t.Errorf("secret in log %q", e.logged())
	}
}

func TestForbiddenAfterNewLogin(t *testing.T) {
	q := newFakeQB(t, true, 6881)
	e := newEnv(t, q, true)
	e.sidecar("40000", time.Second)
	// A server that logs in but never accepts the cookie.
	q.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/auth/login" {
			http.SetCookie(w, &http.Cookie{Name: "SID", Value: "x"})
			fmt.Fprint(w, "Ok.")
			return
		}
		http.Error(w, "Forbidden", http.StatusForbidden)
	})
	e.step()
	want := "molebridge-port-sync: qBittorrent refused the request (HTTP 403) after a new login\n"
	if e.logged() != want {
		t.Errorf("log %q", e.logged())
	}
}

func TestQBittorrent5CookieName(t *testing.T) {
	q := newFakeQB(t, true, 6881)
	q.cookieName = "QBT_SID_8080"
	e := newEnv(t, q, true)
	e.sidecar("40000", time.Second)
	e.step()
	if len(q.posts) != 1 {
		t.Errorf("posts %q log %q", q.posts, e.logged())
	}
}

func TestRecordGates(t *testing.T) {
	for _, c := range []struct {
		name  string
		write func(e *env)
		want  string
	}{
		{"absent", func(e *env) {}, "no current status record from the exit"},
		{"stale", func(e *env) { e.sidecar("40000", 151*time.Second) }, "no current status record from the exit"},
		{"future", func(e *env) { e.sidecar("40000", -time.Minute) }, "no current status record from the exit"},
		{"not an object", func(e *env) { e.record(`[1]`) }, "no current status record from the exit"},
		{"duplicate keys", func(e *env) {
			e.record(fmt.Sprintf(`{"kind":"sidecar","checked_at":%q,"forwarded_port":40000,"forwarded_port":40001}`, validate.FormatTime(epoch)))
		}, "no current status record from the exit"},
		{"foreign kind", func(e *env) {
			e.record(fmt.Sprintf(`{"kind":"overlay","checked_at":%q,"forwarded_port":40000}`, validate.FormatTime(epoch)))
		}, "the status record is not a sidecar's"},
		{"no kind", func(e *env) {
			e.record(fmt.Sprintf(`{"checked_at":%q,"forwarded_port":40000}`, validate.FormatTime(epoch)))
		}, "the status record is not a sidecar's"},
		{"port 1023", func(e *env) { e.sidecar("1023", 0) }, "the status record's forwarded_port is not an integer from 1024 to 65535"},
		{"port 65536", func(e *env) { e.sidecar("65536", 0) }, "the status record's forwarded_port is not an integer from 1024 to 65535"},
		{"port string", func(e *env) { e.sidecar(`"40000"`, 0) }, "the status record's forwarded_port is not an integer from 1024 to 65535"},
		{"port float", func(e *env) { e.sidecar(`40000.5`, 0) }, "the status record's forwarded_port is not an integer from 1024 to 65535"},
		{"port true", func(e *env) { e.sidecar(`true`, 0) }, "the status record's forwarded_port is not an integer from 1024 to 65535"},
	} {
		t.Run(c.name, func(t *testing.T) {
			q := newFakeQB(t, false, 6881)
			e := newEnv(t, q, false)
			c.write(e)
			e.step()
			if want := Prefix + c.want + "\n"; e.logged() != want {
				t.Errorf("log %q, want %q", e.logged(), want)
			}
			if q.gets != 0 || len(q.posts) != 0 || q.logins != 0 {
				t.Errorf("qBittorrent was asked: gets=%d posts=%q", q.gets, q.posts)
			}
		})
	}
}

func TestPortBoundariesAreAccepted(t *testing.T) {
	for _, port := range []string{"1024", "65535"} {
		q := newFakeQB(t, false, 6881)
		e := newEnv(t, q, false)
		e.sidecar(port, 0)
		e.step()
		if len(q.posts) != 1 || !strings.Contains(q.posts[0], `"listen_port":`+port+",") {
			t.Errorf("%s: posts %q", port, q.posts)
		}
	}
	// A record exactly 150 s old still counts.
	q := newFakeQB(t, false, 6881)
	e := newEnv(t, q, false)
	e.sidecar("40000", 150*time.Second)
	e.step()
	if len(q.posts) != 1 {
		t.Errorf("posts %q log %q", q.posts, e.logged())
	}
}

func TestNoPortYetIsSaidOnce(t *testing.T) {
	q := newFakeQB(t, false, 6881)
	e := newEnv(t, q, false)
	e.sidecar("null", 0)
	e.step()
	e.step()
	e.record(fmt.Sprintf(`{"kind":"sidecar","checked_at":%q}`, validate.FormatTime(e.now)))
	e.step()
	if want := "molebridge-port-sync: no forwarded port yet\n"; e.logged() != want {
		t.Errorf("log %q", e.logged())
	}
	if q.gets != 0 || q.logins != 0 {
		t.Errorf("qBittorrent was asked")
	}
	// A port arrives, then goes away again: said again.
	e.sidecar("40000", 0)
	e.step()
	e.sidecar("null", 0)
	e.step()
	if got := strings.Count(e.logged(), "no forwarded port yet"); got != 2 {
		t.Errorf("said %d times: %q", got, e.logged())
	}
}

func TestFailureKindsAreRateLimited(t *testing.T) {
	q := newFakeQB(t, false, 6881)
	e := newEnv(t, q, false)
	e.step() // no record
	e.now = e.now.Add(30 * time.Second)
	e.step()
	e.now = e.now.Add(29 * time.Second)
	e.step()
	if got := strings.Count(e.logged(), "\n"); got != 1 {
		t.Fatalf("logged %d lines within a minute: %q", got, e.logged())
	}
	e.now = e.now.Add(time.Second)
	e.step()
	if got := strings.Count(e.logged(), "\n"); got != 2 {
		t.Errorf("logged %d lines after a minute: %q", got, e.logged())
	}
	// Another kind is not held back by the first.
	e.record(fmt.Sprintf(`{"kind":"overlay","checked_at":%q}`, validate.FormatTime(e.now)))
	e.step()
	if got := strings.Count(e.logged(), "\n"); got != 3 {
		t.Errorf("logged %d lines: %q", got, e.logged())
	}
}

func TestQBittorrentDownIsRateLimitedAndRecovers(t *testing.T) {
	q := newFakeQB(t, false, 6881)
	e := newEnv(t, q, false)
	e.sync.Settings.URL = "http://127.0.0.1:1"
	e.sidecar("40000", 0)
	e.step()
	e.step()
	out := e.logged()
	if strings.Count(out, "\n") != 1 || !strings.HasPrefix(out, "molebridge-port-sync: qBittorrent could not be reached (") {
		t.Errorf("log %q", out)
	}
}

func TestBadPreferenceAnswers(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"not json", "nope", "qBittorrent's preferences are not a JSON object"},
		{"array", "[]", "qBittorrent's preferences are not a JSON object"},
		{"no port", `{"upnp":true}`, "qBittorrent's preferences have no integer listen_port"},
		{"string port", `{"listen_port":"6881"}`, "qBittorrent's preferences have no integer listen_port"},
		{"duplicate", `{"listen_port":1,"listen_port":2}`, "qBittorrent's preferences are not a JSON object"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var posts int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts++
				}
				fmt.Fprint(w, c.body)
			}))
			defer server.Close()
			q := &fakeQB{server: server}
			e := newEnv(t, q, false)
			e.sync.Settings.URL = server.URL
			e.sidecar("40000", 0)
			e.step()
			if want := Prefix + c.want + "\n"; e.logged() != want || posts != 0 {
				t.Errorf("log %q posts %d", e.logged(), posts)
			}
		})
	}
}

func TestHTTPErrorStatuses(t *testing.T) {
	status := 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/app/preferences" && status == 0 {
			fmt.Fprint(w, `{"listen_port":1}`)
			return
		}
		code := status
		if code == 0 {
			code = 500
		}
		w.WriteHeader(code)
	}))
	defer server.Close()
	q := &fakeQB{server: server}
	e := newEnv(t, q, false)
	e.sync.Settings.URL = server.URL
	e.sidecar("40000", 0)
	e.step()
	status = 0
	e.now = e.now.Add(time.Minute)
	e.sidecar("40000", 0)
	e.step()
	want := "molebridge-port-sync: qBittorrent answered the preferences request with HTTP 500\n" +
		"molebridge-port-sync: qBittorrent answered the port change with HTTP 500\n"
	if e.logged() != want {
		t.Errorf("log %q", e.logged())
	}
}

func TestRedirectIsAnAnswerNotFollowed(t *testing.T) {
	var followed bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed = true }))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer server.Close()
	e := newEnv(t, &fakeQB{server: server}, false)
	e.sync.Settings.URL = server.URL
	e.sidecar("40000", 0)
	e.step()
	if followed || !strings.Contains(e.logged(), "HTTP 302") {
		t.Errorf("followed=%v log %q", followed, e.logged())
	}
}

func TestCredentialFileUnreadableAtRunTime(t *testing.T) {
	q := newFakeQB(t, true, 6881)
	e := newEnv(t, q, true)
	os.Remove(e.sync.Settings.PasswordFile)
	e.sidecar("40000", 0)
	e.step()
	want := "molebridge-port-sync: the login credential files cannot be read (PORT_SYNC_USERNAME_FILE, PORT_SYNC_PASSWORD_FILE)\n"
	if e.logged() != want || q.logins != 0 {
		t.Errorf("log %q logins %d", e.logged(), q.logins)
	}
}

func TestRunStopsWhenTheContextEnds(t *testing.T) {
	q := newFakeQB(t, false, 6881)
	e := newEnv(t, q, false)
	e.sidecar("40000", 0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.sync.Run(ctx); close(done) }()
	deadline := time.After(5 * time.Second)
	for {
		q.mu.Lock()
		n := q.gets
		q.mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("Run did not repeat")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestSettings(t *testing.T) {
	dir := t.TempDir()
	user, pass := filepath.Join(dir, "u"), filepath.Join(dir, "p")
	os.WriteFile(user, []byte("alice\n"), 0o600)
	os.WriteFile(pass, []byte("secret-value\n"), 0o600)
	big := filepath.Join(dir, "big")
	os.WriteFile(big, bytes.Repeat([]byte("x"), 1025), 0o600)
	empty := filepath.Join(dir, "empty")
	os.WriteFile(empty, []byte("\n"), 0o600)
	good := func(over map[string]string) map[string]string {
		m := map[string]string{"PORT_SYNC_CLIENT": "qbittorrent"}
		for k, v := range over {
			m[k] = v
		}
		return m
	}
	refused := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"no client", map[string]string{}, "PORT_SYNC_CLIENT is required (the only client is qbittorrent)"},
		{"other client", good(map[string]string{"PORT_SYNC_CLIENT": "transmission"}), "PORT_SYNC_CLIENT must be qbittorrent"},
		{"https", good(map[string]string{"PORT_SYNC_URL": "https://127.0.0.1:8080"}), "PORT_SYNC_URL must be an http URL (https is refused: the application is on a loopback address)"},
		{"no scheme", good(map[string]string{"PORT_SYNC_URL": "127.0.0.1:8080"}), "PORT_SYNC_URL must be an http URL (https is refused: the application is on a loopback address)"},
		{"ftp", good(map[string]string{"PORT_SYNC_URL": "ftp://127.0.0.1"}), "PORT_SYNC_URL must be an http URL (https is refused: the application is on a loopback address)"},
		{"userinfo", good(map[string]string{"PORT_SYNC_URL": "http://u:p@127.0.0.1:8080"}), "PORT_SYNC_URL must not contain a user name or password"},
		{"user only", good(map[string]string{"PORT_SYNC_URL": "http://u@127.0.0.1:8080"}), "PORT_SYNC_URL must not contain a user name or password"},
		{"query", good(map[string]string{"PORT_SYNC_URL": "http://127.0.0.1:8080/?a=b"}), "PORT_SYNC_URL must not contain a query or fragment"},
		{"empty query", good(map[string]string{"PORT_SYNC_URL": "http://127.0.0.1:8080?"}), "PORT_SYNC_URL must not contain a query or fragment"},
		{"fragment", good(map[string]string{"PORT_SYNC_URL": "http://127.0.0.1:8080/#x"}), "PORT_SYNC_URL must not contain a query or fragment"},
		{"path", good(map[string]string{"PORT_SYNC_URL": "http://127.0.0.1:8080/qb"}), "PORT_SYNC_URL must not contain a path"},
		{"lan address", good(map[string]string{"PORT_SYNC_URL": "http://192.0.2.10:8080"}), "PORT_SYNC_URL must name a loopback IP address (127.0.0.0/8 or [::1])"},
		{"hostname", good(map[string]string{"PORT_SYNC_URL": "http://qbittorrent.example.net:8080"}), "PORT_SYNC_URL must name a loopback IP address (127.0.0.0/8 or [::1])"},
		{"localhost name", good(map[string]string{"PORT_SYNC_URL": "http://localhost:8080"}), "PORT_SYNC_URL must name a loopback IP address (127.0.0.0/8 or [::1])"},
		{"unspecified", good(map[string]string{"PORT_SYNC_URL": "http://0.0.0.0:8080"}), "PORT_SYNC_URL must name a loopback IP address (127.0.0.0/8 or [::1])"},
		{"bad port", good(map[string]string{"PORT_SYNC_URL": "http://127.0.0.1:99999"}), "PORT_SYNC_URL has an invalid port"},
		{"user file alone", good(map[string]string{"PORT_SYNC_USERNAME_FILE": user}), "PORT_SYNC_USERNAME_FILE and PORT_SYNC_PASSWORD_FILE must be set together or not at all"},
		{"password file alone", good(map[string]string{"PORT_SYNC_PASSWORD_FILE": pass}), "PORT_SYNC_USERNAME_FILE and PORT_SYNC_PASSWORD_FILE must be set together or not at all"},
		{"missing file", good(map[string]string{"PORT_SYNC_USERNAME_FILE": user, "PORT_SYNC_PASSWORD_FILE": filepath.Join(dir, "none")}), "PORT_SYNC_PASSWORD_FILE: cannot be opened"},
		{"directory", good(map[string]string{"PORT_SYNC_USERNAME_FILE": dir, "PORT_SYNC_PASSWORD_FILE": pass}), "PORT_SYNC_USERNAME_FILE: is not a regular file"},
		{"large file", good(map[string]string{"PORT_SYNC_USERNAME_FILE": user, "PORT_SYNC_PASSWORD_FILE": big}), "PORT_SYNC_PASSWORD_FILE: is larger than 1 KiB"},
		{"empty file", good(map[string]string{"PORT_SYNC_USERNAME_FILE": empty, "PORT_SYNC_PASSWORD_FILE": pass}), "PORT_SYNC_USERNAME_FILE: is empty"},
		{"interval text", good(map[string]string{"PORT_SYNC_INTERVAL": "soon"}), "PORT_SYNC_INTERVAL must be a whole number of seconds from 10 to 300"},
		{"interval 9", good(map[string]string{"PORT_SYNC_INTERVAL": "9"}), "PORT_SYNC_INTERVAL must be a whole number of seconds from 10 to 300"},
		{"interval 301", good(map[string]string{"PORT_SYNC_INTERVAL": "301"}), "PORT_SYNC_INTERVAL must be a whole number of seconds from 10 to 300"},
		{"interval plus", good(map[string]string{"PORT_SYNC_INTERVAL": "+30"}), "PORT_SYNC_INTERVAL must be a whole number of seconds from 10 to 300"},
		{"interval space", good(map[string]string{"PORT_SYNC_INTERVAL": " 30"}), "PORT_SYNC_INTERVAL must be a whole number of seconds from 10 to 300"},
		{"interval fraction", good(map[string]string{"PORT_SYNC_INTERVAL": "30.5"}), "PORT_SYNC_INTERVAL must be a whole number of seconds from 10 to 300"},
	}
	for _, c := range refused {
		t.Run("refuse "+c.name, func(t *testing.T) {
			if _, err := LoadSettings(c.env); err == nil || err.Error() != c.want {
				t.Errorf("got %v, want %q", err, c.want)
			}
		})
	}

	s, err := LoadSettings(good(nil))
	if err != nil || s.URL != "http://127.0.0.1:8080" || s.StateDir != "/state" || s.Interval != 30*time.Second || s.UsernameFile != "" {
		t.Errorf("defaults: %+v %v", s, err)
	}
	for _, accepted := range []string{"http://127.0.0.1:8080", "http://127.5.5.5:9000/", "http://[::1]:8080", "http://127.0.0.1"} {
		if _, err := LoadSettings(good(map[string]string{"PORT_SYNC_URL": accepted})); err != nil {
			t.Errorf("%s: %v", accepted, err)
		}
	}
	for v, want := range map[string]time.Duration{"10": 10 * time.Second, "300": 300 * time.Second} {
		if s, err := LoadSettings(good(map[string]string{"PORT_SYNC_INTERVAL": v})); err != nil || s.Interval != want {
			t.Errorf("interval %s: %+v %v", v, s, err)
		}
	}
	s, err = LoadSettings(good(map[string]string{"PORT_SYNC_USERNAME_FILE": user, "PORT_SYNC_PASSWORD_FILE": pass, "STATE_DIR": "/x"}))
	if err != nil || s.UsernameFile != user || s.StateDir != "/x" {
		t.Errorf("credentials: %+v %v", s, err)
	}
}

func TestReadCredentialStripsOneNewline(t *testing.T) {
	dir := t.TempDir()
	for content, want := range map[string]string{"pw": "pw", "pw\n": "pw", "pw\r\n": "pw", "pw\n\n": "pw\n", " pw ": " pw "} {
		path := filepath.Join(dir, "c")
		os.WriteFile(path, []byte(content), 0o600)
		if got, err := ReadCredential(path); err != nil || got != want {
			t.Errorf("%q: got %q %v", content, got, err)
		}
	}
	path := filepath.Join(dir, "exact")
	os.WriteFile(path, bytes.Repeat([]byte("x"), 1024), 0o600)
	if _, err := ReadCredential(path); err != nil {
		t.Errorf("1024 bytes: %v", err)
	}
	// A symlink to a file (a mounted secret) is read.
	link := filepath.Join(dir, "link")
	os.WriteFile(filepath.Join(dir, "target"), []byte("pw\n"), 0o600)
	os.Symlink(filepath.Join(dir, "target"), link)
	if got, err := ReadCredential(link); err != nil || got != "pw" {
		t.Errorf("symlink: %q %v", got, err)
	}
}

func TestErrorsNeverCarryTheURLOrSecrets(t *testing.T) {
	// A refused credential file error names neither path nor content.
	dir := t.TempDir()
	path := filepath.Join(dir, "secret-name-file")
	if _, err := ReadCredential(path); err == nil || strings.Contains(err.Error(), "secret-name-file") {
		t.Errorf("error %v", err)
	}
}
