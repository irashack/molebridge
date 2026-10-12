package nordkey

// Ported from the tools/nordvpn-key.py section of tools/test_nordvpn.py
// (test_key_tool_writes_the_tunnel_config through
// test_script_runs_standalone_and_fails_closed). The curl-specific tests
// (test_fetch_passes_the_credential_only_in_a_private_file,
// test_fetch_failure_is_a_fixed_error_and_cleans_up) become httptest tests of
// the Go client: the credential travels in the Authorization header only, and
// every failure is the one fixed error. All HTTP here is loopback.

import (
	"bytes"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/tunnelconf"
)

// Fictitious values.
const (
	token      = "e9f2example0token1234567890abcdef0123456789"
	privateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

var credentials = []byte(`{"id": 1, "nordlynx_private_key": "` + privateKey + `", "username": "u-EXAMPLE", "password": "p-EXAMPLE"}`)

type fake struct {
	response []byte
	err      error
	tokens   []string
}

func (f *fake) fetch(token string) ([]byte, error) {
	f.tokens = append(f.tokens, token)
	return f.response, f.err
}

func tokenFile(t *testing.T, dir string, mode os.FileMode, text string) string {
	t.Helper()
	path := filepath.Join(dir, "token")
	os.Remove(path)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func runTool(f *fake, stdin string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	o := Options{Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb, Fetch: f.fetch}
	return Main(args, o), out.String(), errb.String()
}

func assertNoSecrets(t *testing.T, streams ...string) {
	t.Helper()
	for _, s := range streams {
		for _, secret := range []string{token, privateKey, "u-EXAMPLE", "p-EXAMPLE", "nordlynx_private_key"} {
			if strings.Contains(s, secret) {
				t.Errorf("secret %q in %q", secret, s)
			}
		}
	}
}

func TestKeyToolWritesTheTunnelConfig(t *testing.T) { // test_key_tool_writes_the_tunnel_config
	dir := t.TempDir()
	out := filepath.Join(dir, "wg_confs", "nordvpn.conf")
	f := &fake{response: credentials}
	code, stdout, stderr := runTool(f, "", tokenFile(t, dir, 0o600, token+"\n"), out)
	if code != 0 || stderr != "" || stdout != OKLine+"\n" {
		t.Fatalf("%d %q %q", code, stdout, stderr)
	}
	if len(f.tokens) != 1 || f.tokens[0] != token {
		t.Errorf("tokens %q", f.tokens)
	}
	assertNoSecrets(t, stdout, stderr)
	raw, _ := os.ReadFile(out)
	text := string(raw)
	for _, want := range []string{"PrivateKey = " + privateKey + "\n", "Address = 10.5.0.2/32\n", "Table = off\n", "MTU = 1420\n",
		"ip route replace default dev %i table 51821"} {
		if !strings.Contains(text, want) {
			t.Errorf("config lacks %q", want)
		}
	}
	for _, not := range []string{"[Peer]", "DNS", "Endpoint", "ip -6"} {
		if strings.Contains(text, not) {
			t.Errorf("config has %q", not)
		}
	}
	// The exit's validator takes it (a NordVPN config has an address and no peer).
	if _, err := tunnelconf.Parse(text, tunnelconf.NordVPN, 51821); err != nil {
		t.Errorf("not accepted by the exit's validator: %v\n%s", err, text)
	}
}

func TestConfigMatchesTheMullvadFormatWithoutThePeer(t *testing.T) { // test_config_matches_the_mullvad_format_without_the_peer
	nord, err := BuildNordConf(privateKey, "51821")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"PrivateKey = " + privateKey, "MTU = 1420", "Table = off",
		"PostUp = ip route replace default dev %i table 51821", "PreDown = ip route del default dev %i table 51821"}
	var got []string
	for _, line := range strings.Split(nord, "\n")[1:] {
		switch strings.SplitN(line, " = ", 2)[0] {
		case "PrivateKey", "MTU", "Table", "PostUp", "PreDown":
			got = append(got, line)
		}
	}
	// The Mullvad generator writes these lines in the order Interface lists
	// them: PrivateKey, (Address), MTU, Table, PostUp, PreDown.
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("%q", got)
	}
}

func TestOutputIsMode0600WhateverTheUmask(t *testing.T) { // test_output_is_mode_0600_whatever_the_umask
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	dir := t.TempDir()
	out := filepath.Join(dir, "nordvpn.conf")
	if code, _, _ := runTool(&fake{response: credentials}, "", tokenFile(t, dir, 0o600, token), out); code != 0 {
		t.Fatal("failed")
	}
	info, _ := os.Stat(out)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode())
	}
}

func TestTokenFileWithLooseModeIsRefused(t *testing.T) { // test_token_file_with_loose_mode_is_refused
	dir := t.TempDir()
	out := filepath.Join(dir, "nordvpn.conf")
	f := &fake{response: credentials}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660, 0o644, 0o666, 0o601} {
		code, stdout, stderr := runTool(f, "", tokenFile(t, dir, mode, token+"\n"), out)
		if code != 1 || stdout != "" || !strings.Contains(stderr, "0600") {
			t.Errorf("%v: %d %q %q", mode, code, stdout, stderr)
		}
		assertNoSecrets(t, stdout, stderr)
	}
	if _, err := os.Stat(out); err == nil || len(f.tokens) != 0 {
		t.Error("wrote or fetched with a loose token file")
	}
}

func TestTokenFileWithStrictModeIsAccepted(t *testing.T) { // test_token_file_with_strict_mode_is_accepted
	for _, mode := range []os.FileMode{0o600, 0o400} {
		dir := t.TempDir()
		f := &fake{response: credentials}
		if code, _, stderr := runTool(f, "", tokenFile(t, dir, mode, token+"\n"), filepath.Join(dir, "out.conf")); code != 0 || len(f.tokens) != 1 {
			t.Errorf("%v: %d %s", mode, code, stderr)
		}
	}
}

func TestTokenFileThatIsNotARegularFileIsRefused(t *testing.T) { // test_token_file_that_is_not_a_regular_file_is_refused
	dir := t.TempDir()
	target := tokenFile(t, dir, 0o600, token+"\n")
	link := filepath.Join(dir, "link")
	os.Symlink(target, link)
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	f := &fake{response: credentials}
	for _, source := range []string{link, dir, filepath.Join(dir, "missing"), fifo} {
		done := make(chan struct{})
		var code int
		var stdout, stderr string
		go func() { code, stdout, stderr = runTool(f, "", source, filepath.Join(dir, "out.conf")); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: blocked", source)
		}
		if code != 1 || stdout != "" {
			t.Errorf("%s: %d %q %q", source, code, stdout, stderr)
		}
		assertNoSecrets(t, stdout, stderr)
	}
	if len(f.tokens) != 0 {
		t.Error("fetched")
	}
}

func TestTokenFromStdin(t *testing.T) { // test_token_from_stdin
	dir := t.TempDir()
	out := filepath.Join(dir, "out.conf")
	f := &fake{response: credentials}
	code, stdout, stderr := runTool(f, token+"\n", "-", out)
	if code != 0 || len(f.tokens) != 1 || f.tokens[0] != token {
		t.Fatalf("%d %q", code, stderr)
	}
	assertNoSecrets(t, stdout, stderr)
	if raw, _ := os.ReadFile(out); !strings.Contains(string(raw), privateKey) {
		t.Error("key missing from the output")
	}
}

func TestBadTokenTextIsRefused(t *testing.T) { // test_bad_token_text_is_refused
	for name, content := range map[string]string{
		"empty": "", "newline": "\n", "space": "has space\n", "two lines": "two\nlines\n", "quote": "quo\"te",
		"backslash": "back\\slash", "high bytes": "\xff\xfe", "too long": strings.Repeat("x", 513), "tab": "tab\there",
		"nul": "a\x00b", "crlf only": "\r\n", "double cr": "tok\r\r\n", "256+1": strings.Repeat("y", 257),
	} {
		dir := t.TempDir()
		out := filepath.Join(dir, "out.conf")
		f := &fake{response: credentials}
		code, stdout, stderr := runTool(f, content, "-", out)
		if code != 1 || stdout != "" || len(f.tokens) != 0 || !strings.HasPrefix(stderr, "error: ") || strings.Contains(stderr, strings.Repeat("x", 20)) {
			t.Errorf("%s: %d %q %q", name, code, stdout, stderr)
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%s: wrote the output", name)
		}
	}
	// Accepted spellings: a token, with one trailing LF or CRLF.
	for _, content := range []string{token, token + "\n", token + "\r\n", strings.Repeat("z", 256)} {
		f := &fake{response: credentials}
		if code, _, stderr := runTool(f, content, "-", filepath.Join(t.TempDir(), "out.conf")); code != 0 {
			t.Errorf("%q refused: %s", content, stderr)
		}
	}
}

func TestExistingOutputIsRefusedAndUntouched(t *testing.T) { // test_existing_output_is_refused_and_untouched
	dir := t.TempDir()
	out := filepath.Join(dir, "nordvpn.conf")
	os.WriteFile(out, []byte("existing"), 0o600)
	f := &fake{response: credentials}
	code, stdout, stderr := runTool(f, "", tokenFile(t, dir, 0o600, token+"\n"), out)
	if code != 1 || stdout != "" || stderr != "error: the output file exists; keep it, or remove it deliberately\n" {
		t.Errorf("%d %q %q", code, stdout, stderr)
	}
	if raw, _ := os.ReadFile(out); string(raw) != "existing" || len(f.tokens) != 0 {
		t.Error("touched the existing file or fetched")
	}
}

func TestDanglingSymlinkOutputIsRefused(t *testing.T) { // test_dangling_symlink_output_is_refused
	dir := t.TempDir()
	out := filepath.Join(dir, "nordvpn.conf")
	os.Symlink(filepath.Join(dir, "elsewhere"), out)
	f := &fake{response: credentials}
	if code, _, _ := runTool(f, "", tokenFile(t, dir, 0o600, token+"\n"), out); code != 1 {
		t.Error("accepted a symlink")
	}
	if _, err := os.Stat(filepath.Join(dir, "elsewhere")); err == nil || len(f.tokens) != 0 {
		t.Error("followed the link or fetched")
	}
}

func TestWriteNewNeverReplaces(t *testing.T) { // test_write_new_never_replaces
	// The O_EXCL create inside the tool: a file that appears between the
	// existence check and the write is refused too.
	dir := t.TempDir()
	out := filepath.Join(dir, "nordvpn.conf")
	f := &fake{response: credentials}
	f.err = nil
	o := Options{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	o.Fetch = func(string) ([]byte, error) {
		os.WriteFile(out, []byte("first"), 0o600) // the race
		return credentials, nil
	}
	if code := Main([]string{tokenFile(t, dir, 0o600, token), out}, o); code != 1 {
		t.Fatal("replaced a file created during the request")
	}
	if raw, _ := os.ReadFile(out); string(raw) != "first" {
		t.Errorf("content %q", raw)
	}
	if !strings.Contains(o.Stderr.(*bytes.Buffer).String(), "the output file exists") {
		t.Error("message")
	}
}

func TestUnusableResponsesWriteNothing(t *testing.T) { // test_unusable_responses_write_nothing
	good := privateKey
	for name, response := range map[string]string{
		"empty": "", "not json": "not json", "array": "[]", "object": "{}", "null": "null",
		"short":      `{"nordlynx_private_key": "short"}`,
		"null key":   `{"nordlynx_private_key": null}`,
		"number":     `{"nordlynx_private_key": 7}`,
		"stray bits": `{"nordlynx_private_key": "` + good[:42] + `R="}`,
		"other name": `{"private_key": "` + good + `"}`,
		"duplicate":  `{"nordlynx_private_key": "` + good + `", "nordlynx_private_key": "x"}`,
		"bad utf-8":  "\xff\xfe",
	} {
		dir := t.TempDir()
		out := filepath.Join(dir, "out.conf")
		code, stdout, stderr := runTool(&fake{response: []byte(response)}, "", tokenFile(t, dir, 0o600, token+"\n"), out)
		if code != 1 || stdout != "" || !strings.HasPrefix(stderr, "error: ") {
			t.Errorf("%s: %d %q %q", name, code, stdout, stderr)
		}
		if _, err := os.Stat(out); err == nil {
			t.Errorf("%s: wrote the output", name)
		}
		assertNoSecrets(t, stdout, stderr)
	}
}

func TestFailedRequestWritesNothingAndPrintsAFixedLine(t *testing.T) { // test_failed_request_writes_nothing_and_prints_a_fixed_line
	dir := t.TempDir()
	out := filepath.Join(dir, "out.conf")
	code, stdout, stderr := runTool(&fake{err: errFetch}, "", tokenFile(t, dir, 0o600, token+"\n"), out)
	if code != 1 || stdout != "" || stderr != "error: the request to NordVPN failed\n" {
		t.Errorf("%d %q %q", code, stdout, stderr)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("wrote the output")
	}
}

func TestUnexpectedErrorDoesNotEchoItsMessage(t *testing.T) { // test_unexpected_error_does_not_echo_its_message
	dir := t.TempDir()
	code, stdout, stderr := runTool(&fake{err: errors.New("leaked " + token + " " + privateKey)}, "", tokenFile(t, dir, 0o600, token), filepath.Join(dir, "out.conf"))
	if code != 1 || stderr != "error: the tunnel config could not be written\n" {
		t.Errorf("%d %q", code, stderr)
	}
	assertNoSecrets(t, stdout, stderr)
}

func TestUsageError(t *testing.T) { // test_usage_error
	for _, args := range [][]string{nil, {"only-one"}, {"a", "b", "c"}} {
		code, _, stderr := runTool(&fake{}, "", args...)
		if code != 2 || !strings.Contains(stderr, "usage: molebridge nordvpn-key") {
			t.Errorf("%q: %d %q", args, code, stderr)
		}
	}
	var out bytes.Buffer
	if code := Main([]string{"--help"}, Options{Stdout: &out}); code != 0 || !strings.Contains(out.String(), "--user") {
		t.Error("help")
	}
}

func TestTokenIsNeverTakenFromTheEnvironment(t *testing.T) { // test_token_is_never_taken_from_the_environment
	dir := t.TempDir()
	f := &fake{response: credentials}
	var out, errb bytes.Buffer
	o := Options{Env: map[string]string{"NORDVPN_TOKEN": token, "NORD_TOKEN": token}, Stdout: &out, Stderr: &errb, Fetch: f.fetch}
	if code := Main([]string{filepath.Join(dir, "missing"), filepath.Join(dir, "out.conf")}, o); code != 1 || len(f.tokens) != 0 {
		t.Error("read the token from the environment")
	}
}

func TestExitTableComesFromTheEnvironment(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.conf")
	f := &fake{response: credentials}
	var so, se bytes.Buffer
	o := Options{Env: map[string]string{"EXIT_TABLE": "40000"}, Stdout: &so, Stderr: &se, Fetch: f.fetch}
	if code := Main([]string{tokenFile(t, dir, 0o600, token), out}, o); code != 0 {
		t.Fatal(se.String())
	}
	raw, _ := os.ReadFile(out)
	if !strings.Contains(string(raw), "table 40000") {
		t.Error("EXIT_TABLE ignored")
	}
	// A bad table is the generic failure, after the request (as in Python).
	o.Env = map[string]string{"EXIT_TABLE": "12"}
	se.Reset()
	other := filepath.Join(dir, "other.conf")
	if code := Main([]string{tokenFile(t, dir, 0o600, token), other}, o); code != 1 || se.String() != "error: the tunnel config could not be written\n" {
		t.Errorf("%q", se.String())
	}
	if _, err := os.Stat(other); err == nil {
		t.Error("wrote with a bad table")
	}
}

// -- the HTTP client -------------------------------------------------------

func testClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	client := NewClient()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	client.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	return client
}

func TestFetchSendsTheCredentialOnlyAsBasicAuth(t *testing.T) { // test_fetch_passes_the_credential_only_in_a_private_file
	var seen *http.Request
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		w.Write(credentials)
	}))
	defer srv.Close()
	got, err := FetchCredentials(testClient(t, srv), srv.URL+"/v1/users/services/credentials", token)
	if err != nil || !bytes.Equal(got, credentials) {
		t.Fatalf("%q %v", got, err)
	}
	user, pass, ok := seen.BasicAuth()
	if !ok || user != "token" || pass != token || seen.Method != "GET" || seen.URL.Path != "/v1/users/services/credentials" {
		t.Errorf("request: %v %q %q %q", ok, user, pass, seen.URL)
	}
	if strings.Contains(seen.URL.String(), token) || strings.Contains(seen.URL.RawQuery, "token") {
		t.Error("token in the URL")
	}
}

func TestFetchFailureIsAFixedError(t *testing.T) { // test_fetch_failure_is_a_fixed_error_and_cleans_up
	big := bytes.Repeat([]byte("x"), ResponseMaxBytes+1)
	for name, handler := range map[string]http.HandlerFunc{
		"401":            func(w http.ResponseWriter, r *http.Request) { http.Error(w, "bad "+token, 401) },
		"500":            func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) },
		"too big":        func(w http.ResponseWriter, r *http.Request) { w.Write(big) },
		"too big chunks": func(w http.ResponseWriter, r *http.Request) { w.(http.Flusher).Flush(); w.Write(big) },
		"hangs up": func(w http.ResponseWriter, r *http.Request) {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
		},
	} {
		srv := httptest.NewTLSServer(handler)
		_, err := FetchCredentials(testClient(t, srv), srv.URL, token)
		srv.Close()
		if err != errFetch || strings.Contains(err.Error(), token) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A server that is gone, and one that speaks plain HTTP to an https URL.
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	url := srv.URL
	client := testClient(t, srv)
	srv.Close()
	if _, err := FetchCredentials(client, url, token); err != errFetch {
		t.Errorf("closed server: %v", err)
	}
	plain := httptest.NewServer(http.NotFoundHandler())
	defer plain.Close()
	if _, err := FetchCredentials(NewClient(), "https"+strings.TrimPrefix(plain.URL, "http"), token); err != errFetch {
		t.Errorf("plain server: %v", err)
	}
	// An untrusted certificate is refused (the default roots do not hold it).
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(credentials) }))
	defer srv.Close()
	if _, err := FetchCredentials(NewClient(), srv.URL, token); err != errFetch {
		t.Errorf("untrusted certificate: %v", err)
	}
}

func TestFetchDoesNotFollowRedirects(t *testing.T) {
	hits := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write(credentials)
	}))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()
	body, err := FetchCredentials(testClient(t, srv), srv.URL, token)
	if hits != 0 {
		t.Error("followed a redirect and sent the credential on")
	}
	// As with curl without -L, the 3xx body is returned and then fails to parse.
	if err != nil {
		t.Fatal(err)
	}
	if _, perr := ParsePrivateKey(body); perr == nil {
		t.Error("a redirect body parsed as credentials")
	}
}

func TestClientIgnoresTheProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("https_proxy", "http://127.0.0.1:1")
	tr := NewClient().Transport.(*http.Transport)
	if tr.Proxy != nil {
		t.Error("the client reads proxy settings")
	}
	if tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Error("TLS below 1.2")
	}
	if NewClient().Timeout != Timeout {
		t.Error("no deadline")
	}
}
