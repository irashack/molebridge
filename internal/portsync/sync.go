package portsync

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/validate"
)

const (
	// maxRecordBytes bounds result.json, as the panel does.
	maxRecordBytes = 16384
	// maxRecordAge is how long, in seconds, a status record counts as
	// current (the applier's own bound, state.StatusMaxAge).
	maxRecordAge = 150
	// repeatAfter is how long a failure kind stays quiet after it was logged.
	repeatAfter = time.Minute
	// maxAnswerBytes bounds every answer from the application.
	maxAnswerBytes = 256 << 10
	// MinPort and MaxPort bound a forwarded port the role will install.
	MinPort = 1024
	MaxPort = 65535
)

// Fetcher is the HTTP client: netx.Client in the role, a fake in tests.
type Fetcher interface {
	Fetch(ctx context.Context, req netx.Request) (netx.Response, error)
}

// Failure kinds, each logged at most once a minute.
const (
	kindRecord      = "record"
	kindForeign     = "foreign"
	kindPortValue   = "port-value"
	kindUnreachable = "unreachable"
	kindCredentials = "credentials"
	kindLogin       = "login"
	kindForbidden   = "forbidden"
	kindAnswer      = "answer"
	kindSecretFile  = "secret-file"
)

// Syncer is one run of the role. Its fields other than the settings are
// optional in a test and filled by New.
type Syncer struct {
	Settings Settings
	HTTP     Fetcher
	Now      func() time.Time
	Log      io.Writer

	cookie     string               // the session cookie, in memory only
	lastLogged map[string]time.Time // failure kind -> when it was last logged
	noPortSaid bool                 // "no forwarded port yet" was said and no port seen since
}

// New returns a Syncer on the real clock and the real HTTP client.
func New(s Settings, log io.Writer) *Syncer {
	return &Syncer{Settings: s, HTTP: netx.Client{}, Now: time.Now, Log: log}
}

// Run does a pass at once and then every Interval until ctx ends.
func (y *Syncer) Run(ctx context.Context) {
	for {
		y.Step(ctx)
		timer := time.NewTimer(y.Settings.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Step does one pass: read the record, and if it carries a forwarded port, make
// the application listen on it.
func (y *Syncer) Step(ctx context.Context) {
	port, ok := y.forwardedPort()
	if !ok || ctx.Err() != nil {
		return
	}
	y.syncQBittorrent(ctx, port)
}

// forwardedPort judges the status record. It logs why not when it returns false.
func (y *Syncer) forwardedPort() (int, bool) {
	now := y.now()
	record, ok := jsonfile.ReadObject(filepath.Join(y.Settings.StateDir, "applier", "result.json"), maxRecordBytes)
	if !ok || !validate.Recent(record["checked_at"], maxRecordAge, now) {
		y.failure(kindRecord, "no current status record from the exit")
		return 0, false
	}
	if kind, _ := record["kind"].(string); kind != "sidecar" {
		y.failure(kindForeign, "the status record is not a sidecar's")
		return 0, false
	}
	value, present := record["forwarded_port"]
	if !present || value == nil {
		if !y.noPortSaid {
			y.noPortSaid = true
			y.line("no forwarded port yet")
		}
		return 0, false
	}
	y.noPortSaid = false
	port, isInt := validate.IsInt(value)
	if !isInt || port < MinPort || port > MaxPort {
		y.failure(kindPortValue, "the status record's forwarded_port is not an integer from 1024 to 65535")
		return 0, false
	}
	return int(port), true
}

func (y *Syncer) now() time.Time {
	if y.Now != nil {
		return y.Now()
	}
	return time.Now()
}

func (y *Syncer) line(format string, args ...any) {
	if y.Log != nil {
		fmt.Fprintf(y.Log, Prefix+format+"\n", args...)
	}
}

// failure logs a message unless the same kind was logged within a minute.
func (y *Syncer) failure(kind, message string) {
	now := y.now()
	if last, seen := y.lastLogged[kind]; seen && now.Sub(last) < repeatAfter && !now.Before(last) {
		return
	}
	if y.lastLogged == nil {
		y.lastLogged = map[string]time.Time{}
	}
	y.lastLogged[kind] = now
	y.line("%s", message)
}

// qbError is a failed exchange with qBittorrent: its kind and message.
type qbError struct{ kind, message string }

func (y *Syncer) syncQBittorrent(ctx context.Context, port int) {
	if err := y.apply(ctx, port); err != nil {
		y.failure(err.kind, err.message)
	}
}

func (y *Syncer) apply(ctx context.Context, port int) *qbError {
	answer, err := y.call(ctx, http.MethodGet, "/api/v2/app/preferences", nil)
	if err != nil {
		return err
	}
	if answer.Status != 200 {
		return &qbError{kindAnswer, fmt.Sprintf("qBittorrent answered the preferences request with HTTP %d", answer.Status)}
	}
	decoded, derr := validate.DecodeJSON(answer.Body)
	preferences, isObject := decoded.(map[string]any)
	if derr != nil || !isObject {
		return &qbError{kindAnswer, "qBittorrent's preferences are not a JSON object"}
	}
	current, isInt := validate.IsInt(preferences["listen_port"])
	if !isInt || current < 0 || current > 65535 {
		return &qbError{kindAnswer, "qBittorrent's preferences have no integer listen_port"}
	}
	if int(current) == port {
		return nil
	}
	form := url.Values{"json": {fmt.Sprintf(`{"listen_port":%d,"random_port":false,"upnp":false}`, port)}}
	answer, err = y.call(ctx, http.MethodPost, "/api/v2/app/setPreferences", form)
	if err != nil {
		return err
	}
	if answer.Status != 200 {
		return &qbError{kindAnswer, fmt.Sprintf("qBittorrent answered the port change with HTTP %d", answer.Status)}
	}
	y.line("qBittorrent listens on %d; set to %d", current, port)
	return nil
}

// call sends one request. With credentials it logs in first when it holds no
// cookie, and after a 403 it logs in again and repeats the request once.
func (y *Syncer) call(ctx context.Context, method, path string, form url.Values) (netx.Response, *qbError) {
	hasCredentials := y.Settings.UsernameFile != ""
	if hasCredentials && y.cookie == "" {
		if err := y.login(ctx); err != nil {
			return netx.Response{}, err
		}
	}
	answer, err := y.send(ctx, method, path, form)
	if err != nil {
		return netx.Response{}, err
	}
	if answer.Status != http.StatusForbidden {
		return answer, nil
	}
	if !hasCredentials {
		return netx.Response{}, &qbError{kindForbidden,
			"qBittorrent refused the request (HTTP 403); it needs the login: set PORT_SYNC_USERNAME_FILE and PORT_SYNC_PASSWORD_FILE"}
	}
	y.cookie = ""
	if err := y.login(ctx); err != nil {
		return netx.Response{}, err
	}
	answer, err = y.send(ctx, method, path, form)
	if err != nil {
		return netx.Response{}, err
	}
	if answer.Status == http.StatusForbidden {
		y.cookie = ""
		return netx.Response{}, &qbError{kindForbidden, "qBittorrent refused the request (HTTP 403) after a new login"}
	}
	return answer, nil
}

func (y *Syncer) send(ctx context.Context, method, path string, form url.Values) (netx.Response, *qbError) {
	request := netx.Request{
		URL:       strings.TrimSuffix(y.Settings.URL, "/") + path,
		Method:    method,
		AllowHTTP: true,
		AnyStatus: true,
		MaxBytes:  maxAnswerBytes,
		Timeout:   10 * time.Second,
		UserAgent: "molebridge-port-sync",
		// qBittorrent compares the Host header (the URL's own host, which
		// net/http sends) and the Referer with its own address.
		Header: map[string]string{"Referer": y.Settings.URL},
	}
	if form != nil {
		request.Body = []byte(form.Encode())
		request.Header["Content-Type"] = "application/x-www-form-urlencoded"
	}
	if y.cookie != "" {
		request.Header["Cookie"] = y.cookie
	}
	answer, err := y.HTTP.Fetch(ctx, request)
	if err != nil {
		return netx.Response{}, &qbError{kindUnreachable, "qBittorrent could not be reached (" + strings.TrimPrefix(err.Error(), "netx: ") + ")"}
	}
	return answer, nil
}

// login reads the credential files, logs in and keeps the session cookie.
func (y *Syncer) login(ctx context.Context) *qbError {
	user, uerr := ReadCredential(y.Settings.UsernameFile)
	password, perr := ReadCredential(y.Settings.PasswordFile)
	if uerr != nil || perr != nil {
		return &qbError{kindSecretFile, "the login credential files cannot be read (PORT_SYNC_USERNAME_FILE, PORT_SYNC_PASSWORD_FILE)"}
	}
	y.cookie = ""
	answer, err := y.send(ctx, http.MethodPost, "/api/v2/auth/login", url.Values{"username": {user}, "password": {password}})
	if err != nil {
		return err
	}
	// qBittorrent 5.2 answers a good login with 204 and no body, a bad one
	// with 401; earlier releases answer 200 with "Ok." or "Fails.".
	switch answer.Status {
	case http.StatusForbidden:
		return &qbError{kindLogin, "qBittorrent refused the login (HTTP 403); it may have banned this address after failed logins"}
	case http.StatusUnauthorized:
		return &qbError{kindCredentials, "qBittorrent refused the user name or password"}
	case http.StatusNoContent:
	case http.StatusOK:
		switch strings.TrimSpace(string(answer.Body)) {
		case "Ok.":
		case "Fails.":
			return &qbError{kindCredentials, "qBittorrent refused the user name or password"}
		default:
			return &qbError{kindLogin, "qBittorrent answered the login with an unexpected body"}
		}
	default:
		return &qbError{kindLogin, fmt.Sprintf("qBittorrent answered the login with HTTP %d", answer.Status)}
	}
	for _, c := range (&http.Response{Header: answer.Header}).Cookies() {
		// SID, or QBT_SID_<port> in qBittorrent 5.
		if c.Value != "" && (c.Name == "SID" || strings.HasPrefix(c.Name, "QBT_SID_")) {
			y.cookie = c.Name + "=" + c.Value
			return nil
		}
	}
	return &qbError{kindLogin, "qBittorrent accepted the login but sent no session cookie"}
}
