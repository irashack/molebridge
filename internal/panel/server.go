package panel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/irashack/molebridge/internal/panel/oidc"
	"github.com/irashack/molebridge/internal/panel/pystr"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
	"github.com/irashack/molebridge/panel/static"
)

const (
	maxBodyBytes   = 4096
	csrfCookieName = "csrf_nonce"
	exitCookieName = "molebridge_exit"
	// ListenAddr is where the panel listens: all interfaces in its own
	// container, published on loopback only by the Compose file.
	ListenAddr = "0.0.0.0:8080"
)

// Server is the panel: one process-lifetime value holding the settings, the
// exits, the sign-in state and the probe state that app.py kept in module
// globals.
type Server struct {
	Settings *Settings
	// Exits is PANEL_EXITS; empty means a single-exit panel, described by
	// Single.
	Exits  []Exit
	Single Exit
	Auth   *oidc.Authenticator

	// Log receives the panel's log lines (stderr in production).
	Log   io.Writer
	logMu sync.Mutex

	now  func() time.Time
	mono func() time.Time
	dial DialFunc
	// probe times one relay address; tests replace it.
	probe func(ip string) *float64
	files fs.FS

	csrfSecret []byte
	versions   map[string]string
	manifest   []byte
	secHeaders map[string]string
	latency    *latencyState

	selectMu    sync.Mutex
	selectLocks map[string]*sync.Mutex

	relayMu    sync.Mutex
	relayCache map[string]relayCacheEntry
}

type relayCacheEntry struct {
	mtimeNs int64
	size    int64
	relays  *providers.Entries
}

// Options are the parts of a Server a test replaces.
type Options struct {
	Now  func() time.Time
	Mono func() time.Time
	// AuthClock is the sign-in clock (default: Now).
	AuthClock func() time.Time
	Dial      DialFunc
	Log       io.Writer
	Files     fs.FS
	// HTTPClient is the client for the issuer (nil: oidc.NewIssuerClient()).
	HTTPClient *http.Client
}

// NewServer builds the panel from its configuration.
func NewServer(cfg *Config, opt Options) *Server {
	s := &Server{
		Settings: cfg.Settings, Exits: cfg.Exits, Single: cfg.Single,
		Log: opt.Log, now: opt.Now, mono: opt.Mono, dial: opt.Dial, files: opt.Files,
		latency: newLatencyState(), selectLocks: map[string]*sync.Mutex{}, relayCache: map[string]relayCacheEntry{},
	}
	if s.Log == nil {
		s.Log = os.Stderr
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.mono == nil {
		s.mono = time.Now
	}
	if s.dial == nil {
		s.dial = (&net.Dialer{}).DialContext
	}
	if s.files == nil {
		s.files = static.Files
	}
	s.probe = func(ip string) *float64 {
		return probeTCPRTT(s.dial, ip, probePort, probeTimeout, probeAttempts, s.mono)
	}
	s.csrfSecret = make([]byte, 32)
	if _, err := rand.Read(s.csrfSecret); err != nil {
		panic(err)
	}
	s.versions = staticVersions(s.files)
	s.manifest = s.buildManifest()
	s.secHeaders = s.securityHeaders()
	if cfg.Settings.Auth != nil {
		ids := make([]string, len(cfg.Exits))
		for i, e := range cfg.Exits {
			ids[i] = e.ID
		}
		authClock := opt.AuthClock
		if authClock == nil {
			authClock = opt.Now
		}
		s.Auth = oidc.NewAuthenticator(cfg.Settings.Auth, ids, authClock, opt.HTTPClient)
	}
	return s
}

func (s *Server) buildManifest() []byte {
	manifest := validate.Members(
		"name", s.Settings.Title, "short_name", s.Settings.ShortTitle, "start_url", "/", "scope", "/",
		"display", "standalone", "background_color", themeColor, "theme_color", themeColor,
		"icons", []any{
			validate.Members("src", "/static/icon-192.png", "sizes", "192x192", "type", "image/png"),
			validate.Members("src", "/static/icon-512.png", "sizes", "512x512", "type", "image/png"),
		})
	raw, err := validate.MarshalJSON(manifest)
	if err != nil {
		panic(err)
	}
	return raw
}

const cspBase = "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; " +
	"font-src 'self'; img-src 'self'; manifest-src 'self'; form-action 'self'; base-uri 'none'"

// securityHeaders are sent on every response. no-referrer would make
// browsers send `Origin: null` on form POSTs, which the origin check must
// reject; same-origin keeps the real origin.
func (s *Server) securityHeaders() map[string]string {
	headers := map[string]string{
		"Referrer-Policy":        "same-origin",
		"X-Content-Type-Options": "nosniff",
	}
	if ancestors := s.Settings.FrameAncestors; len(ancestors) > 0 {
		headers["Content-Security-Policy"] = cspBase + "; frame-ancestors " + strings.Join(ancestors, " ")
	} else {
		headers["Content-Security-Policy"] = cspBase + "; frame-ancestors 'none'"
		headers["X-Frame-Options"] = "DENY"
	}
	return headers
}

// -- exits ---------------------------------------------------------------------

func (s *Server) allExits() []Exit {
	if len(s.Exits) > 0 {
		return s.Exits
	}
	return []Exit{s.Single}
}

// findExit is the named exit; a single-exit panel ignores the name.
func (s *Server) findExit(id string) (Exit, bool) {
	if len(s.Exits) == 0 {
		return s.Single, true
	}
	for _, e := range s.Exits {
		if e.ID == id {
			return e, true
		}
	}
	return Exit{}, false
}

// granted is whether the caller may see and switch this exit. Without
// sign-in configured, everyone who reaches the panel may.
func (s *Server) granted(ex Exit, session *oidc.Session) bool {
	if s.Auth == nil {
		return true
	}
	if session == nil {
		return false
	}
	return session.Admin || (ex.ID != "" && session.Exits.Has(ex.ID))
}

// visibleExits are the configured exits this caller is granted, in
// configured order.
func (s *Server) visibleExits(session *oidc.Session) []Exit {
	var out []Exit
	for _, e := range s.Exits {
		if s.granted(e, session) {
			out = append(out, e)
		}
	}
	return out
}

// authorizedExit is findExit, refusing an exit the caller is not granted
// exactly as it refuses one that does not exist.
func (s *Server) authorizedExit(id string, session *oidc.Session) (Exit, bool) {
	ex, ok := s.findExit(id)
	if !ok || !s.granted(ex, session) {
		return Exit{}, false
	}
	return ex, true
}

// -- status: one read, one verdict, every consumer ------------------------------

// ExitStatus is one read of an exit's state files and the one verdict on it.
// The page, /api/status, the exit tabs, /readyz and the switch gate all
// render this.
type ExitStatus struct {
	Desired map[string]any // nil when absent
	Result  map[string]any // nil when absent
	Verdict verdict.Verdict
}

func (s *Server) exitConfig(ex Exit) verdict.ExitConfig {
	return verdict.ExitConfig{Provider: ex.Provider, Kind: ex.Kind, ID: ex.ID}
}

// judge is the verdict on result for this exit. The panel's own request is
// the target unless configuration holds the exit, when it is ignored.
func (s *Server) judge(ex Exit, desired, result any) ExitStatus {
	resultMap, _ := result.(map[string]any)
	var desiredMap map[string]any
	if _, configured := state.ConfiguredServer(resultMap); !configured {
		desiredMap, _ = desired.(map[string]any)
	}
	var resultArg any
	if resultMap != nil {
		resultArg = resultMap
	}
	var desiredArg any
	if desiredMap != nil {
		desiredArg = desiredMap
	}
	v := verdict.Assess(s.exitConfig(ex), resultArg, verdict.TargetForPanel(resultArg, desiredArg, ex.Provider), s.now())
	return ExitStatus{Desired: desiredMap, Result: resultMap, Verdict: v}
}

func (s *Server) readStatus(ex Exit) ExitStatus {
	result := state.ReadJSON(ex.ResultPath, 16384)
	// A configured exit's request file isn't even read.
	var desired any
	if _, configured := state.ConfiguredServer(result); !configured {
		desired = state.ReadJSON(ex.DesiredPath, 4096)
	}
	return s.judge(ex, desired, result)
}

// exitView is the verdict as describe reads it: complete checks, and who
// performs a check Molebridge doesn't.
func (s *Server) exitView(ex Exit, v verdict.Verdict) exitView {
	config := s.exitConfig(ex)
	checks := map[string]string{}
	for _, c := range verdict.FixedChecks(ex.Kind, config.Backend()) {
		checks[c.Name] = c.State
	}
	for _, c := range v.Checks {
		checks[c.Name] = c.State
	}
	complete := map[string]string{}
	by := map[string]string{}
	for _, name := range verdict.CheckNames {
		st := checks[name]
		if st == "" {
			st = "unknown"
		}
		complete[name] = st
		if who, ok := verdict.NotCheckedBy[name]; ok && st == "not-checked" {
			by[name] = who
		}
	}
	return exitView{
		State: v.State, Label: v.Label, Kind: v.Kind, Tier: v.Tier, Message: v.Message, Reasons: v.Reasons,
		NextAction: v.NextAction, NextActionAt: v.NextActionAt, NotCheckedBy: by, Checks: complete,
	}
}

// verdictJSON is the verdict as /api/status sends it, with `checks`
// complete: every check named, as the verdict states it, else as the kind
// fixes it, else unknown. `not_checked_by` names who performs a check
// Molebridge doesn't.
func (s *Server) verdictJSON(ex Exit, v verdict.Verdict) validate.Obj {
	view := s.exitView(ex, v)
	checks := make(validate.Obj, 0, len(verdict.CheckNames))
	var by validate.Obj
	for _, name := range verdict.CheckNames {
		checks = append(checks, validate.Pair{Key: name, Value: view.Checks[name]})
		if who, ok := view.NotCheckedBy[name]; ok {
			by = append(by, validate.Pair{Key: name, Value: who})
		}
	}
	if by == nil {
		by = validate.Obj{}
	}
	return v.AsJSON().Set("checks", checks).Set("not_checked_by", by)
}

// legacyView is /api/status's `view`, deprecated: kept whole for one release
// because a 0.6 page still open in a browser reads it until it reloads.
func legacyView(v verdict.Verdict) validate.Obj {
	var tier, configured any
	if v.Tier != "" {
		tier = v.Tier
	}
	mode := "panel"
	if v.ConfiguredServer != "" {
		mode, configured = "configuration", v.ConfiguredServer
	}
	return validate.Members("state", v.State, "label", v.Label, "tier", tier, "selection_mode", mode,
		"configured_server", configured)
}

// statusPayload is /api/status's body.
func (s *Server) statusPayload(ex Exit, status ExitStatus) validate.Obj {
	var result any
	if status.Result != nil {
		result = status.Result
		if projection, ok := verdict.LegacyProjection(status.Result, status.Verdict); ok {
			// Deprecated, one release: the 0.6 diagnostic fields a cached 0.6
			// script reads, derived from the verdict for a schema-2 record
			// (null where unknown or not applicable). A record's own fields
			// win.
			merged := validate.Obj{}
			for _, p := range projection.JSONObject() {
				if own, present := status.Result[p.Key]; present {
					merged = append(merged, validate.Pair{Key: p.Key, Value: own})
				} else {
					merged = append(merged, p)
				}
			}
			rest := make([]string, 0, len(status.Result))
			for k := range status.Result {
				if !projectionHas(projection.JSONObject(), k) {
					rest = append(rest, k)
				}
			}
			sort.Strings(rest)
			for _, k := range rest {
				merged = append(merged, validate.Pair{Key: k, Value: status.Result[k]})
			}
			result = merged
		}
	}
	var desired any
	if status.Desired != nil {
		desired = status.Desired
	}
	return validate.Members("desired", desired, "result", result, "verdict", s.verdictJSON(ex, status.Verdict),
		"view", legacyView(status.Verdict))
}

// cachedRelays is the exit's catalogue, re-read only when the snapshot file
// changes. For display only (the exit tabs); switching always re-reads it.
func (s *Server) cachedRelays(ex Exit) *providers.Entries {
	info, err := os.Stat(ex.RelaysPath)
	if err != nil {
		return providers.NewEntries()
	}
	s.relayMu.Lock()
	cached, ok := s.relayCache[ex.RelaysPath]
	s.relayMu.Unlock()
	if ok && cached.mtimeNs == info.ModTime().UnixNano() && cached.size == info.Size() {
		return cached.relays
	}
	relays := s.loadRelays(ex)
	s.relayMu.Lock()
	s.relayCache[ex.RelaysPath] = relayCacheEntry{info.ModTime().UnixNano(), info.Size(), relays}
	s.relayMu.Unlock()
	return relays
}

func (s *Server) loadRelays(ex Exit) *providers.Entries {
	return providers.SnapshotRelays(providers.ReadSnapshot(ex.RelaysPath, ex.Provider), ex.Provider)
}

// loadAllowlist is the set of names a switch may request: the fresh
// catalogue's, or none.
func (s *Server) loadAllowlist(ex Exit) *providers.Entries {
	snapshot := providers.ReadSnapshot(ex.RelaysPath, ex.Provider)
	if snapshot == nil || !state.Recent(snapshot["fetched_at"], state.CatalogMaxAge, s.now()) {
		return providers.NewEntries()
	}
	return providers.SnapshotRelays(snapshot, ex.Provider)
}

// fetchError is the page's relay refresh error: the applier's message, or a
// fixed one when there is no fresh catalogue.
func (s *Server) fetchError(ex Exit) (message, at string) {
	data, _ := state.ReadObject(ex.RelayErrorPath, 4096)
	snapshot := providers.ReadSnapshot(ex.RelaysPath, ex.Provider)
	if snapshot == nil || !state.Recent(snapshot["fetched_at"], state.CatalogMaxAge, s.now()) {
		return "No fresh trusted relay catalogue; selections are unavailable.", ""
	}
	if data == nil {
		return "", ""
	}
	return orEmpty(data["message"]), orEmpty(data["checked_at"])
}

// exitSummary is what an exit tab shows: name, provider, state and where it
// exits.
func (s *Server) exitSummary(ex Exit, status *ExitStatus) ExitSummary {
	var st ExitStatus
	if status != nil {
		st = *status
	} else {
		st = s.readStatus(ex)
	}
	place := ""
	if server, ok := st.Result["server"].(string); ok && st.Verdict.State == "ok" {
		if info, found := s.cachedRelays(ex).Get(server); found {
			place = info.City
		}
	}
	return ExitSummary{ID: ex.ID, Label: ex.Label, Provider: ex.Provider, State: st.Verdict.State,
		Status: st.Verdict.Label, Place: place}
}

func summaryJSON(x ExitSummary) validate.Obj {
	return validate.Members("id", x.ID, "label", x.Label, "provider", x.Provider, "state", x.State,
		"status", x.Status, "place", x.Place)
}

// -- CSRF ----------------------------------------------------------------------

func newCSRFNonce() string {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// csrfToken ties a nonce to the panel's key; binding ties the token to a
// signed-in session, so a token read by one person cannot be replayed with
// another person's session.
func (s *Server) csrfToken(nonce, binding string) string {
	message := nonce
	if binding != "" {
		message = nonce + "\n" + binding
	}
	mac := hmac.New(sha256.New, s.csrfSecret)
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

var (
	csrfTokenRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
	csrfNonceRE = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)
)

func (s *Server) verifyCSRF(nonce string, haveNonce bool, token, binding string) bool {
	if !haveNonce || !csrfTokenRE.MatchString(token) {
		return false
	}
	return hmac.Equal([]byte(s.csrfToken(nonce, binding)), []byte(token))
}

// -- responses and logs -------------------------------------------------------------

type reply struct {
	code        int
	contentType string
	body        []byte
	headers     [][2]string
	cookies     []string
}

func plain(code int, message string) reply {
	return reply{code: code, contentType: "text/plain; charset=utf-8", body: []byte(message)}
}

func redirect(location string, cookies ...string) reply {
	return reply{code: 303, contentType: "text/plain; charset=utf-8",
		headers: [][2]string{{"Location", location}, {"Cache-Control", "no-store"}}, cookies: cookies}
}

func (s *Server) jsonReply(value any) reply {
	raw, err := validate.MarshalJSON(value)
	if err != nil {
		return plain(500, "internal error")
	}
	return reply{code: 200, contentType: "application/json", body: raw, headers: [][2]string{{"Cache-Control", "no-store"}}}
}

func apiSignedOut() reply {
	return reply{code: 401, contentType: "application/json", body: []byte(`{"error": "sign in required"}`),
		headers: [][2]string{{"Cache-Control", "no-store"}}}
}

func htmlReply(code int, body string, extra ...[2]string) reply {
	return reply{code: code, contentType: "text/html; charset=utf-8", body: []byte(body),
		headers: append([][2]string{{"Cache-Control", "no-store"}}, extra...)}
}

var knownRoutes = map[string]bool{
	"/": true, "/embed": true, "/healthz": true, "/readyz": true, "/api/status": true, "/api/exits": true,
	"/api/latency": true, "/select": true, "/manifest.webmanifest": true, "/login": true,
	"/auth/callback": true, "/logout": true, "/signed-out": true,
}

// logRequest writes one fixed-route line: no addresses or user-controlled
// text.
func (s *Server) logRequest(r *http.Request) {
	path, _, _ := strings.Cut(r.RequestURI, "?")
	route := "(unknown route)"
	if knownRoutes[path] {
		route = path
	} else if name, ok := strings.CutPrefix(path, "/static/"); ok && s.staticType(name) != "" {
		route = path
	}
	method := "(other method)"
	switch r.Method {
	case http.MethodGet, http.MethodPost, http.MethodHead:
		method = r.Method
	}
	t := s.now().Local()
	s.writeLog(fmt.Sprintf("%02d/%s/%04d %02d:%02d:%02d %s %s\n", t.Day(), t.Month().String()[:3], t.Year(),
		t.Hour(), t.Minute(), t.Second(), method, route))
}

func (s *Server) writeLog(line string) {
	s.logMu.Lock()
	defer s.logMu.Unlock()
	io.WriteString(s.Log, line)
}

// logEvent is log_event: a timestamped line.
func (s *Server) logEvent(text string) {
	s.writeLog(s.now().UTC().Format("2006-01-02T15:04:05Z") + " " + text + "\n")
}

func (s *Server) send(w http.ResponseWriter, r *http.Request, rep reply) {
	h := w.Header()
	h.Set("Content-Type", rep.contentType)
	h.Set("Content-Length", strconv.Itoa(len(rep.body)))
	for _, kv := range rep.headers {
		h.Set(kv[0], kv[1])
	}
	for _, c := range rep.cookies {
		h.Add("Set-Cookie", c)
	}
	h.Set("Connection", "close")
	for k, v := range s.secHeaders {
		h.Set(k, v)
	}
	w.WriteHeader(rep.code)
	w.Write(rep.body)
	s.logRequest(r)
}

// -- request helpers -----------------------------------------------------------------

func (s *Server) cookie(r *http.Request, name string) (string, bool) {
	header := r.Header.Get("Cookie")
	if s.Auth == nil {
		return getCookie(header, name)
	}
	return getCookieStrict(header, name)
}

func (s *Server) session(r *http.Request) *oidc.Session {
	if s.Auth == nil {
		return nil
	}
	id, _ := s.cookie(r, oidc.SessionCookie)
	return s.Auth.Session(id)
}

func (s *Server) csrfBinding(session *oidc.Session) string {
	if session != nil {
		return session.CSRFKey
	}
	return ""
}

// misdirected answers 421 for a name the panel is not published under.
func (s *Server) misdirected(w http.ResponseWriter, r *http.Request) bool {
	if s.Settings.HostAllowed(r.Host) {
		return false
	}
	s.writeLog("rejected request: host is not in PANEL_PUBLIC_HOSTS or loopback\n")
	s.send(w, r, plain(421, "unknown host; publish the panel under PANEL_PUBLIC_HOSTS"))
	return true
}

// requestedExit is the exit a request names with ?exit=; it answers 404 for
// a name that is not configured or not granted to the caller, with the same
// response for both.
func (s *Server) requestedExit(w http.ResponseWriter, r *http.Request, query map[string][]string, session *oidc.Session) (Exit, bool) {
	ex, ok := s.authorizedExit(first(query, "exit"), session)
	if !ok {
		s.send(w, r, plain(404, "unknown exit"))
	}
	return ex, ok
}

// signedOut answers 401 when sign-in is configured and there is no session.
func (s *Server) signedOut(w http.ResponseWriter, r *http.Request, session *oidc.Session, api bool) bool {
	if s.Auth == nil || session != nil {
		return false
	}
	if api {
		s.send(w, r, apiSignedOut())
	} else {
		s.send(w, r, plain(401, "sign in required"))
	}
	return true
}

var nextPathRE = regexp.MustCompile(`^/(embed)?(\?exit=[a-z0-9][a-z0-9-]{0,31})?$`)

// safeNext is where to land after sign-in: a panel page, never another site.
func safeNext(value string) string {
	if nextPathRE.MatchString(value) {
		return value
	}
	return "/"
}

// loginURL is absolute, on the canonical https address: the proxy in front
// may also answer plain http, where a Secure cookie can be neither set nor
// sent.
func (s *Server) loginURL(nextPath string) string {
	return s.Settings.Auth.PublicURL + "/login?" + pystr.Encode(pystr.Pair{Key: "next", Value: safeNext(nextPath)})
}

// authCookie: __Host- names require Secure, Path=/ and no Domain, so a
// sibling subdomain cannot plant or overwrite them. Lax, not Strict: the
// browser arrives from the issuer by a cross-site redirect, and must bring
// both.
func authCookie(name, value string, maxAge int) string {
	return fmt.Sprintf("%s=%s; Path=/; Max-Age=%d; Secure; HttpOnly; SameSite=Lax", name, value, maxAge)
}

// ServeHTTP is the panel.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.doGET(w, r)
	case http.MethodPost:
		s.doPOST(w, r)
	default:
		message := "Unsupported method (" + pystr.Repr(r.Method) + ")."
		body := "<!DOCTYPE HTML>\n<html lang=\"en\">\n    <head>\n        <meta charset=\"utf-8\">\n" +
			"        <title>Error response</title>\n    </head>\n    <body>\n        <h1>Error response</h1>\n" +
			"        <p>Error code: 501</p>\n        <p>Message: " + pystr.Escape(message) + "</p>\n" +
			"        <p>Error code explanation: 501 - Server does not support this operation.</p>\n    </body>\n</html>\n"
		w.Header().Set("Content-Type", "text/html;charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.Header().Set("Connection", "close")
		w.WriteHeader(501)
		io.WriteString(w, body)
		s.logRequest(r)
	}
}

func (s *Server) doGET(w http.ResponseWriter, r *http.Request) {
	path, rawQuery := splitTarget(r.RequestURI)
	query := parseQS(rawQuery, false)
	if path == "/healthz" {
		s.send(w, r, plain(200, "ok"))
		return
	}
	if s.misdirected(w, r) {
		return
	}
	session := s.session(r)
	switch {
	case path == "/readyz":
		// Every exit, or the one named with ?exit=. Anonymous callers get only
		// the aggregate: with sign-in on, a named exit needs a session that is
		// granted it, and any other name is simply unknown.
		chosen := s.allExits()
		if _, named := query["exit"]; named {
			ex, ok := s.requestedExit(w, r, query, session)
			if !ok {
				return
			}
			chosen = []Exit{ex}
		}
		ready := true
		for _, e := range chosen {
			if s.readStatus(e).Verdict.State != "ok" {
				ready = false
			}
		}
		if ready {
			s.send(w, r, plain(200, "ready"))
		} else {
			s.send(w, r, plain(503, "not ready"))
		}
	case path == "/" || path == "/embed":
		embed := path == "/embed"
		if s.Auth != nil && session == nil {
			s.sendSignedOut(w, r, query, embed)
			return
		}
		if _, named := query["exit"]; len(s.Exits) > 0 && !named {
			// Always name the exit in the address: the page reloads itself, and
			// a reload must not follow another tab's choice.
			visible := s.visibleExits(session)
			if len(visible) == 0 {
				s.send(w, r, plain(404, "unknown exit"))
				return
			}
			ex := visible[0]
			if remembered, have := s.cookie(r, exitCookieName); have {
				if e, ok := s.authorizedExit(remembered, session); ok {
					ex = e
				}
			}
			page := "/"
			if embed {
				page = "/embed"
			}
			s.send(w, r, redirect(page+"?exit="+ex.ID))
			return
		}
		s.handleIndex(w, r, query, session, embed)
	case path == "/manifest.webmanifest":
		s.send(w, r, reply{code: 200, contentType: "application/manifest+json", body: s.manifest,
			headers: [][2]string{{"Cache-Control", "public, max-age=86400"}}})
	case path == "/api/status":
		if s.signedOut(w, r, session, true) {
			return
		}
		if ex, ok := s.requestedExit(w, r, query, session); ok {
			s.send(w, r, s.jsonReply(s.statusPayload(ex, s.readStatus(ex))))
		}
	case path == "/api/exits":
		if s.signedOut(w, r, session, true) {
			return
		}
		list := []any{}
		for _, e := range s.visibleExits(session) {
			list = append(list, summaryJSON(s.exitSummary(e, nil)))
		}
		s.send(w, r, s.jsonReply(validate.Members("exits", list)))
	case path == "/api/latency":
		if s.signedOut(w, r, session, true) {
			return
		}
		ex, ok := s.requestedExit(w, r, query, session)
		if !ok {
			return
		}
		s.handleLatency(w, r, query, ex)
	case path == "/login" && s.Auth != nil:
		s.handleLogin(w, r, query, session)
	case path == "/auth/callback" && s.Auth != nil:
		s.handleCallback(w, r, query)
	case path == "/signed-out" && s.Auth != nil:
		body := s.RenderMessage("Signed out", "You have signed out of this panel.", &[2]string{s.loginURL("/"), "Sign in"}, false)
		s.send(w, r, htmlReply(200, body))
	case strings.HasPrefix(path, "/static/"):
		s.handleStatic(w, r, strings.TrimPrefix(path, "/static/"))
	default:
		s.send(w, r, plain(404, "not found"))
	}
}

func (s *Server) handleLatency(w http.ResponseWriter, r *http.Request, query map[string][]string, ex Exit) {
	if !s.latency.admit(ex.ID) {
		// Backpressure: this exit already has a request running, or the panel
		// is at its limit. Nothing has been loaded yet.
		s.send(w, r, reply{code: 429, contentType: "application/json", body: []byte(`{"error": "latency busy"}`),
			headers: [][2]string{{"Cache-Control", "no-store"}, {"Retry-After", "3"}}})
		return
	}
	var body validate.Obj
	func() {
		defer s.latency.release(ex.ID)
		relays := s.loadRelays(ex)
		fresh := first(query, "fresh") == "1"
		measured := s.measureLatency(relays, latencyTargets(query, relays), fresh, ex.ID)
		latency := make(validate.Obj, 0, len(measured))
		for _, m := range measured {
			var ms any
			if m.MS != nil {
				ms = *m.MS
			}
			latency = append(latency, validate.Pair{Key: m.Hostname, Value: ms})
		}
		body = validate.Members("latency", latency)
		if country := first(query, "country"); country != "" {
			probed, total := countrySample(relays, country)
			body = append(body, validate.Pair{Key: "country", Value: validate.Members("probed", len(probed), "total", total)})
		}
	}()
	s.send(w, r, s.jsonReply(body))
}

func (s *Server) staticType(name string) string {
	for _, f := range staticTypes {
		if f.name == name {
			return f.contentType
		}
	}
	return ""
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request, name string) {
	contentType := s.staticType(name)
	if contentType == "" {
		s.send(w, r, plain(404, "not found"))
		return
	}
	body, err := fs.ReadFile(s.files, name)
	if err != nil {
		s.send(w, r, plain(404, "not found"))
		return
	}
	s.send(w, r, reply{code: 200, contentType: contentType, body: body,
		headers: [][2]string{{"Cache-Control", "public, max-age=86400"}}})
}

// sendSignedOut: the full page sends a browser straight to sign-in, on the
// canonical address. The embed shows a link instead: sign-in cannot run
// inside a frame.
func (s *Server) sendSignedOut(w http.ResponseWriter, r *http.Request, query map[string][]string, embed bool) {
	exitID := first(query, "exit")
	nextPath := "/"
	if exitIDRE.MatchString(exitID) {
		nextPath = "/?exit=" + exitID
	}
	if !embed {
		s.send(w, r, redirect(s.loginURL(nextPath)))
		return
	}
	body := s.RenderMessage("Signed out", "Sign in to see and switch your exit.", &[2]string{s.loginURL(nextPath), "Sign in ↗"}, true)
	s.send(w, r, htmlReply(200, body))
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request, query map[string][]string, session *oidc.Session) {
	nextPath := safeNext(first(query, "next"))
	proto := "https"
	if values := r.Header.Values("X-Forwarded-Proto"); len(values) > 0 {
		proto = values[0]
	}
	if _, canonical := query["canonical"]; strings.ToLower(pystr.Strip(proto)) != "https" && !canonical {
		// A sign-in started over plain http could not keep its Secure cookie.
		// The header only steers this redirect; nothing trusts it. Once only:
		// a proxy that always says http must not loop.
		s.send(w, r, redirect(s.loginURL(nextPath)+"&canonical=1"))
		return
	}
	if session != nil {
		s.send(w, r, redirect(s.Settings.Auth.PublicURL+nextPath))
		return
	}
	cookie, authorizeURL, err := s.Auth.Begin(nextPath)
	if err != nil {
		s.logEvent("sign-in unavailable: " + err.Error())
		body := s.RenderMessage("Sign-in unavailable", "The identity provider could not be reached. Try again in a minute.",
			&[2]string{s.loginURL(nextPath), "Try again"}, false)
		s.send(w, r, htmlReply(503, body))
		return
	}
	s.send(w, r, redirect(authorizeURL, authCookie(oidc.LoginCookie, cookie, oidc.LoginTTL)))
}

func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request, query map[string][]string) {
	clearLogin := authCookie(oidc.LoginCookie, "", 0)
	loginID, _ := s.cookie(r, oidc.LoginCookie)
	var sessionID string
	var session *oidc.Session
	var nextPath string
	var err error
	if _, refused := query["error"]; refused {
		// Consume the pending sign-in; the issuer's own text is not shown.
		s.Auth.Discard(loginID)
		err = &oidc.AuthError{Msg: "access: the identity provider refused the sign-in"}
	} else {
		sessionID, session, nextPath, err = s.Auth.Finish(loginID, first(query, "state"), first(query, "code"))
	}
	if err != nil {
		s.logEvent("sign-in failed: " + err.Error())
		refused := strings.HasPrefix(err.Error(), "access:")
		heading, message, code := "Sign-in failed", "The sign-in could not be completed. Start it again from the panel.", 400
		if refused {
			heading, message, code = "Not allowed", "This account is not allowed to use this panel.", 403
		}
		body := s.RenderMessage(heading, message, &[2]string{s.loginURL("/"), "Try again"}, false)
		rep := htmlReply(code, body)
		rep.cookies = []string{clearLogin}
		s.send(w, r, rep)
		return
	}
	admin, exits := "no", strings.Join(session.Exits.Sorted(), ",")
	if session.Admin {
		admin = "yes"
	}
	if exits == "" {
		exits = "-"
	}
	s.logEvent(fmt.Sprintf("signed in: user=%s sub=%s admin=%s exits=%s", session.Name, oidc.LogSafe(session.Sub), admin, exits))
	s.send(w, r, redirect(s.Settings.Auth.PublicURL+nextPath, clearLogin,
		authCookie(oidc.SessionCookie, sessionID, s.Settings.Auth.SessionTTL)))
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request, query map[string][]string, session *oidc.Session, embed bool) {
	ex, ok := s.requestedExit(w, r, query, session)
	if !ok {
		return
	}
	nonce, have := s.cookie(r, csrfCookieName)
	if !have || !csrfNonceRE.MatchString(nonce) {
		nonce = newCSRFNonce()
	}
	token := s.csrfToken(nonce, s.csrfBinding(session))
	fetchError, fetchErrorAt := s.fetchError(ex)
	// One verdict on this exit for the page and its own tab.
	status := s.readStatus(ex)
	snapshot := providers.ReadSnapshot(ex.RelaysPath, ex.Provider)
	var summaries []ExitSummary
	for _, e := range s.visibleExits(session) {
		if e.ID == ex.ID {
			summaries = append(summaries, s.exitSummary(e, &status))
		} else {
			summaries = append(summaries, s.exitSummary(e, nil))
		}
	}
	var user *string
	if session != nil {
		user = &session.Name
	}
	body := s.renderIndex(IndexPage{
		Exit: ex, Status: status, Relays: providers.SnapshotRelays(snapshot, ex.Provider), RelaysData: snapshot,
		FetchError: fetchError, FetchErrAt: fetchErrorAt, CSRFToken: token, Embed: embed, Exits: summaries, User: user,
		// A home dashboard is the operator's; people granted a single exit are
		// not sent there.
		ShowHome: s.Auth == nil || (session != nil && session.Admin),
	})
	// With sign-in on the panel is served over https, so these are Secure too.
	secure := ""
	if s.Auth != nil {
		secure = "; Secure"
	}
	cookies := []string{fmt.Sprintf("%s=%s; Path=/; HttpOnly; SameSite=Strict%s", csrfCookieName, nonce, secure)}
	if ex.ID != "" {
		cookies = append(cookies, fmt.Sprintf("%s=%s; Path=/; Max-Age=31536000; HttpOnly; SameSite=Strict%s", exitCookieName, ex.ID, secure))
	}
	rep := htmlReply(200, body)
	rep.cookies = cookies
	s.send(w, r, rep)
}

// -- POST ----------------------------------------------------------------------------

// readForm reads the bounded POST body as form fields, after the Origin
// check; ok is false once an error response has been sent.
func (s *Server) readForm(w http.ResponseWriter, r *http.Request) (map[string]string, bool) {
	header := r.Header.Get("Content-Length")
	if _, present := r.Header["Content-Length"]; !present {
		s.send(w, r, plain(411, "length required"))
		return nil, false
	}
	length, err := strconv.Atoi(pystr.Strip(header))
	if err != nil || length < 0 {
		s.send(w, r, plain(400, "bad content-length"))
		return nil, false
	}
	if length > maxBodyBytes {
		s.send(w, r, plain(413, "request body too large"))
		return nil, false
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r.Body, body); err != nil {
		var netErr net.Error
		switch {
		case errors.As(err, &netErr) && netErr.Timeout():
			s.send(w, r, plain(408, "request timeout"))
		case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
			s.send(w, r, plain(400, "incomplete body"))
		default:
			s.send(w, r, plain(408, "request timeout"))
		}
		return nil, false
	}
	if !s.Settings.OriginAllowed(r.Header.Get("Origin")) {
		s.writeLog("rejected POST: origin is not a published panel host\n")
		s.send(w, r, plain(403, "origin is not a published panel host"))
		return nil, false
	}
	return parseSelectForm(body), true
}

func (s *Server) selectLock(ex Exit) *sync.Mutex {
	s.selectMu.Lock()
	defer s.selectMu.Unlock()
	lock := s.selectLocks[ex.DesiredPath]
	if lock == nil {
		lock = &sync.Mutex{}
		s.selectLocks[ex.DesiredPath] = lock
	}
	return lock
}

func randomHex(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	return hex.EncodeToString(raw)
}

// processSelect validates a requested server and writes the request.
func (s *Server) processSelect(server string, haveServer bool, allowlist *providers.Entries, desiredPath, provider string) (int, string) {
	if !haveServer || !state.ValidServerName(server, provider) || !allowlist.Has(server) {
		return 400, "unknown or unlisted server"
	}
	request := validate.Members("server", server, "requested_at", validate.FormatTime(s.now()), "request_id", randomHex(16))
	if err := os.MkdirAll(filepath.Dir(desiredPath), 0o777); err == nil {
		err = state.WriteJSONAtomic(desiredPath, request, false, 0)
		if err != nil {
			return 500, "internal error"
		}
		return 303, "ok"
	}
	return 500, "internal error"
}

func (s *Server) doPOST(w http.ResponseWriter, r *http.Request) {
	path, _ := splitTarget(r.RequestURI)
	if (path != "/select" && path != "/logout") || (path == "/logout" && s.Auth == nil) {
		s.send(w, r, plain(404, "not found"))
		return
	}
	if s.misdirected(w, r) {
		return
	}
	fields, ok := s.readForm(w, r)
	if !ok {
		return
	}
	session := s.session(r)
	if path == "/logout" {
		// A missing session is fine: signing out twice lands on the same page.
		nonce, haveNonce := s.cookie(r, csrfCookieName)
		if session != nil && !s.verifyCSRF(nonce, haveNonce, fields["csrf_token"], session.CSRFKey) {
			s.send(w, r, plain(403, "invalid or missing csrf token"))
			return
		}
		if session != nil {
			id, _ := s.cookie(r, oidc.SessionCookie)
			s.Auth.End(id)
			s.logEvent("signed out: user=" + session.Name)
		}
		s.send(w, r, redirect(s.Settings.Auth.PublicURL+"/signed-out", authCookie(oidc.SessionCookie, "", 0)))
		return
	}
	if s.signedOut(w, r, session, false) {
		return
	}
	nonce, haveNonce := s.cookie(r, csrfCookieName)
	if !s.verifyCSRF(nonce, haveNonce, fields["csrf_token"], s.csrfBinding(session)) {
		s.send(w, r, plain(403, "invalid or missing csrf token"))
		return
	}
	ex, ok := s.authorizedExit(fields["exit"], session)
	if !ok {
		s.send(w, r, plain(400, "unknown exit"))
		return
	}
	// Assess, then write, under this exit's lock, so two requests can't both
	// pass on the same snapshot. The responses go out after it.
	var code int
	var message string
	lock := s.selectLock(ex)
	lock.Lock()
	v := s.readStatus(ex).Verdict
	switch {
	case v.ConfiguredServer != "":
		code, message = 403, "Exit is set in configuration; change SERVER to choose another server."
	case v.State == "applying":
		// D8. Only a switch the panel can see blocks: while the status is stale
		// or unreadable (unknown) a request goes through, and the applier
		// admits it or not.
		code, message = 409, "A switch is in progress; wait for it to finish."
	default:
		server, have := fields["server"]
		code, message = s.processSelect(server, have, s.loadAllowlist(ex), ex.DesiredPath, ex.Provider)
	}
	lock.Unlock()
	if code == 303 {
		if session != nil {
			exitID := ex.ID
			if exitID == "" {
				exitID = "-"
			}
			s.logEvent(fmt.Sprintf("switch: user=%s sub=%s exit=%s server=%s", session.Name, oidc.LogSafe(session.Sub), exitID, fields["server"]))
		}
		location := "/"
		if fields["return"] == "embed" {
			location = "/embed"
		}
		if ex.ID != "" {
			location += "?exit=" + ex.ID
		}
		s.send(w, r, reply{code: 303, contentType: "text/plain; charset=utf-8", headers: [][2]string{{"Location", location}}})
		return
	}
	s.send(w, r, plain(code, message))
}

func projectionHas(o validate.Obj, key string) bool {
	for _, p := range o {
		if p.Key == key {
			return true
		}
	}
	return false
}
