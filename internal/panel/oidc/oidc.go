// Package oidc is the optional OpenID Connect sign-in for Switchyard, ported
// from panel/oidc.py.
//
// Authorization code flow with PKCE (S256), as a public client unless a
// client secret file is configured. Standard library only.
//
// The ID token is taken from the issuer's token endpoint over a verified TLS
// connection, in exchange for a single-use code and a PKCE verifier that only
// this process knows. OpenID Connect Core 1.0 section 3.1.3.7 allows TLS
// server validation in place of checking the token's signature in exactly
// this case, which is what lets the panel stay free of a cryptography
// dependency. Its issuer, audience, authorized party, expiry, issue time and
// nonce are still checked. The groups claim comes from that ID token; when
// the ID token has no groups claim the userinfo endpoint is asked instead,
// and its subject must match. JWKS verification is a later option. See
// docs/architecture.md, "Sign-in".
//
// Sessions live in this process's memory only: a restart signs everyone out.
// Each has a fixed lifetime from sign-in (PANEL_SESSION_TTL), after which the
// browser goes back to the issuer and group membership is read again. A
// sign-in in progress is held by the browser, in a cookie this process signs,
// so nobody can crowd out someone else's sign-in by starting many of their
// own.
package oidc

import (
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/irashack/molebridge/internal/panel/pystr"
)

// Cookie names. The __Host- prefix requires Secure, Path=/ and no Domain.
const (
	SessionCookie = "__Host-molebridge_session"
	LoginCookie   = "__Host-molebridge_login"
)

// Limits and timings, all as in oidc.py.
const (
	DefaultScopes     = "openid profile email groups"
	DefaultSessionTTL = 3600
	MinSessionTTL     = 300
	MaxSessionTTL     = 7 * 24 * 3600
	LoginTTL          = 600
	DiscoveryTTL      = 3600
	DiscoveryRetryS   = 30
	HTTPTimeout       = 10 * time.Second
	UserAgent         = "molebridge-panel"
	MaxResponseBytes  = 256 * 1024
	ClockSkewS        = 120
	MaxGroups         = 256

	maxIDTokenChars = 64 * 1024
	maxCodeChars    = 4096
	maxSubjectChars = 255
)

// Limits bound the in-memory sign-in state. Tests lower them; a field of
// the Authenticator rather than package state.
type Limits struct {
	MaxSessions           int
	MaxSessionsPerSubject int
	MaxConsumedLogins     int
}

// DefaultLimits are oidc.py's MAX_SESSIONS, MAX_SESSIONS_PER_SUBJECT and
// MAX_CONSUMED_LOGINS.
func DefaultLimits() Limits {
	return Limits{MaxSessions: 4096, MaxSessionsPerSubject: 16, MaxConsumedLogins: 65536}
}

// AuthError is a sign-in that cannot complete. The message is fixed text,
// safe to show and to log; it never carries a token or an issuer response
// body.
type AuthError struct{ Msg string }

func (e *AuthError) Error() string { return e.Msg }

func authErr(format string, args ...any) *AuthError {
	return &AuthError{Msg: fmt.Sprintf(format, args...)}
}

// Set is a set of names (Python's frozenset of str).
type Set map[string]struct{}

// NewSet builds a Set.
func NewSet(items ...string) Set {
	s := Set{}
	for _, item := range items {
		s[item] = struct{}{}
	}
	return s
}

// Has reports membership.
func (s Set) Has(item string) bool { _, ok := s[item]; return ok }

// Sorted returns the members in order.
func (s Set) Sorted() []string {
	out := make([]string, 0, len(s))
	for item := range s {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

// Equal reports whether two sets hold the same members.
func (s Set) Equal(o Set) bool {
	if len(s) != len(o) {
		return false
	}
	for item := range s {
		if !o.Has(item) {
			return false
		}
	}
	return true
}

func isLoopbackHost(hostname string) bool {
	if hostname == "" {
		return false
	}
	if hostname == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(hostname)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

// SecureURL reports whether value is https, or http to a loopback address (a
// local test issuer), with no credentials or fragment.
func SecureURL(value string) bool {
	u, err := url.Parse(value)
	if err != nil {
		return false
	}
	if u.User != nil || u.Fragment != "" || u.Hostname() == "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && isLoopbackHost(strings.ToLower(u.Hostname())))
}

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------

// Config is the sign-in configuration.
type Config struct {
	Issuer       string
	ClientID     string
	ClientSecret *string // nil: a public client
	PublicURL    string  // canonical https origin, no trailing slash
	Scopes       string
	GroupsClaim  string
	AdminGroups  Set
	Access       map[string]Set // group -> exit ids
	SessionTTL   int
}

// RedirectURI is the callback address registered with the issuer.
func (c *Config) RedirectURI() string { return c.PublicURL + "/auth/callback" }

// PublicHost is PANEL_PUBLIC_URL's lowercase host and port (0: none given).
func (c *Config) PublicHost() (string, int) {
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return "", 0
	}
	port, _ := strconv.Atoi(u.Port())
	return strings.ToLower(u.Hostname()), port
}

// ExitsFor returns whether a set of group names is admin, and the exit ids
// they are granted.
func (c *Config) ExitsFor(groups Set, allExitIDs []string) (bool, Set) {
	for group := range groups {
		if c.AdminGroups.Has(group) {
			return true, NewSet(allExitIDs...)
		}
	}
	granted := Set{}
	for group := range groups {
		for id := range c.Access[group] {
			granted[id] = struct{}{}
		}
	}
	return false, granted
}

func splitList(raw string) []string {
	var out []string
	for _, item := range strings.Split(raw, ",") {
		if item = pystr.Strip(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// validGroup is GROUP_RE: 1 to 128 characters, none whitespace, comma or =.
func validGroup(group string) bool {
	n := 0
	for _, r := range group {
		if pystr.IsSpace(r) || r == ',' || r == '=' || r == utf8.RuneError {
			return false
		}
		n++
	}
	return n >= 1 && n <= 128
}

// ParseAccess parses PANEL_ACCESS: comma-separated group=exit pairs. Repeat
// a group to grant it several exits. Every exit must be one the panel
// serves.
func ParseAccess(raw string, exitIDs []string) (map[string]Set, error) {
	access := map[string]Set{}
	for _, entry := range splitList(raw) {
		group, exitID, sep := strings.Cut(entry, "=")
		group, exitID = pystr.Strip(group), pystr.Strip(exitID)
		if !sep || !validGroup(group) {
			return nil, fmt.Errorf("PANEL_ACCESS: entries are group=exit, with no spaces, commas or = in the group, in %s", pyRepr(entry))
		}
		known := false
		for _, id := range exitIDs {
			if id == exitID {
				known = true
			}
		}
		if !known {
			return nil, fmt.Errorf("PANEL_ACCESS: %s is not an exit in PANEL_EXITS, in %s", pyRepr(exitID), pyRepr(entry))
		}
		if access[group] == nil {
			access[group] = Set{}
		}
		access[group][exitID] = struct{}{}
	}
	return access, nil
}

// pyRepr is repr() for the plain text the settings messages quote: single
// quotes unless the text holds a single quote and no double quote, and a
// backslash escape for the characters repr escapes.
func pyRepr(s string) string {
	quote := byte('\'')
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case !unicode.IsPrint(r):
			switch {
			case r < 0x100:
				fmt.Fprintf(&b, `\x%02x`, r)
			case r < 0x10000:
				fmt.Fprintf(&b, `\u%04x`, r)
			default:
				fmt.Fprintf(&b, `\U%08x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// strerror is the C library's text for the errors reading a file can give,
// which is what Python's OSError.strerror carries.
func strerror(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ENOENT:
			return "No such file or directory"
		case syscall.EACCES:
			return "Permission denied"
		case syscall.EPERM:
			return "Operation not permitted"
		case syscall.EISDIR:
			return "Is a directory"
		case syscall.ENOTDIR:
			return "Not a directory"
		case syscall.ELOOP:
			return "Too many levels of symbolic links"
		case syscall.ENAMETOOLONG:
			return "File name too long"
		case syscall.EIO:
			return "Input/output error"
		}
		text := errno.Error()
		if text != "" {
			return strings.ToUpper(text[:1]) + text[1:]
		}
	}
	return "Unknown error"
}

// pyInt is int(text) for the settings that take a whole number: optional
// sign, digits with single underscores between them, surrounding whitespace.
// ok is false for anything else; overflow reports ok with a value outside
// every range this package accepts.
func pyInt(text string) (value int64, ok bool) {
	text = pystr.Strip(text)
	neg := false
	if text != "" && (text[0] == '+' || text[0] == '-') {
		neg = text[0] == '-'
		text = text[1:]
	}
	if text == "" || text[0] == '_' || text[len(text)-1] == '_' || strings.Contains(text, "__") {
		return 0, false
	}
	digits := strings.ReplaceAll(text, "_", "")
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		n = math.MaxInt64
	}
	if neg {
		n = -n
	}
	return n, true
}

// ConfigFromEnv returns nil when PANEL_OIDC_ISSUER is unset: the panel has
// no login. An error, which stops the panel, is returned for any incomplete
// or unsafe setting.
func ConfigFromEnv(env map[string]string, exitIDs []string) (*Config, error) {
	get := func(name string) string { return env[name] }
	issuer := pystr.Strip(get("PANEL_OIDC_ISSUER"))
	if issuer == "" {
		for _, name := range []string{"PANEL_OIDC_CLIENT_ID", "PANEL_ACCESS", "PANEL_ADMIN_GROUPS", "PANEL_PUBLIC_URL"} {
			if pystr.Strip(get(name)) != "" {
				return nil, fmt.Errorf("%s is set but PANEL_OIDC_ISSUER is not; set both or neither", name)
			}
		}
		return nil, nil
	}
	if u, err := url.Parse(issuer); !SecureURL(issuer) || err != nil || u.RawQuery != "" {
		return nil, errors.New("PANEL_OIDC_ISSUER must be an https URL (http only for a loopback test issuer)")
	}
	clientID := pystr.Strip(get("PANEL_OIDC_CLIENT_ID"))
	if clientID == "" || utf8.RuneCountInString(clientID) > 255 || !pystr.IsPrintable(clientID) {
		return nil, errors.New("PANEL_OIDC_CLIENT_ID is required with PANEL_OIDC_ISSUER")
	}
	var clientSecret *string
	if secretFile := pystr.Strip(get("PANEL_OIDC_CLIENT_SECRET_FILE")); secretFile != "" {
		raw, err := os.ReadFile(secretFile)
		if err != nil {
			return nil, fmt.Errorf("PANEL_OIDC_CLIENT_SECRET_FILE cannot be read: %s", strerror(err))
		}
		if !utf8.Valid(raw) {
			return nil, errors.New("PANEL_OIDC_CLIENT_SECRET_FILE cannot be read: not valid UTF-8")
		}
		secret := pystr.Strip(string(raw))
		if secret == "" {
			return nil, errors.New("PANEL_OIDC_CLIENT_SECRET_FILE is empty")
		}
		clientSecret = &secret
	}
	publicURL := strings.TrimRight(pystr.Strip(get("PANEL_PUBLIC_URL")), "/")
	publicErr := errors.New("PANEL_PUBLIC_URL must be the https origin people open, such as https://exit.example.net")
	if publicURL == "" || !SecureURL(publicURL) {
		return nil, publicErr
	}
	if u, err := url.Parse(publicURL); err != nil || u.Path != "" || u.RawQuery != "" {
		return nil, publicErr
	}
	scopesRaw, set := env["PANEL_OIDC_SCOPES"]
	if !set {
		scopesRaw = DefaultScopes
	}
	scopes := strings.Join(pystr.Fields(scopesRaw), " ")
	hasOpenID := false
	for _, scope := range strings.Split(scopes, " ") {
		if scope == "openid" {
			hasOpenID = true
		}
	}
	if !hasOpenID {
		return nil, errors.New("PANEL_OIDC_SCOPES must include openid")
	}
	groupsClaim := pystr.Strip(get("PANEL_OIDC_GROUPS_CLAIM"))
	if groupsClaim == "" {
		groupsClaim = "groups"
	}
	adminGroups := NewSet(splitList(get("PANEL_ADMIN_GROUPS"))...)
	for _, group := range adminGroups.Sorted() {
		if !validGroup(group) {
			return nil, fmt.Errorf("PANEL_ADMIN_GROUPS: %s is not a valid group name", pyRepr(group))
		}
	}
	access, err := ParseAccess(get("PANEL_ACCESS"), exitIDs)
	if err != nil {
		return nil, err
	}
	if len(adminGroups) == 0 && len(access) == 0 {
		return nil, errors.New("With PANEL_OIDC_ISSUER set, PANEL_ADMIN_GROUPS or PANEL_ACCESS must name at least one group")
	}
	ttlText, set := env["PANEL_SESSION_TTL"]
	if !set {
		ttlText = strconv.Itoa(DefaultSessionTTL)
	}
	ttl, ok := pyInt(ttlText)
	if !ok {
		return nil, errors.New("PANEL_SESSION_TTL must be a whole number of seconds")
	}
	if ttl < MinSessionTTL || ttl > MaxSessionTTL {
		return nil, fmt.Errorf("PANEL_SESSION_TTL must be between %d and %d seconds", MinSessionTTL, MaxSessionTTL)
	}
	return &Config{
		Issuer: issuer, ClientID: clientID, ClientSecret: clientSecret, PublicURL: publicURL,
		Scopes: scopes, GroupsClaim: groupsClaim, AdminGroups: adminGroups, Access: access,
		SessionTTL: int(ttl),
	}, nil
}

// --------------------------------------------------------------------------
// Outbound HTTPS to the issuer
// --------------------------------------------------------------------------

// NewIssuerClient is the HTTP client the panel uses for the issuer: no proxy
// from the environment, no redirects, certificates verified. The panel talks
// only to the URLs the issuer's discovery document names.
func NewIssuerClient() *http.Client {
	dialer := &net.Dialer{Timeout: HTTPTimeout}
	return &http.Client{
		Timeout: HTTPTimeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   HTTPTimeout,
			ResponseHeaderTimeout: HTTPTimeout,
			DisableKeepAlives:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// httpJSON GETs (or, with form, POSTs) a JSON object from the issuer. It
// returns an AuthError with a fixed message naming what; nothing from the
// response reaches the message.
func httpJSON(client *http.Client, target string, form []pystr.Pair, headers map[string]string, what string) (map[string]any, error) {
	if !SecureURL(target) {
		return nil, authErr("%s: the issuer named an insecure URL", what)
	}
	method, body := http.MethodGet, io.Reader(nil)
	if form != nil {
		method, body = http.MethodPost, strings.NewReader(pystr.Encode(form...))
	}
	ctx, cancel := context.WithTimeout(context.Background(), HTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, authErr("%s: the issuer could not be reached", what)
	}
	req.Header.Set("Accept", "application/json")
	// Some issuer fronts (Cloudflare among them) refuse a generic client's
	// default agent with 403.
	req.Header.Set("User-Agent", UserAgent)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, authErr("%s: the issuer could not be reached", what)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, authErr("%s: the issuer answered HTTP %d", what, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, authErr("%s: the issuer could not be reached", what)
	}
	if len(raw) > MaxResponseBytes {
		return nil, authErr("%s: the issuer response is too large", what)
	}
	value, err := loads(raw)
	if err != nil {
		return nil, authErr("%s: the issuer response is not valid JSON", what)
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, authErr("%s: the issuer response is not a JSON object", what)
	}
	return obj, nil
}

// Endpoints are the issuer URLs the flow uses. Userinfo is empty when the
// issuer named none that may be trusted.
type Endpoints struct {
	Authorization string
	Token         string
	Userinfo      string
}

// ParseDiscovery checks a discovery document against the configured issuer.
func ParseDiscovery(doc map[string]any, issuer string) (Endpoints, error) {
	if got, ok := doc["issuer"].(string); !ok || got != issuer {
		return Endpoints{}, authErr("discovery: the issuer in the discovery document does not match PANEL_OIDC_ISSUER")
	}
	// Plain http only when the issuer itself is a loopback test issuer; an
	// https issuer can never send the panel to http.
	issuerURL, _ := url.Parse(issuer)
	httpsOnly := issuerURL != nil && issuerURL.Scheme == "https"
	allowed := func(value any) (string, bool) {
		s, ok := value.(string)
		if !ok || !SecureURL(s) {
			return "", false
		}
		if httpsOnly {
			if u, err := url.Parse(s); err != nil || u.Scheme != "https" {
				return "", false
			}
		}
		return s, true
	}
	authorization, ok1 := allowed(doc["authorization_endpoint"])
	token, ok2 := allowed(doc["token_endpoint"])
	if !ok1 || !ok2 {
		return Endpoints{}, authErr("discovery: the authorization and token endpoints must be https URLs")
	}
	userinfo, _ := allowed(doc["userinfo_endpoint"])
	if methods, ok := doc["code_challenge_methods_supported"].([]any); ok {
		found := false
		for _, m := range methods {
			if s, ok := m.(string); ok && s == "S256" {
				found = true
			}
		}
		if !found {
			return Endpoints{}, authErr("discovery: the issuer does not support PKCE with S256")
		}
	}
	return Endpoints{Authorization: authorization, Token: token, Userinfo: userinfo}, nil
}

// --------------------------------------------------------------------------
// PKCE and the ID token
// --------------------------------------------------------------------------

func b64url(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func isB64URLChar(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-'
}

func allB64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isB64URLChar(s[i]) {
			return false
		}
	}
	return true
}

func b64urlDecode(text string) ([]byte, error) {
	if !allB64URL(text) {
		return nil, errors.New("not base64url")
	}
	return base64.RawURLEncoding.DecodeString(text)
}

// PKCEChallenge is the S256 challenge for a verifier.
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64url(sum[:])
}

func tokenURLSafe(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic(err) // crypto/rand does not fail on a working system
	}
	return b64url(buf)
}

// pyStrLower is str(value).lower() for the one place it matters: a JWT
// header's alg, where only the empty string and "none" (a missing value, or
// JSON null, whose str() is "None") mean unsigned.
func pyStrLower(v any, missing bool) string {
	switch t := v.(type) {
	case string:
		return strings.ToLower(t)
	case nil:
		if missing {
			return ""
		}
		return "none"
	}
	return "\x00" // some other type: never empty and never "none"
}

// IDTokenClaims decodes and checks an ID token received directly from the
// token endpoint over TLS (see the package comment for why the signature is
// not checked). now is in seconds since the epoch. It returns an AuthError
// on any mismatch.
func IDTokenClaims(token any, issuer, clientID, nonce string, now float64) (map[string]any, error) {
	text, ok := token.(string)
	if !ok || utf8.RuneCountInString(text) > maxIDTokenChars {
		return nil, authErr("token: the issuer returned no ID token")
	}
	parts := strings.Split(text, ".")
	if len(parts) != 3 {
		return nil, authErr("token: the ID token is malformed")
	}
	malformed := authErr("token: the ID token is malformed")
	rawHeader, err1 := b64urlDecode(parts[0])
	rawClaims, err2 := b64urlDecode(parts[1])
	if err1 != nil || err2 != nil {
		return nil, malformed
	}
	headerValue, err1 := loads(rawHeader)
	claimsValue, err2 := loads(rawClaims)
	if err1 != nil || err2 != nil {
		return nil, malformed
	}
	header, ok1 := headerValue.(map[string]any)
	claims, ok2 := claimsValue.(map[string]any)
	if !ok1 || !ok2 {
		return nil, malformed
	}
	alg, algPresent := header["alg"]
	if a := pyStrLower(alg, !algPresent); a == "" || a == "none" || parts[2] == "" {
		return nil, authErr("token: the ID token is unsigned")
	}
	if iss, ok := claims["iss"].(string); !ok || iss != issuer {
		return nil, authErr("token: the ID token was issued by another issuer")
	}
	var audiences []any
	switch aud := claims["aud"].(type) {
	case string:
		audiences = []any{aud}
	case []any:
		audiences = aud
	default:
		return nil, authErr("token: the ID token is for another client")
	}
	found := false
	for _, a := range audiences {
		if s, ok := a.(string); ok && s == clientID {
			found = true
		}
	}
	if !found {
		return nil, authErr("token: the ID token is for another client")
	}
	if _, hasAzp := claims["azp"]; len(audiences) > 1 || hasAzp {
		if azp, ok := claims["azp"].(string); !ok || azp != clientID {
			return nil, authErr("token: the ID token is for another client")
		}
	}
	if exp, ok := number(claims["exp"]); !ok || exp+ClockSkewS < now {
		return nil, authErr("token: the ID token has expired")
	}
	if iat, ok := number(claims["iat"]); !ok || iat-ClockSkewS > now {
		return nil, authErr("token: the ID token was issued in the future")
	}
	claimNonce, ok := claims["nonce"].(string)
	if !ok || subtle.ConstantTimeCompare([]byte(claimNonce), []byte(nonce)) != 1 {
		return nil, authErr("token: the ID token does not belong to this sign-in")
	}
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" || utf8.RuneCountInString(sub) > maxSubjectChars {
		return nil, authErr("token: the ID token has no subject")
	}
	return claims, nil
}

// GroupsFrom returns the group names in a claim; present is false when the
// claim is absent. A single string counts as one group; anything else that
// is not a list of strings is refused.
func GroupsFrom(claims map[string]any, claim string) (groups Set, present bool, err error) {
	value, ok := claims[claim]
	if !ok {
		return nil, false, nil
	}
	var list []any
	switch v := value.(type) {
	case string:
		list = []any{v}
	case []any:
		list = v
	default:
		return nil, true, authErr("token: the groups claim is malformed")
	}
	if len(list) > MaxGroups {
		return nil, true, authErr("token: the groups claim is malformed")
	}
	groups = Set{}
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, true, authErr("token: the groups claim is malformed")
		}
		if s != "" {
			groups[s] = struct{}{}
		}
	}
	return groups, true, nil
}

// safeName replaces every character outside A-Z a-z 0-9 . _ @ + - with an
// underscore (LOG_NAME_RE).
func safeName(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r < 0x80 && (isB64URLChar(byte(r)) || r == '.' || r == '@' || r == '+') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}

func firstRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// LogSafe reduces a value to a safe character set for one log line.
func LogSafe(value string) string {
	if out := firstRunes(safeName(value), 64); out != "" {
		return out
	}
	return "-"
}

// DisplayName is a short name for the page and the switch log:
// preferred_username, else email, else the subject. Reduced to a safe
// character set.
func DisplayName(claims map[string]any) string {
	for _, key := range []string{"preferred_username", "email", "sub"} {
		value, ok := claims[key].(string)
		if !ok || pystr.Strip(value) == "" {
			continue
		}
		cleaned := firstRunes(safeName(pystr.Strip(value)), 64)
		if strings.Trim(cleaned, "_") != "" {
			return cleaned
		}
	}
	return "unknown"
}

// --------------------------------------------------------------------------
// Sign-in state
// --------------------------------------------------------------------------

// PendingLogin is a sign-in in progress. The nonce and PKCE verifier are
// derived from the state with the process's key, so the cookie never carries
// them.
type PendingLogin struct {
	State    string
	Nonce    string
	Verifier string
	NextPath string
	Created  int64
}

// Session is a signed-in browser.
type Session struct {
	Sub     string
	Name    string
	Groups  Set
	Admin   bool
	Exits   Set
	Expires time.Time
	CSRFKey string
}

type sessionEntry struct {
	session *Session
	seq     uint64
}

type discovered struct {
	endpoints *Endpoints // nil after a failure
	at        float64
}

// Authenticator holds the discovery cache, pending sign-ins and sessions for
// one panel process.
type Authenticator struct {
	// Limits may be lowered before first use.
	Limits Limits

	config  *Config
	exitIDs []string
	clock   func() time.Time
	client  *http.Client

	mu       sync.Mutex
	sessions map[string]*sessionEntry
	seq      uint64
	// Signs the pending sign-in cookie; a new key per process.
	loginKey []byte
	// state -> when it was used, in the order they were used, for sign-ins
	// already finished or refused, so a callback cannot be replayed with the
	// same cookie. Expiry and eviction both work from the oldest end.
	consumed      *list.List
	consumedIndex map[string]*list.Element
	endpoints     *discovered
}

type consumedItem struct {
	state string
	used  int64
}

// NewAuthenticator creates an Authenticator. A nil clock is time.Now and a
// nil client is NewIssuerClient().
func NewAuthenticator(config *Config, exitIDs []string, clock func() time.Time, client *http.Client) *Authenticator {
	if clock == nil {
		clock = time.Now
	}
	if client == nil {
		client = NewIssuerClient()
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return &Authenticator{
		Limits: DefaultLimits(), config: config, exitIDs: append([]string(nil), exitIDs...), clock: clock, client: client,
		sessions: map[string]*sessionEntry{}, loginKey: key,
		consumed: list.New(), consumedIndex: map[string]*list.Element{},
	}
}

// Config is the configuration the Authenticator was made with.
func (a *Authenticator) Config() *Config { return a.config }

func (a *Authenticator) now() float64 {
	t := a.clock()
	return float64(t.Unix()) + float64(t.Nanosecond())/1e9
}

// -- discovery ---------------------------------------------------------------

func (a *Authenticator) discover() (Endpoints, error) {
	now := a.now()
	a.mu.Lock()
	cached := a.endpoints
	a.mu.Unlock()
	if cached != nil && cached.endpoints != nil && now-cached.at < DiscoveryTTL {
		return *cached.endpoints, nil
	}
	if cached != nil && cached.endpoints == nil && now-cached.at < DiscoveryRetryS {
		// A recent failure: don't let every anonymous /login wait on it.
		return Endpoints{}, authErr("discovery: the issuer could not be reached recently; retrying shortly")
	}
	doc, err := httpJSON(a.client, strings.TrimRight(a.config.Issuer, "/")+"/.well-known/openid-configuration", nil, nil, "discovery")
	var endpoints Endpoints
	if err == nil {
		endpoints, err = ParseDiscovery(doc, a.config.Issuer)
	}
	if err != nil {
		a.mu.Lock()
		a.endpoints = &discovered{nil, now}
		a.mu.Unlock()
		return Endpoints{}, err
	}
	a.mu.Lock()
	a.endpoints = &discovered{&endpoints, now}
	a.mu.Unlock()
	return endpoints, nil
}

// -- sign-in -------------------------------------------------------------------

// Begin starts a sign-in: the value for the pending sign-in cookie and the
// authorization URL.
func (a *Authenticator) Begin(nextPath string) (cookie, authorizeURL string, err error) {
	endpoints, err := a.discover()
	if err != nil {
		return "", "", err
	}
	pending := a.pending(tokenURLSafe(32), nextPath, int64(a.now()))
	query := pystr.Encode(
		pystr.Pair{Key: "response_type", Value: "code"},
		pystr.Pair{Key: "client_id", Value: a.config.ClientID},
		pystr.Pair{Key: "redirect_uri", Value: a.config.RedirectURI()},
		pystr.Pair{Key: "scope", Value: a.config.Scopes},
		pystr.Pair{Key: "state", Value: pending.State},
		pystr.Pair{Key: "nonce", Value: pending.Nonce},
		pystr.Pair{Key: "code_challenge", Value: PKCEChallenge(pending.Verifier)},
		pystr.Pair{Key: "code_challenge_method", Value: "S256"},
	)
	separator := "?"
	if u, perr := url.Parse(endpoints.Authorization); perr == nil && u.RawQuery != "" {
		separator = "&"
	}
	return a.Seal(pending), endpoints.Authorization + separator + query, nil
}

func (a *Authenticator) derive(purpose, state string) string {
	mac := hmac.New(sha256.New, a.loginKey)
	mac.Write([]byte(purpose + "\n" + state))
	return b64url(mac.Sum(nil))
}

func (a *Authenticator) pending(state, nextPath string, created int64) PendingLogin {
	return PendingLogin{state, a.derive("nonce", state), a.derive("verifier", state), nextPath, created}
}

func (a *Authenticator) sign(body string) string {
	mac := hmac.New(sha256.New, a.loginKey)
	mac.Write([]byte(body))
	return b64url(mac.Sum(nil))
}

// Seal signs a pending sign-in into its cookie value. Only the state, the
// next path and the creation time travel in it.
func (a *Authenticator) Seal(p PendingLogin) string {
	fields, err := json.Marshal(struct {
		State    string `json:"state"`
		NextPath string `json:"next_path"`
		Created  int64  `json:"created"`
	}{p.State, p.NextPath, p.Created})
	if err != nil {
		panic(err)
	}
	body := b64url(fields)
	return body + "." + a.sign(body)
}

func validLoginCookie(value string) bool {
	body, mac, ok := strings.Cut(value, ".")
	if !ok || len(body) < 1 || len(body) > 2048 || len(mac) != 43 {
		return false
	}
	return allB64URL(body) && allB64URL(mac)
}

func validState(state string) bool { return len(state) == 43 && allB64URL(state) }

var errNotStarted = "callback: this browser did not start a sign-in, or it expired"

// open returns the pending sign-in a cookie holds, if this process signed it
// and it has not expired or been used. It uses the sign-in up.
func (a *Authenticator) open(value string) (PendingLogin, error) {
	expired := authErr("%s", errNotStarted)
	if !validLoginCookie(value) {
		return PendingLogin{}, expired
	}
	body, mac, _ := strings.Cut(value, ".")
	if !hmac.Equal([]byte(mac), []byte(a.sign(body))) {
		return PendingLogin{}, expired
	}
	raw, err := b64urlDecode(body)
	if err != nil {
		return PendingLogin{}, expired
	}
	decoded, err := loads(raw)
	fields, ok := decoded.(map[string]any)
	if err != nil || !ok || len(fields) != 3 {
		return PendingLogin{}, expired
	}
	state, ok1 := fields["state"].(string)
	nextPath, ok2 := fields["next_path"].(string)
	created, ok3 := fields["created"].(int64)
	if !ok1 || !ok2 || !ok3 || !validState(state) {
		return PendingLogin{}, expired
	}
	now := a.now()
	if age := now - float64(created); age < 0 || age > LoginTTL {
		return PendingLogin{}, expired
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneConsumed(now)
	if _, used := a.consumedIndex[state]; used {
		return PendingLogin{}, expired
	}
	for a.consumed.Len() >= a.Limits.MaxConsumedLogins {
		front := a.consumed.Front()
		delete(a.consumedIndex, front.Value.(consumedItem).state)
		a.consumed.Remove(front)
	}
	a.consumedIndex[state] = a.consumed.PushBack(consumedItem{state, int64(now)})
	return a.pending(state, nextPath, created), nil
}

// Finish completes a sign-in: the session id, the session and the path to
// land on. The pending sign-in is used up whatever the outcome.
func (a *Authenticator) Finish(loginCookie, state, code string) (string, *Session, string, error) {
	pending, err := a.open(loginCookie)
	if err != nil {
		return "", nil, "", err
	}
	if subtle.ConstantTimeCompare([]byte(state), []byte(pending.State)) != 1 {
		return "", nil, "", authErr("callback: the sign-in state does not match")
	}
	if code == "" || utf8.RuneCountInString(code) > maxCodeChars {
		return "", nil, "", authErr("callback: the issuer returned no code")
	}
	endpoints, err := a.discover()
	if err != nil {
		return "", nil, "", err
	}
	form := []pystr.Pair{
		{Key: "grant_type", Value: "authorization_code"},
		{Key: "code", Value: code},
		{Key: "redirect_uri", Value: a.config.RedirectURI()},
		{Key: "code_verifier", Value: pending.Verifier},
		{Key: "client_id", Value: a.config.ClientID},
	}
	headers := map[string]string{}
	if a.config.ClientSecret != nil {
		pair := pystr.Quote(a.config.ClientID) + ":" + pystr.Quote(*a.config.ClientSecret)
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(pair))
	}
	tokens, err := httpJSON(a.client, endpoints.Token, form, headers, "token")
	if err != nil {
		return "", nil, "", err
	}
	claims, err := IDTokenClaims(tokens["id_token"], a.config.Issuer, a.config.ClientID, pending.Nonce, a.now())
	if err != nil {
		return "", nil, "", err
	}
	groups, present, err := GroupsFrom(claims, a.config.GroupsClaim)
	if err != nil {
		return "", nil, "", err
	}
	sub := claims["sub"].(string)
	if !present {
		accessToken, _ := tokens["access_token"].(string)
		groups, err = a.userinfoGroups(endpoints, accessToken, sub)
		if err != nil {
			return "", nil, "", err
		}
	}
	admin, exits := a.config.ExitsFor(groups, a.exitIDs)
	if !admin && len(exits) == 0 {
		return "", nil, "", authErr("access: this account is not in a group that may use this panel")
	}
	now := a.clock()
	session := &Session{
		Sub: sub, Name: DisplayName(claims), Groups: groups, Admin: admin, Exits: exits,
		Expires: now.Add(time.Duration(a.config.SessionTTL) * time.Second), CSRFKey: tokenURLSafe(32),
	}
	sessionID := tokenURLSafe(32)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prune(a.now())
	// One person's many sign-ins replace their own oldest session, not
	// somebody else's.
	var own []string
	for key, entry := range a.sessions {
		if entry.session.Sub == session.Sub {
			own = append(own, key)
		}
	}
	sort.Slice(own, func(i, j int) bool { return a.older(own[i], own[j]) })
	drop := len(own) - a.Limits.MaxSessionsPerSubject + 1
	if drop > 0 {
		for _, key := range own[:drop] {
			delete(a.sessions, key)
		}
	}
	if len(a.sessions) >= a.Limits.MaxSessions {
		oldest, first := "", true
		for key := range a.sessions {
			if first || a.older(key, oldest) {
				oldest, first = key, false
			}
		}
		delete(a.sessions, oldest)
	}
	a.seq++
	a.sessions[sessionID] = &sessionEntry{session, a.seq}
	return sessionID, session, pending.NextPath, nil
}

// older orders sessions by expiry, then by when they were made. The caller
// holds the lock.
func (a *Authenticator) older(x, y string) bool {
	ex, ey := a.sessions[x], a.sessions[y]
	if !ex.session.Expires.Equal(ey.session.Expires) {
		return ex.session.Expires.Before(ey.session.Expires)
	}
	return ex.seq < ey.seq
}

// Discard uses up a pending sign-in the issuer refused.
func (a *Authenticator) Discard(loginCookie string) { _, _ = a.open(loginCookie) }

func (a *Authenticator) userinfoGroups(endpoints Endpoints, accessToken, sub string) (Set, error) {
	claim := a.config.GroupsClaim
	if endpoints.Userinfo == "" || accessToken == "" {
		return nil, authErr("token: the issuer sent no %s claim", claim)
	}
	info, err := httpJSON(a.client, endpoints.Userinfo, nil, map[string]string{"Authorization": "Bearer " + accessToken}, "userinfo")
	if err != nil {
		return nil, err
	}
	if got, ok := info["sub"].(string); !ok || got != sub {
		return nil, authErr("userinfo: the subject does not match the ID token")
	}
	groups, present, err := GroupsFrom(info, claim)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, authErr("userinfo: the issuer sent no %s claim", claim)
	}
	return groups, nil
}

// -- sessions ------------------------------------------------------------------

// Session returns the live session for an id, or nil.
func (a *Authenticator) Session(sessionID string) *Session {
	if len(sessionID) != 43 || !allB64URL(sessionID) {
		return nil
	}
	now := a.clock()
	a.mu.Lock()
	defer a.mu.Unlock()
	entry := a.sessions[sessionID]
	if entry == nil {
		return nil
	}
	if !entry.session.Expires.After(now) {
		delete(a.sessions, sessionID)
		return nil
	}
	return entry.session
}

// End signs a session out.
func (a *Authenticator) End(sessionID string) {
	if sessionID == "" {
		return
	}
	a.mu.Lock()
	delete(a.sessions, sessionID)
	a.mu.Unlock()
}

// prune drops expired sessions and used sign-ins. The caller holds the lock.
func (a *Authenticator) prune(now float64) {
	t := a.clock()
	for key, entry := range a.sessions {
		if !entry.session.Expires.After(t) {
			delete(a.sessions, key)
		}
	}
	a.pruneConsumed(now)
}

// pruneConsumed drops used sign-ins older than LoginTTL, from the oldest end.
// Entries are kept in the order they were used, so this stops at the first
// one still young. The caller holds the lock.
func (a *Authenticator) pruneConsumed(now float64) {
	for front := a.consumed.Front(); front != nil; front = a.consumed.Front() {
		item := front.Value.(consumedItem)
		if now-float64(item.used) <= LoginTTL {
			break
		}
		delete(a.consumedIndex, item.state)
		a.consumed.Remove(front)
	}
}
