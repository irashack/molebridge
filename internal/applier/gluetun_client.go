package applier

// The gluetun control-server client (applier/gluetun.py): a bounded,
// loopback-only client for gluetun v3.41.3's control server.
//
// It does not read VPN settings or control routes. The API key reaches the
// request only as one header; the caller supplies the key file (read by
// gluetunauth.ReadAPIKey, mode 0600) and there is no environment or
// command-line credential interface. No error carries the key, the URL or any
// part of an answer.
//
// The Python client ran `curl -q --noproxy '*' --proto =http -fsS
// --connect-timeout 2 --max-time 10 --max-redirs 0 --max-filesize 16384` with
// the key in a mode-0600 header file; the same bounds are the netx.Request
// here: plain HTTP allowed (AllowHTTP), no proxy and no redirect (netx never
// does either), a 2-second connect, a 10-second total, a 16384-byte answer,
// and an HTTP status of 400 or more a failure (-f).

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/irashack/molebridge/internal/gluetunauth"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

// Limits of the control-server client.
const (
	GluetunMaxResponseBytes  = 16384
	GluetunMaxOutcomeChars   = 1024
	gluetunMaxUpdaterOutcome = 64
)

// GluetunError is a refusal or failure of the client with a fixed message.
// Python raised RuntimeError for a failed request and ValueError for the
// rest; the applier caught both alike, and so do callers here.
type GluetunError string

func (e GluetunError) Error() string { return string(e) }

// The client's fixed errors.
const (
	// ErrGluetunRequest: the request failed or its answer was unusable as
	// text (RuntimeError in Python).
	ErrGluetunRequest GluetunError = "gluetun control request failed"
	// ErrGluetunURL: the control URL is not a loopback address with a port.
	ErrGluetunURL GluetunError = "invalid gluetun control URL"
	// ErrGluetunRoute: only the authorized routes are sent.
	ErrGluetunRoute GluetunError = "gluetun control route refused"
)

// VPNStatuses are the loop statuses gluetun reports for its VPN and updater.
var VPNStatuses = []string{"starting", "running", "stopping", "stopped", "crashed", "completed"}

var (
	listFilters = []string{"countries", "regions", "cities", "names", "numbers", "categories", "isps", "hostnames"}
	boolFilters = []string{"owned_only", "free_only", "premium_only", "stream_only", "multi_hop_only",
		"port_forward_only", "secure_core_only", "tor_only"}
	baseURLRE = regexp.MustCompile(`^http://(?:127\.0\.0\.1|\[::1\]):([1-9][0-9]{0,4})$`)
)

// FetchFunc sends one HTTP request (netx.Client.Fetch, System.Fetch).
type FetchFunc func(ctx context.Context, req netx.Request) (netx.Response, error)

// GluetunClient talks to gluetun's control server.
type GluetunClient struct {
	baseURL string
	apiKey  string
	fetch   FetchFunc
}

// NewGluetunClient checks the control URL, then reads the API key file. fetch
// is netx.Client{}.Fetch when nil.
func NewGluetunClient(baseURL, apiKeyFile string, fetch FetchFunc) (*GluetunClient, error) {
	match := baseURLRE.FindStringSubmatch(baseURL)
	if match == nil {
		return nil, ErrGluetunURL
	}
	if port, _ := strconv.Atoi(match[1]); port > 65535 {
		return nil, ErrGluetunURL
	}
	key, err := gluetunauth.ReadAPIKey(apiKeyFile)
	if err != nil {
		return nil, err
	}
	if fetch == nil {
		fetch = netx.Client{}.Fetch
	}
	return &GluetunClient{baseURL: baseURL, apiKey: key, fetch: fetch}, nil
}

// BaseURL is the control server's URL.
func (c *GluetunClient) BaseURL() string { return c.baseURL }

func authorized(route string) bool {
	for _, r := range gluetunauth.Routes {
		if r == route {
			return true
		}
	}
	return false
}

// request sends one of the authorized routes; GET settings and anything else
// is refused before any I/O. hasBody must be true exactly for PUT.
func (c *GluetunClient) request(ctx context.Context, method, path string, body []byte, hasBody bool) (string, error) {
	if !authorized(method + " " + path) {
		return "", ErrGluetunRoute
	}
	if (method == "PUT") != hasBody {
		return "", GluetunError("invalid gluetun request body")
	}
	request := netx.Request{URL: c.baseURL + path, Method: method, Header: map[string]string{"X-API-Key": c.apiKey},
		MaxBytes: GluetunMaxResponseBytes, Timeout: 10 * time.Second, ConnectTimeout: 2 * time.Second, AllowHTTP: true}
	if hasBody {
		request.Header["Content-Type"] = "application/json"
		request.Body = body
	}
	response, err := c.fetch(ctx, request)
	if err != nil {
		if errors.Is(err, netx.ErrCanceled) || errors.Is(err, context.Canceled) {
			return "", context.Canceled
		}
		return "", ErrGluetunRequest
	}
	if len(response.Body) > GluetunMaxResponseBytes || !utf8.Valid(response.Body) {
		return "", ErrGluetunRequest
	}
	return string(response.Body), nil
}

func (c *GluetunClient) object(ctx context.Context, path string) (map[string]any, error) {
	raw, err := c.request(ctx, "GET", path, nil, false)
	if err != nil {
		return nil, err
	}
	data, err := validate.DecodeJSONString(raw)
	object, ok := data.(map[string]any)
	if err != nil || !ok {
		return nil, GluetunError("invalid gluetun JSON response")
	}
	return object, nil
}

func knownStatus(value any) (string, bool) {
	s, ok := value.(string)
	if !ok {
		return "", false
	}
	for _, v := range VPNStatuses {
		if v == s {
			return s, true
		}
	}
	return "", false
}

// UpdaterStatus is gluetun's server-list updater: GET /v1/updater/status, the
// same loop statuses as the VPN's ("completed" after a finished run).
func (c *GluetunClient) UpdaterStatus(ctx context.Context) (string, error) {
	data, err := c.object(ctx, "/v1/updater/status")
	if err != nil {
		return "", err
	}
	status, ok := knownStatus(data["status"])
	if !ok {
		return "", GluetunError("invalid gluetun updater status")
	}
	return status, nil
}

// StartUpdate asks gluetun to refresh its server list now: PUT
// /v1/updater/status with {"status":"running"} (internal/server/updater.go:
// 62-84, wrappers.go:11-26). gluetun answers {"outcome": ...} once the run has
// started, or "already <status>". It returns the outcome, bounded.
func (c *GluetunClient) StartUpdate(ctx context.Context) (string, error) {
	raw, err := c.request(ctx, "PUT", "/v1/updater/status", []byte(`{"status":"running"}`), true)
	if err != nil {
		return "", err
	}
	var outcome string
	if data, derr := validate.DecodeJSONString(raw); derr == nil {
		if object, ok := data.(map[string]any); ok {
			outcome, _ = object["outcome"].(string)
		}
	}
	if n := validate.RuneCount(outcome); n == 0 || n > gluetunMaxUpdaterOutcome || !printable(outcome) {
		return "", GluetunError("invalid gluetun updater outcome")
	}
	return outcome, nil
}

// printable is str.isprintable for text that is valid UTF-8.
func printable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// VPNStatus is gluetun's VPN loop status.
func (c *GluetunClient) VPNStatus(ctx context.Context) (string, error) {
	data, err := c.object(ctx, "/v1/vpn/status")
	if err != nil {
		return "", err
	}
	status, ok := knownStatus(data["status"])
	if !ok {
		return "", GluetunError("invalid gluetun VPN status")
	}
	return status, nil
}

// SelectRelay selects a validated catalogue relay by its ID and its own
// selection filter; a non-empty selectionFilter must agree with the relay's
// (SelectServer).
func (c *GluetunClient) SelectRelay(ctx context.Context, relay *providers.Relay, selectionFilter string) (string, error) {
	if relay == nil {
		return "", GluetunError("invalid gluetun server selection")
	}
	if selectionFilter != "" && selectionFilter != relay.SelectionFilter {
		return "", GluetunError("conflicting gluetun server selection filter")
	}
	return c.SelectServer(ctx, relay.ID, relay.SelectionFilter)
}

// SelectServer sets one exact ID filter, clearing location, tier and feature
// filters. Catalogue uniqueness authorizes exact selection; this client checks
// the ID and filter syntax, not membership in a catalogue.
//
// v3.41.3 internal/configuration/settings/serverselection.go:24-65 defines the
// filter tags; :316-336 uses OverrideWithSlice/OverrideWithPointer. An
// explicit [] is a non-nil Go slice and replaces the old list; null decodes
// to nil and retains it. false supplies a non-nil *bool and clears a boolean
// filter, whereas null retains it. Do not send null.
// wireguardselection.go:17-33,122-125 holds endpoint/key overrides, not list
// filters; these and all other VPN settings are deliberately omitted.
// internal/server/vpn.go:126-127 returns the outcome as plain text.
//
// id is a string, or an int for the "numbers" filter. The outcome is the
// answer with control, format and surrogate characters removed and trimmed.
func (c *GluetunClient) SelectServer(ctx context.Context, id any, selectionFilter string) (string, error) {
	if !providers.ValidGluetunServerID(id, selectionFilter) {
		return "", GluetunError("invalid gluetun server selection")
	}
	selection := validate.Obj{}
	for _, field := range listFilters {
		value := any([]any{})
		if field == selectionFilter {
			value = []any{id}
		}
		selection = append(selection, validate.Pair{Key: field, Value: value})
	}
	for _, field := range boolFilters {
		selection = append(selection, validate.Pair{Key: field, Value: false})
	}
	body, err := validate.MarshalJSON(validate.Members("provider", validate.Members("server_selection", selection)))
	if err != nil {
		return "", GluetunError("invalid gluetun server selection")
	}
	raw, err := c.request(ctx, "PUT", "/v1/vpn/settings", compactJSON(body), true)
	if err != nil {
		return "", err
	}
	if n := validate.RuneCount(raw); n == 0 || n > GluetunMaxOutcomeChars {
		return "", GluetunError("invalid gluetun selection outcome")
	}
	var kept []rune
	for _, r := range raw {
		if !unicode.In(r, unicode.Cc, unicode.Cf) {
			kept = append(kept, r)
		}
	}
	outcome := trimSpace(string(kept))
	if outcome == "" {
		return "", GluetunError("invalid gluetun selection outcome")
	}
	return outcome, nil
}

// trimSpace is str.strip().
func trimSpace(s string) string {
	runes := []rune(s)
	start, end := 0, len(runes)
	for start < end && validate.IsSpace(runes[start]) {
		start++
	}
	for end > start && validate.IsSpace(runes[end-1]) {
		end--
	}
	return string(runes[start:end])
}

// compactJSON is json.dumps(..., separators=(',', ':')) of an encoding made
// with ", " and ": " separators: the separators outside strings go.
func compactJSON(raw []byte) []byte {
	out := make([]byte, 0, len(raw))
	inString := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case inString:
			out = append(out, c)
			if c == '\\' && i+1 < len(raw) {
				i++
				out = append(out, raw[i])
			} else if c == '"' {
				inString = false
			}
		case c == '"':
			inString = true
			out = append(out, c)
		case c == ' ':
		default:
			out = append(out, c)
		}
	}
	return out
}

// PublicIP is the tunnel's public address as gluetun sees it, canonical, with
// the geolocation fields ignored.
func (c *GluetunClient) PublicIP(ctx context.Context) (string, error) {
	data, err := c.object(ctx, "/v1/publicip/ip")
	if err != nil {
		return "", err
	}
	value, ok := data["public_ip"].(string)
	if ok && len(value) <= 45 {
		if address, perr := netip.ParseAddr(value); perr == nil && !strings.Contains(value, "%") &&
			address.String() == value {
			return value, nil
		}
	}
	return "", GluetunError("invalid gluetun public IP")
}
