// Package state is the bounded state-file I/O and the status contract shared
// by the panel and the applier (molebridge/state.py).
//
// It offers:
//
//   - Constants: StatusMaxAge, SwitchTimeouts, CatalogMaxAge, MaxCatalogBytes.
//   - Time: NowISO, AgeSeconds, Recent (the lenient reading of the files'
//     timestamps).
//   - Files: ReadJSON, ReadObject and WriteJSONAtomic, which are
//     internal/jsonfile under the Python names.
//   - The panel's request: Request, DesiredRequest, RequestToken.
//   - Status helpers: ConfiguredServer, ExitConfirmed, EgressTier,
//     ValidServerName, ProviderFromEnv.
//
// StatusView, which Python also kept here, is verdict.StatusView: the verdict
// imports state, so the reverse would be a cycle.
package state

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

const (
	// StatusMaxAge is how long, in seconds, a status record counts as current.
	StatusMaxAge = 150
	// CatalogMaxAge is how long a relay snapshot counts as fresh (seconds).
	CatalogMaxAge = providers.CatalogMaxAge
	// MaxCatalogBytes is the default download cap and the bound on reading a
	// validated snapshot back. A provider's download cap is its registry
	// entry's CatalogMaxBytes.
	MaxCatalogBytes = providers.DefaultCatalogBytes
)

// SwitchTimeouts is how long an applier gives a switch before it fails it, by
// backend (seconds); the panel says so while a switch runs.
var SwitchTimeouts = map[string]int{providers.BackendNative: 60, providers.BackendGluetun: 90}

// ErrSizeLimit is the error WriteJSONAtomic returns for a document over its
// bound.
var ErrSizeLimit = jsonfile.ErrSizeLimit

// NowISO is the current time in the state files' format.
func NowISO() string { return validate.FormatTime(time.Now()) }

// AgeSeconds is validate.AgeSeconds. A zero now means the current time.
func AgeSeconds(value any, now time.Time) (float64, bool) { return validate.AgeSeconds(value, now) }

// Recent reports whether value is a timestamp no newer than now and at most
// maxAge seconds old.
func Recent(value any, maxAge float64, now time.Time) bool {
	return validate.Recent(value, maxAge, now)
}

// ReadJSON rejects special files, symlinks, oversized and duplicate-key JSON
// and bad UTF-8, returning nil for each (see jsonfile.Read).
func ReadJSON(path string, limit int64) any { return jsonfile.Read(path, limit) }

// ReadObject is ReadJSON for a document that must be an object.
func ReadObject(path string, limit int64) (map[string]any, bool) {
	return jsonfile.ReadObject(path, limit)
}

// WriteJSONAtomic replaces path atomically, encoding incrementally into a
// temporary file. With maxBytes above zero, encoding stops with ErrSizeLimit as
// soon as the output passes the limit; the temporary file is removed and the
// old file stays in place. Memory stays bounded by the encoder's chunks,
// whatever the document's size. Public files are 0644, others 0600.
func WriteJSONAtomic(path string, v any, public bool, maxBytes int64) error {
	return jsonfile.Write(path, v, jsonfile.Options{Public: public, MaxBytes: maxBytes})
}

// ProviderFromEnv is the id of the provider the PROVIDER setting selects.
func ProviderFromEnv(getenv func(string) string) (string, error) {
	p, err := providers.FromEnv(getenv)
	if err != nil {
		return "", err
	}
	return p.ID, nil
}

// ValidServerName reports whether value is a selectable name for the provider.
// An unknown provider has none.
func ValidServerName(value any, provider string) bool {
	spec, ok := providers.Lookup(provider)
	return ok && spec.ValidServerName(value)
}

// ExitConfirmed is the provider-side egress confirmation; older results carry
// the Mullvad field.
func ExitConfirmed(result map[string]any) bool {
	if confirmed, present := result["exit_confirmed"]; present {
		return confirmed == true
	}
	return result["mullvad_exit_ip"] == true
}

// EgressTier says how the result's egress was confirmed: "provider" (the
// provider's own endpoint said so), "tunnel" (the tunnel checks in
// internal/egress, accepted only for a provider whose registry entry has no
// stronger check), or "" for neither. Results written before tiers existed
// have only exit_confirmed.
func EgressTier(result map[string]any, provider string) string {
	if ExitConfirmed(result) {
		return providers.TierProvider
	}
	if spec, ok := providers.Lookup(provider); ok && result["egress_tier"] == providers.TierTunnel && spec.EgressTier == providers.TierTunnel {
		return providers.TierTunnel
	}
	return ""
}

// Request is the panel's request of a server (state/panel/desired.json).
type Request struct {
	Server      string
	RequestedAt string
	// RequestID is 32 lower-case hex digits, or empty for the old two-field
	// request.
	RequestID string
}

var requestIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// DesiredRequest accepts the old two-field request and the new retry-aware
// request schema: an object with only the members server, requested_at and
// request_id, a server name valid for the provider, a timestamp (read
// leniently, as AgeSeconds does) and, when present, a request id. It returns
// false for anything else.
func DesiredRequest(value any, provider string) (Request, bool) {
	m, ok := value.(map[string]any)
	if !ok {
		return Request{}, false
	}
	for k := range m {
		if k != "server" && k != "requested_at" && k != "request_id" {
			return Request{}, false
		}
	}
	if !ValidServerName(m["server"], provider) {
		return Request{}, false
	}
	if _, ok := AgeSeconds(m["requested_at"], time.Time{}); !ok {
		return Request{}, false
	}
	request := Request{Server: m["server"].(string), RequestedAt: m["requested_at"].(string)}
	if id, present := m["request_id"]; present && id != nil {
		s, isString := id.(string)
		if !isString || !requestIDRE.MatchString(s) {
			return Request{}, false
		}
		request.RequestID = s
	}
	return request, true
}

// JSONObject implements validate.ObjectMarshaler: the members in the order the
// panel writes them.
func (r Request) JSONObject() validate.Obj {
	o := validate.Members("server", r.Server, "requested_at", r.RequestedAt)
	if r.RequestID != "" {
		o = append(o, validate.Pair{Key: "request_id", Value: r.RequestID})
	}
	return o
}

// RequestToken identifies a request: its id, or for the old schema
// "<server>@<requested_at>".
func RequestToken(r Request) string {
	if r.RequestID != "" {
		return r.RequestID
	}
	return r.Server + "@" + r.RequestedAt
}

// ConfiguredServer is the SERVER setting the status record reports.
// Configuration authority survives stale status; freshness only governs
// health. Invalid SERVER names still lock the exit. Older snapshots have no
// setting. A malformed name (a lone surrogate, a control character) keeps the
// lock but is shown escaped, so rendering it can't fail, and the result is at
// most 256 characters.
func ConfiguredServer(result any) (string, bool) {
	m, ok := result.(map[string]any)
	if !ok {
		return "", false
	}
	value, ok := m["configured_server"].(string)
	if !ok || value == "" {
		return "", false
	}
	// value.encode('utf-8', 'backslashreplace').decode('utf-8')
	var escaped strings.Builder
	for s := value; len(s) > 0; {
		r, size := validate.NextRune(s)
		switch {
		case validate.IsSurrogate(r):
			fmt.Fprintf(&escaped, `\u%04x`, r)
		case r == unicode.ReplacementChar && size == 1:
			fmt.Fprintf(&escaped, `\x%02x`, s[0])
		default:
			escaped.WriteString(s[:size])
		}
		s = s[size:]
	}
	// ''.join(c if c.isprintable() else f'\x{ord(c):02x}' for c in value)[:256]
	var out strings.Builder
	count := 0
	for s := escaped.String(); len(s) > 0 && count < 256; count++ {
		r, size := validate.NextRune(s)
		if unicode.IsPrint(r) {
			out.WriteString(s[:size])
		} else {
			// Python's \x escape grows past two digits for larger code points.
			fmt.Fprintf(&out, `\x%02x`, r)
		}
		s = s[size:]
	}
	return truncateRunes(out.String(), 256), true
}

func truncateRunes(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}
