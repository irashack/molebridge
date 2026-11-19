package verdict

import (
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/validate"
)

// The proxy's status record, proxy.json (docs/design/menu.md, "The proxy's
// status"), and its verdict. The record is a file of its own beside the
// exit's: AssessProxy reads nothing else, and nothing here touches the exit's
// verdict.

const (
	// ProxySchema is the proxy.json version this package reads.
	ProxySchema = 1
	// ProxyMaxAge: the record counts for this long (seconds).
	ProxyMaxAge = 30
	// ProxyMaxBytes bounds proxy.json for its writer and its readers.
	ProxyMaxBytes = 262144
)

// ProxyStatuses are the proxy's own statuses: serving, refusing new
// connections because the exit's verdict isn't ok, and the listener down.
var ProxyStatuses = []string{"ok", "refusing", "failed"}

// ProxyVerdict is the judgment of a proxy.json.
type ProxyVerdict struct {
	State   string // "ok", "refusing", "failed" or "unknown"
	Label   string
	Reasons []string
	// Message is the proxy's own message, nil for an unknown verdict.
	Message *string
	// Tunnel is the exit's verdict as the proxy saw it ("" when unknown).
	Tunnel string
	// Benched, Sessions and Open repeat the record's counts.
	Benched, Sessions, Open int
}

// ReadProxy reads proxy.json at path under the state files' rules (bounded,
// strict: duplicate keys refused); nil when it is missing or unreadable.
func ReadProxy(path string) any { return jsonfile.Read(path, ProxyMaxBytes) }

// AssessProxy judges a decoded proxy.json for a proxy of provider (empty:
// any provider). It is "unknown" for a missing, malformed, stale (older than
// ProxyMaxAge seconds) or future record, and otherwise the record's own
// status. A zero now means the current time.
func AssessProxy(record any, provider string, now time.Time) ProxyVerdict {
	if now.IsZero() {
		now = time.Now()
	}
	unknown := func(label, reason string) ProxyVerdict {
		return ProxyVerdict{State: "unknown", Label: label, Reasons: []string{reason}}
	}
	r, ok := record.(map[string]any)
	if !ok {
		return unknown("awaiting status", "no-status")
	}
	if n, isInt := validate.IsInt(r["schema"]); !isInt || n != ProxySchema {
		return unknown("unsupported status version", "unsupported-schema")
	}
	if r["kind"] != "proxy" {
		return unknown("kind mismatch", "kind-mismatch")
	}
	if p, isString := r["provider"].(string); !isString || (provider != "" && p != provider) {
		return unknown("provider mismatch", "provider-mismatch")
	}
	if _, valid := validate.ParseTime(r["checked_at"]); !valid {
		return unknown("invalid status record", "invalid-record")
	}
	if !validate.Fresh(r["checked_at"], ProxyMaxAge, now) {
		return unknown("status stale", "status-stale")
	}
	v, valid := readProxyRecord(r)
	if !valid {
		return unknown("invalid status record", "invalid-record")
	}
	return v
}

// readProxyRecord checks every member the writer writes and builds the
// verdict from the status.
func readProxyRecord(r map[string]any) (ProxyVerdict, bool) {
	status, _ := r["status"].(string)
	message, isString := r["message"].(string)
	if !contains(ProxyStatuses, status) || !isString || !validate.ValidText(message) ||
		r["guarantee"] != "opt-in" || !validate.ValidText(r["listen"]) {
		return ProxyVerdict{}, false
	}
	tunnel, ok := object(r["tunnel"])
	if !ok || !hasAll(tunnel, "verdict", "server", "checked_at") {
		return ProxyVerdict{}, false
	}
	tunnelVerdict, ok := textOrNull(tunnel["verdict"])
	if !ok {
		return ProxyVerdict{}, false
	}
	if _, ok := textOrNull(tunnel["server"]); !ok {
		return ProxyVerdict{}, false
	}
	if at := tunnel["checked_at"]; at != nil {
		if _, valid := validate.ParseTime(at); !valid {
			return ProxyVerdict{}, false
		}
	}
	servers, ok := object(r["servers"])
	if !ok {
		return ProxyVerdict{}, false
	}
	if _, ok := count(servers["known"]); !ok {
		return ProxyVerdict{}, false
	}
	benched, ok := servers["benched"].([]any)
	if !ok {
		return ProxyVerdict{}, false
	}
	for _, entry := range benched {
		b, ok := object(entry)
		if !ok || !validate.ValidText(b["server"]) || !validate.ValidText(b["reason"]) {
			return ProxyVerdict{}, false
		}
		if _, valid := validate.ParseTime(b["until"]); !valid {
			return ProxyVerdict{}, false
		}
	}
	sessions, ok := count(r["sessions"])
	if !ok {
		return ProxyVerdict{}, false
	}
	connections, ok := object(r["connections"])
	if !ok {
		return ProxyVerdict{}, false
	}
	open, ok1 := count(connections["open"])
	_, ok2 := count(connections["total"])
	_, ok3 := count(connections["failed"])
	if !ok1 || !ok2 || !ok3 {
		return ProxyVerdict{}, false
	}
	v := ProxyVerdict{State: status, Reasons: []string{}, Message: &message, Tunnel: tunnelVerdict,
		Benched: len(benched), Sessions: sessions, Open: open}
	switch status {
	case "ok":
		v.Label = "serving"
	case "refusing":
		v.Label = "refusing"
		v.Reasons = []string{"tunnel-not-ok"}
	case "failed":
		v.Label = "listener down"
		v.Reasons = []string{"listener-down"}
	}
	return v, true
}

// hasAll reports whether every key is a member of m (null included).
func hasAll(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if _, present := m[k]; !present {
			return false
		}
	}
	return true
}

// count is a non-negative JSON integer.
func count(v any) (int, bool) {
	n, ok := validate.IsInt(v)
	if !ok || n < 0 || n > 1<<31-1 {
		return 0, false
	}
	return int(n), true
}

// textOrNull is a short text or null ("" for null); false for anything else.
func textOrNull(v any) (string, bool) {
	if v == nil {
		return "", true
	}
	if !validate.ValidText(v) {
		return "", false
	}
	return v.(string), true
}
