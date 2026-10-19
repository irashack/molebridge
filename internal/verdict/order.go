package verdict

import (
	"sort"

	"github.com/irashack/molebridge/internal/validate"
)

// Member order of a record (the Python dict's) and of the checks, so the
// published file reads like the Python applier's did. Members not listed
// follow in sorted order.
var (
	recordOrder = []string{"schema", "kind", "backend", "provider", "status", "message", "checked_at", "server",
		"requested_server", "configured_server", "request_id", "selection", "checks", "egress_ip", "egress_ips",
		"egress_city", "egress_country"}
	selectionOrder = []string{"source", "outcome", "attempt", "target", "next_action", "next_action_at"}
	checkOrder     = []string{"state", "at", "server", "tier", "expected_families", "families", "reason", "age_s", "fallback", "from", "by", "expires_at"}
)

// ordered renders a decoded object in a given member order, the rest sorted.
func ordered(m map[string]any, order []string, child func(key string, v any) any) validate.Obj {
	o := make(validate.Obj, 0, len(m))
	seen := map[string]bool{}
	add := func(k string) {
		v, ok := m[k]
		if !ok || seen[k] {
			return
		}
		seen[k] = true
		if child != nil {
			v = child(k, v)
		}
		o = append(o, validate.Pair{Key: k, Value: v})
	}
	for _, k := range order {
		add(k)
	}
	rest := make([]string, 0, len(m))
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	for _, k := range rest {
		add(k)
	}
	return o
}

// OrderRecord renders a decoded record in the Python applier's member order.
// kind and backend order the checks (required first, then the fixed ones).
func OrderRecord(rec map[string]any, kind, backend string) validate.Obj {
	return ordered(rec, recordOrder, func(k string, v any) any {
		sub, ok := v.(map[string]any)
		if !ok {
			return v
		}
		switch k {
		case "selection":
			return ordered(sub, selectionOrder, nil)
		case "checks":
			names := append(append([]string{}, RequiredChecks(kind, backend)...), "owner_record", "app_attachment", "routing", "netbird", "traffic_protection")
			return ordered(sub, names, func(_ string, c any) any {
				if cm, ok := c.(map[string]any); ok {
					return ordered(cm, checkOrder, nil)
				}
				return c
			})
		}
		return v
	})
}
