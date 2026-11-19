package exit

import (
	"strings"
	"time"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

// Messages the supervisor publishes itself.
const (
	// StartingMessage is what the Python applier published before its first
	// inspection (applier/apply.py main).
	StartingMessage = "Applier starting; waiting for verification."
	// OwnerStoppedMessage is D7's failure message.
	OwnerStoppedMessage = "exit owner stopped responding"
)

// serverReportChars is applier.ServerReportChars: the longest configured
// server a record reports.
const serverReportChars = 256

// BlankChecks is the checks of a record nothing has measured: the required
// ones unknown, the rest as the kind fixes them (blank_checks).
func BlankChecks(kind, backend string) validate.Obj {
	checks := validate.Obj{}
	for _, name := range verdict.RequiredChecks(kind, backend) {
		checks = append(checks, validate.Pair{Key: name, Value: validate.Members("state", "unknown")})
	}
	for _, c := range verdict.FixedChecks(kind, backend) {
		check := validate.Members("state", c.State)
		if c.State == "not-checked" {
			check = append(check, validate.Pair{Key: "by", Value: verdict.NotCheckedBy[c.Name]})
		}
		checks = checks.Set(c.Name, check)
	}
	return checks
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

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// parseFlag is pia.py's parse_flag, lenient: an unreadable word is off (the
// pipeline refuses it on its own).
func parseFlag(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}

// StartingRecord is the record the Python applier published at start, before
// its first inspection: status unknown, nothing measured, the seed selection.
func StartingRecord(s *Settings, now time.Time) map[string]any {
	kind, backend := s.Kind(), s.BackendName()
	rec := validate.Members(
		"schema", verdict.Schema, "kind", kind, "backend", backend, "provider", s.Provider,
		"status", "unknown", "message", StartingMessage, "checked_at", validate.FormatTime(now),
		"server", nil, "requested_server", nil,
		"configured_server", nullable(truncateRunes(s.Server, serverReportChars)), "request_id", nil,
		"selection", validate.Members("source", "seed", "outcome", nil, "attempt", 0, "target", nil,
			"next_action", nil, "next_action_at", nil),
		"checks", BlankChecks(kind, backend),
		"egress_ip", nil, "egress_ips", validate.Obj{}, "egress_city", nil, "egress_country", nil)
	if s.Provider == "pia" {
		forward := parseFlag(s.Env["PIA_PORT_FORWARD"])
		rec = append(rec, validate.Pair{Key: "port_forward", Value: forward}, validate.Pair{Key: "forwarded_port", Value: nil})
		if forward {
			rec = append(rec, validate.Pair{Key: "port_forward_error", Value: nil})
		}
	}
	return toMap(rec)
}

// RoutingActivity is the routing_activity member of a record: what the
// mutation owner and the kernel watcher counted since the worker started.
// Only exits with a routing contract carry it. No reader judges it.
type RoutingActivity struct {
	// Repairs counts the repair passes that changed the kernel, and
	// LastRepair is when the last one ran (zero before the first).
	Repairs    uint64
	LastRepair time.Time
	// Events counts the kernel's notifications, Relevant those that asked for
	// a repair pass, Lost the receive-buffer overruns (each one ran a full
	// pass) and Periodic the full passes on ROUTING_RECONCILE_INTERVAL.
	Events, Relevant, Lost, Periodic uint64
}

// JSONObject implements validate.ObjectMarshaler.
func (r RoutingActivity) JSONObject() validate.Obj {
	var last any
	if !r.LastRepair.IsZero() {
		last = validate.FormatTime(r.LastRepair)
	}
	return validate.Members("repairs", r.Repairs, "last_repair_at", last, "events", r.Events,
		"relevant_events", r.Relevant, "events_lost", r.Lost, "periodic_passes", r.Periodic)
}

// toMap turns an ordered record into the decoded form the supervisor keeps.
func toMap(o validate.Obj) map[string]any {
	raw, err := validate.MarshalJSON(o)
	if err != nil {
		panic("exit: an internal record does not encode: " + err.Error())
	}
	v, err := validate.DecodeJSON(raw)
	if err != nil {
		panic("exit: an internal record does not decode: " + err.Error())
	}
	return v.(map[string]any)
}

// OwnerCheck is the owner_record check: pass with the accepted expiry on the
// wall clock, or fail. at is the time of writing. expires_at is truncated down
// to the second so the record never claims more than the lease.
func OwnerCheck(held bool, now time.Time, expiryWall time.Time) validate.Obj {
	if !held {
		return validate.Members("state", "fail", "at", validate.FormatTime(now))
	}
	return validate.Members("state", "pass", "at", validate.FormatTime(now), "expires_at", validate.FormatTime(expiryWall))
}

// WithOwnerCheck returns a copy of the record with its owner_record check
// replaced. Records of other exit kinds are returned as they are: only a
// native overlay exit carries the check (D7).
func WithOwnerCheck(rec map[string]any, check validate.Obj) map[string]any {
	out := make(map[string]any, len(rec))
	for k, v := range rec {
		out[k] = v
	}
	checks := map[string]any{}
	if old, ok := rec["checks"].(map[string]any); ok {
		for k, v := range old {
			checks[k] = v
		}
	}
	checks["owner_record"] = toMap(check)
	out["checks"] = checks
	return out
}

// FailureRecord is the record the supervisor publishes when the lease lapses
// or the worker dies, built from the last record it held (D7). One
// constructor, three branches:
//
//   - a native overlay fails owner_record, routing, netbird and, consistently
//     (the reader rejects a passed traffic_protection beside a failed
//     routing), traffic_protection;
//   - a gluetun overlay fails routing, netbird and traffic_protection and
//     keeps owner_record n/a;
//   - a sidecar keeps every fixed field and marks its required checks (peer,
//     handshake, egress) unknown: the worker that measured them is gone and
//     nothing is invented.
//
// In every branch the status is failed, the message OwnerStoppedMessage,
// checked_at and the failed checks' times are the lapse time, and everything
// else (the other checks with their own evidence times, the selection, the
// server) is kept.
func FailureRecord(prev map[string]any, s *Settings, lapse time.Time) map[string]any {
	kind, backend := s.Kind(), s.BackendName()
	at := validate.FormatTime(lapse)
	rec := map[string]any{}
	for k, v := range prev {
		rec[k] = v
	}
	if prev == nil {
		rec = StartingRecord(s, lapse)
	}
	checks := map[string]any{}
	if old, ok := rec["checks"].(map[string]any); ok {
		for k, v := range old {
			checks[k] = v
		}
	}
	blank := toMap(BlankChecks(kind, backend))
	for name := range blank {
		if _, ok := checks[name]; !ok {
			checks[name] = blank[name]
		}
	}
	fail := func(name string, extra ...any) {
		c := map[string]any{"state": "fail", "at": at}
		for i := 0; i+1 < len(extra); i += 2 {
			c[extra[i].(string)] = extra[i+1]
		}
		checks[name] = c
	}
	switch {
	case kind == "sidecar":
		for _, name := range verdict.RequiredChecks(kind, backend) {
			checks[name] = map[string]any{"state": "unknown"}
		}
	default:
		if backend == providers.BackendNative {
			fail("owner_record")
		}
		fail("routing")
		fail("netbird")
		fail("traffic_protection", "from", "routing")
	}
	rec["checks"] = checks
	rec["status"] = "failed"
	rec["message"] = OwnerStoppedMessage
	rec["checked_at"] = at
	return rec
}
