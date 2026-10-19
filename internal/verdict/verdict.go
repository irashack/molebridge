// Package verdict is the one judgment of an exit's status record, for every
// reader (molebridge/verdict.py).
//
// The applier writes state/applier/result.json (schema 2, below). The panel's
// page, its API, the exit tabs, the browser, /readyz, the Gatus push and the
// doctor all judge it here, with Assess, so they agree. The container health
// check is operational and stays separate.
//
// Schema 2 states every check explicitly (CheckStates) and says which exit kind
// wrote it: "overlay" (a NetBird exit, native or gluetun backend) or "sidecar"
// (a tunnel other containers share: an ordinary gluetun, or, since 0.9.0, the
// native sidecar, Molebridge's own tunnel with a native provider). Records written before schema 2
// (0.6 and earlier) are read as overlay records (legacy). Any other schema is
// never connected.
//
// Only a fresh "pass" counts as passed. Every measured check carries its own
// "at", and peer, handshake and egress carry the "server" they measured, which
// must be the record's server: evidence never carries across a change of
// server, and a slow inspection's early measurements can age out even when the
// record itself is fresh.
//
// 0.8.0 addition (decision D7): the owner_record check may carry "expires_at",
// the supervisor's acknowledged lease expiry. It is an additional upper bound on
// that check, never an extension: a record without it is judged as in 0.7.0; a
// malformed one, or one that has passed, fails the check.
//
// The package offers Assess (with ExitConfig, Target and Verdict), StatusView,
// LegacyProjection, RequiredChecks, FixedChecks, BackendOf, OrderRecord (the
// member order the supervisor writes), and the schema's constants.
package verdict

import (
	"errors"
	"reflect"
	"time"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
)

// Schema is the status record version this package reads.
const Schema = 2

// The vocabularies of schema 2.
var (
	Kinds        = []string{"overlay", "sidecar"}
	CheckStates  = []string{"pass", "fail", "unknown", "n/a", "not-checked"}
	CheckNames   = []string{"routing", "netbird", "owner_record", "peer", "handshake", "egress", "traffic_protection", "app_attachment"}
	Sources      = []string{"configured", "panel", "restore", "reconverge", "retry", "operator-retry", "seed", "failover"}
	Outcomes     = []string{"verified", "applied-unverified", "pending", "rejected", "mutation-failed"}
	NextActions  = []string{"recheck", "reapply"}
	ServerBound  = []string{"peer", "handshake", "egress"}
	Families     = []string{"4", "6"}
	NotCheckedBy = map[string]string{"traffic_protection": "gluetun's firewall", "app_attachment": "the host doctor"}
)

const (
	// EvidenceMaxAge: a record, and each measured check in it, counts for this
	// long (seconds).
	EvidenceMaxAge = 150
	// HandshakeFreshSec: a handshake this old or older is stale.
	HandshakeFreshSec = 180
)

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// BackendOf is "gluetun" or "native", from the provider registry.
func BackendOf(provider string) string {
	if spec, ok := providers.Lookup(provider); ok && spec.Backend == providers.BackendGluetun {
		return providers.BackendGluetun
	}
	return providers.BackendNative
}

// RequiredChecks are the checks that must pass for this kind and backend.
func RequiredChecks(kind, backend string) []string {
	if kind == "sidecar" {
		if backend == providers.BackendNative {
			// The native sidecar keeps its applications' traffic in the tunnel
			// itself (routing contract and firewall), so it judges both.
			return []string{"routing", "traffic_protection", "peer", "handshake", "egress"}
		}
		// A gluetun sidecar has no contract of ours, and gluetun's firewall is
		// not ours to check.
		return []string{"peer", "handshake", "egress"}
	}
	if backend == providers.BackendNative {
		return []string{"routing", "netbird", "owner_record", "peer", "handshake", "egress", "traffic_protection"}
	}
	return []string{"routing", "netbird", "peer", "handshake", "egress", "traffic_protection"}
}

// Check is one check's display state.
type Check struct {
	Name  string
	State string
}

// Checks are the display states by check, in the order Python's dict held them.
type Checks []Check

// Get returns a check's state, or "" when there is none.
func (c Checks) Get(name string) string {
	for _, check := range c {
		if check.Name == name {
			return check.State
		}
	}
	return ""
}

func (c *Checks) set(name, state string) {
	for i := range *c {
		if (*c)[i].Name == name {
			(*c)[i].State = state
			return
		}
	}
	*c = append(*c, Check{name, state})
}

// Map returns the states by name.
func (c Checks) Map() map[string]string {
	out := make(map[string]string, len(c))
	for _, check := range c {
		out[check.Name] = check.State
	}
	return out
}

// JSONObject implements validate.ObjectMarshaler.
func (c Checks) JSONObject() validate.Obj {
	o := make(validate.Obj, 0, len(c))
	for _, check := range c {
		o = append(o, validate.Pair{Key: check.Name, Value: check.State})
	}
	return o
}

// FixedChecks are the checks that are "n/a" or "not-checked" for this kind and
// backend.
func FixedChecks(kind, backend string) Checks {
	if kind == "sidecar" {
		if backend == providers.BackendNative {
			// No NetBird and no owner lease; the host doctor attaches the
			// application.
			return Checks{{"netbird", "n/a"}, {"owner_record", "n/a"}, {"app_attachment", "not-checked"}}
		}
		return Checks{{"routing", "n/a"}, {"netbird", "n/a"}, {"owner_record", "n/a"},
			{"traffic_protection", "not-checked"}, {"app_attachment", "not-checked"}}
	}
	fixed := Checks{{"app_attachment", "n/a"}}
	if backend == providers.BackendGluetun {
		fixed = append(fixed, Check{"owner_record", "n/a"})
	}
	return fixed
}

// ExitConfig is the reader's own configuration of one exit.
type ExitConfig struct {
	Provider string
	Kind     string // "overlay", or "sidecar" (a gluetun sidecar or a native sidecar)
	ID       string
}

// NewExitConfig validates the combination: a known provider and a known kind.
// A sidecar takes any provider: a gluetun provider makes the gluetun sidecar,
// a native one (since 0.9.0) the native sidecar. An empty kind means "overlay".
func NewExitConfig(provider, kind, id string) (ExitConfig, error) {
	if kind == "" {
		kind = "overlay"
	}
	if _, ok := providers.Lookup(provider); !ok {
		return ExitConfig{}, errors.New("unknown provider")
	}
	if !contains(Kinds, kind) {
		return ExitConfig{}, errors.New("EXIT_KIND must be overlay or sidecar")
	}
	return ExitConfig{Provider: provider, Kind: kind, ID: id}, nil
}

// gluetunSidecar is the sidecar of 0.8.0: an ordinary gluetun that other
// containers share. The native sidecar is the other sidecar.
func (c ExitConfig) gluetunSidecar() bool {
	return c.Kind == "sidecar" && c.Backend() == providers.BackendGluetun
}

// Backend is "gluetun" or "native".
func (c ExitConfig) Backend() string { return BackendOf(c.Provider) }

// Spec is the provider's registry entry (nil for an unregistered provider).
func (c ExitConfig) Spec() *providers.Provider {
	spec, _ := providers.Lookup(c.Provider)
	return spec
}

// Target is the server the reader expects, and why. An empty Server is none.
//
//   - In the applier and the doctor: the applier's own resolution (its local
//     SERVER first, then its pipeline state).
//   - In the panel (TargetForPanel): the configured lock read from the record,
//     or else the panel's own request, which the record must acknowledge.
type Target struct {
	Server string
	Source string
	// Request is the panel's desired.json request, when the target is one.
	Request *state.Request
}

// TargetForPanel is the panel's target for a status record and its request.
func TargetForPanel(result, desired any, provider string) Target {
	if configured, ok := state.ConfiguredServer(result); ok {
		return Target{Server: configured, Source: "configured"}
	}
	if request, ok := state.DesiredRequest(desired, provider); ok {
		return Target{Server: request.Server, Source: "panel", Request: &request}
	}
	return Target{}
}

// Verdict is the judgment.
type Verdict struct {
	State   string
	Label   string
	Reasons []string
	// Message is the applier's own message, shown with a failure; nil for none.
	Message          *string
	Tier             string // "provider" or "tunnel" when connected
	Checks           Checks
	Schema           int // 0 for none, else 1 or 2
	Kind             string
	ConfiguredServer string // empty for none
	NextAction       string // "recheck", "reapply" or empty
	NextActionAt     string // a timestamp, or empty
}

func orNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// AsJSON is the verdict as the panel's API reports it, in Python's member order.
func (v Verdict) AsJSON() validate.Obj {
	reasons := make([]any, len(v.Reasons))
	for i, r := range v.Reasons {
		reasons[i] = r
	}
	var message any
	if v.Message != nil {
		message = *v.Message
	}
	var schema any
	if v.Schema != 0 {
		schema = v.Schema
	}
	return validate.Members("state", v.State, "label", v.Label, "reasons", reasons, "message", message,
		"tier", orNull(v.Tier), "checks", v.Checks.JSONObject(), "schema", schema, "kind", orNull(v.Kind),
		"configured_server", orNull(v.ConfiguredServer), "next_action", orNull(v.NextAction),
		"next_action_at", orNull(v.NextActionAt))
}

// JSONObject implements validate.ObjectMarshaler.
func (v Verdict) JSONObject() validate.Obj { return v.AsJSON() }

// -- the verdict --------------------------------------------------------------

func fresh(value any, now time.Time) bool { return validate.Fresh(value, now, EvidenceMaxAge) }

func object(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// same is Python's == on decoded JSON values (without ever panicking on
// values Go cannot compare).
func same(a, b any) bool { return reflect.DeepEqual(a, b) }

// Assess is the one judgment of result (the parsed result.json) for this exit,
// against target. A zero now means the current time. The order of the rules is
// the order below.
func Assess(exit ExitConfig, result any, target Target, now time.Time) Verdict {
	if now.IsZero() {
		now = time.Now()
	}
	// 1. The configured lock, independently: it holds when the record is stale.
	configured, _ := state.ConfiguredServer(result)
	base := Verdict{ConfiguredServer: configured, Kind: exit.Kind}
	with := func(v Verdict) Verdict {
		v.ConfiguredServer, v.Kind, v.Schema = base.ConfiguredServer, base.Kind, base.Schema
		v.NextAction, v.NextActionAt = base.NextAction, base.NextActionAt
		if v.Reasons == nil {
			v.Reasons = []string{}
		}
		return v
	}
	// 2. Nothing readable yet.
	record, ok := object(result)
	if !ok {
		return with(Verdict{State: "unknown", Label: "awaiting status", Reasons: []string{"no-status"}})
	}
	// 3. The schema.
	if _, present := record["schema"]; !present {
		return legacy(exit, record, target, now, base)
	}
	if n, isInt := validate.IsInt(record["schema"]); !isInt || n != Schema {
		return with(Verdict{State: "unknown", Label: "unsupported status version", Reasons: []string{"unsupported-schema"}})
	}
	base.Schema = Schema
	selection, _ := object(record["selection"])
	if selection == nil {
		selection = map[string]any{}
	}
	if action, isString := selection["next_action"].(string); isString && contains(NextActions, action) {
		base.NextAction = action
		if _, valid := validate.ParseTime(selection["next_action_at"]); valid {
			base.NextActionAt = selection["next_action_at"].(string)
		}
	}
	// 4. Kind, provider and backend: never defaulted.
	if record["kind"] != exit.Kind {
		return with(Verdict{State: "unknown", Label: "kind mismatch", Reasons: []string{"kind-mismatch"}})
	}
	if record["provider"] != exit.Provider || record["backend"] != exit.Backend() {
		return with(Verdict{State: "unknown", Label: "provider mismatch", Reasons: []string{"provider-mismatch"}})
	}
	// 5. A stale or future record.
	if !fresh(record["checked_at"], now) {
		return with(Verdict{State: "unknown", Label: "status stale", Reasons: []string{"status-stale"}})
	}
	// 6. The panel's request, acknowledged.
	if state_, label, reason, pending := unacknowledged(record, target, now); pending {
		return with(Verdict{State: state_, Label: label, Reasons: []string{reason}})
	}
	status := record["status"]
	// 7. A switch in progress.
	if status == "applying" {
		return with(Verdict{State: "applying", Label: "switching", Reasons: []string{"applying"}})
	}
	var message *string
	if m, isString := record["message"].(string); isString {
		message = &m
	}
	checks, problems, valid := readChecks(exit, record, now)
	if !valid {
		return with(Verdict{State: "unknown", Label: "invalid status record", Reasons: []string{"invalid-record"}, Checks: checks})
	}
	failed, expired, unmeasured := problems.failed, problems.expired, problems.unmeasured
	outcome, _ := selection["outcome"].(string)
	rejected := outcome == "rejected" || outcome == "mutation-failed"
	// A tunnel-tier gluetun sidecar can't compare its egress with the host's
	// own address: switched, never verified, and not a measured failure. Only
	// the gluetun sidecar: a native sidecar's providers confirm the egress
	// themselves (provider tier), so for it an egress failure, whatever reason
	// the record gives, is a measured failure and falls through to rule 8.
	if exit.gluetunSidecar() && !rejected && len(failed) == 1 && failed[0] == "egress" {
		allChecks, _ := object(record["checks"])
		if egress, isObject := object(allChecks["egress"]); isObject && egress["reason"] == "host-address-not-measurable" {
			text := "Switched; the egress couldn't be compared with this host's address."
			return with(Verdict{State: "unknown", Label: "switched, egress unverified", Reasons: []string{"host-address-not-measurable"},
				Message: &text, Checks: checks})
		}
	}
	// 8. A fresh measured failure, or a rejection, first; then expired
	// evidence; then what was never measured.
	if len(failed) > 0 || rejected {
		reasons := []string{}
		for _, name := range failed {
			reasons = append(reasons, name+"-failed")
		}
		if rejected {
			reasons = append(reasons, "rejected")
		}
		return with(Verdict{State: "failed", Label: "failed", Reasons: reasons, Message: message, Checks: checks})
	}
	if len(expired) > 0 {
		reasons := []string{}
		for _, name := range expired {
			reasons = append(reasons, name+"-expired")
		}
		return with(Verdict{State: "unknown", Label: "evidence expired", Reasons: reasons, Checks: checks})
	}
	if status == "failed" {
		return with(Verdict{State: "failed", Label: "failed", Reasons: []string{"status-failed"}, Message: message, Checks: checks})
	}
	if len(unmeasured) > 0 {
		reasons := []string{}
		for _, name := range unmeasured {
			reasons = append(reasons, name+"-unmeasured")
		}
		return with(Verdict{State: "unknown", Label: "not yet measured", Reasons: reasons, Checks: checks})
	}
	// 9. A healthy record: every required check passes and the target agrees.
	if status == "ok" {
		allChecks, _ := object(record["checks"])
		egress, _ := object(allChecks["egress"])
		tier, _ := egress["tier"].(string)
		if disagreement := targetDisagreement(record, target, selection, configured, configuredPresent(configured)); disagreement != "" {
			return with(Verdict{State: "failed", Label: "verification failed", Reasons: []string{disagreement}, Message: message, Checks: checks})
		}
		var note []string
		src := selection["source"]
		if target.Server == "" && (src == nil || src == "seed") {
			note = []string{"no-selection"}
		}
		return with(Verdict{State: "ok", Label: "connected", Reasons: note, Tier: tier, Checks: checks})
	}
	// 10. Anything else.
	return with(Verdict{State: "unknown", Label: "unknown", Reasons: []string{"status-unknown"}, Message: message, Checks: checks})
}

func configuredPresent(configured string) bool { return configured != "" }

// unacknowledged: while the panel's request isn't acknowledged, switching
// while it is fresh, then unknown.
func unacknowledged(record map[string]any, target Target, now time.Time) (state_, label, reason string, pending bool) {
	if target.Source != "panel" || target.Request == nil {
		return "", "", "", false
	}
	if record["request_id"] == state.RequestToken(*target.Request) {
		return "", "", "", false
	}
	if fresh(target.Request.RequestedAt, now) {
		return "applying", "switching", "request-pending", true
	}
	return "unknown", "request not acknowledged", "request-not-acknowledged", true
}

// targetDisagreement is why the record's server isn't the reader's target, or
// "".
func targetDisagreement(record map[string]any, target Target, selection map[string]any, configured string, hasConfigured bool) string {
	server := record["server"]
	if target.Source == "configured" || hasConfigured {
		expected := configured
		if target.Source == "configured" {
			expected = target.Server
		}
		if server == expected {
			return ""
		}
		return "not-configured-server"
	}
	if target.Source == "panel" {
		if server == target.Server && record["requested_server"] == target.Server {
			return ""
		}
		return "not-requested-server"
	}
	if target.Server != "" {
		if server == target.Server {
			return ""
		}
		return "not-target-server"
	}
	// The reader has no target of its own: the record's selection must agree
	// with itself, except an observed seed.
	if source, isString := selection["source"].(string); isString && contains([]string{"restore", "reconverge", "retry", "operator-retry", "failover"}, source) {
		if same(server, selection["target"]) {
			return ""
		}
		return "not-target-server"
	}
	return ""
}

type issues struct{ failed, expired, unmeasured []string }

// readChecks returns the display states by check and the problems among the
// required checks, or valid == false when the record is malformed.
func readChecks(exit ExitConfig, record map[string]any, now time.Time) (display Checks, found issues, valid bool) {
	kind, backend := exit.Kind, exit.Backend()
	display = FixedChecks(kind, backend)
	raw, ok := object(record["checks"])
	if !ok {
		return display, found, false
	}
	server := record["server"]
	required := RequiredChecks(kind, backend)
	for _, name := range required {
		check, ok := object(raw[name])
		if !ok {
			return display, found, false
		}
		stateText, isString := check["state"].(string)
		if !isString || !contains(CheckStates, stateText) {
			return display, found, false
		}
		if stateText == "n/a" || stateText == "not-checked" {
			// A required check can't be waived by the record.
			return display, found, false
		}
		if stateText == "pass" || stateText == "fail" {
			if !validShape(name, check, stateText, exit) {
				return display, found, false
			}
			if !fresh(check["at"], now) {
				found.expired = append(found.expired, name)
				display.set(name, "unknown")
				continue
			}
			if contains(ServerBound, name) && (!same(check["server"], server) || server == nil) && stateText == "pass" {
				// A pass for another selection never counts.
				found.expired = append(found.expired, name)
				display.set(name, "unknown")
				continue
			}
			if stateText == "pass" && name == "owner_record" && leaseLapsed(check, now) {
				// The lease the supervisor acknowledged has run out, or the
				// record's account of it can't be read: the owner is not live.
				stateText = "fail"
			}
			if stateText == "fail" {
				found.failed = append(found.failed, name)
			}
		} else {
			found.unmeasured = append(found.unmeasured, name)
		}
		display.set(name, stateText)
	}
	if contains(required, "traffic_protection") && display.Get("traffic_protection") == "pass" {
		// Traffic protection is the routing contract itself (the overlay), or
		// the contract and the firewall together (the native sidecar); a pass
		// is only ever "from" routing, as a failure names the firewall alone.
		protection, _ := object(raw["traffic_protection"])
		if protection["from"] != "routing" || display.Get("routing") == "fail" {
			return display, found, false
		}
	}
	if display.Get("egress") == "pass" && !EgressIPsConsistent(record) {
		return display, found, false
	}
	return display, found, true
}

// leaseLapsed implements the 0.8.0 bound on owner_record: with an expires_at
// member (the same timestamp format as "at"), the check is good only until
// then. Without the member it is never lapsed (0.7.0 behavior); with one that is
// not a well-formed timestamp, or that is now or in the past, it is.
func leaseLapsed(check map[string]any, now time.Time) bool {
	value, present := check["expires_at"]
	if !present {
		return false
	}
	deadline, ok := validate.ParseTime(value)
	return !ok || !now.Before(deadline)
}

// validShape applies strict types to the checks that carry measurements.
func validShape(name string, check map[string]any, stateText string, exit ExitConfig) bool {
	spec := exit.Spec()
	switch name {
	case "handshake":
		age := check["age_s"]
		n, isInt := validate.IsInt(age)
		if age != nil && (!isInt || n < 0) {
			return false
		}
		if stateText == "pass" && (age == nil || n >= HandshakeFreshSec) {
			return false
		}
	case "egress":
		families, ok1 := object(check["families"])
		expected, ok2 := check["expected_families"].([]any)
		if !ok1 || !ok2 || len(expected) == 0 {
			return false
		}
		for family := range families {
			if !contains(Families, family) {
				return false
			}
		}
		seen := map[string]bool{}
		for _, raw := range expected {
			family, isString := raw.(string)
			if !isString || !contains(Families, family) || seen[family] {
				return false
			}
			seen[family] = true
		}
		for _, value := range families {
			s, isString := value.(string)
			if !isString || !contains(CheckStates, s) {
				return false
			}
		}
		if stateText == "pass" {
			for _, raw := range expected {
				if families[raw.(string)] != "pass" {
					return false
				}
			}
			tier, isString := check["tier"].(string)
			if !isString || !contains(providers.Tiers, tier) {
				return false
			}
			// The tunnel tier counts only where the provider has no stronger
			// check, and never for a gluetun sidecar (it can't measure the
			// host's address). A native sidecar follows the overlay's rule.
			if tier == providers.TierTunnel && (exit.gluetunSidecar() || spec == nil || spec.EgressTier != providers.TierTunnel) {
				return false
			}
		}
	}
	return true
}

// EgressIPsConsistent reports whether the record's egress_ips covers exactly
// the passing families of its egress check.
func EgressIPsConsistent(record any) bool {
	m, ok := object(record)
	if !ok {
		return false
	}
	checks, _ := object(m["checks"])
	check, ok1 := object(checks["egress"])
	ips, ok2 := object(m["egress_ips"])
	if !ok1 || !ok2 {
		return false
	}
	families, _ := object(check["families"])
	passing := 0
	for family, value := range families {
		if value == "pass" {
			passing++
			if _, listed := ips[family]; !listed {
				return false
			}
		}
	}
	return len(ips) == passing
}

// -- legacy records (schema absent: 0.6 and earlier) --------------------------------

// legacy judges a 0.6 overlay record as 0.6's status_view judged it, plus the
// target and provider. Its checks aren't reported individually.
func legacy(exit ExitConfig, record map[string]any, target Target, now time.Time, base Verdict) Verdict {
	base.Schema = 1
	with := func(v Verdict) Verdict {
		v.ConfiguredServer, v.Kind, v.Schema = base.ConfiguredServer, base.Kind, base.Schema
		if v.Reasons == nil {
			v.Reasons = []string{}
		}
		return v
	}
	checks := Checks{}
	for _, name := range []string{"routing", "netbird", "owner_record", "peer", "handshake", "egress", "traffic_protection"} {
		checks = append(checks, Check{name, "legacy"})
	}
	checks = append(checks, Check{"app_attachment", "n/a"})
	// Records without a schema are 0.6 overlay records: either sidecar is a
	// kind mismatch.
	if exit.Kind != "overlay" {
		return with(Verdict{State: "unknown", Label: "kind mismatch", Reasons: []string{"kind-mismatch"}})
	}
	if !fresh(record["checked_at"], now) {
		return with(Verdict{State: "unknown", Label: "status stale", Reasons: []string{"status-stale"}})
	}
	if state_, label, reason, pending := unacknowledged(record, target, now); pending {
		return with(Verdict{State: state_, Label: label, Reasons: []string{reason}})
	}
	status := record["status"]
	var message *string
	if m, isString := record["message"].(string); isString {
		message = &m
	}
	switch status {
	case "applying":
		return with(Verdict{State: "applying", Label: "switching", Reasons: []string{"applying"}})
	case "failed":
		return with(Verdict{State: "failed", Label: "failed", Reasons: []string{"status-failed"}, Message: message, Checks: checks})
	case "ok":
	default:
		return with(Verdict{State: "unknown", Label: "unknown", Reasons: []string{"status-unknown"}, Checks: checks})
	}
	provider := record["provider"]
	tier := state.EgressTier(record, exit.Provider)
	if provider != nil && provider != exit.Provider {
		return with(Verdict{State: "unknown", Label: "provider mismatch", Reasons: []string{"provider-mismatch"}})
	}
	reasons := []string{}
	if record["routing_ok"] != true {
		reasons = append(reasons, "routing-failed")
	}
	// Results written before the NetBird mode check have no such field.
	if native, present := record["netbird_native"]; present && native != true {
		reasons = append(reasons, "netbird-failed")
	}
	if tier == "" {
		reasons = append(reasons, "egress-failed")
	}
	if disagreement := targetDisagreement(record, target, map[string]any{}, base.ConfiguredServer, base.ConfiguredServer != ""); disagreement != "" {
		reasons = append(reasons, disagreement)
	}
	if len(reasons) > 0 {
		return with(Verdict{State: "failed", Label: "verification failed", Reasons: reasons, Message: message, Checks: checks})
	}
	return with(Verdict{State: "ok", Label: "connected", Tier: tier, Checks: checks})
}

// StatusView is (state, label) for an exit, as Assess judges it. An exit
// configuration that doesn't validate is "unknown provider".
func StatusView(desired, result any, provider, kind string, now time.Time) (stateText, label string) {
	exit, err := NewExitConfig(provider, kind, "")
	if err != nil {
		return "unknown", "unknown provider"
	}
	verdict := Assess(exit, result, TargetForPanel(result, desired, provider), now)
	return verdict.State, verdict.Label
}

// -- the deprecated 0.6 projection -----------------------------------------------

// LegacyFields hold the fields a cached 0.6 browser script reads from
// /api/status's "result", derived from a schema-2 record (deprecated; one
// release). A nil pointer is None where the check is unknown or doesn't apply.
type LegacyFields struct {
	RoutingOK           *bool
	NetbirdNative       *bool
	ExitConfirmed       *bool
	EgressTier          *string
	HandshakeAgeS       any
	UnreachableFallback *bool
}

// JSONObject implements validate.ObjectMarshaler.
func (p LegacyFields) JSONObject() validate.Obj {
	b := func(v *bool) any {
		if v == nil {
			return nil
		}
		return *v
	}
	var tier any
	if p.EgressTier != nil {
		tier = *p.EgressTier
	}
	return validate.Members("routing_ok", b(p.RoutingOK), "netbird_native", b(p.NetbirdNative),
		"exit_confirmed", b(p.ExitConfirmed), "egress_tier", tier, "handshake_age_s", p.HandshakeAgeS,
		"unreachable_fallback", b(p.UnreachableFallback))
}

// LegacyProjection returns the fields for a schema-2 record, and false for
// anything else (Python returns {}).
func LegacyProjection(result any, verdict Verdict) (LegacyFields, bool) {
	record, ok := object(result)
	if !ok || verdict.Schema != Schema {
		return LegacyFields{}, false
	}
	checks, _ := object(record["checks"])
	routing, _ := object(checks["routing"])
	egress, _ := object(checks["egress"])
	handshake, _ := object(checks["handshake"])
	state := func(name string) *bool {
		var v bool
		switch verdict.Checks.Get(name) {
		case "pass":
			v = true
		case "fail":
			v = false
		default:
			return nil
		}
		return &v
	}
	var p LegacyFields
	p.RoutingOK, p.NetbirdNative = state("routing"), state("netbird")
	egressState := verdict.Checks.Get("egress")
	switch egressState {
	case "pass":
		confirmed := egress["tier"] == "provider"
		p.ExitConfirmed = &confirmed
		if egress["tier"] == providers.TierTunnel {
			tier := providers.TierTunnel
			p.EgressTier = &tier
		}
	case "fail":
		confirmed := false
		p.ExitConfirmed = &confirmed
	}
	if s := verdict.Checks.Get("handshake"); s == "pass" || s == "fail" {
		p.HandshakeAgeS = handshake["age_s"]
	}
	if s := verdict.Checks.Get("routing"); s == "pass" || s == "fail" {
		if fallback, isBool := routing["fallback"].(bool); isBool {
			p.UnreachableFallback = &fallback
		}
	}
	return p, true
}
