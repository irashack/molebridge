package panel

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/irashack/molebridge/internal/panel/oidc"
	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

// /metrics is the Prometheus text format (version 0.0.4) of what the panel
// already reads for /readyz and /api/status: one verdict per exit, its
// checks, and a few numbers from the record and the catalogue. It reads the
// same files on each scrape and keeps no state of its own.
//
// It shows what /readyz shows: molebridge_ready to anyone who passes the
// Host check, and the per-exit series for the exits /readyz?exit= would
// answer for, which with sign-in on are the ones the caller's session is
// granted (none without a session).

const metricsContentType = "text/plain; version=0.0.4; charset=utf-8"

// exitStates and checkStates are every value the state series take, so each
// exit has all of them, 1 for the current one and 0 for the rest.
var (
	exitStates  = []string{"ok", "failed", "applying", "unknown"}
	checkStates = append(append([]string(nil), verdict.CheckStates...), "legacy")
)

// metricsWriter writes families in order, each with its HELP and TYPE once.
type metricsWriter struct {
	b    strings.Builder
	seen map[string]bool
}

func (m *metricsWriter) family(name, kind, help string) {
	if m.seen[name] {
		return
	}
	m.seen[name] = true
	fmt.Fprintf(&m.b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
}

// sample writes one line; labels are name, value pairs.
func (m *metricsWriter) sample(name string, value float64, labels ...string) {
	m.b.WriteString(name)
	if len(labels) > 0 {
		m.b.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				m.b.WriteByte(',')
			}
			m.b.WriteString(labels[i] + `="` + escapeLabel(labels[i+1]) + `"`)
		}
		m.b.WriteByte('}')
	}
	m.b.WriteByte(' ')
	m.b.WriteString(strconv.FormatFloat(value, 'f', -1, 64))
	m.b.WriteByte('\n')
}

// escapeLabel is the text format's label escaping. Every value the panel
// writes is an exit id, a provider id or a fixed name, so this never fires;
// it is kept so that a label can never break the format.
func escapeLabel(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// metricsExits are the exits whose series a caller sees: /readyz?exit='s rule.
func (s *Server) metricsExits(session *oidc.Session) []Exit {
	var out []Exit
	for _, e := range s.allExits() {
		if s.granted(e, session) {
			out = append(out, e)
		}
	}
	return out
}

// metrics is the /metrics body.
func (s *Server) metrics(session *oidc.Session) []byte {
	m := &metricsWriter{seen: map[string]bool{}}
	statuses := map[string]ExitStatus{}
	ready := true
	for _, e := range s.allExits() {
		st := s.readStatus(e)
		statuses[e.ID] = st
		ready = ready && st.Verdict.State == "ok"
	}
	m.family("molebridge_ready", "gauge", "1 when every exit has a fresh verified connected state, as /readyz answers 200.")
	m.sample("molebridge_ready", boolValue(ready))

	exits := s.metricsExits(session)
	for _, e := range exits {
		m.family("molebridge_exit_info", "gauge", "One series per exit, naming its provider and kind.")
		m.sample("molebridge_exit_info", 1, "exit", e.ID, "provider", e.Provider, "kind", e.Kind)
	}
	for _, e := range exits {
		v := statuses[e.ID].Verdict
		m.family("molebridge_exit_state", "gauge", "The verdict on the exit: 1 for its state, 0 for the others.")
		for _, st := range exitStates {
			m.sample("molebridge_exit_state", boolValue(v.State == st), "exit", e.ID, "state", st)
		}
	}
	for _, e := range exits {
		view := s.exitView(e, statuses[e.ID].Verdict)
		m.family("molebridge_exit_check", "gauge", "Each check as /api/status states it: 1 for its state, 0 for the others.")
		for _, name := range verdict.CheckNames {
			for _, st := range checkStates {
				m.sample("molebridge_exit_check", boolValue(view.Checks[name] == st), "exit", e.ID, "check", name, "state", st)
			}
		}
	}
	for _, e := range exits {
		if at, ok := validate.ParseTime(statuses[e.ID].Result["checked_at"]); ok {
			m.family("molebridge_exit_checked_timestamp_seconds", "gauge", "When the exit last wrote its record (checked_at), as Unix time.")
			m.sample("molebridge_exit_checked_timestamp_seconds", float64(at.Unix()), "exit", e.ID)
		}
	}
	for _, e := range exits {
		if age, ok := handshakeAge(statuses[e.ID]); ok {
			m.family("molebridge_exit_handshake_age_seconds", "gauge", "The tunnel's last handshake age as the record states it, as of checked_at.")
			m.sample("molebridge_exit_handshake_age_seconds", age, "exit", e.ID)
		}
	}
	type snapshot struct {
		exit   string
		meta   map[string]any
		relays int
	}
	var snapshots []snapshot
	for _, e := range exits {
		if meta, relays := s.cachedSnapshot(e); meta != nil {
			snapshots = append(snapshots, snapshot{e.ID, meta, relays.Len()})
		}
	}
	for _, sn := range snapshots {
		if at, ok := validate.ParseTime(sn.meta["fetched_at"]); ok {
			m.family("molebridge_exit_catalog_fetched_timestamp_seconds", "gauge", "When the exit's relay catalogue was fetched, as Unix time.")
			m.sample("molebridge_exit_catalog_fetched_timestamp_seconds", float64(at.Unix()), "exit", sn.exit)
		}
	}
	for _, sn := range snapshots {
		m.family("molebridge_exit_catalog_relays", "gauge", "The relays in the exit's catalogue that passed validation.")
		m.sample("molebridge_exit_catalog_relays", float64(sn.relays), "exit", sn.exit)
	}
	s.routingMetrics(m, exits, statuses)
	return []byte(m.b.String())
}

// handshakeAge is the record's checks.handshake.age_s, where the verdict
// says the handshake was measured (pass or fail).
func handshakeAge(st ExitStatus) (float64, bool) {
	if state := st.Verdict.Checks.Get("handshake"); state != "pass" && state != "fail" {
		return 0, false
	}
	checks, _ := st.Result["checks"].(map[string]any)
	handshake, _ := checks["handshake"].(map[string]any)
	age, ok := validate.IsNumber(handshake["age_s"])
	if !ok || age < 0 || math.IsInf(age, 0) || math.IsNaN(age) {
		return 0, false
	}
	return age, true
}

// routingCounters are routing_activity's counters, as metric names.
var routingCounters = [][3]string{
	{"repairs", "molebridge_exit_routing_repairs_total", "Repair passes that changed the kernel since the exit's worker started."},
	{"events", "molebridge_exit_routing_kernel_events_total", "Kernel notifications the exit's watcher received since its worker started."},
	{"relevant_events", "molebridge_exit_routing_relevant_events_total", "Kernel notifications that asked for a repair pass."},
	{"events_lost", "molebridge_exit_routing_events_lost_total", "Receive-buffer overruns, each followed by a full pass."},
	{"periodic_passes", "molebridge_exit_routing_periodic_passes_total", "Full passes on ROUTING_RECONCILE_INTERVAL."},
}

// routingMetrics are the record's routing_activity, for an exit whose
// record has one that reads as the exit writes it (molebridge status's
// rule). The counters restart from zero when the worker does.
func (s *Server) routingMetrics(m *metricsWriter, exits []Exit, statuses map[string]ExitStatus) {
	type activity struct {
		exit   string
		counts []int64
		last   *float64
	}
	var all []activity
	for _, e := range exits {
		raw, ok := statuses[e.ID].Result["routing_activity"].(map[string]any)
		if !ok {
			continue
		}
		a := activity{exit: e.ID}
		for _, c := range routingCounters {
			n, ok := validate.IsInt(raw[c[0]])
			if !ok || n < 0 {
				a.counts = nil
				break
			}
			a.counts = append(a.counts, n)
		}
		if a.counts == nil {
			continue
		}
		if at, present := raw["last_repair_at"]; present && at != nil {
			parsed, valid := validate.ParseTime(at)
			if !valid {
				continue
			}
			unix := float64(parsed.Unix())
			a.last = &unix
		}
		all = append(all, a)
	}
	for i, c := range routingCounters {
		for _, a := range all {
			m.family(c[1], "counter", c[2])
			m.sample(c[1], float64(a.counts[i]), "exit", a.exit)
		}
	}
	for _, a := range all {
		if a.last != nil {
			m.family("molebridge_exit_routing_last_repair_timestamp_seconds", "gauge", "When the last repair pass that changed the kernel ran, as Unix time.")
			m.sample("molebridge_exit_routing_last_repair_timestamp_seconds", *a.last, "exit", a.exit)
		}
	}
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request, session *oidc.Session) {
	s.send(w, r, reply{code: 200, contentType: metricsContentType, body: s.metrics(session),
		headers: [][2]string{{"Cache-Control", "no-store"}}})
}
