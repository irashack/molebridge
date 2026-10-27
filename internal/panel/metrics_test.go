package panel

// New in 0.10.0: /metrics, from the same verdict as every other consumer.

import (
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/verdict"
)

var (
	metricLine = regexp.MustCompile(`^([a-z_]+)(\{[a-z_]+="[^"\\\n]*"(,[a-z_]+="[^"\\\n]*")*\})? (-?[0-9.e+]+)$`)
	helpLine   = regexp.MustCompile(`^# (HELP|TYPE) ([a-z_]+) (.+)$`)
)

// scrape reads /metrics and checks the text format: every family declared
// once, before its samples, and every sample line well formed. It returns
// the samples, keyed by their name and labels as written.
func scrape(t *testing.T, h *harness, cookie string) map[string]string {
	t.Helper()
	a := h.get("/metrics", cookie, nil)
	if a.Status != 200 || a.Header.Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("status %d, type %q", a.Status, a.Header.Get("Content-Type"))
	}
	if !strings.HasSuffix(a.Body, "\n") {
		t.Fatal("the body does not end with a newline")
	}
	declared := map[string]int{}
	typed := map[string]bool{}
	samples := map[string]string{}
	current := ""
	for _, line := range strings.Split(strings.TrimSuffix(a.Body, "\n"), "\n") {
		if m := helpLine.FindStringSubmatch(line); m != nil {
			declared[m[1]+" "+m[2]]++
			if m[1] == "TYPE" {
				typed[m[2]] = true
				if m[3] != "gauge" && m[3] != "counter" {
					t.Errorf("type %q", line)
				}
			}
			current = m[2]
			continue
		}
		m := metricLine.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("malformed line %q", line)
		}
		if m[1] != current || !typed[m[1]] {
			t.Fatalf("sample %q outside its family", line)
		}
		key := m[1] + m[2]
		if _, dup := samples[key]; dup {
			t.Fatalf("repeated series %q", key)
		}
		samples[key] = m[4]
	}
	for k, n := range declared {
		if n != 1 {
			t.Errorf("%s declared %d times", k, n)
		}
	}
	return samples
}

func TestMetricsFollowTheOneVerdict(t *testing.T) {
	for _, name := range caseNames() {
		c := consumerCases[name]
		t.Run(name, func(t *testing.T) {
			h := setupExit(t, c.provider, c.kind, c.record(), c.request())
			got := scrape(t, h, "")
			want := map[string]string{`molebridge_ready`: "0",
				`molebridge_exit_info{exit="x",provider="` + c.provider + `",kind="` + c.kind + `"}`: "1"}
			if c.state == "ok" {
				want["molebridge_ready"] = "1"
			}
			for _, st := range exitStates {
				value := "0"
				if st == c.state {
					value = "1"
				}
				want[`molebridge_exit_state{exit="x",state="`+st+`"}`] = value
			}
			for k, v := range want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
			// Every check has exactly one state, the one /api/status gives.
			checks := jsonBody(t, h.get("/api/status?exit=x", "", nil))["verdict"].(map[string]any)["checks"].(map[string]any)
			for _, check := range verdict.CheckNames {
				ones := 0
				for _, st := range checkStates {
					key := `molebridge_exit_check{exit="x",check="` + check + `",state="` + st + `"}`
					switch got[key] {
					case "1":
						ones++
						if checks[check] != st {
							t.Errorf("%s: metric %s, /api/status %v", check, st, checks[check])
						}
					case "0":
					default:
						t.Errorf("%s missing", key)
					}
				}
				if ones != 1 {
					t.Errorf("%s has %d states", check, ones)
				}
			}
		})
	}
}

func TestMetricsCarryTheRecordsNumbers(t *testing.T) {
	record := schema2(recOpts{Extra: map[string]any{
		"checked_at": "2026-10-11T11:59:55Z",
		"routing_activity": map[string]any{"repairs": 3, "last_repair_at": "2026-10-11T11:00:00Z", "events": 120,
			"relevant_events": 7, "events_lost": 1, "periodic_passes": 40},
	}})
	h := setupExit(t, "mullvad", "overlay", record, request(serverOf("mullvad")))
	mustWrite(t, h.exit("x").RelaysPath, map[string]any{"fetched_at": "2026-10-11T10:00:00Z", "provider": "mullvad",
		"relays": map[string]any{"se-sto-wg-001": relayEntry("se-sto-wg-001", nil), "se-got-wg-002": relayEntry("se-got-wg-002", nil),
			"bad": relayEntry("bad", map[string]any{"ipv4_addr_in": "10.0.0.1"})}})
	got := scrape(t, h, "")
	for k, v := range map[string]string{
		`molebridge_exit_checked_timestamp_seconds{exit="x"}`:             "1791719995",
		`molebridge_exit_catalog_fetched_timestamp_seconds{exit="x"}`:     "1791712800",
		`molebridge_exit_catalog_relays{exit="x"}`:                        "2",
		`molebridge_exit_routing_repairs_total{exit="x"}`:                 "3",
		`molebridge_exit_routing_kernel_events_total{exit="x"}`:           "120",
		`molebridge_exit_routing_relevant_events_total{exit="x"}`:         "7",
		`molebridge_exit_routing_events_lost_total{exit="x"}`:             "1",
		`molebridge_exit_routing_periodic_passes_total{exit="x"}`:         "40",
		`molebridge_exit_routing_last_repair_timestamp_seconds{exit="x"}`: "1791716400",
	} {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// The record is stale here, so the handshake was not measured as far as
	// the verdict goes: no age.
	if _, present := got[`molebridge_exit_handshake_age_seconds{exit="x"}`]; present {
		t.Error("a handshake age from a stale record")
	}

	// A fresh record gives the handshake age; a malformed routing_activity
	// gives no counters at all.
	fresh := schema2(recOpts{Extra: map[string]any{"routing_activity": map[string]any{"repairs": -1}}})
	mustWrite(t, h.exit("x").ResultPath, fresh)
	got = scrape(t, h, "")
	if got[`molebridge_exit_handshake_age_seconds{exit="x"}`] != "12" {
		t.Errorf("handshake age %q", got[`molebridge_exit_handshake_age_seconds{exit="x"}`])
	}
	for k := range got {
		if strings.HasPrefix(k, "molebridge_exit_routing_") {
			t.Errorf("%s from a malformed routing_activity", k)
		}
	}
}

func TestMetricsWithoutARecord(t *testing.T) {
	h := newSingleHarness(t, nil)
	got := scrape(t, h, "")
	if got["molebridge_ready"] != "0" || got[`molebridge_exit_state{exit="",state="unknown"}`] != "1" {
		t.Fatalf("%v", got)
	}
	for k := range got {
		if strings.HasPrefix(k, "molebridge_exit_checked_") || strings.HasPrefix(k, "molebridge_exit_handshake_") ||
			strings.HasPrefix(k, "molebridge_exit_routing_") {
			t.Errorf("%s without a record", k)
		}
	}
	if a := h.do("HEAD", "/metrics", nil, nil); a.Status != 200 || a.Body != "" {
		t.Errorf("HEAD: %d %q", a.Status, a.Body)
	}
	if a := h.get("/metrics", "", map[string]string{"Host": "other.example.test"}); a.Status != 421 {
		t.Errorf("misdirected: %d", a.Status)
	}
}

// With sign-in on, /metrics shows what /readyz shows: the aggregate to
// anyone, an exit only to a session granted it.
func TestMetricsShowWhatReadyzShows(t *testing.T) {
	p := newAccessPanel(t)
	exitsIn := func(samples map[string]string) string {
		var ids []string
		for k := range samples {
			if m := regexp.MustCompile(`^molebridge_exit_info\{exit="([a-z0-9-]*)"`).FindStringSubmatch(k); m != nil {
				ids = append(ids, m[1])
			}
		}
		sort.Strings(ids)
		return strings.Join(ids, ",")
	}
	anonymous := scrape(t, p.harness, "")
	if len(anonymous) != 1 || anonymous["molebridge_ready"] != "0" {
		t.Fatalf("anonymous: %v", anonymous)
	}
	eq(t, "friend", exitsIn(scrape(t, p.harness, p.friend)), "a")
	eq(t, "admin", exitsIn(scrape(t, p.harness, p.admin)), "a,b,mine")
	for k := range scrape(t, p.harness, p.friend) {
		if strings.Contains(k, `exit="b"`) || strings.Contains(k, `exit="mine"`) {
			t.Errorf("friend sees %s", k)
		}
	}
}
