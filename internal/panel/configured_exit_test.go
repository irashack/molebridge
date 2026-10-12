package panel

// Ported from panel/test_configured_exit.py: read-only exits through
// rendering and handlers.

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

const configuredServer = "configured.example.test"

func configuredResult(changes map[string]any) map[string]any {
	r := map[string]any{"status": "ok", "checked_at": nowISO(), "configured_server": configuredServer,
		"server": configuredServer, "routing_ok": true, "netbird_native": true, "exit_confirmed": true}
	for k, v := range changes {
		r[k] = v
	}
	return r
}

func desire() map[string]any {
	return map[string]any{"server": "se-sto-wg-001", "request_id": strings.Repeat("0", 32), "requested_at": nowISO()}
}

func TestConfigurationPageHasNoSwitchFormOrControls(t *testing.T) {
	for _, provider := range providers.IDs() {
		for _, embed := range []bool{false, true} {
			for _, st := range []string{"ok", "failed", "unknown", "applying"} {
				h := newHarness(t, nil, nil)
				ex := ExitUnder("", provider, "Example", t.TempDir(), "overlay")
				snapshot := map[string]any{"provider": provider, "fetched_at": nowISO(), "relays": map[string]any{
					configuredServer: map[string]any{"hostname": configuredServer, "country": "Example", "city": "Example City",
						"location_code": "ex-one", "ipv4_addr_in": "198.51.100.10"}}}
				result := configuredResult(map[string]any{"status": st, "message": "Example failure."})
				page := h.srv.renderIndex(IndexPage{Exit: ex, Status: h.srv.judge(ex, desire(), result), CSRFToken: "token", Embed: embed,
					RelaysData: snapshot, Relays: providers.SnapshotRelays(snapshot, provider)})
				mustContain(t, page, "Set in configuration:", configuredServer, "Diagnostics", "data-state-pill", `data-request=""`)
				mustNotContain(t, page, `action="/select"`, `id="select-form"`, `name="server"`, "data-retry", `id="fastest"`,
					`id="saved"`, "data-pin", "locations-widget")
			}
		}
	}
}

func payloadMap(t *testing.T, o validate.Obj) map[string]any {
	t.Helper()
	raw, err := validate.MarshalJSON(o)
	if err != nil {
		t.Fatal(err)
	}
	return jsonBody(t, answer{Body: string(raw)})
}

func TestConfigurationStatusIgnoresPanelAndKeepsStaleLock(t *testing.T) {
	for _, checked := range []string{nowISO(), "2000-01-01T00:00:00Z"} {
		h := newHarness(t, nil, nil)
		ex := h.srv.Single
		mustWrite(t, ex.DesiredPath, desire())
		mustWrite(t, ex.ResultPath, configuredResult(map[string]any{"checked_at": checked}))
		payload := payloadMap(t, h.srv.statusPayload(ex, h.srv.readStatus(ex)))
		view := payload["view"].(map[string]any)
		wantState := "ok"
		if checked == "2000-01-01T00:00:00Z" {
			wantState = "unknown"
		}
		if payload["desired"] != nil || view["selection_mode"] != "configuration" || view["configured_server"] != configuredServer || view["state"] != wantState {
			t.Fatalf("checked %s: %v", checked, payload)
		}
		// The request file is not even read: the exit has none to show.
		page := h.render(desire(), configuredResult(map[string]any{"checked_at": checked}), nil, nil)
		mustContain(t, page, "Set in configuration:")
		mustNotContain(t, page, `action="/select"`)
	}
}

func TestPostRefusedWithoutWritingForConfiguredExit(t *testing.T) {
	for _, checked := range []string{nowISO(), "2000-01-01T00:00:00Z"} {
		h := newHarness(t, map[string]string{"PANEL_EXITS": "example=mullvad:Example"}, nil)
		ex := h.exit("example")
		mustWrite(t, ex.DesiredPath, desire())
		before := readDesired(ex)
		mustWrite(t, ex.ResultPath, configuredResult(map[string]any{"checked_at": checked}))
		mustWrite(t, ex.RelaysPath, catalogue(relayEntry("se-sto-wg-001", nil)))
		nonce := newCSRFNonce()
		a := h.post("/select", [][2]string{{"server", "se-sto-wg-001"}, {"csrf_token", h.srv.csrfToken(nonce, "")}, {"exit", "example"}}, "csrf_nonce="+nonce, "")
		if a.Status != 403 || a.Body != "Exit is set in configuration; change SERVER to choose another server." {
			t.Fatalf("%d %q", a.Status, a.Body)
		}
		if got := readDesired(ex); got["request_id"] != before["request_id"] || got["server"] != before["server"] {
			t.Fatal("the request file changed")
		}
	}
}

func TestAPIStatusExposesConfiguration(t *testing.T) {
	h := newHarness(t, map[string]string{"PANEL_EXITS": "example=mullvad:Example"}, nil)
	ex := h.exit("example")
	mustWrite(t, ex.DesiredPath, desire())
	mustWrite(t, ex.ResultPath, configuredResult(nil))
	payload := jsonBody(t, h.get("/api/status?exit=example", "", nil))
	view := payload["view"].(map[string]any)
	if payload["desired"] != nil || view["configured_server"] != configuredServer || view["selection_mode"] != "configuration" || view["state"] != "ok" {
		t.Fatalf("payload = %v", payload)
	}
}

func TestWithoutSettingSelectionAndStatusKeepOldBehavior(t *testing.T) {
	for _, configured := range []any{nil, ""} {
		h := newHarness(t, nil, nil)
		ex := h.srv.Single
		mustWrite(t, ex.ResultPath, configuredResult(map[string]any{"configured_server": configured}))
		mustWrite(t, ex.RelaysPath, catalogue(relayEntry("se-sto-wg-001", nil)))
		nonce := newCSRFNonce()
		a := h.post("/select", [][2]string{{"server", "se-sto-wg-001"}, {"csrf_token", h.srv.csrfToken(nonce, "")}}, "csrf_nonce="+nonce, "")
		if a.Status != 303 || readDesired(ex)["server"] != "se-sto-wg-001" {
			t.Fatalf("%d %v", a.Status, readDesired(ex))
		}
		payload := payloadMap(t, h.srv.statusPayload(ex, h.srv.readStatus(ex)))
		view := payload["view"].(map[string]any)
		if view["selection_mode"] != "panel" || payload["desired"].(map[string]any)["server"] != "se-sto-wg-001" || view["state"] != "applying" {
			t.Fatalf("payload = %v", payload)
		}
	}
}

func TestInvalidConfiguredTextEscapedAndNotReportedConnected(t *testing.T) {
	h := newSingleHarness(t, nil)
	configured := "<script>bad</script>\"\n"
	res := configuredResult(map[string]any{"configured_server": configured, "status": "failed"})
	page := h.render(desire(), res, nil, nil)
	mustNotContain(t, page, "<script>bad</script>", `action="/select"`)
	mustContain(t, page, pyEscape(strings.ReplaceAll(configured, "\n", `\x0a`)))
	st, label := verdict.StatusView(desire(), res, "mullvad", "overlay", time.Now())
	if st != "failed" || label != "failed" {
		t.Fatalf("status view %s/%s", st, label)
	}
}

func TestConfiguredStatusCannotMarkADifferentServerConnected(t *testing.T) {
	st, label := verdict.StatusView(desire(), configuredResult(map[string]any{"server": "other.example.test"}), "mullvad", "overlay", time.Now())
	if st != "failed" || label != "verification failed" {
		t.Fatalf("status view %s/%s", st, label)
	}
}

func TestConfigurationLockIsPerExit(t *testing.T) {
	h := newHarness(t, map[string]string{"PANEL_EXITS": "configured=mullvad:Configured,writable=mullvad:Writable"}, nil)
	configured, writable := h.exit("configured"), h.exit("writable")
	mustWrite(t, configured.ResultPath, configuredResult(nil))
	mustWrite(t, writable.ResultPath, configuredResult(map[string]any{"configured_server": nil}))
	mustWrite(t, configured.RelaysPath, catalogue(relayEntry("se-sto-wg-001", nil)))
	mustWrite(t, writable.RelaysPath, catalogue(relayEntry("se-sto-wg-001", nil)))
	nonce := newCSRFNonce()
	token := h.srv.csrfToken(nonce, "")
	post := func(exit string) answer {
		return h.post("/select", [][2]string{{"server", "se-sto-wg-001"}, {"csrf_token", token}, {"exit", exit}}, "csrf_nonce="+nonce, "")
	}
	if a := post("configured"); a.Status != 403 || readDesired(configured) != nil {
		t.Fatalf("configured exit: %d", a.Status)
	}
	if a := post("writable"); a.Status != 303 || readDesired(writable)["server"] != "se-sto-wg-001" || readDesired(configured) != nil {
		t.Fatalf("writable exit: %d", a.Status)
	}
}

func TestMalformedConfiguredServerKeepsTheLockAndRenders(t *testing.T) {
	for name, bad := range map[string]string{"lone surrogate": "\xed\xa0\x80", "NUL": "bad\x00name", "long": strings.Repeat("x", 5000)} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, nil, nil)
			ex := ExitUnder("", "mullvad", "Example", t.TempDir(), "overlay")
			result := configuredResult(map[string]any{"configured_server": bad})
			page := h.srv.renderIndex(IndexPage{Exit: ex, Status: h.srv.judge(ex, desire(), result), CSRFToken: "token"})
			if !utf8.ValidString(page) {
				t.Fatal("the page is not valid UTF-8")
			}
			mustContain(t, page, "Set in configuration:")
			mustNotContain(t, page, `id="select-form"`)
		})
	}
}

var _ = state.NowISO
