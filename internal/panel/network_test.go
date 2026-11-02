package panel

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/validate"
)

func TestNetworkExitIsJudgedOnlyWhileTheExchangeHearsFromIt(t *testing.T) {
	h := newHarness(t, map[string]string{"PANEL_EXITS": "home=mullvad,away=mullvad", "PANEL_NETWORK_EXITS": "away"}, nil)
	for _, id := range []string{"home", "away"} {
		mustWrite(t, h.exit(id).ResultPath, schema2(recOpts{}))
	}
	link := func(contact time.Time, offset any) {
		t.Helper()
		state := validate.Members("schema", 1, "exit", "away", "last_contact_at", validate.FormatTime(contact), "clock_offset_s", offset, "files", validate.Obj{})
		if err := jsonfile.Write(filepath.Join(h.dir, "away", "exchange.json"), state, jsonfile.Options{Public: true}); err != nil {
			t.Fatal(err)
		}
	}
	reasons := func() string {
		t.Helper()
		var payload struct {
			Verdict struct {
				State   string   `json:"state"`
				Reasons []string `json:"reasons"`
			} `json:"verdict"`
		}
		if err := json.Unmarshal([]byte(h.get("/api/status?exit=away", "", nil).Body), &payload); err != nil {
			t.Fatal(err)
		}
		return payload.Verdict.State + " " + strings.Join(payload.Verdict.Reasons, ",")
	}
	now := h.clock.Now()

	if got := reasons(); got != "unknown exit-unreachable" {
		t.Fatalf("no link state: %q", got)
	}
	if h.get("/readyz?exit=away", "", nil).Status != 503 || h.get("/readyz?exit=home", "", nil).Status != 200 {
		t.Fatal("readyz before contact")
	}
	link(now, 0.4)
	if got := reasons(); got != "ok " {
		t.Fatalf("fresh link: %q", got)
	}
	if h.get("/readyz?exit=away", "", nil).Status != 200 {
		t.Fatal("readyz with a fresh link")
	}
	link(now.Add(-20*time.Second), 0.4)
	if got := reasons(); got != "unknown exit-unreachable" {
		t.Fatalf("old link: %q", got)
	}
	link(now, 12.5)
	if got := reasons(); got != "unknown clock-skew" {
		t.Fatalf("skewed link: %q", got)
	}
}

func TestNetworkExitsMustBeConfiguredExits(t *testing.T) {
	_, err := ConfigFromEnv(map[string]string{"STATE_DIR": t.TempDir(), "PANEL_EXITS": "home=mullvad", "PANEL_NETWORK_EXITS": "away"})
	if err == nil || !strings.Contains(err.Error(), "PANEL_NETWORK_EXITS: 'away' is not an exit in PANEL_EXITS") {
		t.Fatalf("err = %v", err)
	}
}
