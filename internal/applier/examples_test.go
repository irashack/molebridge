package applier

// The example status records in docs/examples: one healthy record for each
// exit kind, built by the applier on its test fakes, judged ok by the verdict
// every reader uses, and rendered in the member order the supervisor writes
// (verdict.OrderRecord), with owner_record in the shape exit.OwnerCheck gives
// it. Timestamps are fixed for the docs: every time is exampleTime, and
// expires_at the default GUARD_GRACE later. After a
// change to the record, regenerate them with
//
//	MOLEBRIDGE_UPDATE_EXAMPLES=1 go test ./internal/applier -run TestExampleRecords
//
// and say in the changelog what changed for readers.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

const (
	exampleTime    = "2026-10-10T18:00:00Z"
	exampleExpires = "2026-10-10T18:00:30Z"
)

var expiresRE = regexp.MustCompile(`"expires_at": "\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z"`)

func exampleScenarios() map[string]func(t *testing.T) (*Applier, *Record) {
	return map[string]func(t *testing.T) (*Applier, *Record){
		"result-overlay-native.json": func(t *testing.T) (*Applier, *Record) {
			a, _, _ := mullvadSetup(t)
			a.ownerCheck = func() validate.Obj {
				now := time.Now()
				return validate.Members("state", "pass", "at", validate.FormatTime(now), "expires_at", validate.FormatTime(now.Add(30*time.Second)))
			}
			return a, a.switchTo(t, requestAt(testHost, nil))
		},
		"result-overlay-gluetun.json": func(t *testing.T) (*Applier, *Record) {
			f := newGluetunFixture(t, glOptions{provider: "mullvad"})
			return f.a, f.a.switchTo(t, glRequest(hostB))
		},
		"result-sidecar-gluetun.json": func(t *testing.T) (*Applier, *Record) {
			f := sidecarFixture(t, "nordvpn")
			desire(t, f.a, glRequest(hostB))
			return f.a, mustTick(t, f.a)
		},
		"result-sidecar-native.json": func(t *testing.T) (*Applier, *Record) {
			a, _, _ := nativeSidecarSetup(t, "pia", true)
			connectNativeSidecar(t, a)
			return a, a.inspect(t)
		},
	}
}

// exampleText is the record as docs/examples has it: indented, with fixed times.
func exampleText(t *testing.T, a *Applier, r *Record) []byte {
	t.Helper()
	raw, err := validate.MarshalJSON(verdict.OrderRecord(a.judged(r).Decoded(), r.Get("kind").(string), r.Get("backend").(string)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		t.Fatal(err)
	}
	text := timestampRE.ReplaceAllString(out.String(), exampleTime)
	return []byte(expiresRE.ReplaceAllString(text, `"expires_at": "`+exampleExpires+`"`) + "\n")
}

func TestExampleRecords(t *testing.T) {
	update := os.Getenv("MOLEBRIDGE_UPDATE_EXAMPLES") == "1"
	for name, scenario := range exampleScenarios() {
		t.Run(name, func(t *testing.T) {
			a, r := scenario(t)
			judged := a.judged(r)
			if v := a.assess(judged.Decoded()); v.State != "ok" {
				t.Fatalf("verdict %s %s %v", v.State, v.Label, v.Reasons)
			}
			got := exampleText(t, a, r)
			path := filepath.Join("..", "..", "docs", "examples", name)
			if update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s is out of date; regenerate it (see examples_test.go):\n%s", path, got)
			}
		})
	}
}
