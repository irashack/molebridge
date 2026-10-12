package panel

// The Node tests (panel/js-tests) check the browser script against what the
// real server serves for every case in the consumer matrix. They used to
// run panel/fixtures/payloads.py; with MOLEBRIDGE_PANEL=go, server.js runs
// this test instead, which writes the same document:
//
//	PANEL_PAYLOADS_OUT=/tmp/payloads.json go test ./internal/panel -run TestWritePayloads

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/irashack/molebridge/internal/validate"
)

func TestWritePayloads(t *testing.T) {
	out := os.Getenv("PANEL_PAYLOADS_OUT")
	if out == "" {
		t.Skip("PANEL_PAYLOADS_OUT is not set")
	}
	h := newHarness(t, nil, nil)
	cases := validate.Obj{}
	for _, name := range caseNames() {
		c := consumerCases[name]
		ex := ExitUnder(name, c.provider, "Example", filepath.Join(h.dir, name), c.kind)
		result, request := c.record(), c.request()
		mustWrite(t, ex.ResultPath, result)
		mustWrite(t, ex.DesiredPath, request)
		status := h.srv.readStatus(ex)
		payload := h.srv.statusPayload(ex, status)
		// describe reads the verdict and result exactly as /api/status sends them.
		var merged map[string]any
		for _, p := range payload {
			if p.Key == "result" && p.Value != nil {
				raw, err := validate.MarshalJSON(p.Value)
				if err != nil {
					t.Fatal(err)
				}
				decoded, err := validate.DecodeJSON(raw)
				if err != nil {
					t.Fatal(err)
				}
				merged, _ = decoded.(map[string]any)
			}
		}
		view := describe(h.srv.exitView(ex, status.Verdict), merged)
		cases = append(cases, validate.Pair{Key: name, Value: validate.Members("payload", payload, "describe", view)})
	}
	var wording any
	if err := json.Unmarshal([]byte(textJSON), &wording); err != nil {
		t.Fatal(err)
	}
	raw, err := validate.MarshalJSON(validate.Members("text", wording, "cases", cases))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}
