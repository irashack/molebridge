package panel

// The Node tests (panel/js-tests) check the browser script against what the
// real server serves for every case in the consumer matrix. server.js runs
// this test, which writes the document they read (it replaced
// panel/fixtures/payloads.py of 0.7.0):
//
//	PANEL_PAYLOADS_OUT=/tmp/payloads.json go test ./internal/panel -run TestWritePayloads

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

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
		if networkCases[name] {
			ex.Network, ex.LinkPath = true, filepath.Join(h.dir, name, "exchange.json")
		}
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
	// The proxy view's cases: each testdata/proxy fixture, as /api/status
	// sends it and as the server describes it.
	ph := newHarness(t, nil, func(o *Options) { o.Now = func() time.Time { return proxyNow } })
	proxyCases := validate.Obj{}
	for _, name := range sortedFixtureNames() {
		ex := ExitUnder(name, "mullvad", "Example", filepath.Join(ph.dir, name), "overlay")
		ex.ProxyPath = filepath.Join(ph.dir, name, "proxy", "proxy.json")
		copyFixture(t, name, ex.ProxyPath)
		proxyCases = append(proxyCases, validate.Pair{Key: name,
			Value: validate.Members("payload", ph.srv.proxyPayload(ex), "describe", ph.srv.proxyView(ex))})
	}
	// A multi-provider exit's status line for each case's verdict label, with
	// and without a provider and a server.
	providerLines := []any{}
	for _, name := range caseNames() {
		for _, pv := range [][2]string{{"PIA", "us_chicago"}, {"NordVPN", ""}, {"", "se-sto-wg-001"}} {
			label := consumerCases[name].label
			providerLines = append(providerLines, validate.Members("label", label, "provider", pv[0], "server", pv[1],
				"line", providerLine(label, pv[0], pv[1])))
		}
	}
	var wording any
	if err := json.Unmarshal([]byte(textJSON), &wording); err != nil {
		t.Fatal(err)
	}
	raw, err := validate.MarshalJSON(validate.Members("text", wording, "cases", cases, "proxy_cases", proxyCases,
		"provider_lines", providerLines))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func sortedFixtureNames() []string {
	names := make([]string, 0, len(proxyFixtures))
	for name := range proxyFixtures {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
