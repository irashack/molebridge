package applier

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
)

// The (provider, server) target (docs/design/multi-provider.md, step 3).

func (m *multiExit) attemptFile(t testing.TB) map[string]any {
	t.Helper()
	data, ok := jsonfile.ReadObject(filepath.Join(m.dir, "applier", "attempt.json"), 1<<16)
	if !ok {
		t.Fatal("attempt.json")
	}
	return data
}

func TestAChangeOfProviderBetweenEveryPair(t *testing.T) {
	for _, from := range allThree {
		for _, to := range allThree {
			if from == to || from == "pia" {
				// Leaving PIA is the design's step 4.
				continue
			}
			t.Run(from+"_to_"+to, func(t *testing.T) {
				m := newMulti(t, "", from, allThree, nil)
				r := m.a.switchTo(t, targetOf(to))
				if status(r) != "ok" {
					t.Fatalf("%s: %s", status(r), message(r))
				}
				if m.a.Providers().Active() != to || m.a.spec.ID != to {
					t.Fatalf("active %s", m.a.Providers().Active())
				}
				if strings.Join(m.tunnels.replaced, ",") != to {
					t.Fatalf("replaced %v", m.tunnels.replaced)
				}
				// The provider is persisted before the tunnel is replaced.
				if m.tunnels.active[0] != to {
					t.Fatalf("replaced while %s was active", m.tunnels.active[0])
				}
				raw, _ := os.ReadFile(filepath.Join(m.dir, "applier", "tunnel-provider.json"))
				if string(raw) != `{"provider": "`+to+`"}` {
					t.Fatalf("tunnel-provider.json %s", raw)
				}
				at := m.attemptFile(t)
				if at["provider"] != to || at["outcome"] != "verified" {
					t.Fatalf("attempt %v", at)
				}
				if !m.k.logged("changing the tunnel's provider from " + specLabel(from) + " to " + specLabel(to)) {
					t.Fatalf("%v", m.k.logs)
				}
				// Settled: the next pass changes nothing.
				r = mustTick(t, m.a)
				if status(r) != "ok" || len(m.tunnels.replaced) != 1 {
					t.Fatalf("%s %v", status(r), m.tunnels.replaced)
				}
			})
		}
	}
}

func specLabel(id string) string {
	spec, err := providers.Get(id)
	if err != nil {
		panic(err)
	}
	return spec.Label
}

func TestASwitchOnTheActiveProviderIsTodays(t *testing.T) {
	m := newMulti(t, "", "mullvad", allThree, nil)
	addRelay(m.a, otherHost, otherKey)
	r := m.a.switchTo(t, requestAt(otherHost, map[string]any{"provider": "mullvad"}))
	if status(r) != "ok" || len(m.tunnels.replaced) != 0 {
		t.Fatalf("%s %v", status(r), m.tunnels.replaced)
	}
	if m.attemptFile(t)["provider"] != "mullvad" {
		t.Fatal("the attempt names no provider")
	}
	// A request that names no provider is the active provider's.
	r = m.a.switchTo(t, requestAt(testHost, map[string]any{"request_id": strings.Repeat("3", 32)}))
	if status(r) != "ok" || len(m.tunnels.replaced) != 0 || m.a.Providers().Active() != "mullvad" {
		t.Fatalf("%s %v", status(r), m.tunnels.replaced)
	}
	// ...and one whose server isn't the active provider's is invalid.
	desire(t, m.a, requestAt(nordUS, map[string]any{"request_id": strings.Repeat("4", 32)}))
	r = mustTick(t, m.a)
	if len(m.tunnels.replaced) != 0 || !strings.Contains(message(r), "nvalid") {
		t.Fatalf("%s %v", message(r), m.tunnels.replaced)
	}
}

func TestAFailedChangeStaysOnTheTarget(t *testing.T) {
	m := newMulti(t, "", "mullvad", allThree, nil)
	m.tunnels.fail = errInjected
	desire(t, m.a, targetOf("nordvpn"))
	r := mustTick(t, m.a)
	if status(r) == "ok" {
		t.Fatal("ok after a failed change")
	}
	at := m.attemptFile(t)
	if at["provider"] != "nordvpn" || at["state"] != "failed" {
		t.Fatalf("attempt %v", at)
	}
	// The exit stays on the target provider, fail-closed: it never goes
	// back to Mullvad by itself.
	if m.a.Providers().Active() != "nordvpn" {
		t.Fatalf("active %s", m.a.Providers().Active())
	}
	// The exit's recovery brings the tunnel up as NordVPN's, the active
	// provider's; the retry is then a switch on NordVPN.
	m.tunnels.fail = nil
	tunnelAs(m.k, "nordvpn")
	for range 20 {
		m.k.now += 60
		if r = mustTick(t, m.a); status(r) == "ok" {
			break
		}
	}
	if status(r) != "ok" || m.a.Providers().Active() != "nordvpn" || len(m.tunnels.replaced) != 1 {
		t.Fatalf("%s: %s, active %s, replaced %v", status(r), message(r), m.a.Providers().Active(), m.tunnels.replaced)
	}
	if at := m.attemptFile(t); at["provider"] != "nordvpn" || at["outcome"] != "verified" {
		t.Fatalf("attempt %v", at)
	}
}

func TestARefusedRegistrationLeavesThePreviousTunnel(t *testing.T) {
	m := newMulti(t, "", "mullvad", allThree, nil)
	m.pia.addkeyBad = true
	desire(t, m.a, targetOf("pia"))
	r := mustTick(t, m.a)
	if status(r) == "ok" || len(m.tunnels.replaced) != 0 {
		t.Fatalf("%s %v", status(r), m.tunnels.replaced)
	}
	if m.a.Providers().Active() != "mullvad" || m.attemptFile(t)["provider"] != "pia" {
		t.Fatalf("active %s, attempt %v", m.a.Providers().Active(), m.attemptFile(t))
	}
	if len(m.k.keys) != 1 || m.k.keys[0] != testKey {
		t.Fatalf("Mullvad's peer changed: %v", m.k.keys)
	}
	// Retried on the backoff, to PIA.
	m.pia.addkeyBad = false
	for range 20 {
		m.k.now += 60
		mustTick(t, m.a)
		if len(m.tunnels.replaced) > 0 {
			break
		}
	}
	if strings.Join(m.tunnels.replaced, ",") != "pia" || m.a.Providers().Active() != "pia" {
		t.Fatalf("replaced %v, active %s", m.tunnels.replaced, m.a.Providers().Active())
	}
}

func TestARefusedPIALoginIsRejectedForPIAsCredentials(t *testing.T) {
	m := newMulti(t, "", "nordvpn", allThree, nil)
	m.pia.status = 401
	desire(t, m.a, targetOf("pia"))
	r := mustTick(t, m.a)
	if !strings.Contains(message(r), specLabel("pia")+" refused the login") || len(m.tunnels.replaced) != 0 {
		t.Fatalf("%s %v", message(r), m.tunnels.replaced)
	}
	rejected, _ := m.attemptFile(t)["rejected"].(map[string]any)
	if rejected == nil || !strings.HasPrefix(rejected["key"].(string), "pia/") ||
		!strings.HasPrefix(rejected["release"].(string), "pia:") {
		t.Fatalf("rejected %v", rejected)
	}
	// NordVPN's catalogue changing doesn't release it.
	mustTick(t, m.a)
	if m.k.tokenRequests() != 1 {
		t.Fatalf("retried: %d logins", m.k.tokenRequests())
	}
}

func TestTheGateReadsTheTargetProvidersCatalogue(t *testing.T) {
	m := newMulti(t, "", "mullvad", allThree, nil)
	// A server NordVPN's catalogue doesn't list.
	r := m.a.switchTo(t, requestAt("us9999.nordvpn.com", map[string]any{"provider": "nordvpn"}))
	if message(r) != Unlisted || len(m.tunnels.replaced) != 0 || m.a.Providers().Active() != "mullvad" {
		t.Fatalf("%s %v", message(r), m.tunnels.replaced)
	}
	rejected, _ := m.attemptFile(t)["rejected"].(map[string]any)
	if rejected == nil || !strings.HasPrefix(rejected["key"].(string), "nordvpn/") ||
		!strings.HasPrefix(rejected["release"].(string), "nordvpn:") {
		t.Fatalf("rejected %v", rejected)
	}
	// Read for the pass; only the target provider's stays.
	for id := range m.a.set.loaded {
		if id != "nordvpn" {
			t.Fatalf("resident %v", m.a.set.loaded)
		}
	}
	// An unusable target catalogue holds the request pending. (The file
	// changes behind the applier's back: the copy it kept is dropped.)
	m.a.set.release("")
	writeFile(t, filepath.Join(m.dir, "applier", "relays-nordvpn.json"), "{}", 0o644)
	r = m.a.switchTo(t, targetOf("nordvpn"))
	if !strings.Contains(message(r), "fresh trusted relay catalogue") || len(m.tunnels.replaced) != 0 {
		t.Fatalf("%s %v", message(r), m.tunnels.replaced)
	}
}

func TestTheGateWaitsForTheTargetProvidersCredentials(t *testing.T) {
	m := newMulti(t, "", "mullvad", allThree, nil)
	if err := os.Remove(filepath.Join(m.dir, "secrets", "username")); err != nil {
		t.Fatal(err)
	}
	desire(t, m.a, targetOf("pia"))
	r := mustTick(t, m.a)
	if message(r) != "Waiting for "+specLabel("pia")+"'s credentials; request will retry automatically." {
		t.Fatalf("%s", message(r))
	}
	if len(m.tunnels.replaced) != 0 || m.k.tokenRequests() != 0 || m.a.Providers().Active() != "mullvad" {
		t.Fatal("changed without credentials")
	}
	writeFile(t, filepath.Join(m.dir, "secrets", "username"), piaUsername+"\n", 0o600)
	m.k.now += 60
	r = mustTick(t, m.a)
	if m.a.Providers().Active() != "pia" {
		t.Fatalf("%s: %s", status(r), message(r))
	}
}

func TestAnInterruptedChangeIsResumed(t *testing.T) {
	// Interrupted before the provider changed (the registration).
	m := newMulti(t, "", "mullvad", allThree, nil)
	m.k.hooks = append(m.k.hooks, func(req netx.Request) error {
		if strings.Contains(req.URL, "/addKey?") {
			return context.Canceled
		}
		return nil
	})
	desire(t, m.a, targetOf("pia"))
	if _, err := m.a.Tick(context.Background()); err == nil {
		t.Fatal("not interrupted")
	}
	if at := m.attemptFile(t); at["provider"] != "pia" || at["state"] != "attempting" {
		t.Fatalf("attempt %v", at)
	}
	again := newMulti(t, m.dir, "mullvad", allThree, nil)
	if again.a.Providers().Active() != "mullvad" || again.a.attempt.Provider != "pia" {
		t.Fatalf("restarted on %s, attempt %q", again.a.Providers().Active(), again.a.attempt.Provider)
	}
	for range 10 {
		mustTick(t, again.a)
		again.k.now += 60
	}
	if again.a.Providers().Active() != "pia" || m.attemptFile(t)["outcome"] != "verified" {
		t.Fatalf("active %s, attempt %v", again.a.Providers().Active(), m.attemptFile(t))
	}

	// Interrupted after it: the exit's recovery brought up NordVPN's config.
	m = newMulti(t, "", "mullvad", allThree, nil)
	m.tunnels.fail = context.Canceled
	desire(t, m.a, targetOf("nordvpn"))
	if _, err := m.a.Tick(context.Background()); err == nil {
		t.Fatal("not interrupted")
	}
	again = newMulti(t, m.dir, "nordvpn", allThree, nil)
	if again.a.Providers().Active() != "nordvpn" {
		t.Fatalf("restarted on %s", again.a.Providers().Active())
	}
	for range 10 {
		mustTick(t, again.a)
		again.k.now += 60
	}
	if r := again.a.inspect(t); status(r) != "ok" || m.attemptFile(t)["outcome"] != "verified" {
		t.Fatalf("%s %s, attempt %v", status(r), message(r), m.attemptFile(t))
	}
}

func TestServerNamesItsProviderOnAMultiProviderExit(t *testing.T) {
	m := newMulti(t, "", "mullvad", allThree, func(c *Config) { c.Server = "nordvpn/" + nordUS })
	r := mustTick(t, m.a)
	if m.a.Providers().Active() != "nordvpn" || status(r) != "ok" {
		t.Fatalf("%s: %s, active %s", status(r), message(r), m.a.Providers().Active())
	}
	if at := m.attemptFile(t); at["provider"] != "nordvpn" || at["source"] != "configured" {
		t.Fatalf("attempt %v", at)
	}
	for _, bad := range []string{nordUS, "protonvpn/" + nordUS, "nordvpn/" + testHost, "nordvpn/"} {
		m := newMulti(t, "", "mullvad", allThree, func(c *Config) { c.Server = bad })
		r := mustTick(t, m.a)
		if !strings.HasPrefix(message(r), "Invalid SERVER") || len(m.tunnels.replaced) != 0 {
			t.Errorf("%s: %s %v", bad, message(r), m.tunnels.replaced)
		}
	}
	// A server the provider's catalogue doesn't list.
	m = newMulti(t, "", "mullvad", allThree, func(c *Config) { c.Server = "nordvpn/us9999.nordvpn.com" })
	if r := mustTick(t, m.a); !strings.HasPrefix(message(r), "Unknown SERVER") {
		t.Fatalf("%s", message(r))
	}
}

func TestLeavingPIAIsRefusedUntilItIsBuilt(t *testing.T) {
	m := newMulti(t, "", "pia", allThree, nil)
	m.a.switchTo(t, targetOf("pia"))
	r := m.a.switchTo(t, targetOf("mullvad"))
	if status(r) == "ok" || len(m.tunnels.replaced) != 0 || m.a.Providers().Active() != "pia" {
		t.Fatalf("%s %v %s", status(r), m.tunnels.replaced, m.a.Providers().Active())
	}
	if at := m.attemptFile(t); at["mutation_certainty"] != "definite" {
		t.Fatalf("attempt %v", at)
	}
}

func TestAMultiProviderExitNeedsItsTunnelConfigs(t *testing.T) {
	k := newKernel(t)
	m, n := NewMullvad(), NewNordVPN()
	if _, err := New(Config{StateDir: t.TempDir(), Exit: k.exit, Provider: m, Providers: []Provider{m, n}, System: k,
		BootID: testBoot}); err == nil {
		t.Fatal("accepted")
	}
}

func TestAnAttemptsProviderOutsideTheSetIsForgotten(t *testing.T) {
	m := newMulti(t, "", "mullvad", []string{"mullvad", "nordvpn"}, nil)
	m.a.switchTo(t, targetOf("nordvpn"))
	raw, _ := os.ReadFile(filepath.Join(m.dir, "applier", "attempt.json"))
	writeFile(t, filepath.Join(m.dir, "applier", "attempt.json"),
		strings.Replace(string(raw), `"provider": "nordvpn"`, `"provider": "pia"`, 1), 0o644)
	again := newMulti(t, m.dir, "nordvpn", []string{"mullvad", "nordvpn"}, nil)
	if again.a.attempt.Provider != "" {
		t.Fatalf("attempt provider %q", again.a.attempt.Provider)
	}
}
