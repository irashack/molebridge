package exit

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/contract"
)

const goodToken = "0123456789abcdef0123456789abcdef"

func TestLoadExchange(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := map[string]string{"EXCHANGE_URL": "https://exchange.example.net:8097", "EXCHANGE_EXIT_ID": "home", "EXCHANGE_TOKEN": goodToken}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range good {
			m[a] = b
		}
		m[k] = v
		return m
	}
	if x, err := loadExchange(map[string]string{}); x != nil || err != nil {
		t.Fatalf("unset: %v %v", x, err)
	}
	if x, err := loadExchange(good); err != nil || x.ExitID != "home" {
		t.Fatalf("good: %v %v", x, err)
	}
	for name, env := range map[string]map[string]string{
		"scheme":      with("EXCHANGE_URL", "ftp://exchange.example.net"),
		"credentials": with("EXCHANGE_URL", "https://u:p@exchange.example.net"),
		"query":       with("EXCHANGE_URL", "https://exchange.example.net/?t=1"),
		"no host":     with("EXCHANGE_URL", "https:///x"),
		"exit id":     with("EXCHANGE_EXIT_ID", "Home"),
		"no exit id":  with("EXCHANGE_EXIT_ID", ""),
		"short token": with("EXCHANGE_TOKEN", "short"),
		"token space": with("EXCHANGE_TOKEN", strings.Repeat("a", 20)+" "+strings.Repeat("b", 20)),
		"bad CA":      with("EXCHANGE_CA_FILE", ca),
		"missing CA":  with("EXCHANGE_CA_FILE", ca+".missing"),
	} {
		if _, err := loadExchange(env); err == nil {
			t.Errorf("%s: accepted", name)
		} else if _, ok := err.(*Refusal); !ok {
			t.Errorf("%s: %T is not a refusal", name, err)
		}
	}
}

func TestPlainRemoteWarning(t *testing.T) {
	for raw, want := range map[string]bool{
		"http://exchange.example.net:8097": true, "http://192.0.2.10:8097": true,
		"http://127.0.0.1:8097": false, "http://localhost:8097": false, "http://[::1]:8097": false,
		"https://exchange.example.net": false,
	} {
		if got := plainRemote(raw); got != want {
			t.Errorf("plainRemote(%s) = %v", raw, got)
		}
	}
}

func TestExchangeEnvHoldsNoOtherSecret(t *testing.T) {
	s := settingsFor(contract.Overlay, contract.Native, "mullvad")
	s.StateDir = "/state"
	s.Env = map[string]string{"NB_SETUP_KEY": "SETUP", "GATUS_TOKEN": "GATUS", "PIA_PASS": "PIA",
		"EXCHANGE_URL": "https://exchange.example.net", "EXCHANGE_EXIT_ID": "home", "EXCHANGE_TOKEN": goodToken, "TZ": "UTC"}
	env := strings.Join(ExchangeEnv(s), "\n")
	for _, secret := range []string{"SETUP", "GATUS", "PIA"} {
		if strings.Contains(env, secret) {
			t.Fatalf("the exchange child's environment holds %s:\n%s", secret, env)
		}
	}
	for _, want := range []string{"EXCHANGE_TOKEN=" + goodToken, "STATE_DIR=/state", "PROVIDER=mullvad", markEnv + "="} {
		if !strings.Contains(env, want) {
			t.Fatalf("missing %s:\n%s", want, env)
		}
	}
}

// The supervisor starts the exchange child, starts it again when it ends,
// never stops anything else for it, and stops it in the stop sequence.
func TestSupervisorRunsTheExchangeChild(t *testing.T) {
	h := newHarness(t, "good", "ok")
	h.s.Exchange = &ExchangeSettings{URL: "http://127.0.0.1:1", ExitID: "home", Token: goodToken}
	h.s.Env["EXCHANGE_TOKEN"] = goodToken
	h.cfg.ExchangeArgs = []string{"fake-exchange", "wait", h.trace}
	done := h.run()
	if !h.waitTrace("exchange started", 10*time.Second) {
		t.Fatalf("no exchange child\n%s", strings.Join(h.traceLines(), "\n"))
	}
	lines := h.traceLines()
	started := lines[index(lines, "exchange started")]
	for _, secret := range []string{"NB_SETUP_KEY", "GATUS_TOKEN"} {
		if strings.Contains(started, secret) {
			t.Fatalf("the exchange child saw %s: %s", secret, started)
		}
	}
	h.sigs <- syscall.SIGTERM
	if code := h.wait(done, 10*time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !h.waitTrace("exchange terminated", 3*time.Second) {
		t.Fatalf("the exchange child wasn't stopped\n%s", strings.Join(h.traceLines(), "\n"))
	}
}

func TestExchangeChildEndingStopsNothing(t *testing.T) {
	h := newHarness(t, "good", "ok")
	h.s.Exchange = &ExchangeSettings{URL: "http://127.0.0.1:1", ExitID: "home", Token: goodToken}
	h.cfg.ExchangeArgs = []string{"fake-exchange", "exit", h.trace}
	done := h.run()
	// Started, ended with status 3, started again after a second.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && strings.Count(strings.Join(h.traceLines(), "\n"), "exchange started") < 2 {
		time.Sleep(50 * time.Millisecond)
	}
	if n := strings.Count(strings.Join(h.traceLines(), "\n"), "exchange started"); n < 2 {
		t.Fatalf("started %d times\n%s", n, strings.Join(h.traceLines(), "\n"))
	}
	select {
	case code := <-done:
		t.Fatalf("the supervisor stopped (%d) when the exchange child ended", code)
	default:
	}
	if !h.waitTrace("netbird up", 10*time.Second) {
		t.Fatalf("NetBird never came up\n%s", strings.Join(h.traceLines(), "\n"))
	}
	h.sigs <- syscall.SIGTERM
	if code := h.wait(done, 10*time.Second); code != 0 {
		t.Fatalf("exit %d", code)
	}
}
