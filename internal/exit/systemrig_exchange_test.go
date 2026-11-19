//go:build drill && systemrig && linux

package exit

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/exchange"
	"github.com/irashack/molebridge/internal/nstest"
)

// The network exchange's rig: the panel and the exchange in "panelnode", on a
// link of their own to "internet"; the exit reaches the exchange by its host
// path, over HTTPS with the rig's authority, and shares no directory with
// the panel.
const (
	rigExchange4    = "198.51.100.17"
	rigExchangeGW4  = "198.51.100.18"
	rigExchangePort = "8097"
	rigExchangeName = "exchange.example.net"
	rigExitID       = "home"
)

// exchangeProc is the `molebridge exchange` role, run as uid 65534 with no
// capabilities in "panelnode".
type exchangeProc struct {
	cmd  *exec.Cmd
	out  *syncBuf
	done chan struct{}
}

// newExchangeRig is newSystemRig with the panel's side on its own node and
// the exit configured for the exchange. Nothing runs yet.
func newExchangeRig(t *testing.T) *systemRig {
	t.Helper()
	r := newSystemRig(t)
	pn := nstest.New(t, "panelnode")
	rigSysctls(pn)
	pn.Veth("eth0", r.internet, "panel0")
	addrUp(pn, "eth0", rigExchange4+"/30")
	addrUp(r.internet, "panel0", rigExchangeGW4+"/30")
	pn.IP("route", "add", "default", "via", rigExchangeGW4)
	r.panelNS = pn

	// The panel's state directory, on the panel's node: the exchange writes
	// <id>/applier/ and <id>/exchange.json, the panel <id>/panel/.
	panelState := r.path("panelstate")
	exitDir := filepath.Join(panelState, rigExitID)
	tokens := r.path("exchange-tokens")
	for _, d := range []string{panelState, exitDir, filepath.Join(exitDir, "applier"), filepath.Join(exitDir, "panel"), tokens} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if d != panelState {
			if err := os.Chown(d, rigPanelUID, rigPanelUID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Chmod(tokens, 0o700); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	tokenPath := filepath.Join(tokens, rigExitID)
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{tokenPath, r.keyPath} {
		if err := os.Chown(f, rigPanelUID, rigPanelUID); err != nil {
			t.Fatal(err)
		}
	}
	// The exit's own request file: the exchange's client writes it.
	if err := os.MkdirAll(filepath.Join(r.stateDir, "panel"), 0o755); err != nil {
		t.Fatal(err)
	}

	r.panelOwn, r.panelApplier = filepath.Join(exitDir, "panel"), filepath.Join(exitDir, "applier")
	r.desiredPath = filepath.Join(exitDir, "panel", "desired.json")
	r.panelQS = "?exit=" + rigExitID
	r.panelEnv = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "STATE_DIR=" + panelState, "PANEL_EXITS=" + rigExitID + "=mullvad",
		"PANEL_NETWORK_EXITS=" + rigExitID, "TZ=UTC"}
	r.exitExtra = []string{"EXCHANGE_URL=https://" + rigExchange4 + ":" + rigExchangePort, "EXCHANGE_EXIT_ID=" + rigExitID,
		"EXCHANGE_TOKEN=" + token, "EXCHANGE_CA_FILE=" + r.caPath, "EXCHANGE_TLS_NAME=" + rigExchangeName}
	return r
}

func (r *systemRig) panelState() string { return filepath.Dir(r.panelOwn) }

// startExchange runs the exchange role in "panelnode" and waits until it
// answers over TLS.
func (r *systemRig) startExchange() *exchangeProc {
	t := r.t
	x := &exchangeProc{out: &syncBuf{}, done: make(chan struct{})}
	x.cmd = exec.Command("ip", "netns", "exec", r.panelNS.Name, "setpriv", "--reuid="+strconv.Itoa(rigPanelUID), "--regid="+strconv.Itoa(rigPanelUID),
		"--clear-groups", "--inh-caps=-all", "--bounding-set=-all", "--no-new-privs", r.bin, "exchange")
	x.cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "STATE_DIR=" + r.panelState(), "PANEL_EXITS=" + rigExitID + "=mullvad",
		"EXCHANGE_LISTEN=" + rigExchange4 + ":" + rigExchangePort, "EXCHANGE_TOKENS_DIR=" + r.path("exchange-tokens"),
		"EXCHANGE_CERT_FILE=" + r.certPath, "EXCHANGE_KEY_FILE=" + r.keyPath, "TZ=UTC"}
	x.cmd.Stdout, x.cmd.Stderr = x.out, x.out
	if err := x.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = x.cmd.Wait(); close(x.done) }()
	t.Cleanup(func() {
		x.stop()
		if t.Failed() {
			t.Logf("exchange output:\n%s", x.out.String())
		}
	})
	client := nsClient(r.panelNS, r.roots, rigExchangeName, 3*time.Second)
	r.waitFor(20*time.Second, "the exchange to answer over TLS", func() bool {
		select {
		case <-x.done:
			t.Fatalf("the exchange stopped:\n%s", x.out.String())
		default:
		}
		resp, err := client.Get("https://" + rigExchange4 + ":" + rigExchangePort + "/v1/exits/" + rigExitID)
		if err != nil {
			return false
		}
		resp.Body.Close()
		// No token: refused, as an unknown exit would be.
		return resp.StatusCode == 401
	})
	if s := x.out.String(); strings.Contains(s, "warning") || strings.Contains(s, "refusing") {
		t.Fatalf("the exchange's start:\n%s", s)
	}
	return x
}

// stop ends the exchange with SIGTERM, as a container stop would.
func (x *exchangeProc) stop() {
	select {
	case <-x.done:
		return
	default:
	}
	_ = x.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-x.done:
	case <-time.After(10 * time.Second):
		_ = x.cmd.Process.Kill()
		<-x.done
	}
}

// link reads the exchange's link state for the exit, exchange.json.
func (r *systemRig) link() map[string]any {
	raw, err := os.ReadFile(filepath.Join(r.panelState(), rigExitID, exchange.LinkFile))
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// bringUpExchange starts the exchange, then the exit, its overlay and the
// panel, and waits for the exit verified on relay A on both sides.
func (r *systemRig) bringUpExchange() (*exitProc, *exchangeProc) {
	x := r.startExchange()
	p := r.bringUp()
	a := r.relays[0]
	r.waitFor(30*time.Second, "the panel to show "+a.host+" ok through the exchange", func() bool {
		res := r.panelResult()
		return r.panelStatus()["state"] == "ok" && res["server"] == a.host
	})
	return p, x
}

// TestSystemRigExchange is the network exchange's live record
// (docs/testing.md) on the system rig: an exit and a panel that share no
// directory, the exit's files carried by the real exchange role over HTTPS.
func TestSystemRigExchange(t *testing.T) {
	t.Parallel()
	t.Run("SwitchAndRestart", func(t *testing.T) {
		t.Parallel()
		r := newExchangeRig(t)
		a, b := r.relays[0], r.relays[1]
		p, x := r.bringUpExchange()

		// The link: fresh contact, the clocks agree.
		l := r.link()
		contact, err := time.Parse(time.RFC3339Nano, toString(l["last_contact_at"]))
		age := time.Since(contact)
		offset, isNumber := l["clock_offset_s"].(float64)
		if err != nil || age > 5*time.Second || age < -time.Second || l["exit"] != rigExitID || l["schema"] != float64(exchange.Schema) {
			t.Errorf("exchange.json: %s (contact %v old)", jsonText(l), age)
		}
		if !isNumber || math.Abs(offset) > 1 {
			t.Errorf("clock_offset_s: %v, want about 0", l["clock_offset_s"])
		}
		files, _ := l["files"].(map[string]any)
		for _, f := range []string{exchange.FileResult, exchange.FileRelays} {
			if _, ok := files[f].(map[string]any); !ok {
				t.Errorf("exchange.json lists no %s: %s", f, jsonText(files))
			}
		}
		code, body, _ := r.panelGet("/api/exits")
		var listed struct {
			Exits []map[string]any `json:"exits"`
		}
		if code != 200 || json.Unmarshal(body, &listed) != nil || len(listed.Exits) != 1 ||
			listed.Exits[0]["id"] != rigExitID || listed.Exits[0]["state"] != "ok" {
			t.Errorf("/api/exits: %d %s", code, body)
		}
		t.Logf("link: last_contact_at %v old, clock_offset_s %v; /api/exits %s", age.Round(time.Millisecond), l["clock_offset_s"], jsonText(listed.Exits))

		// A switch through the panel, the result back on its side.
		id, at := r.panelSwitch(b.host)
		r.waitVerified(p, b, id, 120*time.Second)
		exitAfter := time.Since(at)
		r.waitPanelVerified(b, id, 30*time.Second)
		panelAfter := time.Since(at)
		r.clientVia(b, 20*time.Second)
		t.Logf("switch %s -> %s through the exchange: the exit verified %v after the panel's answer, the panel showed it at %v",
			a.host, b.host, exitAfter.Round(time.Millisecond), panelAfter.Round(time.Millisecond))

		// The exchange restarted with an empty volume: the copies and the link
		// state go, the panel's own request stays.
		mark := len(p.out.String())
		stopped := time.Now()
		x.stop()
		var unreachable time.Duration
		r.waitFor(30*time.Second, "the panel to show the exit unreachable", func() bool {
			v := r.panelStatus()
			reasons, _ := v["reasons"].([]any)
			if v["state"] == "unknown" && v["label"] == "exit unreachable" && slices.Equal(reasons, []any{"exit-unreachable"}) {
				unreachable = time.Since(stopped)
				return true
			}
			time.Sleep(500 * time.Millisecond)
			return false
		})
		gone := []string{filepath.Join(r.panelState(), rigExitID, exchange.LinkFile)}
		for _, f := range exchange.Files {
			gone = append(gone, filepath.Join(r.panelApplier, f))
		}
		for _, f := range gone {
			if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
		}
		restarted := time.Now()
		r.startExchange()
		r.waitPanelVerified(b, id, 60*time.Second)
		currentAfter := time.Since(restarted)
		for _, f := range []string{exchange.FileResult, exchange.FileRelays} {
			if _, err := os.Stat(filepath.Join(r.panelApplier, f)); err != nil {
				t.Errorf("the copy of %s after the restart: %v", f, err)
			}
		}
		mine, _ := os.ReadFile(filepath.Join(r.stateDir, "applier", exchange.FileRelays))
		copied, _ := os.ReadFile(filepath.Join(r.panelApplier, exchange.FileRelays))
		if len(mine) == 0 || exchange.Hash(mine) != exchange.Hash(copied) {
			t.Errorf("the catalog's copy differs from the exit's after the restart")
		}
		if res := r.result(); res["server"] != b.host || res["request_id"] != id {
			t.Errorf("the exit moved while the exchange restarted: %s", fmtStatus(res))
		}
		r.waitFor(10*time.Second, "the exit to log the exchange working again", func() bool {
			return strings.Contains(p.out.String()[mark:], prefix+"exchange: works again")
		})
		if logged := p.out.String()[mark:]; !strings.Contains(logged, prefix+"exchange: round failed: ") {
			t.Errorf("no failed round logged while the exchange was down:\n%s", logged)
		}

		// And the panel drives the exit again.
		id2, at2 := r.panelSwitch(a.host)
		r.waitVerified(p, a, id2, 120*time.Second)
		r.waitPanelVerified(a, id2, 30*time.Second)
		backAfter := time.Since(at2)
		t.Logf("exchange restarted with an empty volume: exit unreachable %v after the stop; the panel current (ok on %s, request kept) %v after the start; switch back to %s shown verified %v after the request",
			unreachable.Round(time.Millisecond), b.host, currentAfter.Round(time.Millisecond), a.host, backAfter.Round(time.Millisecond))
	})

	t.Run("SecondSwitch409", func(t *testing.T) {
		t.Parallel()
		r := newExchangeRig(t)
		p, _ := r.bringUpExchange()
		drillSecondSwitch(r, p)
	})

	t.Run("FailedSwitchRetry", func(t *testing.T) {
		t.Parallel()
		r := newExchangeRig(t)
		p, _ := r.bringUpExchange()
		drillFailedRetry(r, p)
	})
}
