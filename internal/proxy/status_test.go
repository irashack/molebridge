package proxy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

// waitStatus waits until proxy.json judges as want, and returns its record.
func waitStatus(t *testing.T, r *rig, want string, check func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		record := verdict.ReadProxy(r.status)
		v := verdict.AssessProxy(record, "mullvad", r.clock.now())
		if v.State == want && (check == nil || check(record.(map[string]any))) {
			return record.(map[string]any)
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy.json: %+v, want %s (%v)", v, want, record)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestStatusRecordShape(t *testing.T) {
	r := startRig(t, nil)
	r.up.mu.Lock()
	r.up.servers = []ServerState{
		{Server: "se-got-wg-001", LastOK: r.clock.now()},
		{Server: "de-fra-wg-003", Benched: true, BenchedUntil: r.clock.now().Add(2 * time.Minute), Reason: "handshake timed out"},
		// A bench that has run out is not listed.
		{Server: "de-fra-wg-004", Benched: true, BenchedUntil: r.clock.now().Add(-time.Second), Reason: "old"},
	}
	r.up.mu.Unlock()
	r.srv.kickStatus()
	waitStatus(t, r, "ok", func(m map[string]any) bool {
		servers := m["servers"].(map[string]any)
		return len(servers["benched"].([]any)) == 1
	})
	raw, err := os.ReadFile(r.status)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema": 1, "kind": "proxy", "provider": "mullvad", "guarantee": "opt-in", ` +
		`"status": "ok", "message": "Serving.", "checked_at": "2026-11-19T18:00:00Z", "listen": "127.0.0.1:1080", ` +
		`"tunnel": {"verdict": "ok", "server": "se-got-wg-001", "checked_at": "2026-11-19T17:59:30Z"}, ` +
		`"servers": {"known": 3, "benched": [{"server": "de-fra-wg-003", "until": "2026-11-19T18:02:00Z", "reason": "handshake timed out"}]}, ` +
		`"sessions": 0, "connections": {"open": 0, "total": 0, "failed": 0}}`
	if string(raw) != want {
		t.Fatalf("proxy.json:\n%s\nwant\n%s", raw, want)
	}
	info, _ := os.Stat(r.status)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
}

func TestStatusFollowsTheTunnelAndTheListener(t *testing.T) {
	r := startRig(t, nil)
	waitStatus(t, r, "ok", nil)
	r.tunnel.Store("unknown")
	record := waitStatus(t, r, "refusing", nil)
	if record["message"] != "Refusing new connections: the exit's verdict is unknown." {
		t.Fatal(record["message"])
	}
	r.tunnel.Store("ok")
	waitStatus(t, r, "ok", nil)
	// The listener fails: Serve returns, and the record says so.
	r.lnClosed()
	select {
	case err := <-r.done:
		if err == nil {
			t.Fatal("no error for a failed listener")
		}
		r.done <- nil
	case <-time.After(5 * time.Second):
		t.Fatal("the proxy kept running without its listener")
	}
	record = waitStatus(t, r, "failed", nil)
	if record["message"] != "The listener is down." {
		t.Fatal(record["message"])
	}
}

func TestStatusCountsConnections(t *testing.T) {
	// The counts are written with the regular rewrite (here every check).
	r := startRig(t, func(c *Config) { c.StatusInterval = time.Millisecond })
	c := r.dial(t)
	socksGreet(t, c, "se.one", testPassword)
	c.Write(socksRequest(cmdConnect, atypIPv4, []byte{192, 0, 2, 1}, 80))
	socksReply(t, c)
	bad := r.dial(t)
	socksGreet(t, bad, "se", "wrong")
	waitStatus(t, r, "ok", func(m map[string]any) bool {
		conns := m["connections"].(map[string]any)
		open, _ := validate.IsInt(conns["open"])
		total, _ := validate.IsInt(conns["total"])
		failed, _ := validate.IsInt(conns["failed"])
		sessions, _ := validate.IsInt(m["sessions"])
		return open == 1 && total == 2 && failed == 1 && sessions == 1
	})
}

func TestShortReason(t *testing.T) {
	if got := shortReason("line\none\x00"); got != "line one " {
		t.Fatalf("%q", got)
	}
	if got := shortReason(""); got != "unknown" {
		t.Fatalf("%q", got)
	}
	long := shortReason(strings.Repeat("é", 200))
	if len(long) > maxReasonBytes || !validate.ValidText(long) {
		t.Fatalf("%d bytes", len(long))
	}
}

func TestServeWritesFailedWhenItCannotListen(t *testing.T) {
	// Another listener holds the port.
	r := startRig(t, nil)
	path := filepath.Join(t.TempDir(), "proxy.json")
	err := Serve(t.Context(), Config{Listen: r.addr, Upstream: r.up, Provider: "mullvad", StatusPath: path,
		Tunnel: func() TunnelState { return TunnelState{Verdict: "ok"} }, PasswordFile: writePassword(t, "x", 0o600)})
	if err == nil {
		t.Fatal("listened twice on one port")
	}
	if v := verdict.AssessProxy(verdict.ReadProxy(path), "mullvad", time.Now()); v.State != "failed" {
		t.Fatalf("%+v", v)
	}
}
