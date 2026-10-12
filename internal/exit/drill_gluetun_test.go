//go:build drill && linux

package exit

// The gluetun backend's and the sidecar's drills. The lab stands in for
// gluetun's namespace: a tunnel interface (wg0) that gluetun owns, the host
// interface (eth0), and a control server on the loopback. No gluetun runs.

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const dGluetunIf = "wg0"

// gluetunLab prepares the namespace the way gluetun leaves it: its tunnel
// interface with an address, its own default route through the host interface,
// and a control server listening on 127.0.0.1:8000.
func gluetunLab(t *testing.T, control string) *lab {
	t.Helper()
	drillBinaries(t)
	l := newLab(t, false)
	if _, err := l.exit.TryIP("link", "add", dGluetunIf, "type", "wireguard"); err != nil {
		t.Skipf("no WireGuard: %v", err)
	}
	l.exit.IP("addr", "add", "203.0.113.9/32", "dev", dGluetunIf)
	l.exit.IP("link", "set", dGluetunIf, "up")
	if control != "" {
		var ln net.Listener
		if err := l.exit.Do(func() (err error) { ln, err = net.Listen("tcp", control); return }); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
	}
	key := l.path("api_key")
	if err := os.WriteFile(key, []byte("DRILLKEYVALUE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return l
}

func (l *lab) gluetunEnv(kind string, extra ...string) []string {
	env := []string{
		"PATH=" + binDir + ":/usr/sbin:/usr/bin:/bin:/sbin",
		"TUNNEL_BACKEND=gluetun", "EXIT_KIND=" + kind, "PROVIDER=gluetun-mullvad", "EXIT_IF=" + dGluetunIf,
		"STATE_DIR=" + l.stateDir, "MOLEBRIDGE_RUN_DIR=" + l.runDir, "GUARD_GRACE=5", "FWMARK_GRACE=5",
		"GLUETUN_CONTROL_URL=http://127.0.0.1:8000", "GLUETUN_API_KEY_FILE=" + l.path("api_key"),
		"GLUETUN_SERVERS_FILE=" + l.path("servers.json"), "GLUETUN_UPDATER_PERIOD=0", "TZ=UTC",
	}
	if kind == "overlay" {
		env = append(env,
			"OVERLAY_IF="+dOverlay, "OVERLAY_CIDR=192.0.2.0/24", "OVERLAY6_CIDR=2001:db8:1::/64", "NB_INTERFACE_NAME="+dOverlay,
			"NB_DISABLE_USERSPACE_ROUTING=true", "NB_STATE_DIR="+l.nbDir, "NB_FAKE_DIR="+l.fakeDir,
			"NB_LOG_FILE=console,"+l.path("client.log"), "NB_EXTRA_IFACE_BLACKLIST="+dGluetunIf,
			"HOST_IF=eth0", "HOST_TABLE=51822", "CONTROL_MARK=0x1bd00", "NB_FWMARK_BASE=0x1bd00",
			"ROUTING_RECONCILE_INTERVAL=10", "EXIT_TABLE=51821", "NB_FAKE_FWMARK=0x1bd00")
	}
	return append(env, extra...)
}

func TestDrillGluetunStartToReadyAndStop(t *testing.T) {
	skipWithoutWireGuard(t)
	l := gluetunLab(t, "127.0.0.1:8000")
	p := l.startEnv(l.gluetunEnv("overlay"))
	l.waitReady(p)

	// Started only once the whole contract held, host table included.
	var v4 string
	for _, line := range l.trace() {
		if i := strings.Index(line, " rule-4 "); i >= 0 {
			v4 += strings.ReplaceAll(line[i+8:], " [detached]", "") + "\n"
		}
	}
	for _, want := range []string{"1: not from all iif wt0 lookup local", "88: from all fwmark 0x1bd00 iif lo lookup 51822", "89: from all fwmark 0x1bd00 iif lo unreachable",
		"97: from all iif wt0 unreachable", "102:", "103:", "104: from all iif lo unreachable"} {
		if !strings.Contains(v4, want) {
			t.Errorf("at `netbird service run` the IPv4 rules lacked %q:\n%s", want, v4)
		}
	}
	host, _ := l.exit.TryIP("route", "show", "table", "51822")
	if !strings.Contains(host, "default via 198.51.100.2 dev eth0") {
		t.Errorf("the host table: %q", host)
	}

	// NetBird carries the control mark: it is left running past FWMARK_GRACE.
	time.Sleep(9 * time.Second)
	if l.traceHas("terminated") {
		t.Fatalf("NetBird was stopped although it carries the control mark:\n%s", p.out.String())
	}
	if !p.running() {
		t.Fatal("the exit stopped")
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	if code := p.wait(20 * time.Second); code != 0 {
		t.Errorf("a requested stop exited %d\n%s", code, p.out.String())
	}
	// The cleanup removed NetBird's interface and never gluetun's tunnel.
	if l.linkExists(l.exit, dOverlay) {
		t.Error("the overlay interface was left")
	}
	if !l.linkExists(l.exit, dGluetunIf) {
		t.Error("the cleanup removed gluetun's tunnel")
	}
	rules := l.rules("-4")
	for _, want := range []string{"1: not from all iif wt0 lookup local", "97: from all iif wt0 unreachable", "104: from all iif lo unreachable"} {
		if !strings.Contains(rules, want) {
			t.Errorf("after the stop the rules lack %q:\n%s", want, rules)
		}
	}
}

func TestDrillGluetunStopsNetBirdWithoutTheControlMark(t *testing.T) {
	skipWithoutWireGuard(t)
	l := gluetunLab(t, "127.0.0.1:8000")
	p := l.startEnv(l.gluetunEnv("overlay", "NB_FAKE_FWMARK=0x2a00"))
	l.waitReady(p)
	started := time.Now()
	l.waitFor(30*time.Second, "NetBird to be stopped for the missing mark", func() bool { return l.traceHas("terminated") })
	took := time.Since(started)
	t.Logf("NetBird stopped %v after `netbird up` (FWMARK_GRACE=5)", took)
	if took > 5*time.Second+4*time.Second {
		t.Errorf("stopped %v after the launch, grace is 5 s", took)
	}
	if !strings.Contains(p.out.String(), "has not carried the control mark 0x1bd00 for 5 seconds (last reported: 0x2a00)") {
		t.Errorf("the reason is not in the log:\n%s", p.out.String())
	}
	if !p.running() {
		t.Error("the exit itself keeps running; only NetBird is stopped")
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	p.wait(20 * time.Second)
}

func TestDrillGluetunStopsNetBirdThatFellBackFromAdvancedRouting(t *testing.T) {
	skipWithoutWireGuard(t)
	l := gluetunLab(t, "127.0.0.1:8000")
	p := l.startEnv(l.gluetunEnv("overlay", "NB_FAKE_LOG_AFTER=1",
		"NB_FAKE_LOG_LINE=WARN client/net/env_linux.go:61: falling back to legacy routing"))
	l.waitReady(p)
	started := time.Now()
	l.waitFor(20*time.Second, "NetBird to be stopped for the log line", func() bool { return l.traceHas("terminated") })
	t.Logf("NetBird stopped %v after `netbird up`", time.Since(started))
	if !strings.Contains(p.out.String(), FallbackMessage) {
		t.Errorf("the reason is not in the log:\n%s", p.out.String())
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	p.wait(20 * time.Second)
}

func TestDrillGluetunRefusesAControlServerOnAnyAddress(t *testing.T) {
	skipWithoutWireGuard(t)
	l := gluetunLab(t, "0.0.0.0:8000")
	p := l.startEnv(l.gluetunEnv("overlay"))
	if code := p.wait(60 * time.Second); code == 0 {
		t.Error("exit status")
	}
	if !strings.Contains(p.out.String(), "has a listener on an address other than loopback") {
		t.Errorf("the refusal is not in the log:\n%s", p.out.String())
	}
	if l.traceHas("service run") {
		t.Error("NetBird was started")
	}
	// Nothing of the contract was installed before the refusal.
	if strings.Contains(l.rules("-4"), "iif wt0") {
		t.Errorf("rules were installed:\n%s", l.rules("-4"))
	}
}

func TestDrillSidecarOwnsNoInterfaceAndRunsNoNetBird(t *testing.T) {
	skipWithoutWireGuard(t)
	l := gluetunLab(t, "127.0.0.1:8000")
	p := l.startEnv(l.gluetunEnv("sidecar"))
	l.waitFor(30*time.Second, "the first record", func() bool { return l.result() != nil })
	time.Sleep(4 * time.Second)
	if l.traceHas("service run") {
		t.Error("a sidecar runs no NetBird")
	}
	if !p.running() {
		t.Fatalf("the sidecar stopped:\n%s", p.out.String())
	}
	if r := l.result(); r["kind"] != "sidecar" {
		t.Errorf("record: %v", r)
	}
	// A crashed worker: the failure record marks peer, handshake and egress
	// unknown, and the cleanup touches nothing (wg0 is gluetun's).
	if err := syscall.Kill(l.workerPid(), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if code := p.wait(25 * time.Second); code == 0 {
		t.Error("exit status")
	}
	r := l.result()
	if r["status"] != "failed" || r["message"] != OwnerStoppedMessage {
		t.Fatalf("the failure record: %v", r)
	}
	checks := r["checks"].(map[string]any)
	for _, name := range []string{"peer", "handshake", "egress"} {
		if c := checks[name].(map[string]any); c["state"] != "unknown" {
			t.Errorf("%s: %v", name, c)
		}
	}
	if !l.linkExists(l.exit, dGluetunIf) {
		t.Error("the sidecar's cleanup removed gluetun's tunnel")
	}
	_ = filepath.Join
}
