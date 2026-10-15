//go:build drill && linux

package exit

// The native sidecar's end-to-end drill: the real binary in the exit
// namespace, where an application would run beside it. The tunnel's peer does
// not exist, so nothing ever arrives through it; what the drill counts is
// whether anything the namespace sends reaches the destination by the host
// path, which only a leak could.

import (
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func (l *lab) nativeSidecarEnv() []string {
	return []string{
		"PATH=" + binDir + ":/usr/sbin:/usr/bin:/bin:/sbin",
		"TUNNEL_BACKEND=native", "EXIT_KIND=sidecar", "PROVIDER=mullvad", "EXIT_IF=" + dExit,
		// The host path's gateway only: the destination is not LAN.
		"SIDECAR_LAN_CIDRS=198.51.100.2/32,2001:db8:2::2/128",
		"STATE_DIR=" + l.stateDir, "TUNNEL_CONF_DIR=" + l.confDir, "MOLEBRIDGE_RUN_DIR=" + l.runDir,
		"GUARD_GRACE=5", "ROUTING_RECONCILE_INTERVAL=10", "TZ=UTC",
	}
}

// leakCounter counts, in the outside namespace, packets addressed to the
// destination: the host path is the only way they could arrive.
func (l *lab) leakCounter() {
	l.t.Helper()
	script := `table inet leak {
  counter target {}
  counter handshake {}
  chain pre {
    type filter hook prerouting priority raw; policy accept;
    ip daddr ` + dTarget4 + ` counter name target
    ip6 daddr ` + dTarget6 + ` counter name target
    ip daddr 198.51.100.10 udp dport 51820 counter name handshake
  }
}
`
	if out, err := l.outside.ExecInput(script, "nft", "-f", "-"); err != nil {
		l.t.Fatalf("nft: %v\n%s", err, out)
	}
}

func (l *lab) leaked() int { return l.counted("target") }

func (l *lab) counted(name string) int {
	l.t.Helper()
	out, err := l.outside.Exec("nft", "list", "counter", "inet", "leak", name)
	if err != nil {
		l.t.Fatalf("nft: %v\n%s", err, out)
	}
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "packets" && i+1 < len(fields) {
			n, _ := strconv.Atoi(fields[i+1])
			return n
		}
	}
	return 0
}

func (l *lab) sidecarTables() int {
	out, _ := l.exit.Exec("nft", "list", "tables")
	return strings.Count(out, "inet molebridge_sidecar")
}

// sidecarInstalled: the firewall, rules 96 and 97 in both families, and the
// exit table's fallback.
func (l *lab) sidecarInstalled() bool {
	if l.sidecarTables() != 1 {
		return false
	}
	for _, f := range []string{"-4", "-6"} {
		rules := l.rules(f)
		if !strings.Contains(rules, "96: from all iif lo lookup 51821") || !strings.Contains(rules, "97: from all iif lo unreachable") {
			return false
		}
		table, _ := l.exit.TryIP(f, "route", "show", "table", "51821")
		if !strings.Contains(table, "unreachable default") {
			return false
		}
	}
	return true
}

// appSends sends from the exit namespace as an application would: unbound,
// and bound to the host interface, in both families. It returns whether the
// LAN gateway answered.
func (l *lab) appSends() bool {
	for _, a := range [][]string{{"-4", dTarget4}, {"-6", dTarget6}} {
		_, _ = l.exit.Exec("ping", a[0], "-c", "2", "-i", "0.2", "-W", "1", a[1])
		_, _ = l.exit.Exec("ping", a[0], "-c", "2", "-i", "0.2", "-W", "1", "-I", "eth0", a[1])
	}
	_, err := l.exit.Exec("ping", "-4", "-c", "1", "-W", "2", "198.51.100.2")
	return err == nil
}

func TestDrillNativeSidecarKeepsTheNamespaceClosed(t *testing.T) {
	skipWithoutWireGuard(t)
	l := newLab(t, false)
	// The tunnel config's peer endpoint, on the host path's subnet: it must
	// answer ARP for the handshake to be sent at all.
	l.outside.IP("addr", "add", "198.51.100.10/32", "dev", "outside0")
	l.leakCounter()
	p := l.startEnv(l.nativeSidecarEnv())
	l.waitFor(30*time.Second, "the firewall, the rules and the tunnel", func() bool {
		if !p.running() {
			t.Fatalf("the exit stopped early (%d):\n%s", p.code, p.out.String())
		}
		return l.sidecarInstalled() && l.linkExists(l.exit, dExit)
	})
	if l.traceHas("service run") {
		t.Error("a native sidecar runs no NetBird")
	}

	if !l.appSends() {
		t.Error("the LAN gateway did not answer")
	}
	if n := l.leaked(); n != 0 {
		t.Fatalf("%d packets reached the destination by the host path", n)
	}
	// The tunnel's own UDP carries its fwmark (EXIT_TABLE) and so reaches the
	// peer's endpoint by the host path (rule 93): the handshake the sends
	// above started arrived outside.
	if n := l.counted("handshake"); n == 0 {
		t.Error("no handshake reached the peer's endpoint: the tunnel's fwmark is not routed to the host")
	}

	// A deleted firewall comes back within a few of its 2-second checks.
	if out, err := l.exit.Exec("nft", "delete", "table", "inet", "molebridge_sidecar"); err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}
	l.waitFor(10*time.Second, "the firewall to be reinstalled", func() bool { return l.sidecarTables() == 1 })
	l.waitFor(5*time.Second, "the reinstall to be logged", func() bool {
		return strings.Contains(p.out.String(), "the sidecar firewall was not as installed (")
	})

	// A crashed worker: the supervisor stops, the cleanup removes the tunnel
	// link only, and the namespace stays closed.
	if r := l.result(); r["kind"] != "sidecar" || r["backend"] != "native" {
		t.Errorf("record: %v", r)
	}
	if err := syscall.Kill(l.workerPid(), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if code := p.wait(25 * time.Second); code == 0 {
		t.Error("exit status 0 after a crashed worker")
	}
	if l.linkExists(l.exit, dExit) {
		t.Error("the cleanup left the tunnel link")
	}
	if !l.sidecarInstalled() {
		t.Fatalf("the rules or the firewall went with the exit:\n%s\n%s", l.rules("-4"), l.rules("-6"))
	}
	r := l.result()
	if r["status"] != "failed" || r["message"] != OwnerStoppedMessage {
		t.Fatalf("the failure record: %v", r)
	}
	checks := r["checks"].(map[string]any)
	for _, name := range []string{"routing", "traffic_protection", "peer", "handshake", "egress"} {
		if c, ok := checks[name].(map[string]any); !ok || c["state"] != "unknown" {
			t.Errorf("%s: %v", name, checks[name])
		}
	}
	l.appSends()
	if n := l.leaked(); n != 0 {
		t.Fatalf("%d packets reached the destination while the exit was down", n)
	}

	// The next run, in the namespace that outlived the last (a pod's, across
	// a container restart): one firewall, one copy of each rule.
	p = l.startEnv(l.nativeSidecarEnv())
	l.waitFor(30*time.Second, "the second run's tunnel", func() bool {
		if !p.running() {
			t.Fatalf("the second run stopped early (%d):\n%s", p.code, p.out.String())
		}
		return l.sidecarInstalled() && l.linkExists(l.exit, dExit)
	})
	time.Sleep(3 * time.Second)
	for _, f := range []string{"-4", "-6"} {
		rules := l.rules(f)
		for _, prio := range []string{"88:", "89:", "90:", "93:", "96:", "97:"} {
			if n := strings.Count(rules, "\n"+prio) + boolInt(strings.HasPrefix(rules, prio)); n != 1 {
				t.Errorf("%s: %d rules at %s after the restart:\n%s", f, n, prio, rules)
			}
		}
	}
	if !l.appSends() {
		t.Error("the LAN gateway did not answer after the restart")
	}
	if n := l.leaked(); n != 0 {
		t.Fatalf("%d packets reached the destination after the restart", n)
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := p.wait(20 * time.Second); code != 0 {
		t.Errorf("a requested stop exited %d", code)
	}
	if !l.sidecarInstalled() {
		t.Error("a requested stop removed the rules or the firewall")
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
