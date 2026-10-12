//go:build drill && linux

package exit

// The exit's drills. They build the real molebridge binary (with the drill
// hook) and a fake netbird, and run the supervisor in a disposable network
// namespace of a privileged container (internal/nstest/drill.sh). No real
// NetBird, provider or network is involved: the namespaces are joined only to
// each other.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/nstest"
)

var (
	buildOnce sync.Once
	binDir    string
	buildErr  error
)

// drillBinaries builds molebridge (drill tag) and the fake netbird once.
func drillBinaries(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		binDir, buildErr = os.MkdirTemp("", "mb-drill-bin")
		if buildErr != nil {
			return
		}
		for _, b := range []struct{ out, pkg string }{
			{"molebridge", "github.com/irashack/molebridge/cmd/molebridge"},
			{"netbird", "github.com/irashack/molebridge/internal/exit/testdata/fakenetbird"},
		} {
			cmd := exec.Command("go", "build", "-tags", "drill", "-o", filepath.Join(binDir, b.out), b.pkg)
			if out, err := cmd.CombinedOutput(); err != nil {
				buildErr = fmt.Errorf("go build %s: %v\n%s", b.pkg, err, out)
				return
			}
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return binDir
}

const (
	dOverlay = "wt0"
	dExit    = "mullvad"
	dTarget4 = "198.51.100.100"
	dTarget6 = "2001:db8:2::100"
)

// syncBuf is a goroutine-safe buffer for a child's output.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type lab struct {
	t                       *testing.T
	client, exit, outside   *nstest.NS
	dir                     string
	stateDir, runDir, nbDir string
	fakeDir, confDir        string
}

func (l *lab) path(parts ...string) string { return filepath.Join(append([]string{l.dir}, parts...)...) }

// newLab builds the namespaces: the exit, the host path to "outside" (where
// the destination answers, and where a leak would be counted) and the client
// behind the overlay interface, which the lab pre-creates as a veth when
// overlay is true.
func newLab(t *testing.T, overlayVeth bool) *lab {
	t.Helper()
	l := &lab{t: t, dir: t.TempDir()}
	l.client = nstest.New(t, "client")
	l.exit = nstest.New(t, "exit")
	l.outside = nstest.New(t, "outside")
	for _, ns := range []*nstest.NS{l.client, l.exit, l.outside} {
		ns.Sysctl("net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0", "net.ipv6.conf.default.accept_dad=0",
			"net.ipv6.conf.all.disable_ipv6=0", "net.ipv6.conf.default.disable_ipv6=0")
	}
	l.exit.Veth("eth0", l.outside, "outside0")
	l.exit.IP("addr", "add", "198.51.100.1/24", "dev", "eth0")
	l.exit.IP("-6", "addr", "add", "2001:db8:2::1/64", "dev", "eth0", "nodad")
	l.exit.IP("link", "set", "eth0", "up")
	l.outside.IP("addr", "add", "198.51.100.2/24", "dev", "outside0")
	l.outside.IP("-6", "addr", "add", "2001:db8:2::2/64", "dev", "outside0", "nodad")
	l.outside.IP("link", "set", "outside0", "up")
	l.outside.IP("addr", "add", dTarget4+"/32", "dev", "outside0")
	l.outside.IP("-6", "addr", "add", dTarget6+"/128", "dev", "outside0", "nodad")
	l.exit.IP("route", "add", "default", "via", "198.51.100.2")
	l.exit.IP("-6", "route", "add", "default", "via", "2001:db8:2::2")
	l.outside.IP("route", "add", "192.0.2.0/24", "via", "198.51.100.1")
	l.outside.IP("-6", "route", "add", "2001:db8:1::/64", "via", "2001:db8:2::1")
	l.exit.Sysctl("net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1", "net.ipv4.icmp_errors_use_inbound_ifaddr=1")
	script := `table inet mb {
  counter client {}
  chain pre {
    type filter hook prerouting priority raw; policy accept;
    ip saddr 192.0.2.0/24 counter name client
    ip6 saddr 2001:db8:1::/64 counter name client
  }
}
`
	if out, err := l.outside.ExecInput(script, "nft", "-f", "-"); err != nil {
		t.Fatalf("nft: %v\n%s", err, out)
	}
	if overlayVeth {
		l.makeOverlay()
	}
	l.stateDir, l.runDir, l.nbDir = l.path("state"), l.path("run"), l.path("netbird")
	l.fakeDir, l.confDir = l.path("fake"), l.path("wg_confs")
	for _, d := range []string{filepath.Join(l.stateDir, "applier"), l.runDir, l.nbDir, l.fakeDir, l.confDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	conf := "[Interface]\nPrivateKey = " + zeroKey + "\nAddress = 203.0.113.2/32\nMTU = 1420\nTable = off\n" +
		"PostUp = ip route replace default dev %i table 51821\nPreDown = ip route del default dev %i table 51821\n\n" +
		"[Peer]\nPublicKey = " + zeroKey + "\nEndpoint = 198.51.100.10:51820\nAllowedIPs = 0.0.0.0/0\n"
	if err := os.WriteFile(filepath.Join(l.confDir, dExit+".conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	return l
}

// makeOverlay creates the overlay interface as a veth to the client, the way a
// peer's traffic would arrive.
func (l *lab) makeOverlay() {
	l.exit.Veth(dOverlay, l.client, "client0")
	l.exit.IP("link", "set", dOverlay, "address", "02:00:00:00:01:01")
	l.client.IP("link", "set", "client0", "address", "02:00:00:00:01:02")
	l.exit.IP("addr", "add", "192.0.2.1/24", "dev", dOverlay)
	l.exit.IP("-6", "addr", "add", "2001:db8:1::1/64", "dev", dOverlay, "nodad")
	l.client.IP("addr", "add", "192.0.2.2/24", "dev", "client0")
	l.client.IP("-6", "addr", "add", "2001:db8:1::2/64", "dev", "client0", "nodad")
	l.exit.IP("link", "set", dOverlay, "up")
	l.client.IP("link", "set", "client0", "up")
	l.client.IP("route", "add", "default", "via", "192.0.2.1")
	l.client.IP("-6", "route", "add", "default", "via", "2001:db8:1::1")
	for _, a := range []string{"192.0.2.1", "2001:db8:1::1"} {
		l.client.TryIP("neigh", "replace", a, "lladdr", "02:00:00:00:01:01", "nud", "permanent", "dev", "client0")
	}
	for _, a := range []string{"192.0.2.2", "2001:db8:1::2"} {
		l.exit.TryIP("neigh", "replace", a, "lladdr", "02:00:00:00:01:02", "nud", "permanent", "dev", dOverlay)
	}
}

func (l *lab) env(extra ...string) []string {
	env := []string{
		"PATH=" + binDir + ":/usr/sbin:/usr/bin:/bin:/sbin",
		"TUNNEL_BACKEND=native", "EXIT_KIND=overlay", "PROVIDER=mullvad", "EXIT_IF=" + dExit, "OVERLAY_IF=" + dOverlay,
		"OVERLAY_CIDR=192.0.2.0/24", "OVERLAY6_CIDR=2001:db8:1::/64", "NB_INTERFACE_NAME=" + dOverlay,
		"NB_DISABLE_USERSPACE_ROUTING=true", "NB_STATE_DIR=" + l.nbDir, "NB_FAKE_DIR=" + l.fakeDir,
		"NB_LOG_FILE=console," + l.path("client.log"), "NB_EXTRA_IFACE_BLACKLIST=" + dExit,
		"STATE_DIR=" + l.stateDir, "TUNNEL_CONF_DIR=" + l.confDir, "MOLEBRIDGE_RUN_DIR=" + l.runDir,
		"GUARD_GRACE=5", "ROUTING_RECONCILE_INTERVAL=10", "NB_SETUP_KEY=drill-setup-value", "TZ=UTC",
	}
	return append(env, extra...)
}

type exitProc struct {
	l    *lab
	cmd  *exec.Cmd
	out  *syncBuf
	done chan int
	code int
	at   time.Time
}

// start runs `molebridge exit` in the exit namespace.
func (l *lab) start(extra ...string) *exitProc {
	l.t.Helper()
	drillBinaries(l.t)
	p := &exitProc{l: l, out: &syncBuf{}, done: make(chan int, 1), at: time.Now()}
	p.cmd = exec.Command("ip", "netns", "exec", l.exit.Name, filepath.Join(binDir, "molebridge"), "exit")
	p.cmd.Env = l.env(extra...)
	p.cmd.Stdout, p.cmd.Stderr = p.out, p.out
	if err := p.cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	go func() {
		err := p.cmd.Wait()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		p.done <- code
	}()
	l.t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = p.cmd.Process.Kill()
			killTree(l.exit)
			<-p.done
		}
		if l.t.Failed() {
			l.t.Logf("exit output:\n%s", p.out.String())
			l.t.Logf("trace:\n%s", strings.Join(l.trace(), "\n"))
		}
	})
	return p
}

// killTree ends everything left in the exit namespace by a failed test.
func killTree(ns *nstest.NS) {
	out, _ := exec.Command("ip", "netns", "pids", ns.Name).Output()
	for _, f := range strings.Fields(string(out)) {
		if pid, err := strconv.Atoi(f); err == nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

func (p *exitProc) wait(d time.Duration) int {
	p.l.t.Helper()
	select {
	case code := <-p.done:
		p.done <- code
		p.code = code
		return code
	case <-time.After(d):
		p.l.t.Fatalf("the exit did not stop within %v\n%s", d, p.out.String())
		return -1
	}
}

func (p *exitProc) running() bool {
	select {
	case c := <-p.done:
		p.done <- c
		return false
	default:
		return true
	}
}

func (l *lab) trace() []string {
	b, _ := os.ReadFile(filepath.Join(l.fakeDir, "trace"))
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func (l *lab) traceHas(substr string) bool {
	for _, line := range l.trace() {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

func (l *lab) traceCount(substr string) int {
	n := 0
	for _, line := range l.trace() {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

func (l *lab) waitFor(d time.Duration, what string, cond func() bool) {
	l.t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			l.t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitReady waits until the fake NetBird has been started and `up` has run.
func (l *lab) waitReady(p *exitProc) {
	l.t.Helper()
	l.waitFor(60*time.Second, "NetBird to be started", func() bool {
		if !p.running() {
			l.t.Fatalf("the exit stopped early (%d):\n%s", p.code, p.out.String())
		}
		return l.traceHas(" up")
	})
}

func (l *lab) linkExists(ns *nstest.NS, name string) bool {
	_, err := ns.TryIP("link", "show", "dev", name)
	return err == nil
}

// pid finds a process of the namespace by its command line.
func (l *lab) pid(match ...string) int {
	out, _ := exec.Command("ip", "netns", "pids", l.exit.Name).Output()
	for _, f := range strings.Fields(string(out)) {
		raw, err := os.ReadFile("/proc/" + f + "/cmdline")
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		if len(args) < len(match) {
			continue
		}
		ok := true
		for i, m := range match {
			if !strings.HasSuffix(args[i], m) {
				ok = false
			}
		}
		if ok {
			n, _ := strconv.Atoi(f)
			return n
		}
	}
	return 0
}

func (l *lab) workerPid() int { return l.pid("molebridge", "exit", "--worker") }

func (l *lab) result() map[string]any {
	b, err := os.ReadFile(filepath.Join(l.stateDir, "applier", "result.json"))
	if err != nil {
		return nil
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func (l *lab) rules(family string) string {
	out, _ := l.exit.TryIP(family, "rule", "show")
	return out
}

// guardsStay asserts the contract's rules and the unreachable fallback remain.
func (l *lab) guardsStay(when string) {
	l.t.Helper()
	for _, f := range []string{"-4", "-6"} {
		rules := l.rules(f)
		for _, want := range []string{"1:\tnot from all iif " + dOverlay + " lookup local", "97:\tfrom all iif " + dOverlay + " ", "95:", "96:"} {
			if !strings.Contains(rules, want) {
				l.t.Errorf("%s: %s rules lack %q:\n%s", when, f, want, rules)
			}
		}
		table, _ := l.exit.TryIP(f, "route", "show", "table", "51821")
		if !strings.Contains(table, "unreachable default") {
			l.t.Errorf("%s: %s exit table lost its fallback:\n%s", when, f, table)
		}
	}
}

func (l *lab) counter() int {
	l.t.Helper()
	out, err := l.outside.Exec("nft", "list", "counter", "inet", "mb", "client")
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

// ping sends a few packets from the client toward the destination.
func (l *lab) pingBoth() {
	for _, a := range [][]string{{"-4", dTarget4}, {"-6", dTarget6}} {
		l.client.Exec("ping", a[0], "-c", "3", "-i", "0.2", "-W", "1", a[1])
	}
}

func skipWithoutWireGuard(t *testing.T) {
	t.Helper()
	l := nstest.New(t, "wgprobe")
	if _, err := l.TryIP("link", "add", "wgprobe0", "type", "wireguard"); err != nil {
		t.Skipf("this kernel has no WireGuard: %v", err)
	}
}

func TestDrillStartToReady(t *testing.T) {
	skipWithoutWireGuard(t)
	l := newLab(t, false)
	p := l.start()
	l.waitReady(p)

	// NetBird was started only after the contract held and the tunnel was up.
	var v4, links string
	for _, line := range l.trace() {
		if i := strings.Index(line, " rule-4 "); i >= 0 {
			v4 += line[i+8:] + "\n"
		}
		if i := strings.Index(line, " links "); i >= 0 {
			links = line[i+7:]
		}
	}
	for _, want := range []string{"1: not from all iif " + dOverlay + " lookup local", "97: from all iif " + dOverlay, "96: from all oif " + dExit, "94: from 203.0.113.2 ipproto icmp", "98: from 203.0.113.2 ipproto icmp"} {
		if !strings.Contains(v4, want) {
			t.Errorf("at `netbird service run` the IPv4 rules lacked %q:\n%s", want, v4)
		}
	}
	if !strings.Contains(links, dExit+":") || !strings.Contains(links, "UP") {
		t.Errorf("at `netbird service run` the tunnel was not up: %s", links)
	}
	if t.Failed() {
		return
	}

	l.waitFor(40*time.Second, "the record with a lease-backed owner_record", func() bool {
		r := l.result()
		if r == nil {
			return false
		}
		o, _ := r["checks"].(map[string]any)["owner_record"].(map[string]any)
		return o["state"] == "pass" && o["expires_at"] != nil
	})
	r := l.result()
	if r["kind"] != "overlay" || r["backend"] != "native" || r["provider"] != "mullvad" {
		t.Errorf("record header: %v", r)
	}
	l.waitFor(40*time.Second, "the heartbeat", func() bool { _, err := os.Stat(filepath.Join(l.runDir, "molebridge", "heartbeat")); return err == nil })

	health := exec.Command("ip", "netns", "exec", l.exit.Name, filepath.Join(binDir, "molebridge"), "health")
	health.Env = l.env()
	if out, err := health.CombinedOutput(); err != nil {
		t.Errorf("health: %v\n%s", err, out)
	}
	status := exec.Command("ip", "netns", "exec", l.exit.Name, filepath.Join(binDir, "molebridge"), "status")
	status.Env = l.env()
	out, _ := status.CombinedOutput()
	t.Logf("status:\n%s", out)
	if !strings.Contains(string(out), "lease: held") || !strings.Contains(string(out), "heartbeat: fresh") {
		t.Errorf("status:\n%s", out)
	}
	l.guardsStay("while running")

	// A requested stop with complete cleanup exits 0.
	stopAt := time.Now()
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	if code := p.wait(20 * time.Second); code != 0 {
		t.Errorf("a requested stop exited %d\n%s", code, p.out.String())
	}
	t.Logf("requested stop took %v", time.Since(stopAt))
	if l.linkExists(l.exit, dExit) || l.linkExists(l.exit, dOverlay) {
		t.Error("the cleanup left an interface")
	}
	l.guardsStay("after the stop")
	if !l.traceHas("terminated") {
		t.Error("NetBird was not told to stop")
	}
	if strings.Contains(p.out.String(), "drill-setup-value") {
		t.Error("the setup key reached the output")
	}
}

func TestDrillFrozenWorkerStopsNetBirdWithinGraceAndBudget(t *testing.T) {
	skipWithoutWireGuard(t)
	l := newLab(t, false)
	p := l.start()
	l.waitReady(p)
	pid := l.workerPid()
	if pid == 0 {
		t.Fatal("no worker")
	}
	frozen := time.Now()
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	l.waitFor(30*time.Second, "NetBird to be terminated", func() bool { return l.traceHas("terminated") })
	nbStopped := time.Since(frozen)
	code := p.wait(30 * time.Second)
	total := time.Since(frozen)
	t.Logf("NetBird terminated %v after the freeze (GUARD_GRACE=5); the exit ended %v after it, status %d", nbStopped, total, code)
	if code == 0 {
		t.Error("a lapsed lease must not exit 0")
	}
	// The lease can run up to its grace before the last renewal; the stop
	// sequence starts at once.
	if nbStopped > 5*time.Second+3*time.Second {
		t.Errorf("NetBird outlived the grace by too much: %v", nbStopped)
	}
	if total > 5*time.Second+13*time.Second+4*time.Second {
		t.Errorf("the stop took %v, over GUARD_GRACE + the 13-second budget", total)
	}
	if l.linkExists(l.exit, dExit) || l.linkExists(l.exit, dOverlay) {
		t.Error("the cleanup left an interface")
	}
	l.guardsStay("after the lapse")
	r := l.result()
	if r["status"] != "failed" || r["message"] != OwnerStoppedMessage {
		t.Errorf("the failure record: %v %v", r["status"], r["message"])
	}
	if o, _ := r["checks"].(map[string]any)["owner_record"].(map[string]any); o["state"] != "fail" {
		t.Errorf("owner_record: %v", o)
	}
}

func TestDrillWedgedMutatorLapsesTheLeaseEvenWithRenewalsRunnable(t *testing.T) {
	skipWithoutWireGuard(t)
	l := newLab(t, false)
	p := l.start()
	l.waitReady(p)
	l.waitFor(20*time.Second, "the first full record", func() bool { return l.result() != nil && l.result()["status"] != "unknown" })
	wedged := time.Now()
	if err := os.WriteFile(filepath.Join(l.runDir, "wedge-mutator"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	l.waitFor(60*time.Second, "NetBird to be terminated", func() bool { return l.traceHas("terminated") })
	nbStopped := time.Since(wedged)
	code := p.wait(40 * time.Second)
	total := time.Since(wedged)
	t.Logf("NetBird terminated %v after the wedge (bound 10 s + GUARD_GRACE 5 s); the exit ended %v after it, status %d", nbStopped, total, code)
	if code == 0 {
		t.Error("a lapsed lease must not exit 0")
	}
	if nbStopped > 10*time.Second+5*time.Second+4*time.Second {
		t.Errorf("NetBird outlived 10 s + the grace by too much: %v", nbStopped)
	}
	if total > 10*time.Second+5*time.Second+13*time.Second+4*time.Second {
		t.Errorf("the stop took %v", total)
	}
	if !strings.Contains(p.out.String(), "wedging the mutation owner") {
		t.Error("the hook did not run")
	}
	l.guardsStay("after the lapse")
}

func TestDrillCrashedWorkerCleansUpAndTheRulesStay(t *testing.T) {
	skipWithoutWireGuard(t)
	l := newLab(t, false)
	p := l.start()
	l.waitReady(p)
	if err := syscall.Kill(l.workerPid(), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	code := p.wait(25 * time.Second)
	if code == 0 {
		t.Error("a crashed worker must not exit 0")
	}
	if l.linkExists(l.exit, dExit) || l.linkExists(l.exit, dOverlay) {
		t.Errorf("the cleanup left an interface:\n%s", func() string { o, _ := l.exit.TryIP("link", "show"); return o }())
	}
	if !l.traceHas("terminated") {
		t.Error("NetBird was not stopped")
	}
	l.guardsStay("after the crash")
	r := l.result()
	if r["status"] != "failed" {
		t.Errorf("status %v", r["status"])
	}
	if !strings.Contains(p.out.String(), "the worker exited") {
		t.Errorf("the stop does not name its step:\n%s", p.out.String())
	}
}

// With the namespace held by another process, nothing the exit leaves behind
// forwards off-tunnel: after a crash and its cleanup, a peer that comes back
// on the overlay interface still cannot reach the host path.
func TestDrillNothingLeavesOffTunnelAfterACrash(t *testing.T) {
	skipWithoutWireGuard(t)
	l := newLab(t, true)
	// The fake NetBird finds the overlay interface in place and leaves it be.
	p := l.start("NB_FAKE_MODE=existing")
	l.waitReady(p)
	l.pingBoth()
	if n := l.counter(); n != 0 {
		t.Fatalf("%d packets from the overlay reached the host path while the exit ran", n)
	}
	if err := syscall.Kill(l.workerPid(), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if code := p.wait(25 * time.Second); code == 0 {
		t.Error("exit status")
	}
	if l.linkExists(l.exit, dOverlay) {
		t.Fatal("the cleanup should have removed the overlay interface")
	}
	// The peer returns (NetBird in another container would recreate it).
	l.client.IP("link", "del", "client0")
	l.makeOverlay()
	l.pingBoth()
	if n := l.counter(); n != 0 {
		t.Errorf("%d packets from the overlay reached the host path after the cleanup", n)
	}
	l.guardsStay("after the cleanup")
}

func TestDrillProfileWithoutTheTunnelExclusionAdmitsNothing(t *testing.T) {
	skipWithoutWireGuard(t)
	l := newLab(t, false)
	p := l.start("NB_FAKE_NOBLACKLIST=1")
	l.waitFor(60*time.Second, "NetBird to be started", func() bool { return l.traceHas(" up") })
	l.waitFor(30*time.Second, "NetBird to be stopped again", func() bool { return l.traceHas("terminated") })
	time.Sleep(12 * time.Second)
	if !p.running() {
		t.Fatalf("the exit should stay up, unready:\n%s", p.out.String())
	}
	if n := l.traceCount("service run"); n != 1 {
		t.Errorf("NetBird was started %d times; a refused profile must not be retried", n)
	}
	if !strings.Contains(p.out.String(), "does not exclude the tunnel interface") {
		t.Errorf("the refusal is not in the log:\n%s", p.out.String())
	}
	if r := l.result(); r != nil && r["status"] != "unknown" {
		t.Errorf("the pipeline must stay off: %v", r["status"])
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	p.wait(20 * time.Second)
}

func TestDrillNetBirdDyingStopsTheExit(t *testing.T) {
	skipWithoutWireGuard(t)
	l := newLab(t, false)
	p := l.start("NB_FAKE_MODE=die")
	code := p.wait(60 * time.Second)
	if code == 0 {
		t.Error("an unexpected NetBird exit must not exit 0")
	}
	if l.linkExists(l.exit, dExit) {
		t.Error("the tunnel was left")
	}
	l.guardsStay("after NetBird died")
}

// cpuTicks is the CPU time (user + system, own and reaped children) of a
// process in clock ticks.
func cpuTicks(pid int) (int64, bool) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndex(s, ")")+2:])
	var total int64
	for _, i := range []int{11, 12, 13, 14} { // utime stime cutime cstime
		n, _ := strconv.ParseInt(f[i], 10, 64)
		total += n
	}
	return total, true
}

// TestDrillIdleCPU measures the supervisor and worker over two minutes with
// the fake NetBird. Set MB_IDLE_CPU=1; the figure is logged.
func TestDrillIdleCPU(t *testing.T) {
	if os.Getenv("MB_IDLE_CPU") == "" {
		t.Skip("set MB_IDLE_CPU=1 to run the two-minute measurement")
	}
	skipWithoutWireGuard(t)
	l := newLab(t, false)
	p := l.start()
	l.waitReady(p)
	// Let the first inspections and the catalogue attempt settle.
	time.Sleep(30 * time.Second)
	pids := []int{p.cmd.Process.Pid, l.workerPid()}
	if pids[1] == 0 {
		t.Fatal("no worker")
	}
	read := func() (total int64) {
		for _, pid := range pids {
			n, ok := cpuTicks(pid)
			if !ok {
				t.Fatalf("process %d is gone", pid)
			}
			total += n
		}
		return
	}
	before, start := read(), time.Now()
	cg0 := cgroupUsec()
	time.Sleep(120 * time.Second)
	ticks, elapsed := read()-before, time.Since(start)
	cg1 := cgroupUsec()
	hz := 100.0
	pct := float64(ticks) / hz / elapsed.Seconds() * 100
	t.Logf("supervisor + worker (own and reaped children): %d ticks in %v = %.3f%% of one core", ticks, elapsed.Round(time.Second), pct)
	if cg0 >= 0 && cg1 >= 0 {
		t.Logf("the container's cgroup (harness included): %.3f%% of one core", float64(cg1-cg0)/1e6/elapsed.Seconds()*100)
	}
	if pct > 0.5 {
		t.Errorf("idle CPU %.3f%% is over the 0.5%% target", pct)
	}
}

// cgroupUsec reads usage_usec from the container's cgroup, -1 when unavailable.
func cgroupUsec() int64 {
	b, err := os.ReadFile("/sys/fs/cgroup/cpu.stat")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "usage_usec ") {
			n, _ := strconv.ParseInt(strings.Fields(line)[1], 10, 64)
			return n
		}
	}
	return -1
}
