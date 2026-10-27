package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/exit"
)

const testKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func writeConf(t *testing.T, dir string) {
	t.Helper()
	conf := `[Interface]
PrivateKey = ` + testKey + `
Address = 203.0.113.2/32
MTU = 1420
Table = off
PostUp = ip route replace default dev %i table 51821
PreDown = ip route del default dev %i table 51821

[Peer]
PublicKey = ` + testKey + `
Endpoint = 198.51.100.10:51820
AllowedIPs = 0.0.0.0/0
`
	if err := os.WriteFile(filepath.Join(dir, "mullvad.conf"), []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
}

func roleEnv(t *testing.T) (map[string]string, string) {
	t.Helper()
	dir := t.TempDir()
	confDir := filepath.Join(dir, "wg_confs")
	for _, d := range []string{confDir, filepath.Join(dir, "state", "applier"), filepath.Join(dir, "nb")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeConf(t, confDir)
	return map[string]string{
		"TUNNEL_BACKEND": "native", "PROVIDER": "mullvad", "EXIT_IF": "mullvad", "OVERLAY_CIDR": "192.0.2.0/24",
		"NB_DISABLE_USERSPACE_ROUTING": "true", "NB_EXTRA_IFACE_BLACKLIST": "mullvad", "NB_STATE_DIR": filepath.Join(dir, "nb"),
		"STATE_DIR": filepath.Join(dir, "state"), "TUNNEL_CONF_DIR": confDir, "MOLEBRIDGE_RUN_DIR": filepath.Join(dir, "run"),
	}, dir
}

func TestExitRoleRefusesUnknownArguments(t *testing.T) {
	var stderr bytes.Buffer
	if code := exitMain([]string{"--bogus"}, nil, &stderr); code != 2 || !strings.Contains(stderr.String(), "--worker and --cleanup") {
		t.Fatalf("%d %q", code, stderr.String())
	}
}

func TestExitRoleRefusalPrintsOneFixedLine(t *testing.T) {
	var stderr bytes.Buffer
	code := exitMain(nil, []string{"TUNNEL_BACKEND=native", "PROVIDER=mullvad", "OVERLAY_CIDR=bogus", "STATE_DIR=/nonexistent"}, &stderr)
	if code != 1 || stderr.String() != "molebridge-exit: OVERLAY_CIDR must be an IPv4 CIDR\n" {
		t.Fatalf("%d %q", code, stderr.String())
	}
}

func TestCheckConfig(t *testing.T) {
	env, _ := roleEnv(t)
	var stdout, stderr bytes.Buffer
	if code := checkConfigMain(nil, env, &stdout, &stderr); code != 0 {
		t.Fatalf("%d\n%s%s", code, stdout.String(), stderr.String())
	}
	want := "molebridge-exit: configuration accepted (" + env["TUNNEL_CONF_DIR"] + "/mullvad.conf: an IPv4 address)\nNetBird gate: configuration accepted\n"
	if stdout.String() != want {
		t.Fatalf("%q\nwant %q", stdout.String(), want)
	}
	// It changes nothing: the state directory is read, never written.
	entries, _ := os.ReadDir(filepath.Join(env["STATE_DIR"], "applier"))
	if len(entries) != 0 {
		t.Errorf("check-config wrote %v", entries)
	}
	env["GUARD_GRACE"] = "99"
	stdout.Reset()
	stderr.Reset()
	if code := checkConfigMain(nil, env, &stdout, &stderr); code != 1 || stderr.String() != "molebridge-exit: GUARD_GRACE must be 5..30 seconds\n" || stdout.Len() != 0 {
		t.Fatalf("%d %q %q", code, stdout.String(), stderr.String())
	}
	if code := checkConfigMain([]string{"x"}, env, &stdout, &stderr); code != 2 {
		t.Errorf("usage: %d", code)
	}
}

func TestHealthRole(t *testing.T) {
	env, _ := roleEnv(t)
	var stdout, stderr bytes.Buffer
	if code := healthMain(nil, env, &stdout, &stderr); code != 1 || !strings.HasPrefix(stdout.String(), "unhealthy: ") ||
		!strings.HasSuffix(stdout.String(), " (molebridge dev)\n") {
		t.Fatalf("%d %q", code, stdout.String())
	}
	if code := healthMain([]string{"x"}, env, &stdout, &stderr); code != 2 {
		t.Errorf("usage: %d", code)
	}
}

func TestHealthRoleGuarded(t *testing.T) {
	env, dir := roleEnv(t)
	if err := os.MkdirAll(filepath.Join(dir, "run", "molebridge"), 0o755); err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Skip("no boot id here")
	}
	ns := exit.NetNamespace()
	if ns == "" {
		t.Skip("no network namespace here")
	}
	line := fmt.Sprintf("molebridge-guarded 1 %s %s %d\n", strings.TrimSpace(string(boot)), ns, int64(bootclock.System()()))
	if err := os.WriteFile(filepath.Join(dir, "run", "molebridge", "guarded"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := healthMain([]string{"--guarded"}, env, &stdout, &stderr); code != 0 {
		t.Fatalf("guarded: %d %q", code, stdout.String())
	}
	// The guards in place say nothing about the tunnel: plain health still fails.
	if code := healthMain(nil, env, &stdout, &stderr); code != 1 {
		t.Errorf("health without a heartbeat: %d", code)
	}
	// Evidence from another network namespace (a pod's emptyDir that outlived
	// its sandbox) proves nothing about this one.
	other := fmt.Sprintf("molebridge-guarded 1 %s net:[1] %d\n", strings.TrimSpace(string(boot)), int64(bootclock.System()()))
	if err := os.WriteFile(filepath.Join(dir, "run", "molebridge", "guarded"), []byte(other), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	if code := healthMain([]string{"--guarded"}, env, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), "another network namespace") {
		t.Errorf("another namespace's evidence: %d %q", code, stdout.String())
	}
	// Where the kernel has namespace cookies, this namespace's inode number
	// is not enough: a destroyed namespace's number is given to new ones.
	if inode, err := os.Readlink("/proc/self/ns/net"); err == nil && strings.HasPrefix(ns, "netns-cookie:") {
		recycled := fmt.Sprintf("molebridge-guarded 1 %s %s %d\n", strings.TrimSpace(string(boot)), inode, int64(bootclock.System()()))
		if err := os.WriteFile(filepath.Join(dir, "run", "molebridge", "guarded"), []byte(recycled), 0o644); err != nil {
			t.Fatal(err)
		}
		stdout.Reset()
		if code := healthMain([]string{"--guarded"}, env, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), "another network namespace") {
			t.Errorf("evidence naming the namespace by its inode number: %d %q", code, stdout.String())
		}
	}
	if code := healthMain([]string{"--guarded", "x"}, env, &stdout, &stderr); code != 2 {
		t.Errorf("usage: %d", code)
	}
}

func TestStatusRoleWithNothingPublishedYet(t *testing.T) {
	env, _ := roleEnv(t)
	var stdout, stderr bytes.Buffer
	clock := func() time.Duration { return time.Hour }
	code := statusMain(nil, env, clock, time.Now, &stdout, &stderr)
	out := stdout.String()
	if code != 1 || !strings.Contains(out, "state: unknown (awaiting status)") || !strings.Contains(out, "reasons: no-status") ||
		!strings.Contains(out, "heartbeat: none") || !strings.Contains(out, "lease: unknown (no lease file") ||
		strings.Contains(out, "routing activity") {
		t.Fatalf("%d\n%s", code, out)
	}
}

// The counters are printed only as the exit writes them: an older exit's
// record has none, and anything malformed prints nothing.
func TestStatusActivityLineReadsOnlyAWellFormedMember(t *testing.T) {
	good := map[string]any{"repairs": int64(0), "last_repair_at": nil, "events": int64(3), "relevant_events": int64(1),
		"events_lost": int64(0), "periodic_passes": int64(2)}
	if got := activityLine(map[string]any{"routing_activity": good}); got != "repairs 0 (last none), kernel events 3 (relevant 1), event losses 0, periodic passes 2" {
		t.Errorf("%q", got)
	}
	for name, bad := range map[string]map[string]any{
		"negative": {"repairs": int64(-1)},
		"text":     {"events": "3"},
		"missing":  {"periodic_passes": nil},
		"odd time": {"last_repair_at": "yesterday\n"},
	} {
		member := map[string]any{}
		for k, v := range good {
			member[k] = v
		}
		for k, v := range bad {
			if v == nil {
				delete(member, k)
			} else {
				member[k] = v
			}
		}
		if got := activityLine(map[string]any{"routing_activity": member}); got != "" {
			t.Errorf("%s: %q", name, got)
		}
	}
	if activityLine(nil) != "" || activityLine(map[string]any{"routing_activity": "x"}) != "" {
		t.Error("printed a line for no member")
	}
}

func TestStatusRoleReadsTheRecordAndTheLease(t *testing.T) {
	env, dir := roleEnv(t)
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	record := `{"schema": 2, "kind": "overlay", "backend": "native", "provider": "mullvad", "status": "failed", "message": "exit owner stopped responding", ` +
		`"checked_at": "2026-10-12T12:00:00Z", "server": null, "requested_server": null, "configured_server": null, "request_id": null, ` +
		`"selection": {"source": "seed", "outcome": null, "attempt": 0, "target": null, "next_action": null, "next_action_at": null}, ` +
		`"checks": {"routing": {"state": "fail", "at": "2026-10-12T12:00:00Z"}, "netbird": {"state": "fail", "at": "2026-10-12T12:00:00Z"}, ` +
		`"owner_record": {"state": "fail", "at": "2026-10-12T12:00:00Z"}, "peer": {"state": "unknown"}, "handshake": {"state": "unknown"}, ` +
		`"egress": {"state": "unknown"}, "traffic_protection": {"state": "fail", "at": "2026-10-12T12:00:00Z", "from": "routing"}, "app_attachment": {"state": "n/a"}}, ` +
		`"egress_ip": null, "egress_ips": {}, "egress_city": null, "egress_country": null, ` +
		`"routing_activity": {"repairs": 2, "last_repair_at": "2026-10-12T11:58:00Z", "events": 40, "relevant_events": 12, "events_lost": 1, "periodic_passes": 30}}`
	if err := os.WriteFile(filepath.Join(dir, "state", "applier", "result.json"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "run", "molebridge"), 0o755); err != nil {
		t.Fatal(err)
	}
	lease := `{"state": "held", "generation": "x", "expiry_boot_ns": 1017000000000, "updated_boot_ns": 1000000000000, "grace_s": 30}`
	if err := os.WriteFile(filepath.Join(dir, "run", "molebridge", "lease.json"), []byte(lease), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	clock := func() time.Duration { return 1003 * time.Second }
	code := statusMain(nil, env, clock, func() time.Time { return now.Add(time.Second) }, &stdout, &stderr)
	out := stdout.String()
	for _, want := range []string{
		"state: failed (failed)",
		"reasons: routing-failed, netbird-failed, owner_record-failed, traffic_protection-failed",
		"message: exit owner stopped responding",
		"lease: held, 14 s to expiry",
		"routing activity: repairs 2 (last 2026-10-12T11:58:00Z), kernel events 40 (relevant 12), event losses 1, periodic passes 30",
		"version: dev\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if code != 1 {
		t.Errorf("exit %d", code)
	}
	if strings.Contains(out, testKey) {
		t.Error("status printed key material")
	}
	_ = exit.DefaultStateDir
}
