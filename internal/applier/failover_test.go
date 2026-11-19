package applier

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/failover"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

// Automatic failover in the applier (failover.go), against the fake kernel:
// three servers in one city, the primary's handshake going stale.

const thirdHost = "se-sto-wg-003"

// foRig is an applier with failover on and the fake kernel's handshake
// age following the live peer: stale for the keys in bad.
type foRig struct {
	t      *testing.T
	a      *Applier
	k      *kernel
	dir    string
	bad    map[string]bool
	uplink bool
}

func failoverConfig() failover.Config {
	return failover.Config{Mode: failover.ModeSameCity, After: failover.DefaultAfter, Return: failover.ReturnAuto}
}

func newFoRig(t *testing.T, cfg failover.Config, server string) *foRig {
	t.Helper()
	r := &foRig{t: t, k: newKernel(t), dir: t.TempDir(), bad: map[string]bool{}, uplink: true}
	r.k.keys = []string{otherKey}
	writeSnapshot(t, r.dir, "", map[string]any{testHost: mullvadEntry(testHost, testKey),
		otherHost: mullvadEntry(otherHost, otherKey), thirdHost: mullvadEntry(thirdHost, thirdKey)})
	r.k.handler = func(req netx.Request) (netx.Response, error) {
		if req.URL == providers.MullvadRelaysURL && req.Method == "HEAD" {
			if !r.uplink {
				return netx.Response{}, errors.New("injected: no route")
			}
			return netx.Response{Status: 200}, nil
		}
		return r.k.defaultHandler(req)
	}
	r.k.afterReplacePeer = r.follow
	r.a = r.build(cfg, server)
	return r
}

func (r *foRig) build(cfg failover.Config, server string) *Applier {
	r.t.Helper()
	k := r.k
	a, err := New(Config{StateDir: r.dir, Exit: k.exit, Provider: NewMullvad(), System: k, Server: server, BootID: testBoot,
		Monotonic: k.clock, Sleep: k.sleep, Log: func(s string) { k.logs = append(k.logs, s) }, Failover: cfg})
	if err != nil {
		r.t.Fatal(err)
	}
	a.nextCatalog = infinity
	a.ownerCheck = func() validate.Obj { return validate.Members("state", "pass", "at", validate.FormatTime(time.Now())) }
	return a
}

// follow sets the handshake for the live peer.
func (r *foRig) follow() {
	r.k.age = 1
	if len(r.k.keys) == 1 && r.bad[r.k.keys[0]] {
		r.k.age = 400
	}
}

func (r *foRig) breakKey(key string, broken bool) {
	r.bad[key] = broken
	r.follow()
}

// oldRequest is a panel request made long enough ago not to be fresh.
func oldRequest(server, id string) map[string]any {
	return requestAt(server, map[string]any{"requested_at": validate.FormatTime(time.Now().Add(-time.Hour)), "request_id": id})
}

// run ticks every 5 s of the boot clock for seconds, returning the last
// record published.
func (r *foRig) run(seconds float64) *Record {
	r.t.Helper()
	var last *Record
	for end := r.k.now + seconds; r.k.now < end; r.k.now += PollSec {
		if rec := mustTick(r.t, r.a); rec != nil {
			last = rec
		}
	}
	return last
}

// until ticks until cond holds of a published record, at most seconds.
func (r *foRig) until(seconds float64, cond func(*Record) bool) *Record {
	r.t.Helper()
	for end := r.k.now + seconds; r.k.now < end; r.k.now += PollSec {
		if rec := mustTick(r.t, r.a); rec != nil && cond(rec) {
			return rec
		}
	}
	r.t.Fatalf("not reached in %v s; state %+v; logs %v", seconds, r.a.fo, r.k.logs)
	return nil
}

func failoverOf(rec *Record) map[string]any {
	m, _ := rec.Decoded()["failover"].(map[string]any)
	return m
}

func sourceOf(rec *Record) any { return rec.Decoded()["selection"].(map[string]any)["source"] }

func onServer(server string) func(*Record) bool {
	return func(rec *Record) bool { return status(rec) == "ok" && rec.Get("server") == server }
}

func (r *foRig) verifiedOnPrimary() {
	r.t.Helper()
	desire(r.t, r.a, oldRequest(testHost, strings.Repeat("0", 32)))
	r.until(120, onServer(testHost))
	if r.a.location.Server != testHost {
		r.t.Fatalf("location %+v", r.a.location)
	}
}

func TestAFailingPrimaryMovesToABackupInTheSameCity(t *testing.T) {
	r := newFoRig(t, failoverConfig(), "")
	r.verifiedOnPrimary()
	r.breakKey(testKey, true)
	start := r.k.now
	// The first record on the backup already says on-backup.
	rec := r.until(900, onServer(otherHost))
	if r.k.now-start < 300 {
		t.Fatalf("moved after %v s", r.k.now-start)
	}
	fo := failoverOf(rec)
	if fo["phase"] != "on-backup" || r.k.mutations == nil {
		t.Fatalf("the first record on the backup: %v", rec.Decoded())
	}
	if sourceOf(rec) != "failover" || rec.Get("requested_server") != testHost || fo["from"] != testHost ||
		fo["to"] != otherHost || fo["reason"] != "handshake-failed" || fo["next_return_at"] == nil {
		t.Fatalf("record %v", rec.Decoded())
	}
	if !r.k.logged("the selected server has kept failing for") || !r.k.logged("moving to backup "+otherHost) {
		t.Fatalf("logs %v", r.k.logs)
	}
	v := r.a.assess(r.a.judged(rec).Decoded())
	if v.State != "ok" || v.Label != verdict.BackupLabel {
		t.Fatalf("the exit's verdict %s %s %v", v.State, v.Label, v.Reasons)
	}
	target := verdict.Target{Server: testHost, Source: "panel", Request: r.a.request}
	if v := verdict.Assess(r.a.exitConfig(), r.a.judged(rec).Decoded(), target, r.a.wall()); v.State != "ok" || v.Label != verdict.BackupLabel {
		t.Fatalf("the panel's verdict %s %s %v", v.State, v.Label, v.Reasons)
	}
	if r.a.location.Server != testHost {
		t.Fatalf("the backup was remembered as the location: %+v", r.a.location)
	}
	if _, err := os.Stat(r.a.failoverPath()); err != nil {
		t.Fatal(err)
	}
	// A restart keeps the episode.
	b := r.build(failoverConfig(), "")
	if b.fo.Phase != failover.PhaseOnBackup || b.fo.Backup != otherHost {
		t.Fatalf("loaded %+v", b.fo)
	}
}

func TestAFailedReturnRestoresTheBackupAndALaterOneEndsTheEpisode(t *testing.T) {
	r := newFoRig(t, failoverConfig(), "")
	r.verifiedOnPrimary()
	r.breakKey(testKey, true)
	r.until(900, func(rec *Record) bool { return failoverOf(rec)["phase"] == "on-backup" })
	// The first return, 15 minutes on: the primary is still broken.
	r.until(1200, func(rec *Record) bool { return failoverOf(rec)["phase"] == "returning" })
	if !r.k.logged("trying the selected server again") {
		t.Fatalf("logs %v", r.k.logs)
	}
	rec := r.until(300, func(rec *Record) bool { return onServer(otherHost)(rec) && failoverOf(rec)["phase"] == "on-backup" })
	if !r.k.logged("the selected server still fails; back to backup " + otherHost) {
		t.Fatalf("logs %v", r.k.logs)
	}
	if r.a.fo.ReturnStep != 1 {
		t.Fatalf("state %+v", r.a.fo)
	}
	_ = rec
	// Repaired: the next return, 30 minutes on, ends the episode.
	r.breakKey(testKey, false)
	rec = r.until(2400, func(rec *Record) bool { return onServer(testHost)(rec) && failoverOf(rec) == nil })
	if sourceOf(rec) == "failover" || !r.k.logged("the selected server verified again; failover ended") {
		t.Fatalf("source %v logs %v", sourceOf(rec), r.k.logs)
	}
	v := r.a.assess(r.a.judged(rec).Decoded())
	if v.State != "ok" || v.Label != "connected" {
		t.Fatalf("verdict %s %s", v.State, v.Label)
	}
}

func TestNoBackupVerifiesExhaustsTheEpisode(t *testing.T) {
	r := newFoRig(t, failoverConfig(), "")
	r.verifiedOnPrimary()
	r.breakKey(testKey, true)
	r.breakKey(otherKey, true)
	r.breakKey(thirdKey, true)
	rec := r.until(1800, func(rec *Record) bool { return failoverOf(rec)["phase"] == "exhausted" })
	fo := failoverOf(rec)
	if fo["to"] != nil || len(fo["tried"].([]any)) != 2 || !r.k.logged("no backup verified; staying on the selected server") {
		t.Fatalf("failover %v logs %v", fo, r.k.logs)
	}
	if !r.k.logged("backup " + otherHost + " did not verify; trying the next") {
		t.Fatalf("logs %v", r.k.logs)
	}
	rec = r.until(300, func(rec *Record) bool { return rec.Get("server") == testHost })
	v := r.a.assess(r.a.judged(rec).Decoded())
	if v.State == "ok" || v.Reasons[len(v.Reasons)-1] != verdict.ReasonFailoverExhausted {
		t.Fatalf("verdict %s %v", v.State, v.Reasons)
	}
}

func TestTheUplinkDownNeverFailsOver(t *testing.T) {
	r := newFoRig(t, failoverConfig(), "")
	r.verifiedOnPrimary()
	r.breakKey(testKey, true)
	r.uplink = false
	r.run(900)
	if r.a.fo.Phase != "" || r.a.target.Server != testHost || !r.k.logged("the host's network does not answer; not failing over") {
		t.Fatalf("state %+v logs %v", r.a.fo, r.k.logs)
	}
	if len(r.k.requestsTo(providers.MullvadRelaysURL)) == 0 {
		t.Fatal("no probe")
	}
	r.uplink = true
	r.until(300, onServer(otherHost))
}

// A server that stops hearing the exit (the system rig's drill drops its
// WireGuard input) keeps asking for a handshake, so the peer still receives,
// and the exit's last handshake stays fresh for up to three minutes. The
// first unanswered check counts, and the failover comes FAILOVER_AFTER later
// with the next periodic check.
func TestAServerThatStopsHearingTheExitCountsFromTheFirstCheck(t *testing.T) {
	r := newFoRig(t, failoverConfig(), "")
	r.verifiedOnPrimary()
	r.k.egressOK, r.k.unheard = false, true
	dropped, first := r.k.now, 0.0
	for r.a.fo.Phase == "" && r.k.now < dropped+900 {
		// The handshake was 60 s old at the drop and is never renewed.
		r.k.age = 60 + int(r.k.now-dropped)
		mustTick(t, r.a)
		if first == 0 && r.a.fo.Failures > 0 {
			first = r.k.now
			if r.a.fo.Reason != failover.ReasonTunnelSilent || r.k.age >= HandshakeFreshSec {
				t.Fatalf("the first count: %+v with the handshake %d s old", r.a.fo, r.k.age)
			}
		}
		r.k.now += PollSec
	}
	moved := r.k.now - PollSec
	if first == 0 || first-dropped > RefreshSec+EgressRetrySec+2*EgressRetryBudgetSec {
		t.Fatalf("the count started %v s after the drop; logs %v", first-dropped, r.k.logs)
	}
	if r.a.fo.Phase != failover.PhaseTrying || moved-first > failover.DefaultAfter.Seconds()+RefreshSec {
		t.Fatalf("failed over %v s after the first count (%+v); logs %v", moved-first, r.a.fo, r.k.logs)
	}
	if !r.k.logged("the selected server has kept failing for 300 s") {
		t.Fatalf("logs %v", r.k.logs)
	}
}

func TestFailuresThatAreNotTheServersNeverFailOver(t *testing.T) {
	cases := map[string]func(r *foRig){
		// The provider's check service is down, the tunnel receives.
		"check service down": func(r *foRig) { r.k.egressOK = false },
		// The check service drops the requests: the server heard them and
		// sends only its passive keepalives, 32 bytes each.
		"check service silent": func(r *foRig) { r.k.egressOK, r.k.keepalives = false, true },
		// An answer that doesn't confirm the egress.
		"not confirmed": func(r *foRig) {
			for f := range r.k.probes {
				r.k.probes[f]["mullvad_exit_ip"] = false
			}
		},
		// No fresh catalogue: no candidates, and the gates hold changes.
		"stale catalogue": func(r *foRig) { r.breakKey(testKey, true); staleCatalogue(r.a) },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			r := newFoRig(t, failoverConfig(), "")
			r.verifiedOnPrimary()
			breakIt(r)
			r.run(1200)
			if r.a.fo.Phase != "" || r.k.logged("moving to backup") {
				t.Fatalf("state %+v logs %v", r.a.fo, r.k.logs)
			}
		})
	}
}

func TestAPanelRequestEndsAnEpisodeAtOnce(t *testing.T) {
	r := newFoRig(t, failoverConfig(), "")
	r.verifiedOnPrimary()
	r.breakKey(testKey, true)
	r.until(900, func(rec *Record) bool { return failoverOf(rec)["phase"] == "on-backup" })
	r.breakKey(testKey, false)
	desire(t, r.a, requestAt(testHost, map[string]any{"request_id": strings.Repeat("1", 32)}))
	rec := mustTick(t, r.a)
	if rec == nil || status(rec) != "ok" || rec.Get("server") != testHost || failoverOf(rec) != nil || r.a.fo.Phase != "" {
		t.Fatalf("record %v state %+v", rec.Decoded(), r.a.fo)
	}
	if !r.k.logged("a new selection ends the failover") {
		t.Fatalf("logs %v", r.k.logs)
	}
}

func TestFailoverWithTheConfiguredServer(t *testing.T) {
	r := newFoRig(t, failoverConfig(), testHost)
	r.until(120, onServer(testHost))
	r.breakKey(testKey, true)
	rec := r.until(900, func(rec *Record) bool { return onServer(otherHost)(rec) && failoverOf(rec)["phase"] == "on-backup" })
	if rec.Get("configured_server") != testHost {
		t.Fatalf("record %v", rec.Decoded())
	}
	if v := r.a.assess(r.a.judged(rec).Decoded()); v.State != "ok" || v.Label != verdict.BackupLabel {
		t.Fatalf("verdict %s %s %v", v.State, v.Label, v.Reasons)
	}
}

func TestFailoverChainsAfterTheRetiredServersMove(t *testing.T) {
	r := newFoRig(t, failoverConfig(), "")
	r.verifiedOnPrimary()
	retire(r.a, testHost)
	r.until(300, onServer(otherHost))
	r.breakKey(otherKey, true)
	rec := r.until(900, func(rec *Record) bool { return onServer(thirdHost)(rec) && failoverOf(rec)["phase"] == "on-backup" })
	from, to := movedOf(rec)
	if from != testHost || to != otherHost || failoverOf(rec)["from"] != otherHost || rec.Get("requested_server") != testHost {
		t.Fatalf("moved %v -> %v failover %v", from, to, failoverOf(rec))
	}
	target := verdict.Target{Server: testHost, Source: "panel", Request: r.a.request}
	if v := verdict.Assess(r.a.exitConfig(), r.a.judged(rec).Decoded(), target, r.a.wall()); v.State != "ok" || v.Label != verdict.BackupLabel {
		t.Fatalf("the panel's verdict %s %s %v", v.State, v.Label, v.Reasons)
	}
}

func TestAMalformedOrForeignFailoverFileIsNoEpisode(t *testing.T) {
	r := newFoRig(t, failoverConfig(), "")
	r.verifiedOnPrimary()
	r.breakKey(testKey, true)
	r.until(900, func(rec *Record) bool { return failoverOf(rec)["phase"] == "on-backup" })
	raw, err := os.ReadFile(r.a.failoverPath())
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"not json":         "{",
		"another mode":     strings.Replace(string(raw), `"same-city|"`, `"same-country|"`, 1),
		"an unknown phase": strings.Replace(string(raw), `"on-backup"`, `"standby"`, 1),
		"a bad name":       strings.Replace(string(raw), `"`+otherHost+`"`, `"not a server"`, 1),
	} {
		if content == string(raw) {
			t.Fatalf("%s: the replacement changed nothing in %s", name, raw)
		}
		writeFile(t, r.a.failoverPath(), content, 0o600)
		if b := r.build(failoverConfig(), ""); b.fo.Phase != "" || b.foKey != "" {
			t.Errorf("%s: loaded %+v", name, b.fo)
		}
	}
	// Failover turned off drops the file.
	r.build(failover.Config{Mode: failover.ModeOff}, "")
	if _, err := os.Stat(r.a.failoverPath()); !os.IsNotExist(err) {
		t.Fatalf("file kept: %v", err)
	}
}

func TestFailoverOffChangesNothing(t *testing.T) {
	r := newFoRig(t, failover.Config{Mode: failover.ModeOff}, "")
	r.verifiedOnPrimary()
	r.breakKey(testKey, true)
	transfers := r.k.countCalls("Transfers")
	r.run(1200)
	if r.a.target.Server != testHost || r.k.logged("backup") || r.k.countCalls("Transfers") != transfers ||
		len(r.k.requestsTo(providers.MullvadRelaysURL)) != 0 {
		t.Fatalf("logs %v", r.k.logs)
	}
	if _, err := os.Stat(r.a.failoverPath()); !os.IsNotExist(err) {
		t.Fatalf("failover.json written: %v", err)
	}
}

func TestFailoverRefusesTheGluetunBackend(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	_, err := New(Config{StateDir: t.TempDir(), Exit: f.k.exit, Provider: f.provider, System: f.k, BootID: testBoot,
		Monotonic: f.k.clock, Failover: failoverConfig()})
	if err == nil || !strings.Contains(err.Error(), "failover") {
		t.Fatalf("err %v", err)
	}
}

// classify against the rows of the design's eligibility tables.
func TestClassify(t *testing.T) {
	checks := func(handshake, egress, reason string) validate.Obj {
		e := validate.Members("state", egress)
		if reason != "" {
			e = e.Set("reason", reason)
		}
		return validate.Members("peer", validate.Members("state", "pass"), "handshake", validate.Members("state", handshake), "egress", e)
	}
	finding := func(status, server string, c validate.Obj) *Finding {
		return &Finding{Status: status, Server: server, Checks: c, Safe: true}
	}
	quiet := finding("failed", testHost, checks("pass", "fail", "unanswered"))
	quiet.Quiet = true
	silent := finding("failed", testHost, checks("pass", "fail", "tunnel-silent"))
	silent.Silent = true
	unsafe := finding("failed", testHost, checks("pass", "pass", ""))
	unsafe.Safe = false
	for _, c := range []struct {
		name              string
		state, target     string
		f                 *Finding
		mutated, repaired bool
		want              failover.Outcome
		reason            string
	}{
		{"verified", "idle", testHost, finding("ok", testHost, checks("pass", "pass", "")), false, false, failover.Verified, ""},
		{"verified after a change", "idle", testHost, finding("ok", testHost, checks("pass", "pass", "")), true, false, failover.Verified, ""},
		{"a change that failed", "failed", testHost, finding("failed", otherHost, checks("pass", "pass", "")), true, false, failover.Eligible, failover.ReasonSwitchFailed},
		{"a failed change re-checked", "failed", testHost, finding("failed", otherHost, checks("pass", "pass", "")), false, false, failover.None, ""},
		{"a stale handshake", "idle", testHost, finding("failed", testHost, checks("fail", "pass", "")), false, false, failover.Eligible, failover.ReasonHandshakeFailed},
		{"applied, unverified, stale", "unverified", testHost, finding("failed", testHost, checks("fail", "pass", "")), true, false, failover.Eligible, failover.ReasonHandshakeFailed},
		{"unanswered, nothing received", "idle", testHost, quiet, false, false, failover.Eligible, failover.ReasonTunnelSilent},
		{"PIA's silent tunnel", "idle", testHost, silent, false, false, failover.Eligible, failover.ReasonTunnelSilent},
		{"a repair that didn't verify", "unverified", testHost, finding("failed", testHost, checks("fail", "pass", "")), true, true, failover.Eligible, failover.ReasonRepairFailed},
		{"unanswered while receiving", "idle", testHost, finding("failed", testHost, checks("pass", "fail", "unanswered")), false, false, failover.Ineligible, ""},
		{"not confirmed", "idle", testHost, finding("failed", testHost, checks("pass", "fail", "not-confirmed")), false, false, failover.Ineligible, ""},
		{"pending", "pending", testHost, finding("failed", testHost, checks("fail", "fail", "unanswered")), false, false, failover.Ineligible, ""},
		{"rejected", "rejected", testHost, finding("failed", "", nil), true, false, failover.Ineligible, ""},
		{"a guard lost", "failed", testHost, unsafe, true, false, failover.Ineligible, ""},
		{"another server live", "idle", testHost, finding("failed", otherHost, checks("fail", "pass", "")), false, false, failover.None, ""},
		{"no finding", "idle", testHost, nil, false, false, failover.None, ""},
		{"a routing failure", "idle", testHost, finding("failed", testHost, checks("pass", "pass", "")), false, false, failover.Ineligible, ""},
	} {
		got, reason := classify(c.state, c.target, c.f, c.mutated, c.repaired)
		if got != c.want || reason != c.reason {
			t.Errorf("%s: %v %q, want %v %q", c.name, got, reason, c.want, c.reason)
		}
	}
}

func TestSelectionKeysOfFailoverTargets(t *testing.T) {
	primary := &Selection{Server: testHost, Source: "configured"}
	backup := &Selection{Server: otherHost, Source: "failover", Failover: &FailoverOf{Primary: testHost, Source: "configured"}}
	returning := &Selection{Server: testHost, Source: "failover", Failover: &FailoverOf{Primary: testHost, Source: "configured"}}
	keys := map[string]bool{primary.Key(): true, backup.Key(): true, returning.Key(): true}
	if len(keys) != 3 || !strings.HasPrefix(backup.Key(), primary.Key()+"|failover:") {
		t.Fatalf("keys %v", keys)
	}
	if target := backup.target(); target.Server != testHost || target.Source != "configured" {
		t.Fatalf("target %+v", target)
	}
}
