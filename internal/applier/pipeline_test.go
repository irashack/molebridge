// Tests ported from tools/test_pipeline.py: the admission pipeline and its
// persisted attempt (applier/apply.py, applier/attempt.py), against the fake
// kernel. Nothing touches a live tunnel.
//
// Not ported: test_deadlines_from_another_boot_are_rebased and
// test_an_unreadable_attempt_starts_idle (internal/attempt's own tests) and
// test_native_aborts_when_the_owner_record_is_lost_during_a_switch (the
// supervisor's lease replaces the owner record, decision D7).
package applier

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/attempt"
	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
)

// pipelineSetup is the Python `setup` fixture: live on the other server, so a
// switch is needed.
func pipelineSetup(t testing.TB) (*Applier, *kernel, string) {
	t.Helper()
	dir := t.TempDir()
	k := newKernel(t)
	k.keys = []string{otherKey}
	return buildApplier(t, k, dir, NewMullvad(), ""), k, dir
}

// buildApplier is the Python build(): the snapshot with both relays, an applier.
func buildApplier(t testing.TB, k *kernel, dir string, provider Provider, server string) *Applier {
	t.Helper()
	writeSnapshot(t, dir, "", map[string]any{testHost: mullvadEntry(testHost, testKey), otherHost: mullvadEntry(otherHost, otherKey)})
	return newApplier(t, k, dir, provider, server)
}

func saved(t testing.TB, dir string) map[string]any {
	t.Helper()
	m, ok := jsonfile.ReadObject(dir+"/applier/attempt.json", 16384)
	if !ok {
		t.Fatal("no attempt.json")
	}
	return m
}

func TestTheAttemptIsWrittenBeforeAnyMutationIO(t *testing.T) {
	dir := t.TempDir()
	k := newKernel(t)
	k.keys = []string{otherKey}
	o := &overridden{Provider: NewMullvad()}
	a := buildApplier(t, k, dir, o, "")
	var seen map[string]any
	o.applyRelay = func(ctx context.Context, a *Applier, relay *providers.Relay, keys []string) error {
		seen = saved(t, dir)
		return NewMullvad().ApplyRelay(ctx, a, relay, keys)
	}
	desire(t, a, requestAt(testHost, nil))
	if r := mustTick(t, a); status(r) != "ok" {
		t.Fatalf("%s %s", status(r), message(r))
	}
	if seen["state"] != "attempting" || seen["target"] != testHost || seen["attempts"] != int64(1) ||
		seen["mutation_certainty"] != "uncertain" || seen["boot_id"] != testBoot {
		t.Fatalf("saved before the I/O: %v", seen)
	}
	after := saved(t, dir)
	if after["state"] != "idle" || after["outcome"] != "verified" || after["backoff_step"] != int64(0) {
		t.Fatalf("after: %v", after)
	}
}

func TestThePublishedSelectionSaysWhyAndHow(t *testing.T) {
	a, _, _ := pipelineSetup(t)
	desire(t, a, requestAt(testHost, nil))
	r := mustTick(t, a)
	d := r.Decoded()
	sel := d["selection"].(map[string]any)
	if d["schema"] != int64(2) || d["kind"] != "overlay" || d["backend"] != "native" {
		t.Errorf("record %v", d)
	}
	want := map[string]any{"source": "panel", "outcome": "verified", "attempt": int64(1), "target": testHost,
		"next_action": nil, "next_action_at": nil}
	for key, value := range want {
		if sel[key] != value {
			t.Errorf("selection[%s] = %v, want %v", key, sel[key], value)
		}
	}
	if len(sel) != len(want) {
		t.Errorf("selection %v", sel)
	}
}

// -- crash at every boundary -----------------------------------------------------------

func restart(t testing.TB, k *kernel, dir string) *Applier {
	return buildApplier(t, k, dir, NewMullvad(), "")
}

// interrupted persists an attempt as `attempting`, as a crash leaves it.
func interrupted(t testing.TB, k *kernel, dir string, liveAfter bool) {
	t.Helper()
	at := attempt.New(time.Now(), attempt.NewParams{Source: "panel", Target: testHost, TargetKey: strings.Repeat("0", 32), BootID: testBoot})
	at.State, at.Attempts = "attempting", 1
	last := k.now
	at.LastMutationAt = &last
	at.MutationCertainty = "uncertain"
	if err := at.Save(dir + "/applier/attempt.json"); err != nil {
		t.Fatal(err)
	}
	if liveAfter {
		k.keys = []string{testKey}
	} else {
		k.keys = []string{otherKey}
	}
}

func TestACrashBeforeTheRecordStartsAfresh(t *testing.T) {
	a, k, dir := pipelineSetup(t)
	desire(t, a, requestAt(testHost, nil))
	a = restart(t, k, dir)
	if r := mustTick(t, a); status(r) != "ok" || len(k.adds()) != 1 {
		t.Fatalf("%s %v", status(r), k.adds())
	}
}

func TestACrashAfterTheRecordBeforeTheIOIsInspectedNotReplayed(t *testing.T) {
	a, k, dir := pipelineSetup(t)
	desire(t, a, requestAt(testHost, nil))
	interrupted(t, k, dir, false)
	a = restart(t, k, dir)
	r := mustTick(t, a)
	if len(k.adds()) != 0 || status(r) != "failed" || a.attempt.State != "failed" ||
		a.attempt.MutationCertainty != "uncertain" || a.attempt.NextAction != "reapply" {
		t.Fatalf("%s %s %v", status(r), a.attempt.State, k.adds())
	}
	k.now += float64(attempt.BackoffSec[0] - 1)
	mustTick(t, a)
	if len(k.adds()) != 0 {
		t.Fatal("reapplied early")
	}
	k.now++
	if r := mustTick(t, a); status(r) != "ok" || len(k.adds()) != 1 {
		t.Fatalf("%s %v", status(r), k.adds())
	}
}

func TestACrashAfterTheMutationTookEffectVerifiesWithoutASecond(t *testing.T) {
	for _, boundary := range []string{"after the io", "after the response"} {
		a, k, dir := pipelineSetup(t)
		desire(t, a, requestAt(testHost, nil))
		interrupted(t, k, dir, true)
		a = restart(t, k, dir)
		r := mustTick(t, a)
		if status(r) != "ok" || a.attempt.State != "idle" || len(k.adds()) != 0 {
			t.Errorf("%s: %s %s %v", boundary, status(r), a.attempt.State, k.adds())
		}
	}
}

func TestACrashWithTheTargetLiveButUnverifiedRechecks(t *testing.T) {
	a, k, dir := pipelineSetup(t)
	desire(t, a, requestAt(testHost, nil))
	interrupted(t, k, dir, true)
	k.egressOK = false
	a = restart(t, k, dir)
	r := mustTick(t, a)
	if a.attempt.State != "unverified" || r.Decoded()["selection"].(map[string]any)["next_action"] != "recheck" {
		t.Fatalf("%s %v", a.attempt.State, r.Decoded()["selection"])
	}
	for i := 0; i < 10; i++ {
		k.now += 60
		mustTick(t, a)
	}
	if len(k.adds()) != 0 {
		t.Fatal("reapplied")
	}
}

func TestRestingStatesSurviveARestartThroughTheApplier(t *testing.T) {
	for _, st := range []string{"unverified", "failed", "pending", "rejected"} {
		a, k, dir := pipelineSetup(t)
		desire(t, a, requestAt(testHost, nil))
		at := attempt.New(time.Now(), attempt.NewParams{Source: "panel", Target: testHost, TargetKey: strings.Repeat("0", 32), BootID: testBoot})
		at.State = st
		at.Message = "Example."
		if st == "failed" {
			due := 500.0
			at.NextAction, at.NextActionAt, at.BackoffStep = "reapply", &due, 2
		}
		if st == "rejected" {
			at.Extra = attempt.Extra{Why: "invalid", Release: "invalid"}
		}
		if err := at.Save(dir + "/applier/attempt.json"); err != nil {
			t.Fatal(err)
		}
		a = restart(t, k, dir)
		if a.attempt.State != st {
			t.Fatalf("%s: loaded %s", st, a.attempt.State)
		}
		mustTick(t, a)
		if a.attempt.Target != testHost {
			t.Errorf("%s: target %q", st, a.attempt.Target)
		}
		if st == "failed" && (len(k.adds()) != 0 || a.attempt.NextActionAt == nil || *a.attempt.NextActionAt != 500) {
			// Nothing before its deadline, which survived the restart.
			t.Errorf("failed: %v %v", k.adds(), a.attempt.NextActionAt)
		}
		if st == "rejected" && len(k.adds()) != 0 {
			t.Errorf("rejected: %v", k.adds())
		}
	}
}

// -- lost responses ----------------------------------------------------------------------

func TestALostResponseRecoversWithoutASecondMutation(t *testing.T) {
	dir := t.TempDir()
	k := newKernel(t)
	k.keys = []string{otherKey}
	o := &overridden{Provider: NewMullvad()}
	a := buildApplier(t, k, dir, o, "")
	o.applyRelay = func(ctx context.Context, a *Applier, relay *providers.Relay, keys []string) error {
		if err := NewMullvad().ApplyRelay(ctx, a, relay, keys); err != nil {
			return err
		}
		return errInjected // the response is lost
	}
	desire(t, a, requestAt(testHost, nil))
	// The check right after finds the target live and verified.
	if r := mustTick(t, a); status(r) != "ok" || a.attempt.State != "idle" || len(k.adds()) != 1 {
		t.Fatalf("%s %s %v", status(r), a.attempt.State, k.adds())
	}
}

func TestALostResponseAfterFailedWasPersisted(t *testing.T) {
	dir := t.TempDir()
	k := newKernel(t)
	k.keys = []string{otherKey}
	egressAsked := 0
	lose := func() *overridden {
		return &overridden{Provider: NewMullvad(), applyRelay: func(ctx context.Context, a *Applier, relay *providers.Relay, keys []string) error {
			if err := NewMullvad().ApplyRelay(ctx, a, relay, keys); err != nil {
				return err
			}
			k.egressOK = false // not verifiable at once
			egressAsked++
			return errInjected
		}}
	}
	a := buildApplier(t, k, dir, lose(), "")
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	if a.attempt.State != "failed" || saved(t, dir)["state"] != "failed" {
		t.Fatalf("%s", a.attempt.State)
	}
	// A restart, then the egress answers: verified, nothing applied again.
	a = buildApplier(t, k, dir, lose(), "")
	k.egressOK = true
	k.now += float64(attempt.BackoffSec[0])
	if r := mustTick(t, a); status(r) != "ok" || egressAsked != 1 || a.attempt.State != "idle" {
		t.Fatalf("%s %d %s", status(r), egressAsked, a.attempt.State)
	}
}

// -- triggers ------------------------------------------------------------------------------

func TestDriftWithinTheGuardWaits(t *testing.T) {
	a, k, _ := pipelineSetup(t)
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	k.keys = []string{otherKey} // something put the other server back
	k.now += attempt.ReapplyGuardSec - 10
	mustTick(t, a)
	if len(k.adds()) != 1 {
		t.Fatalf("%v", k.adds())
	}
	k.now += 10
	r := mustTick(t, a)
	if len(k.adds()) != 2 || r.Decoded()["selection"].(map[string]any)["source"] != "reconverge" {
		t.Fatalf("%v %v", k.adds(), r.Decoded()["selection"])
	}
}

func TestAMullvadRequestReconvergesAfterTunnelRecreation(t *testing.T) {
	// A recreated tunnel starts with its config's peer.
	a, k, _ := pipelineSetup(t)
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	k.now += 600
	k.keys = []string{otherKey}
	r := mustTick(t, a)
	if status(r) != "ok" || len(k.keys) != 1 || k.keys[0] != testKey || len(k.adds()) != 2 {
		t.Fatalf("%s %v %v", status(r), k.keys, k.adds())
	}
}

func TestAnUnidentifiablePeerIsWaitedOut(t *testing.T) {
	a, k, _ := pipelineSetup(t)
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	k.now += 600
	k.keys = []string{thirdKey}
	mustTick(t, a)
	k.now += attempt.UnidentifiedSec - 1
	mustTick(t, a)
	if len(k.adds()) != 1 {
		t.Fatalf("%v", k.adds())
	}
	// Identifiable again (the right one): the timer resets.
	k.keys = []string{testKey}
	mustTick(t, a)
	k.keys = []string{thirdKey}
	k.now++
	mustTick(t, a)
	if len(k.adds()) != 1 {
		t.Fatalf("%v", k.adds())
	}
	k.now += attempt.UnidentifiedSec
	mustTick(t, a)
	if len(k.adds()) != 2 || k.keys[0] != testKey {
		t.Fatalf("%v %v", k.adds(), k.keys)
	}
}

func TestANewOwnerGenerationReappliesOnceAtOnce(t *testing.T) {
	dir := t.TempDir()
	k := newKernel(t)
	k.keys = nil
	a := buildApplier(t, k, dir, NewMullvad(), "")
	k.generation = "0a0a"
	desire(t, a, requestAt(testHost, nil))
	if r := mustTick(t, a); status(r) != "ok" || len(k.adds()) != 1 {
		t.Fatalf("%s %v", status(r), k.adds())
	}
	// The wireguard container started again: no peer, new generation.
	k.now += attempt.ReapplyGuardSec
	k.keys = nil
	k.generation = "0b0b"
	if r := mustTick(t, a); status(r) != "ok" || len(k.adds()) != 2 {
		t.Fatalf("%s %v", status(r), k.adds())
	}
	// A failure backing off: no peer in the same generation waits for the
	// backoff; a new generation is re-applied once at once.
	k.now += attempt.ReapplyGuardSec
	k.failSet = true
	k.keys = []string{otherKey}
	desire(t, a, requestAt(testHost, map[string]any{"request_id": strings.Repeat("9", 32)}))
	mustTick(t, a)
	if a.attempt.State != "failed" {
		t.Fatalf("%s", a.attempt.State)
	}
	k.failSet = false
	k.keys = nil
	late := k.now + 900 // a late backoff step
	a.attempt.NextActionAt = &late
	k.now += attempt.ReapplyGuardSec
	mustTick(t, a)
	if a.attempt.State != "failed" {
		t.Fatalf("same generation: %s", a.attempt.State)
	}
	k.generation = "0c0c"
	if r := mustTick(t, a); status(r) != "ok" || a.attempt.State != "idle" {
		t.Fatalf("%s %s", status(r), a.attempt.State)
	}
}

func TestANewOwnerGenerationStillRespectsTheGuard(t *testing.T) {
	dir := t.TempDir()
	k := newKernel(t)
	k.keys = nil
	a := buildApplier(t, k, dir, NewMullvad(), "")
	k.generation = "0a0a"
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	k.keys = nil
	k.generation = "0b0b"
	k.now += 10
	mustTick(t, a)
	if len(k.adds()) != 1 {
		t.Fatalf("%v", k.adds())
	}
}

func TestNoNativePeerWhileIdleIsAppliedAtOnce(t *testing.T) {
	// The exit's routing loop recreated a lost tunnel from its config, which
	// (NordVPN, PIA) has no peer.
	a, k, _ := pipelineSetup(t)
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	k.now += attempt.ReapplyGuardSec
	k.keys = nil
	r := mustTick(t, a)
	if status(r) != "ok" || len(k.keys) != 1 || k.keys[0] != testKey || len(k.adds()) != 2 {
		t.Fatalf("%s %v %v", status(r), k.keys, k.adds())
	}
}

func TestNoPeerAfterAFailedMutationWaitsForTheBackoff(t *testing.T) {
	// A NordVPN-style replacement interrupted after the old peer went.
	a, k, _ := pipelineSetup(t)
	k.failSet = true
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	k.keys = nil
	k.failSet = false
	for i := 0; i < 5; i++ {
		k.now += 10
		mustTick(t, a)
	}
	if len(k.adds()) != 0 {
		t.Fatalf("%v", k.adds())
	}
	k.now += float64(attempt.BackoffSec[0])
	mustTick(t, a)
	if len(k.adds()) != 1 || a.attempt.State != "idle" {
		t.Fatalf("%v %s", k.adds(), a.attempt.State)
	}
}

func TestTheBackoffSteps(t *testing.T) {
	a, k, _ := pipelineSetup(t)
	k.failSet = true
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	var times []float64
	start := k.now
	for len(times) < 6 {
		k.now += 5
		before := a.attempt.Attempts
		mustTick(t, a)
		if a.attempt.Attempts > before {
			times = append(times, k.now-start)
			start = k.now
		}
	}
	want := []float64{60, 120, 240, 480, 900, 900}
	for i := range want {
		if times[i] != want[i] {
			t.Fatalf("steps %v, want %v", times, want)
		}
	}
}

func TestANewTargetCancelsTheBackoff(t *testing.T) {
	a, k, _ := pipelineSetup(t)
	k.failSet = true
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	if a.attempt.NextAction != "reapply" {
		t.Fatalf("%q", a.attempt.NextAction)
	}
	k.failSet = false
	desire(t, a, requestAt(otherHost, map[string]any{"request_id": strings.Repeat("1", 32)}))
	k.keys = []string{testKey}
	r := mustTick(t, a)
	if status(r) != "ok" || r.Get("server") != otherHost || a.attempt.BackoffStep != 0 || a.attempt.Source != "panel" {
		t.Fatalf("%s %v %d %s", status(r), r.Get("server"), a.attempt.BackoffStep, a.attempt.Source)
	}
}

func TestRetryNowIsANewRequestID(t *testing.T) {
	a, k, _ := pipelineSetup(t)
	k.failSet = true
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	k.failSet = false
	desire(t, a, requestAt(testHost, map[string]any{"request_id": strings.Repeat("2", 32)}))
	r := mustTick(t, a)
	if status(r) != "ok" || r.Decoded()["selection"].(map[string]any)["source"] != "operator-retry" {
		t.Fatalf("%s %v", status(r), r.Decoded()["selection"])
	}
}

func TestAnOldRequestIsInspectedFirstAFreshOneApplied(t *testing.T) {
	// An upgrade from 0.6 finds desired.json without an attempt: the server
	// already live isn't touched. A request made now is applied.
	a, k, _ := pipelineSetup(t)
	k.keys = []string{testKey}
	desire(t, a, requestAt(testHost, map[string]any{"requested_at": "2026-01-01T00:00:00Z"}))
	if r := mustTick(t, a); status(r) != "ok" || len(k.adds()) != 0 {
		t.Fatalf("%s %v", status(r), k.adds())
	}
	desire(t, a, requestAt(testHost, map[string]any{"request_id": strings.Repeat("3", 32)}))
	if r := mustTick(t, a); status(r) != "ok" || len(k.adds()) != 1 {
		t.Fatalf("%s %v", status(r), k.adds())
	}
}

func TestNativeAbortsWhenNetbirdIsLostDuringASwitch(t *testing.T) {
	a, k, _ := pipelineSetup(t)
	k.afterReplacePeer = func() { k.overlayWG = false }
	desire(t, a, requestAt(testHost, nil))
	r := mustTick(t, a)
	sel := r.Decoded()["selection"].(map[string]any)
	if status(r) != "failed" || a.attempt.State != "failed" || sel["outcome"] != "mutation-failed" || k.now >= 10 {
		t.Fatalf("%s %s %v %v", status(r), a.attempt.State, sel, k.now)
	}
}

// -- Gatus ----------------------------------------------------------------------------------

func withGatus(a *Applier) {
	a.gatus = Gatus{URL: "https://gatus.example.test", Token: "token"}
}

func TestGatusGetsTheVerdictAndNeverApplying(t *testing.T) {
	a, k, _ := pipelineSetup(t)
	withGatus(a)
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	if len(k.pushed) != 1 || k.pushed[0] != "success=true&error=" {
		t.Fatalf("%v", k.pushed)
	}
	k.egressOK = false
	k.now += 60
	mustTick(t, a)
	if last := k.pushed[len(k.pushed)-1]; !strings.HasPrefix(last, "success=false&error=") {
		t.Fatalf("%v", k.pushed)
	}
	// The request goes to the endpoint, authenticated by a header, never a URL.
	push := k.requestsTo("/external?")[0]
	if push.Method != "POST" || push.Header["Authorization"] != "Bearer token" || strings.Contains(push.URL, "token") ||
		!strings.HasPrefix(push.URL, "https://gatus.example.test/api/v1/endpoints/molebridge/external?") || !push.AllowHTTP {
		t.Errorf("push %+v", push)
	}
}

func TestGatusIsOffWithoutBothSettingsOrWithAnOddURL(t *testing.T) {
	for name, gatus := range map[string]Gatus{
		"no url": {Token: "t"}, "no token": {URL: "https://gatus.example.test"},
		"ftp": {URL: "ftp://gatus.example.test", Token: "t"}, "newline": {URL: "https://gatus.example.test", Token: "t\nx"}} {
		a, k, _ := pipelineSetup(t)
		a.gatus = gatus
		desire(t, a, requestAt(testHost, nil))
		mustTick(t, a)
		if len(k.pushed) != 0 {
			t.Errorf("%s: pushed %v", name, k.pushed)
		}
	}
}

func TestAGatusPushFailureIsLoggedNotFatal(t *testing.T) {
	a, k, _ := pipelineSetup(t)
	withGatus(a)
	k.hooks = append(k.hooks, func(r netx.Request) error {
		if strings.Contains(r.URL, "/external?") {
			return errInjected
		}
		return nil
	})
	desire(t, a, requestAt(testHost, nil))
	if r := mustTick(t, a); status(r) != "ok" {
		t.Fatalf("%s", status(r))
	}
	if !k.logged("applier: monitoring push failed") {
		t.Error("not logged")
	}
}

func TestAGatusEndpointAndErrorAreEscaped(t *testing.T) {
	a, k, _ := pipelineSetup(t)
	a.gatus = Gatus{URL: "https://gatus.example.test/", Token: "token", Endpoint: "my exit/1"}
	k.egressOK = false
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	push := k.requestsTo("/external?")[0]
	if !strings.HasPrefix(push.URL, "https://gatus.example.test/api/v1/endpoints/my%20exit%2F1/external?success=false&error=") ||
		strings.ContainsAny(strings.SplitN(push.URL, "error=", 2)[1], " ;") {
		t.Errorf("url %s", push.URL)
	}
}

func TestARequestArrivingDuringVerificationIsNotJudgedByTheOldOne(t *testing.T) {
	dir := t.TempDir()
	k := newKernel(t)
	k.keys = []string{otherKey}
	o := &overridden{Provider: NewMullvad()}
	a := buildApplier(t, k, dir, o, "")
	withGatus(a)
	o.applyRelay = func(ctx context.Context, a *Applier, relay *providers.Relay, keys []string) error {
		if err := NewMullvad().ApplyRelay(ctx, a, relay, keys); err != nil {
			return err
		}
		desire(t, a, requestAt(otherHost, map[string]any{"request_id": strings.Repeat("4", 32)}))
		return nil
	}
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	// Verified, but the operator has already asked for another server.
	if len(k.pushed) != 0 {
		t.Fatalf("%v", k.pushed)
	}
}

func TestTheOverlayHealthCheckLeavesAMissingPeerToThePipeline(t *testing.T) {
	// A lost tunnel comes back without its peer; killing the worker for that
	// would only delay the repair.
	a, k, dir := pipelineSetup(t)
	withPublished(a, dir)
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	k.keys = nil
	if !a.Healthy(context.Background()) {
		t.Fatal("unhealthy without a peer")
	}
	k.tunnelPresent = false
	if a.Healthy(context.Background()) {
		t.Fatal("healthy without the tunnel interface")
	}
}
