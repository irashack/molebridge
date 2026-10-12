// Tests ported from tools/test_gluetun_transition.py: the applier's collection
// of gluetun's reconnection states during a switch (transition_status), against
// a fake that behaves as Linux and the guard do. The protective predicate
// itself (gluetun_transition_status and family_status: the reconnection steps
// and their twins, the rule-94 forms, the conditional rules 90 to 92) is
// internal/contract's tests; what is here is what the applier adds: the sampling
// of the interface before and after, the detached rules, the three-sample limit
// and what a switch does with the answer. Nothing touches a kernel.
package applier

import (
	"context"
	"testing"

	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/validate"
)

// reconnectingFixture is the Python reconnecting(): the Reconnecting kernel
// with gluetun's PUT starting its phases.
func reconnectingFixture(t testing.TB) (*glFixture, *reconnecting) {
	t.Helper()
	k := newGlKernel(t, glRouting(t))
	rc := &reconnecting{address: rcOld, ifindex: 7}
	k.rc = rc
	f := newGluetunFixture(t, glOptions{kernel: k})
	f.control.onPut = rc.put
	return f, rc
}

func TestAnOrdinarySwitchWithEveryReconnectionStateSucceeds(t *testing.T) {
	f, _ := reconnectingFixture(t)
	statuses := withPublished(f.a, f.dir)
	r := f.a.switchTo(t, glRequest(hostB))
	if status(r) != "ok" || r.Get("server") != hostB {
		t.Fatalf("%s %q", status(r), message(r))
	}
	for _, s := range *statuses {
		if s == "failed" {
			t.Errorf("a failed record during the switch: %v", *statuses)
		}
	}
	if f.a.attempt.State != "idle" {
		t.Errorf("attempt %s", f.a.attempt.State)
	}
}

func TestAStableViolationDuringTheSwitchAborts(t *testing.T) {
	f, rc := reconnectingFixture(t)
	rc.third = true
	r := f.a.switchTo(t, glRequest(hostB))
	if status(r) != "failed" || f.a.attempt.State != "failed" || message(r) != "Routing changed during the switch; retrying after recovery." {
		t.Errorf("%s %s %q", status(r), f.a.attempt.State, message(r))
	}
}

func TestEveryReconnectionRecordCarriesTheReconnectingReason(t *testing.T) {
	// measure_guards while a switch is verified: routing fails with the
	// "reconnecting" reason while the guard is safe, traffic protection follows
	// routing, and an unsafe state has no reason.
	f, rc := reconnectingFixture(t)
	f.a.switchDeadline = floatPtr(infinity)
	rc.put(hostB)
	at := "2026-01-01T00:00:00Z"
	finding := f.a.newFinding()
	f.provider.MeasureGuards(context.Background(), f.a, at, finding)
	check := recordCheck(finding, "routing")
	if check["state"] != "fail" || check["reason"] != "reconnecting" || check["fallback"] != true || check["at"] != at {
		t.Errorf("routing %v", check)
	}
	if tp := recordCheck(finding, "traffic_protection"); tp["state"] != "fail" || tp["from"] != "routing" {
		t.Errorf("traffic_protection %v", tp)
	}
	if !finding.Safe || finding.Guard != RoutingFailed {
		t.Errorf("safe %v guard %q", finding.Safe, finding.Guard)
	}
	// Unsafe: no reason, and the finding is not safe.
	rc.third = true
	finding = f.a.newFinding()
	f.provider.MeasureGuards(context.Background(), f.a, at, finding)
	if check := recordCheck(finding, "routing"); check["state"] != "fail" || check["reason"] != nil || check["fallback"] != false {
		t.Errorf("unsafe routing %v", check)
	}
	if finding.Safe {
		t.Error("an unsafe state is safe")
	}
}

func recordCheck(f *Finding, name string) map[string]any {
	for _, p := range f.Checks {
		if p.Key == name {
			r := &Record{members: validate.Members("check", p.Value)}
			return r.Decoded()["check"].(map[string]any)
		}
	}
	return nil
}

func floatPtr(v float64) *float64 { return &v }

func TestASampleTakenWhileTheInterfaceChangedIsTakenAgain(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	links := []uint32{1, 2, 2, 2}
	f.k.linkScript = func() TunnelLink {
		index := links[0]
		links = links[1:]
		return TunnelLink{Present: true, Up: true, Index: index}
	}
	f.provider.previous = map[int]string{4: glTunnel4}
	safe, ready, err := f.provider.transitionStatus(context.Background(), f.a)
	if err != nil || !safe || !ready {
		t.Errorf("(%v, %v, %v)", safe, ready, err)
	}
	if len(links) != 0 {
		t.Errorf("%d link reads left", len(links))
	}
}

func TestThreeContradictorySamplesWithholdReadinessWithoutAborting(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	var n uint32
	f.k.linkScript = func() TunnelLink {
		n++
		return TunnelLink{Present: true, Up: true, Index: n}
	}
	f.provider.previous = map[int]string{4: glTunnel4}
	safe, ready, err := f.provider.transitionStatus(context.Background(), f.a)
	if err != nil || !safe || ready {
		t.Errorf("(%v, %v, %v)", safe, ready, err)
	}
	if n != 2*TransitionSamples {
		t.Errorf("%d link reads, want %d", n, 2*TransitionSamples)
	}
}

func TestAnInterfacePresentWithDetachedRulesIsSampledAgain(t *testing.T) {
	f := newGluetunFixture(t, glOptions{})
	for i, r := range f.k.rules[4] {
		if r.Priority == 96 {
			f.k.rules[4][i].Flags |= rtnl.FIBRuleOifDetached
		}
	}
	f.provider.previous = map[int]string{4: glTunnel4}
	safe, ready, err := f.provider.transitionStatus(context.Background(), f.a)
	if err != nil || !safe || ready {
		t.Errorf("(%v, %v, %v)", safe, ready, err)
	}
}

func TestDetachedRulesWithoutAnInterfaceAreTheReconnectionNotASampleToRepeat(t *testing.T) {
	// While the interface is absent Linux detaches rules 90 and 96: that is the
	// state the predicate tolerates, and nothing is sampled again for it.
	f := newGluetunFixture(t, glOptions{})
	f.k.tunnel = ""
	for _, priority := range []uint32{90, 96} {
		for i, r := range f.k.rules[4] {
			if r.Priority == priority {
				f.k.rules[4][i].Flags |= rtnl.FIBRuleIifDetached | rtnl.FIBRuleOifDetached
			}
		}
	}
	reads := f.k.countCalls("GluetunLinks")
	safe, _, err := f.provider.transitionStatus(context.Background(), f.a)
	if err != nil || !safe {
		t.Errorf("safe %v, %v", safe, err)
	}
	if got := f.k.countCalls("GluetunLinks") - reads; got != 2 {
		t.Errorf("%d link reads, want one sample (2)", got)
	}
}

func TestATransitionReadThatFailsIsNotSafe(t *testing.T) {
	// measure_guards: any failure to read is unsafe and not ready.
	f := newGluetunFixture(t, glOptions{})
	f.a.switchDeadline = floatPtr(infinity)
	f.k.returnPath = "0\n"
	finding := f.a.newFinding()
	f.provider.MeasureGuards(context.Background(), f.a, "2026-01-01T00:00:00Z", finding)
	if finding.Safe && finding.Guard == "" {
		t.Errorf("safe %v guard %q", finding.Safe, finding.Guard)
	}
	f.k.returnPath = "1\n"
	f.k.overlayPresent = false
	finding = f.a.newFinding()
	f.provider.MeasureGuards(context.Background(), f.a, "2026-01-01T00:00:00Z", finding)
	if finding.Safe || finding.Guard != RoutingFailed {
		t.Errorf("safe %v guard %q", finding.Safe, finding.Guard)
	}
}
