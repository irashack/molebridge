package applier

import (
	"errors"
	"strings"
	"testing"
)

func (k *kernel) countLogged(substr string) int {
	n := 0
	for _, l := range k.logs {
		if strings.Contains(l, substr) {
			n++
		}
	}
	return n
}

// A PIA step retried on every pass logs its first failure with the cause, not
// every pass; again once FailureRelog has passed; and once when it recovers.
func TestPIARetriedStepsLogTheirFailureOncePerRelog(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, false)
	k.nftAlwaysFail = true
	for i := 0; i < 3; i++ {
		mustTick(t, a)
		k.now += PollSec
	}
	if n := k.countLogged("applier: installing the ingress guard failed: injected failure"); n != 1 {
		t.Fatalf("guard failure logged %d times in three passes: %q", n, k.logs)
	}
	if n := k.countLogged("applier: clearing a forwarded port left by an earlier run failed: injected failure"); n != 1 {
		t.Fatalf("cleanup failure logged %d times in three passes: %q", n, k.logs)
	}
	k.now += FailureRelog
	mustTick(t, a)
	if n := k.countLogged("applier: installing the ingress guard failed"); n != 2 {
		t.Fatalf("not logged again after FailureRelog: %d: %q", n, k.logs)
	}
	k.nftAlwaysFail = false
	k.now += PollSec
	mustTick(t, a)
	mustTick(t, a)
	if n := k.countLogged("applier: the ingress guard is installed"); n != 1 {
		t.Fatalf("recovery logged %d times: %q", n, k.logs)
	}
	if n := k.countLogged("applier: the forwarded port left by an earlier run is cleared"); n != 1 {
		t.Fatalf("recovery logged %d times: %q", n, k.logs)
	}
}

// The tunnel repair's failure is logged with its cause, and again when the
// cause changes.
func TestPIATunnelRepairFailureIsLoggedPerCause(t *testing.T) {
	a, k, _, _, _ := piaSetup(t, false)
	k.addrErr = errors.New("first cause")
	mustTick(t, a)
	k.now += PollSec
	mustTick(t, a)
	k.addrErr = errors.New("second cause")
	k.now += PollSec
	mustTick(t, a)
	const line = "applier: repairing the tunnel's address and return-path rules failed: "
	if k.countLogged(line+"first cause") != 1 || k.countLogged(line+"second cause") != 1 {
		t.Fatalf("%q", k.logs)
	}
	k.addrErr = nil
	k.now += PollSec
	mustTick(t, a)
	if n := k.countLogged("applier: the tunnel's address and return-path rules are consistent again"); n != 1 {
		t.Fatalf("recovery logged %d times: %q", n, k.logs)
	}
}

// A switch logs one line per state change of its attempt: admitted, then
// verified; a later check that changes nothing logs nothing, and a rejected
// request says why, once.
func TestASwitchLogsEachStateChangeOnce(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	desire(t, a, requestAt(testHost, nil))
	mustTick(t, a)
	admitted := `applier: switch to "` + testHost + `" admitted (panel, change 1); applying`
	verified := `applier: "` + testHost + `" is verified`
	if k.countLogged(admitted) != 1 || k.countLogged(verified) != 1 {
		t.Fatalf("%q", k.logs)
	}
	lines := len(k.logs)
	for i := 0; i < 3; i++ {
		k.now += RefreshSec + 1
		mustTick(t, a)
	}
	if len(k.logs) != lines {
		t.Fatalf("checks that changed nothing logged %q", k.logs[lines:])
	}
	desire(t, a, requestAt(otherHost, map[string]any{"request_id": strings.Repeat("2", 32)}))
	mustTick(t, a)
	k.now += RefreshSec + 1
	mustTick(t, a)
	if n := k.countLogged(`applier: switch to "` + otherHost + `" rejected: ` + Unlisted); n != 1 {
		t.Fatalf("rejection logged %d times: %q", n, k.logs)
	}
}

// Every native overlay exit installs the ingress guard, not only PIA: checked
// on every pass, before the provider's own steps. A failure is logged once and its
// recovery once. The gluetun backend and the native sidecar install none.
func TestEveryNativeOverlayInstallsTheIngressGuard(t *testing.T) {
	for name, setup := range map[string]func(testing.TB) (*Applier, *kernel, string){"mullvad": mullvadSetup, "nordvpn": nordSetup} {
		t.Run(name, func(t *testing.T) {
			a, k, _ := setup(t)
			k.nftFailures = 1
			mustTick(t, a)
			if a.ingressGuarded() || k.guardInstalled != 0 {
				t.Fatal("marked done after a failure")
			}
			if n := k.countLogged("applier: installing the ingress guard failed: "); n != 1 {
				t.Errorf("failure logged %d times: %q", n, k.logs)
			}
			k.now += PollSec
			mustTick(t, a)
			k.now += PollSec
			mustTick(t, a)
			if !a.ingressGuarded() || k.guardInstalled != 1 {
				t.Fatalf("guard installed %d times", k.guardInstalled)
			}
			if n := k.countLogged("applier: the ingress guard is installed"); n != 1 {
				t.Errorf("recovery logged %d times: %q", n, k.logs)
			}
		})
	}
	f := newGluetunFixture(t, glOptions{})
	mustTick(t, f.a)
	if f.k.guardInstalled != 0 {
		t.Error("the gluetun backend installed the ingress guard")
	}
}

// Fail closed: while the ingress guard cannot be installed, no change is
// applied, the first one included, so no tunnel carries forwarded traffic
// unguarded; once it installs, the change goes ahead. A guard that fails
// again later holds the next change the same way.
func TestNoTunnelIsSetUntilTheIngressGuardIsIn(t *testing.T) {
	cases := map[string]struct {
		setup   func(testing.TB) (*Applier, *kernel, string)
		request func() map[string]any
	}{
		"mullvad": {mullvadSetup, func() map[string]any { return requestAt(testHost, nil) }},
		"nordvpn": {nordSetup, func() map[string]any { return nordRequest(nordUS, nil) }},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a, k, _ := c.setup(t)
			before := strings.Join(k.keys, ",")
			k.nftAlwaysFail = true
			r := a.switchTo(t, c.request())
			if status(r) == "ok" || !strings.Contains(message(r), "Waiting for the ingress guard") ||
				a.attempt.State != "pending" || strings.Join(k.keys, ",") != before {
				t.Fatalf("without the guard: %s %q %s %v", status(r), message(r), a.attempt.State, k.keys)
			}
			k.nftAlwaysFail = false
			k.now += PollSec
			if r := a.switchTo(t, c.request()); status(r) != "ok" {
				t.Fatalf("with the guard: %s %q", status(r), message(r))
			}
			after := strings.Join(k.keys, ",")
			// The guard fails again: the next change waits, the tunnel as it was.
			k.nftAlwaysFail = true
			k.now += 600
			if r := a.switchTo(t, c.request()); status(r) == "ok" || strings.Join(k.keys, ",") != after {
				t.Fatalf("guard lost: %s %q %v", status(r), message(r), k.keys)
			}
		})
	}
}

// molebridge#180: an intact ingress guard is read back on every pass and not
// written again. Rewriting it every pass (v0.14.6-rc.1 to rc.2) made a new
// nftables table and chain every 5 s, and NetBird's client in the same
// namespace reacts to each one by reconciling its firewall; in live
// acceptance those exits' PIA switches timed out. A guard that was deleted is
// written again at the next pass, logged once, and changes are held only
// while the check itself fails.
func TestAnIntactIngressGuardIsNotRewrittenEveryPass(t *testing.T) {
	a, k, _ := mullvadSetup(t)
	mustTick(t, a)
	if k.guardInstalled != 1 {
		t.Fatalf("guard installed %d times at the first pass", k.guardInstalled)
	}
	for i := 0; i < 20; i++ {
		k.now += PollSec
		mustTick(t, a)
	}
	if k.guardInstalled != 1 {
		t.Fatalf("an intact guard was written %d times in 21 passes", k.guardInstalled)
	}
	if n := k.countLogged("applier: the ingress guard was not as installed"); n != 0 {
		t.Fatalf("repair logged for an intact guard: %q", k.logs)
	}
	k.guardLost = true
	k.now += PollSec
	mustTick(t, a)
	if k.guardInstalled != 2 || !a.ingressGuarded() {
		t.Fatalf("a deleted guard: written %d times, guarded %v", k.guardInstalled, a.ingressGuarded())
	}
	if n := k.countLogged("applier: the ingress guard was not as installed (no table inet molebridge_guard); it is installed again"); n != 1 {
		t.Fatalf("repair logged %d times: %q", n, k.logs)
	}
	if r := a.switchTo(t, requestAt(testHost, nil)); status(r) != "ok" {
		t.Fatalf("switch after the repair: %s %q", status(r), message(r))
	}
}
