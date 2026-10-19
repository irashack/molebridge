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
