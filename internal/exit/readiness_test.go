package exit

import (
	"testing"
	"time"
)

func TestReadinessPolicy(t *testing.T) {
	t0 := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	r := &readiness{grace: 10 * time.Second}
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }

	if a := r.step(at(0), false, false, false); a != actNone {
		t.Error("nothing to say before the contract holds")
	}
	if a := r.step(at(1), true, false, false); a != actNone {
		t.Error("the tunnel is not up yet")
	}
	if a := r.step(at(2), true, true, false); a != actReady {
		t.Error("ready once the contract holds and the tunnel is up")
	}
	if a := r.step(at(3), true, true, false); a != actNone {
		t.Error("ready is sent once")
	}
	// A lost tunnel alone does not take NetBird down.
	if a := r.step(at(4), true, false, false); a != actNone {
		t.Error("tunnel loss is not unready")
	}
	// A broken contract is waited out for the grace.
	if a := r.step(at(5), false, true, false); a != actNone {
		t.Error("a contract that fails to verify for a moment is not yet unready")
	}
	if a := r.step(at(14), false, true, false); a != actNone {
		t.Error("9 seconds into the grace")
	}
	if a := r.step(at(15), false, true, false); a != actUnready {
		t.Error("unready after the grace")
	}
	if a := r.step(at(16), false, true, false); a != actNone {
		t.Error("unready is sent once")
	}
	if a := r.step(at(17), true, true, false); a != actReady {
		t.Error("ready again when the contract verifies")
	}
	// A contract that comes back inside the grace resets it.
	r.step(at(20), false, true, false)
	r.step(at(25), true, true, false)
	if a := r.step(at(31), false, true, false); a != actNone {
		t.Error("the grace restarts after a verification")
	}
}

func TestReadinessBlockedByTheProfileCheck(t *testing.T) {
	t0 := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	r := &readiness{grace: 10 * time.Second}
	if r.step(t0, true, true, false) != actReady {
		t.Fatal("ready")
	}
	if a := r.step(t0.Add(time.Second), true, true, true); a != actUnready {
		t.Error("a refused profile after `netbird up` takes NetBird down at once")
	}
	if a := r.step(t0.Add(2*time.Second), true, true, true); a != actNone {
		t.Error("and ready is never sent again while blocked")
	}
}
