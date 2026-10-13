//go:build drill && linux

package drill

// The temporary guard (priority 80) on a real kernel: a repair of rules 90-97
// is made behind it, it comes out once a pass verifies, and while a pass cannot
// verify it stays and nothing forwarded leaves.

import (
	"context"
	"strings"
	"testing"
	"time"
)

func hasRule80(r *rig) bool {
	out, _ := r.exit.TryIP("-4", "rule", "show")
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "80:") {
			return true
		}
	}
	return false
}

func TestTheTemporaryGuardComesOutOnceAPassVerifies(t *testing.T) {
	r := newRig(t)
	if hasRule80(r) {
		t.Fatal("a guard in a healthy namespace")
	}
	r.exit.IP("-4", "rule", "del", "priority", "95")
	r.waitHealthy(2 * time.Second) // healthy requires no priority-80 rule in either family
	if hasRule80(r) {
		t.Error("the temporary guard stayed after the repair verified")
	}
	log := r.logs.text()
	guard, restored := strings.LastIndex(log, "added the IPv4 temporary guard"), strings.LastIndex(log, "added IPv4 rule 95")
	if guard < 0 || restored < 0 || guard > restored {
		t.Errorf("the repair of rule 95 was not made behind the guard:\n%s", log)
	}
	if ok, which := r.connected(); !ok {
		t.Errorf("not connected after the repair (%s)", which)
	}
}

func TestTheTemporaryGuardStaysWhileAPassCannotVerifyAndBlocksForwarding(t *testing.T) {
	wrap, kernel := refusingWrap()
	r := newRig(t, func(o *rigOptions) { o.wrap = wrap })
	k := kernel()
	// The kernel will not take rule 95 back: the repair cannot complete.
	k.set(func(op string, priority uint32) bool { return op == "add" && priority == 95 })
	r.exit.IP("-4", "rule", "del", "priority", "95")
	deadline := time.Now().Add(3 * time.Second)
	for !hasRule80(r) {
		if time.Now().After(deadline) {
			t.Fatalf("no temporary guard went in\n%s", r.logs.text())
		}
		time.Sleep(5 * time.Millisecond)
	}
	resetCounter(t, r.outside)
	time.Sleep(400 * time.Millisecond)
	if !hasRule80(r) {
		t.Error("the guard came out although the pass could not verify")
	}
	if r.mut.Ready() {
		t.Error("ready while the contract is broken")
	}
	if r.ping("-4") {
		t.Error("forwarding works while the guard stands and rule 95 is gone")
	}
	r.held("the guard standing")
	// The kernel cooperates: one pass restores rule 95, verifies, and the guard goes.
	k.set(nil)
	if res, err := r.mut.ReconcileNow(context.Background(), "after"); err != nil || !res.Verified {
		t.Fatalf("%+v %v\n%s", res, err, r.logs.text())
	}
	r.waitHealthy(2 * time.Second)
	if hasRule80(r) {
		t.Error("the guard stayed after the pass verified")
	}
	if ok, which := r.connected(); !ok {
		t.Errorf("not connected after the repair (%s)", which)
	}
}
