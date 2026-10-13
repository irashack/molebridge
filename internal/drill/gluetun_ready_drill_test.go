//go:build drill && linux

package drill

// "Contract not intact, not ready" (check-routing.sh, the gluetun gate): every
// break below must keep NetBird from starting until the guard repairs it. In
// the Go exit the worker tells the supervisor "ready" only on a pass that
// verifies the contract (internal/exit, readiness), and Ready and Verified are
// the owner's verdict on the real kernel. The kernel connection is wrapped so
// that the owner cannot repair while the break stands: the pass then reports
// the contract as not holding, as it does for any break it cannot fix, and
// readiness is withdrawn; once the kernel lets the owner repair, one pass
// verifies and readiness returns.

import (
	"context"
	"testing"
	"time"
)

func TestGluetunContractNotIntactIsNotReady(t *testing.T) {
	wrap, kernel := refusingWrap()
	g := newGluetunRigWith(t, wrap)
	k := kernel()
	ctx := context.Background()

	if res, err := g.mut.ReconcileNow(ctx, "baseline"); err != nil || !res.Verified || !g.mut.Ready() {
		t.Fatalf("not ready with the whole guard in place: %+v %v", res, err)
	}
	if ok, why := g.strict(); !ok {
		t.Fatalf("the independent judgment disagrees: %s", why)
	}

	type brk struct {
		name    string
		do      func()
		restore func() // only what the owner is not expected to repair
	}
	var breaks []brk
	for _, p := range []string{"88", "89", "90", "94", "95", "96"} {
		p := p
		breaks = append(breaks, brk{name: "IPv6 rule " + p + " is missing", do: func() { g.exit.IP("-6", "rule", "del", "priority", p) }})
	}
	breaks = append(breaks,
		brk{name: "an early main-table rule for the overlay", do: func() {
			g.exit.IP("-4", "rule", "add", "iif", overlayIf, "lookup", "main", "priority", "50")
		}},
		brk{name: "a host route in the exit table", do: func() {
			g.exit.IP("-4", "route", "add", "198.51.100.0/28", "via", "198.51.100.2", "dev", "eth0", "table", "51821")
		}},
	)
	for _, b := range breaks {
		t.Run(b.name, func(t *testing.T) {
			// The kernel refuses the owner's repairs while the break stands.
			k.set(refuseAll)
			b.do()
			res, err := g.mut.ReconcileNow(ctx, "break")
			if err == nil && res.Verified {
				t.Errorf("verified a contract with a break in it: %+v", res)
			}
			if res.ContractHolds {
				t.Errorf("the contract was said to hold: %+v", res)
			}
			if g.mut.Ready() {
				t.Error("ready with the contract broken: the exit would start NetBird")
			}
			if ok, _ := g.strict(); ok {
				t.Error("the independent judgment calls the broken contract intact")
			}
			// The kernel lets the owner repair: one pass restores everything and
			// readiness comes back.
			k.set(nil)
			res, err = g.mut.ReconcileNow(ctx, "repair")
			if err != nil || !res.Verified {
				t.Fatalf("one pass did not repair it: %+v %v\n%s", res, err, g.logs.text())
			}
			if !g.mut.Ready() {
				t.Error("not ready after the repair verified")
			}
			g.waitStrict(2 * time.Second)
		})
	}
}
