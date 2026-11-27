//go:build drill && systemrig && linux

package exit

import (
	"strings"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/applier"
)

// TestSystemRigIngressGuardDeleted is the ingress guard's single-fault drill
// on the system rig: with the release build verified on relay A and a client
// behind the overlay, something else deletes table inet molebridge_guard
// from the exit's namespace. The applier installs the guard again on every
// pass, so it must be back, with its one rule, within two passes; the exit
// stays verified, the client keeps leaving by the relay, and nothing of the
// client's reaches the internet by the exit's host path.
func TestSystemRigIngressGuardDeleted(t *testing.T) {
	t.Parallel()
	r := newSystemRig(t)
	a := r.relays[0]
	p := r.bringUp()
	r.clientVia(a, 30*time.Second)

	guard := func() (string, bool) {
		out, err := r.exit.Exec("nft", "list", "table", "inet", "molebridge_guard")
		return out, err == nil
	}
	installed := func(out string) bool {
		return strings.Contains(out, "hook forward") &&
			strings.Contains(out, `iifname "`+dExit+`" oifname != "`+dOverlay+`" drop`)
	}
	r.waitFor(2*applier.PollSec*time.Second, "the ingress guard installed", func() bool {
		out, ok := guard()
		return ok && installed(out)
	})

	for round := 1; round <= 2; round++ {
		if out, err := r.exit.Exec("nft", "delete", "table", "inet", "molebridge_guard"); err != nil {
			t.Fatalf("deleting the guard: %v\n%s", err, out)
		}
		deleted := time.Now()
		if _, ok := guard(); ok {
			t.Fatal("the guard is still listed after its deletion")
		}
		r.waitFor(2*applier.PollSec*time.Second+5*time.Second, "the ingress guard back", func() bool {
			if !p.running() {
				t.Fatalf("the exit stopped (%d):\n%s", p.code, p.out.String())
			}
			out, ok := guard()
			return ok && installed(out)
		})
		t.Logf("round %d: the ingress guard was back %v after its deletion", round, time.Since(deleted).Round(time.Millisecond))
		if !r.verified(a, "") {
			t.Errorf("round %d: result.json is no longer verified on %s: %s", round, a.host, jsonText(r.result()))
		}
		r.clientVia(a, 30*time.Second)
		if leaked := r.counted("leak"); leaked != 0 {
			t.Errorf("round %d: %d packets from the client reached the internet by the host path", round, leaked)
		}
	}
	if !p.running() {
		t.Fatalf("the exit stopped (%d):\n%s", p.code, p.out.String())
	}
}
