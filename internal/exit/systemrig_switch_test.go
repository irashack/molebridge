//go:build drill && systemrig && linux

package exit

import (
	"testing"
	"time"
)

// TestSystemRigClientSwitch is the client-switch drill on the system rig: a
// client behind the overlay while the panel switches the exit from relay A to
// B and back. Each switch must end verified for the panel's request, with the
// client's traffic in both families leaving by the new relay, and nothing
// from the client may reach the internet by the exit's host path at any
// point.
func TestSystemRigClientSwitch(t *testing.T) {
	t.Parallel()
	r := newSystemRig(t)
	a, b := r.relays[0], r.relays[1]
	p := r.bringUp()
	r.clientVia(a, 30*time.Second)

	stop := make(chan struct{})
	samples := r.probeLoop(stop)
	type switchTime struct {
		from, to         string
		verified, client time.Duration
	}
	var times []switchTime
	for _, step := range []struct{ from, to *rigRelay }{{a, b}, {b, a}} {
		id, at := r.panelSwitch(step.to.host)
		r.waitVerified(p, step.to, id, 120*time.Second)
		verified := time.Since(at)
		client := r.clientVia(step.to, 30*time.Second).Sub(at)
		times = append(times, switchTime{step.from.host, step.to.host, verified, client})
		t.Logf("switch %s -> %s: result.json verified %v after the panel's answer, the client's traffic by %s %v after it",
			step.from.host, step.to.host, verified.Round(time.Millisecond), step.to.host, client.Round(time.Millisecond))
		if leaked := r.counted("leak"); leaked != 0 {
			t.Errorf("after the switch to %s: %d packets from the client reached the internet by the host path", step.to.host, leaked)
		}
	}
	close(stop)
	all := <-samples

	// What the client saw while the panel switched: every answer came by a
	// relay or failed, never by another path.
	byVia := map[string]int{}
	for _, s := range all {
		byVia[s.via]++
		if s.via != "" && s.via != a.host && s.via != b.host {
			t.Errorf("a client probe at %s left by %s", s.at.Format(time.RFC3339Nano), s.via)
		}
	}
	t.Logf("client probes during the switches: %d by %s, %d by %s, %d failed", byVia[a.host], a.host, byVia[b.host], b.host, byVia[""])

	if leaked := r.counted("leak"); leaked != 0 {
		t.Errorf("%d packets from the client reached the internet by the exit's host path", leaked)
	}
	viaA, viaB := r.counted("via_"+a.link), r.counted("via_"+b.link)
	if viaA == 0 || viaB == 0 {
		t.Errorf("the client's probes should have arrived by both relays: %d by %s, %d by %s", viaA, a.host, viaB, b.host)
	}
	t.Logf("client probe packets at the internet: %d by %s, %d by %s, 0 by the host path", viaA, a.host, viaB, b.host)
	for _, s := range times {
		t.Logf("switch time %s -> %s: verified %v, client %v", s.from, s.to, s.verified.Round(time.Millisecond), s.client.Round(time.Millisecond))
	}
	if !p.running() {
		t.Fatalf("the exit stopped (%d):\n%s", p.code, p.out.String())
	}
}
