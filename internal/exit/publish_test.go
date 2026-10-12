package exit

import (
	"reflect"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/validate"
)

type pubHarness struct {
	p      *publisher
	lease  *Lease
	clock  *fakeClock
	wall   time.Time
	writes []map[string]any
}

func newPubHarness(t *testing.T) *pubHarness {
	t.Helper()
	h := &pubHarness{clock: &fakeClock{now: 1000 * time.Second}, wall: time.Date(2026, 10, 12, 12, 0, 0, 500_000_000, time.UTC)}
	s := settingsFor("overlay", "wireguard", "mullvad")
	h.lease = NewLease(h.clock.read, 10*time.Second, nativeBounds)
	h.p = newPublisher(s, h.lease, h.clock.read, func() time.Time { return h.wall.Add(h.clock.now - 1000*time.Second) }, func(string, ...any) {})
	h.p.write = func(path string, v any) error {
		m, err := marshalForTest(v)
		if err != nil {
			return err
		}
		h.writes = append(h.writes, m)
		return nil
	}
	return h
}

func (h *pubHarness) renew(seq uint64, gen string) {
	if _, err := h.lease.Accept(renew(gen, seq, map[string]time.Duration{LoopMutator: h.clock.now, LoopWatcher: h.clock.now})); err != nil {
		panic(err)
	}
}

func TestLeaseOnlyPublicationChangesNothingButOwnerRecord(t *testing.T) {
	h := newPubHarness(t)
	gen, _ := h.lease.NewGeneration()
	h.renew(1, gen)
	s := h.p.s
	rec := okRecord(s, h.wall)
	h.p.Full(rec)
	h.p.Wait(time.Second)
	first := h.writes[len(h.writes)-1]

	h.clock.now += 4 * time.Second
	h.renew(2, gen)
	h.p.LeaseOnly()
	h.p.Wait(time.Second)
	second := h.writes[len(h.writes)-1]
	if len(h.writes) != 2 {
		t.Fatalf("%d writes", len(h.writes))
	}
	// checked_at and every other check's evidence time are those of the last
	// full inspection.
	if first["checked_at"] != second["checked_at"] {
		t.Errorf("checked_at moved: %v -> %v", first["checked_at"], second["checked_at"])
	}
	c1, c2 := first["checks"].(map[string]any), second["checks"].(map[string]any)
	for name := range c1 {
		if name == "owner_record" {
			continue
		}
		if !reflect.DeepEqual(c1[name], c2[name]) {
			t.Errorf("%s changed: %v -> %v", name, c1[name], c2[name])
		}
	}
	o1, o2 := c1["owner_record"].(map[string]any), c2["owner_record"].(map[string]any)
	if o1["state"] != "pass" || o2["state"] != "pass" || o1["at"] == o2["at"] || o1["expires_at"] == o2["expires_at"] {
		t.Errorf("owner_record: %v -> %v", o1, o2)
	}
	// The claim never outlives the lease: the expiry is the accepted expiry,
	// truncated down to the second.
	want := validate.FormatTime(h.wall.Add(4*time.Second + 10*time.Second))
	if o2["expires_at"] != want {
		t.Errorf("expires_at %v, want %v", o2["expires_at"], want)
	}
	for k, v := range first {
		if k != "checks" && !reflect.DeepEqual(v, second[k]) {
			t.Errorf("%s changed in a lease-only publication", k)
		}
	}
}

func TestOwnerRecordFailsWhenTheLeaseIsNotHeld(t *testing.T) {
	h := newPubHarness(t)
	gen, _ := h.lease.NewGeneration()
	h.p.Full(okRecord(h.p.s, h.wall))
	h.p.Wait(time.Second)
	if o := h.writes[0]["checks"].(map[string]any)["owner_record"].(map[string]any); o["state"] != "fail" {
		t.Errorf("no renewal yet: %v", o)
	}
	h.renew(1, gen)
	h.clock.now += 11 * time.Second // the expiry has passed
	h.p.LeaseOnly()
	h.p.Wait(time.Second)
	if o := h.writes[len(h.writes)-1]["checks"].(map[string]any)["owner_record"].(map[string]any); o["state"] != "fail" || o["expires_at"] != nil {
		t.Errorf("expired lease: %v", o)
	}
}

func TestRecordsAfterTheFailureRecordAreDropped(t *testing.T) {
	h := newPubHarness(t)
	gen, _ := h.lease.NewGeneration()
	h.renew(1, gen)
	h.p.Full(okRecord(h.p.s, h.wall))
	h.p.Wait(time.Second)
	h.lease.Revoke()
	h.p.Failure(h.wall.Add(time.Minute))
	h.p.Wait(time.Second)
	n := len(h.writes)
	last := h.writes[n-1]
	if last["status"] != "failed" || last["message"] != OwnerStoppedMessage {
		t.Fatalf("%v", last)
	}
	h.p.Full(okRecord(h.p.s, h.wall))
	h.p.Wait(time.Second)
	h.p.LeaseOnly()
	h.p.Wait(time.Second)
	h.p.Failure(h.wall)
	h.p.Wait(time.Second)
	if len(h.writes) != n {
		t.Fatalf("%d writes after the failure record", len(h.writes)-n)
	}
}

func TestOtherKindsGetNoLeaseOnlyPublication(t *testing.T) {
	for _, s := range []*Settings{settingsFor("overlay", "gluetun", "gluetun-mullvad"), settingsFor("sidecar", "gluetun", "gluetun-mullvad")} {
		h := newPubHarness(t)
		h.p.s = s
		h.p.Full(okRecord(s, h.wall))
		h.p.Wait(time.Second)
		h.p.LeaseOnly()
		h.p.Wait(time.Second)
		if len(h.writes) != 1 {
			t.Errorf("%s: %d writes; only a native overlay exit carries owner_record", s.Kind(), len(h.writes))
		}
		// And the record is written as the worker built it: owner_record n/a
		// or untouched.
		if o := h.writes[0]["checks"].(map[string]any)["owner_record"].(map[string]any); o["state"] != "n/a" {
			t.Errorf("%s: owner_record %v", s.Kind(), o)
		}
	}
}
