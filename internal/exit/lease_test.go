package exit

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeClock struct{ now time.Duration }

func (c *fakeClock) read() time.Duration { return c.now }

func newTestLease(c *fakeClock, grace time.Duration, bounds map[string]time.Duration) (*Lease, string) {
	l := NewLease(c.read, grace, bounds)
	gen, err := l.NewGeneration()
	if err != nil {
		panic(err)
	}
	return l, gen
}

var nativeBounds = map[string]time.Duration{LoopMutator: MutatorBound, LoopWatcher: LoopBound}

func renew(gen string, seq uint64, loops map[string]time.Duration) Msg {
	m := Msg{Type: TypeRenew, Gen: gen, Seq: seq, Loops: map[string]int64{}}
	for k, v := range loops {
		m.Loops[k] = int64(v)
	}
	return m
}

func TestLeaseAcceptanceTable(t *testing.T) {
	const grace = 10 * time.Second
	base := 1000 * time.Second
	tests := []struct {
		name  string
		msg   func(gen string) Msg
		setup func(l *Lease, gen string)
		want  string // "" accepted, else a fragment of the refusal
	}{
		{"accepted", func(g string) Msg {
			return renew(g, 1, map[string]time.Duration{LoopMutator: base - time.Second, LoopWatcher: base - time.Second})
		}, nil, ""},
		{"loops exactly now", func(g string) Msg {
			return renew(g, 1, map[string]time.Duration{LoopMutator: base, LoopWatcher: base})
		}, nil, ""},
		{"stale generation", func(g string) Msg {
			return renew(strings.Repeat("0", 32), 1, map[string]time.Duration{LoopMutator: base, LoopWatcher: base})
		}, nil, "stale generation"},
		{"sequence repeats", func(g string) Msg {
			return renew(g, 4, map[string]time.Duration{LoopMutator: base, LoopWatcher: base})
		}, func(l *Lease, g string) {
			if _, err := l.Accept(renew(g, 4, map[string]time.Duration{LoopMutator: base, LoopWatcher: base})); err != nil {
				panic(err)
			}
		}, "sequence number"},
		{"sequence goes back", func(g string) Msg {
			return renew(g, 3, map[string]time.Duration{LoopMutator: base, LoopWatcher: base})
		}, func(l *Lease, g string) {
			if _, err := l.Accept(renew(g, 4, map[string]time.Duration{LoopMutator: base, LoopWatcher: base})); err != nil {
				panic(err)
			}
		}, "sequence number"},
		{"sequence zero", func(g string) Msg {
			return renew(g, 0, map[string]time.Duration{LoopMutator: base, LoopWatcher: base})
		}, nil, "sequence number"},
		{"mutator older than its bound", func(g string) Msg {
			return renew(g, 1, map[string]time.Duration{LoopMutator: base - MutatorBound - TransitSlack - time.Millisecond, LoopWatcher: base})
		}, nil, "mutator loop is older"},
		{"mutator at its bound", func(g string) Msg {
			return renew(g, 1, map[string]time.Duration{LoopMutator: base - MutatorBound, LoopWatcher: base})
		}, nil, ""},
		{"watcher older than its bound", func(g string) Msg {
			return renew(g, 1, map[string]time.Duration{LoopMutator: base, LoopWatcher: base - LoopBound - TransitSlack - time.Millisecond})
		}, nil, "watcher loop is older"},
		{"loop in the future", func(g string) Msg {
			return renew(g, 1, map[string]time.Duration{LoopMutator: base, LoopWatcher: base + time.Nanosecond})
		}, nil, "in the future"},
		{"loop missing", func(g string) Msg {
			return renew(g, 1, map[string]time.Duration{LoopMutator: base})
		}, nil, "loops reported"},
		{"unknown loop", func(g string) Msg {
			return renew(g, 1, map[string]time.Duration{LoopMutator: base, LoopWatcher: base, "bogus": base})
		}, nil, "loops reported"},
		{"renamed loop", func(g string) Msg {
			return renew(g, 1, map[string]time.Duration{LoopMutator: base, "bogus": base})
		}, nil, "watcher loop is missing"},
		{"revoked lease", func(g string) Msg {
			return renew(g, 1, map[string]time.Duration{LoopMutator: base, LoopWatcher: base})
		}, func(l *Lease, g string) { l.Revoke() }, "revoked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &fakeClock{now: base}
			l, gen := newTestLease(c, grace, nativeBounds)
			if tt.setup != nil {
				tt.setup(l, gen)
			}
			expiry, err := l.Accept(tt.msg(gen))
			if tt.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if expiry != base+grace {
					t.Errorf("expiry %v, want now + grace = %v", expiry, base+grace)
				}
				return
			}
			var rej *RejectError
			if !errors.As(err, &rej) || !strings.Contains(rej.Reason, tt.want) {
				t.Fatalf("err %v, want a refusal containing %q", err, tt.want)
			}
		})
	}
}

func TestLeaseExpiryComesFromTheSupervisorsClock(t *testing.T) {
	c := &fakeClock{now: 500 * time.Second}
	l, gen := newTestLease(c, 5*time.Second, nativeBounds)
	if l.Held() {
		t.Fatal("held before any renewal")
	}
	loops := func() map[string]time.Duration {
		return map[string]time.Duration{LoopMutator: c.now, LoopWatcher: c.now}
	}
	exp, err := l.Accept(renew(gen, 1, loops()))
	if err != nil || exp != 505*time.Second {
		t.Fatalf("%v %v", exp, err)
	}
	c.now += 4 * time.Second
	if !l.Held() || l.Lapsed() {
		t.Fatal("still inside the grace")
	}
	// Re-sending the same renewal (or an old one) extends nothing.
	if _, err := l.Accept(renew(gen, 1, loops())); err == nil {
		t.Fatal("a repeated sequence number must be refused")
	}
	if e, _ := l.Expiry(); e != 505*time.Second {
		t.Fatalf("expiry moved to %v", e)
	}
	c.now += 2 * time.Second // 506 s: past the expiry
	if l.Held() || !l.Lapsed() {
		t.Fatal("the lease must have lapsed at 505 s")
	}
	// Expiry is irreversible within a generation: a late renewal with fresh
	// loops, and a late record, revive nothing.
	if _, err := l.Accept(renew(gen, 2, loops())); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("a renewal after the expiry must be refused: %v", err)
	}
	if l.Held() || !l.Lapsed() {
		t.Fatal("the lease is back after a late renewal")
	}
	if l.AcceptStatus(gen, 9) {
		t.Fatal("a record after the expiry must be dropped")
	}
	// Even a clock that is somehow earlier again (it is not) cannot undo it.
	c.now -= 10 * time.Second
	if !l.Lapsed() {
		t.Fatal("the lapse is sticky")
	}
	// A new generation (a new worker) starts afresh.
	gen2, _ := l.NewGeneration()
	c.now += 10 * time.Second
	if _, err := l.Accept(renew(gen2, 1, loops())); err != nil {
		t.Fatalf("a new generation: %v", err)
	}
}

func TestExpiryIsFoundByTheMessageItself(t *testing.T) {
	// A renewal that arrives after the deadline but before the supervisor's
	// next timer event finds the lease lapsed; it is not a race to be won.
	c := &fakeClock{now: 100 * time.Second}
	l, gen := newTestLease(c, 5*time.Second, nativeBounds)
	if _, err := l.Accept(renew(gen, 1, map[string]time.Duration{LoopMutator: c.now, LoopWatcher: c.now})); err != nil {
		t.Fatal(err)
	}
	c.now += 5 * time.Second // exactly the deadline
	if _, err := l.Accept(renew(gen, 2, map[string]time.Duration{LoopMutator: c.now, LoopWatcher: c.now})); err == nil {
		t.Fatal("accepted at the deadline")
	}
	if !l.Lapsed() {
		t.Fatal("not lapsed")
	}
}

func TestLeaseFirstRenewalIsDueWithinTheStartupAllowance(t *testing.T) {
	c := &fakeClock{now: 100 * time.Second}
	l, _ := newTestLease(c, 5*time.Second, nativeBounds)
	c.now += StartupAllowance - time.Second
	if l.Lapsed() {
		t.Fatal("lapsed inside the startup allowance")
	}
	c.now += 2 * time.Second
	if !l.Lapsed() {
		t.Fatal("a worker that never renews must lapse")
	}
}

func TestLeaseNewGenerationResets(t *testing.T) {
	c := &fakeClock{now: 100 * time.Second}
	l, gen := newTestLease(c, 5*time.Second, nativeBounds)
	if _, err := l.Accept(renew(gen, 5, map[string]time.Duration{LoopMutator: c.now, LoopWatcher: c.now})); err != nil {
		t.Fatal(err)
	}
	l.Revoke()
	gen2, err := l.NewGeneration()
	if err != nil || gen2 == gen || len(gen2) != 32 {
		t.Fatalf("%q %q %v", gen, gen2, err)
	}
	if _, err := l.Accept(renew(gen, 6, map[string]time.Duration{LoopMutator: c.now, LoopWatcher: c.now})); err == nil {
		t.Fatal("the old generation must be stale")
	}
	if _, err := l.Accept(renew(gen2, 1, map[string]time.Duration{LoopMutator: c.now, LoopWatcher: c.now})); err != nil {
		t.Fatalf("sequence numbers start over with a generation: %v", err)
	}
}

func TestStatusAcceptance(t *testing.T) {
	c := &fakeClock{now: 100 * time.Second}
	l, gen := newTestLease(c, 5*time.Second, nativeBounds)
	if !l.AcceptStatus(gen, 1) {
		t.Fatal("first record")
	}
	if l.AcceptStatus(gen, 1) || l.AcceptStatus(gen, 0) {
		t.Fatal("a sequence not above the last is dropped")
	}
	if l.AcceptStatus(strings.Repeat("a", 32), 9) {
		t.Fatal("a stale generation is dropped")
	}
	if !l.AcceptStatus(gen, 7) {
		t.Fatal("a higher sequence")
	}
	l.Revoke()
	if l.AcceptStatus(gen, 8) {
		t.Fatal("a revoked lease drops every record")
	}
}

func TestLoopBoundsByMode(t *testing.T) {
	native := &Settings{}
	native.Routing.Kind, native.Routing.Backend = "overlay", "wireguard"
	if b := LoopBounds(native); len(b) != 2 || b[LoopMutator] != MutatorBound || b[LoopWatcher] != LoopBound {
		t.Errorf("native: %v", b)
	}
	gl := &Settings{}
	gl.Routing.Kind, gl.Routing.Backend = "overlay", "gluetun"
	if b := LoopBounds(gl); len(b) != 4 || b[LoopFwmark] != LoopBound || b[LoopLog] != LoopBound {
		t.Errorf("gluetun: %v", b)
	}
	sc := &Settings{}
	sc.Routing.Kind, sc.Routing.Backend = "sidecar", "gluetun"
	if b := LoopBounds(sc); len(b) != 1 {
		t.Errorf("sidecar: %v", b)
	}
}
