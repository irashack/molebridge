//go:build drill && linux

package drill

import (
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/watch"
)

// stalled is an event source whose reader can be frozen: while it is, the
// kernel's queue for the socket fills and overflows.
type stalled struct {
	watch.Source
	mu      sync.Mutex
	stall   chan struct{}
	dropAll bool
}

func (s *stalled) Next(deadline time.Time) ([]rtnl.Event, error) {
	s.mu.Lock()
	gate, drop := s.stall, s.dropAll
	s.mu.Unlock()
	if drop {
		// A watcher that never hears anything.
		time.Sleep(time.Until(deadline))
		return nil, os.ErrDeadlineExceeded
	}
	if gate != nil {
		<-gate
	}
	return s.Source.Next(deadline)
}

func (s *stalled) freeze() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stall = make(chan struct{})
	return s.stall
}

// Event loss by flood: the receive buffer overflows while the watcher is not
// reading, the kernel reports ENOBUFS, and the watcher runs a full pass at
// once, which finds the fault whose event was among the lost ones.
func TestEventLossByFloodRunsAFullPass(t *testing.T) {
	var src *stalled
	r := newRig(t, func(o *rigOptions) {
		o.buffer = 2048
		o.source = func(s watch.Source) watch.Source { src = &stalled{Source: s}; return src }
	})
	r.flood()
	gate := src.freeze()
	// Let a blocked receive that is already in flight come back first.
	time.Sleep(250 * time.Millisecond)
	resetCounter(t, r.outside)
	var batch strings.Builder
	for i := 0; i < 4000; i++ {
		batch.WriteString("rule add lookup main priority 5000\nrule del priority 5000\n")
	}
	path := t.TempDir() + "/flood.batch"
	if err := os.WriteFile(path, []byte(batch.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	r.exit.IP("-batch", path)
	// A real fault, lost among the flood.
	r.exit.IP("rule", "del", "priority", "96")
	before := r.watcher.Stats().Overruns
	close(gate)
	took := r.waitHealthy(3 * time.Second)
	if r.watcher.Stats().Overruns == before {
		t.Fatalf("no overrun was reported; the flood did not overflow the buffer\n%s", r.logs.text())
	}
	if !strings.Contains(r.logs.text(), "netlink events were lost") {
		t.Errorf("the loss was not logged:\n%s", r.logs.text())
	}
	t.Logf("repaired %v after the watcher resumed", took)
	r.held("event loss")
	if ok, f := r.connected(); !ok {
		t.Errorf("%s: not connected", f)
	}
}

// The periodic pass is the fallback when events never arrive at all.
func TestPeriodicPassFindsWhatEventsNeverReported(t *testing.T) {
	var src *stalled
	r := newRig(t, func(o *rigOptions) {
		o.interval = 400 * time.Millisecond
		o.source = func(s watch.Source) watch.Source { src = &stalled{Source: s}; return src }
	})
	src.mu.Lock()
	src.dropAll = true
	src.mu.Unlock()
	time.Sleep(150 * time.Millisecond)
	r.exit.IP("rule", "del", "priority", "95")
	r.exit.IP("-6", "route", "flush", "table", "51821")
	took := r.waitHealthy(2 * time.Second)
	if took > 400*time.Millisecond+repairBudget {
		t.Errorf("repaired %v after the change; the interval is 400ms", took)
	}
	if r.watcher.Stats().Periodic == 0 {
		t.Error("no periodic pass ran")
	}
}
