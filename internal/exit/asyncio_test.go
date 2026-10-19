package exit

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// gatedWriter blocks every write until it is opened, like a log driver that
// stopped reading.
type gatedWriter struct {
	open chan struct{}
	mu   sync.Mutex
	buf  bytes.Buffer
}

func (g *gatedWriter) Write(p []byte) (int, error) {
	<-g.open
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.buf.Write(p)
}

func (g *gatedWriter) String() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.buf.String()
}

// A stuck sink never blocks a writer: lines beyond the queue are dropped and
// counted, and the count is reported as a line of its own once the sink moves.
func TestBoundedLogNeverBlocksAndReportsWhatItDropped(t *testing.T) {
	sink := &gatedWriter{open: make(chan struct{})}
	b := newBoundedLog(sink, 2)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20; i++ {
			_, _ = b.Write([]byte("line\n"))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a write blocked on a stuck sink")
	}
	close(sink.open)
	if !b.Flush(5 * time.Second) {
		t.Fatal("the queue did not drain")
	}
	// The count goes out ahead of the next line the sink takes.
	_, _ = b.Write([]byte("after\n"))
	if !b.Flush(5 * time.Second) {
		t.Fatal("the queue did not drain")
	}
	out := sink.String()
	if !strings.Contains(out, "molebridge-exit: log: ") || !strings.Contains(out, " lines were dropped while the log sink was slow\n") {
		t.Fatalf("no count of the dropped lines: %q", out)
	}
	if !strings.HasSuffix(out, "after\n") {
		t.Fatalf("the later line is missing: %q", out)
	}
}
