package rtnl

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// A connection with no deadline of its own: the call blocks until the
// connection is closed.
type stallConn struct{ closed chan struct{} }

func newStall() *stallConn { return &stallConn{closed: make(chan struct{})} }
func (s *stallConn) close() {
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
}
func (s *stallConn) call() error {
	<-s.closed
	return errors.New("connection closed")
}

func TestARunThatFinishesReturnsItsResult(t *testing.T) {
	want := errors.New("boom")
	if err := RunBounded(context.Background(), time.Second, func() { t.Error("aborted") }, func() error { return want }); err != want {
		t.Fatalf("%v", err)
	}
	if err := RunBounded(context.Background(), time.Second, func() {}, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestAStalledCallIsCutOffAtTheDeadlineByClosingItsConnection(t *testing.T) {
	s := newStall()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	var aborted atomic.Bool
	start := time.Now()
	err := RunBounded(ctx, time.Second, func() { aborted.Store(true); s.close() }, s.call)
	took := time.Since(start)
	if !errors.Is(err, os.ErrDeadlineExceeded) || !aborted.Load() {
		t.Fatalf("%v aborted=%v", err, aborted.Load())
	}
	if took < 50*time.Millisecond || took > 250*time.Millisecond {
		t.Errorf("took %v for a 60 ms deadline", took)
	}
}

func TestACallThatCompletesDuringTheAbortKeepsItsResult(t *testing.T) {
	s := newStall()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := RunBounded(ctx, time.Second, s.close, func() error { <-s.closed; return nil })
	if err != nil {
		t.Fatalf("a mutation that finished is reported as it finished: %v", err)
	}
}

func TestACallThatIgnoresTheCloseIsReportedStuck(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	release := make(chan struct{})
	defer close(release)
	err := RunBounded(ctx, 50*time.Millisecond, func() {}, func() error { <-release; return nil })
	if !errors.Is(err, ErrStuck) || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

func TestACancelledContextRunsNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ran := false
	if err := RunBounded(ctx, time.Second, func() {}, func() error { ran = true; return nil }); !errors.Is(err, context.Canceled) || ran {
		t.Fatalf("%v %v", err, ran)
	}
}
