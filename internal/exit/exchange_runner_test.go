package exit

import (
	"errors"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/proc"
)

// Close, which the stop sequence calls first, returns at once even while the
// exchange child is being created: no lock is held across the fork.
func TestExchangeRunnerCloseDoesNotWaitForAStalledStart(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	r := newExchangeRunner(func() (*proc.Process, error) {
		close(entered)
		<-release
		return nil, errors.New("not started")
	}, func(string, ...any) {})
	go r.Run()
	<-entered
	closed := make(chan struct{})
	go func() {
		r.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("Close waited for the child's creation")
	}
	close(release)
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not end after Close")
	}
}
