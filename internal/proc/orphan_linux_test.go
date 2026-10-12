//go:build linux

package proc

import (
	"testing"
	"time"
)

func TestOrphansAreReapedBySubreaper(t *testing.T) {
	before := testReaper.Orphans()
	// The shell exits at once; its two children are reparented to us (a
	// sub-reaper, as PID 1 is) and must be reaped when they finish.
	p, err := testReaper.Start(sh(`sleep 0.3 & sleep 0.3 & exit 0`))
	if err != nil {
		t.Fatal(err)
	}
	if !p.WaitGone(5 * time.Second) {
		t.Fatal("the group never emptied: the orphans were not reaped")
	}
	deadline := time.Now().Add(5 * time.Second)
	for testReaper.Orphans() < before+2 {
		if time.Now().After(deadline) {
			t.Fatalf("orphans reaped: %d, want %d", testReaper.Orphans()-before, 2)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
