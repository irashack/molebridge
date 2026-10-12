package bootclock

import (
	"testing"
	"time"
)

func TestSystemClockAdvances(t *testing.T) {
	c := System()
	a := c()
	time.Sleep(20 * time.Millisecond)
	b := c()
	if b <= a || b-a > time.Second {
		t.Fatalf("%v %v", a, b)
	}
	if Clock(func() time.Duration { return 90*time.Second + 999*time.Millisecond }).Seconds() != 90 {
		t.Fatal("Seconds truncates")
	}
}
