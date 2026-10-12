package tunnel

import (
	"testing"
	"time"
)

func TestDelayCurve(t *testing.T) {
	var d time.Duration
	var got []time.Duration
	for i := 0; i < 8; i++ {
		d = Delay(d)
		got = append(got, d)
	}
	want := []time.Duration{2, 4, 8, 16, 32, 60, 60, 60}
	for i := range want {
		if got[i] != want[i]*time.Second {
			t.Fatalf("%v", got)
		}
	}
	if Delay(-time.Second) != FirstDelay || Delay(31*time.Second) != MaxDelay {
		t.Fatal("edges")
	}
}
