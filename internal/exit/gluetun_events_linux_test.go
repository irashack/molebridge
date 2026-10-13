//go:build linux

package exit

import (
	"testing"
	"time"
)

func monitorsAt(now time.Duration) *gluetunMonitors {
	return &gluetunMonitors{w: &worker{clock: func() time.Duration { return now }}, grace: 5 * time.Second}
}

// The reviewer's interleaving: launch 2 begins before launch 1's stopped event
// is handled. Events name their launch, and one of an older launch cannot
// disarm the newer launch's monitors.
func TestAStaleStopDoesNotDisarmTheNextLaunch(t *testing.T) {
	m := monitorsAt(100 * time.Second)
	m.event(Msg{State: NBLaunching, Launch: 1, LogOffset: 10, AtBootNs: int64(90 * time.Second)})
	m.event(Msg{State: NBStarted, Launch: 1})
	if !m.launched {
		t.Fatal("launch 1 is not being watched")
	}
	m.event(Msg{State: NBLaunching, Launch: 2, LogOffset: 99, AtBootNs: int64(95 * time.Second)})
	m.event(Msg{State: NBStopped, Launch: 1}) // arrives late
	if !m.launched || m.cur.launch != 2 || m.cur.offset != 99 || m.lastGood != 95*time.Second {
		t.Fatalf("launch 2 lost its accounting: launched=%v cur=%+v lastGood=%v", m.launched, m.cur, m.lastGood)
	}
	m.event(Msg{State: NBFailed, Launch: 1})
	if !m.launched {
		t.Fatal("a failure of launch 1 disarmed launch 2")
	}
	// A late launching message of an older launch does not rewind it either.
	m.event(Msg{State: NBLaunching, Launch: 1, LogOffset: 1, AtBootNs: int64(80 * time.Second)})
	if m.cur.launch != 2 {
		t.Fatalf("%+v", m.cur)
	}
	// Its own stop disarms it, and its started event (re)arms it from the
	// launch's own start.
	m.event(Msg{State: NBStopped, Launch: 2})
	if m.launched {
		t.Fatal("launch 2 stopped but is still watched")
	}
	m.event(Msg{State: NBStarted, Launch: 2})
	if !m.launched || m.lastGood != 95*time.Second {
		t.Fatalf("started did not re-arm launch 2 from its start: launched=%v lastGood=%v", m.launched, m.lastGood)
	}
	// Started of an older launch arms nothing.
	m.event(Msg{State: NBStopped, Launch: 2})
	m.event(Msg{State: NBStarted, Launch: 1})
	if m.launched {
		t.Fatal("an older launch's started event armed the monitors")
	}
}
