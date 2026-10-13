//go:build linux

package exit

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/irashack/molebridge/internal/tunnel"
)

// sample is the period of both monitors, and so their loop bound.
const sample = 2 * time.Second

// gluetunMonitors are the two checks the NetBird gate made on the gluetun
// backend, now loops of the worker under the lease (a stalled monitor lapses
// it):
//
//   - the fwmark monitor reads the overlay interface's fwmark through wgctrl
//     every 2 seconds. A missing interface, a failed read or a wrong mark
//     never advances the last good time; accounting starts at launch; NetBird
//     is stopped when it has not carried the control mark for FWMARK_GRACE
//     seconds, independent of the 30-second routing fallback;
//   - the log monitor reads only the current launch's bytes of NetBird's log
//     and stops NetBird on either line NetBird logs when it falls back from
//     advanced routing, so its control traffic would be unmarked.
type gluetunMonitors struct {
	w         *worker
	tun       *tunnel.Manager
	overlayIf string
	mark      uint32
	grace     time.Duration
	logPath   string

	fwProgress, logProgress atomic.Int64

	mu sync.Mutex
	// cur is the newest launch the supervisor announced; events of older
	// launches are ignored.
	cur      launchInfo
	launched bool
	launchAt time.Duration
	lastGood time.Duration
	lastSeen string
	scanner  *logScanner
}

func (w *worker) startGluetunMonitors(tun *tunnel.Manager) error {
	m := &gluetunMonitors{w: w, tun: tun, overlayIf: w.s.Routing.OverlayIf, mark: w.s.Routing.ControlMark,
		grace: w.s.FwmarkGrace, logPath: w.s.WatchLog}
	now := int64(w.clock())
	m.fwProgress.Store(now)
	m.logProgress.Store(now)
	w.monitors = m
	w.loops[LoopFwmark] = loopSource{func() time.Duration { return time.Duration(m.fwProgress.Load()) }, LoopBound}
	w.loops[LoopLog] = loopSource{func() time.Duration { return time.Duration(m.logProgress.Load()) }, LoopBound}
	go m.fwmarkLoop(w.ctx)
	go m.logLoop(w.ctx)
	return nil
}

// newLaunch starts accounting for a NetBird launch, at the launch itself: the
// supervisor reports it before the daemon exists, with the size NetBird's log
// had then and the boot-clock time the launch began. The log is read from that
// offset and the mark is owed from that time, however long `netbird up` takes,
// as when the gate was NetBird's parent.
func (m *gluetunMonitors) newLaunch(launch int, logOffset int64, at time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if launch < m.cur.launch {
		return
	}
	if now := m.w.clock(); at <= 0 || at > now {
		at = now
	}
	m.cur = launchInfo{launch: launch, offset: logOffset, at: at}
	m.arm()
}

// arm starts the accounting for the current launch from its own start.
func (m *gluetunMonitors) arm() {
	m.launched, m.launchAt, m.lastGood, m.lastSeen = true, m.cur.at, m.cur.at, "nothing"
	m.scanner = newLogScanner(m.logPath, m.cur.offset)
}

// event applies a supervisor report about NetBird to the monitors, by launch
// identity: launching arms the accounting of its launch; started for the
// current launch re-arms it if something had disarmed it; stopped or failed
// disarms only the launch it is about. A report of an older launch changes
// nothing.
func (m *gluetunMonitors) event(msg Msg) {
	switch msg.State {
	case NBLaunching:
		m.newLaunch(msg.Launch, msg.LogOffset, time.Duration(msg.AtBootNs))
	case NBStarted:
		m.mu.Lock()
		if msg.Launch == m.cur.launch && !m.launched {
			m.arm()
		}
		m.mu.Unlock()
	case NBStopped, NBFailed:
		m.mu.Lock()
		if msg.Launch == m.cur.launch {
			m.launched, m.scanner = false, nil
		}
		m.mu.Unlock()
	}
}

// stop is fatal to the generation, as `stop` was in wait-for-guards: NetBird
// cannot be trusted to mark its control traffic, so the worker ends, the
// supervisor runs the stop sequence, publishes the failure record and exits
// non-zero. It is never a silent relaunch of the rejected client.
func (m *gluetunMonitors) stop(reason string) {
	m.mu.Lock()
	m.launched, m.scanner = false, nil
	m.mu.Unlock()
	m.w.fatal(fmt.Sprintf("NetBird gate: stopping NetBird: %s (see docs/troubleshooting.md)", reason))
}

func (m *gluetunMonitors) fwmarkLoop(ctx context.Context) {
	for {
		value := "absent"
		mark, err := m.tun.FwmarkContext(ctx, m.overlayIf)
		if err == nil {
			if mark == 0 {
				value = "off"
			} else {
				value = fmt.Sprintf("0x%x", mark)
			}
		}
		now := m.w.clock()
		m.mu.Lock()
		if m.launched {
			if err == nil && mark == m.mark {
				m.lastGood = now
			}
			m.lastSeen = value
			if now-m.lastGood > m.grace {
				seen := m.lastSeen
				m.mu.Unlock()
				m.stop(fmt.Sprintf("%s has not carried the control mark 0x%x for %d seconds (last reported: %s)",
					m.overlayIf, m.mark, int(m.grace/time.Second), seen))
				m.fwProgress.Store(int64(m.w.clock()))
				if !sleepCtx(ctx, sample) {
					return
				}
				continue
			}
		}
		m.mu.Unlock()
		m.fwProgress.Store(int64(m.w.clock()))
		if !sleepCtx(ctx, sample) {
			return
		}
	}
}

func (m *gluetunMonitors) logLoop(ctx context.Context) {
	for {
		m.mu.Lock()
		sc := m.scanner
		m.mu.Unlock()
		if sc != nil && sc.step() {
			m.stop(FallbackMessage)
		}
		m.logProgress.Store(int64(m.w.clock()))
		if !sleepCtx(ctx, sample) {
			return
		}
	}
}

// checkControlServer is the start-time check that moved here from the host
// doctor: gluetun's control server listens on loopback only, read from
// /proc/net/tcp and /proc/net/tcp6. The loopback listener must exist (gluetun
// may take a few seconds to start it, so it is waited for, boundedly); a
// listener on the port on any other address is refused at once.
func (w *worker) checkControlServer() error {
	port, err := controlPort(w.s.Env["GLUETUN_CONTROL_URL"])
	if err != nil {
		return err
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		tcp4, tcp6, err := readProcNet()
		if err != nil {
			return fmt.Errorf("cannot read the listening sockets: %w", err)
		}
		found, refusal := ControlServerVerdict(tcp4, tcp6, port)
		if refusal != nil {
			return refusal
		}
		if found {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("gluetun's control server is not listening on 127.0.0.1 port %d", port)
		}
		if !sleepCtx(w.ctx, time.Second) {
			return context.Canceled
		}
	}
}
