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

	mu       sync.Mutex
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

// newLaunch starts accounting for a NetBird launch: the log from the offset
// the supervisor reported, the mark from this moment.
func (m *gluetunMonitors) newLaunch(launch int, logOffset int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.w.clock()
	m.launched, m.launchAt, m.lastGood, m.lastSeen = true, now, now, "nothing"
	m.scanner = newLogScanner(m.logPath, logOffset)
}

func (m *gluetunMonitors) endLaunch() {
	m.mu.Lock()
	m.launched, m.scanner = false, nil
	m.mu.Unlock()
}

// stop tells the supervisor NetBird must not run.
func (m *gluetunMonitors) stop(reason string) {
	m.mu.Lock()
	m.launched, m.scanner = false, nil
	m.mu.Unlock()
	m.w.logf("%s", reason)
	m.w.nbRunning.Store(false)
	m.w.resetReady.Store(true)
	_ = m.w.send.send(Msg{Type: TypeUnready, Reason: truncate(reason, 900)})
}

func (m *gluetunMonitors) fwmarkLoop(ctx context.Context) {
	for {
		value := "absent"
		mark, err := m.tun.Fwmark(m.overlayIf)
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
