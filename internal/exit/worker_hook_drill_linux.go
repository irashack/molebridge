//go:build linux && drill

package exit

import (
	"context"
	"os"
	"path/filepath"
	"runtime/pprof"
	"time"

	"github.com/irashack/molebridge/internal/mutator"
)

// drillHooks wedges the mutation owner on request: when the file
// <run dir>/wedge-mutator appears, one operation that never returns is queued,
// so the owner reports no more steps while the rest of the worker (the renewal
// loop included) keeps running. It exists only in binaries built with the
// drill tag.
func (w *worker) drillHooks() {
	// MOLEBRIDGE_DRILL_CPUPROFILE=<file> profiles the worker until it stops.
	if path := w.s.Env["MOLEBRIDGE_DRILL_CPUPROFILE"]; path != "" {
		if f, err := os.Create(path); err == nil && pprof.StartCPUProfile(f) == nil {
			w.drillStop = func() {
				pprof.StopCPUProfile()
				f.Close()
			}
		}
	}
	path := filepath.Join(w.s.RunDir, "wedge-mutator")
	go func() {
		for {
			if _, err := os.Stat(path); err == nil {
				w.logf("drill hook: wedging the mutation owner")
				_ = w.mut.Do(w.ctx, "wedge", func(tx *mutator.Tx) error {
					time.Sleep(time.Hour)
					return nil
				})
				return
			}
			if !sleepCtx(w.ctx, time.Second) {
				return
			}
		}
	}()
}

// drillBetweenLinks holds a tunnel replacement between its links on
// request: while the file <run dir>/hold-replace exists, Replace waits
// after deleting the old link and before creating the new one, until the
// file goes or the operation's deadline passes. The system rig kills the
// worker there (TestSystemRigMultiProviderInterruptedReplace).
func (w *worker) drillBetweenLinks() func(context.Context) {
	path := filepath.Join(w.s.RunDir, "hold-replace")
	return func(ctx context.Context) {
		if _, err := os.Stat(path); err != nil {
			return
		}
		w.logf("drill hook: holding the tunnel replacement between its links")
		for {
			if _, err := os.Stat(path); err != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}
}
