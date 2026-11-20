//go:build linux && !drill

package exit

import "context"

// drillHooks is the drills' test hook (see worker_hook_drill_linux.go); the
// production binary has none.
func (w *worker) drillHooks() {}

// drillBetweenLinks is the drills' hook on a tunnel replacement (see
// worker_hook_drill_linux.go); the production binary has none.
func (w *worker) drillBetweenLinks() func(context.Context) { return nil }
