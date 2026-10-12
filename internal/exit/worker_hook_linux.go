//go:build linux && !drill

package exit

// drillHooks is the drills' test hook (see worker_hook_drill_linux.go); the
// production binary has none.
func (w *worker) drillHooks() {}
