//go:build !drill

package exit

import "github.com/irashack/molebridge/internal/failover"

// drillFailover is the drills' hook on the failover timings (see
// failover_hook_drill.go); the production binary has none.
func drillFailover(_ map[string]string, c failover.Config) failover.Config { return c }
