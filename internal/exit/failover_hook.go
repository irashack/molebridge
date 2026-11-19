//go:build !drill

package exit

import "github.com/irashack/molebridge/internal/applier"

// drillFailover is the drills' hook on automatic failover (see
// failover_hook_drill.go); the production binary has none.
func drillFailover(map[string]string, *applier.Config) {}
