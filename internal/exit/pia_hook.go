//go:build !drill

package exit

import "github.com/irashack/molebridge/internal/applier"

// drillProviders is the drills' hook on the providers (see
// pia_hook_drill.go); the production binary has none.
func drillProviders(map[string]string, func(string), ...applier.Provider) {}
