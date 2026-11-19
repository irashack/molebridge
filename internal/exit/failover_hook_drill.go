//go:build drill

package exit

import (
	"strconv"
	"strings"
	"time"

	"github.com/irashack/molebridge/internal/applier"
	"github.com/irashack/molebridge/internal/failover"
)

// drillFailover shortens automatic failover's timings for the system rig's
// drills, below what the settings accept: MOLEBRIDGE_DRILL_FAILOVER_AFTER
// (seconds) replaces FAILOVER_AFTER and MOLEBRIDGE_DRILL_FAILOVER_RETURN
// (comma-separated seconds) the return schedule. It exists only in binaries
// built with the drill tag. MOLEBRIDGE_DRILL_FAILOVER_TRACE=1 logs each pass
// the policy observes, with the inspection it classified, and the bytes the
// tunnel moved during each failed egress check.
func drillFailover(env map[string]string, cfg *applier.Config) {
	c := &cfg.Failover
	if !c.On() {
		return
	}
	if env["MOLEBRIDGE_DRILL_FAILOVER_TRACE"] == "1" && cfg.Log != nil {
		log := cfg.Log
		cfg.FailoverTrace = func(line string) { log("drill: " + line) }
	}
	if n, err := strconv.Atoi(env["MOLEBRIDGE_DRILL_FAILOVER_AFTER"]); err == nil && n > 0 && n <= 3600 {
		c.After = time.Duration(n) * time.Second
	}
	if list := env["MOLEBRIDGE_DRILL_FAILOVER_RETURN"]; list != "" {
		var schedule []time.Duration
		for _, field := range strings.Split(list, ",") {
			n, err := strconv.Atoi(field)
			if err != nil || n <= 0 || n > 7200 {
				return
			}
			schedule = append(schedule, time.Duration(n)*time.Second)
		}
		failover.ReturnSchedule = schedule
	}
}
