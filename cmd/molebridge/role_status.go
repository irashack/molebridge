package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/exit"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
	"github.com/irashack/molebridge/internal/verdict"
)

func init() {
	register("status", "print the exit's runtime status: the verdict with reason codes, heartbeat and lease",
		func(args []string) int {
			return statusMain(args, exit.EnvMap(os.Environ()), bootclock.System(), time.Now, os.Stdout, os.Stderr)
		})
}

// statusMain prints the runtime half of an exit's status, from inside its
// container: the verdict of internal/verdict on state/applier/result.json (the
// one judgment every reader makes), the heartbeat's age and the supervisor's
// lease. Everything printed is a fixed label, a reason code, a check state or
// a number; nothing secret is read. Exit status 0 when the exit is connected,
// 1 when it is not, 2 for a usage error.
func statusMain(args []string, env map[string]string, clock bootclock.Clock, wall func() time.Time, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: molebridge status")
		return 2
	}
	provider := env["PROVIDER"]
	if provider == "" {
		provider = "mullvad"
	}
	kind := env["EXIT_KIND"]
	cfg, err := verdict.NewExitConfig(provider, kind, "")
	if err != nil {
		fmt.Fprintf(stderr, "molebridge status: %v\n", err)
		return 1
	}
	stateDir := env["STATE_DIR"]
	if stateDir == "" {
		stateDir = exit.DefaultStateDir
	}
	result := state.ReadJSON(filepath.Join(stateDir, "applier", "result.json"), 16384)
	desired := state.ReadJSON(filepath.Join(stateDir, "panel", "desired.json"), 16384)
	v := verdict.Assess(cfg, result, verdict.TargetForPanel(result, desired, provider), wall())

	fmt.Fprintf(stdout, "state: %s (%s)\n", v.State, v.Label)
	reasons := "none"
	if len(v.Reasons) > 0 {
		reasons = strings.Join(v.Reasons, ", ")
	}
	fmt.Fprintf(stdout, "reasons: %s\n", reasons)
	if v.Tier != "" {
		fmt.Fprintf(stdout, "egress tier: %s\n", v.Tier)
	}
	if len(v.Checks) > 0 {
		parts := make([]string, len(v.Checks))
		for i, c := range v.Checks {
			parts[i] = c.Name + "=" + c.State
		}
		fmt.Fprintf(stdout, "checks: %s\n", strings.Join(parts, " "))
	}
	if v.Message != nil {
		fmt.Fprintf(stdout, "message: %s\n", *v.Message)
	}
	if v.ConfiguredServer != "" {
		fmt.Fprintf(stdout, "configured server: %s\n", v.ConfiguredServer)
	}

	if age, err := exit.HeartbeatAge(exit.HeartbeatPathOf(env), clock); err != nil {
		fmt.Fprintf(stdout, "heartbeat: none (%s)\n", err)
	} else if age > exit.MaxHeartbeatAge() {
		fmt.Fprintf(stdout, "heartbeat: stale (%d s old)\n", int(age/time.Second))
	} else {
		fmt.Fprintf(stdout, "heartbeat: fresh (%d s old)\n", int(age/time.Second))
	}
	fmt.Fprintf(stdout, "lease: %s\n", leaseLine(exit.LeasePathOf(env), clock))
	// The sidecar attachment and the host's checks are not made from here.
	if v.State == "ok" {
		return 0
	}
	return 1
}

// leaseLine reads the small file the supervisor keeps.
func leaseLine(path string, clock bootclock.Clock) string {
	o, ok := state.ReadObject(path, 4096)
	if !ok {
		return "unknown (no lease file; the supervisor is not running here)"
	}
	st, _ := o["state"].(string)
	updated, ok1 := validate.IsInt(o["updated_boot_ns"])
	expiry, ok2 := validate.IsInt(o["expiry_boot_ns"])
	if !ok1 || !ok2 || st == "" {
		return "unknown (unreadable lease file)"
	}
	now := clock()
	since := now - time.Duration(updated)
	if since > 10*time.Second {
		return fmt.Sprintf("unknown (the supervisor last wrote it %d s ago)", int(since/time.Second))
	}
	if st == "held" {
		left := time.Duration(expiry) - now
		if left <= 0 {
			return "lapsed"
		}
		return fmt.Sprintf("held, %d s to expiry", int(left/time.Second))
	}
	return st
}
