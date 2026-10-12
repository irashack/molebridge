package main

import (
	"fmt"
	"io"
	"os"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/exit"
)

func init() {
	register("health", "exit 0 when the exit's heartbeat is fresh (the container health check)",
		func(args []string) int { return healthMain(args, exit.EnvMap(os.Environ()), os.Stdout, os.Stderr) })
}

// healthMain is the container health check, operational only: the worker writes
// a heartbeat after each 5-second tick whose checks pass (tunnel interface,
// contract, NetBird running, the pipeline's own health), and health passes while
// it is no more than three ticks (15 seconds) old on the boot clock. A failed
// provider verification never fails it.
func healthMain(args []string, env map[string]string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: molebridge health")
		return 2
	}
	ok, why := exit.Healthy(exit.HeartbeatPathOf(env), bootclock.System())
	if !ok {
		fmt.Fprintf(stdout, "unhealthy: %s\n", why)
		return 1
	}
	return 0
}
