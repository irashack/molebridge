package main

import (
	"fmt"
	"io"
	"os"

	"github.com/irashack/molebridge/internal/bootclock"
	"github.com/irashack/molebridge/internal/exit"
)

func init() {
	register("health", "exit 0 when the exit's heartbeat is fresh (the container health check); --guarded: a native sidecar's guards are in place",
		func(args []string) int { return healthMain(args, exit.EnvMap(os.Environ()), os.Stdout, os.Stderr) })
}

// healthMain is the container health check, operational only: the worker writes
// a heartbeat after each 5-second tick whose checks pass (tunnel interface,
// contract, NetBird running, the pipeline's own health), and health passes while
// it is no more than three ticks (15 seconds) old on the boot clock. A failed
// provider verification never fails it.
//
// With --guarded it answers a narrower question for a native sidecar: are its
// firewall and routing contract in place (the tunnel may still be down)? The
// worker renews that heartbeat every 2 seconds while both read back as
// installed. It is the startup gate for applications that share the
// namespace: before it passes, nothing keeps their traffic off the host path.
func healthMain(args []string, env map[string]string, stdout, stderr io.Writer) int {
	path := exit.HeartbeatPathOf(env)
	switch {
	case len(args) == 1 && args[0] == "--guarded":
		path = exit.GuardedPathOf(env)
	case len(args) != 0:
		fmt.Fprintln(stderr, "usage: molebridge health [--guarded]")
		return 2
	}
	ok, why := exit.Healthy(path, bootclock.System())
	if !ok {
		fmt.Fprintf(stdout, "unhealthy: %s\n", why)
		return 1
	}
	return 0
}
