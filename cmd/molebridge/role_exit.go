package main

import (
	"fmt"
	"io"
	"os"

	"github.com/irashack/molebridge/internal/exit"
)

func init() {
	register("exit", "the exit node: supervisor (PID 1), routing worker, NetBird (internal flags: --worker, --cleanup)",
		func(args []string) int { return exitMain(args, os.Environ(), os.Stderr) })
}

// exitMain is `molebridge exit`. Without arguments it is the supervisor; the
// supervisor starts itself again with --worker (the routing worker) and
// --cleanup (the independent cleanup child). Settings come from the
// environment; a refusal prints one fixed line and exits 1 before anything
// changes.
func exitMain(args []string, environ []string, stderr io.Writer) int {
	env := exit.EnvMap(environ)
	switch {
	case len(args) == 0:
		s, err := exit.LoadSettings(env, exit.LoadOptions{WriteChecks: true})
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		// The supervisor's first line names the build. It follows the settings
		// check so that a refusal stays the one line it is documented as.
		fmt.Fprintf(stderr, "molebridge-exit: molebridge %s\n", version)
		return exit.New(exit.Config{Settings: s, Stderr: stderr}).Run()
	case args[0] == "--worker" && len(args) == 1:
		return exit.RunWorker(environ, stderr)
	case args[0] == "--cleanup":
		return exit.RunCleanup(args[1:], env, stderr)
	}
	fmt.Fprintln(stderr, "molebridge-exit: the only arguments are the internal --worker and --cleanup")
	return 2
}
