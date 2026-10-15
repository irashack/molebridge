package main

import (
	"fmt"
	"io"
	"os"

	"github.com/irashack/molebridge/internal/exit"
)

func init() {
	register("check-config", "validate the exit's settings, tunnel config and NetBird profile; changes nothing",
		func(args []string) int { return checkConfigMain(args, exit.EnvMap(os.Environ()), os.Stdout, os.Stderr) })
}

// checkConfigMain validates what `molebridge exit` validates at start, with the
// exit's own environment, and changes nothing. On success it prints the lines
// `molebridge-exit --check-config` and the NetBird gate's `--check-config`
// printed.
func checkConfigMain(args []string, env map[string]string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: molebridge check-config (settings come from the environment)")
		return 2
	}
	s, err := exit.LoadSettings(env, exit.LoadOptions{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if s.NativeTunnel() {
		fmt.Fprintf(stdout, "molebridge-exit: configuration accepted (%s/%s.conf: %s)\n", s.ConfDir, s.Routing.ExitIf, s.Conf.Families())
	} else {
		fmt.Fprintln(stdout, "molebridge-exit: configuration accepted")
	}
	if s.Overlay() {
		fmt.Fprintln(stdout, "NetBird gate: configuration accepted")
	}
	return 0
}
