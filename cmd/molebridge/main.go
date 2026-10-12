// Command molebridge is the single Molebridge binary. The role is always the
// first argument; it is never guessed from the environment.
package main

import (
	"fmt"
	"os"
)

type role struct {
	run  func(args []string) int
	help string
}

// roles is filled by the role files in this directory (one init per role).
var roles = map[string]role{}

func register(name, help string, run func(args []string) int) {
	if _, dup := roles[name]; dup {
		panic("molebridge: role registered twice: " + name)
	}
	roles[name] = role{run: run, help: help}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: molebridge <role> [arguments]")
	fmt.Fprintln(os.Stderr, "roles:")
	for _, name := range sortedRoles() {
		fmt.Fprintf(os.Stderr, "  %-20s %s\n", name, roles[name].help)
	}
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	r, ok := roles[os.Args[1]]
	if !ok {
		fmt.Fprintf(os.Stderr, "molebridge: unknown role %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	os.Exit(r.run(os.Args[2:]))
}
