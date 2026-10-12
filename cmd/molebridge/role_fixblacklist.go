package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/irashack/molebridge/internal/nbprofile"
)

func init() {
	register("fix-blacklist",
		"add the tunnel interface to the stored NetBird profile's interface blacklist (exit stopped)",
		func(args []string) int {
			return fixBlacklistMain(args, fixBlacklistEnv(), os.Stdout, os.Stderr, nbprofile.DefaultPaths)
		})
}

// fixBlacklistMain is the operator's repair tool for D25. It reads the same
// non-secret settings the exit has (PROVIDER is accepted and unused here: the
// profile does not depend on it; EXIT_IF, TUNNEL_BACKEND and NB_STATE_DIR
// decide which profile and which interface), prints only fixed messages and
// never anything read from the profile. Exit status 0 for a repair or an
// already-correct profile, 1 for a refusal, 2 for a usage error.
func fixBlacklistMain(args []string, env map[string]string, stdout, stderr io.Writer, paths func(stateDir string) nbprofile.Paths) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: molebridge fix-blacklist (settings come from the environment)")
		return 2
	}
	_, tunnelIF, stateDir, err := nbprofile.TunnelFromEnv(env)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	res, err := nbprofile.FixBlacklist(paths(stateDir), tunnelIF)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if res.Changed {
		fmt.Fprintf(stdout, "fix-blacklist: added the tunnel interface %s to the interface blacklist of the stored NetBird profile %s\n", tunnelIF, res.Path)
	} else {
		fmt.Fprintf(stdout, "fix-blacklist: the stored NetBird profile %s already excludes the tunnel interface %s; nothing changed\n", res.Path, tunnelIF)
	}
	return 0
}

// fixBlacklistEnv returns the process environment as a map.
func fixBlacklistEnv() map[string]string {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	return env
}
