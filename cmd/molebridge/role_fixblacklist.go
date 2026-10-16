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
		"add the tunnel interface, and --add interfaces, to the stored NetBird profile's interface blacklist; --clear-external-ip-map (exit stopped)",
		func(args []string) int {
			return fixBlacklistMain(args, fixBlacklistEnv(), os.Stdout, os.Stderr, nbprofile.DefaultPaths)
		})
}

const fixBlacklistUsage = "usage: molebridge fix-blacklist [--add IFACE]... [--clear-external-ip-map] (settings come from the environment)"

// fixBlacklistMain is the operator's repair tool for D25. It reads the same
// non-secret settings the exit has (PROVIDER is accepted and unused here: the
// profile does not depend on it; EXIT_IF, TUNNEL_BACKEND and NB_STATE_DIR
// decide which profile and which interface), prints only fixed messages, the
// interface names it was given, and never anything read from the profile.
// --add IFACE (repeatable) also excludes IFACE, and --clear-external-ip-map
// empties the stored --external-ip-map: the edits for a peer moved to another
// runtime. Exit status 0 for a repair or an already-correct profile, 1 for a
// refusal, 2 for a usage error.
func fixBlacklistMain(args []string, env map[string]string, stdout, stderr io.Writer, paths func(stateDir string) nbprofile.Paths) int {
	var req nbprofile.FixRequest
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--clear-external-ip-map":
			req.ClearExternalIPMap = true
		case arg == "--add" && i+1 < len(args):
			i++
			req.Add = append(req.Add, args[i])
		case strings.HasPrefix(arg, "--add=") && len(arg) > len("--add="):
			req.Add = append(req.Add, strings.TrimPrefix(arg, "--add="))
		default:
			fmt.Fprintln(stderr, fixBlacklistUsage)
			return 2
		}
	}
	_, tunnelIF, stateDir, err := nbprofile.TunnelFromEnv(env)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	res, err := nbprofile.FixProfile(paths(stateDir), tunnelIF, req)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if !res.Changed {
		if len(req.Add) == 0 && !req.ClearExternalIPMap {
			fmt.Fprintf(stdout, "fix-blacklist: the stored NetBird profile %s already excludes the tunnel interface %s; nothing changed\n", res.Path, tunnelIF)
			return 0
		}
		names := strings.Join(append([]string{tunnelIF}, req.Add...), ", ")
		ext := ""
		if req.ClearExternalIPMap {
			ext = " and has no external-IP map"
		}
		fmt.Fprintf(stdout, "fix-blacklist: the stored NetBird profile %s already excludes the interfaces %s%s; nothing changed\n", res.Path, names, ext)
		return 0
	}
	for _, name := range res.Added {
		what := "the interface"
		if name == tunnelIF {
			what = "the tunnel interface"
		}
		fmt.Fprintf(stdout, "fix-blacklist: added %s %s to the interface blacklist of the stored NetBird profile %s\n", what, name, res.Path)
	}
	if res.ClearedExternalIPMap {
		fmt.Fprintf(stdout, "fix-blacklist: cleared the external-IP map (NATExternalIPs) of the stored NetBird profile %s\n", res.Path)
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
