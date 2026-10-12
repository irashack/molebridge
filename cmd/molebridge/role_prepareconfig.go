package main

import (
	"os"

	"github.com/irashack/molebridge/internal/tools/prepareconfig"
)

func init() {
	register("prepare-config",
		"turn a Mullvad WireGuard download into the tunnel config, or (--pia) create a PIA one",
		func(args []string) int {
			return prepareconfig.Main(args, prepareconfig.Defaults(toolsEnv(), os.Stdout, os.Stderr))
		})
}
