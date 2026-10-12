package main

import (
	"os"

	"github.com/irashack/molebridge/internal/tools/gluetun"
)

func init() {
	register("gluetun-auth",
		"write gluetun's control-server role file and the exit's API key (--rotate replaces both)",
		func(args []string) int {
			return gluetun.AuthMain(args, gluetun.Defaults(toolsEnv(), os.Stdout, os.Stderr))
		})
	register("gluetun-post-rules",
		"write gluetun's post-rules file from the routing settings in the environment",
		func(args []string) int {
			return gluetun.PostRulesMain(args, gluetun.Defaults(toolsEnv(), os.Stdout, os.Stderr))
		})
}
