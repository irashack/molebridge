package main

import (
	"os"

	"github.com/irashack/molebridge/internal/tools/nordkey"
)

func init() {
	register("nordvpn-key",
		"fetch the NordLynx private key with an access token and write the tunnel config",
		func(args []string) int {
			return nordkey.Main(args, nordkey.Defaults(toolsEnv(), os.Stdin, os.Stdout, os.Stderr))
		})
}
