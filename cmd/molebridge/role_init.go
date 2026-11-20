package main

import (
	"os"

	"github.com/irashack/molebridge/internal/tools/initmenu"
)

func init() {
	register("init",
		"pick a provider, the ways in and the extras, and write a Compose file and an .env (experimental)",
		func(args []string) int {
			o := initmenu.Defaults(os.Stdin, os.Stdout, os.Stderr)
			o.Version = version
			return initmenu.Main(args, o)
		})
}
