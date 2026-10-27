package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/irashack/molebridge/internal/panel"
)

func init() {
	register("panel", "Switchyard, the web panel for choosing an exit's server (no capabilities, non-root)",
		func(args []string) int {
			if len(args) != 0 {
				fmt.Fprintln(os.Stderr, "usage: molebridge panel (settings come from the environment)")
				return 2
			}
			// The first line names the build, before any refusal.
			fmt.Fprintf(os.Stderr, "molebridge panel: molebridge %s\n", version)
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()
			return panel.Run(ctx, fixBlacklistEnv(), os.Stderr, panel.DefaultProbe())
		})
}
