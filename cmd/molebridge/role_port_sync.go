package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/irashack/molebridge/internal/exit"
	"github.com/irashack/molebridge/internal/portsync"
)

func init() {
	register("port-sync", "keep qBittorrent's listening port on the exit's forwarded port (no capabilities, writes nothing)",
		func(args []string) int {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()
			return portSyncMain(ctx, args, exit.EnvMap(os.Environ()), os.Stderr)
		})
}

// portSyncMain refuses a bad setting with one line and status 1, and
// otherwise runs until ctx ends (SIGTERM or SIGINT), then returns 0.
func portSyncMain(ctx context.Context, args []string, env map[string]string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: molebridge port-sync (settings come from the environment)")
		return 2
	}
	settings, err := portsync.LoadSettings(env)
	if err != nil {
		fmt.Fprintln(stderr, portsync.Prefix+err.Error())
		return 1
	}
	portsync.New(settings, stderr).Run(ctx)
	return 0
}
