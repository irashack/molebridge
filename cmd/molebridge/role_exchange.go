package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/irashack/molebridge/internal/exchange"
	"github.com/irashack/molebridge/internal/exit"
	"github.com/irashack/molebridge/internal/panel"
)

const exchangePrefix = "molebridge exchange: "

func init() {
	register("exchange", "the panel's side of the network exchange: receives exits' status, hands out requests (no capabilities, non-root)",
		func(args []string) int {
			fmt.Fprintf(os.Stderr, exchangePrefix+"molebridge %s\n", version)
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
			defer stop()
			return exchangeMain(ctx, args, exit.EnvMap(os.Environ()), os.Stderr, panel.DefaultProbe())
		})
}

// exchangeConfig is the exchange's settings.
type exchangeConfig struct {
	server            *exchange.Server
	listen            string
	certFile, keyFile string
}

// exchangeFromEnv reads PANEL_EXITS (the exits served, with the panel's ids),
// STATE_DIR, EXCHANGE_LISTEN, EXCHANGE_TOKENS_DIR and the optional
// EXCHANGE_CERT_FILE and EXCHANGE_KEY_FILE.
func exchangeFromEnv(env map[string]string) (*exchangeConfig, error) {
	stateDir := env["STATE_DIR"]
	if stateDir == "" {
		stateDir = "/state"
	}
	exits, err := panel.ParseExits(env["PANEL_EXITS"], stateDir)
	if err != nil {
		return nil, err
	}
	if len(exits) == 0 {
		return nil, errors.New("PANEL_EXITS names no exit; the exchange serves exits by their ids")
	}
	cfg := &exchangeConfig{listen: env["EXCHANGE_LISTEN"], certFile: env["EXCHANGE_CERT_FILE"], keyFile: env["EXCHANGE_KEY_FILE"]}
	if cfg.listen == "" {
		cfg.listen = "0.0.0.0:8097"
	}
	if host, port, err := net.SplitHostPort(cfg.listen); err != nil || host == "" || port == "" {
		return nil, errors.New("EXCHANGE_LISTEN is host:port with a host, such as 0.0.0.0:8097")
	}
	if (cfg.certFile == "") != (cfg.keyFile == "") {
		return nil, errors.New("EXCHANGE_CERT_FILE and EXCHANGE_KEY_FILE go together")
	}
	tokens := env["EXCHANGE_TOKENS_DIR"]
	if tokens == "" {
		tokens = "/run/secrets/exchange"
	}
	served := map[string]exchange.Exit{}
	for _, ex := range exits {
		served[ex.ID] = exchange.Exit{ID: ex.ID, Provider: ex.Provider, Dir: filepath.Join(stateDir, ex.ID)}
	}
	cfg.server = &exchange.Server{Exits: served, TokensDir: tokens}
	return cfg, nil
}

// exchangeMain refuses a bad setting or a failed self-check with one line and
// status 1, and otherwise serves until ctx ends.
func exchangeMain(ctx context.Context, args []string, env map[string]string, stderr io.Writer, probe panel.IsolationProbe) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: molebridge exchange (settings come from the environment)")
		return 2
	}
	cfg, err := exchangeFromEnv(env)
	if err != nil {
		fmt.Fprintln(stderr, exchangePrefix+err.Error())
		return 1
	}
	// The panel's first two checks: no capabilities, not root. The exchange
	// writes the copies, so the read-only check of applier/ is the panel's
	// alone.
	if refusals := exchangeIsolation(probe.Gather(env, nil, os.DevNull)); len(refusals) > 0 {
		for _, r := range refusals {
			fmt.Fprintln(stderr, exchangePrefix+"refusing to start: "+r)
		}
		return 1
	}
	for id := range cfg.server.Exits {
		if _, ok := exchange.ReadToken(filepath.Join(cfg.server.TokensDir, id)); !ok {
			fmt.Fprintf(stderr, exchangePrefix+"warning: no usable token for exit %s; its requests are refused\n", id)
		}
	}
	cfg.server.Logf = func(format string, a ...any) { fmt.Fprintf(stderr, exchangePrefix+format+"\n", a...) }
	listener, err := net.Listen("tcp", cfg.listen)
	if err != nil {
		fmt.Fprintf(stderr, exchangePrefix+"cannot listen: %v\n", err)
		return 1
	}
	return serveExchange(ctx, cfg, listener, stderr)
}

// exchangeIsolation is the panel's first two checks in the exchange's words:
// no capabilities, and not root unless PANEL_ALLOW_ROOT is 1. The exchange
// writes the copies, so the panel's read-only check of applier/ isn't one.
func exchangeIsolation(in panel.IsolationInputs) []string {
	var refusals []string
	switch {
	case !in.CapKnown:
		refusals = append(refusals, "the exchange cannot read its capability set from /proc/self/status, so it cannot show it has none")
	case in.CapEff != 0:
		refusals = append(refusals, "the exchange must run with no capabilities (cap_drop: [ALL]); its effective capability set is not empty")
	}
	if in.UID == 0 && in.AllowRoot != "1" {
		refusals = append(refusals, "the exchange must not run as root; run it as PANEL_USER, the panel's uid:gid (on a rootless engine, 0:0 with PANEL_ALLOW_ROOT=1)")
	}
	return refusals
}

func serveExchange(ctx context.Context, cfg *exchangeConfig, listener net.Listener, stderr io.Writer) int {
	server := &http.Server{
		Handler:           cfg.server,
		ReadHeaderTimeout: 10 * time.Second,
		// A catalog is up to 16 MiB.
		ReadTimeout:    90 * time.Second,
		WriteTimeout:   100 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	done := make(chan error, 1)
	go func() {
		if cfg.certFile != "" {
			done <- server.ServeTLS(listener, cfg.certFile, cfg.keyFile)
			return
		}
		done <- server.Serve(listener)
	}()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
		server.Close()
		return 0
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, exchangePrefix+"%v\n", err)
			return 1
		}
		return 0
	}
}
