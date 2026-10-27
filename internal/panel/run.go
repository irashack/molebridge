package panel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Run is `molebridge panel`: read the settings, check the process's
// isolation, serve until ctx ends. It returns the process's exit status.
// Settings and isolation refusals print their fixed messages to stderr and
// return 1 before anything listens.
func Run(ctx context.Context, env map[string]string, stderr io.Writer, probe IsolationProbe) int {
	cfg, err := ConfigFromEnv(env)
	if err != nil {
		fmt.Fprintf(stderr, "molebridge panel: %v\n", err)
		return 1
	}
	if err := VerifyIsolation(env, cfg.Exits, cfg.StateDir, probe, stderr); err != nil {
		var refused *ErrIsolation
		if errors.As(err, &refused) {
			for _, refusal := range refused.Refusals {
				fmt.Fprintf(stderr, "molebridge panel: refusing to start: %s\n", refusal)
			}
		}
		return 1
	}
	address := ListenAddr
	if override := env[ListenEnv]; override != "" {
		address = override
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Fprintf(stderr, "molebridge panel: cannot listen: %v\n", err)
		return 1
	}
	return Serve(ctx, NewServer(cfg, Options{Log: stderr}), listener, stderr)
}

const (
	idleTimeout = 60 * time.Second
	// Own probes take at most ceil(maxProbeTargets/probeWorkers) rounds of
	// probeAttempts*probeTimeout (33 s), then probeWait (60 s).
	writeTimeout = probeWait + time.Minute
)

// Serve runs the panel on a listener until ctx ends, then closes it. As a
// container's PID 1 the panel must stop on SIGTERM, or every stop would wait
// out the engine's timeout and end in SIGKILL.
func Serve(ctx context.Context, s *Server, listener net.Listener, stderr io.Writer) int {
	server := &http.Server{
		Handler: s,
		// The Python panel gave every socket operation ten seconds.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		// Connections are kept open between requests (a page load is about
		// seven, and every poll another), for at most this long idle.
		IdleTimeout: idleTimeout,
		// From the end of the request to the end of the answer, which bounds
		// a client that never reads it. The slowest handler is /api/latency:
		// its own probes, then up to probeWait for probes another request
		// started.
		WriteTimeout: writeTimeout,
		ErrorLog:     nil,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
		server.Close()
		return 0
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(stderr, "molebridge panel: %v\n", err)
			return 1
		}
		return 0
	}
}
