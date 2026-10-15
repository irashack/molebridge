package exit

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/irashack/molebridge/internal/applier"
	"github.com/irashack/molebridge/internal/validate"
)

// Pipeline is the provider pipeline as the worker drives it: one control cycle
// every TickInterval, and the container's operational health. *applier.Applier
// is the implementation (through applierPipeline).
type Pipeline interface {
	// Tick runs one control cycle. An error is logged and the cycle repeats.
	Tick(ctx context.Context) error
	// Healthy is the operational health (D5): never "verified", only "intact".
	Healthy(ctx context.Context) bool
}

// TickInterval is the control cycle's period (applier.PollSec), and so the
// heartbeat's.
const TickInterval = applier.PollSec * time.Second

// HealthAge is how stale the heartbeat may be for `molebridge health`: three
// ticks, and never more than 30 seconds.
const HealthAge = 3 * TickInterval

//lint:ignore U1000 linux-only: built in newPipeline, used by worker_linux.go
type applierPipeline struct{ a *applier.Applier }

//lint:ignore U1000 linux-only: see applierPipeline
func (p applierPipeline) Tick(ctx context.Context) error {
	_, err := p.a.Tick(ctx)
	return err
}

//lint:ignore U1000 linux-only: see applierPipeline
func (p applierPipeline) Healthy(ctx context.Context) bool { return p.a.Healthy(ctx) }

// pipelineEnv is what a pipeline is built from.
//
//lint:ignore U1000 linux-only: built by newPipeline, called from worker_linux.go
type pipelineEnv struct {
	S       *Settings
	System  applier.System
	Publish func(validate.ObjectMarshaler) error
	// OwnerCheck is the supervisor's owner_record check as it would write it
	// now; nil where the exit carries none.
	OwnerCheck func() validate.Obj
	Log        func(string)
}

// newPipeline builds the pipeline for the settings' provider.
//
//lint:ignore U1000 linux-only: called from worker_linux.go
func newPipeline(e pipelineEnv) (Pipeline, error) {
	s := e.S
	exit := applier.Exit{ExitIf: s.Routing.ExitIf, OverlayIf: s.Routing.OverlayIf, Table: fmt.Sprint(s.Routing.Table), Kind: s.Kind()}
	if s.Routing.Overlay.IsValid() {
		exit.Overlay = s.Routing.Overlay.String()
	}
	for _, p := range append(append([]netip.Prefix(nil), s.Routing.LAN...), s.Routing.LAN6...) {
		exit.LAN = append(exit.LAN, p.String())
	}
	getenv := func(name string) string { return s.Env[name] }
	prov, err := applier.ProviderFor(s.Provider, exit, getenv)
	if err != nil {
		return nil, err
	}
	a, err := applier.New(applier.Config{
		StateDir: s.StateDir, Exit: exit, Provider: prov, System: e.System, Server: s.Server,
		Publish:    func(r *applier.Record) error { return e.Publish(r) },
		OwnerCheck: e.OwnerCheck, Log: e.Log,
		Gatus: applier.Gatus{URL: s.Env["GATUS_URL"], Token: s.Env["GATUS_TOKEN"], Endpoint: orDefault(s.Env["GATUS_ENDPOINT"], "molebridge")},
	})
	if err != nil {
		return nil, err
	}
	return applierPipeline{a}, nil
}
