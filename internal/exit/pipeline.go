package exit

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/irashack/molebridge/internal/applier"
	"github.com/irashack/molebridge/internal/validate"
)

// Pipeline is the provider pipeline as the worker drives it: one control cycle
// every TickInterval, and the container's operational health. *applier.Applier
// is one (through applierPipeline); the built-in inspector below is the other,
// for the exit kinds the native pipeline does not cover.
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

type applierPipeline struct{ a *applier.Applier }

func (p applierPipeline) Tick(ctx context.Context) error {
	_, err := p.a.Tick(ctx)
	return err
}

func (p applierPipeline) Healthy(ctx context.Context) bool { return p.a.Healthy(ctx) }

// pipelineEnv is what a pipeline is built from.
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
func newPipeline(e pipelineEnv) (Pipeline, error) {
	s := e.S
	exit := applier.Exit{ExitIf: s.Routing.ExitIf, OverlayIf: s.Routing.OverlayIf, Table: fmt.Sprint(s.Routing.Table),
		Overlay: s.Routing.Overlay.String(), Kind: s.Kind()}
	getenv := func(name string) string { return s.Env[name] }
	prov, err := applier.ProviderFor(s.Provider, exit, getenv)
	if err != nil {
		if s.Routing.IsGluetun() {
			// The gluetun providers are not the native pipeline's: until the
			// gluetun pipeline is wired in, the built-in inspector measures
			// what this process can and marks the rest unknown.
			return newInspector(e), nil
		}
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

// -- the built-in inspector ----------------------------------------------------

// inspector publishes a schema-2 record whose routing, traffic_protection and
// netbird checks are measured in this process (routing from the snapshot,
// netbird from the overlay link's kind and NetBird's nftables objects, as
// routing.py:545-570 judged them) and whose every other required check is
// unknown: it never claims a peer, a handshake or an egress it did not see.
type inspector struct {
	e   pipelineEnv
	sys applier.System
}

func newInspector(e pipelineEnv) *inspector { return &inspector{e: e, sys: e.System} }

func (in *inspector) measure(ctx context.Context) (protected, fallback, netbird bool) {
	s := in.e.S
	protected, fallback = true, true
	for _, fam := range []int{4, 6} {
		p, f, err := in.sys.RoutingStatus(ctx, fam, in.tunnelAddress(ctx, fam))
		if err != nil {
			protected, fallback = false, false
			break
		}
		protected, fallback = protected && p, fallback && f
	}
	if v, err := in.sys.ReadSysctl(ctx, applier.ReturnPathSysctl); err != nil || strings.TrimSpace(v) != "1" {
		protected = false
	}
	if s.Routing.Kind == "overlay" {
		wg, err1 := in.sys.OverlayKernelWireGuard(ctx)
		fw, err2 := in.sys.NetbirdFirewallPresent(ctx)
		netbird = err1 == nil && err2 == nil && wg && fw
	}
	return
}

// tunnelAddress is the family's global address on the exit interface.
func (in *inspector) tunnelAddress(ctx context.Context, family int) string {
	addrs, err := in.sys.TunnelAddresses(ctx)
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if (family == 4) == a.Is4() {
			return a.String()
		}
	}
	return ""
}

// Tick publishes one record.
func (in *inspector) Tick(ctx context.Context) error {
	s := in.e.S
	now := time.Now().UTC()
	rec := StartingRecord(s, now)
	rec["status"], rec["message"] = "unknown", "Provider verification is not available for this backend in this build."
	checks := rec["checks"].(map[string]any)
	at := validate.FormatTime(now)
	if s.Routing.Kind == "overlay" {
		protected, fallback, netbird := in.measure(ctx)
		state := func(ok bool) string {
			if ok {
				return "pass"
			}
			return "fail"
		}
		checks["routing"] = map[string]any{"state": state(protected), "at": at, "fallback": fallback}
		checks["traffic_protection"] = map[string]any{"state": state(protected), "at": at, "from": "routing"}
		checks["netbird"] = map[string]any{"state": state(netbird), "at": at}
		if !protected || !netbird {
			rec["status"] = "failed"
			rec["message"] = applier.RoutingFailed
			if protected {
				rec["message"] = applier.NetbirdModeFailed
			}
		}
	}
	return in.e.Publish(recordObj(OrderRecord(rec, s.Kind(), s.BackendName())))
}

// Healthy: the namespace is intact for the kind.
func (in *inspector) Healthy(ctx context.Context) bool {
	if in.e.S.Routing.Kind == "sidecar" {
		keys, err := in.sys.Peers(ctx)
		return err == nil && len(keys) == 1
	}
	protected, _, netbird := in.measure(ctx)
	return protected && netbird
}

// recordObj is an ordered record as a publishable value.
type recordObj validate.Obj

// JSONObject implements validate.ObjectMarshaler.
func (r recordObj) JSONObject() validate.Obj { return validate.Obj(r) }
