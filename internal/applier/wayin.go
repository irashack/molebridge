package applier

import (
	"context"

	"github.com/irashack/molebridge/internal/validate"
)

// wayIn is the applier's one boundary to the exit's way in, the client peers
// reach the exit through: NetBird for an overlay exit (netbirdWayIn) and
// nothing for a sidecar (noWayIn). It matches the exit's own boundaries
// (internal/exit/wayin.go).
//
// The applier keeps when it asks and what follows: the gate waits while the
// way in is not ready, an inspection records the way in's check beside the
// routing contract's and is safe only when both hold, and the health check
// asks it on the overlay. What ready means, the check's name and the messages
// are the implementation's.
type wayIn interface {
	// Ready reports whether the way in runs as Molebridge requires now.
	Ready(ctx context.Context) bool
	// Record sets the way in's check in a measured finding's checks from
	// ready, measured at at. A way in with no check leaves the checks as
	// blankChecks fixed them (n/a).
	Record(checks validate.Obj, ready bool, at string) validate.Obj
	// Failed is the finding's guard when routing holds and the way in is not
	// ready.
	Failed() string
	// Waiting is the gate's pending message while the way in is not ready.
	Waiting() string
}

// newWayIn is the way in of this exit's kind.
func (a *Applier) newWayIn() wayIn {
	if a.kind() != "overlay" {
		return noWayIn{}
	}
	return netbirdWayIn{a.sys}
}

// noWayIn is the way in of a sidecar: nothing to wait for and no check of its
// own.
type noWayIn struct{}

func (noWayIn) Ready(context.Context) bool { return true }
func (noWayIn) Record(checks validate.Obj, _ bool, _ string) validate.Obj {
	return checks
}
func (noWayIn) Failed() string  { return "" }
func (noWayIn) Waiting() string { return "" }

// netbirdWayIn is NetBird on an overlay exit: ready when it runs kernel
// WireGuard on the overlay interface and its own kernel firewall is in
// place, as Molebridge requires; the record's netbird check says which.
type netbirdWayIn struct{ sys System }

func (n netbirdWayIn) Ready(ctx context.Context) bool {
	native, err := n.sys.OverlayKernelWireGuard(ctx)
	if err != nil || !native {
		return false
	}
	present, err := n.sys.NetbirdFirewallPresent(ctx)
	return err == nil && present
}

func (netbirdWayIn) Record(checks validate.Obj, ready bool, at string) validate.Obj {
	nb := "fail"
	if ready {
		nb = "pass"
	}
	return checks.Set("netbird", validate.Members("state", nb, "at", at))
}

func (netbirdWayIn) Failed() string { return NetbirdModeFailed }

func (netbirdWayIn) Waiting() string {
	return "Waiting for NetBird to run kernel WireGuard with its kernel firewall; " +
		"request will retry automatically."
}
