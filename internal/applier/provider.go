package applier

import (
	"context"

	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

// Catalog is the applier's view of the relay catalogue: the validated
// snapshot and its refresh. The native providers use the snapshot of
// internal/providers (NativeCatalog); the gluetun backend reads gluetun's own
// list instead.
type Catalog interface {
	// Usable: there are relays and the snapshot is recent.
	Usable() bool
	// Relays are the entries by name.
	Relays() *providers.Entries
	// Snapshot holds the snapshot's members other than the relays.
	Snapshot() map[string]any
	// Refresh downloads (through fetch, which the gluetun catalogue ignores)
	// and publishes the catalogue. It returns true on success; on a failure
	// the last good catalogue stays and the error record says so.
	Refresh(ctx context.Context, fetch func() ([]byte, error)) (bool, error)
	// ExitIPs are the exit addresses the catalogue lists for a server, for the
	// tunnel tier's comparison; none for every native catalogue.
	ExitIPs(server string) []string
}

// Provider is what a provider overrides of the applier: the hooks the Python
// subclasses overrode (Applier, PiaApplier, NordApplier, GluetunApplier). The
// Applier holds one and calls through it; BaseProvider has the defaults, which
// are the Mullvad applier's behavior.
//
// Hooks run on the applier's goroutine. Each receives the Applier to reach the
// core (the pipeline's state and the Default* behaviors a hook may extend).
type Provider interface {
	// ID is the provider's registry id.
	ID() string
	// SwitchTimeout is how many seconds a switch is verified before it fails.
	SwitchTimeout() float64

	// MakeCatalog builds the catalogue for the applier's state directory.
	MakeCatalog(a *Applier) Catalog
	// FetchCatalog downloads the provider's server list.
	FetchCatalog(ctx context.Context, a *Applier) ([]byte, error)
	// MaintainCatalog refreshes the catalogue when it is due (Tick, first).
	MaintainCatalog(ctx context.Context, a *Applier) error

	// BeforeTick runs at the start of Tick, AfterTick at its end with the
	// record Tick is returning (nil for none).
	BeforeTick(ctx context.Context, a *Applier)
	AfterTick(ctx context.Context, a *Applier, result *Record)
	// BeforeGate runs before the pipeline's gates are evaluated.
	BeforeGate(ctx context.Context, a *Applier)

	// ServerFor names the server the live peers are, "" for none.
	ServerFor(ctx context.Context, a *Applier, keys []string) (string, error)
	// ApplyRelay points the tunnel at an approved relay. A failure after
	// which nothing changed wraps ErrMutationRefused; a refused login wraps
	// ErrCredentialRejected.
	ApplyRelay(ctx context.Context, a *Applier, relay *providers.Relay, keys []string) error

	// EgressFor is the egress fields for the current server; Egress is the
	// provider's own typed check (also what the default EgressFor uses when
	// the registry entry says "provider").
	EgressFor(ctx context.Context, a *Applier, server string, handshakeAge *int) (EgressResult, error)
	Egress(ctx context.Context, a *Applier) (EgressResult, error)
	// Echo is the caller's address from an IP echo service, through the tunnel
	// interface or, with tunnel false, over the host's own route.
	Echo(ctx context.Context, a *Applier, url string, family int, tunnel bool) (string, error)

	// RoutingStatus is (protected, fallback). Without requireAddress an
	// interface that has no address yet passes when its guards are intact: a
	// provider that assigns the address per server installs rules 94 and 98
	// with it.
	RoutingStatus(ctx context.Context, a *Applier, requireAddress bool) (protected, fallback bool)
	// MeasureGuards fills the overlay's own guard checks of an inspection:
	// the routing contract, NetBird's kernel mode.
	MeasureGuards(ctx context.Context, a *Applier, at string, f *Finding)

	// NoPeerMessage is what an inspection says when there is not exactly one
	// peer.
	NoPeerMessage(a *Applier, keys []string) string
	WaitingMessage() string
	MutationFailedMessage() string
	// ResultDefaults are members of every record, after the common ones;
	// PublishDefaults are members added after the explicit fields unless those
	// already have them.
	ResultDefaults() validate.Obj
	PublishDefaults() validate.Obj

	// RestoreTarget is the server to put back when nothing else selects one.
	RestoreTarget(a *Applier) *Selection
	// BeforeMutation runs just before the mutation's I/O; OnApplied when a
	// server is live after a mutation, verified or not; OnVerified when a check
	// passed on the target.
	BeforeMutation(ctx context.Context, a *Applier, target *Selection)
	OnApplied(a *Applier, server string) error
	OnVerified(a *Applier, server string) error
	// ControlAnswers is whether the provider's control plane answers (the
	// sidecar's health).
	ControlAnswers(ctx context.Context, a *Applier) bool
	// ReleaseSignature is what a rejection waits for; ok is false when the
	// provider has no signature of its own for this reason (the core's applies).
	ReleaseSignature(a *Applier, why string) (signature string, ok bool)
	// Published sees every record the applier publishes.
	Published(rec *Record)
}

// BaseProvider is the Mullvad applier's behavior and the defaults every other
// provider starts from. It holds no state and calls into the core only
// through the Applier it is given; providers embed it for the hooks they do
// not override, and nothing here dispatches to an overriding method.
type BaseProvider struct {
	// Name is the registry id this provider serves.
	Name string
}

// NewMullvad is the Mullvad provider.
func NewMullvad() Provider { return BaseProvider{Name: "mullvad"} }

// ID implements Provider.
func (b BaseProvider) ID() string { return b.Name }

// SwitchTimeout implements Provider.
func (BaseProvider) SwitchTimeout() float64 { return SwitchTimeoutSec }

// MakeCatalog implements Provider.
func (b BaseProvider) MakeCatalog(a *Applier) Catalog {
	return NativeCatalog(a.directory, b.Name, false, a.wall)
}

// FetchCatalog implements Provider.
func (BaseProvider) FetchCatalog(ctx context.Context, a *Applier) ([]byte, error) {
	return a.DefaultFetchCatalog(ctx)
}

// MaintainCatalog implements Provider.
func (BaseProvider) MaintainCatalog(ctx context.Context, a *Applier) error {
	return a.DefaultMaintainCatalog(ctx)
}

// BeforeTick implements Provider.
func (BaseProvider) BeforeTick(context.Context, *Applier) {}

// AfterTick implements Provider.
func (BaseProvider) AfterTick(context.Context, *Applier, *Record) {}

// BeforeGate implements Provider.
func (BaseProvider) BeforeGate(context.Context, *Applier) {}

// ServerFor implements Provider.
func (BaseProvider) ServerFor(_ context.Context, a *Applier, keys []string) (string, error) {
	return a.DefaultServerFor(keys), nil
}

// ApplyRelay implements Provider.
func (BaseProvider) ApplyRelay(ctx context.Context, a *Applier, relay *providers.Relay, keys []string) error {
	return a.DefaultApplyRelay(ctx, relay, keys)
}

// EgressFor implements Provider.
func (b BaseProvider) EgressFor(ctx context.Context, a *Applier, server string, age *int) (EgressResult, error) {
	return a.DefaultEgressFor(ctx, server, age)
}

// Egress implements Provider: Mullvad's check for every family the tunnel
// carries.
func (BaseProvider) Egress(ctx context.Context, a *Applier) (EgressResult, error) {
	return a.MullvadEgress(ctx)
}

// Echo implements Provider.
func (BaseProvider) Echo(ctx context.Context, a *Applier, url string, family int, tunnel bool) (string, error) {
	return a.DefaultEcho(ctx, url, family, tunnel)
}

// RoutingStatus implements Provider.
func (BaseProvider) RoutingStatus(ctx context.Context, a *Applier, requireAddress bool) (bool, bool) {
	return a.DefaultRoutingStatus(ctx, requireAddress)
}

// MeasureGuards implements Provider.
func (BaseProvider) MeasureGuards(ctx context.Context, a *Applier, at string, f *Finding) {
	a.DefaultMeasureGuards(ctx, at, f)
}

// NoPeerMessage implements Provider.
func (BaseProvider) NoPeerMessage(*Applier, []string) string {
	return "Expected exactly one tunnel peer."
}

// WaitingMessage implements Provider.
func (BaseProvider) WaitingMessage() string { return "Waiting for tunnel verification." }

// MutationFailedMessage implements Provider.
func (BaseProvider) MutationFailedMessage() string {
	return "Peer update failed; retrying automatically."
}

// ResultDefaults implements Provider.
func (BaseProvider) ResultDefaults() validate.Obj { return nil }

// PublishDefaults implements Provider.
func (BaseProvider) PublishDefaults() validate.Obj { return nil }

// RestoreTarget implements Provider.
func (BaseProvider) RestoreTarget(*Applier) *Selection { return nil }

// BeforeMutation implements Provider.
func (BaseProvider) BeforeMutation(context.Context, *Applier, *Selection) {}

// OnApplied implements Provider.
func (BaseProvider) OnApplied(*Applier, string) error { return nil }

// OnVerified implements Provider.
func (BaseProvider) OnVerified(*Applier, string) error { return nil }

// ControlAnswers implements Provider.
func (BaseProvider) ControlAnswers(context.Context, *Applier) bool { return true }

// ReleaseSignature implements Provider.
func (BaseProvider) ReleaseSignature(*Applier, string) (string, bool) { return "", false }

// Published implements Provider.
func (BaseProvider) Published(*Record) {}
