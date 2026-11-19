package applier

import (
	"context"
	"errors"
	"strings"

	"github.com/irashack/molebridge/internal/attempt"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/state"
	"github.com/irashack/molebridge/internal/validate"
)

// The target on a multi-provider exit (docs/design/multi-provider.md, step
// 3): a provider and a server, through the same admission pipeline. A
// target on the active provider is today's switch, through that provider's
// ApplyRelay. A target on another provider is a change of provider: the
// active provider leaves (Leave), the target provider prepares its tunnel
// outside the mutation owner (EnterTunnel: PIA registers the config's key),
// the target becomes the active provider, persisted, and the exit replaces
// the whole tunnel (ProviderTunnels.Replace); then the target is verified
// with its own provider's check. A failure stays on the target provider and
// is retried on the backoff: the exit never goes back by itself.
//
// None of this runs on a single-provider exit: its selections and attempts
// carry no provider, and every comparison below reduces to today's.

// ProviderTunnels is what a multi-provider applier needs of the exit to
// change provider: each provider's tunnel config is the exit's, parsed and
// validated at start.
type ProviderTunnels interface {
	// PublicKey is the public key of a provider's tunnel config, in
	// WireGuard's base64 form. The private key never leaves the exit.
	PublicKey(provider string) (string, error)
	// Replace replaces the tunnel in place, whatever provider's it is,
	// with provider's config carrying peer (none when peer.PublicKey is
	// empty): tunnel.Manager.Replace, one operation of the mutation owner.
	// The applier has made provider the active one (tunnel-provider.json)
	// before it asks, which is what the exit's TunnelSource reads, so a
	// tunnel lost during or after the change comes back as provider's.
	Replace(ctx context.Context, provider string, peer PeerConfig) error
}

// CredentialChecker is implemented by a provider whose credentials are
// files the applier reads (PIA's): a multi-provider exit's gate asks it
// before a change to that provider.
type CredentialChecker interface {
	// CredentialsReadable is nil when the credential files can be read now.
	CredentialsReadable() error
}

// providerOf is a selection's provider: its own on a multi-provider exit,
// the active one otherwise.
func (a *Applier) providerOf(s *Selection) string {
	if s != nil && s.Provider != "" {
		return s.Provider
	}
	return a.set.active
}

// onActive is true when a selection is on the active provider: always on a
// single-provider exit.
func (a *Applier) onActive(s *Selection) bool { return s == nil || a.providerOf(s) == a.set.active }

// attemptOnActive is true when the attempt's target is on the active
// provider; an attempt without a provider is the active provider's.
func (a *Applier) attemptOnActive(at *attempt.Attempt) bool {
	return at.Provider == "" || at.Provider == a.set.active
}

// catalogOf is the catalogue a selection's server is judged against: its
// provider's.
func (a *Applier) catalogOf(s *Selection) Catalog { return a.set.Catalog(a.providerOf(s)) }

// specOf is a provider's registry entry, the active one's for "".
func (a *Applier) specOf(provider string) *providers.Provider {
	if provider == "" || provider == a.set.active {
		return a.spec
	}
	spec, err := providers.Get(provider)
	if err != nil {
		return a.spec
	}
	return spec
}

// requestKey is a request's identity as a target key: its token, after its
// provider on a multi-provider exit.
func (a *Applier) requestKey(r state.Request) string {
	if r.Provider != "" {
		return r.Provider + "/" + state.RequestToken(r)
	}
	return state.RequestToken(r)
}

// desiredRequest reads a panel request: DesiredRequest on a single-provider
// exit, unchanged; DesiredRequestFor on a multi-provider exit, with a request
// that names no provider read as the active provider's.
func (a *Applier) desiredRequest(value any) (state.Request, bool) {
	if !a.multiProvider() {
		return state.DesiredRequest(value, a.hooks.ID())
	}
	request, ok := state.DesiredRequestFor(value, a.set.ids)
	if !ok {
		return state.Request{}, false
	}
	if request.Provider == "" {
		if !state.ValidServerName(request.Server, a.set.active) {
			return state.Request{}, false
		}
		request.Provider = a.set.active
	}
	return request, true
}

// configuredTarget splits a multi-provider exit's SERVER, <provider>/<server>,
// into its provider and server; ok is false when it doesn't parse.
func (a *Applier) configuredTarget() (provider, server string, ok bool) {
	provider, server, found := strings.Cut(a.configuredServer, "/")
	if !found || a.set.hooks[provider] == nil || !state.ValidServerName(server, provider) {
		return "", "", false
	}
	return provider, server, true
}

// replacementOf is replacementFor for a selection's provider: a retired
// server is replaced only on the active provider, whose location memory and
// catalogue are resident. Another provider's retired server stays refused
// until that provider is active.
func (a *Applier) replacementOf(provider, server string) string {
	if a.multiProvider() && provider != "" && provider != a.set.active {
		return ""
	}
	return a.replacementFor(server)
}

// credentialsGate is the gate's message when the target provider's
// credentials can't be read, "" when they can (or it has none).
func (a *Applier) credentialsGate(provider string) string {
	if !a.multiProvider() {
		return ""
	}
	checker, ok := a.set.Hooks(provider).(CredentialChecker)
	if !ok || checker.CredentialsReadable() == nil {
		return ""
	}
	return "Waiting for " + a.specOf(provider).Label + "'s credentials; request will retry automatically."
}

// Leave implements Provider: Mullvad and NordVPN hold nothing beyond the
// tunnel.
func (BaseProvider) Leave(context.Context, *Applier) error { return nil }

// EnterTunnel implements Provider: Mullvad's tunnel comes up on the relay's
// peer, its key and addresses from its config.
func (BaseProvider) EnterTunnel(_ context.Context, _ *Applier, relay *providers.Relay, replace func(PeerConfig) error) error {
	return replace(relayPeer(relay))
}

// EnterTunnel implements Provider: NordVPN's tunnel comes up on the
// server's peer, IPv4 only.
func (nordProvider) EnterTunnel(_ context.Context, _ *Applier, relay *providers.Relay, replace func(PeerConfig) error) error {
	return replace(nordPeer(relay))
}

// changeProvider applies a target on another provider than the active one.
// The attempt is recorded attempting, with the target's provider, before
// any I/O. Then the active provider leaves, the target provider enters:
// what it must do outside the mutation owner first, then SetActive and the
// exit's Replace, then (PIA) its address and peer. A refusal before
// SetActive leaves the active provider's tunnel as it was; a failure after
// it leaves the exit with no tunnel, fail-closed, until the exit's recovery
// brings up the target provider's config. Either way the attempt fails and
// is re-applied on the backoff, on the target provider.
func (a *Applier) changeProvider(ctx context.Context, target *Selection) (*Record, error) {
	at := a.attempt
	to := target.Provider
	enter := a.set.Hooks(to)
	relay, listed := a.set.Catalog(to).Relays().Get(target.Server)
	keys, err := a.peers(ctx)
	current := ""
	if err == nil {
		current, err = a.hooks.ServerFor(ctx, a, keys)
	}
	if err != nil || !listed || a.tunnels == nil {
		at.State, at.Outcome = "pending", "pending"
		at.Message = "Waiting for the WireGuard interface; request will retry automatically."
		if err := a.saveAttempt(); err != nil {
			return nil, err
		}
		return a.Inspect(ctx, false)
	}
	at.State, at.Outcome, at.Message = "attempting", "", ""
	at.Provider = to
	at.Attempts++
	a.passMutated = true
	now := a.clock()
	at.LastMutationAt = &now
	at.MutationCertainty = "uncertain"
	at.NextAction, at.NextActionAt = "", nil
	if generation := a.currentGeneration(ctx); generation != "" {
		at.Generation = generation
	}
	// Recorded before any I/O: a lost response can hide success.
	if err := a.saveAttempt(); err != nil {
		return nil, err
	}
	a.log("applier: changing the tunnel's provider from " + a.spec.Label + " to " + a.specOf(to).Label)
	message := "Changing the exit's provider to " + a.specOf(to).Label + "."
	if _, err := a.publishRecord("applying", message, current, nil, nil); err != nil {
		return nil, err
	}
	err = a.hooks.Leave(ctx, a)
	if err == nil {
		err = enter.EnterTunnel(ctx, a, relay, func(peer PeerConfig) error {
			if err := a.set.SetActive(to); err != nil {
				return err
			}
			return a.tunnels.Replace(ctx, to, peer)
		})
	}
	return a.afterMutation(ctx, target, err)
}

// publicKeyOf is a provider's config key from the exit, checked.
func (a *Applier) publicKeyOf(provider string) (string, error) {
	if a.tunnels == nil {
		return "", errors.New("no tunnel configs to change provider with")
	}
	key, err := a.tunnels.PublicKey(provider)
	if err != nil {
		return "", err
	}
	key = strings.TrimFunc(key, validate.IsSpace)
	if !validate.ValidKey(key) {
		return "", errors.New("invalid tunnel config public key")
	}
	return key, nil
}
