package applier

// NordVPN (NordLynx): shaped like Mullvad, with three differences
// (applier/nordvpn.py).
//
//   - One account key and the tunnel address 10.5.0.2/32 work on every server,
//     so the address is in the tunnel config before any switch, as with
//     Mullvad. The config has no peer: a fresh exit carries no traffic until a
//     server is chosen. NordLynx carries no IPv6, so forwarded IPv6 always hits
//     the exit table's unreachable fallback, as with PIA.
//   - Server keys belong to a location, not a server: every server in a city
//     can share one key. The current server is therefore the one whose address
//     is the live peer's endpoint (System.Endpoints), and whose key is the
//     peer's key. A switch replaces the peer even when the key stays the same,
//     so the new server's handshake is a fresh one.
//   - Egress is confirmed by NordVPN's ips/insights (protected), IPv4 only.
//     NordVPN serves that answer from a cache for up to an hour per address. An
//     answer of protected: false for an address that is the selected server's
//     own (NordLynx servers have so far exited from their entry address) is
//     asked again every InsightsRetrySec, for up to SwitchTimeoutSec and never
//     past a running switch's own timeout, before it counts. If it still says
//     false, the exit reports the failure; it is never accepted on the address
//     alone.
//
// The applier holds no NordVPN credential: prepare-config --nordvpn (or
// nordvpn-key) writes the private key once at setup, into the tunnel config
// the applier never mounts.

import (
	"context"
	"math"
	"strconv"
	"time"

	"github.com/irashack/molebridge/internal/netx"
	"github.com/irashack/molebridge/internal/providers"
	"github.com/irashack/molebridge/internal/validate"
)

const (
	// InsightsRetrySec is how long a cached "unprotected" answer for the
	// server's own address is waited out between asks.
	InsightsRetrySec = 10
	// InsightsMaxBytes bounds the insights answer.
	InsightsMaxBytes = 16384
)

type nordProvider struct{ BaseProvider }

// NewNordVPN is the NordVPN provider.
func NewNordVPN() Provider { return nordProvider{BaseProvider{Name: "nordvpn"}} }

// ServerFor: the server is the one whose address is the live peer's endpoint
// and whose key is the peer's key.
func (nordProvider) ServerFor(ctx context.Context, a *Applier, keys []string) (string, error) {
	return NordServerFor(ctx, a, keys)
}

// NordServerFor is NordVPN's server identification, for the gluetun backend's
// NordVPN entry too.
func NordServerFor(ctx context.Context, a *Applier, keys []string) (string, error) {
	if len(keys) != 1 {
		return "", nil
	}
	endpoints, err := a.sys.Endpoints(ctx)
	if err != nil {
		return "", err
	}
	host, ok := providers.ServerForEndpoint(a.catalog.Relays(), endpoints[keys[0]])
	if !ok {
		return "", nil
	}
	relay, _ := a.catalog.Relays().Get(host)
	if relay == nil || relay.PublicKey != keys[0] {
		return "", nil
	}
	return host, nil
}

// ApplyRelay replaces the peer. Every current peer goes first, including one
// with the new server's key, which another server in the same location may
// hold; a failed removal aborts before the new peer is added. IPv4 only.
func (nordProvider) ApplyRelay(ctx context.Context, a *Applier, relay *providers.Relay, keys []string) error {
	return a.sys.ReplacePeer(ctx, keys, PeerConfig{PublicKey: relay.PublicKey,
		Endpoint: relay.IPv4AddrIn + ":" + strconv.Itoa(providers.NordPort), AllowedIPs: []string{"0.0.0.0/0"}, KeepaliveSec: 25})
}

// NordInsights asks NordVPN whether the tunnel's address is protected.
func NordInsights(ctx context.Context, a *Applier) (EgressResult, error) {
	if _, err := a.tunnelAddresses(ctx, true); err != nil {
		return EgressResult{}, err
	}
	response, err := a.sys.Fetch(ctx, netx.Request{URL: providers.NordInsightsURL, Family: 4, BindInterface: a.exit.ExitIf,
		MaxBytes: InsightsMaxBytes, Timeout: 10 * time.Second})
	if err != nil {
		return EgressResult{}, err
	}
	decoded, err := validate.DecodeJSON(response.Body)
	if err != nil {
		return EgressResult{}, err
	}
	insights, err := providers.ParseInsights(decoded)
	if err != nil {
		return EgressResult{}, err
	}
	state := "fail"
	if insights.ExitConfirmed {
		state = "pass"
	}
	return EgressResult{EgressIP: insights.EgressIP, EgressCity: insights.EgressCity, EgressCountry: insights.EgressCountry,
		ExitConfirmed: insights.ExitConfirmed, EgressIPs: validate.Members("4", insights.EgressIP),
		Families: validate.Members("4", state)}, nil
}

// EgressFor: NordVPN's insights, with a cached answer for the server's own
// address asked again.
func (nordProvider) EgressFor(ctx context.Context, a *Applier, server string, age *int) (EgressResult, error) {
	return NordEgressFor(ctx, a, server)
}

// NordEgressFor is NordVPN's typed egress check (reused as is for
// gluetun-nordvpn).
func NordEgressFor(ctx context.Context, a *Applier, server string) (EgressResult, error) {
	var relay *providers.Relay
	if server != "" {
		relay, _ = a.catalog.Relays().Get(server)
	}
	deadline := a.clock() + SwitchTimeoutSec
	if a.switchDeadline != nil {
		// During a switch, never wait past the switch's own timeout.
		deadline = math.Min(deadline, *a.switchDeadline)
	}
	if a.retryDeadline != nil {
		// Nor, when asked a second time, past that attempt's budget.
		deadline = math.Min(deadline, *a.retryDeadline)
	}
	for {
		if err := a.withinRetryBudget(); err != nil {
			return EgressResult{}, err
		}
		fields, err := NordInsights(ctx, a)
		if err != nil {
			return EgressResult{}, err
		}
		// Any of the server's entry addresses (the gluetun backend lists them
		// all; the native catalogue has one).
		var entries []string
		if relay != nil {
			entries = relay.IPv4Addrs
			if len(entries) == 0 {
				entries = []string{relay.IPv4AddrIn}
			}
		}
		cached := false
		if !fields.ExitConfirmed {
			for _, e := range entries {
				cached = cached || e == fields.EgressIP
			}
		}
		if !cached || a.clock()+InsightsRetrySec > deadline {
			return fields, nil
		}
		a.sleep(ctx, InsightsRetrySec)
		if ctx.Err() != nil {
			return EgressResult{}, ctx.Err()
		}
	}
}

// Egress is the check with no server in view.
func (p nordProvider) Egress(ctx context.Context, a *Applier) (EgressResult, error) {
	return p.EgressFor(ctx, a, "", nil)
}

// NoPeerMessage asks for a server on a fresh exit.
func (p nordProvider) NoPeerMessage(a *Applier, keys []string) string {
	if len(keys) == 0 && a.target == nil {
		return "No NordVPN server is selected yet; choose one in the panel."
	}
	return p.BaseProvider.NoPeerMessage(a, keys)
}
