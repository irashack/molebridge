//go:build linux

package exit

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/applier"
	"github.com/irashack/molebridge/internal/tunnel"
	"github.com/irashack/molebridge/internal/tunnelconf"
)

// A multi-provider exit's side of a provider change
// (docs/design/multi-provider.md, step 6): its TunnelSource reads the active
// provider from tunnel-provider.json, which the applier writes before it
// asks for a replacement, and exitTunnels gives the applier each provider's
// public key and the whole-tunnel replacement (tunnel.Manager.Replace).

// multiSource is a multi-provider exit's TunnelSource: the config of the
// provider tunnel-provider.json names, on the last peer set for it when that
// provider comes back on its last peer (Mullvad, NordVPN).
type multiSource struct {
	w    *worker
	path string
	// mu guards last, the provider last read: a file that can't be read
	// keeps it, so a passing read error never brings back another
	// provider's tunnel.
	mu   sync.Mutex
	last string
}

func newMultiSource(w *worker) *multiSource {
	return &multiSource{w: w, path: applier.TunnelProviderPath(w.s.StateDir, w.s.PrivateDir), last: w.s.StartProvider}
}

// active is the provider tunnel-provider.json names now, or the last one
// read (the start provider before any).
func (m *multiSource) active() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id, ok := applier.ReadTunnelProvider(m.path, m.w.s.Providers); ok {
		m.last = id
	}
	return m.last
}

// Current implements tunnel.TunnelSource.
func (m *multiSource) Current() (string, *tunnelconf.Conf) {
	id := m.active()
	conf := m.w.s.Confs[id]
	if conf != nil && remembersPeer(id) && m.w.sys != nil {
		if peer := m.w.sys.lastPeerFor(id); peer != nil {
			c := *conf
			c.Peer = peer
			conf = &c
		}
	}
	return id, conf
}

// exitTunnels is a multi-provider exit's applier.ProviderTunnels.
type exitTunnels struct{ w *worker }

var _ applier.ProviderTunnels = exitTunnels{}

// PublicKey implements applier.ProviderTunnels: the public half of the
// provider's config key, which never leaves the exit.
func (t exitTunnels) PublicKey(provider string) (string, error) {
	conf := t.w.s.Confs[provider]
	if conf == nil {
		return "", fmt.Errorf("no tunnel config for %q", provider)
	}
	return wgtypes.Key(conf.PrivateKey).PublicKey().String(), nil
}

// Replace implements applier.ProviderTunnels: the tunnel in place, whatever
// provider's, is replaced with provider's config on peer, as one operation
// of the mutation owner. The old return path (the old config's rules 94 and
// 98, and those of any address still on the link, PIA's) goes with it.
func (t exitTunnels) Replace(ctx context.Context, provider string, peer applier.PeerConfig) error {
	w := t.w
	conf := w.s.Confs[provider]
	if conf == nil {
		return fmt.Errorf("no tunnel config for %q", provider)
	}
	if w.tun == nil || w.mut == nil {
		return errors.New("the tunnel is not ready")
	}
	next := *conf
	next.Peer = nil
	if peer.PublicKey != "" {
		p, err := tunnelPeer(peer)
		if err != nil {
			return err
		}
		next.Peer = p
	}
	from := tunnel.Params{ExitIf: w.s.Routing.ExitIf, Conf: w.built.Load()}
	to := tunnel.Params{ExitIf: w.s.Routing.ExitIf, Conf: &next}
	defer w.sys.invalidate()
	if err := w.tun.Replace(ctx, w.mut, from, to); err != nil {
		// Whatever was remembered was another provider's tunnel's.
		w.sys.rememberPeerFor(provider, applier.PeerConfig{})
		return err
	}
	w.built.Store(&next)
	w.sys.rememberPeerFor(provider, peer)
	w.mut.Reconcile("tunnel replaced")
	return nil
}
