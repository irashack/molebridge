package exit

import (
	"net/netip"
	"testing"

	"github.com/irashack/molebridge/internal/applier"
	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/tunnelconf"
)

const (
	confKey  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	otherKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
)

func mullvadWorker(t *testing.T, withPeer bool) *worker {
	t.Helper()
	s := settingsFor(contract.Overlay, contract.Native, "mullvad")
	s.Routing.ExitIf = "mullvad"
	s.Conf = &tunnelconf.Conf{Provider: "mullvad"}
	if withPeer {
		s.Conf.Peer = &tunnelconf.Peer{Endpoint: netip.MustParseAddrPort("192.0.2.1:51820"),
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	}
	return &worker{s: s, sys: &KernelSystem{S: s}}
}

// The tunnel comes up on the remembered peer, and the config's own
// starting server only when nothing was remembered.
func TestTunnelComesUpOnTheRememberedPeer(t *testing.T) {
	w := mullvadWorker(t, true)
	if p := w.tunnelParams(); p.Conf != w.s.Conf {
		t.Fatal("with nothing remembered, the config itself")
	}
	peer := applier.PeerConfig{PublicKey: otherKey, Endpoint: "198.51.100.10:51820", AllowedIPs: []string{"0.0.0.0/0", "::/0"}, KeepaliveSec: 25}
	if err := w.sys.SetStartPeer(peer); err != nil {
		t.Fatal(err)
	}
	p := w.tunnelParams()
	if p.Conf == w.s.Conf || p.Conf.Peer.Endpoint.String() != "198.51.100.10:51820" || len(p.Conf.Peer.AllowedIPs) != 2 || p.Conf.Peer.Keepalive != 25 {
		t.Fatalf("start peer not used: %+v", p.Conf.Peer)
	}
	if w.s.Conf.Peer.Endpoint.String() != "192.0.2.1:51820" {
		t.Fatal("the settings' config was changed")
	}
	// A switch's peer replaces it; removing peers only forgets it.
	w.sys.rememberPeer(applier.PeerConfig{PublicKey: confKey, Endpoint: "203.0.113.7:51820", AllowedIPs: []string{"0.0.0.0/0"}})
	if p := w.tunnelParams(); p.Conf.Peer.Endpoint.String() != "203.0.113.7:51820" {
		t.Fatalf("switch peer not used: %+v", p.Conf.Peer)
	}
	w.sys.rememberPeer(applier.PeerConfig{})
	if p := w.tunnelParams(); p.Conf != w.s.Conf {
		t.Fatal("a forgotten peer still used")
	}
}

// NordVPN's peerless config comes back on the remembered peer after a tunnel
// loss; PIA's never gets one this way.
func TestRememberedPeerByProvider(t *testing.T) {
	for provider, want := range map[string]bool{"nordvpn": true, "pia": false} {
		w := mullvadWorker(t, false)
		w.s.Provider, w.s.Conf.Provider = provider, tunnelconf.Provider(provider)
		w.sys.rememberPeer(applier.PeerConfig{PublicKey: otherKey, Endpoint: "198.51.100.10:51820", AllowedIPs: []string{"0.0.0.0/0"}})
		if got := w.tunnelParams().Conf.Peer != nil; got != want {
			t.Errorf("%s: peer %v, want %v", provider, got, want)
		}
	}
}

func TestTunnelPeerRefusesBadValues(t *testing.T) {
	for name, pc := range map[string]applier.PeerConfig{
		"empty":    {},
		"key":      {PublicKey: "nope", Endpoint: "198.51.100.10:51820"},
		"endpoint": {PublicKey: otherKey, Endpoint: "198.51.100.10"},
		"allowed":  {PublicKey: otherKey, Endpoint: "198.51.100.10:51820", AllowedIPs: []string{"all"}},
	} {
		if _, err := tunnelPeer(pc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var w worker
	w.sys = &KernelSystem{}
	if err := w.sys.SetStartPeer(applier.PeerConfig{PublicKey: "nope"}); err == nil || w.sys.lastPeer() != nil {
		t.Fatal("a bad start peer was kept")
	}
}

type fixedSource struct {
	provider string
	conf     *tunnelconf.Conf
}

func (s fixedSource) Current() (string, *tunnelconf.Conf) { return s.provider, s.conf }

// A tunnel source set for the worker names what recovery brings up, in place
// of the settings' config and its remembered peer; without one the worker is
// the single-provider exit it was.
func TestTunnelComesUpOnTheSourcesConfig(t *testing.T) {
	w := mullvadWorker(t, true)
	if p, c := w.tunnelSource().Current(); p != "mullvad" || c != w.s.Conf {
		t.Fatalf("single source: %s %p", p, c)
	}
	other := &tunnelconf.Conf{Provider: "nordvpn", Addr4: netip.MustParseAddr("203.0.113.7")}
	w.src = fixedSource{"nordvpn", other}
	w.sys.rememberPeer(applier.PeerConfig{PublicKey: otherKey, Endpoint: "198.51.100.10:51820", AllowedIPs: []string{"0.0.0.0/0"}})
	if p := w.tunnelParams(); p.Conf != other || p.ExitIf != "mullvad" {
		t.Fatalf("source not used: %+v", p)
	}
}

// The starting expected state takes its return path from the config as it
// did before tunnel.ReturnPathOf.
func TestSpecReturnPathFromTheConfig(t *testing.T) {
	a4, a6 := netip.MustParseAddr("203.0.113.2"), netip.MustParseAddr("2001:db8:3::2")
	for name, tc := range map[string]struct {
		conf   *tunnelconf.Conf
		v4, v6 int
		leave  bool
	}{
		"both":    {&tunnelconf.Conf{Provider: "mullvad", Addr4: a4, Addr6: a6}, 1, 1, false},
		"v4 only": {&tunnelconf.Conf{Provider: "nordvpn", Addr4: a4}, 1, 0, false},
		"none":    {&tunnelconf.Conf{Provider: "pia"}, 0, 0, true},
		"no conf": {nil, 0, 0, false},
	} {
		w := mullvadWorker(t, false)
		w.s.Conf = tc.conf
		sp := w.spec()
		if len(sp.ReturnPath[rtnl.V4]) != tc.v4 || len(sp.ReturnPath[rtnl.V6]) != tc.v6 ||
			sp.LeaveReturnPath[rtnl.V4] != tc.leave || sp.LeaveReturnPath[rtnl.V6] != tc.leave || sp.TempGuard == nil {
			t.Errorf("%s: %+v", name, sp)
		}
	}
}
