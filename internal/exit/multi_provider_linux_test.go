//go:build linux

package exit

import (
	"context"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/irashack/molebridge/internal/applier"
	"github.com/irashack/molebridge/internal/rtnl"
	"github.com/irashack/molebridge/internal/validate"
)

// The exit's side of a provider change, short of the kernel: the tunnel
// source follows tunnel-provider.json, the remembered peer stays with the
// provider it was set for, and the public keys are each config's.

func multiWorker(t *testing.T, start string) (*worker, *fixture) {
	t.Helper()
	f := multiFixture(t, []string{"mullvad", "pia", "nordvpn"}, start)
	s, err := f.load()
	if err != nil {
		t.Fatal(err)
	}
	w := &worker{s: s}
	w.multi = newMultiSource(w)
	w.src = w.multi
	w.sys = &KernelSystem{S: s, Active: w.multi.active}
	return w, f
}

const peerKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestTheMultiProviderTunnelSourceFollowsTheActiveProvider(t *testing.T) {
	w, f := multiWorker(t, "mullvad")
	id, conf := w.tunnelSource().Current()
	if id != "mullvad" || conf != w.s.Confs["mullvad"] || w.activeProvider() != "mullvad" {
		t.Fatalf("%s %v", id, conf)
	}
	// What the applier's SetActive writes, before it asks for Replace.
	f.writeTunnelProvider(t, `{"provider":"pia"}`)
	if id, conf = w.tunnelSource().Current(); id != "pia" || conf != w.s.Confs["pia"] {
		t.Fatalf("%s %v", id, conf)
	}
	// The contract's expected state at a start is the active provider's:
	// PIA's config has no address, so rules 94 and 98 are the applier's.
	sp := w.spec()
	if len(sp.ReturnPath[rtnl.V4]) != 0 || !sp.LeaveReturnPath[rtnl.V4] {
		t.Errorf("spec %+v %+v", sp.ReturnPath, sp.LeaveReturnPath)
	}
	if w.rememberedPeerApplies() {
		t.Error("PIA's tunnel comes back on a remembered peer")
	}
	// A file that can't be read keeps the last provider read, never going
	// back to PROVIDER.
	f.writeTunnelProvider(t, `{"provider":`)
	if id, _ = w.tunnelSource().Current(); id != "pia" {
		t.Fatalf("after a bad read: %s", id)
	}
	f.writeTunnelProvider(t, `{"provider":"nordvpn"}`)
	if id, conf = w.tunnelSource().Current(); id != "nordvpn" || conf.Peer != nil {
		t.Fatalf("%s %v", id, conf)
	}
	sp = w.spec()
	if len(sp.ReturnPath[rtnl.V4]) != 1 || sp.LeaveReturnPath[rtnl.V4] {
		t.Errorf("spec %+v %+v", sp.ReturnPath, sp.LeaveReturnPath)
	}
}

func TestTheRememberedPeerStaysWithItsProvider(t *testing.T) {
	w, f := multiWorker(t, "mullvad")
	if !w.rememberedPeerApplies() {
		t.Fatal("Mullvad's tunnel comes back on its last peer")
	}
	peer := applier.PeerConfig{PublicKey: peerKey, Endpoint: "198.51.100.20:51820", AllowedIPs: []string{"0.0.0.0/0"}}
	// A switch on Mullvad: its tunnel comes back on the new peer.
	w.sys.rememberPeer(peer)
	_, conf := w.tunnelSource().Current()
	if conf.Peer == nil || conf.Peer.Endpoint.String() != "198.51.100.20:51820" {
		t.Fatalf("%v", conf)
	}
	if w.s.Confs["mullvad"].Peer.Endpoint.String() == "198.51.100.20:51820" {
		t.Fatal("the loaded config was changed")
	}
	// After the change to NordVPN, Mullvad's peer is not NordVPN's.
	f.writeTunnelProvider(t, `{"provider":"nordvpn"}`)
	if _, conf = w.tunnelSource().Current(); conf.Peer != nil {
		t.Fatalf("NordVPN's tunnel took Mullvad's peer: %v", conf.Peer)
	}
	// Replace remembers the peer for the provider it brought up.
	nord := applier.PeerConfig{PublicKey: peerKey, Endpoint: "203.0.113.30:51820", AllowedIPs: []string{"0.0.0.0/0"}}
	w.sys.rememberPeerFor("nordvpn", nord)
	if _, conf = w.tunnelSource().Current(); conf.Peer == nil || conf.Peer.Endpoint.String() != "203.0.113.30:51820" {
		t.Fatalf("%v", conf)
	}
	// Back on Mullvad, its tunnel comes up on its config's own peer.
	f.writeTunnelProvider(t, `{"provider":"mullvad"}`)
	if _, conf = w.tunnelSource().Current(); conf != w.s.Confs["mullvad"] {
		t.Fatalf("%v", conf)
	}
}

func TestTheExitGivesEachProvidersPublicKey(t *testing.T) {
	w, _ := multiWorker(t, "mullvad")
	tunnels := exitTunnels{w}
	want := wgtypes.Key(w.s.Confs["pia"].PrivateKey).PublicKey().String()
	for _, id := range []string{"mullvad", "pia", "nordvpn"} {
		key, err := tunnels.PublicKey(id)
		if err != nil || key != want {
			t.Errorf("%s: %q %v", id, key, err)
		}
	}
	if _, err := tunnels.PublicKey("gluetun-mullvad"); err == nil {
		t.Error("a key for a provider outside the set")
	}
	// Replace refuses a provider outside the set, and a worker without its
	// tunnel, before anything changes.
	if err := tunnels.Replace(context.Background(), "gluetun-mullvad", applier.PeerConfig{}); err == nil {
		t.Error("replaced with a provider outside the set")
	}
	if err := tunnels.Replace(context.Background(), "nordvpn", applier.PeerConfig{}); err == nil {
		t.Error("replaced without a tunnel")
	}
}

func TestTheMultiProviderPipelineHoldsEveryProvider(t *testing.T) {
	w, f := multiWorker(t, "nordvpn")
	f.writeTunnelProvider(t, `{"provider":"pia"}`)
	pipe, err := newPipeline(pipelineEnv{S: w.s, System: w.sys, Publish: func(validate.ObjectMarshaler) error { return nil },
		Log: func(string) {}, Tunnels: exitTunnels{w}})
	if err != nil {
		t.Fatal(err)
	}
	set := pipe.(applierPipeline).a.Providers()
	if got := strings.Join(set.IDs(), ","); got != "mullvad,pia,nordvpn" || set.Active() != "pia" {
		t.Fatalf("%s active %s", got, set.Active())
	}
	// Without the exit's tunnels the applier refuses a multi-provider set.
	if _, err := newPipeline(pipelineEnv{S: w.s, System: w.sys, Publish: func(validate.ObjectMarshaler) error { return nil },
		Log: func(string) {}}); err == nil {
		t.Fatal("a multi-provider pipeline without tunnels")
	}
}
