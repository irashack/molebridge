package applier

import (
	"path/filepath"
	"testing"

	"github.com/irashack/molebridge/internal/jsonfile"
	"github.com/irashack/molebridge/internal/validate"
)

// The peer a native Mullvad tunnel starts with is the target's relay, from the
// cached catalog, and only when everything needed to trust it is there.
func TestStartPeer(t *testing.T) {
	catalog := map[string]any{testHost: mullvadEntry(testHost, testKey), otherHost: mullvadEntry(otherHost, otherKey)}
	mullvad := func(t *testing.T, server string, request map[string]any) *Applier {
		t.Helper()
		dir := t.TempDir()
		writeSnapshot(t, dir, "", catalog)
		if request != nil {
			if err := jsonfile.Write(filepath.Join(dir, "panel", "desired.json"), request, jsonfile.Options{}); err != nil {
				t.Fatal(err)
			}
		}
		return newApplier(t, newKernel(t), dir, NewMullvad(), server)
	}

	if _, _, ok := mullvad(t, "", nil).StartPeer(); ok {
		t.Fatal("a start peer with no target")
	}
	for name, a := range map[string]*Applier{
		"SERVER":            mullvad(t, otherHost, nil),
		"the panel request": mullvad(t, "", requestAt(otherHost, nil)),
	} {
		server, peer, ok := a.StartPeer()
		if !ok || server != otherHost || peer.PublicKey != otherKey || peer.Endpoint != "198.51.100.10:51820" ||
			len(peer.AllowedIPs) != 2 || peer.KeepaliveSec != 25 {
			t.Fatalf("%s: %v %q %+v", name, ok, server, peer)
		}
	}
	if _, _, ok := mullvad(t, "", requestAt("se-got-wg-009", nil)).StartPeer(); ok {
		t.Fatal("a start peer for a server the catalog doesn't list")
	}

	// A catalog older than a day is not trusted for it.
	dir := t.TempDir()
	old := validate.Members("fetched_at", "2000-01-01T00:00:00Z", "relays", catalog)
	if err := jsonfile.Write(filepath.Join(dir, "applier", "relays.json"), old, jsonfile.Options{Public: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := newApplier(t, newKernel(t), dir, NewMullvad(), otherHost).StartPeer(); ok {
		t.Fatal("a start peer from a stale catalog")
	}

	// NordVPN: its own peer, IPv4 only. PIA: none, its peer is a registration's.
	nord, _ := native(t, "nordvpn", "")
	if _, _, ok := nord.StartPeer(); ok {
		t.Fatal("a NordVPN start peer with no target")
	}
	nord, _ = native(t, "nordvpn", nordUS2)
	server, peer, ok := nord.StartPeer()
	if !ok || server != nordUS2 || len(peer.AllowedIPs) != 1 || peer.AllowedIPs[0] != "0.0.0.0/0" || peer.PublicKey == "" {
		t.Fatalf("NordVPN: %v %q %+v", ok, server, peer)
	}
	pia, _ := native(t, "pia", "")
	if _, _, ok := pia.StartPeer(); ok {
		t.Fatal("a start peer for PIA")
	}
}
