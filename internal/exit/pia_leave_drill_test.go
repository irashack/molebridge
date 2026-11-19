//go:build drill && linux

package exit

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irashack/molebridge/internal/applier"
)

// noTunnels is a multi-provider applier's exit side for a drill that never
// changes the tunnel.
type noTunnels struct{}

func (noTunnels) PublicKey(string) (string, error) { return "", errors.New("not in this drill") }
func (noTunnels) Replace(context.Context, string, applier.PeerConfig) error {
	return errors.New("not in this drill")
}

// Leaving PIA on a multi-provider exit (docs/design/multi-provider.md, step
// 4) removes the port-forwarding table from the real kernel before another
// provider's tunnel can replace PIA's, and forgets the registration: a
// forwarded port must never point into another provider's tunnel.
func TestDrillLeavingPIATearsDownTheForwardTable(t *testing.T) {
	ks, ns := sysRig(t)
	ctx := context.Background()
	exit := applier.Exit{ExitIf: "mullvad", OverlayIf: "wt0", Table: "51821", Overlay: "192.0.2.0/24", Kind: "overlay"}
	pia := applier.NewPIA(applier.PIAConfig{PortForward: true, ForwardTarget: "192.0.2.10"})
	mullvad := applier.NewMullvad()
	dir := t.TempDir()
	a, err := applier.New(applier.Config{StateDir: dir, Exit: exit, Provider: pia,
		Providers: []applier.Provider{mullvad, pia}, Tunnels: noTunnels{}, System: offlineSystem{ks},
		Publish: func(*applier.Record) error { return nil }, Log: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	table := func() (string, error) { return ns.Exec("nft", "list", "table", "ip", "molebridge_forward") }

	// PIA forwarding a port, with its registration recorded.
	if err := ks.ApplyForwardRules(ctx, 43210, netip.MustParseAddr("192.0.2.10")); err != nil {
		t.Fatal(err)
	}
	if out, err := table(); err != nil || !strings.Contains(out, "43210") {
		t.Fatalf("the forward table: %v\n%s", err, out)
	}
	// tunnel.json, in the applier's directory when there is no private one.
	registration := filepath.Join(dir, "applier", "tunnel.json")
	if err := os.MkdirAll(filepath.Dir(registration), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(registration, []byte(`{"region": "ex_example"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := pia.Leave(ctx, a); err != nil {
		t.Fatal(err)
	}
	if out, err := table(); err == nil {
		t.Fatalf("the forward table outlived PIA:\n%s", out)
	}
	if out, _ := ns.Exec("nft", "list", "tables"); strings.Contains(out, "molebridge_forward") {
		t.Fatalf("the forward table outlived PIA:\n%s", out)
	}
	if _, err := os.Stat(registration); !os.IsNotExist(err) {
		t.Fatalf("PIA's registration outlived it: %v", err)
	}
	// Leaving again, with nothing left to remove, is not an error.
	if err := pia.Leave(ctx, a); err != nil {
		t.Fatal(err)
	}
}
