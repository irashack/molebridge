//go:build linux

package nft

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/rtnl"
)

// A change whose context is already over never opens a socket or touches the
// kernel, and says so with the deadline error the owner reports.
func TestForwardChangesHonorTheDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	target := netip.MustParseAddr("100.64.0.9")
	for name, err := range map[string]error{
		"guard":  InstallIngressGuard(ctx, 0, "mullvad", "wt0"),
		"apply":  ApplyForwardRules(ctx, 0, "mullvad", "wt0", 41234, target),
		"remove": RemoveForwardRules(ctx, 0),
	} {
		if !errors.Is(err, rtnl.ErrDeadline) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := ApplyForwardRules(context.Background(), 0, "mullvad", "wt0", 0, target); err == nil {
		t.Error("port 0 must be refused before any socket opens")
	}
}
