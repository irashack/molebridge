//go:build drill && linux

package tunnel

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/nstest"
)

func TestTheWireGuardFamilyProbeAnswersInTheNamespace(t *testing.T) {
	ns := nstest.New(t, "probe")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := probeWireGuardFamily(ctx, ns.Fd()); err != nil {
		t.Fatal(err)
	}
	dead, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := probeWireGuardFamily(dead, ns.Fd()); err == nil {
		t.Fatal("a cancelled context probed anyway")
	}
	late, cancel3 := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel3()
	if err := probeWireGuardFamily(late, ns.Fd()); err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}
