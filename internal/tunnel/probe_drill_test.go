//go:build drill && linux

package tunnel

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/irashack/molebridge/internal/nstest"
	"github.com/irashack/molebridge/internal/tunnel/wgnl"
)

func TestTheWireGuardSocketAnswersInTheNamespace(t *testing.T) {
	ns := nstest.New(t, "probe")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := wgnl.Dial(ctx, ns.Fd())
	if err != nil {
		t.Fatal(err)
	}
	// A device that is not there is an answer, not a failure of the socket.
	if _, err := c.Device(ctx, "nope"); !errors.Is(err, os.ErrNotExist) || c.Broken() {
		t.Fatalf("%v broken=%v", err, c.Broken())
	}
	_ = c.Close()
	dead, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if _, err := wgnl.Dial(dead, ns.Fd()); err == nil {
		t.Fatal("a cancelled context dialled anyway")
	}
	late, cancel3 := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel3()
	if _, err := wgnl.Dial(late, ns.Fd()); err == nil || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}
