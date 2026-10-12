//go:build linux

package tunnel

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// The deprecated library handles (legacy_linux.go) keep the bounds they had:
// closed at the deadline, replaced, and closed again if they arrive late.

type legacyWG struct {
	closed chan struct{}
	once   sync.Once
}

func (c *legacyWG) ConfigureDevice(string, wgtypes.Config) error {
	<-c.closed
	return errors.New("closed")
}
func (c *legacyWG) Device(string) (*wgtypes.Device, error) {
	<-c.closed
	return nil, errors.New("closed")
}
func (c *legacyWG) Close() error { c.once.Do(func() { close(c.closed) }); return nil }

type legacyLK struct {
	per    time.Duration
	calls  atomic.Int32
	closed chan struct{}
	once   sync.Once
}

func (f *legacyLK) wait() error {
	f.calls.Add(1)
	select {
	case <-time.After(f.per):
		return nil
	case <-f.closed:
		return errors.New("use of a closed handle")
	}
}
func (f *legacyLK) Close() { f.once.Do(func() { close(f.closed) }) }

func TestALegacyHandleGroupSharesOneAbsoluteDeadline(t *testing.T) {
	var all []*legacyLK
	var mu sync.Mutex
	m := &Manager{legacy: legacy{openLK: func() (linkAPI, error) {
		f := &legacyLK{per: 40 * time.Millisecond, closed: make(chan struct{})}
		mu.Lock()
		all = append(all, f)
		mu.Unlock()
		return f, nil
	}}}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := m.legacyLinkDo(ctx, func(h linkAPI) error {
		for i := 0; i < 3; i++ {
			if err := h.(*legacyLK).wait(); err != nil {
				return err
			}
		}
		return nil
	})
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if took := time.Since(start); took > 110*time.Millisecond {
		t.Errorf("took %v for a 70 ms deadline", took)
	}
	select {
	case <-all[0].closed:
	default:
		t.Error("the handle was not closed at the deadline")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := m.legacyLinkDo(ctx2, func(h linkAPI) error { return h.(*legacyLK).wait() }); err != nil || len(all) != 2 {
		t.Fatalf("%v (%d handles)", err, len(all))
	}
}

func TestALegacyHandleDeliveredAfterTheDeadlineIsClosed(t *testing.T) {
	late := &legacyLK{closed: make(chan struct{})}
	release := make(chan struct{})
	m := &Manager{legacy: legacy{openLK: func() (linkAPI, error) { <-release; return late, nil }}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := m.legacyLinkDo(ctx, func(linkAPI) error { return nil }); err == nil {
		t.Fatal("no error")
	}
	close(release)
	select {
	case <-late.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the handle delivered after cancellation was left open")
	}
	m.lmu.Lock()
	kept := m.llk
	m.lmu.Unlock()
	if kept != nil {
		t.Error("the late handle was kept")
	}
}

func TestALegacyWireGuardClientDeliveredAfterTheDeadlineIsClosed(t *testing.T) { // finding: a late client leaked
	late := &legacyWG{closed: make(chan struct{})}
	release := make(chan struct{})
	m := &Manager{legacy: legacy{openWG: func(context.Context) (wgClient, error) { <-release; return late, nil }}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := m.legacyWgDo(ctx, func(wgClient) error { return nil })
	if !errors.Is(err, os.ErrDeadlineExceeded) || time.Since(start) > 400*time.Millisecond {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
	close(release)
	select {
	case <-late.closed:
	case <-time.After(2 * time.Second):
		t.Fatal("the client delivered after cancellation was left open")
	}
}

func TestALegacyCallEndsAtTheDeadlineByClosingTheClient(t *testing.T) {
	c := &legacyWG{closed: make(chan struct{})}
	m := &Manager{legacy: legacy{openWG: func(context.Context) (wgClient, error) { return c, nil }}}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := m.legacyWgDo(ctx, func(w wgClient) error { _, err := w.Device("wt0"); return err })
	if err == nil || time.Since(start) > 400*time.Millisecond {
		t.Fatalf("%v after %v", err, time.Since(start))
	}
	select {
	case <-c.closed:
	default:
		t.Error("the client was not closed at the deadline")
	}
}
