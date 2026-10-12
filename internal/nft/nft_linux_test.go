//go:build linux

package nft

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/nftables"
)

type fakeConn struct {
	stall  bool
	once   sync.Once
	closed chan struct{}
	chains []*nftables.Chain
}

func (f *fakeConn) ListChains() ([]*nftables.Chain, error) {
	if f.stall {
		<-f.closed
		return nil, errors.New("closed")
	}
	return f.chains, nil
}
func (f *fakeConn) CloseLasting() error { f.once.Do(func() { close(f.closed) }); return nil }

func TestAStalledChainDumpEndsAtTheDeadline(t *testing.T) { // finding: a stalled dump waited forever
	f := &fakeConn{stall: true, closed: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := listChains(ctx, func() (lister, error) { return f, nil })
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > 250*time.Millisecond {
		t.Errorf("took %v", time.Since(start))
	}
	select {
	case <-f.closed:
	default:
		t.Error("the connection was not closed")
	}
}

func TestChainsAreMapped(t *testing.T) {
	f := &fakeConn{closed: make(chan struct{}), chains: []*nftables.Chain{
		{Name: "netbird-acl", Table: &nftables.Table{Name: "netbird", Family: nftables.TableFamilyIPv4}},
		{Name: "orphan"},
	}}
	got, err := listChains(context.Background(), func() (lister, error) { return f, nil })
	if err != nil || len(got) != 1 || got[0].Family != "ip" || got[0].Table != "netbird" {
		t.Fatalf("%+v %v", got, err)
	}
	select {
	case <-f.closed:
	default:
		t.Error("the lasting connection was left open")
	}
}

func TestAnOpenFailureIsReported(t *testing.T) {
	_, err := listChains(context.Background(), func() (lister, error) { return nil, errors.New("no netlink") })
	if err == nil {
		t.Fatal("no error")
	}
}
