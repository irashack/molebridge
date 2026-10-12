//go:build linux

package nft

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/rtnl"
)

// DefaultBudget bounds ListChains, which has no context.
const DefaultBudget = 10 * time.Second

func familyName(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyBridge:
		return "bridge"
	case nftables.TableFamilyNetdev:
		return "netdev"
	}
	return fmt.Sprintf("family-%d", f)
}

// lister is the part of *nftables.Conn the listing uses. The connection is a
// lasting one, so that closing it cancels a call in flight.
type lister interface {
	ListChains() ([]*nftables.Chain, error)
	CloseLasting() error
}

// ListChains returns every chain of every table, base chains and regular
// ones, as `nft -j list chains` did, within DefaultBudget. netns is a file
// descriptor of a network namespace, 0 for the caller's.
func ListChains(netns int) ([]contract.NftChain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultBudget)
	defer cancel()
	return ListChainsContext(ctx, netns)
}

// ListChainsContext is ListChains bounded by ctx. Every socket the nftables
// connection opens carries the absolute deadline from the start, through the
// connection's own socket options, including the transient socket it opens by
// itself if the lasting one has been closed; and the dump also runs under
// rtnl.RunBounded, which closes the lasting connection at the deadline. A
// connection delivered after cancellation is closed.
func ListChainsContext(ctx context.Context, netns int) ([]contract.NftChain, error) {
	dl, _ := ctx.Deadline()
	return listChains(ctx, func() (lister, error) {
		opts := []nftables.ConnOption{nftables.AsLasting()}
		if !dl.IsZero() {
			opts = append(opts, nftables.WithSockOptions(func(c *netlink.Conn) error { return c.SetDeadline(dl) }))
		}
		if netns != 0 {
			opts = append(opts, nftables.WithNetNSFd(netns))
		}
		return nftables.New(opts...)
	})
}

func listChains(ctx context.Context, open func() (lister, error)) ([]contract.NftChain, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("nft: %w", boundedErr(err))
	}
	// The connection is handed over under a lock, so that one delivered after
	// the call gave up on it is closed by the goroutine that made it.
	var mu sync.Mutex
	var c lister
	abandoned := false
	err := rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, func() {
		mu.Lock()
		abandoned = true
		cc := c
		mu.Unlock()
		if cc != nil {
			_ = cc.CloseLasting()
		}
	}, func() error {
		opened, err := open()
		if err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		if abandoned {
			_ = opened.CloseLasting()
			return rtnl.ErrDeadline
		}
		c = opened
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("nft: open netlink: %w", err)
	}
	defer c.CloseLasting()
	var chains []*nftables.Chain
	err = rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, func() { _ = c.CloseLasting() }, func() error {
		var err error
		chains, err = c.ListChains()
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("nft: list chains: %w", err)
	}
	out := make([]contract.NftChain, 0, len(chains))
	for _, ch := range chains {
		if ch.Table == nil {
			continue
		}
		out = append(out, contract.NftChain{Family: familyName(ch.Table.Family), Table: ch.Table.Name, Name: ch.Name})
	}
	return out, nil
}

func boundedErr(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return rtnl.ErrDeadline
	}
	return err
}
