//go:build linux

package nft

import (
	"context"
	"fmt"
	"time"

	"github.com/google/nftables"

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

// ListChainsContext is ListChains bounded by ctx. The nftables connection has
// no deadline of its own, so the dump runs on a lasting connection that is
// closed at the deadline, which unblocks its read; a fresh connection is used
// for the next call.
func ListChainsContext(ctx context.Context, netns int) ([]contract.NftChain, error) {
	return listChains(ctx, func() (lister, error) {
		opts := []nftables.ConnOption{nftables.AsLasting()}
		if netns != 0 {
			opts = append(opts, nftables.WithNetNSFd(netns))
		}
		return nftables.New(opts...)
	})
}

func listChains(ctx context.Context, open func() (lister, error)) ([]contract.NftChain, error) {
	var c lister
	err := rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, func() {}, func() error {
		var err error
		c, err = open()
		return err
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
