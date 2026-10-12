//go:build linux

package nft

import (
	"fmt"

	"github.com/google/nftables"

	"github.com/irashack/molebridge/internal/contract"
)

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

// ListChains returns every chain of every table, base chains and regular
// ones, as `nft -j list chains` did. netns is a file descriptor of a network
// namespace, 0 for the caller's.
func ListChains(netns int) ([]contract.NftChain, error) {
	var opts []nftables.ConnOption
	if netns != 0 {
		opts = append(opts, nftables.WithNetNSFd(netns))
	}
	c, err := nftables.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("nft: open netlink: %w", err)
	}
	chains, err := c.ListChains()
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
