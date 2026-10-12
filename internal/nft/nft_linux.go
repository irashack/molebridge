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

// ContextBudget bounds a listing whose context has no deadline: a call is
// always run under an absolute deadline.
const ContextBudget = 2 * time.Second

// lister is the part of *nftables.Conn the listing uses.
type lister interface {
	ListChains() ([]*nftables.Chain, error)
}

// connector opens the nftables connection. The library calls sockOpt on every
// netlink socket it creates, before the socket is used.
type connector func(sockOpt nftables.SockOption, netns int) (lister, error)

func dialNftables(sockOpt nftables.SockOption, netns int) (lister, error) {
	opts := []nftables.ConnOption{nftables.AsLasting(), nftables.WithSockOptions(sockOpt)}
	if netns != 0 {
		opts = append(opts, nftables.WithNetNSFd(netns))
	}
	return nftables.New(opts...)
}

// ListChains returns every chain of every table, base chains and regular
// ones, as `nft -j list chains` did, within DefaultBudget. netns is a file
// descriptor of a network namespace, 0 for the caller's.
func ListChains(netns int) ([]contract.NftChain, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultBudget)
	defer cancel()
	return ListChainsContext(ctx, netns)
}

// ListChainsContext is ListChains bounded by ctx, or by ContextBudget if ctx
// has no deadline. One netlink socket is created for the call, under that
// absolute deadline (set on the socket the moment the library creates it) and
// closed when the call ends or ctx does, which unblocks a read the deadline
// did not reach. The socket is never reused, and the library is not given the
// chance to open another: it would redial a transient socket if its lasting
// one were cleared, so the socket is closed directly rather than through
// CloseLasting, and the socket option refuses a second socket.
func ListChainsContext(ctx context.Context, netns int) ([]contract.NftChain, error) {
	return listChains(ctx, netns, dialNftables)
}

var errSecondSocket = errors.New("nft: refusing to open a second netlink socket for one call")

func listChains(ctx context.Context, netns int, open connector) ([]contract.NftChain, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, ContextBudget)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("nft: %w", boundedErr(err))
	}
	dl, _ := ctx.Deadline()
	var (
		mu      sync.Mutex
		sock    *netlink.Conn
		sockets int
	)
	closeSock := func() {
		mu.Lock()
		c := sock
		mu.Unlock()
		if c != nil {
			_ = c.Close()
		}
	}
	sockOpt := func(c *netlink.Conn) error {
		mu.Lock()
		defer mu.Unlock()
		sockets++
		if sockets > 1 {
			_ = c.Close()
			return errSecondSocket
		}
		if err := c.SetDeadline(dl); err != nil {
			_ = c.Close() // the library does not close a socket whose option failed
			return err
		}
		sock = c
		return nil
	}
	conn, err := open(sockOpt, netns)
	defer closeSock()
	if err != nil {
		return nil, fmt.Errorf("nft: open netlink: %w", err)
	}
	var chains []*nftables.Chain
	err = rtnl.RunBounded(ctx, rtnl.DefaultAbortGrace, closeSock, func() error {
		var err error
		chains, err = conn.ListChains()
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
