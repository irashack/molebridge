//go:build drill && linux

package nft_test

import (
	"testing"

	"github.com/irashack/molebridge/internal/contract"
	"github.com/irashack/molebridge/internal/nft"
	"github.com/irashack/molebridge/internal/nstest"
)

func run(t *testing.T, ns *nstest.NS, script string) {
	t.Helper()
	if out, err := ns.Exec("sh", "-c", script); err != nil {
		t.Skipf("nft is unavailable here: %v\n%s", err, out)
	}
}

// NetBird's nftables backend creates a table named netbird; its iptables
// backend (iptables-nft) creates chains named NETBIRD-*. Either is found; an
// unrelated ruleset is not NetBird.
func TestListChainsFindsNetBirdsFirewall(t *testing.T) {
	ns := nstest.New(t, "nft")
	none, err := nft.ListChains(ns.Fd())
	if err != nil {
		t.Fatal(err)
	}
	if contract.NetbirdFirewallPresent(none) {
		t.Fatal("an empty ruleset is not NetBird's firewall")
	}
	run(t, ns, "nft add table inet molebridge_guard && nft add chain inet molebridge_guard prerouting '{ type filter hook prerouting priority 0 ; }' && nft add table ip filter && nft add chain ip filter INPUT")
	chains, err := nft.ListChains(ns.Fd())
	if err != nil {
		t.Fatal(err)
	}
	if len(chains) != 2 || contract.NetbirdFirewallPresent(chains) {
		t.Fatalf("%+v", chains)
	}
	run(t, ns, "nft add table ip netbird && nft add chain ip netbird netbird-acl-input-rules")
	chains, _ = nft.ListChains(ns.Fd())
	if !contract.NetbirdFirewallPresent(chains) {
		t.Fatalf("%+v", chains)
	}
	ns2 := nstest.New(t, "nft2")
	run(t, ns2, "nft add table ip nat && nft add chain ip nat NETBIRD-RT-NAT")
	chains, _ = nft.ListChains(ns2.Fd())
	if !contract.NetbirdFirewallPresent(chains) {
		t.Fatalf("%+v", chains)
	}
	// Only an IPv4 table counts, as in the Python check.
	ns3 := nstest.New(t, "nft3")
	run(t, ns3, "nft add table ip6 netbird && nft add chain ip6 netbird netbird-acl-input-rules")
	chains, _ = nft.ListChains(ns3.Fd())
	if len(chains) == 0 || contract.NetbirdFirewallPresent(chains) {
		t.Fatalf("%+v", chains)
	}
}
