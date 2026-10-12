// Package contract is Molebridge's routing contract: the rules and routes an
// exit namespace must hold, whether a kernel snapshot holds them, and the
// ordered actions that restore them.
//
// It is a port of routing/contract-rules and routing/10-exit-routing (the
// expected rules, rule_actions, exit_table_actions, host_routes) and
// molebridge/routing.py (RoutingConfig, family_status,
// gluetun_transition_status, host_table_status, render_post_rules, the owner
// record), working on the decoded kernel state of internal/rtnl instead of
// `ip` text and `ip -j` JSON. Nothing here touches the kernel; internal/mutator
// applies what this package decides.
//
// Native backend: priorities 0-98 belong to Molebridge.
//
//	1  not iif <overlay> lookup local      local-delivery guard
//	90 iif <tunnel> to <overlay> lookup main
//	94 from <tunnel address> ipproto icmp lookup <exit>
//	95 iif <overlay> lookup <exit>
//	96 oif <tunnel> lookup <exit>
//	97 iif <overlay> unreachable
//	98 from <tunnel address> ipproto icmp unreachable
//
// gluetun backend: priorities 0-97 and 102-104 belong to Molebridge, with the
// control-plane rules 88 and 89, the overlay-bound rules 91 and 92, and the
// kill switch 102-104; see Spec.
package contract
