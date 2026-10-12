// Package rtnl speaks the parts of rtnetlink the routing contract needs: a
// lossless codec for FIB rules, decoders for routes, links and addresses, and
// (on Linux) a request socket and a multicast subscription built on
// mdlayher/netlink.
//
// The codec files carry no build tag so they can be tested and fuzzed
// anywhere. Anything that opens a socket is in a *_linux.go file.
//
// Fail-closed notes for callers:
//
//   - A decoded Rule keeps every attribute it arrived with. Attributes this
//     package does not model are kept raw in Rule.Unknown, so a rule with a
//     selector we do not understand never compares equal to one we expect, and
//     can still be deleted by sending the very same attributes back.
//   - Dumps are taken on a separate socket from the one that receives
//     multicast events, and the event socket is joined to its groups before
//     the first dump, so a change between "dump" and "watch" always produces
//     an event.
package rtnl
