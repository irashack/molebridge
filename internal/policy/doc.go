// Package policy is the model of what the kernel's policy routing does with the
// packets the contract protects, and the check built on it: whether a state of
// the rules and routes lets any of them reach a place it must not, and whether
// removing one rule or route would.
//
// It is one definition used twice. The mutation owner asks it before every
// deletion it makes (a deletion that would turn a protected class of traffic
// into an escape is refused), and the tests ask it after every mutation of the
// fake kernel. The classes are the contract's reason for being:
//
//   - forwarded traffic arriving on the overlay interface, in both families
//     (with gluetun, under each mark NetBird and gluetun set): it may only be
//     routed by the exit table or stopped;
//   - ICMP the exit itself sends from a tunnel address, for every address live
//     on the tunnel interface and every return-path address the contract
//     expects: the exit table or stopped, never the host's route;
//   - packets arriving on the overlay for an address of the exit: never
//     delivered locally;
//   - with gluetun, the exit's own unmarked traffic (gluetun's tunnel table or
//     stopped), NetBird's control-marked traffic (the host table or stopped),
//     and what the exit sends to a client's overlay address (the overlay route
//     or stopped).
//
// A packet is followed through the rules by priority as the kernel does it:
// the selectors (input interface, from and to prefixes, firewall mark and
// mask, IP protocol, invert) decide whether a rule applies, a lookup in a
// table applies the table's best route and the rule's suppress_prefixlength,
// and a lookup that finds nothing falls through to the next rule. A rule with
// selectors this model does not understand (an unknown attribute, a TOS, an
// l3mdev) may or may not apply, and the answer is the worst that either would
// give. Interfaces are taken to exist: a rule marked detached applies as it
// will when its interface appears.
package policy
