# Roadmap

Ideas that are not scheduled. Nothing here is built; each entry says what it
would take as far as we know today.

## Backlog

### A sidecar mode: Switchyard for an ordinary gluetun container

gluetun's own documentation describes it as a sidecar: other containers
share its network namespace, so their traffic goes through the tunnel and gluetun's firewall
blocks anything else. They forward nobody's traffic, so Molebridge's routing
contract, guard and NetBird gate have nothing to do there. gluetun ships no
interface for choosing a server; you change its settings and restart it, or
call its control server.

The parts of Molebridge that are not about forwarding would serve them as
they are: the provider registry and catalogues, the egress checks that ask the
provider whether the address is theirs, server switching through gluetun's
control server, and the panel with sign-in and one tab per gluetun. The
routing scripts, `molebridge/routing.py` and the NetBird gate would not
apply.

What it takes:

- An applier mode without an exit: no guard, no NetBird, and a health check
  without the routing and NetBird checks (`routing_ok` and `netbird_native`
  are required today), keeping the tunnel, handshake and egress checks.
- A compose example that adds the applier and the panel next to an existing
  gluetun stack: the applier joins gluetun's namespace, reads its server list
  read-only and holds the control-server key; the panel holds no key, as now.
- Docs for that form, and a live pass recorded in [testing](docs/testing.md).

Not carried over: NetBird and the exit routing, and PIA's port forwarding,
which gluetun already does for PIA. The DNS-over-TLS leak that rules 102–104
close was found together with the exit's host table for NetBird's traffic;
whether a plain gluetun sidecar has it has not been checked.
