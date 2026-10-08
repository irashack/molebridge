# Roadmap

Ideas that are not scheduled. Nothing here is built; each entry says what it
would take as far as we know today.

## Backlog

### A server set in configuration

Today the server an exit uses is whatever `state/panel/desired.json` names.
The panel writes it, but the applier doesn't care who did, so an exit runs
without a panel if you write that file yourself (its fields are in
[configuration](docs/configuration.md#state-files)). That works, but it isn't
a documented way to run, and it isn't declarative: after the first selection
in a panel, the file is the panel's, and with the gluetun backend the applier
deliberately puts the last verified server back after gluetun restarts, over
`GLUETUN_SERVER_*`.

The idea is a `SERVER` setting (a hostname, or a region for PIA) with one rule:
when it is set, configuration wins.

- The applier ignores `desired.json` and always converges to `SERVER`; a
  gluetun restart returns to it too.
- The panel shows that exit as set in configuration and offers no switching,
  rather than accepting a selection the applier would undo.
- Without `SERVER`, nothing changes: the panel drives the exit.

What it takes: the setting and its validation against the provider's server
names, the applier's request path and the gluetun restore path, a read-only
state in the panel and in `/api/status`, docs (configuration, the panel page,
the standalone gluetun guide) and tests. A middle ground, a configured default
that the panel can override until the next restart, is close to what exists
now and is the confusing option.

### A sidecar mode: Switchyard for an ordinary gluetun container

Most people run gluetun as a sidecar: other containers share its network
namespace, so their traffic goes through the tunnel and gluetun's firewall
blocks anything else. They forward nobody's traffic, so Molebridge's routing
contract, guard and NetBird gate have nothing to do there. gluetun ships no
interface for choosing a server; you change its settings and restart it, or
call its control server.

The parts of Molebridge that are not about forwarding would serve them as
they are: the provider registry and catalogues, the egress checks that ask the
provider whether the address is theirs, server switching through gluetun's
control server, and the panel with sign-in and one tab per gluetun. By line
count that is roughly two-thirds of the code; the routing scripts,
`molebridge/routing.py` and the gate, about a quarter, would not apply.

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
