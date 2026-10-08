# Roadmap

Ideas that are not scheduled. Nothing here is built; each entry says what it
would take as far as we know today.

## Backlog

### A server set in configuration

Today a valid request in `state/panel/desired.json` decides the server an
exit uses. Without one, a native Mullvad exit keeps the peer in its tunnel
config, a new PIA or NordVPN exit waits for a selection, and gluetun starts
from its `GLUETUN_SERVER_*` filters. The panel writes the request, but the
applier doesn't care who did, so an exit runs without a panel if you write
that file yourself (its fields are in
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

### Our own routing image instead of LinuxServer's WireGuard image

`routing/Dockerfile` builds on `lscr.io/linuxserver/wireguard`, pinned by
digest. The native `wireguard` container relies on its init: our routing
script runs from `/custom-cont-init.d` (it must be root-owned there, which is
why the image carries it) before the init brings the tunnel up from
`wg_confs`, and that order is what keeps a starting exit fail-closed. Because
the init writes at start, that container can't have a read-only root
filesystem. The gluetun backend's `guard` uses the same image only as a shell
with iproute2, bypassing the init, so it carries tooling it never runs.

The idea is a small image of our own, for example Alpine with iproute2 and
wireguard-tools, whose entrypoint runs the routing script and then `wg-quick`.
Molebridge would then own the start order outright, the container could have a
read-only root, and one image could serve both the native exit and the guard.

To review before deciding:

- What LinuxServer's init does for this container that we would take over:
  signal handling, bringing the tunnel down cleanly on stop, PUID and PGID,
  module checks, logging. Read it at the pinned digest rather than assuming.
- LinuxServer's terms for images built on theirs, which matter if Molebridge
  ever publishes prebuilt images (today you build them locally), against what
  a base we maintain ourselves would cost to keep updated.
- Whether the change is worth the verification it needs: it touches the
  fail-closed path, so the checks in [verification](docs/verification.md) on
  Docker and on rootless Podman before anyone relies on it.
