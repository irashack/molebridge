# Testing

Unit tests and the isolated Linux namespace drills in CI do not establish that a
whole NetBird/Mullvad deployment works. This page records what has been tested
on real hosts, and the pass to run on your own host before trusting a new
revision.

Revisions are given by their published hashes. The passes before 2026-09-24
ran on pre-publication hashes that a metadata-only history rewrite replaced;
each has an identical tree on `main` (`ae95c33` is `1390860`, `984a703` is
`336d904`, `afa8594` is `4739352`). CI results quoted for those revisions ran
on the old hashes. The panel switcher pass ran on branch hashes that the
rebase merge replaced, again with identical trees (`07c7b41` is `56ac2cc`,
`0d518e4` is `40c461c`).

## macOS / OrbStack pass

Apple silicon, self-hosted NetBird 0.78, simulated client routing plus one real
phone. Steady-state fail-closed behaviour held in every drill for both
families. The pass found six defects, all fixed in `1390860` through
`336d904`: a single-family tunnel-route loss reported healthy; the applier
stayed healthy in an orphaned namespace; `OVERLAY_IF` was not passed to
NetBird; a transient start-up failure consumed the saved selection; NetBird
preceded the routing guards only by timing; and the exit's ICMP errors for
oversized tunnel replies left over the host's route, so UDP (QUIC) through the
exit stalled.

## Rootless Podman pass

Revision `336d904` on Debian 13 / rootless Podman 5.4.2 / podman-compose 1.6.0
on amd64, NetBird client 0.79 against a self-hosted 0.79 management server,
through a Compose file carrying the same services and settings as
`compose.yaml`. Checked live, inside the namespace and from one iPhone client:

- Rules 90/94/95/96/97 present for both families with the `ipproto` qualifier
  on 94 and ahead of NetBird's own rules; `default dev mullvad` plus the
  unreachable fallback in the exit table for both families.
- ICMP from the tunnel address resolves to the tunnel interface for both
  families, while UDP from the same address takes the host path (the point of
  narrowing rule 94).
- Applier `--doctor`: recent check, routing protection, fresh catalogue and
  verified Mullvad egress all PASS; per-family egress probes succeed.
- Real client: mullvad.net/check clean, exit follows a server switch,
  direct (P2P) path once the peer carried the interface blacklist, a
  published UDP port and an external address mapping (see
  [operations](operations.md#exits-on-a-private-container-network)); without
  them every client was relayed.
- Recreation: a forced recreation of all four containers preserved the peer
  identity and rejoined the shared namespace.
- CI green at `336d904` (run on its pre-publication hash).

Found and fixed while adding Podman support: Docker-only Compose settings, the
missing `NET_RAW` capability, the panel user under uid remapping, the missing
kernel module autoload, and the interface blacklist as a requirement rather
than a tip (`4739352` through `336d904`).

## Live client and reboot pass at `5a6e0b5`

2026-09-24, the same Debian 13 / rootless Podman 5.4.2 / podman-compose 1.6.0
host, NetBird 0.79.0 client and self-hosted server. The client was a separate
NetBird 0.79.0 Linux peer (a container on another machine) with the exit
selected, probing IPv4 and IPv6 egress against `am.i.mullvad.net` about every
two seconds, 781 probes in all. Each family's probe used a pinned address, so a
failed family could not take the other's name resolution down with it.

**Fail-closed with the client on the exit.** All six drills from
[verification](verification.md#fail-closed-drills):

| Drill | Client during the drill | Status | After restore |
| :--- | :--- | :--- | :--- |
| Tunnel down | both families failed | — | Mullvad egress on both |
| IPv4 route deleted | IPv4 failed, IPv6 on Mullvad | `/readyz` 503 within 60 s, applier `failed` | Mullvad egress on both |
| IPv6 route deleted | IPv6 failed, IPv4 on Mullvad | `/readyz` 503 within 25 s | Mullvad egress on both |
| IPv4 lookup rule deleted | IPv4 failed, IPv6 on Mullvad | `/readyz` 503 within 45 s | recovered by recreating all four |
| IPv6 lookup rule deleted | IPv6 failed, IPv4 on Mullvad | `/readyz` 503 within 40 s | recovered by recreating all four |
| `wireguard` stopped | both families failed | — | recovered by recreating all four |

No probe returned a non-Mullvad address during any drill, and the exit host's
own traffic kept its ordinary path throughout.

**Reboot.** The host was rebooted with the client still selected. The
lingering boot unit brought the project up without intervention: all four
containers healthy 76 seconds after boot, one shared namespace, doctor 4×
PASS, the same peer identity, and `mullvad` still in the ICE blacklist. The
client failed closed for the whole outage (the NetBird client kept the exit
selected while the peer was offline) and regained Mullvad egress on its own.
A tunnel-down drill after the reboot failed closed.

**LAN isolation.** Through the exit, the client could not reach the exit
host's router (ICMP, TCP 80), the host itself (TCP 22), or the gateway of the
exit's container network. The host reached the same router and port directly,
so the targets were live.

**Oversized replies.** IPv6 replies larger than the overlay MTU made the exit
send ICMPv6 Packet Too Big (MTU 1280) out of the tunnel interface, sourced from
the tunnel address; a capture on the host-side interface saw no ICMP error
leave there. The public servers used ignore Packet Too Big for echo replies,
so that flow did not recover end to end. HTTP/3 (QUIC) requests through the
exit completed on both families to three large sites, but none of them sent
a datagram above 1280 bytes, so no live UDP flow exceeded the overlay MTU.

**Client fallback.** Deselecting the exit on the client sent its IPv4 traffic
out of the client's own connection at once. That is the documented boundary
in the README: server routing is not a device-wide kill switch.

## Clean install from the published files

2026-09-24, a fresh clone of `5a6e0b5` from GitHub on the same host, with the
bundled `compose.yaml` unchanged and only `.env` edited (project name, overlay
ranges, `PUID`/`PGID`, `PANEL_USER=0:0`, panel port, `NB_HOSTNAME`,
`NB_MANAGEMENT_URL`). A new peer enrolled with a fresh setup key; the tunnel
config came from an existing device while that device's other exit was
stopped. Following [setup](setup.md) with the
[rootless Podman commands](operations.md#rootless-podman):

- Build and start: all containers healthy, routing log `rules installed`, the
  three namespace users identical. podman-compose puts the project in its
  default pod; that works, no `x-podman` setting is needed.
- `NB_EXTRA_IFACE_BLACKLIST` put `mullvad` in the ICE blacklist at the first
  enrollment.
- [Namespace checks](verification.md#inside-the-namespace) 1 to 4 and 6 pass;
  doctor 4× PASS. The panel serves `/` and `/readyz`.
- The documented upgrade sequence (pull, build, recreate all four) left all
  four healthy in one namespace with the same peer identity, doctor passing.

This instance carried no client route and had no boot unit; the client and
reboot results above come from the long-running deployment.

**Fixed after the pass.** The panel did not exit on `SIGTERM`: as the
container's PID 1 without a handler it ignored the signal, so every stop waited
for the engine's 10-second timeout and then killed it. The panel now handles
`SIGTERM` and exits cleanly; this is a panel-only change, with routing, the
applier and Compose unchanged from `5a6e0b5`.

## Panel switcher pass at `56ac2cc` and `40c461c`

2026-09-25, the same Debian 13 / rootless Podman host, with each revision
deployed by pinning it in the owner's deployment tooling. That tooling
recreates all four containers on every pin change. Routing, the tunnel
configuration and Compose networking are unchanged from `b4cf640`.

At `56ac2cc`:

- Doctor 4× PASS before and after the deployment. All four containers were
  healthy, and the applier shared the WireGuard namespace.
- The live relay catalogue carried `owned`, `stboot` and `provider` with the
  expected types on every active relay: 536 relays, 113 Mullvad-owned, and
  all reported RAM-only at the time. Inactive relays were excluded as before.
- Panel in Chromium through an SSH forward:
  - Saved stayed hidden until a server was pinned.
  - The Mullvad-owned filter narrowed the list.
  - An opened country showed its Fastest row.
  - Escape cancelled an armed switch.
  - Both themes rendered correctly at desktop width and at 390 px.
- One switch to another server in the same city showed switch progress and
  reached connected about 2.4 s after the confirming click.

**Fixed after the pass**, in `40c461c`:

- a RAM-only filter that hid nothing, because every relay was RAM-only;
- a Switch button offered for the server a switch was already moving to;
- the current-exit line wrapping after its separator on a phone;
- the Diagnostics arrow spacing;
- browsers requesting a missing `/favicon.ico`.

At `40c461c`: doctor 4× PASS before and after, the exit returned on the same
server, and the catalogue refreshed. The page offered only the Mullvad-owned
filter, declared its icon, and made no `/favicon.ico` request. It showed no
console errors and kept the address together when the line wrapped, in both
themes.

Not tested live:

- the Switch-button fix, which needs a switch in progress;
- Retry, since no switch failed;
- fixed `PANEL_THEME=light` and `dark`, since only `auto` was used;
- screen readers beyond the announcement text;
- phone clients.

## Not yet tested

- A live UDP flow whose datagrams exceed the overlay MTU, and an IPv4
  fragmentation-needed error on a live flow. The isolated CI drill covers both
  return paths; the live pass above shows the IPv6 error leaving through the
  tunnel.
- Fail-closed drills with a phone client. The drills above used a Linux
  client; a phone's NetBird client may fall back to its own connection
  differently while the exit peer is offline.
- Docker Engine on Linux, Docker Desktop, and NetBird Cloud, end to end.

## Validating a new revision

### Prepare

1. Schedule an interruption for exit users. Keep an independent SSH/console
   connection to the host that does not depend on this exit.
2. Record the currently deployed Git revision locally for rollback. Back up
   `.env`, state, tunnel configuration, secret files and the named NetBird
   identity volume using your normal protected backup process. Do not commit
   or paste these files into a task, issue or CI log.
3. Keep the existing `COMPOSE_PROJECT_NAME`, `NB_HOSTNAME` and monitoring
   endpoint, and preserve the named identity volume.
4. Pull the new revision.

### Build and deploy

From the repository root on the host:

```sh
docker compose config --quiet
python3 tools/molebridge.py recover
python3 tools/molebridge.py doctor
docker compose ps
```

Recovery builds both derived images before stopping dependents, recreates the
shared namespace and all four containers, preserves the identity volume, and
waits for health. Its final doctor can fail if the account, relay API or egress
probe is unavailable; inspect locally without sharing secret-bearing output.

The applier should create `state/applier/relays.json` and `relay-error.json`.
Existing `desired.json` requests remain readable; no key, peer or client route
needs to be re-enrolled.

### Verify

- Confirm all namespace and client checks in [verification](verification.md),
  including **both** address families, DNS, tunnel down, route deletion, lookup
  rule deletion and container stop. Confirm the host's ordinary Internet path
  remains available while the client's exit path is blocked.
- Switch between two real relay locations, then select the same location again
  after a failed request. Confirm there is no automatic switch to another relay.
- Stop only the applier. After at most 150 seconds plus one 30-second browser
  poll, the panel must show unknown/stale and `/readyz` must return 503. Start
  it again; it must recover its catalogue and report the observed peer.
- Stop the panel or disconnect its browser access path. An already-open page
  must lose its connected indication on the next failed poll.
- Run `python3 tools/molebridge.py recover`, confirm the same NetBird peer
  identity remains enrolled, then repeat after a host reboot and a deliberate
  WireGuard container recreation. Use the helper if dependents are left in an
  old namespace; there is no automatic Docker-socket watchdog.
- With optional Gatus configured, confirm successful, failed and stale/missing
  pushes are handled as expected by your monitoring policy.

### Record results

Record revision, OS/runtime versions, architecture, NetBird server/client
versions, which checks ran, and pass/fail outcomes in a sanitized test report.
Do not record real hostnames, addresses, peer IDs, account numbers or keys.
Distinguish isolated namespace CI results from real overlay/client results.

If rollback is needed, stop the exit containers first, restore the recorded
revision and protected configuration, then recreate the old stack using the
same project name and named volume. Never use `down -v` for rollback.
