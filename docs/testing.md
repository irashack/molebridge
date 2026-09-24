# Testing

Unit tests and the isolated Linux namespace drills in CI do not establish that a
whole NetBird/Mullvad deployment works. This page records what has been tested
on real hosts, and the pass to run on your own host before trusting a new
revision.

## macOS / OrbStack pass

Apple silicon, self-hosted NetBird 0.78, simulated client routing plus one real
phone. Steady-state fail-closed behaviour held in every drill for both
families. The pass found six defects, all fixed in `ae95c33` through
`984a703`: a single-family tunnel-route loss reported healthy; the applier
stayed healthy in an orphaned namespace; `OVERLAY_IF` was not passed to
NetBird; a transient start-up failure consumed the saved selection; NetBird
preceded the routing guards only by timing; and the exit's ICMP errors for
oversized tunnel replies left over the host's route, so UDP (QUIC) through the
exit stalled.

## Rootless Podman pass

Revision `984a703` on Debian 13 / rootless Podman 5.4.2 / podman-compose 1.6.0
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
- CI green at `984a703`.

Found and fixed while adding Podman support: Docker-only Compose settings, the
missing `NET_RAW` capability, the panel user under uid remapping, the missing
kernel module autoload, and the interface blacklist as a requirement rather
than a tip (`afa8594` through `984a703`). The bundled `compose.yaml` validates
with `podman-compose config` but was not itself started unchanged.

## Not yet tested

On any host: a reboot and container-runtime restart, a client held on the exit
during a fail-closed drill, LAN unreachability from a client, and a live
oversized UDP flow (only the isolated drill proves the return path). Linux
hosts running Docker Engine, Docker Desktop and NetBird Cloud have not been
tested end to end.

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
