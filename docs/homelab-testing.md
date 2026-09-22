# Reliability/security pass: homelab handoff

This revision changes routing initialization, applier runtime, catalogue
ownership, Compose mounts and status semantics. Unit tests and isolated Linux
namespace drills do not establish that the whole NetBird/Mullvad deployment
works. Run this pass on the existing homelab before trusting the update.

## Outcome of the 2026-09-20 pass

The pass ran on the original deployment (macOS/OrbStack, self-hosted NetBird)
with simulated client routing plus one real phone. Steady-state fail-closed
behaviour held in every drill for both families. It found six defects, all
fixed since: a single-family tunnel-route loss reported healthy; the applier
stayed Docker-healthy in an orphaned namespace; `OVERLAY_IF` was not passed to
NetBird; a transient start-up failure consumed the saved selection; NetBird
preceded the routing guards only by timing; and the exit's ICMP errors for
oversized tunnel replies left over the host's route, so UDP (QUIC) through the
exit stalled. Still unverified on a live deployment: host reboot and
container-runtime restart, a client held on the exit during a drill, and LAN
unreachability from a client. Rerun this pass after those fixes before relying
on a new revision.

## Prepare

1. Schedule an interruption for exit users. Keep an independent SSH/console
   connection to the host that does not depend on this exit.
2. Record the currently deployed Git revision locally for rollback. Back up
   `.env`, state, tunnel configuration, secret files and the named NetBird
   identity volume using your normal protected backup process. Do not commit
   or paste these files into a task, issue or CI log.
3. Follow [Upgrading from Switchyard](operations.md#upgrading-from-switchyard).
   In particular, keep the existing `COMPOSE_PROJECT_NAME`, `NB_HOSTNAME` and
   monitoring endpoint. Preserve the named identity volume.
4. Pull this revision. The routing script is now bundled root-owned in a
   derived WireGuard image; the checkout no longer needs root-owned init files.
   If the old root-owned `routing/` prevents Git updating it, restore that
   directory's ownership to the checkout owner before pulling.

## Build and deploy

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
The old `state/panel/relays.json` is ignored. Existing `desired.json` requests
remain readable; no key, peer or client route needs to be re-enrolled.

## Verify

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

## Record results

Record revision, OS/runtime versions, architecture, NetBird server/client
versions, which checks ran, and pass/fail outcomes in a sanitized test report.
Do not record real hostnames, addresses, peer IDs, account numbers or keys.
Distinguish isolated namespace CI results from real overlay/client results.

If rollback is needed, stop the exit containers first, restore the recorded
revision and protected configuration, then recreate the old stack using the
same project name and named volume. Never use `down -v` for rollback.
