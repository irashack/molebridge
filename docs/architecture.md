# Architecture

## Goal and boundary

Keep a device on NetBird while Internet traffic received by this exit leaves
through Mullvad. If the tunnel is unavailable, forwarded traffic must fail.
This is a property of the exit namespace, not a device-wide kill switch:
deselecting the exit, disconnecting NetBird, client-local routes, DNS and client
IPv6 behavior require separate verification.

## Components and trust

One Compose project, four containers:

| Container | Runtime | Role |
|---|---|---|
| `wireguard` | Local build from pinned LinuxServer WireGuard | Owns the namespace, installs routing, brings up the tunnel |
| `netbird` | Pinned official NetBird client | Joins the namespace as the overlay exit peer |
| `applier` | Local build from the pinned Python slim base, Debian wg/ip/curl tools | Joins the namespace, owns the relay catalogue, validates requests and controls the peer |
| `control-panel` | Pinned official Python slim | Separate bridge, loopback publish, non-root, no capabilities or subprocesses |

Build both derived images with `docker compose build wireguard applier`. The
routing script is copied root-owned into the WireGuard image, so the checkout
needs no root-owned directories. Each base is
pinned by multi-architecture digest. Debian tools come from signed package
repositories and may change on an uncached rebuild; rebuild deliberately and
rerun verification. The Docker build context excludes configuration, state and
secrets.

The panel can write only its request directory. It reads `state/applier/`
through a read-only mount. It cannot change the relay catalogue, result or
applier code. An old `state/panel/relays.json` has no authority and is ignored.

The applier never mounts the tunnel config, invokes a shell, or reads a
WireGuard private key. Nevertheless it has `NET_ADMIN` in the tunnel namespace:
a compromised applier can retrieve the live key and alter routing. It belongs
to the trusted computing base, along with Docker, the host and NetBird.
Its filesystem is read-only except for its own state and bounded scratch space.

## Routing contract

Initialization installs temporary IPv4 and IPv6 `iif wt0 unreachable` rules at
priority 80. They block forwarding while the permanent rules are rebuilt. The
temporary rules are removed only after all installation commands succeed.
A readiness marker gates the WireGuard healthcheck and dependent startup.

| Priority | Rule | Purpose |
|---|---|---|
| 90 | `iif mullvad to <overlay range> lookup main` | Tunnel replies return over the overlay. Client-originated traffic cannot use this exception. |
| 95 | `iif wt0 lookup 51821` | Forwarded traffic uses the exit table. |
| 96 | `oif mullvad lookup 51821` | Interface-bound health probes use the same table. |
| 97 | `iif wt0 unreachable` | Terminal guard if lookup 95 or all exit-table routes disappear. |
| — | `unreachable default metric 4096 table 51821` | Fallback when the tunnel route is absent. |

IPv6 uses the same contract. Rule 90 is omitted for IPv6 when no IPv6 overlay
range is configured. Table numbers 0–255 are reserved and refused. Interface
names and overlay ranges are validated.

The tunnel uses `Table = off`. Its `PostUp` adds a default route through
`mullvad` to the exit table; `PreDown` removes it. The fallback and terminal
guard are not removed on tunnel down. The exit's own unbound traffic continues
through the ordinary route so NetBird and Mullvad control traffic can connect.
The applier verifies rule priorities/selectors, both fallback routes and that
the exit table contains no route through another interface. An unknown rule
ahead of the guard, an extra selector, or a temporary guard left behind prevents
a healthy result.

A privileged actor can remove or bypass these protections. Health polling
detects drift; it is not an instantaneous defense against a compromised host.

## Relay catalogue

The applier fetches the fixed HTTPS Mullvad relay API at startup and every six
hours. Redirects and proxy environment overrides are refused. Input is size
limited, decoded as JSON with duplicate keys rejected, and checked for active
WireGuard entries, hostname shape, canonical 32-byte base64 keys, IPv4 endpoints
and bounded location strings.

It atomically writes `state/applier/relays.json`. Failed or empty refreshes
keep the last good catalogue and publish a sanitized error in
`relay-error.json`; retries happen every minute. A catalogue older than 24
hours cannot authorize a new switch or a healthy result. It does not remove a
working tunnel merely because the API is unavailable.

## Requests and switching

1. The panel checks membership in the read-only catalogue and atomically writes
   `desired.json` with `server`, `requested_at` and a random `request_id`.
2. Every five seconds the applier reads a bounded, regular, non-symlink file.
   It validates the entire schema and resolves the name only through its own
   fresh catalogue. The old two-field request schema remains readable.
3. Before changing a peer it verifies routing protection. It removes old peers
   and aborts if removal fails, then applies the approved key/endpoint using
   fixed subprocess argument lists and timeouts.
4. It probes Mullvad through the tunnel for up to roughly 60 seconds. Success
   requires a fresh non-future handshake, a typed Mullvad egress response and
   intact routing protection. The current server is derived from live peer
   state, including the initial server from the downloaded configuration.
5. A rejected request or failed switch is acknowledged as failed and is not
   retried every five seconds. Selecting the same server again creates a new
   request and retries. No other server is selected automatically. After normal
   tunnel recreation, a previously successful desired selection is reapplied.

A failed health probe does not necessarily mean traffic is blocked: a working
approved tunnel can carry traffic while the verification endpoint is unavailable.
A failed switch remains visibly failed until a new request or process restart.
Routing protects against a missing tunnel; probe failure does not install an
alternate route.

## Honest status

Every roughly 60 seconds the applier writes a new `result.json`. The panel and
API use the same status interpretation. A missing, malformed, future-dated or
more-than-150-second-old check is unknown, even if the file says `ok`. Requests
must be acknowledged by ID before their outcome is displayed. Failed browser
polls immediately clear the connected indication. Last-check diagnostics are
explicitly historical.

`/healthz` checks panel liveness. `/readyz` returns 200 only for a fresh,
verified connected result; otherwise 503. Docker's applier healthcheck checks
freshness and current routing protection. It does not restart unhealthy
containers. The host-side doctor additionally checks the shared namespace and
recent verified egress.

## Panel and access

There is no application login. Loopback publishing plus authenticated access is
required; see [access](access.md). POSTs require a cookie-bound CSRF token and an
origin check. Security headers restrict scripts/styles/resources to same origin,
and dashboard framing is opt-in. HTTP body size and socket time are bounded.
Remote text is escaped in HTML and assigned as text in JavaScript.
Panel logs use fixed route names and omit client addresses, origins, query
strings, bodies and unknown paths.

Latency probes remain unprivileged TCP connects to port 443, cached for 15
minutes, with bounded concurrency. They run only for open pages and measure the
host-to-relay path, not end-to-end client latency.

## Recovery and verification

`python3 tools/molebridge.py recover` builds first, checks for the existing
identity volume, stops namespace dependents, then recreates all four containers
in dependency order and waits for health. It never deletes a volume or silently
enrolls a new peer. This is an explicit host operation, not a Docker socket
mounted in the panel. `depends_on.restart` also handles explicit Compose
dependency updates, but runtime crashes still require recovery.

[Verification](verification.md) covers the live deployment; isolated namespace
CI tests cover the Linux routing contract. Linux Docker and NetBird Cloud end
to end still need the [homelab test pass](homelab-testing.md).
