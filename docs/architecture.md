# Architecture

## Goal

Keep a device on its NetBird overlay while its Internet traffic leaves through
Mullvad, chosen per session by selecting an exit node. If the Mullvad side is
unavailable, that traffic must fail rather than leave through the host's own
connection.

## Components

One Compose project, four containers:

| Container | Image | Network | Role |
|---|---|---|---|
| `wireguard` | LinuxServer WireGuard | Owns the namespace | Brings up the Mullvad tunnel with `wg-quick`; runs `routing/10-exit-routing` first |
| `netbird` | Official NetBird client | `wireguard`'s namespace | The exit peer (kernel WireGuard, `wt0`) |
| `applier` | LinuxServer WireGuard, entrypoint `applier/apply.sh` | `wireguard`'s namespace | Changes the tunnel's peer to the requested server; health checks |
| `control-panel` | Official Python slim | Its own bridge, loopback publish | Web UI and relay list; no capabilities, non-root, read-only filesystem |

No custom images are built.

## Routing contract

Installed once per `wireguard` start, before the tunnel comes up, and never
removed when the tunnel goes down:

| Priority | Rule | Why |
|---|---|---|
| 90 | `to <overlay range> lookup main` | Replies to clients return over `wt0`, not into the tunnel. |
| 95 | `iif wt0 lookup 51821` | Everything forwarded from the overlay uses the exit table. Matching by name works before `wt0` exists. |
| 96 | `oif mullvad lookup 51821` | The applier's probes bound to the tunnel use it. |
| — | `unreachable default metric 4096 table 51821` | With no tunnel route, forwarded traffic is dropped. |

The tunnel config sets `Table = off`, so WireGuard installs no routes of its own.
Its `PostUp` adds `default dev mullvad` to table 51821 and `PreDown` removes it.
The same rules exist for IPv6.

Consequences:

- **Tunnel down, route deleted, or container stopped:** forwarded traffic hits
  `unreachable`, or the namespace disappears. It never falls through to the
  namespace's normal default route.
- **The exit's own traffic stays off the tunnel.** The Mullvad handshake and
  NetBird's control, signal and relay connections have no `wt0` input interface
  and no tunnel binding, so they use the normal route. This does not rely on
  NetBird's firewall marks.
- **No LAN reach.** Forwarded traffic's only route is the tunnel, so the
  host's LAN and other containers are not reachable from clients.
- Priorities 90–96 sit ahead of NetBird's own rules (105/110).

### Why not Gluetun or wg-quick's defaults

`wg-quick`'s full-tunnel mode and Gluetun both add a default-route rule with
`suppress_prefixlength`, plus firewall rules, that capture the overlay's return
traffic. People running a mesh exit behind them report broken return paths and
MTU stalls. Owning the rules keeps the return path explicit. The tunnel MTU is
pinned at 1420.

## Switching

A Mullvad WireGuard key and tunnel address work on every Mullvad server, so a
switch replaces only the peer's public key and endpoint.

1. The panel validates the requested name against its allowlist and writes
   `desired.json`. It never runs `wg`, `ip` or subprocesses.
2. The applier polls `desired.json` every 5 seconds. It re-validates the name
   against `relays.json` (exact match, 32-byte base64 key, dotted-quad IPv4). If
   the peer differs, it writes `status: applying`, removes the old peer, adds the
   new one with `AllowedIPs 0.0.0.0/0, ::/0` and a 25-second keepalive, and
   records the new server.
3. It probes `https://am.i.mullvad.net/json` through the tunnel until the
   handshake is fresh (under 180 seconds) and the egress is a Mullvad exit IP, or
   60 seconds pass. It writes `ok` or `failed`. On failure it stops. It does not
   try another server.
4. Every 60 seconds it also rewrites the result: `ok` requires a fresh
   handshake, Mullvad egress, and the unreachable fallback present.

The applier never mounts the tunnel config and never brings the interface up,
so it never sees the private key.

## Panel

- **Access:** no authentication. It relies on being published only through
  something that authenticates, and binds to loopback.
- **Posts:** `POST /select` requires a CSRF token (HMAC of a per-page cookie
  nonce with a per-process secret) and an `Origin` matching
  `PANEL_PUBLIC_HOSTS` or the request host. It sends `Referrer-Policy:
  same-origin` because `no-referrer` makes browsers send `Origin: null`.
- **Content Security Policy:** same-origin scripts, styles, fonts, images,
  connections and manifest only; `frame-ancestors` from `PANEL_FRAME_ANCESTORS`,
  otherwise `'none'` plus `X-Frame-Options: DENY`. No inline scripts.
- **Relay data is untrusted:** entries are validated when fetched and escaped
  when rendered. Static files are served from a fixed allowlist.
- **Latency:** a TCP connect to each server's port 443 from the panel container,
  two attempts with a 1.5-second timeout, 24 at a time, results cached 15 minutes
  per server. A refused connection still counts as a round trip. TCP needs no
  capabilities, unlike ICMP, and matched `ping` within a few milliseconds in
  testing. Probes run only for pages that are open.
- **Progressive enhancement:** without JavaScript the page still lists servers
  and switches through a plain form post.

## Limitations

- One server for all clients of the exit; a switch drops open connections.
- No automatic failover to another server, by design.
- Docker does not restart containers left in a dead namespace; see
  [operations](operations.md#restarts).
- IPv4 Mullvad endpoints only (the tunnel still carries IPv6).
- DNS is not routed through Mullvad; see [operations](operations.md#dns).
- NetBird only. Other overlays would need a different `OVERLAY_IF` and have not
  been tried.
