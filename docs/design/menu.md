# Design: the menu of ways in

Status: **being built** (2026-11-19). This is the working contract for the
[roadmap's direction](../../ROADMAP.md#direction): the pieces, their
boundaries and the interfaces between them, so that they can be built in
parallel. Nothing here is released. When a piece ships, its user
documentation replaces the matching section here, and this file goes once all
of them have.

## The pieces

| Piece | What it is | Depends on |
|---|---|---|
| [Tunnel dialer](#the-tunnel-dialer) | connections and DNS bound to the tunnel interface, failing rather than falling back | — |
| [Relay proxies](#relay-proxies) | Mullvad's per-server SOCKS5 proxies as a catalog, choosing a server for a location, benching failed ones | tunnel dialer (by interface only) |
| [The proxy](#the-proxy) | `molebridge proxy`: SOCKS5 and HTTP `CONNECT` for programs that opt in | both above (by interface only) |
| [The proxy's status](#the-proxys-status) | `proxy.json`, its verdict, `molebridge status` | the proxy |
| [The menu](#the-menu) | `molebridge init`: pick the ways in and extras, get a Compose file | — |
| [NetBird as a module](#netbird-as-a-module) | the NetBird exit as one way in behind a boundary, no behavior change | — |
| Switchyard's proxy view | sessions and benched servers, beside the exits | the proxy's status |
| Live acceptance | the proxy's live drill, run by the homelab's acceptance runner | the proxy |

## The guarantee

The proxy's guarantee, stated first wherever it is configured or shown:
**every connection the proxy opens leaves through the tunnel, or fails. It
promises nothing about traffic not sent to it.** It is a way in of its own,
never a sidecar mode or an exit setting, and it never changes the exit's
record, verdict or switching.

## The tunnel dialer

Package `internal/tunneldial`. No capabilities needed: since Linux 5.7 an
unprivileged process may bind a socket to a device with `SO_BINDTODEVICE`.

```go
type Dialer struct {
	Interface string        // the tunnel interface, from TUNNEL_INTERFACE
	Timeout   time.Duration // per connection, default 10s
}
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error)
```

- Every socket is bound to `Interface` before `connect`. A failed bind fails
  the dial; there is no unbound fallback. An address literal is required;
  names go through the resolver below.
- `Resolver{Dialer, Server}` resolves names over DNS sent through the same
  bound dialer to `Server` (for Mullvad `10.64.0.1:53`), never the system
  resolver. Answers are bounded and validated.
- Tests: a network-namespace test (tags `drill && linux`, like
  `internal/nstest`) with the tunnel interface present, absent, and renamed
  mid-run; the absent and renamed cases must fail the dial.

## Relay proxies

Package `internal/relayproxy`. It reads the exit's catalog snapshot
(`state/applier/relays.json`, mounted read-only into the proxy) through
`providers.ReadSnapshot`, so its validation is the catalog's.

- **Mullvad.** Each active WireGuard relay `<cc>-<city>-wg-<n>` has a proxy
  at `<cc>-<city>-wg-socks5-<n>.relays.mullvad.net:1080`. The name is
  resolved through the tunnel resolver, and only an answer in `10.124.0.0/16`
  is accepted. The exit's own server is also reachable at `10.64.0.1:1080`.
  Connections to a relay proxy go through the tunnel dialer, then a SOCKS5
  client handshake (no authentication) to the target.
- **PIA and NordVPN.** No proxy per server is known. Only the exit's current
  server is offered: the target is dialed directly through the tunnel dialer.
- **Locations.** `any`; a country (`se`); a city (`se-got`); a server
  (`se-got-wg-001`). Matching is on the catalog's own fields, lowercased.
- **Choosing.** Uniformly among the location's servers that aren't benched.
  A failed connection to a relay proxy (dial, handshake or a SOCKS failure
  reply other than "host unreachable" or "connection refused" for the
  target) benches that server for 1 minute, doubling to 1 hour; a success
  clears it. Benching is in memory.
- Interface used by the proxy:

```go
type Upstream interface {
	// Dial opens a connection to target ("host:port") through a server in
	// location, preferring pinned when it is set and not benched. It returns
	// the server used.
	Dial(ctx context.Context, location, pinned, target string) (conn net.Conn, server string, err error)
	Servers() []ServerState // for the status record
}
type ServerState struct {
	Server       string
	Benched      bool
	BenchedUntil time.Time
	Reason       string
	LastOK       time.Time
}
```

## The proxy

Role `molebridge proxy`, package `internal/proxy`, standard library only.

- **Where.** Its own container, image `molebridge-core`, no capabilities,
  read-only root, running as a non-root user, in the network namespace of a
  native exit or a native sidecar (`network_mode: service:exit`). It mounts
  the exit's `state/applier` read-only and its own state directory
  read-write.
- **Listening.** One port, default `127.0.0.1:1080` (`PROXY_LISTEN`), taking
  SOCKS5 (first byte `0x05`; `CONNECT` only, username and password per
  RFC 1929) and HTTP `CONNECT` (`Proxy-Authorization: Basic`). The address
  must be loopback or an address on NetBird's interface; anything else is
  refused at start. No plain HTTP proxying, no `BIND`, no UDP for now.
- **Password.** Required, from `PROXY_PASSWORD_FILE`, compared in constant
  time. No file, an empty one or one readable by others: refuse to start.
- **Username.** `<location>` or `<location>.<session>`. The session is
  `[a-z0-9_]{1,32}`. Connections with the same session keep the same server
  while it works and the session has been used in the last 30 minutes;
  without a session each connection chooses again.
- **Names.** The target's host name is sent to the relay proxy (SOCKS5
  domain address), so it is resolved at the far end, never locally.
- **Limits.** At most 512 open client connections (`PROXY_MAX_CONNS`);
  handshake within 10 seconds; idle connections are not cut.
- **Tunnel state.** It reads the exit's `result.json` with the shared
  verdict. While the exit's verdict is not `ok`, new connections are refused
  (SOCKS reply `0x01`, HTTP 503) and open ones are left alone: a stopped
  tunnel fails them by itself.
- **Built so far.** `internal/proxy` has the listener, both handshakes, the
  checks above, sessions and `proxy.json`, entered through
  `proxy.Serve(ctx, proxy.Config)`; the role and its Compose service come
  next. Details it settles: a location is 1 to 63 of `[a-z0-9_-]` (a PIA
  region has underscores), so it never holds a dot; the password file must
  not be readable by others (its group may read it), and one trailing newline is
  dropped; a failed dial is SOCKS reply `0x05`, `0x04` or `0x03` when the
  Upstream's error wraps `ECONNREFUSED`, `EHOSTUNREACH` (or a timeout) or
  `ENETUNREACH`, else `0x01`, and HTTP 504 for a timeout, else 502; other
  methods get 405, a malformed or oversized request (8 KiB) 400. The exit's
  verdict comes from `result.json` without the panel's request, which the
  proxy doesn't mount. Tested by unit tests against a fake Upstream only.

## The proxy's status

The proxy publishes `proxy.json` in its state directory every 10 seconds
and on every bench or recovery. It is a file of its own, never part of
`result.json`, so no reader of an exit's record can take it for one.

```json
{
  "schema": 1, "kind": "proxy", "provider": "mullvad",
  "guarantee": "opt-in",
  "status": "ok", "message": "Serving.",
  "checked_at": "2026-11-19T18:00:00Z",
  "listen": "127.0.0.1:1080",
  "tunnel": {"verdict": "ok", "server": "se-got-wg-001", "checked_at": "2026-11-19T17:59:30Z"},
  "servers": {"known": 512, "benched": [
    {"server": "de-fra-wg-003", "until": "2026-11-19T18:02:00Z", "reason": "handshake timed out"}
  ]},
  "sessions": 3,
  "connections": {"open": 7, "total": 1204, "failed": 12}
}
```

`status` is `ok` (serving), `refusing` (the tunnel's verdict isn't `ok`) or
`failed` (the listener is down). The proxy's verdict, in `internal/verdict`
beside the exit's, is `unknown` for a missing, stale (over 30 seconds) or
malformed file. `molebridge status --proxy` prints it.

## The menu

`molebridge init` asks, or reads the same answers from a file
(`--answers`), and writes a Compose file and an `.env` beside it:

1. The provider (Mullvad, PIA, NordVPN, or a provider through gluetun).
2. The ways in, one or more of: NetBird exit; sidecar for containers;
   proxy (native providers only).
3. The extras: Switchyard; `port-sync` (PIA sidecar only).

It refuses combinations that don't exist (a proxy on gluetun, `port-sync`
without PIA). The output uses the same services, settings and pins as the
shipped Compose files, which stay valid: `EXIT_KIND` and `TUNNEL_BACKEND`
keep their meaning, and `init` only writes them. `tools/check-compose.sh`
checks every combination `init` can write.

## NetBird as a module

The NetBird client's supervision (start only when the routing contract
holds, stop when the lease lapses) moves behind one boundary in
`internal/exit`, so that the exit's core (tunnel, catalog, admission,
record) doesn't name NetBird outside it. No behavior, setting or record
changes; every drill and the system rig must pass unchanged.

## Testing

Each piece brings its unit tests. The proxy adds a system rig drill: fake
Mullvad relay proxies inside the rig's fake Mullvad network, clients choosing
by every kind of location, a session kept and moved, a benched server, an
exit switch, tunnel loss, and an nftables counter on every interface but the
tunnel showing no packet from the proxy. The live drill runs a client through
the proxy on a real Mullvad exit and checks the egress server for a country,
a city and a server name.
