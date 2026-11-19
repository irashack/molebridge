# The proxy

**Every connection the proxy opens leaves through the tunnel, or fails. It
promises nothing about traffic not sent to it.**

`molebridge proxy` is a way in of its own, beside the NetBird exit and the
sidecar: a SOCKS5 and HTTP `CONNECT` proxy in the exit's network namespace,
for the programs you point at it. The username picks where a connection
leaves (with Mullvad, any country, city or server in the exit's catalogue,
without switching the exit); the password keeps others out. It never changes
the exit's status record, verdict or switching, and the exit doesn't know it
is there.

**Experimental, and untested on a real tunnel.** The role, its settings and
its status have unit tests, against fakes and on loopback. The system rig
drill (fake Mullvad relay proxies, tunnel loss, a packet counter on every
interface but the tunnel) and the live drill on a real Mullvad exit have not
run yet, so nothing here has carried traffic through a real tunnel or a real
Mullvad relay proxy. It is in no release yet: an image from before it exits
at once with `unknown role "proxy"`.

## How it keeps the guarantee

- Every socket it opens is bound to the tunnel interface (`TUNNEL_INTERFACE`)
  with `SO_BINDTODEVICE` before it connects. A failed bind fails the
  connection; there is no unbound fallback. When the tunnel interface is
  missing or renamed, connections fail.
- The names it resolves itself go to one resolver (`PROXY_DNS`) through the
  same bound sockets, never to the system resolver or `/etc/hosts`.
- With Mullvad, a connection goes to a Mullvad relay's own SOCKS5 proxy
  inside the tunnel, which resolves the target's name at the far end. A relay
  proxy's address is accepted only in `10.124.0.0/16`.
- While the exit's verdict is not `ok` (read from the exit's `result.json`,
  as `molebridge status` judges it), new connections are refused: SOCKS
  reply `0x01`, HTTP `503`. Open ones are left alone; a stopped tunnel fails
  them by itself.
- It runs with no capabilities, a read-only root and a non-root user, and
  refuses to start as root or with any capability.

What it doesn't do: plain HTTP proxying (only `CONNECT`), SOCKS `BIND`, UDP,
or anything for traffic that isn't sent to it.

## Set it up with Compose

The proxy needs a native exit: Mullvad, PIA or NordVPN, either the NetBird
exit (`compose.yaml`) or the [native sidecar](native-sidecar.md)
(`compose.native-sidecar.yaml`). It refuses a gluetun provider. Its service
is in `compose.proxy.yaml`, added on top of the exit's file:

1. In the directory that holds `compose.yaml`, create the proxy's state
   directory and password file, owned by the user the proxy runs as
   (`PANEL_USER`, default `1000:1000`):

   ```sh
   mkdir -p state/proxy secrets/proxy
   (umask 077; head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > secrets/proxy/password)
   sudo chown -R 1000:1000 state/proxy secrets/proxy
   ```

   Compose refuses to start the proxy while either directory is missing,
   rather than create it owned by root.

2. Add the file to `COMPOSE_FILE` in `.env`:

   ```sh
   COMPOSE_FILE=compose.yaml:compose.proxy.yaml                  # the NetBird exit
   COMPOSE_FILE=compose.native-sidecar.yaml:compose.proxy.yaml   # the native sidecar
   ```

3. Set where it listens (`PROXY_LISTEN`, [below](#where-it-listens)), then
   `docker compose up -d`. The proxy starts once the exit is healthy and is
   restarted with it.

`molebridge init` writes the same service when you choose the proxy, once a
release has the role.

## Settings

| Setting | Default | Purpose |
|---|---|---|
| `PROVIDER` | required | `mullvad`, `pia` or `nordvpn`, the exit's. Anything else is refused at start. Compose passes the exit's. |
| `TUNNEL_INTERFACE` | required | The exit's tunnel interface; every connection is bound to it. Compose passes the exit's `EXIT_IF`. |
| `PROXY_LISTEN` | `127.0.0.1:1080` | An IP address and a port ([below](#where-it-listens)). |
| `PROXY_PASSWORD_FILE` | required | The password file. Compose mounts `secrets/proxy` and sets `/run/secrets/proxy/password`. |
| `PROXY_MAX_CONNS` | `512` | The most client connections open at once, 1 to 65535. One more is closed before anything is read. |
| `PROXY_DNS` | the provider's | The resolver, an IP address with an optional port (53 when left out), for the names the proxy resolves itself: Mullvad relay proxy names, and every target with PIA and NordVPN. Asked through the tunnel. The defaults are each provider's own: Mullvad `10.64.0.1:53`, PIA `10.0.0.243:53`, NordVPN `103.86.96.100:53`. |
| `OVERLAY_IF` | `wt0` | NetBird's interface, as the exit's own `OVERLAY_IF`: the only interface besides loopback whose addresses `PROXY_LISTEN` may use. It must differ from `TUNNEL_INTERFACE`. |
| `STATE_DIR` | `/state` | The exit's `applier/` is read from here (mounted read-only: `relays.json` and `result.json`), and the proxy writes `proxy/proxy.json`. |

An empty value is the same as an unset one. A setting that doesn't parse
stops the proxy with a line naming it, before it listens.

## Where it listens

One address, taking both SOCKS5 and HTTP `CONNECT`. It must be loopback or an
address of NetBird's interface (`OVERLAY_IF`); anything else, including
`0.0.0.0`, is refused at start, so the proxy is never offered on the host's
other networks.

- **With the NetBird exit**, set `PROXY_LISTEN` to the exit's NetBird address
  and a port (for example `192.0.2.10:1080`; `netbird status` inside the exit shows its address),
  for the devices on your NetBird network. Loopback there reaches only the
  exit's own namespace. Limit who may connect with a NetBird access policy as
  well as the password.
- **With the native sidecar**, keep loopback: the containers that share the
  namespace (`network_mode: service:exit`) reach it at `127.0.0.1:1080`.

Nothing is published on the host.

## The password

One line in `secrets/proxy/password`, at most 1 KiB; a trailing newline is
dropped. The proxy refuses to start when the file is missing, empty, not a
regular file, or readable by others (its group may read it: mode `0600`,
`0640` or `0440`). It is compared in constant time, and never logged.

## The username: where a connection leaves

The username is `<location>` or `<location>.<session>`:

| Location | Means |
|---|---|
| `any` | any server |
| a country code, `se` | a server in that country |
| a city, `se-got` | a server in that city (with PIA, a region id such as `de_berlin`) |
| a server, `se-got-wg-001` | that server |

A location is 1 to 63 characters of `a-z`, `0-9`, `_` and `-`. The session is
1 to 32 of `a-z`, `0-9` and `_`. Connections with the same location and
session keep the same server while it works and the session has been used in
the last 30 minutes; without a session each connection chooses again. For
example, with `curl`:

```sh
curl --proxy socks5h://se-got.browser:$(cat secrets/proxy/password)@127.0.0.1:1080 https://am.i.mullvad.net/json
curl --proxy http://de:$(cat secrets/proxy/password)@127.0.0.1:1080 https://am.i.mullvad.net/json
```

Use `socks5h://` (not `socks5://`) so the client sends the host name and the
name is resolved at the far end.

**With Mullvad**, a connection leaves from a relay chosen uniformly among the
location's servers in the exit's catalogue (`state/applier/relays.json`),
through that relay's own SOCKS5 proxy
([Mullvad's SOCKS5 proxies](mullvad-socks5.md)). A relay proxy that fails
(connection, handshake, or a failure reply about itself rather than the
target) is benched for 1 minute, doubling up to 1 hour; a success clears it.
Benching is kept in memory and starts over when the proxy restarts.

**With PIA and NordVPN** no proxy per server is known, so only the exit's
current server is offered: a connection leaves from it, the target resolved
through `PROXY_DNS`. A location that doesn't include that server fails the
connection; `any` always matches.

## Status

The proxy writes `state/proxy/proxy.json` every 10 seconds and whenever a
server is benched or recovers or the exit's verdict changes. It is a file of
its own, never part of the exit's `result.json`. Inside the proxy container:

```sh
docker compose exec proxy molebridge status --proxy
```

prints the guarantee, `state:` (`ok` serving, `refusing` while the exit's
verdict isn't `ok`, `failed` when the listener is down, `unknown` for a
missing, malformed or stale record, over 30 seconds old), its reasons, the
exit's verdict as the proxy last saw it, the benched servers, the sessions
and the open connections. It exits 0 only while the proxy serves.

The container's health check is `molebridge health --proxy`: healthy only
while `proxy.json` is fresh and says `ok`. A proxy that refuses new
connections because the exit's tunnel is down is unhealthy.

## Limits

- **Untested on a real tunnel** ([above](#the-proxy)).
- **Relay choice is Mullvad only.** PIA and NordVPN offer only the exit's
  current server; to leave elsewhere, switch the exit.
- **Mullvad's relay proxies are Mullvad's.** Whether a relay's proxy answers,
  and from which address it connects, is up to Mullvad; the proxy only
  chooses the relay and benches the ones that fail.
- **TCP only.** No UDP and no plain HTTP proxying.
- **Not a kill switch.** It covers the connections sent to it. Programs that
  ignore their proxy setting, or a client that resolves names itself before
  connecting (`socks5://` rather than `socks5h://`), are outside the
  guarantee.
- **One namespace.** With the NetBird exit only devices on your NetBird
  network reach it, and only when `PROXY_LISTEN` is the exit's NetBird
  address.
