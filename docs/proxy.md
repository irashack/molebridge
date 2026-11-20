# The proxy

**Every connection the proxy opens leaves through the tunnel, or fails. It
promises nothing about traffic not sent to it.**

**Experimental, and drilled live on Mullvad only**
([what was tested](#limits-and-what-wasnt-tested)).

## Who it is for

The proxy is a way in for programs that opt in: agents, scripts, a browser
profile, anything you can point at a SOCKS5 or HTTP `CONNECT` proxy. It runs
as `molebridge proxy` in the network namespace of a native exit, the
[NetBird exit](netbird-exit.md) or the [native sidecar](native-sidecar.md),
beside it. The username picks where a connection leaves (with Mullvad, any
country, city or server in the exit's catalogue, without switching the exit);
the password keeps others out.

It is a way in of its own, not a mode of the exit. It never changes the
exit's status record, verdict or switching, and the exit doesn't know it is
there. Choose it when a program should leave through the VPN and the rest of
the machine shouldn't, or when different programs should leave from
different Mullvad servers at once. For everything a device sends, use the
[NetBird exit](netbird-exit.md); for everything a container sends, a
[sidecar](native-sidecar.md). [The menu](menu.md) compares them.

## What you run

One service, `proxy`, from `compose.proxy.yaml`, added on top of the exit's
Compose file. It runs the `ghcr.io/irashack/molebridge-core` image (the
binary without NetBird) with `network_mode: service:exit`, as a non-root user
(`PANEL_USER`, default `1000:1000`), with no capabilities, a read-only root
and `no-new-privileges`. It reads the exit's `state/applier` read-only and
writes only `state/proxy`. Its limits are 64 MiB of memory and 128 processes.

It needs a native exit: Mullvad, PIA or NordVPN. It refuses a gluetun
provider, and a multi-provider exit ([below](#settings)).

## How it keeps the guarantee

- Every socket it opens is bound to the tunnel interface (`TUNNEL_INTERFACE`)
  with `SO_BINDTODEVICE` before it connects. A failed bind fails the
  connection; there is no unbound fallback. When the tunnel interface is
  missing or renamed, connections fail. The binding is what it takes: a
  connection the exit's namespace opens itself, unbound, follows the main
  table, not the tunnel
  ([testing](testing.md#mullvads-socks5-proxies-through-an-exit)).
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

Set up the exit first ([setup](setup.md)), then add the proxy.
`molebridge init` writes the same service when you choose the proxy as a way
in, on top of `netbird-exit` or `sidecar` ([setup](setup.md#molebridge-init)).
By hand:

1. In the directory that holds the exit's Compose file, create the proxy's
   state directory and password file, owned by the user the proxy runs as
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

   podman-compose doesn't read `COMPOSE_FILE` from `.env`; pass the same
   files with `-f` on every command instead
   (`podman-compose -f compose.yaml -f compose.proxy.yaml up -d`;
   [rootless Podman](prerequisites.md#rootless-podman)).

3. Set where it listens (`PROXY_LISTEN`, [below](#where-it-listens)), then
   `docker compose up -d`. The proxy starts once the exit is healthy and is
   restarted with it.

**On rootless Podman**, where the panel runs with `PANEL_USER=0:0`, the proxy
refuses to start, because it never runs as root:

```text
molebridge proxy: refusing to start: the proxy must not run as root (uid 0); set PANEL_USER to the uid:gid that owns state/proxy and secrets/proxy
```

Give the `proxy` service a non-root `user:` of its own in a Compose override,
own `state/proxy` and `secrets/proxy` as that user inside the user namespace
(`podman unshare chown <uid>:<gid> state/proxy secrets/proxy`), and let it
read the exit's files through `STATE_GID`
([readers in another group](configuration.md#readers-in-another-group)).
This form has not been tested.

### A client container outside the stack

A container you start yourself, outside the Compose project, is in another
network namespace, so it doesn't reach a proxy on loopback. Start it in the
exit's namespace. With Docker, `--network container:<exit container>`. With
podman-compose, which puts the project's containers in a pod, start it in
that pod: `podman pod ps` lists it (`pod_<project>` by default), and

```sh
podman run --rm --pod pod_molebridge docker.io/curlimages/curl:<tag> \
  --proxy socks5h://any:<password>@127.0.0.1:1080 https://example.net/
```

reaches it at `127.0.0.1:1080`. On the podman-compose host where this was found
(2026-11-20) a client started without `--pod` didn't reach the proxy; the
Docker form is not recorded in [testing](testing.md).

## Settings

| Setting | Default | Purpose |
|---|---|---|
| `PROVIDER` | required | `mullvad`, `pia` or `nordvpn`, the exit's. Anything else is refused at start. Compose passes the exit's. |
| `TUNNEL_INTERFACE` | required | The exit's tunnel interface; every connection is bound to it. Compose passes the exit's `EXIT_IF`. |
| `PROXY_LISTEN` | `127.0.0.1:1080` | An IP address and a port ([below](#where-it-listens)). |
| `PROXY_PASSWORD_FILE` | required | The password file, an absolute path. Compose mounts `secrets/proxy` and sets `/run/secrets/proxy/password`. |
| `PROXY_MAX_CONNS` | `512` | The most client connections open at once, 1 to 65535. One more is closed before anything is read. |
| `PROXY_DNS` | the provider's | The resolver, an IP address with an optional port (53 when left out), for the names the proxy resolves itself: Mullvad relay proxy names, and every target with PIA and NordVPN. Asked through the tunnel. The defaults are each provider's own: Mullvad `10.64.0.1:53`, PIA `10.0.0.243:53`, NordVPN `103.86.96.100:53`. |
| `OVERLAY_IF` | `wt0` | The only interface besides loopback whose addresses `PROXY_LISTEN` may use: NetBird's, as the exit's own `OVERLAY_IF`, or on Kubernetes the pod's own interface ([below](#on-kubernetes)). It must differ from `TUNNEL_INTERFACE`. |
| `STATE_DIR` | `/state` | A clean absolute path. The exit's `applier/` is read from here (mounted read-only: `relays.json` and `result.json`), and the proxy writes `proxy/proxy.json`. |

An empty value is the same as an unset one. `PROVIDERS` must be unset: the
proxy serves one provider's tunnel and refuses a
[multi-provider exit](multi-provider.md) (`PROVIDERS is set: the proxy is
not supported on a multi-provider exit`). Before it listens, the proxy
checks every setting, the password file and the listen address, and stops
with one `molebridge proxy: refusing to start: ...` line for each problem
it finds, so a configuration you write by hand is corrected in one pass.
Every setting is also listed in [configuration](configuration.md#the-proxy).

## Where it listens

One address, taking both SOCKS5 and HTTP `CONNECT`. It must be loopback or an
address of the interface `OVERLAY_IF` names (NetBird's with Compose);
anything else, including `0.0.0.0`, is refused at start, so the proxy is
never offered on the host's other networks.

- **With the NetBird exit**, set `PROXY_LISTEN` to the exit's NetBird address
  and a port (for example `192.0.2.10:1080`; `netbird status` inside the exit shows its address),
  for the devices on your NetBird network. Loopback there reaches only the
  exit's own namespace. Limit who may connect with a NetBird access policy as
  well as the password.
- **With the native sidecar**, keep loopback: the containers that share the
  namespace (`network_mode: service:exit`) reach it at `127.0.0.1:1080`.

Nothing is published on the host.

### On Kubernetes

`OVERLAY_IF` doesn't have to be NetBird's: the proxy accepts any interface
name other than the tunnel's and requires `PROXY_LISTEN` to be one of that
interface's addresses. In a pod beside the exit (the [native
sidecar](native-sidecar.md#kubernetes)) you can offer it to the cluster on
the pod's own interface and address, taken from the downward API:

```yaml
env:
  - name: POD_IP
    valueFrom:
      fieldRef:
        fieldPath: status.podIP
  - name: OVERLAY_IF
    value: eth0
  - name: PROXY_LISTEN
    value: $(POD_IP):1080
```

That offers the proxy to everything that can reach the pod, so put a
NetworkPolicy in front of it that admits only the clients you mean, as well
as the password. Interface names depend on the cluster's network plugin;
check with `ip -br addr` in the pod.

The proxy reads the exit's `applier/` files as its own non-root user. When
the exit runs as root and its state directory is root's, for example mode
0770, the proxy can't read them and refuses every
connection with a status message such as

```text
Refusing new connections: the exit's verdict is unknown: can't read /state/applier/result.json: permission denied (run the proxy in the exit's STATE_GID group; docs/proxy.md).
```

Set `STATE_GID` on the exit to a group id, make the exit a member of that
group, and run the proxy (and the panel) in it, for example with
`supplementalGroups: [<gid>]` on the pod
([readers in another group](configuration.md#readers-in-another-group)).
Running the proxy in group 0 works too, but gives it everything root's
group may read. The proxy has run this way on one Kubernetes cluster
in group 0, not with `STATE_GID`; nothing of it is recorded in
[testing](testing.md).

## The password

One line in `secrets/proxy/password`, at most 1 KiB; a trailing newline is
dropped. The proxy refuses to start when the file is missing, empty, not a
regular file, or readable by others (its group may read it: mode `0600`,
`0640` or `0440`). It is compared in constant time, and never logged.

## Choosing where a connection leaves: the username

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
([Mullvad's relay proxies](#mullvads-relay-proxies-used-directly)). One
connection tries up to three relay proxies, each attempt (resolving its name,
connecting and the SOCKS5 handshake) given 10 seconds. A relay proxy that
fails (connection, handshake, or a failure reply about itself rather than the
target) is benched for 1 minute, doubling up to 1 hour; a success clears it.
Benching is kept in memory and starts over when the proxy restarts. When
every server for the location is benched, the connection fails.

**With PIA and NordVPN** no proxy per server is known, so only the exit's
current server is offered: a connection leaves from it, the target resolved
through `PROXY_DNS`. A location that doesn't include that server fails the
connection; `any` always matches. To leave elsewhere, switch the exit
([Switchyard](switchyard.md)).

The exit's own server never changes for the proxy, and the proxy's choices
never change the exit's.

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
connections because the exit's tunnel is down is unhealthy. Switchyard shows
the same record when you turn on its
[proxy view](switchyard.md#the-proxy-view) (`PANEL_PROXY_STATUS`,
[configuration](configuration.md#the-proxy-view)).

## Mullvad's relay proxies used directly

Every Mullvad WireGuard server runs a SOCKS5 proxy that answers only from
inside a Mullvad tunnel ([Mullvad's guide](https://mullvad.net/en/help/socks5-proxy)).
The proxy above uses them from the exit's namespace. A device on a native
Mullvad [NetBird exit](netbird-exit.md) is inside that tunnel too, so it can
also use them as they are, without the proxy service. Nothing in Molebridge
needs to change or be set: the exit forwards the device's traffic for them
into the tunnel like any other traffic.

That gives one application a different Mullvad server from the rest of the
device. The device keeps the exit's server, the one Switchyard shows, while
the application's connections leave from the server whose proxy it uses. No
other device moves, and nothing is switched, so no connections drop.

Compared with the proxy service: there is no password, no session, no
benching and no choice by country or city; the device names one server's
proxy itself; and the guarantee is the NetBird exit's, for traffic the
device sends through it, not the proxy's.

This has run once, with a Linux client on a native Mullvad exit at 0.9.4
([testing](testing.md#mullvads-socks5-proxies-through-an-exit)). The gluetun
backend, the native sidecar and clients on other systems are untested.

### The two kinds of relay proxy

- **The exit server's own proxy, at `10.64.0.1:1080`.** Connections leave from
  the server the exit is on, the same address the device already has. It helps
  only an application that wants a proxy setting.
- **Every other server's proxy, at `<server>-socks5`.** Take the server's
  hostname from Switchyard or [Mullvad's server list](https://mullvad.net/en/servers),
  put `socks5-` after `-wg-`, and add `.relays.mullvad.net`, on port 1080.
  `se-sto-wg-001` becomes `se-sto-wg-socks5-001.relays.mullvad.net:1080`.
  These names resolve on public DNS to addresses in `10.124.0.0/16`, which
  only answer through the tunnel. The exit's cached relay list
  (`state/applier/relays.json`) doesn't carry them.

### Check it from a device

Select the Mullvad exit in NetBird first. Then check that the proxies'
addresses go to NetBird's interface, not to a local network:

```sh
route -n get 10.64.0.1        # macOS: the interface should be NetBird's utun
ip route get 10.64.0.1        # Linux: dev wt0, or the interface NetBird created
```

Do the same for the address a proxy's name resolves to
(`host se-sto-wg-socks5-001.relays.mullvad.net`). NetBird looks up the main
routing table before its exit route, so any local route that covers the
address wins: a LAN in `10.0.0.0/8`, another VPN, a container bridge.
Connections to the proxy then go there instead, and fail or reach something
else.

Then compare the two kinds:

```sh
curl --socks5-hostname 10.64.0.1:1080 https://am.i.mullvad.net/json
curl --socks5-hostname se-sto-wg-socks5-001.relays.mullvad.net:1080 https://am.i.mullvad.net/json
```

The first should report the exit's server, the second `se-sto-wg-socks5-001`.
Use `--socks5-hostname` (or `socks5h://` in a proxy URL) so the proxy looks up
the site's name, not the device. An application set to resolve names itself
asks the device's resolver, which the exit carries like any other traffic
([DNS](operations.md#dns)).

### Limits of using them directly

- **The exit must be selected.** Without it the proxies' addresses don't reach
  Mullvad; the connections go wherever the device's own routes send them.
- **It covers only what the application sends to the relay proxy.** Anything
  else on the device, and anything the application sends around the proxy,
  leaves from the exit's server while the exit is selected, and from the
  device's own connection when it isn't
  ([the NetBird exit's limits](netbird-exit.md#limits-and-what-wasnt-tested)).
- **Two hops.** The exit's server still carries the WireGuard leg and its
  bandwidth; the relay proxy only changes where the connection leaves Mullvad.
  A proxy far from the exit's server is slower to connect and to transfer.
- **Molebridge knows nothing about it.** The status record, the verdict and
  Switchyard show the exit's server only, and the egress check verifies only
  that server. When the exit switches, open proxy connections drop with the
  rest.
- **No authentication.** Mullvad's relay proxies don't take a password, so
  every device that can use the exit can use them. They don't answer from
  outside Mullvad's network.
- **Private addresses.** Both kinds have private (RFC 1918) addresses, so they
  stop working if NetBird blocks LAN access through the exit peer. Molebridge
  doesn't turn that on.
- **Only TCP was tested.** UDP through these proxies is untested.
- **Mullvad only.** PIA and NordVPN have no equivalent that Molebridge knows
  of. Mullvad documents the proxies, not their use through a NetBird exit, so a
  change on Mullvad's side could end this without a Molebridge release.

## Limits and what wasn't tested

**What was tested.** The role, its settings and its status have unit tests,
against fakes and on loopback. CI's
[system rig](../CONTRIBUTING.md#the-system-rig) runs the release build's
proxy, unprivileged and without capabilities, in a native Mullvad overlay
exit's namespace with kernel WireGuard tunnels to fake relays, against fake
Mullvad relay proxies and DNS: locations, sessions, benching, refusal while
the exit switches or its tunnel is stopped, and a packet counter showing
nothing of the proxy's outside the tunnel. The live drill on a real Mullvad
exit passed once on a candidate of 0.14.0, before its release: locations,
a session, HTTP `CONNECT`, a wrong password, and nothing of the proxy's
outside the tunnel. Since acceptance policy 18 it runs on every release
candidate ([the proxy drill](verification.md#the-proxy)). An image from
before the proxy role exits at once with `unknown role "proxy"`.

**Not tested:** PIA and NordVPN, the native sidecar's namespace (on the rig
or live), Docker Engine, rootless Podman with a non-root proxy user, and
`STATE_GID` on Kubernetes ([testing](testing.md)).

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
- **One provider.** Not on a gluetun exit and not on a multi-provider exit.
