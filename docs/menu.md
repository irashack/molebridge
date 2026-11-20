# Choosing ways in and extras

Molebridge runs one commercial VPN tunnel (Mullvad, PIA, NordVPN, or a
provider through gluetun) and offers it in more than one way. This page helps
you choose. [Setup](setup.md) installs what you choose with `molebridge init`.

Every part is experimental. What ran live, where and at which revision is in
[testing](testing.md); this page only says which parts have run live at all.

## The ways in

A way in is how traffic reaches the tunnel. Each one makes its own promise,
and the promise is the first thing to compare:

| Way in | What uses the tunnel | Its guarantee | Run live | Image | Guide |
|---|---|---|---|---|---|
| NetBird exit | whole devices on your NetBird network, which select the exit | traffic forwarded from your devices leaves through the tunnel or not at all | Mullvad, PIA and NordVPN, on Kubernetes and rootless Podman | `molebridge` | [NetBird exit](netbird-exit.md) |
| NetBird exit with gluetun | the same, with gluetun holding the tunnel | the same: Molebridge's routing rules in gluetun's namespace | NordVPN only | `molebridge` and gluetun | [gluetun as a NetBird exit](gluetun-netbird-exit.md) |
| Native sidecar | containers that share the exit's network namespace | the containers' traffic leaves through the tunnel or not at all, by Molebridge's routing contract and firewall, except the networks you list in `SIDECAR_LAN_CIDRS` | PIA on Kubernetes only | `molebridge-core` | [native sidecar](native-sidecar.md) |
| gluetun sidecar | containers that share an ordinary gluetun's namespace | gluetun's firewall alone keeps their traffic in the tunnel; Molebridge picks and checks the server | NordVPN only | `molebridge-core` and gluetun | [gluetun sidecar](gluetun-sidecar.md) |
| Proxy | programs you point at it: SOCKS5 or HTTP `CONNECT` | every connection the proxy opens leaves through the tunnel, or fails; it promises nothing about traffic not sent to it | Mullvad, on a NetBird exit only | `molebridge-core` | [proxy](proxy.md) |

`molebridge init` names these `netbird-exit`, `sidecar` and `proxy`. Your
provider decides which form of the first two you get: Mullvad, PIA and
NordVPN give the native form, a `gluetun-<id>` provider the gluetun form.

### Who each one is for

- **NetBird exit.** Your phone or laptop can run one VPN at a time, and you
  want it to stay on NetBird. The exit joins your NetBird network as an exit
  node; a device selects it and its Internet traffic leaves through the
  provider. Every device on the exit follows a server switch with no client
  change. It is not a kill switch on the device: a device that deselects the
  exit or loses NetBird uses its own connection.
- **NetBird exit with gluetun.** As above, for a provider Molebridge doesn't
  drive itself but gluetun does: FastestVPN, IVPN, Surfshark or Windscribe
  (Mullvad and NordVPN work either way).
- **Native sidecar.** Containers on one host, such as a download client, that
  must use the tunnel and nothing else, with a provider gluetun can't drive
  over WireGuard with Molebridge, PIA first. `port-sync` hands PIA's forwarded
  port to qBittorrent.
- **gluetun sidecar.** You already run gluetun for your containers and want
  Switchyard to choose and check its server.
- **Proxy.** Programs that opt in per connection: agents, scrapers, browser
  tests, CI jobs. The username picks where a connection leaves, and on
  Mullvad that can be any country, city or server without switching the
  exit. On PIA and NordVPN every connection leaves through the exit's current
  server. Anything not sent to the proxy is not covered.

### Providers

| Provider | NetBird exit | Native sidecar | Proxy | gluetun forms |
|---|---|---|---|---|
| Mullvad | yes | yes | yes, with a location per connection | yes |
| PIA | yes | yes, with `port-sync` | yes, the current server | no |
| NordVPN | yes | yes | yes, the current server | yes |
| FastestVPN, IVPN, Surfshark, Windscribe | no | no | no | yes |

Mullvad, PIA and NordVPN, and Mullvad and NordVPN through gluetun, confirm
the address your traffic leaves from; with the other gluetun providers the
exit can only check the tunnel itself. [Providers](providers.md) says how
they differ, and [other providers](other-providers.md) why others are not
offered. `init` refuses the gluetun providers it can't select servers for:
`molebridge init: provider gluetun-protonvpn is not offered: gluetun provider
has no unique single-filter server identifier.`

## The extras

| Extra | What it does | Works with | How you add it | Guide |
|---|---|---|---|---|
| Switchyard | the web panel: choose and check the server, see the proxy | every way in | `init` extra `switchyard` | [Switchyard](switchyard.md) |
| `port-sync` | gives PIA's forwarded port to qBittorrent | PIA, native sidecar | `init` extra `port-sync` | [native sidecar](native-sidecar.md#port-forwarding) |
| Failover | moves the exit to a backup server when the selected one keeps failing; off by default | native forms only | `FAILOVER` in `.env` | [failover](failover.md) |
| Multi-provider exit | one NetBird exit that carries Mullvad, PIA or NordVPN, one at a time | the native NetBird exit | its page says | [multi-provider exit](multi-provider.md) |
| Network exchange | an exit and its panel that share no filesystem exchange their files over HTTP | an exit with Switchyard | `EXCHANGE_URL` in `.env` | [network exchange](exchange.md) |

Failover, the multi-provider exit and the network exchange are settings, not
`init` choices: you add them to the `.env` that `init` writes. The exit
refuses failover with gluetun (`molebridge-exit: FAILOVER needs
TUNNEL_BACKEND=native: gluetun reconnects by itself`).

## What combines

One `init` run writes one Compose project with one exit, and so one tunnel and
one provider. On it you can have:

- one of `netbird-exit` or `sidecar`;
- `proxy` on top of either, with Mullvad, PIA or NordVPN;
- `switchyard`, and with PIA and `sidecar`, `port-sync`.

`init` refuses everything else and writes nothing. Its messages:

| You ask for | It says |
|---|---|
| `netbird-exit` and `sidecar` | `molebridge init: netbird-exit and sidecar can't share one exit: the NetBird exit is EXIT_KIND=overlay and the sidecar EXIT_KIND=sidecar, and init writes one exit. Choose one of them; the other needs a Compose project of its own.` |
| `proxy` with a gluetun provider | `molebridge init: the proxy needs a native provider (mullvad, pia, nordvpn): it runs in the namespace of a tunnel Molebridge brings up itself, and with gluetun-surfshark the tunnel is gluetun's.` (with your provider's name) |
| `proxy` alone | `molebridge init: the proxy runs in the network namespace of a native exit: choose netbird-exit or sidecar with it.` |
| `port-sync` with another provider | `molebridge init: port-sync follows PIA's forwarded port: it needs provider pia, not mullvad.` (with your provider's name) |
| `port-sync` without `sidecar` | `molebridge init: port-sync runs in the native sidecar's namespace, beside your qBittorrent: it needs the sidecar way in.` |
| no way in | `molebridge init: choose at least one way in: netbird-exit, sidecar, proxy.` |

To run two ways in that don't share an exit, such as a NetBird exit for your
phones and a native sidecar for a download client, run `init` twice into two
directories. Each is its own Compose project with its own exit, tunnel config
and state, and each follows [setup](setup.md) on its own. Several NetBird
exits, one per provider, can share one Switchyard
([several exits in one panel](switchyard.md#several-exits-in-one-panel)).

## Which image

Both images hold the same `molebridge` binary, built from one commit and
released together. `ghcr.io/irashack/molebridge` adds the pinned NetBird
client; `ghcr.io/irashack/molebridge-core` has none.

| Service | Image |
|---|---|
| `exit` and `switchyard` of a NetBird exit (native or with gluetun) | `molebridge` |
| `exit`, `switchyard` and `port-sync` of a sidecar (native or gluetun) | `molebridge-core` |
| `proxy` | `molebridge-core` |
| `gluetun` | gluetun's own image, pinned by digest |

`init` and the shipped Compose files choose the image for you. A NetBird exit
started from the core image stops at once with `molebridge-exit:
EXIT_KIND=overlay (the default) runs NetBird, and this image has no NetBird
client: use ghcr.io/irashack/molebridge for a NetBird exit (molebridge-core is
for the sidecars)`.

## What doesn't change

`init` writes the same services, settings and image pins as the Compose files
shipped with the release, and writes `EXIT_KIND` and `TUNNEL_BACKEND` as they
do. Those files stay valid: an exit set up from them needs no change, and you
can keep using them instead of `init` ([without init](setup.md#without-init)).
