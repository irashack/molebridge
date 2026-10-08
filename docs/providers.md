# VPN providers

Each Molebridge exit uses one provider. A native exit sets it with `PROVIDER`
in `.env`; with the gluetun backend you set `GLUETUN_PROVIDER` instead, and
Compose gives the applier and the panel the registry id
`gluetun-<provider>`. These ids also name providers in `PANEL_EXITS`:

| Provider | Status | You pick | Keys |
|---|---|---|---|
| `mullvad` (default) | Tested on the hosts in [testing](testing.md) | a server | One device key and tunnel address, valid on every server |
| `pia` | Experimental: fewer live checks so far, see [testing](testing.md) | a region | A key registered on each server, with a different tunnel address on each |
| `nordvpn` | Experimental: one live pass on macOS with OrbStack, see [testing](testing.md#nordvpn-pass-at-036e1cc) | a server | One account key and tunnel address, valid on every server; server keys shared per location |
| `gluetun-fastestvpn`, `gluetun-ivpn`, `gluetun-mullvad`, `gluetun-nordvpn`, `gluetun-surfshark`, `gluetun-windscribe` | Experimental: live passes with NordVPN only, see [testing](testing.md#gluetun-backend-pass-at-a3bb14f); the [gluetun backend](#the-gluetun-backend) | a server | Whatever the provider uses; gluetun holds the key |

To offer more than one, run one exit per provider with different
`COMPOSE_PROJECT_NAME`, `NB_HOSTNAME` and `PANEL_PORT`, each with its own
NetBird route. One [Switchyard](switchyard.md#several-exits-in-one-panel) can
serve them all.

## How PIA differs

A Mullvad switch changes only the tunnel's peer. The interface's key and
addresses stay the same, which is why the applier can run without the tunnel
config mounted.

PIA has no account-wide WireGuard key. To connect to a server, the applier:

1. gets a token from PIA with the account's username and password, and reuses
   it for up to 12 hours;
2. asks the chosen server to accept the interface's public key
   (`https://<server>:1337/addKey`), checking the server's TLS certificate
   against PIA's CA, which Molebridge bundles;
3. receives that server's key and port, and a tunnel address that is valid
   only on that server.

So with PIA the applier also sets the interface's IPv4 address and the
return-path rule (priority 94) on every switch, and it holds the PIA login.
The private key still never leaves the `wireguard` container, because
registration needs only the public key.

| | Mullvad | PIA |
|---|---|---|
| Account credential in the applier | none | username and password, from mode-0600 files |
| The applier changes the tunnel address | never | on every switch |
| Rule 94 is installed by | routing initialization, from the config's `Address` | the applier, after each registration |
| Egress is confirmed by | `am.i.mullvad.net`, for each address family | PIA's `api/client/status` (`connected: true`), IPv4 |

The login and token reach `curl` only through mode-0600 files on the
applier's tmpfs. They never appear in its arguments, logs or state files.

During a switch, the applier adds the new address and its return-path rule
before it removes the old ones. When an interface loses its last IPv4
address, the kernel deletes every route through it, including the exit
table's tunnel route, so the order matters. The applier then puts that route
back. Forwarded traffic stays on the exit table throughout, and while the
route is missing it hits the unreachable fallback.

## PIA details

- **Regions.** The server list is PIA's published region list
  (`serverlist.piaservers.net/vpninfo/servers/v6`). It is checked the same way
  as Mullvad's. PIA appends a signature to that file, which Molebridge doesn't
  verify; it relies on HTTPS for the list and on PIA's CA when registering.
  Offline regions are left out, and PIA's virtual locations are labeled. When
  it registers, the applier picks one of the region's servers.
- **IPv4 only.** PIA carries no IPv6. Forwarded IPv6 hits the exit table's
  unreachable fallback. If your NetBird account has IPv6, still create the
  `::/0` exit route for this peer. Without it, a device using the PIA exit can
  send its IPv6 over its own network.
- **Re-registration.** PIA forgets a key after a server restart or long
  inactivity. When the handshake goes stale, the applier registers again in
  the same region, at most once every five minutes. It never picks another
  region by itself. After the `wireguard` container is recreated, it
  registers the saved region again.
- **Status.** `result.json` carries `provider: "pia"` and `exit_confirmed`.
  PIA's check returns no city or country, so the panel shows the region from
  the server list. `state/applier/tunnel.json` records the current
  registration: region, server, server key and tunnel address. It holds no
  secret.

Setup for PIA is part of [setup](setup.md). On a fresh install the exit
carries no traffic until you pick a region in the panel.

## How NordVPN differs

NordVPN (its WireGuard service is called NordLynx) works like Mullvad: one
private key and the tunnel address `10.5.0.2/32` are valid on every server,
the address is in the tunnel config from the start, and a switch changes
only the peer. The applier holds no NordVPN credential. What differs:

- **The key comes from an access token.** NordVPN has no config download.
  `tools/nordvpn-key.py` asks NordVPN's API for the account's NordLynx
  private key once, at setup, with an access token you create in your Nord
  Account (NordVPN, then Advanced settings, then "Get access token"). It
  writes the tunnel config and nothing else; the token is needed only for
  that, so delete it, or revoke it in your Nord Account, afterwards. The
  [setup](setup.md#2-create-the-tunnel-config) step shows how. Expect
  NordVPN to count the exit as one of the account's devices (not verified).
- **No peer until you pick a server.** The generated config has no `[Peer]`,
  so a fresh exit carries no traffic, and the applier reports "No NordVPN
  server is selected yet; choose one in the panel." until you choose one.
- **IPv4 only.** NordLynx carries no IPv6. Forwarded IPv6 hits the exit
  table's unreachable fallback, as with PIA. If your NetBird account has IPv6,
  still create the `::/0` exit route for this peer. Routing initialization
  and the doctor refuse a NordVPN config with an IPv6 `Address`.
- **Server keys belong to a location.** Every server in a city can share one
  public key, so the key alone doesn't say which server the tunnel uses. The
  applier identifies the current server by the live peer's endpoint
  (`wg show nordvpn endpoints`), which must be the server's entry address on
  port 51820, together with the key. A switch removes the current peer before
  adding the new one, even when the key stays the same, so the new server's
  handshake is a fresh one.
- **Server list.** NordVPN's `api.nordvpn.com/v2/servers`, filtered to
  WireGuard servers, is about 8 MB. The applier allows it up to 32 MiB and 60
  seconds, and needs more memory to parse it, which `compose.nordvpn.yaml`
  provides (512 MB instead of 128 MB). The validated `relays.json` it keeps
  is much smaller, about 1.5 MB for some 5,300 servers, and may grow to
  16 MiB; a refresh that would exceed that keeps the last good catalogue. Only online standard servers with the
  VPN service, a WireGuard key and one location are listed; dedicated-IP,
  Double VPN, Onion over VPN and obfuscated servers are left out. Servers in
  NordVPN's virtual locations are labeled "virtual".
- **Egress check.** Through the tunnel, `curl -4` asks
  `api.nordvpn.com/v1/helpers/ips/insights`; `"protected": true` confirms the
  egress at the `provider` tier. NordVPN caches that answer for up to an hour
  per address. When it says `false` for the selected server's own entry
  address, which is where NordLynx servers have exited so far, the applier
  asks again every 10 seconds for up to 60 seconds, and during a switch never
  past the switch's own timeout, before it reports "Tunnel egress is not
  confirmed as NordVPN." It never accepts the address alone as confirmation.
  If the cached answer outlasts the retries, the exit shows as failed until
  NordVPN's answer changes.

| | Mullvad | NordVPN |
|---|---|---|
| Account credential in the applier | none | none (the key is fetched once at setup) |
| The applier changes the tunnel address | never | never |
| IPv6 through the tunnel | yes, when the config has an IPv6 address | never |
| The current server is found by | the peer's key | the peer's endpoint and key |
| Egress is confirmed by | `am.i.mullvad.net`, for each address family | `ips/insights` (`protected: true`), IPv4 |

What was tested: one live pass on macOS with OrbStack and Docker covered the
key exchange, the server list, switches within a location and to another
country, NordVPN's confirmation, a client's egress, and IPv6 staying blocked
([testing](testing.md#nordvpn-pass-at-036e1cc)). The insights cache retry,
the panel with NordVPN's list, rootless Podman and the fail-closed drills are
covered by unit tests or not at all so far.

## Port forwarding

Off by default, and experimental: the forwarding path is covered by isolated
drills in CI but hasn't been tested against PIA itself. PIA can forward one
port on the current server. Molebridge passes it to **one overlay device**:

```sh
PIA_PORT_FORWARD=on
PIA_PORT_FORWARD_TARGET=192.0.2.10   # that device's NetBird address
```

With it on:

- only regions that offer port forwarding are listed;
- after each healthy switch the applier asks PIA for a port through the
  tunnel, and binds it again every ten minutes (PIA drops a port that isn't
  bound for 15);
- an nftables table, `ip molebridge_forward`, sends TCP and UDP for that port
  from the tunnel to the target, on the **same port number**, and masquerades
  it as the exit's overlay address;
- a separate, permanent table, `inet molebridge_guard`, drops anything
  forwarded from the tunnel that would leave other than over the overlay;
- the port appears under Diagnostics in the panel, and in `result.json` as
  `forwarded_port`. PIA chooses the number. It may change after a switch,
  re-registration or restart, so anything that depends on it has to follow
  `forwarded_port`.

The service on the target must listen on the forwarded port itself; there's
no port translation. You also need a NetBird policy that lets the exit peer
reach that port on the target.

A healthy exit doesn't mean forwarding works. Forwarding errors appear as
`port_forward_error` in `result.json` and in the panel's Diagnostics, without
changing the exit's connected state.

To turn forwarding off, set `PIA_PORT_FORWARD=off`, clear
`PIA_PORT_FORWARD_TARGET` (the applier refuses to start with a target and
forwarding off), and recreate the applier so it picks up the new settings.
It removes `molebridge_forward` as it starts; the
[port-forwarding checks](verification.md#optional-pia-port-forwarding) confirm
it. Connections already open continue until they close, and PIA stops
forwarding within 15 minutes of the last bind.

**This opens a port to the Internet.** Anyone can connect to it, and their
connections reach the target device. Only turn it on for a service that is
meant to be public. The applier refuses a target outside `OVERLAY_CIDR`, and
refuses to start forwarding without a target.

## The gluetun backend

With `compose.gluetun.yaml`, [gluetun](https://github.com/qdm12/gluetun)
v3.41.3 owns the tunnel instead of Molebridge's WireGuard container, and
brings its own provider support. Molebridge keeps its routing guard, NetBird
gate, applier and panel; [architecture](architecture.md#gluetun-backend)
describes how. Its live passes used NordVPN, on Docker and on rootless
Podman; other providers, and client traffic through it on rootless Podman,
are untested ([testing](testing.md#gluetun-backend-pass-at-a3bb14f)). To run gluetun and
NetBird with only Molebridge's routing guard and no panel, see
[gluetun as a NetBird exit](gluetun-netbird-exit.md).

You set gluetun's provider with `GLUETUN_PROVIDER`; `PROVIDER` doesn't
apply. The panel can select servers for these gluetun providers:

| `GLUETUN_PROVIDER` | Panel shows | Egress confirmed by |
|---|---|---|
| `mullvad` | Mullvad via gluetun | Mullvad's own check (`am.i.mullvad.net`), as with native Mullvad |
| `nordvpn` | NordVPN via gluetun | NordVPN's own check (`ips/insights`), as with native NordVPN |
| `fastestvpn`, `ivpn`, `surfshark`, `windscribe` | The provider's name via gluetun | The tunnel checks only, shown as "tunnel checks only" |

How it differs from a native provider:

- The server list is gluetun's, read from gluetun's storage, not downloaded
  by the applier. It is as current as gluetun's updater keeps it
  (`GLUETUN_UPDATER_PERIOD`, 24 hours by default); the panel shows the date
  of the provider's data and calls it stale after 30 days. On a fresh
  install it starts as gluetun's built-in list, which can be years old; the
  applier asks gluetun to refresh it once the tunnel works. Start gluetun
  with `GLUETUN_SERVER_COUNTRIES` set to your country
  ([setup](setup.md#with-the-gluetun-backend-instead)).
- A switch tells gluetun which server to use through its control server.
  gluetun restarts its tunnel for that, so open connections drop, as with
  any switch; the applier waits up to 90 seconds for the new server before
  the switch counts as failed.
- gluetun starts with the server named in `GLUETUN_SERVER_*`. After gluetun
  restarts, the applier puts your last selection back.
- The panel lists only ordinary servers. For NordVPN that is the same rule
  as the native provider: standard servers, without Dedicated IP (a separate
  purchase), Double VPN, Onion Over VPN and obfuscated ones, which Molebridge
  doesn't select. gluetun
  stores Surfshark's multi-hop and obfuscated servers in the same list
  without marking them, so for Surfshark only the ordinary and static-IP
  servers (`xx-yyy.prod.surfshark.com`, `xx-yyy-st001.prod.surfshark.com`)
  are listed.
- gluetun's other WireGuard providers can carry traffic but the panel can't
  select their servers: AirVPN and ProtonVPN list several servers under one
  name, and gluetun's `custom` provider has no list. PIA stays native: its
  port forwarding and per-server addresses don't fit this backend.
- What a DNS leak test shows depends on the provider; nothing has been
  recorded for this backend yet.

## Adding a provider

[Other VPN providers](other-providers.md) lists the providers that aren't
supported, which could be added, and what support would look like.

A provider fits the Mullvad model if one WireGuard key and tunnel address
work on every server. It fits the PIA model if keys are registered per server.
Either way it needs a module under `molebridge/` for its server list, an
applier subclass, and one entry in the provider registry,
`molebridge/providers.py`. The entry is the only place that names the
provider's label, server-name pattern, server-list address and size limit,
address model, egress tier, IPv6 support, panel layout and the applier class;
the applier, the panel and the doctor read it from there. The provider needs:

- a parser that treats the provider's server list as untrusted input, with the
  same size limits, schema checks and last-good fallback;
- `apply_relay`, `server_for` and `egress`;
- an egress tier in its registry entry. `provider` means its applier's
  `egress` asks the provider's own endpoint whether the request arrived over
  its VPN, and returns `exit_confirmed`; prefer it whenever the provider has
  such an endpoint. `tunnel` means it has none: the base applier then runs
  the shared tunnel checks instead (two IP echo services through the tunnel
  that agree, an address different from the host's own, a match against any
  exit addresses the catalogue lists as `exit_ips`, and a fresh handshake),
  and the panel shows a connected exit with a "tunnel checks only" label.
  [Architecture](architecture.md#status-reporting) describes both.

A provider counts as supported only once the full
[verification](verification.md) has run on a real host with a real client,
and the result is recorded in [testing](testing.md).
