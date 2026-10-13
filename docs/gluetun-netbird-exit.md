# gluetun as a NetBird exit node

**Experimental.** This page is for you if you want your NetBird devices to use a
[gluetun](https://github.com/qdm12/gluetun) connection as an exit node, and
want to understand how Molebridge keeps it safe. It describes
`compose.gluetun.yaml`: gluetun, the `exit` container beside it, and the optional
panel. gluetun and NetBird do not work safely together without something like
Molebridge's routing contract.
[Why plain gluetun plus NetBird fails](#why-plain-gluetun-plus-netbird-fails)
explains why, so you can judge whether to use the design as written or adapt it.

**What changed in 0.8.0.** In 0.7 you could run this form without Molebridge's
panel and server logic: three containers, a routing guard as a sidecar, a gate
script in front of NetBird, and any gluetun WireGuard provider. That form is
gone. The `exit` container is one program that holds the routing, supervises
NetBird and runs the provider logic (server list, selection through gluetun's
control server, egress checks, the status record), and it accepts only the six
providers the registry knows: FastestVPN, IVPN, Mullvad, NordVPN, Surfshark and
Windscribe. The panel stays optional: start `gluetun` and `exit` alone, and read
the result with `molebridge status`. A provider outside that list, or OpenVPN,
isn't covered ([other providers](other-providers.md)).

## What was tested

[Testing](testing.md#080) is the record. At 0.8.0 a gluetun overlay exit with NordVPN, upgraded
from 0.7.0 on rootless Podman with Quadlet units, came up healthy and connected. No drill was run
on it live and no client was held on it; the gluetun rules, monitors and stop sequence are covered
by the namespace drills in CI only. The design itself was verified live at 0.7.0, with NordVPN
through gluetun v3.41.3, on Docker
([2026-10-08](testing.md#gluetun-backend-pass-at-a3bb14f)) and on rootless Podman with a Linux
client held on the exit ([2026-10-11](testing.md#070-on-rootless-podman-at-d5a234a)).

**Not tested at any version:** any gluetun provider other than NordVPN, IPv6 through gluetun,
the `SERVER_CATEGORIES` override, podman-compose, and Docker Engine on Linux. **Not tested at
0.8.0:** running `compose.gluetun.yaml` at all, and NetBird Cloud
([the list](testing.md#not-tested-at-080)).

## What you get, and what you don't

You get:

- **Forwarded traffic fails closed.** Traffic your devices send through the exit leaves
  only through gluetun's tunnel. If the tunnel or its route is gone, that traffic is
  dropped; it does not fall back to the host's connection. This is what the routing
  contract is for, and the [drills](#verification) check it.
- **NetBird's own traffic stays off the tunnel.** The exit peer's connections to
  NetBird's management, signal and relay servers, and its WireGuard socket, use the
  host's route. A plain gluetun setup sends them into the tunnel.
- **The exit's own traffic goes into the tunnel or fails.** What gluetun and other
  processes in the namespace send without a mark does not use the host interface while
  gluetun reconnects. Rules 102 to 104 below are why.
- **Server selection and a verdict.** The exit selects servers through gluetun's control
  server, restores your selection after gluetun restarts, and checks the peer, the
  handshake and the egress on a schedule, with the same status record and panel as the
  native providers.
- **Gluetun's tunnel and provider support.** The tunnel is gluetun's; you configure it
  the way gluetun's documentation describes.

You don't get:

- **No automatic failover.** A dead tunnel means a dead exit until gluetun reconnects.
  Molebridge never picks another server.
- **WireGuard only.** The contract assumes a kernel WireGuard tunnel. OpenVPN, and
  providers gluetun supports only over OpenVPN, are not covered.
- **No kill switch on your devices.** As with Molebridge, a device that deselects the exit,
  or that NetBird disconnects, uses its own connection.

## Why plain gluetun plus NetBird fails

Put NetBird in gluetun's network namespace and select it as an exit node, and
two things go wrong. Each is a mechanism, not a setting, which is why the fix
is a routing contract and not a flag.

1. **Gluetun sends NetBird's control traffic into the tunnel.** Gluetun adds
   the policy rule `101: not fwmark 51820 lookup 51820`. It matches every
   packet whose mark is not 51820, and table 51820 sends it through the
   tunnel. NetBird marks its own sockets (management, signal, relay, ICE and
   STUN, and the WireGuard socket) with `0x1BD00` so they can take the host's
   route. Rule 101 matches that mark too, so those connections go to the
   provider instead. At best that adds latency and shows your provider
   NetBird's metadata. At worst the peer cannot reach its control plane.
2. **Gluetun's firewall drops forwarded traffic.** Gluetun sets its `FORWARD`
   policy to `DROP`. Your devices' packets arrive on `wt0` and are dropped
   before they reach the tunnel.

The exit also needs the same NetBird requirements as Molebridge:

- **NetBird runs with kernel WireGuard and its kernel firewall**, with
  `NB_DISABLE_USERSPACE_ROUTING=true`, in daemon mode with its default
  profile. [The exit](#the-checks-in-the-exit) refuses other settings.
- **Overlay traffic is never delivered to the exit itself.** The contract's rule
  1 routes every packet arriving on `wt0` like forwarded traffic, so features
  that serve devices from the exit don't work there.
  [Keep these off for the exit peer](#keep-these-off-for-the-exit-peer).

The contract works in policy routing. The firewall rules in this setup only open
what gluetun's `DROP` policies would block
([Post-rules](#post-rules-for-gluetuns-firewall)).

## The design

Three containers, with the first two sharing one network namespace owned by `gluetun`:

| Service | Role |
|---|---|
| `gluetun` | Owns the namespace, creates the tunnel interface (`wg0` by default), runs its own firewall. Starts through `routing/gluetun-preflight`. |
| `exit` | The Molebridge image's `exit` role, joined to gluetun's namespace (`network_mode: service:gluetun`) with `TUNNEL_BACKEND=gluetun`. Installs and keeps the rules and routes below, runs NetBird as a supervised child, reads gluetun's server list and switches servers through its control server. `NET_ADMIN`, `NET_RAW` and `DAC_OVERRIDE`. |
| `switchyard` | The panel. Optional; on its own network. |

Gluetun deletes and recreates its tunnel interface on every reconnect, and the kernel drops
the routes through it. The exit therefore keeps watching: it repairs on the kernel's
notifications, and runs a full pass every `ROUTING_RECONCILE_INTERVAL` seconds (30 by
default) as the fallback. [Architecture](architecture.md#gluetun-backend) is the canonical
description of how the backend works: the containers, the rules and tables, the repair loop,
the monitors and the switch. This page keeps what you set, what you will see and what to do.

### The rules

The exit owns priorities 0 to 97 and 102 to 104 in this namespace, in both IPv4 and IPv6, and
removes anything else at those priorities. Gluetun's rules 98 to 101 and NetBird's 105 and 110
are left alone. Do not add your own rules at the contract's priorities. Two tables go with
them: the exit table (51821, `EXIT_TABLE`), which always holds an `unreachable default metric
4096` fallback and holds `default dev <tunnel>` only while the tunnel interface is up, and the
host table (51822, `HOST_TABLE`), copies of the host interface's default and on-link routes and
never a route through the tunnel. Table 51820 is gluetun's own, not the exit table.
[Architecture](architecture.md#why-the-routing-contract-is-policy-routing) lists every rule and
why it exists; [Before any drill](#before-any-drill) shows what `ip rule show` should print.
Typing the rules by hand is not a substitute: the tunnel route has to come back every time
gluetun recreates its interface, and that is the exit's loop.

### The checks in the exit

In 0.7 a script in front of NetBird (the gate) did these. In 0.8.0 the exit does them itself,
because it starts NetBird. They matter because rules 88 and 89 only see packets that carry
NetBird's mark: if NetBird runs without it, its control traffic is unmarked and reaches
gluetun's rule 101. The mechanism is in
[architecture](architecture.md#netbirds-control-mark-and-the-monitors). The exit:

1. **Refuses NetBird settings that cannot work here**, with one line and exit status 1:
   `NetBird gate: refusing to start NetBird: <reason> (see docs/troubleshooting.md)`
   (the line keeps the name "gate"). The reasons are the ones in
   [configuration](configuration.md#what-compose-fixes-for-netbird), and for this backend also
   `NB_USE_LEGACY_ROUTING`, `NB_SKIP_SOCKET_MARK` or `NB_DISABLE_CUSTOM_ROUTING` set to true,
   `NB_FWMARK_BASE` different from `CONTROL_MARK`, an `NB_LOG_FILE` with no absolute path, and
   any invalid routing setting (`OVERLAY_CIDR`, `EXIT_IF`, the tables, `CONTROL_MARK`,
   `FWMARK_GRACE`). Check without starting NetBird:

   ```sh
   docker compose run --rm --no-deps exit check-config
   ```

   (gluetun must be running, so the exit can join its namespace.) It prints
   `molebridge-exit: configuration accepted` and `NetBird gate: configuration accepted`, or the
   refusal.
2. **Checks gluetun's control server** before it installs anything: it waits up to 30
   seconds for it to listen on loopback, and refuses if the same port has a listener on
   another address.
3. **Starts NetBird only when the whole contract holds**, in both families, on every start of
   the container. An extra rule at the exit's priorities keeps NetBird from starting.
4. **Stops what it cannot trust**, logging the reason:
   - If NetBird's log shows `advanced routing has been requested to be disabled` or `falling back
     to legacy routing`, or the overlay interface has not carried the control mark for
     `FWMARK_GRACE` seconds (30 by default, 5 to 30), the exit stops NetBird and itself with
     status 1, so the restart policy starts it again. The line is `molebridge-exit: NetBird gate:
     stopping NetBird: <reason> (see docs/troubleshooting.md)`, with the reason `NetBird logged
     that it runs without advanced routing, so its control traffic would be unmarked` or `wt0 has
     not carried the control mark 0x1bd00 for 30 seconds (last reported: <value>)`.
   - If the contract stays broken for `GUARD_GRACE` seconds, the supervisor stops NetBird and
     starts it again once the contract verifies. The container keeps running.
5. **Stops itself** and NetBird if the worker stops answering ([the lease](architecture.md#the-lease)).

One gap remains. NetBird can sign in to management before its overlay interface exists, so the
exit cannot wait for the fwmark before launching. If NetBird's own start-up capability check
fails, its TLS and relay connections go through the provider tunnel until the monitors stop it:
up to `FWMARK_GRACE` seconds, plus sampling and up to 6 seconds for NetBird to exit. That is a
metadata and availability cost for NetBird's control traffic. It does not let your devices'
traffic out: rules 1, 95 and 97 hold forwarded traffic throughout.

## Requirements

- **Linux with kernel WireGuard** (5.6 or later, or an older kernel with the module installed), on an
  always-on host. The setup asks gluetun for the kernel implementation
  (`WIREGUARD_IMPLEMENTATION=kernelspace`), which fails instead of falling back to a userspace tunnel.
  It was tried on a 7.0 kernel in OrbStack's VM on macOS and on rootless Podman, and nowhere else.
- **Docker with Compose 2.24 or later.** At 0.8.0 this Compose file has been validated with
  `docker compose config` only; the live pass used Quadlet units, and 0.7's version ran on Docker
  (OrbStack). Rootless Podman with podman-compose is untested for this setup
  ([below](#rootless-podman)). Molebridge's own stack is tested as described in
  [requirements](prerequisites.md#host).
- **A NetBird account** with admin access, either NetBird Cloud or self-hosted (only a self-hosted
  server has been tried). You need the groups, the policy, a setup key and the exit route. The steps
  are the same as for Molebridge; follow the [NetBird section of the requirements](prerequisites.md#netbird)
  and [setup step 9](setup.md#9-create-the-route-and-try-a-device), and do not skip the group rules: the
  exit peer is never in `exit-users`, and the exit route is never distributed to `All`. The image
  carries the NetBird client; its version is pinned in the `Dockerfile` (0.80.0 at this writing).
- **A WireGuard account at one of the six providers**, with the private key (and the tunnel address, if
  the provider assigns one) that gluetun's documentation for that provider asks for. Only NordVPN has
  been tried.

No Python is needed on the host: the tools run from the image.

## Set up

This is the one installation procedure for the gluetun form, with the reasons. It uses the
bundle's `compose.gluetun.yaml` and `.env.gluetun.example`. The [setup page](setup.md) covers the
native exit and says where this form differs.

1. **Verify and extract the bundle** ([setup](setup.md#1-download-and-verify)), then:

   ```sh
   cp .env.gluetun.example .env
   mkdir -p state/panel state/applier secrets/gluetun tunnel/gluetun
   chmod 700 secrets secrets/gluetun
   IMAGE=$(grep -o 'ghcr.io/irashack/molebridge[^ "]*' compose.gluetun.yaml | head -1)
   ```

   `IMAGE` is the Molebridge reference your Compose file pins; the tools below run from it.

2. **Edit `.env`.** For this setup:

   | Setting | Value |
   |---|---|
   | `COMPOSE_FILE` | `compose.gluetun.yaml` (the example sets it) |
   | `EXIT_IF` | `wg0`: the name gluetun gives its tunnel (`VPN_INTERFACE`). Letters, digits and underscores only. The exit and NetBird's ICE blacklist use the same value |
   | `OVERLAY_CIDR` | Your NetBird peer range, `100.64.0.0/10` for NetBird's default |
   | `OVERLAY6_CIDR` | Your NetBird IPv6 range, if you have one |
   | `GLUETUN_PROVIDER` | gluetun's `VPN_SERVICE_PROVIDER`: `fastestvpn`, `ivpn`, `mullvad`, `nordvpn`, `surfshark` or `windscribe` |
   | `GLUETUN_WIREGUARD_ADDRESSES` | The tunnel address your provider assigned, if it needs one. NordVPN does not |
   | `GLUETUN_SERVER_COUNTRIES` | Your own country, as gluetun names it. See [the first start](#the-first-start) |
   | `NB_HOSTNAME`, `NB_MANAGEMENT_URL` | The peer's name, and your management URL if you self-host NetBird |
   | `HOST_IF` | `eth0` on Docker |

   [Configuration](configuration.md#gluetun-backend) lists every setting. Some providers need gluetun
   settings beyond this table; supply them in a Compose override listed in `COMPOSE_FILE`. AirVPN, for
   example, needs its preshared key, but it isn't one of the six.

3. **Put the provider's WireGuard private key in a file.** Open it in an editor, so the key never lands
   in shell history. It holds one line:

   ```sh
   (umask 077 && ${EDITOR:-vi} secrets/gluetun/wireguard_private_key)
   ```

4. **Write gluetun's role file.** Without a role file, gluetun's control server applies a public default
   role that includes a route that stops the VPN. `compose.gluetun.yaml` therefore refuses to start gluetun
   without the file:

   ```sh
   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/secrets/gluetun:/out" "$IMAGE" gluetun-auth /out
   ```

   It writes `secrets/gluetun/auth.toml` and `secrets/gluetun/api_key`, both mode 0600, from one generated key,
   and never prints the key. The role it defines allows five routes: `PUT /v1/vpn/settings`, `GET
   /v1/vpn/status`, `GET /v1/publicip/ip`, and `GET` and `PUT /v1/updater/status`.

5. **Write gluetun's post-rules** from your settings, and read the result:

   ```sh
   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/tunnel/gluetun:/out" \
     -e OVERLAY_CIDR=<your NetBird range> "$IMAGE" gluetun-post-rules /out
   cat tunnel/gluetun/post-rules.txt
   ```

   Add `--ipv4-only` if gluetun later logs that it found no working `ip6tables`; pass any of `HOST_IF`,
   `EXIT_IF`, `OVERLAY_IF`, `CONTROL_MARK` and `NB_WIREGUARD_PORT` with `-e` when they aren't the defaults.
   [Post-rules](#post-rules-for-gluetuns-firewall) explains the lines.

6. **Add the NetBird setup key** to `secrets/netbird.env`, as one line, `NB_SETUP_KEY=` followed by the key.
   Create the file in an editor:

   ```sh
   (umask 077 && ${EDITOR:-vi} secrets/netbird.env)
   ```

7. **Start gluetun, check, then start the rest:**

   ```sh
   docker compose up -d gluetun
   docker compose run --rm --no-deps exit check-config
   docker compose up -d
   docker compose ps
   docker compose logs exit
   ```

   The exit's log should show `molebridge-exit: rules installed; the exit table holds its unreachable
   fallback`, then `molebridge-exit: ready`, `molebridge-exit: starting NetBird` and `molebridge-exit: NetBird
   is up (launch 1)`. If the exit refuses, its message names the setting; see
   [troubleshooting](troubleshooting.md#startup).

8. **Check that the peer is in NetBird** under `NB_HOSTNAME`, in `exit-nodes`, then delete
   `secrets/netbird.env`. The peer's identity now lives in the `netbird-data` volume; never run `down -v`.
   Revoke the setup key if it was reusable.
9. **Run the [checks](#verification) before any device selects the exit.** Then create the exit-node route as
   the requirements describe, and try one device.

`NB_EXTRA_IFACE_BLACKLIST` (the tunnel interface) takes effect when the peer first enrolls. It is stored in the
peer's profile in the `netbird-data` volume, and changing the environment variable later does not change it. The
exit checks the stored profile before it starts NetBird and refuses a profile that lacks the entry; the repair is
[the `fix-blacklist` tool](operations.md#netbird-interface-blacklist). `NB_WIREGUARD_PORT` also takes effect at
first enrollment.

### If you already run gluetun

You can add the exit container to a gluetun you have, instead of using
`compose.gluetun.yaml`. The exit must be one of the six providers' registry ids
(`PROVIDER=gluetun-<id>`). Copy what that file does:

- `VPN_TYPE=wireguard`, `WIREGUARD_IMPLEMENTATION=kernelspace`, and
  `VPN_INTERFACE` set to the name you use as `EXIT_IF` everywhere. Gluetun
  accepts letters, digits and underscores only, and its own default is `tun0`.
- The sysctls on the gluetun service: `net.ipv4.ip_forward=1`,
  `net.ipv6.conf.all.forwarding=1`, `net.ipv4.icmp_errors_use_inbound_ifaddr=1`,
  and `net.ipv6.conf.all.disable_ipv6=0` with the same for `default`. The
  third makes the exit's ICMP errors for tunnel traffic carry the tunnel
  address, so rule 94 returns them through the tunnel. The exit logs
  `molebridge-exit: warning: net.ipv4.icmp_errors_use_inbound_ifaddr is not 1; ...` when it is missing.
- `FIREWALL_INPUT_PORTS` set to NetBird's WireGuard port (`NB_WIREGUARD_PORT`,
  51820 by default).
- The control server on `127.0.0.1:8000` only
  (`HTTP_CONTROL_SERVER_ADDRESS`), with a role file
  (`HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH`). Its default address, `:8000`,
  listens on every interface in the namespace. No `ports:` entry for it.
- The post-rules file mounted at `/iptables/post-rules.txt`, and the key from
  `WIREGUARD_PRIVATE_KEY_SECRETFILE` (a file, never the environment).
- The role-file check: the `routing/gluetun-preflight` mount and the
  `entrypoint` that runs it before `/gluetun-entrypoint`, with
  `MOLEBRIDGE_KIND=overlay` set on the gluetun service. It refuses a role
  file other than the one `gluetun-auth` writes, so gluetun never logs an
  excerpt of a malformed file, key included, and it refuses to start gluetun
  without the post-rules file.
- Gluetun pinned as `compose.gluetun.yaml` pins it. The design was read against
  that release's source; another release may differ.
- The `exit` service as defined in that file, with `network_mode: service:gluetun`,
  `TUNNEL_BACKEND=gluetun`, the capabilities, tmpfs and mounts it lists. Its
  `EXIT_IF`, `HOST_IF`, `HOST_TABLE`, `CONTROL_MARK` and the other routing settings
  must be the ones you gave `gluetun-post-rules`.

## Gluetun's settings

What `compose.gluetun.yaml` sets on gluetun, and why:

| Setting | Value | Why |
|---|---|---|
| Image | `docker.io/qmcgaw/gluetun:v3.41.3@sha256:fa19cc76b2af13d57a8d3dc3066f2ada061b1c761b8aecf989b3877c0486e027` | Pinned by digest. Update deliberately. |
| `VPN_TYPE` | `wireguard` | The only type the routing contract covers. |
| `WIREGUARD_IMPLEMENTATION` | `kernelspace` | Gluetun's values are `auto`, `userspace` and `kernelspace`; this one fails instead of falling back to a userspace tunnel. |
| `VPN_INTERFACE` | `EXIT_IF` | The exit and NetBird's ICE blacklist must name the same interface. |
| `WIREGUARD_PRIVATE_KEY_SECRETFILE` | `/run/secrets/wireguard_private_key` | The key is read from a file bind-mounted from `secrets/gluetun/wireguard_private_key`, never from the environment. |
| `HTTP_CONTROL_SERVER_ADDRESS` | `127.0.0.1:8000` | Namespace loopback only, never published. |
| `HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH` | `/gluetun/auth/config.toml` | The role file from `gluetun-auth`. With any role in it, gluetun answers no other route. |
| `FIREWALL_INPUT_PORTS` | `NB_WIREGUARD_PORT` | Opens NetBird's WireGuard port in gluetun's `INPUT` chain. |
| `UPDATER_PERIOD` | `24h` | How often gluetun refreshes its server list. The exit also asks it for one refresh when the data is old. |
| `SERVER_COUNTRIES`, `SERVER_CITIES`, `SERVER_HOSTNAMES` | From `.env` | The server gluetun starts with. |

The file also sets `STORAGE_FILEPATH`, in a volume of its own, so the exit can read
gluetun's server list and mount only that directory, read-only.

**The control server's key is full gluetun administration.** Gluetun authorizes
by route and method only, and `PUT /v1/vpn/settings` accepts any VPN setting:
keys, addresses, the provider, command hooks. Keep `secrets/gluetun/api_key`
mode 0600; only the exit mounts it.

## Post-rules for gluetun's firewall

Gluetun enables its firewall once, at startup, and then runs the commands in
`/iptables/post-rules.txt`. The `gluetun-post-rules` tool writes them from your
settings. With the defaults they are:

```text
iptables -A FORWARD -i wt0 -o wg0 -j ACCEPT
iptables -A FORWARD -i wg0 -o wt0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -o eth0 -j ACCEPT
iptables -A INPUT -i eth0 -p udp -m udp --dport 51820 -j ACCEPT
ip6tables -A FORWARD -i wt0 -o wg0 -j ACCEPT
ip6tables -A FORWARD -i wg0 -o wt0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ip6tables -A OUTPUT -o eth0 -j ACCEPT
ip6tables -A INPUT -i eth0 -p udp -m udp --dport 51820 -j ACCEPT
```

These open what the exit needs through gluetun's `DROP` policies. They are not
what keeps traffic in the tunnel: policy routing is.

- The two `FORWARD` lines let `wt0` traffic reach the tunnel and the
  established replies come back.
- The `OUTPUT` line accepts everything that leaves by the host interface. It
  cannot name NetBird's control mark. To remove its own rules on every
  reconnect, gluetun lists the whole chain and parses every line. Its parser
  knows only the targets `ACCEPT`, `DROP`, `REJECT` and `REDIRECT`, and only TCP
  and UDP destination-port and connection-state matches. A mark match or a jump
  to a chain of your own makes it fail, and its old accepts pile up. What may
  actually leave by the host interface is decided by policy routing (rules 88,
  89, 102 and 103); rule 104 stops the rest.
- The `INPUT` line accepts NetBird's WireGuard port. It overlaps with
  `FIREWALL_INPUT_PORTS`; `compose.gluetun.yaml` sets both.
- A line that fails stops gluetun, including every `ip6tables` line when
  gluetun found no working `ip6tables`. That is the case for `--ipv4-only`.
- Gluetun runs the file once, at startup. It does not run it again after an
  in-process VPN restart, which does not clear the rules either. Write it
  again after changing `HOST_IF`, `EXIT_IF`, `OVERLAY_IF`, `CONTROL_MARK` or
  `NB_WIREGUARD_PORT`, and recreate gluetun and the exit.
- If you write your own lines, use only what gluetun's parser reads: no mark
  match and no jump to a custom chain.

## The first start

Set `GLUETUN_SERVER_COUNTRIES` to your own country, as gluetun names it
(`Netherlands`, `United States`), and leave the city and hostname empty.
Gluetun's built-in server list is old (for NordVPN in v3.41.3 it dates from
2024), and gluetun's own updater first runs one `UPDATER_PERIOD` (24 hours)
after it starts, not at start.
A hostname or city missing from the built-in list stops gluetun at start
(`the hostname specified is not valid`, or the same for a city or country).
A whole country is unlikely to be gone, and a nearby one answers best. With the
filter empty, gluetun picks among every country's servers.

On the first start gluetun may restart its VPN several times before it
connects, because it picks servers from the old list that no longer answer. The
exit does not wait for the updater. Once the tunnel has a recent handshake and
the list is older than `GLUETUN_UPDATER_PERIOD` or 7 days, whichever is
shorter, it asks gluetun's updater for one refresh (up to three attempts per
start, five minutes apart; `0` turns this off). The panel shows the list's date
and calls it stale after 30 days.

In the panel, the provider's name appears with "via gluetun". While the refresh runs,
Diagnostics says `updating server list`, and a minute or two after it finishes the panel lists
the current servers; choose a server after that. gluetun starts on any server (or the one from
`GLUETUN_SERVER_*`), and picking one in the panel takes over. For providers other than Mullvad
and NordVPN the panel shows a connected exit as "tunnel checks only", because there is no
provider check.

## A configured server

Set `SERVER` in `.env` to one server hostname from the catalog to pin the exit to it.
When `SERVER` is set, configuration wins: the exit ignores `desired.json` and restores
`SERVER` after a gluetun restart, ahead of a saved panel selection. If you run Switchyard,
it shows that exit read-only as "Set in configuration". Invalid or unknown names fail
validation rather than falling back to a panel selection. `GLUETUN_SERVER_*` filters still
choose gluetun's initial connection before the exit can converge. See [the setting and its
validation](configuration.md#a-server-set-in-configuration).

## Choosing and switching servers

Choose a server in the panel, or pin one with `SERVER`. The exit then puts the selection to
gluetun's control server, which restarts its VPN in-process: the namespace stays, and the
exit puts the exit route back within a couple of seconds. Connections open through the exit
drop. It restores your last verified selection after gluetun restarts, and checks the peer,
the handshake and the egress on a schedule. Without the panel and without `SERVER`, the
server is whatever `GLUETUN_SERVER_*` gives gluetun at start.

Don't `PUT` to gluetun's control server yourself while the exit runs: it keeps its own
selection and would put it back. The role file the exit uses allows only the five routes
listed above, and its key is `secrets/gluetun/api_key`.

**NordVPN.** Molebridge's panel lists only standard servers, not Dedicated IP servers (a
separate purchase), Double VPN, Onion Over VPN or obfuscated ones, which it doesn't
select. A country filter in `GLUETUN_SERVER_*` alone does not exclude them for gluetun's
own first connection; pin a hostname you know is in NordVPN's standard list if that
matters. Gluetun's `SERVER_CATEGORIES` setting selects by category, but
`compose.gluetun.yaml` does not pass it through; you would add it to the gluetun service
in a `compose.override.yaml` and set
`COMPOSE_FILE=compose.gluetun.yaml:compose.override.yaml`. That has not been tried.

## Keep these off for the exit peer

Rosenpass, NetBird SSH, DNS nameservers and domain routes are not supported
on the exit peer.

- **Rosenpass.** Its key exchange needs local delivery from the overlay, which
  the contract refuses. The exit refuses to start NetBird with it on.
- **NetBird SSH.** It doesn't work on the exit peer.
- **DNS nameservers and domain routes served by the exit.** The exit doesn't
  answer anything addressed to itself that arrives over NetBird, so a NetBird
  nameserver group served by the exit cannot work. Point NetBird's nameservers
  at something else.

These features don't work on the exit peer whether or not you follow this
list. The list is about not leaving on a feature that cannot work.

## Verification

Run these on your own host before you rely on the exit, and again after you change routing,
the gluetun settings or the compose file. The namespace checks and drills in
[verification](verification.md) are for the native backend and don't carry over by renaming;
use the ones below. The [client and LAN isolation checks](verification.md#from-a-client) and a
host reboot with unattended recovery apply as written.

Keep an independent way into the host. Do not paste raw addresses from these outputs into a
report. Never run `wg showconf` or print a key.

The commands run in a diagnostic shell joined to the namespace, the one
[verification](verification.md#inside-the-namespace) starts; join `molebridge-gluetun` or
`molebridge-exit`, they share it:

```sh
docker run --rm -it --network container:molebridge-gluetun \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  docker.io/library/alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 \
  sh -c 'apk add --no-cache iproute2 nftables curl wireguard-tools tcpdump >/dev/null && exec sh'
```

(That downloads packages through the namespace's unmarked route, which gluetun sends into the
tunnel: it works only once the tunnel is up.)

### Before any drill

1. **Rules and routes.** In the shell:

   ```sh
   ip rule show
   ip -6 rule show
   ip route show table 51821
   ip -6 route show table 51821
   ip route show table 51822
   ```

   The IPv4 rules should list 1, 88, 89, 90, 91, 92, 94, 95, 96, 97, 102, 103 and 104, with
   gluetun's 98 to 101 (and NetBird's 105 and 110 once it is up) between them, and no rule 0 and
   no rule 80. Rule 1 reads like `1: not from all iif wt0 lookup local`. The exit table shows
   `default dev wg0` and `unreachable default ... metric 4096`. With an IPv4-only tunnel such as
   NordVPN's, the IPv6 exit table has only the unreachable route, and IPv6 has no rule 94. IPv6 has
   rules 90 to 92 only if you set `OVERLAY6_CIDR`.
2. **NetBird's marking.** In the shell:

   ```sh
   wg show wt0 fwmark
   ```

   It must print `0x1bd00`. Anything else, including `0` or `off`, means NetBird's control traffic
   is unmarked and can enter the tunnel. The exit stops NetBird after `FWMARK_GRACE` seconds (30 by
   default) of that; find out why before going on.
3. **Kernel WireGuard.** `ip -d link show wt0` shows `wireguard` on its details line. The exit also
   refuses the settings that switch kernel WireGuard and NetBird's kernel firewall off
   ([the checks](#the-checks-in-the-exit)).
4. **Egress through the tunnel.** From the namespace, an unmarked request goes through gluetun's
   rule 101 into the tunnel. In the shell, with a service you trust:

   ```sh
   curl -fsS https://<ip-echo-service>
   ```

   The address should be your provider's, not your host's public address. Compare it with your
   provider's own check page, and run the same from your host without the container to see the
   difference. For NordVPN, `https://api.nordvpn.com/v1/helpers/ips/insights` reports `protected`.
5. **The exit's own verdict.** `docker compose exec exit molebridge status` should print `state: ok
   (connected)`.

### Drills

For each drill, keep a client on the exit pinging a public address you can test with
(`<probe-ip>`). During the drill the probe must fail. It must not succeed using your host's public
address. With a tunnel that has IPv6, test both families. Run the capture below in a second terminal,
so you see what appears on the host interface.

**The capture.** It watches the host interface inside the namespace for the probe address. It stays in
the namespace it joined, so it can't see a new one: for the drills that recreate gluetun, start it
again once gluetun is back and note the gap, or capture on the host side instead (on Linux, the host's
own interface, filtered the same way). In a shell as above:

```sh
tcpdump -ni eth0 "host <probe-ip>"
```

This must print nothing for the whole drill, including the time between the break and the reconnect, or
from the restart of the capture on. A packet here means a client's traffic left the namespace by the
host's route. Under rootless Podman the interface has the host's own name. To see what the host
interface does carry, use a broader filter: you should see NetBird's WireGuard port, STUN and its TCP
control connections, and gluetun's transport to the provider endpoint. Anything else needs an
explanation.

The exit repairs a deleted rule or route within milliseconds of the kernel's notification, so to watch
a path fail, freeze the worker first and let it continue within the lease (15 seconds is safe at the
default `GUARD_GRACE` of 30):

```sh
docker exec molebridge-exit pkill -STOP -f 'exit --work[e]r'
# break something in the shell, watch the probe fail
docker exec molebridge-exit pkill -CONT -f 'exit --work[e]r'
```

| Drill | Break | Expect | Restore |
|---|---|---|---|
| Tunnel down | In the shell, `ip link set wg0 down` | The probe fails. Nothing in the capture. | In the 0.7 test, gluetun did not bring a downed interface back by itself within several minutes, so recreate: `docker compose up -d --force-recreate gluetun exit` |
| Exit-table route deleted | Freeze the worker, then in the shell `ip route del default dev wg0 table 51821` | The probe fails. | Let the worker continue: the exit logs `molebridge-exit: IPv4 tunnel route through wg0 restored` |
| Lookup rule deleted | Freeze the worker, then `ip rule del priority 95` (and `ip -6` for IPv6) | The probe fails on terminal rule 97. | Let the worker continue: `molebridge-exit: added IPv4 rule 95` |
| Gluetun recreated | `docker compose up -d --force-recreate gluetun exit` | The probe fails until both are back. Nothing in the capture. | The command is the restore |
| Worker hung | `docker exec molebridge-exit pkill -STOP -f 'exit --work[e]r'` and leave it | After `GUARD_GRACE` seconds the log has `molebridge-exit: stopping (lease lapsed)`, NetBird is stopped, the overlay interface is removed (never gluetun's tunnel), and the container restarts. The probe fails. Nothing in the capture. | The restart policy |
| NetBird killed | `docker exec molebridge-exit pkill -KILL -x netbird` | The exit stops and restarts. The probe fails while the peer is down. After it returns, `wg show wt0 fwmark` prints `0x1bd00`. | The restart policy |

The first drill depends on how gluetun reacts when its interface goes down. In the 0.7 test on
2026-10-08, with the applier present, the tunnel-down drill held: no client traffic and none of
gluetun's own flows left the host interface. How long the reconnect took was not recorded. After each
restore, repeat check 4; after the recreation, repeat checks 1 and 2, and run the
[attachment procedure](operations.md#checking-that-containers-share-gluetuns-namespace) for any
application of your own in the namespace.

### Local delivery

A packet that arrives on `wt0` must never reach a process on the exit. Start a listener inside the
namespace, in the shell, then connect to it from a device on the exit:

```sh
nc -l -p 8099
```

From the device, with the exit's overlay address in place of `<exit-overlay-address>`:

```sh
nc -vz -w 3 <exit-overlay-address> 8099
```

The connection must time out or fail. Stop the listener afterward. If it connects, rule 1 is missing
or something sits ahead of it; check `ip rule show` before anything else. A ping to the exit's own
overlay address gets no reply for the same reason, although the access policy allows ICMP.

## Rootless Podman

At 0.8.0 a gluetun overlay exit with NordVPN ran on rootless Podman 5.8 as Quadlet units
([testing](testing.md#080)), upgraded from 0.7.0; podman-compose has not been run with this form. A rootless
engine puts the namespace on a private network, so NetBird's only host candidate is an address nothing outside the
host can reach. Devices on your LAN still connect directly, but devices
elsewhere fall back to a relay without any error. The method that worked for
Molebridge's own stack is pasta's port forwarding on the container that owns
the namespace; in this setup that container is `gluetun`. Do not publish
NetBird's port with `ports:`: it holds the host port, so NetBird's outgoing STUN
cannot use it.

[Exits on a private container network](operations.md#exits-on-a-private-container-network)
has the problem, the `network_mode: "pasta:..."` option string and the
`netbird up --wireguard-port ... --external-ip-map ...` step, written for the
native `exit` service. Put the `network_mode` on `gluetun` instead, keep NetBird's
port in `FIREWALL_INPUT_PORTS`, and set `HOST_IF` to the interface name inside
the namespace (`eth0` with the option string there, which sets `-I eth0`).
Gluetun's control server stays unpublished. The tools run as `podman run` without
`--user`, as in [the tools reference](tools-reference.md).

## DNS inside the namespace

Containers that join gluetun's namespace, the exit and NetBird in it included, resolve names
through gluetun's own DNS server on 127.0.0.1, which forwards through the
tunnel. While the tunnel is down, NetBird cannot look up its management, signal
or relay hostnames; connections it already has carry on, and new lookups work
again once gluetun reconnects. This was observed in the test on Docker with
OrbStack; other engines haven't been checked. Nothing leaves outside the
tunnel because of it.

## Client notes

- **Hotel and other restrictive Wi-Fi.** A healthy exit can still leave a
  device at Connecting on a network that breaks long-lived UDP flows. NetBird's
  relay prefers QUIC, which connects and then dies there, and the client falls
  back to WebSocket only when QUIC cannot connect. That is NetBird's behavior,
  not the exit's.
  [Troubleshooting](troubleshooting.md#clients) has the setting that makes a
  desktop client prefer WebSocket.
- **DNS leak tests.** Neither gluetun nor the exit changes your devices' DNS,
  and the exit cannot serve a nameserver. [DNS](operations.md#dns) says what a
  leak test shows with Mullvad. Nothing is recorded for gluetun or NordVPN.
- **Phones.** Turn off *Force relay connection* in the NetBird app (Settings,
  then Advanced). It is on by default and routes all exit traffic through a
  NetBird relay.
- **Relayed clients.** If `docker compose exec exit netbird status -d` shows `Relayed` for devices that
  should be direct, see [clients are relayed](troubleshooting.md#clients).

## If something goes wrong

[Troubleshooting](troubleshooting.md#gluetun-backend) covers the exit's refusals and stops, the control-server
checks, the preflight's messages, and gluetun refusing to start with a server it does not know. Gluetun's own log
(`docker compose logs gluetun`) says why it could not connect.

---

Gluetun is a separate project under its own license and maintainers. Molebridge isn't affiliated with it, and its
name is used only to say what this page describes.
