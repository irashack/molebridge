# gluetun as a NetBird exit node, without the rest of Molebridge

This page is for you if you already run, or want to run,
[gluetun](https://github.com/qdm12/gluetun) and want your NetBird devices to
use it as an exit node, without Molebridge's panel or applier. It uses one
part of Molebridge, the routing guard, as a sidecar container, and one script
that gates NetBird's start. Gluetun and NetBird do not work safely together
without something like them.
[Why plain gluetun plus NetBird fails](#why-plain-gluetun-plus-netbird-fails)
explains why, so you can judge whether to use the design as written or adapt
it.

## What was tested

On 2026-10-08 this design was verified live on Docker (OrbStack, with a Linux
7.0 kernel VM, on macOS), with NordVPN through gluetun v3.41.3 and a
self-hosted NetBird server with the 0.79.0 client, in two runs:

- **With Molebridge's applier** (at `a3bb14f`): forwarding with a client on a
  direct (P2P) path; local delivery to the exit from NetBird refused; tunnel
  down with no client traffic and none of gluetun's own flows on the host
  interface; NetBird's control traffic on the host interface only; recreation
  and recovery.
- **In the form on this page** (at `4933360`, with only `gluetun`, `guard` and
  `netbird` running): [checks](#before-any-drill) 1 to 4; the drills for a
  deleted exit-table route, a deleted lookup rule, NetBird restarted and
  gluetun recreated, each with the client's probe failing and nothing on the
  host interface's capture; [local delivery](#local-delivery) refused; and a
  server switch through gluetun's control server with the `curl` commands
  under [Choosing and switching servers](#choosing-and-switching-servers).

**Not tested:**

- rootless Podman;
- any gluetun provider other than NordVPN;
- IPv6 through gluetun (NordVPN is IPv4 only);
- the `SERVER_CATEGORIES` override.

[Testing](testing.md#gluetun-backend-pass-at-a3bb14f) holds the record.

## What you get, and what you don't

You get:

- **Forwarded traffic fails closed.** Traffic your devices send through the
  exit leaves only through gluetun's tunnel. If the tunnel or its route is
  gone, that traffic is dropped; it does not fall back to the host's
  connection. This is what the guard is for, and the
  [drills](#verification) check it.
- **NetBird's own traffic stays off the tunnel.** The exit peer's connections
  to NetBird's management, signal and relay servers, and its WireGuard
  socket, use the host's route. A plain gluetun setup sends them into the
  tunnel.
- **The exit's own traffic goes into the tunnel or fails.** What gluetun and
  other processes in the namespace send without a mark does not use the host
  interface while gluetun reconnects. Rules 102 to 104 below are why.
- **Gluetun's tunnel and provider support.** The tunnel is gluetun's; you
  configure it the way gluetun's documentation describes.

You don't get:

- **No panel.** You choose a server by editing gluetun's settings and
  recreating three containers, or through gluetun's own control server
  ([Choosing and switching servers](#choosing-and-switching-servers)).
  Connections open through the exit drop when it switches.
- **No egress status.** Nothing checks, on a schedule, that the tunnel carries
  traffic to your provider, and nothing reports it. You run the checks under
  [Verification](#verification) yourself.
- **No automatic failover.** A dead tunnel means a dead exit until gluetun
  reconnects.
- **WireGuard only.** The guard assumes a kernel WireGuard tunnel. OpenVPN, and
  providers gluetun supports only over OpenVPN, are not covered.
- **No kill switch on your devices.** As with Molebridge, a device that
  deselects the exit, or that NetBird disconnects, uses its own connection.

## Why plain gluetun plus NetBird fails

Put NetBird in gluetun's network namespace and select it as an exit node, and
two things go wrong. Each is a mechanism, not a setting, which is why the fix
is a routing guard and not a flag.

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
  profile. [The gate](#the-gate) refuses other settings.
- **Overlay traffic is never delivered to the exit itself.** The guard's rule
  1 routes every packet arriving on `wt0` like forwarded traffic, so features
  that serve devices from the exit don't work there.
  [Keep these off for the exit peer](#keep-these-off-for-the-exit-peer).

The guard works in policy routing. The firewall rules in this setup only open
what gluetun's `DROP` policies would block
([Post-rules](#post-rules-for-gluetuns-firewall)).

## The design

Three containers share one network namespace, owned by `gluetun`:

| Service | Role |
|---|---|
| `gluetun` | Owns the namespace, creates the tunnel interface (`wg0` by default), runs its own firewall. |
| `guard` | Molebridge's routing script, in the image built from `routing/Dockerfile`, running as a sidecar. Installs and keeps the rules and routes below, and reports when they are all in place. |
| `netbird` | The NetBird peer, started through the gate (`routing/wait-for-guards`), which waits for the guard and then supervises NetBird. |

Gluetun deletes and recreates its tunnel interface on every reconnect, and the
kernel drops the routes through it. The guard therefore keeps running. It
installs the rules once, then every `ROUTING_RECONCILE_INTERVAL` seconds (2 by
default) puts back the exit table's tunnel route, refreshes the host table,
and adds, repairs or removes rules until the set is exactly the expected one.
[Architecture](architecture.md#the-reconcile-loop) describes the loop.

### The rules

The guard owns priorities 0 to 97 and 102 to 104 in this namespace, in both
IPv4 and IPv6, and removes anything else at those priorities. Gluetun's rules
98 to 101 and NetBird's 105 and 110 are left alone. Do not add your own rules
at the guard's priorities. In the table, `<tunnel>` is gluetun's tunnel
interface (`EXIT_IF`), `<overlay>` is your NetBird peer range
(`OVERLAY_CIDR`, and `OVERLAY6_CIDR` for IPv6), `<exit table>` is table 51821
(`EXIT_TABLE`) and `<host table>` is table 51822 (`HOST_TABLE`).

| Priority | Rule | Reason |
|---|---|---|
| 1 | `not iif wt0 lookup local` | Local-delivery guard. It replaces the kernel's priority-0 `lookup local`. A packet arriving on `wt0` never consults the local table, so overlay traffic is never delivered to a process on the exit. Loopback and every other interface keep local delivery. |
| 80 | `iif wt0 unreachable` | Temporary. Blocks forwarding while the guard installs the other rules, then is removed. |
| 88 | `iif lo fwmark 0x1bd00/0xffffffff lookup <host table>` | NetBird's control traffic. The exact mark and `iif lo` mean a forwarded packet that carries one of NetBird's other marks never matches. |
| 89 | `iif lo fwmark 0x1bd00/0xffffffff unreachable` | Terminal for control traffic. If the host table has no route, the connection fails instead of falling to gluetun's rule 101 and the tunnel. |
| 90 | `iif <tunnel> to <overlay> lookup main` | Replies from the tunnel go back to the overlay. Client-originated traffic cannot use it. |
| 91 | `iif lo to <overlay> lookup main suppress_prefixlength 0` | What the exit itself sends to the overlay, above all the ICMP errors it returns to clients, uses NetBird's overlay route in the main table and never main's default route. |
| 92 | `iif lo to <overlay> unreachable` | With no overlay route (NetBird down), that traffic fails here instead of reaching rule 101 and the tunnel. |
| 94 | `from <tunnel address> ipproto icmp lookup <exit table>` | ICMP errors the exit generates for tunnel traffic return through the tunnel. IPv6 uses `ipproto ipv6-icmp`. It exists for a family in which the tunnel interface has an address. |
| 95 | `iif wt0 lookup <exit table>` | Forwarded traffic uses the exit table. |
| 96 | `oif <tunnel> lookup <exit table>` | Probes bound to the tunnel interface use the same table. |
| 97 | `iif wt0 unreachable` | Terminal guard if rule 95 or every exit-table route disappears. |
| 102 | `iif lo fwmark 0xca6c lookup main` | Gluetun's own WireGuard socket carries mark 51820 (`0xca6c`), which rule 101 skips. It reaches the provider's server by the main table. |
| 103 | `iif lo lookup <host table> suppress_prefixlength 0` | The host interface's own subnets (the host table's on-link routes, never its default). Gluetun needs them at start: it adds `default via <gateway> dev eth0 table 200` before its own rule 98 exists, and without rule 103 the kernel refused that route as "network is unreachable" and gluetun stopped. |
| 104 | `iif lo unreachable` | The exit's own kill switch. Anything the exit itself sends that rule 101 did not take into the tunnel fails here, instead of using the host's default route while gluetun reconnects. The guard adds it only after rule 103 and the host table are in place. |

Rules 90 to 92 exist for a family that has an overlay range. The mark `0x1bd00`
is `CONTROL_MARK`; gluetun's mark 51820 is fixed in gluetun v3.41.3.

| Table | Contents | Reason |
|---|---|---|
| Host table (51822) | Copies of the main table's default and on-link routes through the host interface (`HOST_IF`, `eth0` on Docker), and nothing else. Never a route through the tunnel. IPv4 needs a default among them. | Gives rules 88 and 103 a route that does not depend on the main table being complete. |
| Exit table (51821) | `unreachable default metric 4096`, always, plus `default dev <tunnel>` while the tunnel interface is up with an address in that family. Nothing else. | Without the tunnel route, forwarded traffic hits the unreachable route. It does not reach the host's default route. |

The exit table is not gluetun's table 51820. An empty 51820 would let packets
fall through to later rules instead of the fallback.

[Architecture](architecture.md#gluetun-backend) explains each rule in more
detail. `routing/10-exit-routing` is the guard, and `routing/gluetun-rules`
defines the expected set for both the guard and the gate. Typing the rules by
hand is not a substitute: the tunnel route has to come back every time gluetun
recreates its interface, and that is the guard's loop.

### The gate

`routing/wait-for-guards` is the entrypoint of the `netbird` container
(`TUNNEL_BACKEND=gluetun`). Rules 88 and 89 only see packets that carry
NetBird's mark. If NetBird runs without it, its control traffic is unmarked and
reaches gluetun's rule 101. The gate therefore does four things.

1. **It refuses to start NetBird with settings that cannot work here.** It
   exits with status 1 and one line, `NetBird gate: refusing to start NetBird:
   <reason> (see docs/troubleshooting.md)`. The reasons are:
   `NB_FORCE_USERSPACE_FIREWALL`, `NB_FORCE_USERSPACE_ROUTER`,
   `NB_USE_NETSTACK_MODE` or `NB_WG_KERNEL_DISABLED` set to true;
   `NB_DISABLE_USERSPACE_ROUTING` not `true`; `NB_USE_LEGACY_ROUTING`,
   `NB_SKIP_SOCKET_MARK` or `NB_DISABLE_CUSTOM_ROUTING` set to true;
   `NB_FWMARK_BASE` different from `CONTROL_MARK`; Rosenpass enabled, in the
   environment or in the stored profile; foreground mode; `NB_CONFIG`,
   `WT_CONFIG`, `NB_PROFILE` or `WT_PROFILE` set; a stored profile that names
   another interface than `wt0`; and any setting the guard itself would reject
   (`OVERLAY_CIDR`, `EXIT_IF`, the tables, `CONTROL_MARK`). Check without
   starting NetBird:

   ```sh
   docker compose exec netbird sh /usr/local/bin/molebridge-wait-for-guards --check-config
   ```

   It prints `NetBird gate: configuration accepted` or the refusal.
2. **It waits for the whole guard**, in both families, and logs `NetBird gate:
   gluetun backend: waiting for the whole guard (rules 1-97 with control mark
   0x1bd00, exit table 51821, host table 51822)`. "Whole" means every rule in
   the table above that applies, exactly, and nothing else at priorities 0 to
   97 or 102 to 104; the exit table's fallback and no other route in it than
   the tunnel default; and a host table equal to the main table's host routes,
   with an IPv4 default. The gate uses the same definitions as the guard
   (`routing/gluetun-rules`). Every 30 seconds of waiting it says what is still
   missing. It runs again on every start of the container, including after a
   daemon or host restart that ignores `depends_on`.
3. **It stays in front of NetBird instead of handing over.** It logs `NetBird
   gate: NetBird started; watching its log and wt0's fwmark` and supervises
   NetBird as its child.
4. **It stops NetBird**, logging `NetBird gate: stopping NetBird: <reason> (see
   docs/troubleshooting.md)` and exiting with status 1, so the restart policy
   brings the container back, when:
   - NetBird's log shows `advanced routing has been requested to be disabled`
     or `falling back to legacy routing`;
   - `wg show wt0 fwmark` has not been the control mark for 30 seconds,
     counted from launch or from the last good record (the guard writes the
     record every 2 seconds; `FWMARK_GRACE` can shorten the 30 seconds to as
     little as 5);
   - any part of the guard stays missing or wrong for 30 seconds.

NetBird can sign in to management before its overlay interface exists, so the
gate cannot wait for the fwmark before launching. If NetBird's own start-up
capability check fails, its TLS and relay connections go through the provider
tunnel for up to 30 seconds, until the gate sees the log line or the missing
fwmark. That is a metadata and availability cost for NetBird's control
traffic. It does not let your devices' traffic out: rules 1, 95 and 97 hold
forwarded traffic throughout.

## Requirements

- **Linux with kernel WireGuard** (5.6 or later, or an older kernel with the
  module installed), on an always-on host. The setup asks gluetun for the
  kernel implementation (`WIREGUARD_IMPLEMENTATION=kernelspace`), which fails
  instead of falling back to a userspace tunnel. It was tried on a 7.0 kernel
  in OrbStack's VM on macOS and nowhere else.
- **Docker with Compose 2.24 or later.** Rootless Podman with podman-compose
  is untested for this setup ([below](#rootless-podman)). Molebridge's own
  stack is tested as described in [requirements](prerequisites.md#host).
- **Python 3.10 or later on the host**, for two small helpers in
  `tools/molebridge.py` that write gluetun's role file and post-rules.
- **NetBird client 0.79.0**, the version this setup pins, and a NetBird
  account with admin access, either NetBird Cloud or self-hosted (only a
  self-hosted server has been tried). You need the groups, the policy, a
  setup key and the exit route. The steps are the same as for Molebridge;
  follow the [NetBird section of the requirements](prerequisites.md#netbird)
  and [setup step 8](setup.md#8-create-the-route-and-try-a-device), and do not
  skip the group rules: the exit peer is never in `exit-users`, and the exit
  route is never distributed to `All`.
- **A WireGuard account at a provider gluetun supports**, with the private key
  (and the tunnel address, if the provider assigns one) that gluetun's
  documentation for that provider asks for. Only NordVPN has been tried.

## Set up

These steps use `compose.gluetun.yaml` from the Molebridge repository and start
only three of its services, `gluetun`, `guard` and `netbird`. The applier and
the control panel in that file are not started and need nothing from you. The
file is the one place the container definitions live, so it is not copied here;
read it before you start.

1. **Get the code.** The gluetun files are `compose.gluetun.yaml`, `routing/`
   and `tools/molebridge.py`. Check out a release or commit that contains
   `compose.gluetun.yaml`, rather than whatever `main` happens to be:

   ```sh
   git clone https://github.com/irashack/molebridge.git
   cd molebridge
   ls compose.gluetun.yaml routing/gluetun-rules
   cp .env.example .env
   mkdir -p secrets/gluetun
   chmod 700 secrets secrets/gluetun
   ```

2. **Edit `.env`.** For this setup:

   | Setting | Value |
   |---|---|
   | `COMPOSE_FILE` | `compose.gluetun.yaml` |
   | `EXIT_IF` | `wg0`: the name gluetun gives its tunnel (`VPN_INTERFACE`). Letters, digits and underscores only. The guard and NetBird's ICE blacklist use the same value |
   | `OVERLAY_CIDR` | Your NetBird peer range, `100.64.0.0/10` for NetBird's default |
   | `OVERLAY6_CIDR` | Your NetBird IPv6 range, if you have one |
   | `GLUETUN_PROVIDER` | gluetun's `VPN_SERVICE_PROVIDER`, such as `nordvpn` |
   | `GLUETUN_WIREGUARD_ADDRESSES` | The tunnel address your provider assigned, if it needs one. NordVPN does not |
   | `GLUETUN_SERVER_COUNTRIES` | Your own country, as gluetun names it. See [the first start](#the-first-start) |
   | `NB_HOSTNAME`, `NB_MANAGEMENT_URL` | The peer's name, and your management URL if you self-host NetBird |
   | `HOST_IF` | `eth0` on Docker |

   [Configuration](configuration.md#gluetun-backend) lists every setting. The
   panel and applier settings in `.env.example` have no effect on these three
   services.

3. **Put the provider's WireGuard private key in a file.** Open it in an
   editor, so the key never lands in shell history. It holds one line:

   ```sh
   (umask 077 && ${EDITOR:-vi} secrets/gluetun/wireguard_private_key)
   ```

4. **Write gluetun's role file.** Without a role file, gluetun's control server
   applies a public default role that includes a route that stops the VPN.
   `compose.gluetun.yaml` therefore refuses to start gluetun without the file:

   ```sh
   python3 tools/molebridge.py gluetun-auth
   ```

   It writes `secrets/gluetun/auth.toml` and `secrets/gluetun/api_key`, both
   mode 0600, from one generated key, and never prints the key. The role it
   defines allows five routes: `PUT /v1/vpn/settings`, `GET /v1/vpn/status`,
   `GET /v1/publicip/ip`, and `GET` and `PUT /v1/updater/status`. This setup
   uses `api_key` only if you do
   ([Choosing and switching servers](#choosing-and-switching-servers)).

5. **Write gluetun's post-rules** from your settings, and read the result:

   ```sh
   python3 tools/molebridge.py gluetun-post-rules
   cat tunnel/gluetun/post-rules.txt
   ```

   Add `--ipv4-only` if gluetun later logs that it found no working
   `ip6tables`. [Post-rules](#post-rules-for-gluetuns-firewall) explains the
   lines.

6. **Add the NetBird setup key** to `secrets/netbird.env`, as one line,
   `NB_SETUP_KEY=` followed by the key. Create the file in an editor:

   ```sh
   (umask 077 && ${EDITOR:-vi} secrets/netbird.env)
   ```

7. **Build the guard and start the three services:**

   ```sh
   docker compose build guard
   docker compose up -d gluetun guard netbird
   docker compose ps
   docker compose logs guard
   ```

   The guard's log should reach `10-exit-routing: every rule and route in place
   (1/88/89/90/91/92/94/95/96/97/102/103/104, exit table 51821, host table
   51822)`. `netbird` starts once `guard` is healthy. If the gate refuses, its
   message names the setting; see [troubleshooting](troubleshooting.md#startup).

8. **Check that the peer is in NetBird** under `NB_HOSTNAME`, in `exit-nodes`,
   then delete `secrets/netbird.env`. The peer's identity now lives in the
   `netbird-data` volume; never run `down -v`. Revoke the setup key if it was
   reusable.
9. **Run the [checks](#verification) before any device selects the exit.** Then
   create the exit-node route as the requirements describe, and try one device.

`NB_EXTRA_IFACE_BLACKLIST` (the tunnel interface) and `NB_WIREGUARD_PORT` take
effect when the peer first enrolls. They are stored in the peer's profile in
the `netbird-data` volume, and changing the environment variable later does not
change them. To change them on an enrolled peer, run `docker compose exec
netbird netbird down`, then `netbird up` with `--extra-iface-blacklist wg0` or
`--wireguard-port` ([setup step 5](setup.md#5-keep-ice-off-the-tunnel-interface)).
Without the blacklist, clients are relayed and the tunnel's address can be
offered to other peers.

### If you already run gluetun

You can add the guard and NetBird to a gluetun you have, instead of using
`compose.gluetun.yaml`. Copy what that file does:

- `VPN_TYPE=wireguard`, `WIREGUARD_IMPLEMENTATION=kernelspace`, and
  `VPN_INTERFACE` set to the name you use as `EXIT_IF` everywhere. Gluetun
  accepts letters, digits and underscores only, and its own default is `tun0`.
- The sysctls on the gluetun service: `net.ipv4.ip_forward=1`,
  `net.ipv6.conf.all.forwarding=1`, `net.ipv4.icmp_errors_use_inbound_ifaddr=1`,
  and `net.ipv6.conf.all.disable_ipv6=0` with the same for `default`. The
  third makes the exit's ICMP errors for tunnel traffic carry the tunnel
  address, so rule 94 returns them through the tunnel. The guard warns
  (`net.ipv4.icmp_errors_use_inbound_ifaddr is not 1`) when it is missing.
- `FIREWALL_INPUT_PORTS` set to NetBird's WireGuard port (`NB_WIREGUARD_PORT`,
  51820 by default).
- The control server on `127.0.0.1:8000` only
  (`HTTP_CONTROL_SERVER_ADDRESS`), with a role file
  (`HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH`). Its default address, `:8000`,
  listens on every interface in the namespace. No `ports:` entry for it.
- The post-rules file mounted at `/iptables/post-rules.txt`, and the key from
  `WIREGUARD_PRIVATE_KEY_SECRETFILE` (a file, never the environment).
- Gluetun pinned as `compose.gluetun.yaml` pins it. The design was read against
  that release's source; another release may differ.
- The `guard` and `netbird` services as defined in that file, with
  `network_mode: service:gluetun`. Their environment must agree: both read
  `OVERLAY_CIDR`, `OVERLAY6_CIDR`, `EXIT_IF`, `EXIT_TABLE`, `HOST_IF`,
  `HOST_TABLE` and `CONTROL_MARK`.

## Gluetun's settings

What `compose.gluetun.yaml` sets on gluetun, and why:

| Setting | Value | Why |
|---|---|---|
| Image | `docker.io/qmcgaw/gluetun:v3.41.3@sha256:fa19cc76b2af13d57a8d3dc3066f2ada061b1c761b8aecf989b3877c0486e027` | Pinned by digest. Update deliberately. |
| `VPN_TYPE` | `wireguard` | The only type the guard covers. |
| `WIREGUARD_IMPLEMENTATION` | `kernelspace` | Gluetun's values are `auto`, `userspace` and `kernelspace`; this one fails instead of falling back to a userspace tunnel. |
| `VPN_INTERFACE` | `EXIT_IF` | The guard and NetBird's ICE blacklist must name the same interface. |
| `WIREGUARD_PRIVATE_KEY_SECRETFILE` | `/run/secrets/wireguard_private_key` | The key is read from a file bind-mounted from `secrets/gluetun/wireguard_private_key`, never from the environment. |
| `HTTP_CONTROL_SERVER_ADDRESS` | `127.0.0.1:8000` | Namespace loopback only, never published. |
| `HTTP_CONTROL_SERVER_AUTH_CONFIG_FILEPATH` | `/gluetun/auth/config.toml` | The role file from `gluetun-auth`. With any role in it, gluetun answers no other route. |
| `FIREWALL_INPUT_PORTS` | `NB_WIREGUARD_PORT` | Opens NetBird's WireGuard port in gluetun's `INPUT` chain. |
| `UPDATER_PERIOD` | `24h` | How often gluetun refreshes its server list. |
| `SERVER_COUNTRIES`, `SERVER_CITIES`, `SERVER_HOSTNAMES` | From `.env` | The server gluetun starts with. |

The file also sets `STORAGE_FILEPATH` so the applier can read gluetun's server
list; you do not need it without the applier.

**The control server's key is full gluetun administration.** Gluetun authorizes
by route and method only, and `PUT /v1/vpn/settings` accepts any VPN setting:
keys, addresses, the provider, command hooks. Keep `secrets/gluetun/api_key`
mode 0600, mount it nowhere, and read it only to use the control server
yourself.

## Post-rules for gluetun's firewall

Gluetun enables its firewall once, at startup, and then runs the commands in
`/iptables/post-rules.txt`. `python3 tools/molebridge.py gluetun-post-rules`
writes them from your settings. With the defaults they are:

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
the guard: policy routing is.

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
  `NB_WIREGUARD_PORT`, and recreate the three containers.
- If you write your own lines, use only what gluetun's parser reads: no mark
  match and no jump to a custom chain.

## The first start

Set `GLUETUN_SERVER_COUNTRIES` to your own country, as gluetun names it
(`Netherlands`, `United States`), and leave the city and hostname empty.
Gluetun's built-in server list is old (for NordVPN in v3.41.3 it dates from
2024), and gluetun refreshes it only after one `UPDATER_PERIOD`, not at start.
A hostname or city missing from the built-in list stops gluetun at start
(`the hostname specified is not valid`, or the same for a city or country).
A whole country is unlikely to be gone, and a nearby one answers best. With the
filter empty, gluetun picks among every country's servers.

On the first start gluetun may restart its VPN several times before it
connects, because it picks servers from the old list that no longer answer.
Gluetun refreshes the list by itself one `UPDATER_PERIOD` (24 hours) after it
starts, or sooner if you trigger it
([below](#choosing-and-switching-servers)).

## Choosing and switching servers

Without the applier, nothing selects servers for you, and nothing watches
whether the one you selected works.

**Through `.env` and a restart.** Set `GLUETUN_SERVER_COUNTRIES`,
`GLUETUN_SERVER_CITIES` or `GLUETUN_SERVER_HOSTNAMES` (comma-separated values),
then recreate all three containers. A restart of `gluetun` alone leaves `guard`
and `netbird` in its old namespace:

```sh
docker compose up -d --force-recreate gluetun guard netbird
```

Connections open through the exit drop. A hostname must be in the data gluetun
has when it starts.

**Through gluetun's control server.** Gluetun then restarts its VPN in-process,
so the namespace stays and the guard puts the exit route back within a couple
of seconds. The role file from `gluetun-auth` already allows what is needed,
and the key is in `secrets/gluetun/api_key`. The control server listens
only inside the namespace, so run `curl` from a throwaway container that joins
it, with the key in a header file so it never appears in a command line (use
any image that ships `curl`):

```sh
(umask 077 && printf 'X-API-Key: %s\n' "$(cat secrets/gluetun/api_key)" > secrets/gluetun/api_header)
docker run --rm --network container:molebridge-gluetun \
  -v "$PWD/secrets/gluetun/api_header:/header:ro" <image-with-curl> \
  curl -fsS -H @/header http://127.0.0.1:8000/v1/vpn/status
```

Replace `molebridge-gluetun` with `<COMPOSE_PROJECT_NAME>-gluetun` if you
changed the project name. To select a server, send `PUT /v1/vpn/settings` with a
body that sets one filter and clears the others. The applier sends exactly this,
here for a hostname:

```json
{"provider":{"server_selection":{"hostnames":["<hostname>"],"countries":[],"regions":[],"cities":[],"names":[],"numbers":[],"categories":[],"isps":[],"owned_only":false,"free_only":false,"premium_only":false,"stream_only":false,"multi_hop_only":false,"port_forward_only":false,"secure_core_only":false,"tor_only":false}}}
```

Save it as `secrets/gluetun/select.json`, mount it with a second `-v`, and add
`-X PUT -H 'Content-Type: application/json' -d @/select.json` to the `curl`
command. To refresh gluetun's server list now, once the tunnel works, send
`PUT /v1/updater/status` with the body `{"status":"running"}`; gluetun fetches
the provider's list through the tunnel. Delete `api_header` and `select.json`
when you are done. Settings put this way are lost when gluetun restarts, which
starts again from the values in `.env`.

**NordVPN.** Avoid dedicated-IP and Double VPN servers, and Onion Over VPN and
obfuscated ones too: a plain subscription cannot use them, and Molebridge's
panel does not list them. Gluetun stores the category of each server
(`Standard VPN servers`, `Dedicated IP`, `Double VPN`, `Onion Over VPN`,
`Obfuscated Servers`). Molebridge's rule is a server in the standard category
and in none of the others, so pick a hostname you know is in NordVPN's standard
list. A country filter alone does not exclude the others. Gluetun's
`SERVER_CATEGORIES` setting selects by category, but `compose.gluetun.yaml`
does not pass it through; you would add it to the gluetun service in a
`compose.override.yaml`. That has not been tried.

**Checking the result.** Nothing reports it. Check the exit address as
[Verification](#verification) check 4 does, and compare it with your
provider's own check page.

## Keep these off for the exit peer

Rosenpass, NetBird SSH, DNS nameservers and domain routes are not supported
on the exit peer.

- **Rosenpass.** Its key exchange needs local delivery from the overlay, which
  the guard refuses. The gate refuses to start NetBird with it on.
- **NetBird SSH.** It doesn't work on the exit peer.
- **DNS nameservers and domain routes served by the exit.** The exit doesn't
  answer anything addressed to itself that arrives over NetBird, so a NetBird
  nameserver group served by the exit cannot work. Point NetBird's nameservers
  at something else.

These features don't work on the exit peer whether or not you follow this
list. The list is about not leaving on a feature that cannot work.

## Verification

Run these on your own host before you rely on the exit, and again after you
change routing, the gluetun settings or the compose file. The checks in
[verification](verification.md) apply with the names changed: where it says
`wireguard` or `applier`, use `guard` (it has `ip`, `wg` and a shell in the
namespace), and `wg0` where it says `mullvad`. In particular the [client and
LAN isolation checks](verification.md#from-a-client) and a host reboot with
unattended recovery apply as written. The commands below are the checks that
need no applier. None of them has been run in the applier-less form.

Keep an independent way into the host. Do not paste raw addresses from these
outputs into a report. Never run `wg showconf` or print a key.

### Before any drill

1. **Rules and routes.**

   ```sh
   docker compose exec guard ip rule show
   docker compose exec guard ip -6 rule show
   docker compose exec guard ip route show table 51821
   docker compose exec guard ip -6 route show table 51821
   docker compose exec guard ip route show table 51822
   ```

   The IPv4 rules should list 1, 88, 89, 90, 91, 92, 94, 95, 96, 97, 102, 103
   and 104, with gluetun's 98 to 101 (and NetBird's 105 and 110 once it is up)
   between them, and no rule 0 and no rule 80. Rule 1 reads like `1: not from
   all iif wt0 lookup local`. The exit table shows `default dev wg0` and
   `unreachable default ... metric 4096`. With an IPv4-only tunnel such as
   NordVPN's, the IPv6 exit table has only the unreachable route, and IPv6 has
   no rule 94. IPv6 has rules 90 to 92 only if you set `OVERLAY6_CIDR`.
2. **NetBird's marking.**

   ```sh
   docker compose exec guard wg show wt0 fwmark
   ```

   It must print `0x1bd00`. Anything else, including `0` or `off`, means
   NetBird's control traffic is unmarked and can enter the tunnel. The gate
   stops NetBird after 30 seconds of that; find out why before going on.
3. **Kernel WireGuard.** `docker compose exec guard ip -d link show wt0` shows
   `wireguard` on its details line. The gate also refuses the settings that
   switch kernel WireGuard and NetBird's kernel firewall off
   ([the gate](#the-gate)).
4. **Egress through the tunnel.** From the namespace, an unmarked request goes
   through gluetun's rule 101 into the tunnel. Use any image that ships
   `curl`, and a service you trust:

   ```sh
   docker run --rm --network container:molebridge-gluetun <image-with-curl> \
     curl -fsS https://<ip-echo-service>
   ```

   The address should be your provider's, not your host's public address.
   Compare it with your provider's own check page, and run the same from your
   host without the container to see the difference. For NordVPN,
   `https://api.nordvpn.com/v1/helpers/ips/insights` reports `protected`.

### Drills

For each drill, keep a client on the exit pinging a public address you can test
with (`<probe-ip>`). During the drill the probe must fail. It must not succeed
using your host's public address. With a tunnel that has IPv6, test both
families. Run the capture below in a second terminal, so you see what appears
on the host interface.

**The capture.** It watches the host interface inside the namespace for the
probe address. Use any image that ships `tcpdump`. The container joins
gluetun's namespace, so the command is the same on Linux and on Docker with a
VM, such as OrbStack:

```sh
docker run --rm --network container:molebridge-gluetun \
  --cap-add NET_ADMIN --cap-add NET_RAW <image-with-tcpdump> \
  tcpdump -ni eth0 "host <probe-ip>"
```

This must print nothing for the whole drill, including the time between the
break and the reconnect. A packet here means a client's traffic left the
namespace by the host's route. The same with `podman run` under rootless Podman
has not been tried. To see what the host interface does carry, use a broader
filter: you should see NetBird's WireGuard port, STUN and its TCP control
connections, and gluetun's transport to the provider endpoint. Anything else
needs an explanation.

Keep those breaks short: while `guard` is stopped its marking records go stale,
and after 30 seconds the gate stops NetBird (it comes back with the guard).

The guard restores a deleted rule or route within `ROUTING_RECONCILE_INTERVAL`
seconds, so the second and third drills stop it first and make the change from
a one-off container that runs `ip` in the same namespace (`docker compose run`
with `--no-deps` and `--entrypoint ip`):

| Drill | Break | Expect | Restore |
|---|---|---|---|
| Tunnel down | `docker compose exec guard ip link set wg0 down` | The probe fails. Nothing in the capture. | In the test, gluetun did not bring a downed interface back by itself within several minutes, so recreate: `docker compose up -d --force-recreate gluetun guard netbird` |
| Exit-table route deleted | `docker compose stop guard`, then `docker compose run --rm --no-deps --entrypoint ip guard route del default dev wg0 table 51821` | The probe fails. | `docker compose up -d guard` |
| Lookup rule deleted | `docker compose stop guard`, then `docker compose run --rm --no-deps --entrypoint ip guard rule del priority 95` (and `ip -6` for IPv6) | The probe fails on terminal rule 97. | `docker compose up -d guard` |
| Gluetun recreated | `docker compose up -d --force-recreate gluetun guard netbird` | The probe fails until all three are back. Nothing in the capture. | The command is the restore |
| NetBird restarted | `docker compose restart netbird` | The probe fails while the peer is down. After it returns, `wg show wt0 fwmark` prints `0x1bd00`. | The command is the restore |

The first drill depends on how gluetun reacts when its interface goes down. In
the test on 2026-10-08, with the applier present, the tunnel-down drill held:
no client traffic and none of gluetun's own flows left the host interface. How
long the reconnect took was not recorded. After each restore, repeat check 4;
after the recreation, repeat checks 1 and 2.

### Local delivery

A packet that arrives on `wt0` must never reach a process on the exit. Start a
listener inside the namespace, then connect to it from a device on the exit:

```sh
docker compose exec guard nc -l -p 8099
```

From the device, with the exit's overlay address in place of
`<exit-overlay-address>`:

```sh
nc -vz -w 3 <exit-overlay-address> 8099
```

The connection must time out or fail. Stop the listener afterward. If it
connects, rule 1 is missing or something sits ahead of it; check `ip rule
show` before anything else. A ping to the exit's own overlay address gets no
reply for the same reason, although the access policy allows ICMP.

## Rootless Podman

Untested for this setup. A rootless engine puts the namespace on a private
network, so NetBird's only host candidate is an address nothing outside the
host can reach. Devices on your LAN still connect directly, but devices
elsewhere fall back to a relay without any error. The method that worked for
Molebridge's own stack is pasta's port forwarding on the container that owns
the namespace; in this setup that container is `gluetun`. Do not publish
NetBird's port with `ports:`: it holds the host port, so NetBird's outgoing STUN
cannot use it.

[Exits on a private container network](operations.md#exits-on-a-private-container-network)
has the problem, the `network_mode: "pasta:..."` option string and the
`netbird up --wireguard-port ... --external-ip-map ...` step, written for the
`wireguard` service. Put the `network_mode` on `gluetun` instead, keep NetBird's
port in `FIREWALL_INPUT_PORTS`, and set `HOST_IF` to the interface name inside
the namespace (`eth0` with the option string there, which sets `-I eth0`).
Gluetun's control server stays unpublished. `gluetun-auth` and
`gluetun-post-rules` do not call the container engine, so they work as
written. The helpers `doctor` and `recover` need `docker compose`.

## DNS inside the namespace

Containers that join gluetun's namespace, `netbird` included, resolve names
through gluetun's own DNS server on 127.0.0.1, which forwards through the
tunnel. While the tunnel is down, NetBird cannot look up its management, signal
or relay hostnames; connections it already has carry on, and new lookups work
again once gluetun reconnects. This was observed in the test; nothing leaves
outside the tunnel because of it.

## Client notes

- **Hotel and other restrictive Wi-Fi.** A healthy exit can still leave a
  device at Connecting on a network that breaks long-lived UDP flows. NetBird's
  relay prefers QUIC, which connects and then dies there, and the client falls
  back to WebSocket only when QUIC cannot connect. That is NetBird's behavior,
  not the exit's.
  [Troubleshooting](troubleshooting.md#clients) has the setting that makes a
  desktop client prefer WebSocket.
- **DNS leak tests.** Neither gluetun nor the guard changes your devices' DNS,
  and the exit cannot serve a nameserver. [DNS](operations.md#dns) says what a
  leak test shows with Mullvad. Nothing is recorded for gluetun or NordVPN.
- **Phones.** Turn off *Force relay connection* in the NetBird app (Settings,
  then Advanced). It is on by default and routes all exit traffic through a
  NetBird relay.
- **Relayed clients.** If `netbird status -d` shows `Relayed` for devices that
  should be direct, see [clients are relayed](troubleshooting.md#clients).

## If something goes wrong

[Troubleshooting](troubleshooting.md#startup) covers the gate's refusals and
stops, a guard that is not ready, and gluetun refusing to start with a server it
does not know. Gluetun's own log (`docker compose logs gluetun`) says why it
could not connect.

---

Gluetun is a separate project under its own license and maintainers. Molebridge
isn't affiliated with it, and its name is used only to say what this page
describes.
