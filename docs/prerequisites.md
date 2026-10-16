# Requirements

Everything here is needed before [setup](setup.md). Where something has only
been tested in one configuration, this page says so. [Testing](testing.md#080)
is the record of what ran live at 0.8.0; "tested" statements below that name
an earlier release are about that release. The sidecar forms ([gluetun](gluetun-sidecar.md)
and [native](native-sidecar.md), the latter new in 0.9.0 and run live with PIA on Kubernetes only)
need no NetBird account: read the host, runtime and network parts, and skip
[NetBird](#netbird).

## Host

- **An always-on machine.** When it's off, devices using the exit lose their
  Internet connection until they deselect it.
- **Linux with kernel WireGuard** (5.6 or later, or an older kernel with the
  module installed). Molebridge uses the kernel implementation only; there is
  no userspace fallback.
- **nftables in the kernel** (`nf_tables`, which current distribution kernels
  include). The image has no iptables, so NetBird uses its nftables firewall,
  and the exit's own PIA port-forwarding rules are nftables too. A
  [native sidecar](native-sidecar.md#the-firewall) installs its whole firewall
  in nftables, with the `inet` family and the `meta mark` and `ct state` matches. The exit
  fails its `netbird` check without NetBird's firewall in place. On the
  0.8.0 live host NetBird created its `netbird` tables in nftables, as
  intended ([testing](testing.md#live-pass-on-rootless-podman-with-quadlet)).
- **Docker Engine with Compose 2.24 or later, or rootless Podman with
  podman-compose.** The Compose files use `env_file` entries with
  `required: false` and bind mounts that must exist, which older Compose
  versions don't read.

| Runtime | Status |
|---|---|
| Debian testing, amd64, rootless Podman 5.8 with Quadlet units | Tested at 0.8.0: upgrade from 0.7.0 of native Mullvad, PIA and NordVPN exits and of NordVPN through gluetun (overlay exit and sidecar), and live drills from the native exits' namespaces ([testing](testing.md#live-pass-on-rootless-podman-with-quadlet)). This repository ships no Quadlet units. No client device was held on an exit at 0.8.0; one was at 0.7.0, on the same host and setup ([testing](testing.md#070-on-rootless-podman-at-d5a234a)) |
| Debian 13, amd64, rootless Podman 5.4 with podman-compose 1.6 | Tested on 2026-09-24 at `5a6e0b5` (in v0.1.0), the only podman-compose pass: long-running, reboot, clean install, drills with a client ([testing](testing.md#live-client-and-reboot-pass-at-5a6e0b5)). The 0.8.0 Compose files have not run on it |
| macOS with OrbStack, Apple silicon | Tested in earlier passes, the last on 2026-10-08, before 0.7.0 |
| Other Linux with Docker Engine and Compose 2.24+ | Expected to work; not tested at any version |
| Docker Desktop | Untested |
| arm64 Linux | The image is built and checked for arm64 in CI and the namespace drills passed on an arm64 VM; no live exit has run on arm64 |
| Windows | Not supported |
| A Kubernetes node, for the [native sidecar](native-sidecar.md#kubernetes) | Kubernetes 1.29 or later (sidecar containers); `wireguard` loadable on the node. Not yet run live ([testing](testing.md#090)) |

- **amd64 or arm64.** The image is a multi-architecture index; the Compose
  files pin it by digest.
- **No Python on the host.** The setup and repair tools run from the same
  image as throwaway containers ([tools reference](tools-reference.md)). The
  Python 3.10 requirement of 0.7 is gone. You do need `cosign` and the GitHub
  CLI (`gh`) once, to [verify the download](setup.md#1-download-and-verify),
  and `jq` for the acceptance check. Nothing is built locally unless you choose
  to ([CONTRIBUTING](../CONTRIBUTING.md#building-the-image)).
- **Resources.** Measured at 0.8.0 on the rootless Podman host, for exits
  with no client traffic ([testing](testing.md#resources-at-080-on-rootless-podman)):
  a Mullvad or PIA exit, NetBird included, used 0.3 to 0.5 % of one core and
  67 to 78 MB; a NordVPN exit 189 MB; a gluetun exit 123 MB; Switchyard
  27 MB. The image is 61 MB unpacked. NordVPN's and gluetun's server lists
  are large and Go keeps much of the heap that parses them. For comparison,
  0.7.0 measured on the same host ([testing](testing.md#resources-at-070-on-rootless-podman)):
  a Mullvad exit with its panel used 6 to 8 % of one core and about 100 MB
  in four containers, most of the processor time the routing container's
  repair pass every 2 seconds and NetBird, and its images took about 260 MB.
  0.8.0 runs no such pass: a netlink event triggers the repair, and the full
  pass is a fallback every `ROUTING_RECONCILE_INTERVAL` seconds (30 by
  default). The Compose files limit the exit container to 512 MiB and the
  panel to 128 MiB. The exit's limit is NordVPN's: its server list is about
  8 MB of JSON, downloaded and parsed every six hours and capped at 32 MiB,
  and a list near the cap takes about 300 MB to parse. It is a ceiling, not a
  reservation.
- **Upload bandwidth.** Every device's traffic crosses the host twice, in from
  the device and out to the provider. The host's upload speed is the ceiling
  for everyone using the exit.

### Rootless Podman

Three things differ from Docker:

1. **The kernel modules must already be loaded.** A rootless container can't
   load `wireguard`. Load it now and at every boot:

   ```sh
   sudo modprobe wireguard
   echo wireguard | sudo tee /etc/modules-load.d/wireguard.conf
   ```

   Check that `nf_tables` is loaded too (`lsmod | grep nf_tables`). Hosts that
   use nftables for their own firewall already have it.

2. **Set `PANEL_USER=0:0` and `PANEL_ALLOW_ROOT=1`.** Rootless Podman maps
   container root to your own user, so that's the user that can read the state
   directory. The panel still runs with no capabilities, and it refuses to run
   as uid 0 unless `PANEL_ALLOW_ROOT=1` says you mean it
   ([the panel's isolation check](configuration.md#the-panels-isolation-check)).
3. **NET_RAW is not granted by default.** The Compose files add it; an
   override that drops it makes NetBird fail with `failed to create ipv4 raw
   socket: operation not permitted`.

For containers to start at boot you also need a lingering systemd user unit,
shown in [operations](operations.md#rootless-podman).

## Network

The exit needs these outbound connections. It needs no inbound ports unless
you want direct NetBird connections from a rootless or bridged setup (see
[operations](operations.md#exits-on-a-private-container-network)).

| To | Why |
|---|---|
| `ghcr.io` | Pulling the image, once, and again for each upgrade |
| Sigstore's public services, GitHub's API and release assets | Verifying the download once ([setup](setup.md#1-download-and-verify)); needed on the machine you verify from, not on the exit |
| Your NetBird management, signal and relay servers, and STUN | The exit peer; see NetBird's [firewall requirements](https://docs.netbird.io/about-netbird/faq#what-firewall-ports-should-i-open-to-use-net-bird) |
| Mullvad: UDP 51820 to relays; HTTPS to `api.mullvad.net`; TCP 443 to relays | Tunnel, server list, latency probes |
| Mullvad, through the tunnel: HTTPS to `ipv4.am.i.mullvad.net` and `ipv6.am.i.mullvad.net` | Egress checks |
| PIA: HTTPS to `serverlist.piaservers.net` and `www.privateinternetaccess.com`; TCP 1337 to PIA servers; the UDP port each server assigns | Server list, login, key registration, tunnel |
| PIA, through the tunnel: HTTPS to `www.privateinternetaccess.com`; TCP 19999 to the server (port forwarding only) | Egress check, port forwarding |
| NordVPN: UDP 51820 to servers; HTTPS to `api.nordvpn.com`; TCP 443 to servers | Tunnel, server list, latency probes. The `nordvpn-key` tool makes its one request to `api.nordvpn.com` from the throwaway container at setup |
| NordVPN, through the tunnel: HTTPS to `api.nordvpn.com` | Egress check |
| Native sidecar: the rows for its provider above. The exit's provider downloads, login and registration leave over the host's connection; the applications reach only `SIDECAR_LAN_CIDRS` outside the tunnel | As the provider's rows; a resolver inside `SIDECAR_LAN_CIDRS` is reached outside the tunnel ([DNS](native-sidecar.md#dns)) |
| gluetun backend: what gluetun needs for its provider, including its server list updater and DNS, which go through the tunnel | Tunnel, server list |
| gluetun backend with FastestVPN, IVPN, Surfshark or Windscribe: HTTPS to `api.ipify.org` and `ipv4.icanhazip.com` (and `api6.ipify.org`, `ipv6.icanhazip.com` for IPv6), through the tunnel and from the host | The tunnel checks, which compare the address seen through the tunnel with the host's own |

Check your ISP's or hosting provider's terms before relaying traffic for other
people. Some forbid it.

## NetBird

- **A NetBird account**, either NetBird Cloud or self-hosted. The image
  carries the NetBird client at the version pinned in its `Dockerfile`
  (0.80.0 at this writing); NetBird updates arrive as Molebridge patch
  releases. Only self-hosted servers have been tried: 0.78 and 0.79 with 0.79
  clients in earlier passes, and at 0.8.0 a self-hosted server with the
  image's 0.80.0 client. NetBird Cloud has not. The account needs admin access, because
  you will create groups, a policy, a setup key and a route.
- **Clients that support exit nodes.** Current iOS, Android, macOS, Windows
  and Linux clients do.
- **The account's peer network range**, for example NetBird's default `100.64.0.0/10`. It's in
  the dashboard's network settings and in the management API as
  `network_range`. Molebridge uses it to send replies to your devices back
  over NetBird instead of into the tunnel.
- **Optional: an IPv6 overlay range.** If your account has IPv6 enabled, note
  its range too. Without an IPv6 overlay, NetBird can't carry your devices'
  IPv6; it is meant to block IPv6 while the exit is selected, but check each
  device, because a native IPv6 address showing through means a bypass.
  [Verification](verification.md#from-a-client) shows how.
- **Two groups:**
  - `exit-users`: the devices allowed to use this exit, and nothing else;
  - `exit-nodes`: the Molebridge peer.

  Never put the Molebridge peer in `exit-users`, and never distribute the exit
  route to `All`. The exit forwards anything a distributed device sends it,
  and NetBird's access policies don't filter the destinations of forwarded
  traffic.
- **An access policy** from `exit-users` to `exit-nodes`. ICMP alone is
  enough: NetBird connects peers that a policy links. The exit doesn't answer
  pings to its own overlay address, because nothing arriving over NetBird is
  delivered to the exit itself ([architecture](architecture.md#netbird-and-its-checks)).
- **A setup key** for the peer's first enrollment: one-off, auto-assigning
  `exit-nodes`, with a short expiry.
- **The exit-node route**, created during setup: network `0.0.0.0/0`, routing
  peer the Molebridge peer, masquerade on, auto-apply off, distribution group
  `exit-users`. With IPv6 overlay, NetBird adds a matching `::/0` route; check
  that it's there. NetBird's [exit node guide](https://docs.netbird.io/use-cases/remote-access/exit-nodes)
  covers the dashboard steps.

- **Nothing else for the exit peer.** Don't enable NetBird SSH for it, don't
  give `exit-nodes` DNS nameservers, don't route domain resources or domain
  routes through it, and don't turn on Rosenpass for it. None of them is
  supported on the exit peer: overlay traffic is never delivered to the exit
  itself, so they don't work there. The exit refuses to start NetBird with
  Rosenpass on ([troubleshooting](troubleshooting.md#startup)).

On phones, turn off *Force relay connection* in the NetBird app (Settings →
Advanced). It's on by default to save battery, and it routes all exit traffic
through a NetBird relay. On one deployment that took a 32 ms path to 124 ms
and cut throughput by more than half.

## VPN provider

### Mullvad

- **An active account.** When its time runs out, the tunnel stops
  handshaking and the exit fails closed. The panel shows "Tunnel handshake is
  missing or stale; check the account and connectivity." It can't tell an
  expired account from a network problem.
- **One free device slot.** Molebridge uses one WireGuard key on every server,
  so it takes one slot however often you switch.
- **A WireGuard config file for that device:**
  1. Sign in at mullvad.net and open the WireGuard configuration generator.
  2. Choose Linux, generate a new key, and pick any server. That becomes the
     starting server.
  3. Download a single `.conf` file, not the zip of every server.

  The file contains the device's private key. Keep it out of repositories,
  chats and synced folders, and delete it once setup has converted it.

### PIA

- **An active account**, with its username (`p` followed by digits) and
  password. The exit keeps both on the host, in mode-0600 files, and uses
  them to register the tunnel key every time it switches. Two-factor
  authentication doesn't get in the way: PIA's token API accepts the password
  alone.
- Nothing to download: `prepare-config --pia` generates the key.
- PIA carries IPv4 only. See [providers](providers.md) for what else differs,
  and for port forwarding.

### NordVPN (experimental)

Live passes on macOS with OrbStack and on rootless Podman, including the
client-held fail-closed drills at 0.7.0 ([testing](testing.md#070-on-rootless-podman-at-d5a234a)),
and a native exit upgraded from 0.7.0 and drilled on rootless Podman at 0.8.0.

- **An active account** with NordVPN's VPN service.
- **An access token**, from your Nord Account: NordVPN, then Advanced
  settings, then "Get access token". `nordvpn-key` uses it once, at
  setup, to fetch the account's NordLynx private key; the exit never stores
  it. The private key is the same on every server.
- **Memory for the server list.** On the 0.8.0 live host a NordVPN exit
  idled at 189 MB, 136 MB of it anonymous memory. Parsing a list at the
  32 MiB limit took about 300 MB in a local test. The Compose files' 512 MiB
  limit for the exit container is sized for it.
- NordVPN carries IPv4 only. See [providers](providers.md#how-nordvpn-differs).

## Panel access

By default the panel has no login. Anyone who can reach it can switch the
exit for everyone. It listens on the host's loopback address only, and you
need one of:

- SSH to the host, to forward that port to your laptop;
- a reverse proxy that authenticates every request before passing it on, for
  example an identity-aware proxy, or NetBird's reverse proxy restricted to
  the right access groups;
- an OpenID Connect identity provider, if you want the panel to sign people in
  itself. That also needs a proxy that serves the panel over https.

[Panel access](access.md) walks through each. Never publish the panel on an
open port.
