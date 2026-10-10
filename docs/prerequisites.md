# Requirements

Everything here is needed before [setup](setup.md). Where something has only
been tested in one configuration, this page says so.

## Host

- **An always-on machine.** When it's off, devices using the exit lose their
  Internet connection until they deselect it.
- **Linux with kernel WireGuard** (5.6 or later, or an older kernel with the
  module installed). Molebridge uses the kernel implementation only; there is
  no userspace fallback. PIA also needs nftables support in the kernel
  (`nf_tables`), which current distribution kernels include.

| Runtime | Status |
|---|---|
| Debian 13, rootless Podman 5.4, podman-compose 1.6, amd64 | Tested: long-running, reboot and clean install |
| macOS with OrbStack, Apple silicon | Tested in an earlier live pass |
| Other Linux with Docker Engine and Compose 2.24+ | Expected to work; not yet tested end to end |
| Docker Desktop | Untested |
| Windows | Not supported |

- **amd64 or arm64.** All pinned images are multi-arch.
- **Python 3.10 or later on the host**, for `tools/prepare-tunnel-config.py`
  and the `doctor` and `recover` helpers. The containers bring their own
  Python. NordVPN's key setup, `tools/nordvpn-key.py`, also needs `curl` and
  the usual CA certificates on the host.
- **Build access on first setup.** Two small images are built locally from
  pinned bases. The routing image installs `bash`, `iproute2`,
  `wireguard-tools` and `tini` from Alpine's signed repositories, and the
  applier installs `wg`, `ip`, `curl` and `nft` from Debian's.
- **Resources.** Measured on the tested Debian host while idle, with a
  Mullvad exit and the earlier LinuxServer-based routing image: about 100 MB
  of RAM across the four containers, and about 500 MB of disk for images. The Compose memory limits add up to 896 MiB for
  that stack, 1,280 MiB with NordVPN's larger applier limit, and 1,216 MiB
  with the gluetun backend; NordVPN and gluetun weren't measured. CPU use is mostly WireGuard
  encryption and scales with traffic.
- **Upload bandwidth.** Every device's traffic crosses the host twice, in from
  the device and out to the provider. The host's upload speed is the ceiling
  for everyone using the exit.

### Rootless Podman

Two things differ from Docker:

1. **The kernel modules must already be loaded.** A rootless container can't
   load `wireguard`, and `wg-quick` then fails with no useful message. Load it
   now and at every boot:

   ```sh
   sudo modprobe wireguard
   echo wireguard | sudo tee /etc/modules-load.d/wireguard.conf
   ```

   For PIA, check that `nf_tables` is loaded too (`lsmod | grep nf_tables`).
   Hosts that use nftables for their own firewall already have it.

2. **Set `PANEL_USER=0:0`.** Rootless Podman maps container root to your own
   user, so that's the user that can read the state directory. The panel still
   runs with no capabilities.

`tools/molebridge.py doctor` and `recover` drive `docker compose` and don't
work with podman-compose. [Operations](operations.md#rootless-podman) gives
the Podman commands that replace them. For containers to start at boot you
also need a lingering systemd user unit, shown there too.

## Network

The exit needs these outbound connections. It needs no inbound ports unless
you want direct NetBird connections from a rootless or bridged setup (see
[operations](operations.md#exits-on-a-private-container-network)).

| To | Why |
|---|---|
| Your NetBird management, signal and relay servers, and STUN | The exit peer; see NetBird's [firewall requirements](https://docs.netbird.io/about-netbird/faq#what-firewall-ports-should-i-open-to-use-net-bird) |
| Mullvad: UDP 51820 to relays; HTTPS to `api.mullvad.net`; TCP 443 to relays | Tunnel, server list, latency probes |
| Mullvad, through the tunnel: HTTPS to `ipv4.am.i.mullvad.net` and `ipv6.am.i.mullvad.net` | Egress checks |
| PIA: HTTPS to `serverlist.piaservers.net` and `www.privateinternetaccess.com`; TCP 1337 to PIA servers; the UDP port each server assigns | Server list, login, key registration, tunnel |
| PIA, through the tunnel: HTTPS to `www.privateinternetaccess.com`; TCP 19999 to the server (port forwarding only) | Egress check, port forwarding |
| NordVPN: UDP 51820 to servers; HTTPS to `api.nordvpn.com`; TCP 443 to servers | Tunnel, server list (and, once from the host at setup, the key), latency probes |
| NordVPN, through the tunnel: HTTPS to `api.nordvpn.com` | Egress check |
| gluetun backend: what gluetun needs for its provider, including its server list updater and DNS, which go through the tunnel | Tunnel, server list |
| gluetun backend with FastestVPN, IVPN, Surfshark or Windscribe: HTTPS to `api.ipify.org` and `ipv4.icanhazip.com` (and `api6.ipify.org`, `ipv6.icanhazip.com` for IPv6), through the tunnel and from the host | The tunnel checks, which compare the address seen through the tunnel with the host's own |

Check your ISP's or hosting provider's terms before relaying traffic for other
people. Some forbid it.

## NetBird

- **A NetBird account**, either NetBird Cloud or self-hosted. Only
  self-hosted 0.78 and 0.79 have been tested. The account needs admin access,
  because you will create groups, a policy, a setup key and a route.
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
  delivered to the exit itself ([architecture](architecture.md#netbird-requirements)).
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
  itself, so they don't work there. NetBird's entrypoint gate refuses to
  start the peer with Rosenpass on
  ([troubleshooting](troubleshooting.md#startup)).

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
  password. The applier keeps both on the host, in mode-0600 files, and uses
  them to register the tunnel key every time it switches. Two-factor
  authentication doesn't get in the way: PIA's token API accepts the password
  alone.
- Nothing to download: `tools/prepare-tunnel-config.py --pia` generates the key.
- PIA carries IPv4 only. See [providers](providers.md) for what else differs,
  and for port forwarding.

### NordVPN (experimental)

Live passes on macOS with OrbStack and on rootless Podman, without the
client-held fail-closed drills; see [testing](testing.md#nordvpn-pass-at-036e1cc).

- **An active account** with NordVPN's VPN service.
- **An access token**, from your Nord Account: NordVPN, then Advanced
  settings, then "Get access token". `tools/nordvpn-key.py` uses it once, at
  setup, to fetch the account's NordLynx private key; the exit never stores
  it. The private key is the same on every server.
- **More memory for the applier.** Parsing NordVPN's server list every six
  hours took about 70 MB in a local test with a synthetic list of today's
  size, and about 300 MB at the 32 MiB limit; `compose.nordvpn.yaml` raises
  the applier's limit from 128 MB to 512 MB.
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
