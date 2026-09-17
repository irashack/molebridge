# Prerequisites

Gather these before [setup](setup.md).

## Mullvad

- **An active Mullvad account.** When its time runs out, the tunnel stops
  handshaking and the exit fails closed; the panel reports that the account
  may have expired.
- **One free device slot.** Switchyard uses a single WireGuard key for every
  server, so it takes one slot no matter how often you switch.
- **A WireGuard configuration file** generated for that device:
  1. Sign in at mullvad.net and open the WireGuard configuration generator
     (Account → WireGuard configuration).
  2. Choose Linux, generate a new key, and pick any server. It becomes the
     starting server; the panel changes it later.
  3. Download a single `.conf` file, not a zip of every server.

  The file contains the device's private key. Keep it out of repositories,
  chats and shared folders, and delete it after setup converts it.

## NetBird

- **A NetBird account**, NetBird Cloud or self-hosted, with clients that
  support exit nodes (the iOS, Android, macOS, Windows and Linux clients do).
  The author's deployment runs NetBird 0.78.
- **The account's peer network range**, for example `100.92.0.0/16`. It appears
  in the dashboard's network settings and as `network_range` in the
  management API's account settings. Switchyard needs it so replies to your
  devices return over the overlay rather than into the tunnel.
- **Optional IPv6 overlay.** If IPv6 overlay is enabled for the account, note its
  range too. Without it, clients' IPv6 is not carried by NetBird; check what your
  devices do with native IPv6 while the exit is selected (see
  [verification](verification.md#from-a-client)).
- **Two groups:**
  - `exit-users`: only the devices allowed to use this exit;
  - `exit-nodes`: the Switchyard peer.

  Never put the Switchyard peer in `exit-users`, and never distribute the exit
  route to `All`. The exit forwards everything a distributed client sends it,
  and NetBird access policies do not filter forwarded destinations.
- **An access policy** from `exit-users` to `exit-nodes`. ICMP alone is enough;
  NetBird uses it to make the exit selectable.
- **A setup key** for the peer's first enrollment: one-off, auto-assigning
  `exit-nodes`, short expiry.
- Later, during setup, you create an **exit node route**: network `0.0.0.0/0`,
  routing peer the Switchyard peer, masquerade on, auto-apply off, distribution
  group `exit-users`. With IPv6 overlay, add a matching `::/0` route. See
  NetBird's [exit node guide](https://docs.netbird.io/use-cases/remote-access/exit-nodes).

## Host

- **An always-on machine** with Docker Engine and Compose v2.24 or newer, able
  to run containers with `NET_ADMIN` and create WireGuard interfaces:
  - Linux with kernel 5.6 or newer (WireGuard built in): expected to work, not
    yet tested;
  - macOS with OrbStack: tested on Apple silicon;
  - Docker Desktop: untested.
- **amd64 or arm64.** The pinned images are multi-arch.
- **Outbound network access:** UDP 51820 to Mullvad servers, HTTPS to
  `api.mullvad.net` (relay list) and `am.i.mullvad.net` (egress checks), TCP 443
  to Mullvad servers (latency probes), and whatever NetBird needs to reach your
  management server and peers.
- **Upload bandwidth.** Every client's traffic crosses this host twice: in from
  the device, then out to Mullvad. Throughput is bounded by the host's upload.
- **A way to publish the panel with authentication:** an identity-aware reverse
  proxy, NetBird's reverse proxy with access groups, or access only from the
  host itself. The panel has no login of its own.
- **Your provider's terms.** Relaying VPN traffic from a home connection or a
  rented server may be restricted. Check before exposing an exit to anyone.
