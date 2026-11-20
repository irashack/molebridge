# The NetBird exit node

**Traffic your devices forward through the exit leaves through the provider's
tunnel, or not at all.** If the tunnel or its routes are gone, that traffic is
dropped; it never falls back to the host's own connection.

This page is the native NetBird exit: Molebridge builds the WireGuard tunnel
itself, for Mullvad, PIA or NordVPN. The same way in with gluetun owning the
tunnel, for gluetun's providers, is [gluetun as a NetBird
exit](gluetun-netbird-exit.md).

## Who it is for

Phones can usually run only one VPN at a time, so turning on Mullvad, PIA or
NordVPN means turning off NetBird. The NetBird exit moves the provider's
tunnel onto a machine you keep running, which joins your NetBird network as an
exit node. Your devices stay on NetBird, select the exit, and everything they
send to the Internet leaves through the provider. Every device using the exit
follows a server switch with no change on the device.

Choose it for whole devices on your NetBird network. For programs that opt
in, the [proxy](proxy.md) runs on top of this exit; for containers on one
host, a [sidecar](native-sidecar.md) has no NetBird at all.
[The menu](menu.md) compares them.

## What you run

`compose.yaml`, from the release bundle or written by `molebridge init` with
the `netbird-exit` way in ([setup](setup.md)). Its services:

| Service | Image | Role |
|---|---|---|
| `exit` | `ghcr.io/irashack/molebridge` (the binary and the pinned NetBird client) | Owns the network namespace, the tunnel and the routing; `molebridge exit` is PID 1 and supervises the worker and NetBird. `EXIT_KIND=overlay`, `TUNNEL_BACKEND=native`. Capabilities `NET_ADMIN`, `NET_RAW` and `DAC_OVERRIDE`, every other one dropped |
| `switchyard` | the same image | The panel, optional: no capabilities and no network in common with the exit ([Switchyard](switchyard.md)) |

The `molebridge-core` image, without NetBird, refuses to run this exit. The
proxy, if you add it, is one more service ([the proxy](proxy.md)).

## How it keeps the guarantee

The exit's worker installs a routing contract in its own namespace before the
tunnel exists, brings the tunnel up, and keeps both in place; the supervisor
starts NetBird only once the contract holds, in both address families.
[Architecture](architecture.md#routing-contract) lists every rule and why it
is there. In short, with the defaults (`OVERLAY_IF=wt0`, `EXIT_IF=mullvad`,
`EXIT_TABLE=51821`):

- Traffic arriving from NetBird on `wt0` looks up the exit table (rule 95),
  whose only routes are the tunnel's default route and an `unreachable`
  fallback. Behind it, rule 97 (`iif wt0 unreachable`) drops what is left if
  the lookup or the table is gone. Nothing in this path reaches the main
  table, which holds the host's default route.
- Replies from the provider return to your devices over NetBird (rule 90),
  and ICMP errors the exit generates for tunnel traffic go back through the
  tunnel (rule 94, with rule 98 behind it).
- Unicast traffic that arrives over NetBird is never delivered to the exit
  itself (rule 1). The exit's own addresses are ordinary destinations, routed
  into the tunnel like any other.
- The exit repairs a changed rule, route, link or address when the kernel
  reports it, and runs a full pass every 30 seconds
  (`ROUTING_RECONCILE_INTERVAL`) as the fallback. In the live drills a deleted
  rule was back within tens of milliseconds ([testing](testing.md)).
- If the worker stops answering, the supervisor's lease lapses: it stops
  NetBird, removes the interfaces it owns, leaves the routing rules in place
  and exits, and the restart policy starts the container again. From a
  stalled loop to NetBird gone takes at most 55 seconds at the defaults
  ([the lease](architecture.md#the-lease)).

The exit's own NetBird and provider control traffic uses the host's route, so
it can connect while the tunnel is down.

**What the exit requires of NetBird.** Kernel WireGuard and NetBird's kernel
firewall, in daemon mode with its default profile. `compose.yaml` sets
`NB_DISABLE_USERSPACE_ROUTING=true`, and the exit refuses to start NetBird
with the userspace settings
([what Compose fixes for NetBird](configuration.md#what-compose-fixes-for-netbird)).
It also refuses to start NetBird while
`net.ipv4.icmp_errors_use_inbound_ifaddr` is not 1, which `compose.yaml`
sets, and logs:

```text
molebridge-exit: NetBird is not started: net.ipv4.icmp_errors_use_inbound_ifaddr is not 1; set it on the exit service (compose.yaml sets it), or the exit's ICMP errors for tunnel traffic would leave by the host interface
```

**The ICE blacklist.** NetBird shares the namespace with the tunnel, so by
default it gathers connection candidates on the tunnel interface too: direct
connections fail, clients fall back to a relay, and the tunnel address can be
offered to other peers. `compose.yaml` puts the tunnel interface in the peer's
blacklist at its first enrollment (`NB_EXTRA_IFACE_BLACKLIST`). After that the
peer's stored profile wins, so the exit reads the profile before it starts
NetBird and again after `netbird up`, and admits no traffic unless the tunnel
interface is excluded. A peer enrolled earlier, or without the variable, is
refused with a line that names the repair tool, `fix-blacklist`
([operations](operations.md#netbird-interface-blacklist)).

**The identity.** The peer's profile and private key live in the
`netbird-data` volume. When the exit finds none it says so before starting
NetBird: `molebridge-exit: no NetBird identity found in the state directory or
the legacy profile paths; NetBird will enroll a new peer`. That is right on a
first start and wrong after an upgrade; stop and look at
[the identity volume](operations.md#backups) if you expected the old peer.

## Setup specifics

[Setup](setup.md) is the procedure: download and verify, configure, create
the tunnel config, start, check. What is particular to this way in:

- **NetBird first.** You need admin access to your NetBird account, two
  groups (`exit-users` for the devices, `exit-nodes` for the exit peer), an
  access policy from `exit-users` to `exit-nodes`, a one-off setup key that
  assigns `exit-nodes`, and, after the first start, the exit-node route
  ([requirements](prerequisites.md#netbird)). Never put the exit peer in
  `exit-users`, and never distribute the exit route to `All`: the exit
  forwards anything a distributed device sends it.
- **`.env`.** `OVERLAY_CIDR` is your NetBird peer range (and `OVERLAY6_CIDR`
  its IPv6 range, if you have one): the exit uses it to send replies back over
  NetBird. `NB_HOSTNAME` is the peer's name, `NB_MANAGEMENT_URL` your
  management server if you self-host. `PROVIDER` and `EXIT_IF` name the
  provider and the tunnel interface (`mullvad` and `mullvad`, `pia` and `pia`,
  or `nordvpn` and `nordvpn`).
- **The setup key** goes in `secrets/netbird.env` as one line,
  `NB_SETUP_KEY=<key>`. Once the peer shows in the dashboard under
  `NB_HOSTNAME`, in `exit-nodes`, delete the file and revoke the key if it was
  reusable. Never run `docker compose down -v`: it deletes the peer's
  identity.
- **`check-config`** prints `NetBird gate: configuration accepted` beside the
  exit's own line when NetBird's settings pass.
- **The route.** Create it once the peer is up: network `0.0.0.0/0`, routing
  peer the exit, masquerade on, auto-apply off, distribution group
  `exit-users`. With an IPv6 overlay, check that NetBird added the matching
  `::/0` route. With PIA or NordVPN, which carry no IPv6, create the `::/0`
  route anyway, so a device's IPv6 hits the exit's fallback instead of leaving
  over its own network ([providers](providers.md#how-pia-differs)).
- **Leave these off for the exit peer**: Rosenpass, NetBird SSH, DNS
  nameservers served by the exit, and domain routes or domain resources
  through it. None of them can work on the exit, because nothing arriving
  over NetBird is delivered to it, and the exit refuses to start NetBird with
  Rosenpass on.
- **Rootless Podman and Docker's default bridge** put the namespace on a
  private network, so devices elsewhere fall back to a NetBird relay without
  any error. [Exits on a private container
  network](operations.md#exits-on-a-private-container-network) has the fix.
- **Try a device.** Select the exit in a device's NetBird client and open the
  provider's check page, then run the [client checks](verification.md#from-a-client).
  On phones, turn off *Force relay connection* in the NetBird app (Settings,
  then Advanced): it is on by default and routes all exit traffic through a
  NetBird relay.

## Choosing and switching servers

Choose a server (Mullvad, NordVPN) or a region (PIA) in
[Switchyard](switchyard.md), or set `SERVER` in `.env` to keep the exit on
one; the panel then shows it read-only as "Set in configuration"
([a server set in configuration](configuration.md#a-server-set-in-configuration)).
The exit checks the name against the provider's server list, which it
downloads itself, changes the tunnel and reports back. Connections open
through the exit drop when it switches; the devices keep the exit selected
and follow it.

- **Mullvad** starts on the server in the tunnel config and verifies it on
  the first check.
- **PIA** carries no traffic until you choose a region: the exit reports "No
  PIA region is registered yet; choose one in the panel."
- **NordVPN** carries no traffic until you choose a server: "No NordVPN
  server is selected yet; choose one in the panel."

Unless you turn on [automatic failover](failover.md) (experimental, off by
default), the exit never picks another server by itself: it retries the one
you chose, with growing pauses, and PIA registers again within the same
region when its server stops answering. One exit serves one provider; to
offer several, run one exit per provider and serve them from one
[Switchyard](switchyard.md#several-exits-in-one-panel), or see the
[multi-provider exit](multi-provider.md).

A device on a native Mullvad exit can also send one application through
another Mullvad server's relay proxy, without switching the exit
([Mullvad's relay proxies used directly](proxy.md#mullvads-relay-proxies-used-directly)).

## Limits and what wasn't tested

**What was tested.** [Testing](testing.md) is the record. On Kubernetes (k0s
with Cilium), native Mullvad, PIA and NordVPN exits are upgraded from the
previous release for every release candidate, come back `ok`, and pass the
tunnel-loss drill from inside the exit's namespace with no client device held
on them. Native NordVPN has also run live on macOS with OrbStack and on
rootless Podman, and the exit ran on rootless Podman 5.8 with Quadlet units.
A Linux client was last held on an exit through the drills at 0.7.0, whose
routing the Go exit ports
([testing](testing.md#070-on-rootless-podman-at-d5a234a)).

**Not tested:** Docker Engine, podman-compose and NetBird Cloud; running the
shipped `compose.yaml` on any engine (CI validates it with
`docker compose config`; the live exits ran from Quadlet units and Kubernetes
manifests this repository doesn't ship); phones; a reboot; PIA port
forwarding ([the full list](testing.md#not-tested-at-090)). Run the
[verification](verification.md) checks on your own host before you rely on
it, and keep a way into the host that doesn't depend on the exit.

- **Not a kill switch on your devices.** The exit fails closed for traffic it
  receives. A device that deselects the exit, or that NetBird disconnects,
  uses its own connection.
- **No DNS configuration.** Devices keep their own resolvers, and their
  lookups leave through the provider like any other traffic. With Mullvad a
  leak test shows Mullvad's resolver (observed, not documented by Mullvad);
  PIA and NordVPN are untested ([DNS](operations.md#dns)).
- **IPv4 only with PIA and NordVPN.** Forwarded IPv6 hits the exit table's
  fallback.
- **The exit serves nothing over NetBird.** No NetBird SSH, no nameserver, no
  pings to its own overlay address.
- **NetBird only.** It relies on NetBird's exit-node routes and was never
  built or tested for Tailscale or other overlays.
- **The host's upload caps throughput.** Every byte your devices send crosses
  the host twice.
- **Restrictive Wi-Fi.** A healthy exit can still leave a device at
  Connecting on a network that breaks long-lived UDP flows; that is NetBird's
  relay behavior ([troubleshooting](troubleshooting.md#clients)).
