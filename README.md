<p align="center">
  <img src="docs/assets/molebridge-banner.svg" alt="Molebridge: stay on NetBird, exit through Mullvad or PIA" width="1000">
</p>

<p align="center">
  <strong>A self-hosted NetBird exit node that sends traffic through Mullvad, PIA or NordVPN.</strong>
</p>

<p align="center">
  <a href="docs/setup.md"><strong>Setup</strong></a> ·
  <a href="docs/prerequisites.md">Requirements</a> ·
  <a href="docs/switchyard.md">The panel</a> ·
  <a href="docs/architecture.md">Architecture</a> ·
  <a href="CHANGELOG.md">Changelog</a>
</p>

---

Phones can usually run only one VPN at a time, so turning on Mullvad, PIA or
NordVPN means turning off NetBird. Molebridge moves the commercial VPN tunnel onto a
machine you keep running. That machine joins your NetBird network as an exit
node. Your devices stay on NetBird, select the exit, and their Internet
traffic leaves through the VPN provider.

You choose the server (Mullvad, NordVPN) or region (PIA) in a small web panel
called Switchyard. Every device using the exit follows the switch without any client
changes. Connections open through the exit drop when it switches.

<p align="center">
  <img src="docs/assets/switchyard.png" alt="Switchyard, showing a Mullvad exit and a PIA exit as tabs" width="900">
</p>

## How it works

```mermaid
flowchart LR
    device("Your devices<br/>on NetBird")
    provider("Mullvad, PIA or<br/>NordVPN server")

    subgraph host["Exit host · one shared network namespace"]
        peer("NetBird<br/>exit peer")
        route("Policy<br/>routing")
        tunnel("WireGuard<br/>tunnel")
        blocked("Tunnel down:<br/>unreachable")
        peer --> route
        route --> tunnel
        route -.-> blocked
    end

    device --> peer
    tunnel --> provider

    classDef endpoint fill:#24273a,stroke:#8aadf4,color:#cad3f5,stroke-width:2px
    classDef routing fill:#24273a,stroke:#a6da95,color:#cad3f5,stroke-width:2px
    classDef stopped fill:#24273a,stroke:#ed8796,color:#f4dbd6,stroke-width:2px
    class device,peer,provider endpoint
    class route,tunnel routing
    class blocked stopped
    style host fill:#1e2030,stroke:#494d64,color:#cad3f5
    linkStyle default stroke:#8087a2,stroke-width:2px
```

Three containers share one network namespace: the WireGuard tunnel, a NetBird
peer, and an "applier" that controls the tunnel. The fourth, the panel, runs
outside it. Traffic forwarded from your devices can only go into the tunnel.
If the tunnel or its routes disappear, that traffic is dropped; it never falls
back to the host's own connection. The exit's own NetBird and VPN control
traffic uses the host's normal route.

The panel holds no privileges. It writes one file naming the server you
picked. The applier checks that name against the provider's server list,
which the applier downloads itself, then changes the tunnel and reports back.
Details: [architecture](docs/architecture.md).

## What you need

- **An always-on Linux host**, amd64 or arm64, with kernel WireGuard (Linux
  5.6 or later). Rootless Podman with podman-compose is tested, and so is macOS
  with OrbStack. Docker Engine with Compose 2.24 or later should work but
  hasn't been tested end to end. Windows hosts are not supported.
- **Resources:** on the tested host the four containers use about 100 MB of
  RAM between them, and the images take about 500 MB of disk. Every byte your
  devices send crosses the host twice, so the host's upload speed caps
  throughput.
- **A NetBird network**, either NetBird Cloud or self-hosted, with admin
  access to create groups, a policy, a setup key and an exit-node route.
- **A VPN account:**
  - Mullvad, which uses one free device slot;
  - or PIA, which needs your username and password on the host;
  - or NordVPN (experimental), whose access token is needed
    only once, at setup.
- **A way to reach the panel with authentication.** Unless you set up
  OpenID Connect sign-in, the panel has no login of its own; see
  [panel access](docs/access.md).
- **Python 3.10 or later on the host**, for the setup and maintenance helpers.

The full list, with the NetBird groups, the outbound ports and the rootless
Podman details, is in [requirements](docs/prerequisites.md).

## Limits

- **The panel has no login unless you configure one.** By default, anyone who
  can reach it can change the exit for every device that uses it. Reach it
  through an SSH tunnel or an authenticating proxy, or turn on
  [OpenID Connect sign-in](docs/access.md#sign-in-with-openid-connect). Sign-in
  has been tried live with one provider and an admin account only; see
  [testing](docs/testing.md#sign-in-pass-at-62a0170).
- **This is not a kill switch on your devices.** The exit fails closed for
  traffic it receives. If a device deselects the exit or NetBird disconnects,
  that device uses its own connection.
- **Molebridge configures no DNS.** Devices keep their own resolvers. With
  Mullvad, plain DNS that passes through the exit ends up at the Mullvad
  server, so a DNS leak test shows Mullvad; this is observed, not documented
  by Mullvad. PIA and NordVPN are untested. See [DNS](docs/operations.md#dns).
- **Mullvad, PIA and NordVPN only.** NordVPN is experimental: it has had one
  live pass, on macOS with OrbStack, and no fail-closed drills yet. Other
  providers aren't supported. Some could be added if there's interest;
  [other providers](docs/other-providers.md) says which, and what that
  support would realistically look like.
- **One provider per exit.** To offer more than one, run one exit per
  provider on the same host and serve them from one
  [Switchyard](docs/switchyard.md#several-exits-in-one-panel).
- **PIA and NordVPN are IPv4 only.** PIA's port forwarding is experimental
  and opens a port to the Internet.
- **No automatic failover.** Molebridge never moves the exit to a different
  server or region by itself. (PIA re-registers within the same region when
  its server stops answering.)
- **NetBird only.** It relies on NetBird's exit-node routes and was never
  built or tested for Tailscale or other overlays.

## Status

Molebridge is experimental, with one maintainer. Run a release or a pinned
commit, and verify it on your own host before you rely on it. The latest
release is [v0.4.1](https://github.com/irashack/molebridge/releases/tag/v0.4.1),
a security release that tightens the exit's routing and the NetBird settings
it supports; see the [changelog](CHANGELOG.md).

| Setup | Tested |
| :--- | :--- |
| Debian 13, rootless Podman 5.4, podman-compose 1.6, amd64, self-hosted NetBird 0.79: Mullvad | A client held on the exit through all six failure drills, a host reboot with unattended recovery, LAN isolation, and a clean install from the published files. |
| The same host: PIA | First start, recreation, a client held on the exit through a tunnel-down drill, IPv6 and LAN isolation, and region switches. |
| The same host: Switchyard | One panel serving the Mullvad and PIA exits, with a selection verified on each. |
| The same host: Switchyard sign-in | Pocket ID v2.16.0: an admin sign-in and a verified switch through it, and the signed-out behavior through a proxy. Sign-in by someone granted only some exits is covered by tests, not yet live. |
| macOS, OrbStack, Apple silicon, self-hosted NetBird 0.78: Mullvad | An earlier live pass; the six defects it found are fixed. |
| CI on every push | Unit tests, shell lint, Compose validation, image builds, and IPv4/IPv6 routing failure drills in isolated namespaces. |
| macOS, OrbStack, Docker, self-hosted NetBird 0.79: NordVPN | Key setup, the server list, switches within a location and to another country, NordVPN-confirmed egress from a client, and IPv6 blocked. |
| Not yet tested | Docker Engine on Linux, Docker Desktop, NetBird Cloud, phones during failure drills, PIA port forwarding against PIA itself, and NordVPN on rootless Podman or through the fail-closed drills. |

The dated record of each pass is in [testing](docs/testing.md). Report
vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Documentation

**Install**
- [Requirements](docs/prerequisites.md): accounts, host, NetBird groups and ports.
- [Setup](docs/setup.md): from an empty checkout to a working exit.
- [Verification](docs/verification.md): the checks and failure drills to run before you rely on it.
- [Panel access](docs/access.md): SSH forwarding, an authenticating proxy, or OpenID Connect sign-in.

**Use**
- [Switchyard](docs/switchyard.md): switching, embedding in a dashboard, phones, several exits.
- [Operations](docs/operations.md): health, upgrades, recovery, backups, rootless Podman, removal.
- [Troubleshooting](docs/troubleshooting.md): symptoms and fixes.

**Reference**
- [Configuration](docs/configuration.md): every setting, file and endpoint.
- [Providers](docs/providers.md): how PIA and NordVPN differ from Mullvad, port forwarding, adding a provider.
- [Other providers](docs/other-providers.md): unsupported VPNs, and what adding one would take.
- [gluetun as a NetBird exit](docs/gluetun-netbird-exit.md): gluetun and NetBird with only Molebridge's routing guard, no panel or applier; that form is untested.
- [Architecture](docs/architecture.md): routing, trust boundaries and the switching sequence.
- [Testing](docs/testing.md): what has been tested, where and at which revision.

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

---

Molebridge isn't affiliated with Mullvad VPN AB, Private Internet Access,
NordVPN or NetBird. Their names are used only to say what Molebridge works with. The
panel's provider styling uses colors only, with no logos or copied assets.
Molebridge is released under the [MIT License](LICENSE). The bundled
JetBrains Mono font is under the [SIL Open Font License](panel/static/JetBrainsMono-OFL.txt),
and the bundled PIA certificate authority comes with
[PIA's MIT notice](applier/PIA-CA-LICENSE.txt).
