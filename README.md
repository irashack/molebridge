# Switchyard

Use Mullvad without leaving your mesh VPN.

Phones allow one VPN at a time. If your devices live on a NetBird overlay,
turning on the Mullvad app means dropping the overlay. Switchyard runs a Mullvad
WireGuard tunnel behind a NetBird **exit node** on a machine you already have.
Your devices stay on NetBird and choose that exit when they want Mullvad egress.
A small web panel picks the Mullvad server, ranks locations by measured latency,
embeds in a dashboard, and installs as a home-screen app.

**Status:** early. In daily use since 2026-09-16 on one deployment: Docker on
macOS (OrbStack, Apple silicon) with a self-hosted NetBird 0.78 account and
iPhone and macOS clients. Linux Docker hosts and NetBird Cloud are expected to
work but have not been tested. No releases yet; the repository is private
during development and has no license yet.

Switchyard is not affiliated with Mullvad VPN AB or NetBird.

## How it works

```
 iPhone / laptop ──NetBird──▶ exit peer ─┐
 (exit selected)                         │ same network namespace
                                         ▼
                              policy routing ──▶ WireGuard tunnel ──▶ Mullvad server
                              (unreachable if the tunnel is down)
 control panel ──writes desired server──▶ applier ──wg set──▶ tunnel peer
```

- **Fail-closed by routing, not firewall rules.** Traffic forwarded from the
  overlay can only use the tunnel's routing table, whose fallback is
  `unreachable`. If the tunnel is down, a route is deleted, or the container
  stops, clients lose Internet; they never leak out of the host's own
  connection.
- **Privilege split.** The panel has no capabilities and never touches the
  tunnel. It writes the chosen server name to a file. The applier re-validates
  that name against Mullvad's published relay list before changing the peer,
  and it never sees the private key.
- **One Mullvad device.** A Mullvad key works on every WireGuard server, so
  switching changes only the peer. Existing connections drop on a switch.

Details: [architecture](docs/architecture.md).

## Security model

The panel has **no login**. Anyone who can reach it can change the exit server
for everyone using it. Publish it only behind something that authenticates
people, such as an identity-aware reverse proxy or an overlay access policy that
admits only the people who may switch. It binds to `127.0.0.1` by default.

The exit peer forwards everything it receives from clients the NetBird
route is distributed to. Restrict that distribution group; see
[prerequisites](docs/prerequisites.md#netbird).

## Documentation

1. [Prerequisites](docs/prerequisites.md): Mullvad, NetBird and host requirements.
2. [Setup](docs/setup.md): from a fresh clone to a working exit.
3. [Verification](docs/verification.md): prove it fails closed before trusting it.
4. [Operations](docs/operations.md): switching, dashboards, phones, failures, upgrades.
5. [Configuration](docs/configuration.md): every setting.
6. [Architecture](docs/architecture.md): routing contract, file contract, design choices.

## Prior art

Tailscale offers Mullvad exit nodes as a hosted integration; NetBird has no
equivalent. Community attempts to put Gluetun behind a mesh exit node broke the
return path and hit MTU stalls. Switchyard owns its policy routing and pins the
MTU instead. The WireGuard project's
[network namespace guidance](https://www.wireguard.com/netns/) informed the
fail-closed design.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -m pytest -q panel tools
sh -n routing/10-exit-routing applier/apply.sh
cp .env.example .env && docker compose config --quiet
```

The panel is Python standard library only. The bundled JetBrains Mono font is
under the SIL Open Font License (`panel/static/JetBrainsMono-OFL.txt`).
