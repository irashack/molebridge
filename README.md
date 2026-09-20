# Molebridge

Use Mullvad without leaving your mesh VPN.

Phones allow one VPN at a time. If your devices live on a NetBird overlay,
turning on the Mullvad app means dropping the overlay. Molebridge runs a Mullvad
WireGuard tunnel behind a NetBird **exit node** on a machine you already have.
Your devices stay on NetBird and choose that exit when they want Mullvad egress.
A small web panel picks the Mullvad server, ranks locations by measured latency,
embeds in a dashboard, and installs as a home-screen app.

**Status:** early. The original stack has been in daily use since 2026-09-16 on one deployment: Docker on
macOS (OrbStack, Apple silicon) with a self-hosted NetBird 0.78 account and
iPhone and macOS clients. Linux Docker hosts and NetBird Cloud are expected to
work but have not been tested end to end. The reliability/security changes in
this revision still need the [homelab verification pass](docs/homelab-testing.md).
No releases yet; the repository is private
during development and has no license yet.

Molebridge is not affiliated with Mullvad VPN AB or NetBird.

Previously called Switchyard. Existing installations should follow the
[rename upgrade notes](docs/operations.md#upgrading-from-switchyard) before updating.

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
  `unreachable`, backed by a terminal routing rule if the table or its lookup
  disappears. This protects traffic received by the exit; it is not a
  device-wide kill switch when NetBird is disconnected or the exit is deselected.
- **Privilege split.** The panel has no capabilities and never touches the
  tunnel. It writes the chosen server name to a file. The applier re-validates
  that name against a catalogue it fetches directly from Mullvad. The panel
  cannot alter the catalogue. The applier is trusted: its namespace privileges
  can retrieve the live WireGuard key even though the config file is not mounted.
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

DNS remains under the client's/NetBird account's configuration. Check DNS and
IPv6 on each client before relying on the exit for privacy. A healthy server
probe cannot verify the client's complete traffic path.

## Documentation

1. [Prerequisites](docs/prerequisites.md): Mullvad, NetBird and host requirements.
2. [Setup](docs/setup.md): from a fresh clone to a working exit.
3. [Verification](docs/verification.md): prove it fails closed before trusting it.
4. [Operations](docs/operations.md): switching, dashboards, phones, failures, upgrades.
5. [Configuration](docs/configuration.md): every setting.
6. [Architecture](docs/architecture.md): routing contract, file contract, design choices.
7. [Authenticated access](docs/access.md): a complete SSH-forwarding example.
8. [Homelab test handoff](docs/homelab-testing.md): deploy and verify this pass.

## Prior art

Tailscale offers Mullvad exit nodes as a hosted integration; NetBird has no
equivalent. Community attempts to put Gluetun behind a mesh exit node broke the
return path and hit MTU stalls. Molebridge owns its policy routing and pins the
MTU instead. The WireGuard project's
[network namespace guidance](https://www.wireguard.com/netns/) informed the
fail-closed design.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install pytest==9.1.1 PyYAML==6.0.3
.venv/bin/python -m pytest -q panel tools
for script in routing/10-exit-routing applier/apply.sh tools/check-routing.sh; do sh -n "$script"; done
shellcheck -S warning routing/10-exit-routing applier/apply.sh tools/check-routing.sh
cp .env.example .env && docker compose config --quiet
```

On a disposable Linux host, `sudo sh tools/check-routing.sh` exercises IPv4
and IPv6 forwarding and fault handling in isolated namespaces without accounts
or real endpoints. CI also builds both derived images. These checks complement
the real NetBird/Mullvad client drills; they do not replace them.

The panel is Python standard library only. The bundled JetBrains Mono font is
under the SIL Open Font License (`panel/static/JetBrainsMono-OFL.txt`).
