# Contributing

Issues and pull requests are welcome. Molebridge has one maintainer, so
reviews happen when there's time. For a suspected vulnerability, use the
private route in [SECURITY.md](SECURITY.md), not an issue.

## Ground rules

The project's rules are in [AGENTS.md](AGENTS.md); they apply to people as
much as to coding agents. Two matter most for a pull request. First, changes
to routing, the tunnel config, Compose networking or the applier need the
live checks in [verification](docs/verification.md), because CI can't tell
you that a real client fails closed. Second, update the docs your change
affects in the same pull request.

## Checks

```sh
python3 -m venv .venv
.venv/bin/pip install pytest==9.1.1 PyYAML==6.0.3
.venv/bin/python -m pytest -q panel tools

scripts="routing/molebridge-exit routing/10-exit-routing routing/wait-for-guards routing/contract-rules routing/gluetun-preflight applier/apply.sh tools/check-routing.sh tools/check-exit-image.sh"
for script in $scripts; do
  sh -n "$script"
done
shellcheck -x -S warning $scripts
docker compose --env-file .env.example config --quiet
docker compose --env-file .env.example -f compose.yaml -f compose.pia.yaml config --quiet
docker compose --env-file .env.example -f compose.yaml -f compose.nordvpn.yaml config --quiet
docker compose --env-file .env.example -f compose.gluetun.yaml config --quiet
```

On Linux with Docker and kernel WireGuard, two more need root or a privileged
container: the routing drills in throwaway namespaces, and the routing image's
life cycle (start, repair, tunnel loss, every stop). CI runs both:

```sh
sudo env ROUTING_SH="busybox sh" sh tools/check-routing.sh
docker build --tag molebridge-wireguard:dev --file routing/Dockerfile .
sh tools/check-exit-image.sh molebridge-wireguard:dev
```

The gluetun tests include two that check Molebridge's server selection
against gluetun's own bundled server list. They are skipped unless you point
them at `internal/storage/servers.json` in a checkout of gluetun v3.41.3:

```sh
GLUETUN_SERVERS_JSON=/path/to/gluetun/internal/storage/servers.json \
  .venv/bin/python -m pytest -q tools/test_gluetun_client.py -k reference_catalogue
```

CI also builds both images and checks what they contain; see
`.github/workflows/ci.yml`.

On a disposable Linux host, `sudo sh tools/check-routing.sh` runs the routing
failure drills in isolated network namespaces, with no accounts or real
endpoints. It needs `ip`, `ping`, `python3` and `nft`; without `nft` the native repair
drills fail, so install it and read any `SKIP` lines. With BusyBox, `mawk` and `gawk` installed it also runs the
NetBird gate's JSON reader under each awk. CI runs the same drills on every
push.

To work on the panel's look, `python3 tools/preview-panel.py` serves it on
`127.0.0.1:8099` against two fake exits, one Mullvad and one PIA. `--exits
mullvad,pia,nordvpn,mullvad-gluetun,surfshark` adds NordVPN and two exits on
the gluetun backend. Add `--live` to load the native providers' real server
lists, `--theme light` or `--style dashboard` to see the other looks, and
`--fail pia` to see a failed switch.
