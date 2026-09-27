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

for script in routing/10-exit-routing routing/wait-for-guards applier/apply.sh tools/check-routing.sh; do
  sh -n "$script"
done
shellcheck -S warning routing/10-exit-routing routing/wait-for-guards applier/apply.sh tools/check-routing.sh
docker compose --env-file .env.example config --quiet
docker compose --env-file .env.example -f compose.yaml -f compose.pia.yaml config --quiet
```

On a disposable Linux host, `sudo sh tools/check-routing.sh` runs the routing
failure drills in isolated network namespaces, with no accounts or real
endpoints. It needs `ip`, `ping`, `python3` and `nft`. Without `nft` the PIA
port-forwarding drill is skipped and the script still passes, so install it.
CI runs the same drills on every push.

To work on the panel's look, `python3 tools/preview-panel.py` serves it on
`127.0.0.1:8099` against two fake exits, one Mullvad and one PIA. Add `--live`
to load the providers' real server lists, `--theme light` or `--style
dashboard` to see the other looks, and `--fail pia` to see a failed switch.
