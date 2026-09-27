# Switchyard: one panel for several exits

Switchyard is Molebridge's control panel, the page where you pick a server.
Every Molebridge stack runs one for its own exit. If you run more than one exit
on the same host, for example a Mullvad exit and a PIA exit, one Switchyard can
serve all of them:

- one tab per exit, showing its state and where it currently exits;
- each exit in its provider's layout: Mullvad's country, city and relay tree,
  or PIA's flat region list;
- each exit in its provider's colours, unless `PANEL_STYLE=dashboard`.

Nothing about the privilege split changes. The panel still holds no
capabilities and runs no subprocesses. For each exit it reads that exit's
`state/applier` read-only and writes only that exit's `state/panel/desired.json`,
the file the exit's own panel writes. Each exit's applier still validates every
request against its own catalogue. A selection is checked against the
catalogue of the exit it names, so a relay from one provider can never be sent
to another exit.

## Configure it

`PANEL_EXITS` lists the exits, comma-separated, as `id=provider[:label]`:

```sh
PANEL_EXITS=mullvad=mullvad:Mullvad,pia=pia:PIA Chicago
```

- `id`: 1–32 of `a-z`, `0-9` and `-`. It appears in URLs (`/?exit=pia`) and
  names the exit's state directory, `$STATE_DIR/<id>`.
- `provider`: `mullvad` or `pia`.
- `label`: optional, the tab's name (at most 40 characters). It defaults to
  the provider's name.

The panel refuses to start with a malformed entry. Without `PANEL_EXITS` it
serves one exit from `$STATE_DIR/panel` and `$STATE_DIR/applier`, as before.

## Run it

Run Switchyard as one more container beside your exits, mounting each exit's
state directories under `/state/<id>`. This example assumes two Molebridge
checkouts, `/srv/molebridge-mullvad` and `/srv/molebridge-pia`, each already
set up as described in [setup](setup.md):

```yaml
# /srv/switchyard/compose.yaml
name: switchyard
services:
  panel:
    image: docker.io/library/python:3.14.7-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2
    restart: unless-stopped
    user: "1000:1000"          # the owner of both state trees; 0:0 under rootless Podman
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    working_dir: /app
    command: ["python", "/app/panel/app.py"]
    environment:
      STATE_DIR: /state
      PANEL_EXITS: "mullvad=mullvad:Mullvad,pia=pia:PIA"
      PANEL_PUBLIC_HOSTS: switchyard.example.net
      PYTHONDONTWRITEBYTECODE: "1"
    ports:
      - "127.0.0.1:8098:8080"   # loopback only; publish through an authenticating proxy
    volumes:
      - /srv/molebridge-mullvad/panel:/app/panel:ro
      - /srv/molebridge-mullvad/molebridge:/app/molebridge:ro
      - /srv/molebridge-mullvad/state/panel:/state/mullvad/panel
      - /srv/molebridge-mullvad/state/applier:/state/mullvad/applier:ro
      - /srv/molebridge-pia/state/panel:/state/pia/panel
      - /srv/molebridge-pia/state/applier:/state/pia/applier:ro
```

The panel code comes from one checkout. The version doing the serving must
include multi-exit support, but the exits themselves can run any version with
the same state-file contract.

Each exit's own panel keeps working. Both panels write the same `desired.json`,
so whichever posted last wins, as with two people using one panel. Stop an
exit's own `control-panel` container if you want Switchyard to be the only way
in.

## Pages and endpoints

| Path | What it serves |
|---|---|
| `/?exit=<id>` | The full page for one exit. Without `?exit=`, the exit this browser last opened, or else the first listed. |
| `/embed?exit=<id>` | The compact view for a dashboard iframe. The tabs switch within the frame. |
| `/api/exits` | Every exit's `id`, `label`, `provider`, `state`, `status` and `place` (where it exits, when connected). |
| `/api/status?exit=<id>`, `/api/latency?exit=<id>` | As for a single-exit panel, for the named exit. |
| `/readyz` | 200 only when every exit is connected and verified; `/readyz?exit=<id>` checks one. |

An unknown exit id gets 404. Saved servers, recent servers and filters are
kept per exit in the browser.

## Access

The rules in [authenticated access](access.md) apply unchanged. Anyone who can
reach Switchyard can switch every exit it lists, so it needs at least the
access restriction of the most restricted exit.
