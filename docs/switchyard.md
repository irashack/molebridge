# Switchyard, the panel

Switchyard is the web page where you pick the exit's server. Every Molebridge
stack runs one on `127.0.0.1:8095` (`PANEL_PORT`). One Switchyard can also
serve several exits on the same host; see
[several exits in one panel](#several-exits-in-one-panel).

By default it has no login. Put it behind [authenticated access](access.md)
before anyone else can reach it, or turn on its
[OpenID Connect sign-in](access.md#sign-in-with-openid-connect).

## Switching

The page has three parts:

- **The current exit.** It shows the server or region, the egress address and
  a state:

  | State | Meaning |
  |---|---|
  | connected | Verified in the last 150 seconds |
  | switching | A switch is running |
  | failed | The last switch failed |
  | unknown | Status is stale or unavailable |

  A connected exit whose egress was verified only by Molebridge's own tunnel
  checks, because its provider has no check of its own, also shows "tunnel
  checks only"; Diagnostics says which check passed
  ([status reporting](architecture.md#status-reporting)).

- **Fastest from …** lists the lowest-latency places, each with a Switch
  button.
- **Locations** lists everything the provider offers. Press `/` to search it.
  Mullvad and NordVPN locations are grouped by country, then city, then
  server; NordVPN servers in its virtual locations are marked "virtual". PIA
  shows one flat list of regions, marked PF for port forwarding and "virtual"
  for PIA's virtual locations.

A switch takes two taps: the first arms the button, and the second confirms
it within eight seconds. Escape, or moving focus away, cancels. Without
JavaScript a single tap submits.

The applier then changes the tunnel and waits for a fresh handshake and for
the provider to confirm the new egress. That normally takes a few seconds. The
page shows which server it is leaving and for how long it has been switching,
and gives up after about a minute. Every device using the exit moves together,
and connections open through the exit drop.

If a switch fails, press **Retry** or pick something else;
[troubleshooting](troubleshooting.md#switching) explains each message. A
failed check doesn't always mean traffic stopped: the previous or new tunnel
may still be carrying it. What can't happen is forwarded traffic leaving
through the host's own connection. Molebridge also never moves to another
server by itself. With PIA, choosing the region you're already on registers
again; PIA may pick the same server.

Some parts appear only once they're useful:

- **Saved**, once you pin a server with the star, or once this browser has
  used more than one. It is stored in the browser, not on the exit.
- **Fastest: …**, at the top of an opened country, once every server in it
  has been measured, or in a large country every server in its sample.
- **Filters**, next to Locations. For Mullvad the filters are Mullvad-owned
  and RAM-only servers; for PIA, port forwarding. A filter shows only when it
  would narrow the list.

## Latency

The numbers are TCP connection times from the exit host to each server's port
443. That's your host's round trip to the provider, not the latency through
the tunnel. Nothing is measured unless someone has the page open:

- on load, one server per city, plus the current and saved servers;
- when you open a country, every server in it, up to 128. A larger country
  (NordVPN has some) is timed on a sample of 128: the lowest-load servers,
  one city at a time in turn, the same sample every time. The country's
  summary then says how many were timed;
- when a search narrows to 64 servers or fewer, those servers;
- when you press Retest, the per-city check again, bypassing the cache.

Results are cached for 15 minutes. One page sends one latency request at a
time. The panel runs one per exit and four in all; a request beyond that is
answered 429 and the page tries again a few seconds later.

## The server list

The applier downloads the provider's server list at startup and every six
hours, and keeps the last good copy if a download fails. A list older than 24
hours can't authorize a switch. The panel only reads the applier's copy; it
can't change it.

## Looks

By default each exit is drawn in its provider's colors, using system fonts:

- Mullvad: navy and yellow;
- PIA: charcoal and green, with a ring around the current flag that shows the
  state.

`PANEL_STYLE=dashboard` switches to a neutral monospace look that matches
Glance-style dashboards. `PANEL_THEME` picks light, dark, or `auto` (follow the
viewer's system). All animation stops when the system asks for reduced
motion.

## Embedding in a dashboard

`/embed` is a compact view for iframe widgets. Allow your dashboard's origin
to frame it:

```sh
PANEL_FRAME_ANCESTORS=https://dashboard.example.net
```

For Glance or Dynacat:

```yaml
- type: iframe
  title: Exit
  title-url: https://exit.example.net
  source: https://exit.example.net/embed
  height: 460
```

If your proxy signs people in with a session cookie, the frame needs a live
session for the panel's hostname. When the session has expired the frame is
blank; open the panel directly once to sign in. The dashboard and the panel
must be on the same site (two subdomains of `example.net`, for example), or
the browser won't send that cookie inside the frame.

With the panel's own sign-in on, an expired session doesn't leave the frame
blank: it shows a small "Signed out" page with a **Sign in** link that opens in
a new tab, because the identity provider can't be shown inside a frame. Sign
in there, then reload the dashboard. The same-site requirement applies to the
panel's session cookie too. See
[access](access.md#in-a-dashboard-frame).

## On a phone

The panel can be installed as an app. On iPhone, open it in Safari and choose
Share → Add to Home Screen. On Android, use the browser's Install app option.
It opens full screen and refreshes its status whenever you return to it.

On iOS a home-screen app keeps its cookies separate from Safari. It signs in
to your proxy on its own the first time, and again whenever that session
expires. This has been tested with a passkey sign-in through NetBird's
reverse proxy.

## Several exits in one panel

If you run more than one exit on a host, for example a Mullvad exit and a PIA
exit, one Switchyard can serve them all. It shows one tab per exit, with the
exit's state and where it currently exits, and each exit keeps its own
provider's layout.

The privilege split is the same as with one exit. The panel holds no
capabilities, reads each exit's `state/applier` read-only, and writes only
that exit's `state/panel/desired.json`. A selection is checked against the
server list of the exit it names, so one provider's server can't be sent to
another exit.

List the exits in `PANEL_EXITS`, comma-separated, as `id=provider[:label]`:

```sh
PANEL_EXITS='mullvad=mullvad:Mullvad,pia=pia:PIA Chicago'
```

- `id` is 1–32 characters of `a-z`, `0-9` and `-`, starting with a letter or
  digit. It appears in URLs (`/?exit=pia`) and names the exit's state
  directory, `$STATE_DIR/<id>`.
- `provider` is `mullvad`, `pia` or `nordvpn`.
- `label` is optional (40 characters at most). It defaults to the provider's
  name.

The panel refuses to start if an entry is malformed. Without `PANEL_EXITS` it
serves a single exit from `$STATE_DIR/panel` and `$STATE_DIR/applier`.

Run it as one more container beside the exits, mounting each exit's state
under `/state/<id>`. This example assumes two exits already set up in
`/srv/molebridge-mullvad` and `/srv/molebridge-pia`:

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

The panel code comes from one checkout. That checkout must include
multi-exit support, but the exits themselves can run any revision with the
same state-file format.

Each exit's own panel keeps working. Both write the same `desired.json`, so
whichever posted last wins. You can stop an exit's own `control-panel`
container, but recovery and upgrades start it again.

With several exits, every page and API call names its exit. `/` redirects to
`/?exit=<id>` for the exit this browser last opened, and `/api/exits` returns
every exit's state for the tabs. `/readyz` returns 200 only when all exits are
connected; `/readyz?exit=<id>` checks one. The full list is in
[configuration](configuration.md#panel-endpoints).

Without sign-in, anyone who can reach this panel can switch every exit it
lists. Give it at least the access restrictions of the most restricted exit,
or use sign-in to give people different exits.

### Per-person exits

With [OpenID Connect sign-in](access.md#sign-in-with-openid-connect), one panel
can show each person only their own exit. Give each person an exit, list the
exits in `PANEL_EXITS`, and grant each group its exit with `PANEL_ACCESS`, as
`group=exit` pairs:

```sh
PANEL_EXITS='alice=mullvad:Alice,bob=pia:Bob'
PANEL_ACCESS='alice-exit=alice,bob-exit=bob'
PANEL_ADMIN_GROUPS=exit-admins
PANEL_OIDC_ISSUER=https://id.example.net
PANEL_OIDC_CLIENT_ID=switchyard
PANEL_PUBLIC_URL=https://exit.example.net
```

Someone in `alice-exit` sees only the Alice exit and can switch only that one.
Repeat a group to grant it several exits (`family=alice,family=bob`). Members
of `exit-admins` see every exit. The Bob exit is not merely hidden from Alice:
asking for it gets the same answer as an exit that doesn't exist.

The groups live at your identity provider, and the panel reads them at
sign-in, so a change there takes effect within `PANEL_SESSION_TTL`; see
[sessions and lockout](access.md#sessions-and-lockout). `PANEL_ACCESS`
only controls who may use the panel. Which devices send traffic to which exit
is still set in NetBird, and switching an exit still moves every device that
uses it.
