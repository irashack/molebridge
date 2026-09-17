# Operations

## Switching servers

Open the panel. **Current exit** shows the chosen server, its egress IP, and a
status: connected, switching or failed. **Fastest from …** lists the
lowest-latency cities with a Switch button. **Locations** groups every Mullvad
WireGuard server by country and city, with a filter (press `/`).

A switch takes two clicks: the first arms the button, the second (within four
seconds) confirms. Without JavaScript a single click submits. The applier then
swaps the tunnel's peer and waits for a fresh handshake and a Mullvad-confirmed
egress, normally a few seconds. The panel follows along and refreshes when it
finishes.

Every device using the exit shares the one server, and open connections through
the exit drop at the switch.

If a switch fails (no handshake or no Mullvad egress within 60 seconds), the
panel shows **failed** with the reason, and the exit stays fail-closed: clients
have no Internet through it until another server is chosen. The applier never
picks a different server on its own.

## Latency

Numbers are the TCP handshake time from the exit host to each server's port 443.
That is the round trip your host adds on its way to Mullvad, not the latency
through the tunnel. They are measured only while a panel page is open:

- on page load, one server per city plus the current server;
- when you open a country, every server in it;
- when the filter narrows to 64 servers or fewer, those servers;
- when you press Retest, the per-city check again, ignoring the cache.

Results are cached in memory for 15 minutes. With no panel open, nothing is
measured.

## Relay list

The panel fetches Mullvad's published relay list on start and every six hours,
keeping only active WireGuard servers with a valid key and IPv4 address. If a
fetch fails, it keeps the last good list and shows the error.

## Embedding in a dashboard

`/embed` is a compact view (current exit, top five, locations) for iframe
widgets. Allow your dashboard's origin to frame it:

```sh
PANEL_FRAME_ANCESTORS=https://dashboard.example.net
```

For Glance or Dynacat:

```yaml
- type: iframe
  title: Mullvad Exit
  title-url: https://exit.example.net
  source: https://exit.example.net/embed
  height: 460
```

If your proxy authenticates with a session cookie, the frame needs a live
session for the panel's hostname. When it has lapsed the frame is blank; open
the panel directly once to sign in. The dashboard and the panel must be on the
same site (for example two subdomains of `example.net`) for the browser to send
that cookie inside the frame.

## Installing on a phone

The panel is an installable web app. On iPhone, open it in Safari and choose
Share → Add to Home Screen; on Android, use the browser's Install app option. It
opens full screen, and its status refreshes whenever you return to it.

On iOS a home-screen app keeps cookies separate from Safari, so it signs in to
your proxy on its own the first time and whenever that session expires. This
has been tested with a passkey sign-in through a NetBird reverse proxy.

## DNS

Switchyard leaves DNS alone. Clients keep resolving names with whatever
resolver they already use, while traffic leaves through Mullvad. A DNS leak
test may therefore show your usual resolver. On the author's iPhone with local
DNS, mullvad.net/check reported no DNS or WebRTC leak, but that depends on the
client and network.

Sending DNS through Mullvad instead would need a resolver inside the exit's
namespace forwarding to Mullvad's resolver over the tunnel, plus a NetBird
nameserver group. That would apply even when the exit is not selected, and DNS
would fail whenever the tunnel is down. Switchyard does not provide it.

## Health

The applier rewrites `state/applier/result.json` about every minute. Status is
`ok` only when the handshake is under three minutes old, the egress is
confirmed Mullvad, and the unreachable fallback is present. Otherwise it is
`failed` with a reason; if both egress and handshake fail, the reason says the
Mullvad account may have expired.

To feed monitoring, set `GATUS_URL` and `GATUS_ENDPOINT` in `.env` and put
`GATUS_TOKEN=` followed by the token in `secrets/applier.env` (mode 0600). The
applier pushes each result to that Gatus external endpoint.

## Restarts

`wireguard` owns the network namespace. When it restarts, `netbird` and
`applier` are left in the old, dead namespace: their healthchecks fail but Docker
does not restart unhealthy containers on its own. Restart them:

```sh
docker compose restart netbird applier
```

or run a watchdog that restarts unhealthy containers. The author's deployment
uses one; recovery took about nine minutes with the exit fail-closed the whole
time.

## Upgrades

Images are pinned by version and digest in `compose.yaml`. After updating a
pin:

```sh
docker compose pull
docker compose up -d
docker compose restart netbird applier
```

Recreating `wireguard` interrupts the exit for about 30 seconds. The applier
re-applies the chosen server afterwards. Rerun the
[namespace checks](verification.md#inside-the-namespace) after changing the
WireGuard or NetBird image.

## Rotating the Mullvad key

Generate a new configuration for a new device on mullvad.net, run
`tools/prepare-tunnel-config.py` on it, then:

```sh
docker compose up -d --force-recreate wireguard
docker compose restart netbird applier
```

Once the exit works, remove the old device on mullvad.net.

## Removing

1. Delete the exit route and access policy in NetBird.
2. `docker compose down` (add `-v` to also delete the peer's identity volume).
3. Delete the peer in NetBird and the device on mullvad.net.
4. Delete `tunnel/wg_confs/mullvad.conf` and `secrets/`.
