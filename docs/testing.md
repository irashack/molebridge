# Testing

This page records tests on real hosts and the gaps that remain. Unit tests
and isolated Linux namespace drills in CI do not establish that a whole
NetBird deployment works with any provider or backend.

Published hashes below map to identical trees from before the metadata-only
history rewrite: `ae95c33` → `1390860`, `984a703` → `336d904`, and
`afa8594` → `4739352`; their quoted CI runs used the old hashes. The panel
switcher revisions were replaced by a rebase merge, also with identical trees:
`07c7b41` → `56ac2cc` and `0d518e4` → `40c461c`.

## macOS / OrbStack pass

Apple silicon, self-hosted NetBird 0.78, simulated client routing plus one real
phone. Steady-state fail-closed behavior held in every drill for both
families. The pass found six defects, all fixed in `1390860` through
`336d904`: a single-family tunnel-route loss reported healthy; the applier
stayed healthy in an orphaned namespace; `OVERLAY_IF` was not passed to
NetBird; a transient start-up failure consumed the saved selection; NetBird
preceded the routing guards only by timing; and the exit's ICMP errors for
oversized tunnel replies left over the host's route, so UDP (QUIC) through the
exit stalled.

## Rootless Podman pass

Revision `336d904` on Debian 13 / rootless Podman 5.4.2 / podman-compose 1.6.0
on amd64, NetBird client 0.79 against a self-hosted 0.79 management server,
through a Compose file carrying the same services and settings as
`compose.yaml`. Checked live, inside the namespace and from one iPhone client:

- Rules 90/94/95/96/97 present for both families with the `ipproto` qualifier
  on 94 and ahead of NetBird's own rules; `default dev mullvad` plus the
  unreachable fallback in the exit table for both families.
- ICMP from the tunnel address resolves to the tunnel interface for both
  families, while UDP from the same address takes the host path (the point of
  narrowing rule 94).
- Applier `--doctor`: recent check, routing protection, fresh catalogue and
  verified Mullvad egress all PASS; per-family egress probes succeed.
- Real client: mullvad.net/check clean, exit follows a server switch,
  direct (P2P) path once the peer carried the interface blacklist, a
  published UDP port and an external address mapping (see
  [operations](operations.md#exits-on-a-private-container-network)); without
  them every client was relayed.
- Recreation: a forced recreation of all four containers preserved the peer
  identity and rejoined the shared namespace.
- CI green at `336d904` (run on its pre-publication hash).

Found and fixed while adding Podman support: Docker-only Compose settings, the
missing `NET_RAW` capability, the panel user under uid remapping, the missing
kernel module autoload, and the interface blacklist as a requirement rather
than a tip (`4739352` through `336d904`).

## Live client and reboot pass at `5a6e0b5`

2026-09-24, the same Debian 13 / rootless Podman 5.4.2 / podman-compose 1.6.0
host, NetBird 0.79.0 client and self-hosted server. The client was a separate
NetBird 0.79.0 Linux peer (a container on another machine) with the exit
selected, probing IPv4 and IPv6 egress against `am.i.mullvad.net` about every
two seconds, 781 probes in all. Each family's probe used a pinned address, so a
failed family could not take the other's name resolution down with it.

**Fail-closed with the client on the exit.** All six drills from
[verification](verification.md#fail-closed-drills):

| Drill | Client during the drill | Status | After restore |
| :--- | :--- | :--- | :--- |
| Tunnel down | both families failed | — | Mullvad egress on both |
| IPv4 route deleted | IPv4 failed, IPv6 on Mullvad | `/readyz` 503 within 60 s, applier `failed` | Mullvad egress on both |
| IPv6 route deleted | IPv6 failed, IPv4 on Mullvad | `/readyz` 503 within 25 s | Mullvad egress on both |
| IPv4 lookup rule deleted | IPv4 failed, IPv6 on Mullvad | `/readyz` 503 within 45 s | recovered by recreating all four |
| IPv6 lookup rule deleted | IPv6 failed, IPv4 on Mullvad | `/readyz` 503 within 40 s | recovered by recreating all four |
| `wireguard` stopped | both families failed | — | recovered by recreating all four |

No probe returned a non-Mullvad address during any drill, and the exit host's
own traffic kept its ordinary path throughout.

**Reboot.** The host was rebooted with the client still selected. The
lingering boot unit brought the project up without intervention: all four
containers healthy 76 seconds after boot, one shared namespace, doctor 4×
PASS, the same peer identity, and `mullvad` still in the ICE blacklist. The
client failed closed for the whole outage (the NetBird client kept the exit
selected while the peer was offline) and regained Mullvad egress on its own.
A tunnel-down drill after the reboot failed closed.

**LAN isolation.** Through the exit, the client could not reach the exit
host's router (ICMP, TCP 80), the host itself (TCP 22), or the gateway of the
exit's container network. The host reached the same router and port directly,
so the targets were live.

**Oversized replies.** IPv6 replies larger than the overlay MTU made the exit
send ICMPv6 Packet Too Big (MTU 1280) out of the tunnel interface, sourced from
the tunnel address; a capture on the host-side interface saw no ICMP error
leave there. The public servers used ignore Packet Too Big for echo replies,
so that flow did not recover end to end. HTTP/3 (QUIC) requests through the
exit completed on both families to three large sites, but none of them sent
a datagram above 1280 bytes, so no live UDP flow exceeded the overlay MTU.

**Client fallback.** Deselecting the exit on the client sent its IPv4 traffic
out of the client's own connection at once. That is the documented boundary
in the README: server routing is not a device-wide kill switch.

## Clean install from the published files

2026-09-24, a fresh clone of `5a6e0b5` from GitHub on the same host, with the
bundled `compose.yaml` unchanged and only `.env` edited (project name, overlay
ranges, `PUID`/`PGID`, `PANEL_USER=0:0`, panel port, `NB_HOSTNAME`,
`NB_MANAGEMENT_URL`). A new peer enrolled with a fresh setup key; the tunnel
config came from an existing device while that device's other exit was
stopped. Following [setup](setup.md) with the
[rootless Podman commands](operations.md#rootless-podman):

- Build and start: all containers healthy, routing log `rules installed`, the
  three namespace users identical. podman-compose puts the project in its
  default pod; that works, no `x-podman` setting is needed.
- `NB_EXTRA_IFACE_BLACKLIST` put `mullvad` in the ICE blacklist at the first
  enrollment.
- [Namespace checks](verification.md#inside-the-namespace) 1 to 4 and 6 pass;
  doctor 4× PASS. The panel serves `/` and `/readyz`.
- The documented upgrade sequence (pull, build, recreate all four) left all
  four healthy in one namespace with the same peer identity, doctor passing.

This instance carried no client route and had no boot unit; the client and
reboot results above come from the long-running deployment.

**Fixed after the pass.** The panel did not exit on `SIGTERM`: as the
container's PID 1 without a handler it ignored the signal, so every stop waited
for the engine's 10-second timeout and then killed it. The panel now handles
`SIGTERM` and exits cleanly; this is a panel-only change, with routing, the
applier and Compose unchanged from `5a6e0b5`.

## Panel switcher pass at `56ac2cc` and `40c461c`

2026-09-25, the same Debian 13 / rootless Podman host, with each revision
deployed by pinning it in the owner's deployment tooling. That tooling
recreates all four containers on every pin change. Routing, the tunnel
configuration and Compose networking are unchanged from `b4cf640`.

At `56ac2cc`:

- Doctor 4× PASS before and after the deployment. All four containers were
  healthy, and the applier shared the WireGuard namespace.
- The live relay catalogue carried `owned`, `stboot` and `provider` with the
  expected types on every active relay: 536 relays, 113 Mullvad-owned, and
  all reported RAM-only at the time. Inactive relays were excluded as before.
- Panel in Chromium through an SSH forward:
  - Saved stayed hidden until a server was pinned.
  - The Mullvad-owned filter narrowed the list.
  - An opened country showed its Fastest row.
  - Escape cancelled an armed switch.
  - Both themes rendered correctly at desktop width and at 390 px.
- One switch to another server in the same city showed switch progress and
  reached connected about 2.4 s after the confirming click.

**Fixed after the pass**, in `40c461c`:

- a RAM-only filter that hid nothing, because every relay was RAM-only;
- a Switch button offered for the server a switch was already moving to;
- the current-exit line wrapping after its separator on a phone;
- the Diagnostics arrow spacing;
- browsers requesting a missing `/favicon.ico`.

At `40c461c`: doctor 4× PASS before and after, the exit returned on the same
server, and the catalogue refreshed. The page offered only the Mullvad-owned
filter, declared its icon, and made no `/favicon.ico` request. It showed no
console errors and kept the address together when the line wrapped, in both
themes.

Not tested live:

- the Switch-button fix, which needs a switch in progress;
- Retry, since no switch failed;
- fixed `PANEL_THEME=light` and `dark`, since only `auto` was used;
- screen readers beyond the announcement text;
- phone clients.

## PIA pass at `0165147`

2026-09-27, the same Debian 13 / rootless Podman 5.4 / podman-compose 1.6 /
amd64 host, NetBird 0.79 self-hosted, as a second deployment beside the Mullvad
exit with `PROVIDER=pia`, its own peer and port forwarding off. The tunnel key
came from `tools/prepare-tunnel-config.py --pia`; the PIA login had two-factor
authentication on.

- First start: the applier minted a token, registered the key in the seeded
  region, and reported healthy with PIA confirming the egress. Doctor 4× PASS.
  The applier logged nothing; the login and token appear in no state file.
- Namespace, observed 2026-09-27 on this exit: IPv4 holds rules 90, 94, 95,
  96 and 97, with rule 94 naming the PIA-assigned address. IPv6 holds rules
  90, 95, 96 and 97, with no rule 94. Table 51821 holds the tunnel default
  for IPv4 and only the unreachable fallback for IPv6. The tunnel has one
  IPv4 address and no global IPv6 address; `inet molebridge_guard` sits beside
  NetBird's own iptables tables. The host has the `nf_tables` and `wireguard`
  modules loaded.
- A full recreation of the four containers registered the saved region again
  with no intervention.
- A temporary Linux NetBird client selected the exit (`0.0.0.0/0` and `::/0`):
  PIA answered `connected: true` for its traffic, from an address other than
  the host's; IPv6 went to the exit and got no reply; the home LAN router and
  the host's LAN address did not answer.
- With the client holding the exit, `wg-quick down` in the WireGuard container
  left it with no response at all, never the host's address. After `wg-quick
  up`, the applier found no peer, registered the saved region again, and the
  client's traffic returned within ten seconds.
- Switching region and back through `desired.json` reached healthy each time
  on a new server with a new tunnel address, leaving exactly one address and
  one priority-94 rule.

Not tested live: port forwarding against PIA (the isolated drill covers the
nftables DNAT and the ingress guard); a PIA server forgetting the key mid-run;
a stale-catalogue period; phone clients.

## Switchyard pass at `4eda8ff`

2026-09-27, the same host, with one extra panel container serving the Mullvad
and PIA exits above (`PANEL_EXITS=mullvad=mullvad:Mullvad,pia=pia:PIA`),
published through an authenticating proxy and embedded in a dashboard. Both
exits stayed on their own revision, `b2a0a02`.

- `/api/exits` listed both exits connected, with their places. `/readyz`
  answered 200. `/` redirected to `/?exit=<id>`, each exit rendered in its
  provider's layout (Mullvad's tree, PIA's region list), and the embed carried
  the configured `frame-ancestors`.
- A selection posted through the proxy for each exit (its current location
  again) was written to that exit's `desired.json`, acknowledged by its
  applier, and verified connected within a minute. The other exit was
  untouched.
- Headless Chrome screenshots of the full page, a phone width and the embed,
  in both styles and both themes, including the armed and failed states, using
  `tools/preview-panel.py`. Stopping the panel under an open page turned every
  exit tab to "status unavailable" on the next poll.

Not tested live: a switch to a different location through Switchyard; phone
home-screen installation of the multi-exit page.

## Sign-in pass at `62a0170`

2026-10-01, the same host, one Switchyard serving four Mullvad and PIA exits
behind NetBird's reverse proxy (which also answers plain http), signing in
with a self-hosted Pocket ID v2.16.0 whose public name is fronted by
Cloudflare. Public client with PKCE, `PANEL_ADMIN_GROUPS` and a
`PANEL_ACCESS` group per exit.

- Signed out, through the proxy: `/readyz` answered 200 with no login; `/`
  over https and over plain http both answered 303 to the https `/login`;
  `/login` answered 303 to the provider's authorization endpoint with an S256
  challenge; `/api/status`, `/api/latency` and `POST /select` answered 401;
  `/readyz?exit=` gave the same 404 for every id, configured or not; `/embed`
  showed the sign-in link that opens a new tab.
- An admin signed in with a passkey in a browser and saw every exit. A switch
  on one exit was logged (`switch: user=… sub=… exit=… server=…`),
  acknowledged by that exit's applier under the same request ID, and verified
  connected one second after the request.
- Found and fixed during the pass: Cloudflare answered 403 to the panel's
  discovery request, because it refuses urllib's default `Python-urllib`
  agent (fixed in `a8fa497`); with four exits the tabs broke labels mid-word
  (fixed in `62a0170`, checked in headless Chrome at four widths and in the
  embed).

Not tested live: a sign-in by someone granted only some exits (the per-exit
refusals are covered by `panel/test_oidc.py`, 287 tests in all), a dashboard
frame after sign-in, and a phone.

## PIA registration retry at `8587542`

2026-10-07, the same host, the PIA exit. The host restarted while PIA's login
API answered 502 to every request, so the recreated tunnel's first
registration failed and the tunnel had no address. Before this change the
applier waited for an address that never came. Running `8587542` (the same
change as in 0.4.0), it retried the requested region, and the exit registered
and connected by itself after PIA's API recovered. The retry without an
address is covered by `tools/test_pia.py`.

## Routing and NetBird checks at `0f9511a`

2026-10-08, a PIA test exit on macOS with OrbStack (a Linux 7.0 kernel VM)
and Docker, a self-hosted NetBird server and the 0.79.0 client, with a Linux
NetBird client routed through it. First at `d00b52d`, then again at `0f9511a`.
0.4.1 changes only wording on top of `0f9511a`.

- Initialization installed the native rules, 1, 90 and 94 to 97 (no rule 94
  in IPv6, where PIA's tunnel has no address), and no rule 0; `recover` reinstalled them after recreating the containers, and
  `doctor` passed, including the NetBird settings, stored profile and kernel
  mode checks.
- The client's traffic left through PIA. TCP, UDP and ping from the client to
  the exit's own overlay address got no answer, while the same TCP connection
  made from inside the exit's namespace reached the listener.
- With the tunnel interface down, the client had no egress and a capture on
  the host interface showed no client packets.
- In the NetBird container itself (busybox), the startup checks accepted the
  enrolled default profile and refused it when `NB_INTERFACE_NAME` named a
  different interface than its stored one.

## NordVPN pass at `036e1cc`

2026-10-08, a test exit built from `036e1cc`: macOS, OrbStack, Docker, a
self-hosted NetBird server and the NetBird 0.79.0 client, `PROVIDER=nordvpn` with a NordVPN
account.

- `tools/nordvpn-key.py` exchanged a real access token for the account's
  NordLynx key and wrote the tunnel config with mode 0600.
- The applier's catalogue held 5,291 servers; `relays.json` was about
  1.48 MB.
- A selected server in one US city came up `ok` with `egress_tier`
  `provider`: NordVPN's insights check answered `protected: true` and named
  the city.
- A NetBird client routed through the exit egressed from that server.
- A switch to another server in the same city, which shares the location's
  key, was identified correctly by its endpoint.
- A switch to a server in Germany worked and was confirmed by NordVPN.
- Forwarded IPv6 had no egress: the exit table's IPv6 side held only the
  unreachable default.
- A TCP connection from the client to the exit's own overlay address was
  refused.

Not tested live: the insights cache-retry path, the `tunnel` egress tier, the
panel with the NordVPN catalogue, rootless Podman, and the fail-closed drills
in [verification](verification.md) on this provider. The later fixes on this
branch (the unverified IPv6 measurement in the tunnel tier, the snapshot size
limit and the bounded latency probing) are covered by unit tests, not by this
pass.

## gluetun backend pass at `a3bb14f`

2026-10-08, a test exit: Docker on OrbStack (a Linux 7.0 kernel VM on a
macOS host), gluetun v3.41.3 with NordVPN, a self-hosted NetBird server and
the NetBird 0.79.0 client, `compose.gluetun.yaml`. The final pass ran at
`a3bb14f`; earlier revisions of the same pass found these, each fixed
before it:

- the routing image's rule directory was not searchable without
  `DAC_OVERRIDE`, so the guard couldn't start;
- gluetun's built-in server list was stale, and the catalogue offered
  NordVPN's dedicated-IP servers, which an ordinary account can't use;
- a post-rule with a mark match broke gluetun's own iptables parser, so
  its old accepts piled up on every reconnect;
- gluetun's own established DNS-over-TLS connections left by the host
  interface when its tunnel went down (now rules 102–104);
- the kill switch blocked the kernel's check of the gateway route gluetun
  adds at start (now rule 103, added before 104).

Verified at `a3bb14f`:

- A NetBird client on a direct (P2P) connection routed through the exit,
  with provider-confirmed egress (NordVPN's insights check).
- A server switch through the panel's API.
- Traffic from the overlay to the exit's own addresses was not delivered.
- With the tunnel interface down, the client had no egress, and the host
  interface carried no client traffic and none of gluetun's own flows;
  only the kernel's ICMP port-unreachable replies to inbound UDP.
- NetBird's control traffic appeared only on the host interface.
- `tools/molebridge.py recover` recreated the stack, the applier put the
  last verified server back by itself, and `doctor` passed.

Not tested live: other providers through gluetun, rootless Podman, IPv6
through gluetun, gluetun restarting into a new namespace outside a drill,
and long-running stability. The fixes after `a3bb14f` (gluetun's role-file
check before it starts, and identifying the server by any of its addresses)
are covered by unit tests and drills, not by this pass.

## gluetun backend at `4933360`, and the standalone form

2026-10-08, the same test exit, rebuilt at `4933360`:

- gluetun started through the role-file check, every container became
  healthy, and `recover` and `doctor` passed. With `apikey` misspelled in the
  role file, gluetun refused to start with the check's fixed message, and the
  key appeared nowhere in gluetun's log; with the file restored, `recover`
  brought the exit back.
- With the applier and the panel stopped, as in
  [gluetun as a NetBird exit](gluetun-netbird-exit.md): the guide's checks 1 to
  4; deleting the exit-table route and deleting lookup rule 95 (guard stopped),
  restarting NetBird, and recreating gluetun, guard and NetBird, each with the
  client's probe failing during the break and nothing to or from the probe
  addresses on the host interface; local delivery refused; a server switch
  through gluetun's control server with the guide's `curl` commands.
- Observed: gluetun did not bring back a tunnel interface set down by hand
  within several minutes; recreating the containers did. NetBird in the
  namespace resolves names through gluetun's DNS, through the tunnel.

Not tested: rootless Podman, other providers, IPv6 through gluetun.

## NordVPN on rootless Podman at v0.5.0

2026-10-08, the same long-running Debian host with rootless Podman 5.8.6, a
native NordVPN exit (`compose.nordvpn.yaml`) at the release `v0.5.0`, run
as Quadlet units rather than through podman-compose.

- The after-deploy checks: every container healthy, the doctor's five
  `PASS` lines, NordVPN-confirmed egress.
- Namespace checks with no exit route enabled: forwarded IPv4 left only
  through the tunnel; forwarded IPv6, the exit's own overlay address and the
  LAN were never delivered or routed outside it; with the exit-table route
  deleted, forwarded traffic was unreachable.
- Then, with the route enabled, a phone used the exit on cellular over a
  direct (P2P) path for about 1 GB of traffic.

Not done on this host: the client-held fail-closed drills, and a DNS or IPv6
leak test from the phone.

## gluetun backend on rootless Podman at v0.5.0

2026-10-08, the same host, gluetun v3.41.3 with NordVPN, a self-hosted NetBird server, the release `v0.5.0`.
The four containers of `compose.gluetun.yaml` ran as Quadlet units rather
than through podman-compose, with the container's root remapped to another
host ID, on their own pasta network as in
[operations](operations.md#exits-on-a-private-container-network).

- gluetun, the guard, NetBird and the applier all became healthy.
- The applier verified the exit with NordVPN-confirmed egress.
- The exit peer enrolled and its exit routes were created.
- Found: with the container's root remapped, `secrets/gluetun/api_key` must
  belong to the container's root with mode `0600`; the applier refuses a
  group-readable copy. [Operations](operations.md#rootless-podman) now says
  so.

Not done on this host: traffic from a client through the exit, a switch
from the panel, the fail-closed drills, and podman-compose.

## Not yet tested

- The NetBird gate's other refusals (forced userspace modes, Rosenpass,
  foreground mode, other profiles and config paths) on a running peer. Unit
  tests and `tools/check-routing.sh` cover them; the NetBird settings were
  checked against the 0.79.0 source. A Mullvad exit and rootless Podman with
  these checks are untested.
- The [gluetun backend](architecture.md#gluetun-backend) beyond the passes
  [on Docker](#gluetun-backend-pass-at-a3bb14f) and
  [on rootless Podman](#gluetun-backend-on-rootless-podman-at-v050): other
  providers than NordVPN, client traffic and the drills on rootless Podman,
  podman-compose, IPv6 through gluetun, and gluetun restarting into a new
  namespace outside a drill. `tools/check-routing.sh`
  exercises the guard and gate in isolated namespaces with gluetun's rules
  98–101 and NetBird's 105/110 simulated; unit tests cover the scripts
  against a stand-in for iproute2 and the applier against fakes of the
  kernel and gluetun. The applier's request to gluetun clearing every other
  server filter was checked against gluetun's source, not a running gluetun.
  gluetun v3.41.3 and NetBird 0.79.0 behaviors the passes above did not
  exercise were read in their source.
- A live UDP flow whose datagrams exceed the overlay MTU, and an IPv4
  fragmentation-needed error on a live flow. The isolated CI drill covers both
  return paths; the live pass above shows the IPv6 error leaving through the
  tunnel.
- Fail-closed drills with a phone client. The drills above used a Linux
  client; a phone's NetBird client may fall back to its own connection
  differently while the exit peer is offline.
- Docker Engine on Linux, Docker Desktop, and NetBird Cloud, end to end.
- NordVPN beyond the passes [at `036e1cc`](#nordvpn-pass-at-036e1cc) and
  [on rootless Podman](#nordvpn-on-rootless-podman-at-v050): the insights
  cache retry (covered by `tools/test_nordvpn_applier.py`), the panel with
  NordVPN's catalogue, and the client-held fail-closed drills.
- The `tunnel` egress tier, live: FastestVPN, IVPN, Surfshark and Windscribe
  through gluetun use it, and none of them has had a live pass.
  `tools/test_egress.py` and the gluetun tests cover it.
- The panel's [OpenID Connect sign-in](access.md#sign-in-with-openid-connect)
  for someone granted only some exits (`PANEL_ACCESS`), live; any provider but
  Pocket ID; a confidential client; the userinfo fallback against a real
  provider; a phone's home-screen app signing in.

## Validating a new revision

Follow [backups](operations.md#backups) and [upgrades](operations.md#upgrades),
then run [verification](verification.md) on your host. Record:

- Date, revision, OS, architecture, container runtime and Compose versions.
- Provider, NetBird server and client versions, and client device types.
- Checks run, address families tested, pass/fail results, recovery timings and
  checks you skipped. Separate isolated namespace results from live client
  results.

Keep real hostnames, addresses, peer IDs, account numbers and keys out of the
record.
