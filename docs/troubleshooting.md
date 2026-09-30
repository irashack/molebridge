# Troubleshooting

Messages are quoted as the panel, `result.json` or the container logs print
them. For a full check of a running exit, use `python3 tools/molebridge.py
doctor` (Docker) or `podman exec <project>-applier python -m applier.apply
--doctor` (Podman).

Don't paste raw diagnostics into issues. They contain addresses, peer names
and sometimes keys. Never share the output of `wg showconf` or `wg show ...
dump`.

## Startup

**`wireguard` never gets healthy, and `wg-quick` fails with no clear error
(rootless Podman).** A rootless container can't load kernel modules. Load
`wireguard` on the host and make it persist, as shown in
[prerequisites](prerequisites.md#host), then recreate the project.

**`10-exit-routing: …` and the container exits.** The routing script checks
its settings before touching anything and names the one it rejected, for
example `OVERLAY_CIDR must use the network address` or `tunnel configuration
is missing (expected mullvad.conf under wg_confs)`. Fix `.env` or the tunnel
config and start again.

**NetBird logs `failed to create ipv4 raw socket: operation not permitted`.**
The `netbird` service needs `NET_RAW`. Docker grants it by default; Podman
does not. `compose.yaml` adds it, so this means a modified Compose file.

**NetBird's log stops at `NetBird gate: waiting for IPv4 and IPv6 routing
guards`.** NetBird won't start until both priority-97 routing guards exist in
the namespace, so the `wireguard` container didn't finish initializing. Check
its log first.

## The panel

**`421 unknown host; publish the panel under PANEL_PUBLIC_HOSTS`.** The
request's `Host` isn't loopback or listed in `PANEL_PUBLIC_HOSTS`. Add the
public hostname. If your proxy rewrites `Host` when it connects upstream (to
`host.docker.internal:8095`, for example), add that name and port too.

**`403 origin is not a published panel host` or `invalid or missing csrf
token` when switching.** The browser's `Origin` must be a listed host, and
the CSRF cookie must reach the panel. Check that the proxy passes cookies and
doesn't strip `Origin`, and that you opened the panel by the name listed in
`PANEL_PUBLIC_HOSTS`.

**"No fresh trusted relay catalogue; selections are unavailable."** The panel
can't read a catalogue less than 24 hours old. Either the applier hasn't
fetched one yet (give it a minute after first start), the provider's API is
unreachable from the exit, or the panel can't read `state/applier/`. The last
one usually means `PANEL_USER` is wrong: it must be `PUID:PGID` on Docker and
`0:0` on rootless Podman.

**The dashboard frame is blank.** Most often your proxy's session for the
panel's hostname has expired: open the panel directly once to sign in. (With
the panel's own [sign-in](#sign-in) the frame shows a "Signed out" page with a
link instead.) If
that doesn't help, check that `PANEL_FRAME_ANCESTORS` lists the dashboard's origin, and that the
dashboard and the panel are on the same site, so the browser sends the
proxy's cookie inside the frame.

**The status says "status stale" or "awaiting status".** The panel has no
usable result from the applier: none in the last 150 seconds, or one that is
malformed or dated in the future. Check that the `applier` container is
running and healthy, and that the host's clock is right.

## Sign-in

This applies only when `PANEL_OIDC_ISSUER` is set; see
[panel access](access.md#sign-in-with-openid-connect). Sign-in has not yet been
tested against a real identity provider, so this list comes from the code, not
from failures seen in use.

**The panel stops at start.** The last line of the container's log is the
setting it refused, with one of these messages (`<name>` is the setting):

- `<name> is set but PANEL_OIDC_ISSUER is not; set both or neither`, for
  `PANEL_OIDC_CLIENT_ID`, `PANEL_ACCESS`, `PANEL_ADMIN_GROUPS` or
  `PANEL_PUBLIC_URL`
- `PANEL_OIDC_ISSUER must be an https URL (http only for a loopback test issuer)`
- `PANEL_OIDC_CLIENT_ID is required with PANEL_OIDC_ISSUER`
- `PANEL_OIDC_CLIENT_SECRET_FILE cannot be read: <reason>` and
  `PANEL_OIDC_CLIENT_SECRET_FILE is empty`
- `PANEL_PUBLIC_URL must be the https origin people open, such as https://exit.example.net`
- `PANEL_OIDC_SCOPES must include openid`
- `PANEL_ADMIN_GROUPS: '<group>' is not a valid group name`
- `PANEL_ACCESS: entries are group=exit, with no spaces, commas or = in the group, in '<entry>'`
- `PANEL_ACCESS: '<exit>' is not an exit in PANEL_EXITS, in '<entry>'`. A
  single-exit panel has no exits to name, so use `PANEL_ADMIN_GROUPS` there.
- `With PANEL_OIDC_ISSUER set, PANEL_ADMIN_GROUPS or PANEL_ACCESS must name at least one group`
- `PANEL_SESSION_TTL must be a whole number of seconds` and
  `PANEL_SESSION_TTL must be between 300 and 604800 seconds`

**"Sign-in unavailable".** The page says "The identity provider could not be
reached. Try again in a minute." The panel couldn't read the provider's
discovery document. The log has a line `sign-in unavailable: <reason>`, such as
`discovery: the issuer could not be reached`, `discovery: the issuer answered
HTTP <code>`, or `discovery: the issuer in the discovery document does not
match PANEL_OIDC_ISSUER`. Check that the panel container can open an HTTPS
connection to the issuer and trusts its certificate, and that
`PANEL_OIDC_ISSUER` is written exactly as the discovery document's `issuer`.

**"Sign-in failed".** The page says "The sign-in could not be completed. Start
it again from the panel." The log has `sign-in failed: <reason>`. Common ones:

- `callback: this browser did not start a sign-in, or it expired`. The browser
  came back without a valid `__Host-molebridge_login` cookie: the sign-in took
  more than 10 minutes, the panel restarted meanwhile, the same return link
  was opened twice, cookies are blocked, or
  the browser began at a different address from `PANEL_PUBLIC_URL`. Start again
  from `PANEL_PUBLIC_URL`.
- `callback: the sign-in state does not match`. The return belongs to a
  different sign-in than the one this browser started last, for example from a
  second tab. Start again.
- `token: the issuer could not be reached`. The provider answered discovery but
  not the token request, so this shows as "Sign-in failed", not "Sign-in
  unavailable". Check the panel container's route to the issuer.
- `token: the issuer answered HTTP <code>`. The provider refused the code. Check
  that the redirect URL registered there is `PANEL_PUBLIC_URL` plus
  `/auth/callback`, exactly, and that the client is a public client (or that
  `PANEL_OIDC_CLIENT_SECRET_FILE` holds its secret).
- `token: the ID token was issued by another issuer` and `token: the ID token is
  for another client`. `PANEL_OIDC_ISSUER` or `PANEL_OIDC_CLIENT_ID` doesn't
  match what the provider put in the token.
- `token: the issuer sent no groups claim` or `userinfo: the issuer sent no
  groups claim` (with `groups` replaced by `PANEL_OIDC_GROUPS_CLAIM`). The
  provider isn't sending groups. Check that `PANEL_OIDC_SCOPES` includes the
  scope that adds them and that the client is allowed to use it.

**"Not allowed".** The page says "This account is not allowed to use this
panel." The log has `sign-in failed: access: this account is not in a group
that may use this panel`: the person's groups match neither
`PANEL_ADMIN_GROUPS` nor `PANEL_ACCESS`. Compare the group names exactly.
The same page appears, with `sign-in failed: access: the identity provider
refused the sign-in`, when the provider itself turned the person away.

**Someone changed groups and still sees the old exits.** A session keeps the
groups it was created with until it ends, at most `PANEL_SESSION_TTL` seconds
after sign-in. To apply a change now, restart the panel, which signs everyone
out, or have the person sign out and in.

**The dashboard shows "Signed out".** The panel session ended, or was never
started in this browser. Choose **Sign in**, which opens in a new tab, then
reload the dashboard.

## Switching

**"Tunnel handshake is missing or stale; check the account and
connectivity."** The provider isn't answering the tunnel. Possible causes:

- The Mullvad account ran out of time, or the device was removed from the
  account. Check the account page.
- The PIA subscription lapsed.
- Outbound UDP to the provider is blocked. Check the host's firewall and
  [the ports it needs](prerequisites.md#network).
- The selected server is down. If another server works, that's the cause.

**"Peer update failed; choose a server again to retry."** The applier couldn't
apply the server. With PIA, a rejected login or registration shows this way
too: check the files in `secrets/pia/` (one value per file, no extra
whitespace), then select the region again. If one PIA region keeps failing
while others work, the problem is on PIA's side.

**"Switch verification timed out; choose a server again to retry."** The peer
changed, but no handshake or provider-confirmed egress followed within about
a minute. Try again, or try another server.

**"No PIA region is registered yet; choose one in the panel."** It's a fresh
PIA install. Pick a region.

**"Waiting for a fresh trusted relay catalogue; request will retry
automatically."** The selection is saved and will be applied once the
applier has a current catalogue. If this persists, the provider's API is
unreachable from the exit.

**"Routing protection is incomplete; run the recovery helper."** A routing
rule or fallback route is missing, usually after part of the stack was
recreated. Run recovery (below).

## Clients

**Clients get no connectivity at all after you restarted or recreated
`wireguard` alone.** `netbird` and `applier` are still attached to the old
network namespace. Recreate all four containers together:
`python3 tools/molebridge.py recover` on Docker, or the Podman commands in
[operations](operations.md#rootless-podman).

**Everything works, but slowly: clients are relayed.** Run `netbird status
-d` inside the `netbird` container and look at `Connection type`. `Relayed`
has three common causes:

- **A phone with NetBird's "Force relay connection" setting on.** It's on by
  default on mobile; turn it off under Settings → Advanced.
- **The exit interface missing from the peer's ICE blacklist.** The log shows
  `ICE retries exhausted`. Doctor checks for this; the fix is in
  [setup](setup.md#5-keep-ice-off-the-tunnel-interface).
- **The exit on a private container bridge** with no reachable candidate. This
  is normal for rootless setups; see
  [exits on a private container network](operations.md#exits-on-a-private-container-network).

**A video call or download stalls after a few seconds, then sometimes
recovers.** One possible cause is path MTU: oversized replies whose ICMP error
never reaches the sender. Namespace step 6 in
[verification](verification.md#inside-the-namespace) checks for it; the ICMP
source sysctl and rule 94 must both be in place.

**The client shows its real IPv6 address.** Its IPv6 is bypassing the exit.
Check that the account has IPv6 overlay and that the exit has a `::/0` route.
NetBird is meant to block IPv6 on a client when it can't carry it, so if both
are missing and the client still leaks, disable IPv6 on that client and
check its NetBird version. See [verification](verification.md#from-a-client).

**Names don't resolve while the exit is selected.** Molebridge doesn't handle
DNS. The client keeps its own resolver. If that resolver is a private address
the client can only reach through the exit (for example, a server on the exit
host's LAN), the exit sends it into the tunnel, where it goes nowhere. Use a
resolver the client can reach directly, or NetBird's DNS settings.

**A device can't reach addresses on the exit host's LAN.** That's by design.
Forwarded traffic goes only into the tunnel.
