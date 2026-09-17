# Verification

Run these on your own host before letting real traffic through the exit, and
again after changing routing, the tunnel config, compose networking or the
applier. They are the checks run on the author's deployment. None of them print
secrets.

## Inside the namespace

`applier` shares the exit's network namespace, so use it for inspection:

```sh
docker compose exec applier sh
```

1. **Rules are installed.** `ip rule` shows priority 90 (overlay range → `main`),
   95 (`iif wt0` → table 51821) and 96 (`oif mullvad` → table 51821). With
   `OVERLAY6_CIDR` set, `ip -6 rule` shows the same.
2. **The exit table fails closed.** `ip route show table 51821` shows
   `default dev mullvad` and `unreachable default ... metric 4096`. The same
   holds for `ip -6 route show table 51821`.
3. **The tunnel egresses through Mullvad.**
   `curl -s --interface mullvad https://am.i.mullvad.net/json` reports
   `"mullvad_exit_ip": true`.
4. **The exit's own traffic does not.** `curl -s https://am.i.mullvad.net/json`
   without `--interface` reports your host's normal IP. That is the path the
   Mullvad handshake and NetBird's own control connections take; it must stay
   off the tunnel.
5. **Unlisted servers are refused.** Outside the container, write a server name
   that is not in `state/panel/relays.json` into `state/panel/desired.json`
   (for example `{"server": "xx-xxx-wg-999"}`). `docker compose logs applier`
   shows `not in the relay allowlist; ignoring`, and `wg show mullvad` still
   lists the old peer. Restore the file afterwards by picking a server in the
   panel.

## Fail-closed drills

For each drill, keep a client with the exit selected loading
<https://am.i.mullvad.net> or pinging a public IP. During the drill the client
must lose Internet access. It must **never** show your host's own IP.

| Drill | Break | Restore |
|---|---|---|
| Tunnel down | `docker compose exec wireguard wg-quick down /config/wg_confs/mullvad.conf` | `docker compose exec wireguard wg-quick up /config/wg_confs/mullvad.conf` |
| Route deleted | `docker compose exec wireguard ip route del default dev mullvad table 51821` | `docker compose exec wireguard ip route replace default dev mullvad table 51821` |
| Container stopped | `docker compose stop wireguard` | `docker compose up -d`, then `docker compose restart netbird applier` |

After each restore, the client regains Mullvad egress. After the tunnel-down
drill, the applier re-applies the panel's chosen server within a few seconds.

## From a client

With the exit selected on a device in `exit-users`:

- <https://mullvad.net/check> reports that you are using Mullvad, in the chosen
  server's city.
- Addresses on the host's own LAN, such as its router, are unreachable.
- **IPv6.** With IPv6 overlay and a `::/0` route, an IPv6 "what is my IP" check
  shows a Mullvad address. Without IPv6 overlay, check that IPv6 either fails or
  is unused; if a native IPv6 address shows, that traffic is bypassing the
  exit. Mobile carriers that are IPv6-only with NAT64 are the likeliest case.
- **Switch.** Choose a server in another city in the panel. The panel reports
  the new city within about a minute, and the client's egress follows without
  reselecting the exit.
- **DNS.** Switchyard does not change DNS; see
  [operations](operations.md#dns). Check that mullvad.net/check's DNS leak
  result is acceptable to you.
