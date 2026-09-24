# Verification

Run these on your own host before letting real traffic through the exit, and
again after changing routing, the tunnel config, compose networking or the
applier. [Testing](testing.md) records which of these checks have run, and on
which platforms.
Keep an independent host access path. Do not share raw addresses or peer
information from diagnostics. Never run `wg showconf`, `wg show ... dump` or
`wg show ... private-key` for a report: they disclose the live key.

## Inside the namespace

`applier` shares the exit's network namespace, so use it for inspection:

```sh
docker compose exec applier sh
```

1. **Rules are installed.** `ip rule` shows priority 90 (`iif mullvad`, overlay
   destination → `main`), 94 (`from` the tunnel's IPv4 address, `ipproto icmp`
   → table 51821), 95 (`iif wt0` → table 51821), 96 (`oif mullvad` → table
   51821), and 97 (`iif wt0 unreachable`). No temporary priority-80 guard
   should remain. IPv6 has 95/96/97 in all cases, 90 when `OVERLAY6_CIDR` is
   set, and 94 with `ipproto ipv6-icmp` when the tunnel has an IPv6 address.
   Rule 94 must carry the protocol qualifier: without it every protocol
   sourced from the tunnel address is forced into the tunnel, and the applier
   reports `routing_ok` false.
2. **The exit table fails closed.** `ip route show table 51821` shows
   `default dev mullvad` and `unreachable default ... metric 4096`. The same
   holds for `ip -6 route show table 51821` with an IPv6 tunnel config; an
   IPv4-only config still has the IPv6 unreachable fallback.
3. **The tunnel egresses through Mullvad.**
   `curl -4 -fsS --interface mullvad https://ipv4.am.i.mullvad.net/json` reports
   `"mullvad_exit_ip": true`. When the tunnel has an IPv6 address, so does
   `curl -6 -fsS --interface mullvad https://ipv6.am.i.mullvad.net/json`
   (`am.i.mullvad.net` itself has no AAAA record, so `-6` against it fails to
   resolve). Both probes must succeed; one family cannot stand in for the other.
4. **The exit's own traffic does not.** `curl -s https://am.i.mullvad.net/json`
   without `--interface` reports your host's normal IP. That is the path the
   Mullvad handshake and NetBird's own control connections take; it must stay
   off the tunnel.
5. **Trust boundary.** The panel can read `state/applier/relays.json` but cannot
   write the applier mount. The old panel-owned catalogue is ignored. A malformed
   desired file and a valid request for an unlisted name must report failure
   without changing the peer. A valid request has `server`, `requested_at`
   (current UTC `YYYY-MM-DDTHH:MM:SSZ`) and an optional 32-character lowercase
   hexadecimal `request_id`. Use a fictitious unlisted name such as
   `xx-xxx-wg-999`, then restore the desired state by selecting a valid server
   in the panel. `wg show mullvad peers` exposes only the public peer key.
6. **The exit's ICMP errors return through the tunnel.**
   `cat /proc/sys/net/ipv4/icmp_errors_use_inbound_ifaddr` prints `1`, and
   `ip route get 198.51.100.1 from <tunnel IPv4 address> ipproto icmp` shows
   `dev mullvad`; with an IPv6 tunnel address,
   `ip -6 route get 2001:db8::1 from <tunnel IPv6 address> ipproto ipv6-icmp`
   does too. Under client traffic that carries replies larger than the overlay
   MTU, `Icmp6OutPktTooBigs` in `/proc/net/snmp6` grows, and a capture on the
   tunnel interface (`icmp6 and ip6[40] == 2`) shows the errors leaving there
   and not on the host-side interface. Do not rely on `Ip6OutNoRoutes`: on a
   container network without IPv6 it also counts the exit's own IPv6
   attempts. Without this return path, oversized replies are dropped with no
   error to the origin, and UDP flows such as QUIC through the exit stall.
7. **Doctor.** On the host, `python3 tools/molebridge.py doctor` should pass.
   It checks actual namespace agreement as well as routing and status freshness.

## Fail-closed drills

For each drill, keep a client with the exit selected loading
<https://am.i.mullvad.net> or pinging a public IP. During the drill the client
must lose the tested exit path. It must **never** show your host's own IP. Test
IPv4 and IPv6 explicitly; a generic browser check may exercise only one family.
Also record any client fallback to its own connection: server routing cannot
enforce a device-wide kill switch after NetBird disconnects or deselects the exit.

| Drill | Break | Restore |
|---|---|---|
| Tunnel down | `docker compose exec wireguard wg-quick down /config/wg_confs/mullvad.conf` | `docker compose exec wireguard wg-quick up /config/wg_confs/mullvad.conf` |
| IPv4 route deleted | `docker compose exec wireguard ip route del default dev mullvad table 51821` | `docker compose exec wireguard ip route replace default dev mullvad table 51821` |
| IPv6 route deleted (when configured) | `docker compose exec wireguard ip -6 route del default dev mullvad table 51821` | `docker compose exec wireguard ip -6 route replace default dev mullvad table 51821` |
| IPv4 lookup rule deleted | `docker compose exec wireguard ip rule del priority 95` | `python3 tools/molebridge.py recover` |
| IPv6 lookup rule deleted | `docker compose exec wireguard ip -6 rule del priority 95` | `python3 tools/molebridge.py recover` |
| Container stopped | `docker compose stop wireguard` | `python3 tools/molebridge.py recover` |

After each restore, the client regains Mullvad egress. After the tunnel-down
drill, the applier re-applies a previously successful chosen server after the
interface returns. If a request was rejected or failed, select again to retry.
Confirm the exit host's own unbound traffic stays on its ordinary path while
the client path is blocked. The isolated `tools/check-routing.sh` drill also
deletes all exit-table routes together to exercise the terminal guard, and
checks that an oversized tunnel reply produces an ICMP error back over the
tunnel, that a missing return-path rule is detected, and that with the tunnel
route gone no error reaches the tunnel side. It does not watch the host-side
interface, so it cannot tell a dropped error from one sent over the host's
route; a capture on that interface during a live flow can (see step 6
above).
For each single-family route deletion, confirm the other family still works
while the next applier check reports `failed`, `/readyz` returns 503, and any
monitoring push reports failure. A safe black hole must not appear healthy.

## Status and recovery

Stop the applier while leaving the tunnel running. Within 150 seconds plus one
browser poll, the panel must show stale/unknown and `/readyz` must return 503;
`/healthz` remains 200. Restart the applier and confirm fresh status returns.
Disconnect an open browser from the panel and confirm its next failed poll
clears connected status. Test a failed switch followed by selecting the same
server again. Finally, verify the recovery helper, container recreation and
host reboot preserve the NetBird peer identity and shared namespace.
After a WireGuard restart outside Compose, confirm an applier stranded without
the WireGuard interface becomes Docker-unhealthy even if its failure result is
fresh. On a disposable deployment, start NetBird before the routing initializer:
its entrypoint must wait until both priority-97 guards exist in its namespace.
Repeat with a non-default `OVERLAY_IF` and confirm NetBird creates that interface.

Start with a saved desired selection, an expired catalogue and an unavailable
relay API. Confirm no peer change occurs and the result says the request will
retry. Restore the API and confirm the same request is applied automatically.
Malformed/unlisted requests and failed peer updates still require a new selection.

## From a client

With the exit selected on a device in `exit-users`:

- <https://mullvad.net/check> reports that you are using Mullvad, in the chosen
  server's city.
- Addresses on the host's own LAN, such as its router, are unreachable.
- **IPv6.** With IPv6 overlay and a `::/0` route, an IPv6 "what is my IP" check
  shows a Mullvad address. Without IPv6 overlay, check that IPv6 either fails or
  is unused; if a native IPv6 address shows, that traffic is bypassing the
  exit. Mobile carriers that are IPv6-only with NAT64 are the likeliest case.
- **Large UDP.** With the exit selected, a video call or an HTTP/3 (QUIC)
  download does not stall after the first seconds. Browsers fall back to TCP
  when QUIC breaks, so a stall that "fixes itself" is the symptom of a missing
  return path, not of a slow tunnel.
- **Direct path.** On the host, `docker compose exec netbird netbird status -d`
  lists the client with `Connection type: P2P`. `Relayed` adds the relay
  server's round trip to every packet; on a phone, first check that Force relay
  connection is off in the NetBird app. If every client is relayed, confirm the
  exit interface is in the peer's ICE blacklist
  ([setup](setup.md#5-keep-ice-off-the-tunnel-interface)) and look for
  `ICE retries exhausted` in `docker compose logs netbird`. A peer that has hit
  that state retries only hourly, so re-apply the flag and bring the peer back
  up rather than waiting. `python3 tools/molebridge.py doctor` checks the
  stored blacklist; no `netbird` command prints it.
- **Switch.** Choose a server in another city in the panel. The panel reports
  the new city within about a minute, and the client's egress follows without
  reselecting the exit.
- **DNS.** Molebridge does not change DNS; see
  [operations](operations.md#dns). Check that mullvad.net/check's DNS leak
  result is acceptable to you.
