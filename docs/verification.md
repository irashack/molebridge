# Verification

Run these on your own host before relying on the exit, and again after
changing routing, the tunnel config, Compose networking or the applier.
[Testing](testing.md) records which checks have run and on which platforms.

Keep an independent host access path. Do not share raw addresses or peer
information from diagnostics. Never run `wg showconf`, `wg show ... dump` or
`wg show ... private-key` for a report: they disclose the live key.

Commands use the defaults: tunnel interface `mullvad`, exit table `51821`,
and overlay interface `wt0`. For PIA, substitute `pia` for `mullvad` in
interface names and config paths, and `nordvpn` for NordVPN; the table stays
`51821`. NordVPN is experimental: its live passes covered the egress and IPv6
checks, the local-delivery refusal, v0.6.0's repair drills and, at 0.7.0,
the client-held fail-closed drills
([testing](testing.md#070-on-rootless-podman-at-d5a234a)). If you changed
`EXIT_IF`, `EXIT_TABLE` or `OVERLAY_IF`, use your values. For rootless Podman,
use the [Podman commands](operations.md#rootless-podman).

**The gluetun backend** has other containers and other rules, so the namespace
checks and drills on this page don't carry over by renaming. Use the ones in
[gluetun as a NetBird exit](gluetun-netbird-exit.md#verification), which
apply with the applier and panel running too, then
`python3 tools/molebridge.py doctor`. That page's recreation commands name
only `gluetun guard netbird`, for the standalone setup; with the full backend
the applier shares gluetun's namespace too, so wherever a drill recreates
gluetun, use `python3 tools/molebridge.py recover` instead. The [client checks](#from-a-client)
below apply as written. One difference matters when you read results: in
gluetun's namespace, unmarked traffic the exit sends goes into gluetun's
tunnel, and only NetBird's marked control traffic uses the host's
connection, so check 4 below doesn't apply.

## Inside the namespace

`applier` shares the exit's network namespace, so use it for inspection:

```sh
docker compose exec applier sh
```

On PIA, select a region before completing checks 1–3, 6 and 8: registration
supplies the tunnel address, peer and IPv4 rules 94 and 98. Select a region
before the fail-closed drills and client or port-forwarding checks too. IPv6
stays blocked; PIA has no global IPv6 tunnel address or IPv6 rules 94 and
98.

On NordVPN, select a server before checks 3 and 8 and the drills: the config
has no peer until you do. Its IPv4 address (`10.5.0.2`) and rules 94 and 98
come from the config, as with Mullvad; IPv6 stays blocked as on PIA.

1. Check the rules. `ip rule` shows priority 1 (`not from all iif wt0 lookup
   local`) and no priority-0 `from all lookup local` rule, then priority 90
   (`iif mullvad`, overlay destination → `main`), 94 (`from` the tunnel's IPv4 address, `ipproto icmp`
   → table 51821), 95 (`iif wt0` → table 51821), 96 (`oif mullvad` → table
   51821), 97 (`iif wt0 unreachable`), and 98 (`from` the tunnel's IPv4
   address, `ipproto icmp unreachable`), and nothing else up to priority 98.
   No temporary priority-80 guard should remain. IPv6 has 1/95/96/97 in all
   cases, 90 when `OVERLAY6_CIDR` is set, and 94 and 98 with `ipproto
   ipv6-icmp` when the tunnel has an IPv6 address. Rules 94 and 98 must carry
   the protocol qualifier: without it every protocol sourced from the tunnel
   address is forced into the tunnel, or dropped, and the applier's
   `routing` check fails. `ip` may print the protocol as `1` or `58`.
2. Check the exit table. `ip route show table 51821` shows
   `default dev mullvad` and `unreachable default ... metric 4096`. The same
   holds for `ip -6 route show table 51821` with an IPv6 tunnel config; an
   IPv4-only config still has the IPv6 unreachable fallback. PIA and NordVPN
   must have only that fallback for IPv6, with no tunnel default.
3. Check provider egress with the commands below. For a dual-stack Mullvad
   tunnel, both families must succeed. On PIA, IPv4 must report
   `"connected": true`, and on NordVPN `protected` must be `true`; on both, IPv6
   through the exit must fail on the unreachable fallback.
4. Check unbound traffic with the IPv4 probe for your provider, omitting
   `--interface`. It should report your host's normal public IP. This is the
   path for the provider handshake and NetBird control connections.
5. Check the trust boundary. The panel can read `state/applier/relays.json`
   but cannot write the applier mount. The old panel-owned catalogue is ignored.
   A malformed desired file and a valid request for an unlisted name must
   report failure without changing the peer. A valid request has `server`, `requested_at`
   (current UTC `YYYY-MM-DDTHH:MM:SSZ`) and an optional 32-character lowercase
   hexadecimal `request_id`. Use a fictitious unlisted name such as
   `xx-xxx-wg-999`, then restore the desired state by selecting a valid server
   or region in the panel. `wg show mullvad peers` exposes only public peer keys.
6. Check that the exit's ICMP errors return through the tunnel.
   `cat /proc/sys/net/ipv4/icmp_errors_use_inbound_ifaddr` prints `1`, and
   `ip route get 198.51.100.1 from <tunnel IPv4 address> ipproto icmp` shows
   `dev mullvad`; with an IPv6 tunnel address,
   `ip -6 route get 2001:db8::1 from <tunnel IPv6 address> ipproto ipv6-icmp`
   does too. On PIA and NordVPN, run only the IPv4 return-path check. With an IPv6 tunnel,
   replies larger than the overlay MTU should increase `Icmp6OutPktTooBigs`
   in `/proc/net/snmp6`. Capture on both the tunnel and host-side interfaces
   (`icmp6 and ip6[40] == 2`): the errors should leave through the tunnel and
   not the host-side interface. Do not rely on `Ip6OutNoRoutes`: on a
   container network without IPv6 it also counts the exit's own IPv6
   attempts. Without this return path, oversized replies are dropped with no
   error to the origin, which can stall UDP flows such as QUIC through the exit.
7. Check that NetBird runs kernel WireGuard with its kernel firewall.
   `ip -d link show wt0` shows `wireguard` on its details line, and
   `nft list tables` shows `table ip netbird` or a `table ip filter` whose
   chains include `NETBIRD-` ones (`nft list chains`). The applier's health
   check requires both.
8. On the host, `python3 tools/molebridge.py doctor` should pass.
   It checks actual namespace agreement as well as routing, NetBird's mode,
   Rosenpass, status freshness and, last, the verdict on the applier's
   record ("recent provider check" in its `PASS` line).

Run these egress probes inside the namespace:

| Provider | Command | Expected |
|---|---|---|
| Mullvad, IPv4 | `curl -4 -fsS --interface mullvad https://ipv4.am.i.mullvad.net/json` | `"mullvad_exit_ip": true` |
| Mullvad, IPv6 tunnel | `curl -6 -fsS --interface mullvad https://ipv6.am.i.mullvad.net/json` | `"mullvad_exit_ip": true` |
| PIA, IPv4 | `curl -4 -fsS --interface pia https://www.privateinternetaccess.com/api/client/status` | `"connected": true` |
| PIA, IPv6 | `curl -6 -fsS --max-time 10 --interface pia https://ipv6.am.i.mullvad.net/json` | Connection fails; IPv6 is blocked |
| NordVPN, IPv4 | `curl -4 -fsS --interface nordvpn https://api.nordvpn.com/v1/helpers/ips/insights` | `protected` is `true` |
| NordVPN, IPv6 | `curl -6 -fsS --max-time 10 --interface nordvpn https://ipv6.am.i.mullvad.net/json` | Connection fails; IPv6 is blocked |

The PIA and NordVPN IPv6 probes check blocking. Use the explicit IPv6 hostname above;
`am.i.mullvad.net` itself has no AAAA record. A DNS failure alone does not
prove routing blocked the request.

## Fail-closed drills

Run these on every exit you rely on, each provider and backend, with a
client holding the exit. For each drill, keep that client on the selected
exit probing the provider's status endpoint above or pinging a public IP.
During the drill, the affected path must fail without using your host's
own public IP. Test IPv4 and IPv6 explicitly; a browser check may exercise
only one family. Where the exit carries both families, drill both. Where it
carries only IPv4 (PIA, NordVPN, an IPv4-only Mullvad config), check that
IPv6 is blocked before, during and after each drill.

Also record any client fallback to its own connection: server routing cannot
enforce a device-wide kill switch after NetBird disconnects or deselects the exit.

The exit repairs a deleted rule or route at its next repair pass, every
`ROUTING_RECONCILE_INTERVAL` seconds (2 by default), and brings a lost tunnel
back within a few seconds whatever the interval. Two seconds is too short to
watch a probe fail, so for these drills set a 20-second interval on the
`wireguard` service in a `compose.override.yaml`
([repair and gate timing](configuration.md#repair-and-gate-timing)):

```yaml
services:
  wireguard:
    environment:
      ROUTING_RECONCILE_INTERVAL: "20"
```

Apply it with `python3 tools/molebridge.py recover`, and remove it and recover
again when you're done. 20 seconds is shorter than the 30 seconds NetBird's
gate allows the guards to be incomplete, so the gate doesn't stop NetBird
during a rule drill. Follow the exit's log while you run them:
`docker compose logs -f wireguard netbird`.

| Drill | Break | Expect |
|---|---|---|
| Tunnel down | `docker compose exec wireguard wg-quick down /config/wg_confs/mullvad.conf` | The probe fails until the exit brings the tunnel back by itself: `molebridge-exit: bringing the tunnel up`, then `molebridge-exit: tunnel up`. |
| IPv4 route deleted | `docker compose exec wireguard ip route del default dev mullvad table 51821` | The probe fails on the unreachable fallback until the next pass logs `10-exit-routing: IPv4 tunnel route through mullvad restored`. |
| IPv6 route deleted (dual-stack Mullvad only) | `docker compose exec wireguard ip -6 route del default dev mullvad table 51821` | The same for IPv6: `10-exit-routing: IPv6 tunnel route through mullvad restored`. |
| IPv4 lookup rule deleted | `docker compose exec wireguard ip rule del priority 95` | The probe fails on rule 97 until `10-exit-routing: added IPv4 rule 95`. |
| IPv6 lookup rule deleted | `docker compose exec wireguard ip -6 rule del priority 95` | The same for IPv6: `10-exit-routing: added IPv6 rule 95`. |
| Terminal rule deleted | `docker compose exec wireguard ip rule del priority 97` | The probe keeps working through rule 95 and the tunnel; then `10-exit-routing: added IPv4 rule 97`. |
| Fallback deleted | `docker compose exec wireguard ip route del unreachable default metric 4096 table 51821` | The probe keeps working through the tunnel route; then `10-exit-routing: IPv4 unreachable fallback in table 51821 restored`. |
| Return path deleted (Mullvad, NordVPN) | `docker compose exec wireguard ip rule del priority 94` | Until `10-exit-routing: added IPv4 rule 94`, `ip route get 198.51.100.1 from <tunnel IPv4 address> ipproto icmp` inside the namespace fails as unreachable (rule 98) instead of naming the host's interface. |
| Inserted bypass | `docker compose exec wireguard ip rule add lookup main priority 50` | Removed at the next pass: `10-exit-routing: removed IPv4 rule 50: from all lookup main`. Nothing is promised about traffic before that. |
| Owner gone | `docker compose pause wireguard` | The tunnel keeps forwarding at first, but within about 10 seconds NetBird's log shows `NetBird gate: stopping NetBird: the owner record expired (written <n> s ago) (see docs/troubleshooting.md)` and the probe fails. Restore with `docker compose unpause wireguard`; the restart policy starts `netbird` again, and its gate waits for a fresh record. |
| Container stopped | `docker compose stop wireguard` | The probe fails, the exit's log ends with `molebridge-exit: stopped; the routing guards stay in place`, and NetBird's gate stops NetBird. Restore with `python3 tools/molebridge.py recover`. |

On PIA, rules 94 and 98 belong to the applier, which puts a deleted one back
within one pass of its loop (normally 5 seconds, longer during a switch or
periodic check), without a log line. After each
drill, confirm provider egress returns on the supported families. After the
tunnel-down drill, the applier reapplies the saved server or region when the
interface returns. A failed switch is retried by itself on its backoff, and
clears at a later check when its server is live and verified
([retries](operations.md#retries)). These drills follow from the code and
the isolated drills below; [testing](testing.md) records which have run on
a live exit.

Confirm the exit host's own unbound traffic stays on its ordinary path while
the client path is blocked.

The isolated `tools/check-routing.sh` drill also
deletes all exit-table routes together to exercise the terminal guard, and
checks that an oversized tunnel reply produces an ICMP error back over the
tunnel, that a missing return-path rule is detected, and that with the tunnel
route gone no error reaches the tunnel side. It also counts ICMP errors that
reach the host side: none escape with rule 94 missing or with the exit table
empty, and removing rules 94 and 98 together shows the counter can see them.
On a live exit, a capture on the host-side interface during a live flow
does the same (see step 6 above).

For local delivery, the same drill sends TCP and UDP from the overlay side to
the exit's overlay and host-side addresses, in both families, and checks that
no listener in the exit's namespace receives them, also after an nftables
DNAT to a local port. It confirms that it can see local delivery, before and
after the DNAT, by restoring the kernel's priority-0 `lookup local` rule. It also checks that the NetBird gate refuses unsupported NetBird
settings, profiles other than the default and a default profile for another
interface, runs the gate's JSON reader under gawk, mawk and busybox when they
are installed, and keeps waiting while the kernel's priority-0 rule is in
place.

A blocked client path must not appear healthy. The applier checks about once
a minute, so a 20-second break can fall between two checks; the owner-gone
drill lasts as long as you leave the container paused. During it, confirm
the next applier check reports `failed` with "Routing protection is
incomplete; run the recovery helper.", `/readyz` returns 503, and any
monitoring push reports failure. During a route deletion on a dual-stack
Mullvad tunnel, the other family should still work. On PIA, deleting the
IPv4 default must leave both families blocked.

Check that nothing arriving over NetBird reaches the exit itself. Inside the
namespace, `ip route get <exit overlay address> from <client overlay address>
iif wt0` must show `dev mullvad table 51821`, not `local`; with an IPv6
overlay, `ip -6 route get` the same way. `netbird status -d` lists both
addresses. From a client on the exit, ping the exit's overlay address: there
must be no reply, although the access policy allows ICMP, because the ping is
routed into the tunnel instead of reaching the exit. Repeat the ping with the
tunnel down. The local-delivery refusal has been checked on live PIA,
NordVPN and gluetun exits; [testing](testing.md) says which protocols and
families each covered.

## Status and recovery

### Reading the status

Read the applier's record on the host. Every check is listed with its state;
only `pass` counts:

```sh
python3 -c 'import json, sys; r = json.load(open(sys.argv[1])); print("schema", r.get("schema"), r.get("kind"), r.get("status"), r.get("message")); print("selection", r.get("selection")); [print(" ", n, c.get("state"), c.get("reason", "")) for n, c in r.get("checks", {}).items()]; print("egress tier", r.get("checks", {}).get("egress", {}).get("tier"))' state/applier/result.json
```

With `jq`: `jq '{schema, kind, status, message, selection, tier: .checks.egress.tier, checks: (.checks | map_values(.state))}' state/applier/result.json`.
A connected overlay exit shows `schema 2`, `ok`, every required check
`pass` ([which are required](architecture.md#the-status-record)),
`app_attachment` `n/a`, and `egress tier provider` (or `tunnel` for a
provider with only the tunnel checks).

The page, the API, `/readyz`, the doctor and any Gatus push must agree,
because they all judge the record with the same function. Compare them at
the same moment:

```sh
curl -fsS http://127.0.0.1:8095/api/status | python3 -c 'import json, sys; v = json.load(sys.stdin)["verdict"]; print(v["state"], v["label"], v["reasons"], v["tier"])'
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8095/readyz
docker compose exec applier python -m applier.apply --doctor | tail -n 1
```

Add `?exit=<id>` on a panel serving several exits. `ok connected` goes with
`/readyz` 200 and `PASS verified Mullvad egress` (your provider's name);
anything else goes with 503 and `FAIL verified Mullvad egress - ` followed
by the same reason codes.

### Status drills

Stop the applier while leaving the tunnel running. Within 150 seconds plus one
browser poll, the panel must show stale/unknown and `/readyz` must return 503;
`/healthz` remains 200. Restart the applier and confirm fresh status returns.
Disconnect an open browser from the panel and confirm its next failed poll
clears connected status. Test a failed switch followed by **Retry**, which
applies at once, and confirm the panel shows when the applier would have
retried by itself ("Retrying at … UTC").

Start a switch and, before it finishes, choose another server from a second
tab: the panel must answer 409, "A switch is in progress; wait for it to
finish.", and the first switch must complete. Then choose again.

Fail the egress check briefly while the client holds the exit. On the
default backend, drop the exit's own HTTPS through the tunnel, which only
the applier's egress check uses, and leave it for one or two checks:

```sh
docker compose exec applier nft add table inet molebridge_drill
docker compose exec applier nft add chain inet molebridge_drill out '{ type filter hook output priority 0; }'
docker compose exec applier nft add rule inet molebridge_drill out oifname mullvad tcp dport 443 drop
docker compose exec applier nft delete table inet molebridge_drill
```

Until you delete the table, the panel shows the exit failed with "Tunnel
inspection or egress check failed.", the record's `selection.outcome` is
`applied-unverified` with `next_action` `recheck`, the live server stays the
same (no "Applying the requested server."), and the client's traffic
continues. After you delete the table, the next check, within about a
minute, shows it connected again. This drill follows from the code; whether
it has run live is in [testing](testing.md). Finally, verify the recovery helper, container
recreation and host reboot preserve the NetBird peer identity and shared namespace.
After a WireGuard restart outside Compose, confirm an applier stranded without
the WireGuard interface becomes Docker-unhealthy even if its failure result is
fresh. On a disposable deployment, start NetBird before the exit is ready:
its gate must wait until the exit's owner record is live and the whole
routing contract is in place in its namespace, with no priority-0 rule left.
Repeat with a non-default `OVERLAY_IF` and confirm NetBird creates that interface.

Start with a saved desired selection, an expired catalogue and an unavailable
relay API. Confirm no peer change occurs and the result says the request will
retry. Restore the API and confirm the same request is applied automatically.
A malformed or unlisted request is not retried until the server list
changes or you select again; a failed peer update is retried on its
backoff.

## From a client

With the exit selected on a device in `exit-users`:

- For Mullvad, <https://mullvad.net/check> reports Mullvad egress in the
  chosen server's city. For PIA,
  <https://www.privateinternetaccess.com/api/client/status> reports
  `"connected": true`.
- Addresses on the host's own LAN, such as its router, are unreachable.
- With IPv6 overlay and a `::/0` route, an IPv6 egress check shows a Mullvad
  address for a dual-stack Mullvad tunnel. On PIA it must fail: forwarded IPv6
  hits the unreachable fallback. Without an IPv6 overlay and exit route,
  check that IPv6 fails or is unused; a native IPv6 address means that traffic
  bypasses the exit.
- Try a video call or an HTTP/3 (QUIC) download. A stall followed by recovery
  can be a symptom of a missing ICMP return path when a browser falls back to
  TCP. Check the return path with namespace step 6 before drawing that
  conclusion; a completed download alone does not test oversized UDP replies.
- On the host, use `docker compose exec netbird netbird status -d` to check
  whether the client's path is `P2P` or `Relayed`. If it is relayed, see
  [direct connections](operations.md#direct-connections). Confirm the exit
  interface is in the peer's ICE blacklist; `python3 tools/molebridge.py doctor`
  checks the stored value.
- Choose another Mullvad server or PIA region in the panel. Confirm the panel
  reports the new location and the client's egress follows without reselecting
  the exit.
- Molebridge does not change DNS; see [operations](operations.md#dns). Run a
  DNS leak check and confirm the resolvers shown are acceptable to you. If it
  flags a resolver, see
  [when a leak test flags DNS](operations.md#when-a-leak-test-flags-dns).

## Optional PIA port forwarding

These are acceptance checks for [port forwarding](providers.md#port-forwarding).
Live forwarding against PIA remains untested in the [test record](testing.md).
Enable it, select a region that offers forwarding, and wait for an allocated
port in the panel or `forwarded_port` in `/api/status`.

- Have the target service listen on that allocated port for TCP and UDP.
  DNAT changes the destination address and keeps the port.
- Confirm the NetBird policy allows the exit peer to reach the target on
  that port for both protocols. Forwarded connections use the exit peer's
  overlay address.
- From outside your NetBird network, connect to the PIA egress address and
  allocated port over TCP and UDP. Confirm both reach the target service.
- Set `PIA_PORT_FORWARD=off` and clear `PIA_PORT_FORWARD_TARGET`, then
  recreate the applier so it reads the new settings. Check that
  `docker compose exec applier nft list table ip molebridge_forward` reports
  the table absent after startup; the applier retries removal if it fails.
  `docker compose exec applier nft list table inet molebridge_guard` must
  still show the ingress guard. Use new connections for the check: existing
  conntrack mappings can outlive the forwarding rules.
