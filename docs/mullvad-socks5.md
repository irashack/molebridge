# Mullvad's SOCKS5 proxies through an exit

Every Mullvad WireGuard server runs a SOCKS5 proxy that answers only from
inside a Mullvad tunnel ([Mullvad's guide](https://mullvad.net/en/help/socks5-proxy)).
A device that uses a native Mullvad exit is inside that tunnel, so it can use
those proxies as they are. Nothing in Molebridge needs to change or be set:
the exit forwards the device's traffic for them into the tunnel like any other
traffic.

That gives one application a different Mullvad server from the rest of the
device. The device keeps the exit's server, the one Switchyard shows, while
the application's connections leave from the server whose proxy it uses. No
other device moves, and nothing is switched, so no connections drop.

This has run once, with a Linux client on a native Mullvad exit at 0.9.4
([testing](testing.md#mullvads-socks5-proxies-through-an-exit)). The gluetun
backend, the native sidecar and clients on other systems are untested.

## The two kinds of proxy

- **The exit server's own proxy, at `10.64.0.1:1080`.** Connections leave from
  the server the exit is on, the same address the device already has. It helps
  only an application that wants a proxy setting.
- **Every other server's proxy, at `<server>-socks5`.** Take the server's
  hostname from Switchyard or [Mullvad's server list](https://mullvad.net/en/servers),
  put `socks5-` after `-wg-`, and add `.relays.mullvad.net`, on port 1080.
  `se-sto-wg-001` becomes `se-sto-wg-socks5-001.relays.mullvad.net:1080`.
  These names resolve on public DNS to addresses in `10.124.0.0/16`, which
  only answer through the tunnel. The exit's cached relay list
  (`state/applier/relays.json`) doesn't carry them.

## Check it from a device

Select the Mullvad exit in NetBird first. Then check that the proxies'
addresses go to NetBird's interface, not to a local network:

```sh
route -n get 10.64.0.1        # macOS: the interface should be NetBird's utun
ip route get 10.64.0.1        # Linux: dev wt0, or the interface NetBird created
```

Do the same for the address a proxy's name resolves to
(`host se-sto-wg-socks5-001.relays.mullvad.net`). NetBird looks up the main
routing table before its exit route, so any local route that covers the
address wins: a LAN in `10.0.0.0/8`, another VPN, a container bridge.
Connections to the proxy then go there instead, and fail or reach something
else.

Then compare the two kinds:

```sh
curl --socks5-hostname 10.64.0.1:1080 https://am.i.mullvad.net/json
curl --socks5-hostname se-sto-wg-socks5-001.relays.mullvad.net:1080 https://am.i.mullvad.net/json
```

The first should report the exit's server, the second `se-sto-wg-socks5-001`.
Use `--socks5-hostname` (or `socks5h://` in a proxy URL) so the proxy looks up
the site's name, not the device. An application set to resolve names itself
asks the device's resolver, which the exit carries like any other traffic
([DNS](operations.md#dns)).

## Limits

- **The exit must be selected.** Without it the proxies' addresses don't reach
  Mullvad; the connections go wherever the device's own routes send them.
- **It covers only what the application sends to the proxy.** Anything else on
  the device, and anything the application sends around the proxy, leaves from
  the exit's server while the exit is selected, and from the device's own
  connection when it isn't ([limits](../README.md#limits)).
- **Two hops.** The exit's server still carries the WireGuard leg and its
  bandwidth; the proxy only changes where the connection leaves Mullvad. A
  proxy far from the exit's server is slower to connect and to transfer.
- **Molebridge knows nothing about it.** The status record, the verdict and
  Switchyard show the exit's server only, and the egress check verifies only
  that server. When the exit switches, open proxy connections drop with the
  rest.
- **No authentication.** Mullvad's proxies don't take a password, so every
  device that can use the exit can use them. They don't answer from outside
  Mullvad's network.
- **Private addresses.** Both kinds of proxy have private (RFC 1918)
  addresses, so they stop working if NetBird blocks LAN access through the
  exit peer. Molebridge doesn't turn that on.
- **Only TCP was tested.** UDP through these proxies is untested.
- **Mullvad only.** PIA and NordVPN have no equivalent that Molebridge knows
  of. Mullvad documents the proxies, not their use through a NetBird exit, so a
  change on Mullvad's side could end this without a Molebridge release.
