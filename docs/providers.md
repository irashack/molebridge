# VPN providers

Each Molebridge exit uses one provider, set with `PROVIDER` in `.env`:

| Provider | Status | You pick | Keys |
|---|---|---|---|
| `mullvad` (default) | Tested on the hosts in [testing](testing.md) | a server | One device key and tunnel address, valid on every server |
| `pia` | Experimental: fewer live checks so far, see [testing](testing.md) | a region | A key registered on each server, with a different tunnel address on each |

To offer both, run two exits with different `COMPOSE_PROJECT_NAME`,
`NB_HOSTNAME` and `PANEL_PORT`, each with its own NetBird route. One
[Switchyard](switchyard.md#several-exits-in-one-panel) can serve both.

## How PIA differs

A Mullvad switch changes only the tunnel's peer. The interface's key and
addresses stay the same, which is why the applier can run without the tunnel
config mounted.

PIA has no account-wide WireGuard key. To connect to a server, the applier:

1. gets a token from PIA with the account's username and password, and reuses
   it for up to 12 hours;
2. asks the chosen server to accept the interface's public key
   (`https://<server>:1337/addKey`), checking the server's TLS certificate
   against PIA's CA, which Molebridge bundles;
3. receives that server's key and port, and a tunnel address that is valid
   only on that server.

So with PIA the applier also sets the interface's IPv4 address and the
return-path rule (priority 94) on every switch, and it holds the PIA login.
The private key still never leaves the `wireguard` container, because
registration needs only the public key.

| | Mullvad | PIA |
|---|---|---|
| Account credential in the applier | none | username and password, from mode-0600 files |
| The applier changes the tunnel address | never | on every switch |
| Rule 94 is installed by | routing initialization, from the config's `Address` | the applier, after each registration |
| Egress is confirmed by | `am.i.mullvad.net`, for each address family | PIA's `api/client/status` (`connected: true`), IPv4 |

The login and token reach `curl` only through mode-0600 files on the
applier's tmpfs. They never appear in its arguments, logs or state files.

During a switch, the applier adds the new address and its return-path rule
before it removes the old ones. When an interface loses its last IPv4
address, the kernel deletes every route through it, including the exit
table's tunnel route, so the order matters. The applier then puts that route
back. Forwarded traffic stays on the exit table throughout, and while the
route is missing it hits the unreachable fallback.

## PIA details

- **Regions.** The server list is PIA's published region list
  (`serverlist.piaservers.net/vpninfo/servers/v6`). It is checked the same way
  as Mullvad's. PIA appends a signature to that file, which Molebridge doesn't
  verify; it relies on HTTPS for the list and on PIA's CA when registering.
  Offline regions are left out, and PIA's virtual locations are labeled. When
  it registers, the applier picks one of the region's servers.
- **IPv4 only.** PIA carries no IPv6. Forwarded IPv6 hits the exit table's
  unreachable fallback. If your NetBird account has IPv6, still create the
  `::/0` exit route for this peer. Without it, a device using the PIA exit can
  send its IPv6 over its own network.
- **Re-registration.** PIA forgets a key after a server restart or long
  inactivity. When the handshake goes stale, the applier registers again in
  the same region, at most once every five minutes. It never picks another
  region by itself. After the `wireguard` container is recreated, it
  registers the saved region again.
- **Status.** `result.json` carries `provider: "pia"` and `exit_confirmed`.
  PIA's check returns no city or country, so the panel shows the region from
  the server list. `state/applier/tunnel.json` records the current
  registration: region, server, server key and tunnel address. It holds no
  secret.

Setup for PIA is part of [setup](setup.md). On a fresh install the exit
carries no traffic until you pick a region in the panel.

## Port forwarding

Off by default, and experimental: the forwarding path is covered by isolated
drills in CI but hasn't been tested against PIA itself. PIA can forward one
port on the current server. Molebridge passes it to **one overlay device**:

```sh
PIA_PORT_FORWARD=on
PIA_PORT_FORWARD_TARGET=192.0.2.10   # that device's NetBird address
```

With it on:

- only regions that offer port forwarding are listed;
- after each healthy switch the applier asks PIA for a port through the
  tunnel, and binds it again every ten minutes (PIA drops a port that isn't
  bound for 15);
- an nftables table, `ip molebridge_forward`, sends TCP and UDP for that port
  from the tunnel to the target, on the **same port number**, and masquerades
  it as the exit's overlay address;
- a separate, permanent table, `inet molebridge_guard`, drops anything
  forwarded from the tunnel that would leave other than over the overlay;
- the port appears under Diagnostics in the panel, and in `result.json` as
  `forwarded_port`. PIA chooses the number. It may change after a switch,
  re-registration or restart, so anything that depends on it has to follow
  `forwarded_port`.

The service on the target must listen on the forwarded port itself; there's
no port translation. You also need a NetBird policy that lets the exit peer
reach that port on the target.

A healthy exit doesn't mean forwarding works. Forwarding errors appear as
`port_forward_error` in `result.json` and in the panel's Diagnostics, without
changing the exit's connected state.

To turn forwarding off, set `PIA_PORT_FORWARD=off`, clear
`PIA_PORT_FORWARD_TARGET` (the applier refuses to start with a target and
forwarding off), and recreate the applier so it picks up the new settings.
It removes `molebridge_forward` as it starts; the
[port-forwarding checks](verification.md#optional-pia-port-forwarding) confirm
it. Connections already open continue until they close, and PIA stops
forwarding within 15 minutes of the last bind.

**This opens a port to the Internet.** Anyone can connect to it, and their
connections reach the target device. Only turn it on for a service that is
meant to be public. The applier refuses a target outside `OVERLAY_CIDR`, and
refuses to start forwarding without a target.

## Adding a provider

[Other VPN providers](other-providers.md) lists the providers that aren't
supported, which could be added, and what support would look like.

A provider fits the Mullvad model if one WireGuard key and tunnel address
work on every server. It fits the PIA model if keys are registered per server.
Either way it needs, in `molebridge/relays.py` and an applier subclass:

- a parser that treats the provider's server list as untrusted input, with the
  same size limits, schema checks and last-good fallback;
- `apply_relay`, `server_for` and `egress`;
- a way for the provider to confirm egress through the tunnel. The status
  model requires it: without one, the exit can never show as connected or pass
  `/readyz`, so a provider without such an endpoint needs a change to that
  model first.

A provider counts as supported only once the full
[verification](verification.md) has run on a real host with a real client,
and the result is recorded in [testing](testing.md).
