# VPN providers

Molebridge supports two providers, chosen with `PROVIDER` in `.env`:

| Provider | Status | You pick | Key model |
|---|---|---|---|
| `mullvad` (default) | Verified on the hosts in [testing](testing.md) | a relay | One device key and tunnel address, valid on every relay |
| `pia` | Experimental; see [testing](testing.md) for what has run | a region | A key registered on each server, with a tunnel address per server |

One Molebridge deployment uses one provider. To offer both, run two
deployments with different `COMPOSE_PROJECT_NAME`, `NB_HOSTNAME` and
`PANEL_PORT`, and give each its own NetBird exit route. Clients then choose
the exit in NetBird as usual.

## Why PIA works differently

A Mullvad switch changes only the tunnel's **peer**. The interface's private
key and addresses never change, which is why the applier can run without the
tunnel config mounted (see [architecture](architecture.md#components-and-trust)).

PIA has no account-wide WireGuard key. Each connection:

1. mints a token from the account login (valid 24 hours);
2. asks the chosen server to accept the interface's **public** key
   (`https://<server>:1337/addKey`), verifying the server's TLS name against
   PIA's CA, which Molebridge bundles;
3. receives that server's key and port and a tunnel address valid only there.

So for PIA the applier also sets the interface's IPv4 address and the
priority-94 return-path rule on each switch, and it holds the PIA login. The
private key still never leaves the `wireguard` container: registration needs
only the public key. What changes in the privilege split:

| | Mullvad | PIA |
|---|---|---|
| Account credential in the applier | none | the PIA username and password, read from mode-0600 files |
| Applier changes the tunnel address | never | on every switch |
| Priority-94 rule installed by | routing initialization, from the config's `Address` | the applier, after each registration |
| Egress confirmed by | `am.i.mullvad.net`, per address family | PIA's `api/client/status` (`connected: true`), IPv4 |

The login and token reach `curl` only through mode-0600 scratch files on the
applier's tmpfs, never its arguments, logs or state files. The panel still
holds no capabilities and can only name a region from the applier's own
catalogue.

On a switch the applier installs the new address's return-path rule first and
removes the old one last, so the exit's own ICMP errors always have a rule
sending them into the tunnel. It adds the new address before removing the old one:
when an interface loses its last IPv4 address, the kernel deletes every route
through it, the exit table's tunnel default included. It then re-asserts that
route. Forwarded traffic stays on the exit table throughout; a missing route
falls through to the unreachable fallback.

## PIA specifics

- **Regions, not servers.** The catalogue is PIA's published region list
  (`serverlist.piaservers.net/vpninfo/servers/v6`), validated like the
  Mullvad list. The applier picks one of the region's WireGuard servers when
  it registers. Offline regions are left out. Regions PIA marks as virtual
  locations are labelled as such in the panel.
- **IPv4 only.** PIA carries no IPv6. The tunnel config has no IPv6 route, so
  forwarded IPv6 hits the exit table's unreachable fallback. If your NetBird
  account has IPv6, still create the `::/0` exit route for this peer:
  without it, a client using the PIA exit sends IPv6 over its own network.
- **Re-registration.** PIA forgets a key after a server restart or long
  inactivity. When the requested region's handshake goes stale, the applier
  registers again **in the same region**, at most every five minutes. It never
  picks another region by itself. After the `wireguard` container is
  recreated, the saved region is registered again automatically, as with a
  Mullvad server.
- **Status.** `result.json` carries `provider: "pia"` and `exit_confirmed`
  instead of `mullvad_exit_ip`. There is no egress city or country.
  `state/applier/tunnel.json` records the current registration (region,
  server name and address, server key, tunnel address); it holds no secret.

## Setting up PIA

Follow [setup](setup.md) with these differences.

1. In `.env`:

   ```sh
   PROVIDER=pia
   EXIT_IF=pia
   COMPOSE_FILE=compose.yaml:compose.pia.yaml
   ```

   `compose.pia.yaml` mounts the login into the applier only.
2. Create the tunnel config with a new key. It has no address and no peer:

   ```sh
   python3 tools/prepare-tunnel-config.py --pia
   ```

   It writes `tunnel/wg_confs/pia.conf`, mode 0600, and refuses to overwrite
   an existing one.
3. Store the PIA login, one value per file, mode 0600:

   ```sh
   mkdir -p secrets/pia && chmod 700 secrets/pia
   (umask 077; printf '%s' 'p1234567' > secrets/pia/username)
   (umask 077; read -rs pia_password && printf '%s' "$pia_password" > secrets/pia/password)
   ```

   Type the password at the prompt so it stays out of your shell history. The
   example username is a placeholder.
4. Start the stack as in setup. The exit reports "No PIA region is registered
   yet" until you choose a region in the panel, or write one to
   `state/panel/desired.json` in the documented request format.

PIA accounts with two-factor authentication still mint tokens from the
username and password; nothing prompts at startup.

## Port forwarding

Off by default. PIA can forward one port on the current server to the exit.
Molebridge passes it on to **one overlay device**:

```sh
PIA_PORT_FORWARD=on
PIA_PORT_FORWARD_TARGET=192.0.2.10   # that device's NetBird address
```

With it on:

- only regions that offer port forwarding are listed;
- after each healthy switch the applier requests the port through the tunnel
  and binds it again every ten minutes (PIA drops it after fifteen);
- an nftables table, `molebridge_forward`, sends TCP and UDP for that port
  from the tunnel to the target, and masquerades it as the exit's overlay
  address, because the target's WireGuard peer accepts only that address from
  the exit;
- the same table drops anything forwarded from the tunnel that would leave
  other than over the overlay, so a vanished overlay route cannot hand
  inbound connections to the host's network;
- the panel shows the port under Diagnostics, and `result.json` carries
  `forwarded_port`. It changes when the region changes.

Turning forwarding off removes the table when the applier next starts, even if
the tunnel namespace survived. Connections already open continue until they
close, and PIA stops forwarding the port within fifteen minutes of the last
bind.

**This opens a port to the Internet.** Anyone can connect to it, and those
connections reach the target device. Only turn it on for a service that is
meant to be reachable, and allow the exit peer to reach that port on the
target in your NetBird policies; nothing else is opened. A target outside
`OVERLAY_CIDR` is refused, and so is turning forwarding on without a target.

## Adding another provider

A provider fits the Mullvad model only if one WireGuard key and tunnel address
work on every server; check that against the provider's documentation and a
live test. A provider that registers keys per server fits the PIA model
instead. Either way the provider needs, in `molebridge/relays.py` and a
subclass of the applier:

- a catalogue parser that treats the provider's list as untrusted input, with
  the same size limits, schema checks and last-good fallback;
- `apply_relay`, `server_for` and `egress`;
- a provider-side egress confirmation. Without one, the status must say
  "egress observed through the tunnel", not "verified", and `/readyz` must
  not report it as a confirmed result.

A provider is supported only after the full [verification](verification.md)
has run on a real host with a real client and the result is recorded in
[testing](testing.md).
