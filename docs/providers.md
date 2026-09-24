# Other VPN providers

**Status: Mullvad only.** No other provider is supported or tested. This page
records where Mullvad is built into Molebridge, the one property a provider
needs for the current design to work, and the shape a second provider would
most likely take. It is a design note, not a plan of record.

## Where Mullvad is built in

| Place | Mullvad assumption |
|---|---|
| `molebridge/relays.py` | The fixed relay-list URL `api.mullvad.net/app/v1/relays` and its response shape (`locations`, `wireguard.relays`, `active`, `ipv4_addr_in`). |
| `molebridge/state.py` | `HOSTNAME_RE` accepts only Mullvad-style names such as `se-sto-wg-001`, both in the catalogue and in `desired.json`. |
| `applier/apply.py` | `egress_family` asks `ipv4.am.i.mullvad.net` / `ipv6.am.i.mullvad.net`, and a `mullvad_exit_ip` of `true` is required for a healthy result. The peer endpoint port is fixed at `51820`. |
| `panel/app.py` | The latency probe assumes relays accept TCP on port 443. `flag_emoji` and `relay_label` read Mullvad's location codes and `-wg-` names. The page says "Mullvad IP" and "Mullvad-owned". |
| `tools/prepare-tunnel-config.py` | Expects a single-peer WireGuard file with an IPv4 endpoint, as Mullvad's configuration generator produces. |
| Names | The `mullvad` interface (already overridable with `EXIT_IF`), `tunnel/wg_confs/mullvad.conf`, and the docs throughout. |

Routing (`routing/10-exit-routing`, `molebridge/routing.py`) is plain
WireGuard plus policy routing and does not depend on Mullvad.

## The property that decides it

A switch changes only the tunnel's **peer**: the applier removes the old
public key and endpoint and adds the new one. The interface's private key and
tunnel addresses never change, and the applier never reads them. That is what
lets the applier run without the tunnel config mounted (see
[architecture](architecture.md#components-and-trust)).

This works because a Mullvad device has **one private key and one tunnel
address that are valid on every server**. A provider fits the current design
only if it has the same property. Check this against the provider's own
documentation and a live test; a provider's app working on every server does
not by itself show that one static WireGuard key does.

A provider that issues a different key or tunnel address per server, or that
needs an authenticated API call to register the key on each server before
connecting, does not fit. Supporting it would mean the key-holding `wireguard`
container rewriting or swapping its own config on each switch, or the applier
gaining access to the key. Either changes the privilege split, so it needs its
own design and review, not an adapter.

## Likely shape of a second provider

If this is pursued, split the Mullvad-specific parts behind a small provider
seam in the applier, and keep Mullvad as the default:

- **Catalogue source:** returns validated entries with the fields the panel
  already uses (name, country, city, location code, public key, IPv4 endpoint,
  plus a port). The validation rules in `relays.py` stay; the name pattern
  becomes per-provider.
- **Egress verifier:** decides whether traffic leaving the tunnel is really
  going through the provider.

The first provider to add should be a **static** one: a peer list the operator
writes, owned and validated by the applier in the same way as the Mullvad
catalogue, with the panel still able to submit only a name from that list.
It would cover any provider with account-wide keys, and a self-hosted exit
such as a VPS, without trusting a new remote API. Provider-specific relay-list
adapters would come after it, one at a time.

### Honest status without a provider check

Mullvad's `am.i.mullvad.net` lets the applier confirm, from Mullvad's side,
that egress is Mullvad. Most providers offer no equivalent. A generic check
could require a fresh handshake and an egress address, seen through the
tunnel, that differs from the host's own direct egress. That is weaker: it
shows traffic left somewhere else, not where. The status and docs must say so,
for example "egress observed through the tunnel" rather than "verified", and
`/readyz` and the doctor must not report it as the same result as a
provider-confirmed check.

### What changes elsewhere

- Latency probing needs a per-provider port, or a way to say it is not
  available.
- Flags and short labels need a per-provider mapping, or fall back to the
  country and the full name.
- The page's Mullvad wording and the Mullvad-owned filter become per-provider.
- `prepare-tunnel-config.py` needs the provider's config shape, and must keep
  refusing configs it does not understand.

## Before claiming support

A provider is supported only after:

1. its key model is confirmed to meet the property above;
2. its relay list (if used) is treated as untrusted input with the same
   bounds, schema checks and failure handling as Mullvad's;
3. the full [verification](verification.md) runs on a real host with a real
   client, including the fail-closed drills, and the result is recorded in
   [testing](testing.md).

Until then the README and this page keep saying Mullvad only.
