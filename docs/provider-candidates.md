# Provider candidates

Which VPN providers Molebridge could support next, and what each would take.
This is a survey from 2026-09-27, not a commitment. Items marked *unverified*
were inferred and not confirmed against a source.

## What a provider needs

The applier has to do the following unattended, with the kernel WireGuard
client, curl and the Python standard library:

1. Fetch a machine-readable server catalogue: names, locations, addresses, and
   WireGuard public keys or a way to get them.
2. Get tunnel credentials for the chosen server. Mullvad registers one key that
   works on every relay, so a switch only swaps the peer. PIA registers the key
   per server and returns a per-server address.
3. Switch without a person present. An interactive login, CAPTCHA or browser
   OAuth rules a provider out.
4. Ideally, confirm egress through a provider "am I connected" endpoint.

## Ranked

| Rank | Provider | Keys and configs | Server list with WireGuard keys | One key, all servers | Exit check | Port forwarding |
|---|---|---|---|---|---|---|
| 1 | **NordVPN** (NordLynx) | Dashboard access token → `GET api.nordvpn.com/v1/users/services/credentials` returns the WireGuard private key | Public: `api.nordvpn.com/v1/servers/recommendations` (filter `wireguard_udp`), with a `public_key` in the technology metadata | Yes | `api.nordvpn.com/v1/helpers/ips/insights` (`protected`) | No (*unverified*) |
| 2 | **Surfshark** | Keypair made or uploaded in the dashboard, or registered through the account API (`/v1/account/users/public-keys`). Registered keys expire and must be renewed | Public: `api.surfshark.com/v4/server/clusters/generic`, with `pubKey` and `load` | Yes | `surfshark.com/api/v1/server/user` (`secured`) | No (*unverified*) |
| 3 | **Proton VPN** | Dashboard config. The key is a certificate valid for up to a year; the API can issue one after an SRP login | Needs an authenticated session (`/api/vpn/v1/logicals`) | Yes | None official | Yes: NAT-PMP on P2P servers, enabled when the config is generated |
| 4 | **IVPN** | Your own public key, added in the client area or through the session API that IVPN's open-source daemon uses | Public: `api.ivpn.net/v5/servers.json` | Yes | `api.ivpn.net/v4/geo-lookup` (`isIvpnServer`) | Removed in 2023 |
| 5 | **AirVPN** | Official API keyed per user; per-device key, preshared key and addresses from the config generator | Public status list (`airvpn.org/api/status/`); every server shares one public key | Yes (*unverified*, strong) | `airvpn.org/api/whatismyip/` | Yes: static ports reserved in the client area |

### Why this order

- **NordVPN** is the biggest provider, and in Molebridge terms it behaves like
  Mullvad: the public catalogue includes keys, and a switch only swaps the
  peer. The catch is that its credentials call *returns* a private key, and
  the access token that fetches it is a long-lived secret. The applier would
  keep the token, not only a key it generated.
- **Surfshark** also publishes keys in a public list and needs one key for
  every server. Automating key registration means logging in with the account
  password through an unofficial API, and keys expire. The simpler path: the
  user registers a key in the dashboard, and Molebridge only watches its
  expiry.
- **Proton VPN** is the only big mainstream provider with WireGuard port
  forwarding. Its server list is no longer public, and its config certificate
  expires. The practical design: the user supplies a dashboard config, and
  Molebridge refreshes the list with stored credentials and warns before the
  certificate expires.
- **IVPN** is technically the closest to Mullvad, but its user base is small.
- **AirVPN** has an official API and static port forwarding, which PIA users
  who want forwarding would appreciate. Its generator parameters need hands-on
  checking.

## Not now

- **Windscribe**: WireGuard for Pro accounts, a public list with keys, and
  seven-day ephemeral port forwarding. Whether switching needs a per-server
  API call is unconfirmed. It is a reasonable sixth.
- **ExpressVPN**: WireGuard only inside its own apps; otherwise Lightway. No
  exportable WireGuard config was found.
- **CyberGhost**: manual configurations are OpenVPN only; WireGuard needs its
  proprietary client.
- **Mozilla VPN**: runs on Mullvad relays, but device registration needs an
  interactive browser login.
- **TorGuard**: configs are tied to one server and reportedly expire within a
  day, like PIA but without a documented API.

## Sources

The providers' own documentation, where it exists, and endpoints fetched on
2026-09-27. Beyond those:

- [gluetun](https://github.com/qdm12/gluetun) for its provider updaters and wiki;
- [protonvpn-wg-confgen](https://github.com/hatemosphere/protonvpn-wg-confgen) for Proton certificates;
- IVPN's open-source desktop daemon for its session API;
- NordVPN key-fetch write-ups for the credentials call.

Market-share figures come from secondary aggregators and differ between them.
Terms of service were checked for automation clauses; none was found either
way.
