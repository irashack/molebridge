# Other VPN providers

Molebridge supports Mullvad and PIA, and NordVPN as an experiment with one
live pass so far ([providers](providers.md#how-nordvpn-differs)).
Nothing else works today, and there's no generic "bring your own WireGuard
config" mode, because each provider handles keys, server lists and switching
differently.

Some other providers could be added if people want them. If you'd use one,
open an issue saying which, and whether you could help test it. Interest is
what decides whether a provider gets attempted.

## What support would look like

- **Someone has to test against a real account.** The maintainer has
  accounts with Mullvad, PIA and NordVPN only. A new provider needs either a paid
  account for development or a volunteer who runs the live checks on their
  own exit and reports back. Nobody should ever send their credentials.
- **A new provider starts as experimental**, as PIA did. That means unit tests
  and the isolated drills in CI, plus at least one recorded live pass with a
  real client ([verification](verification.md)). It doesn't mean every drill
  on every platform.
- **Most of these integrations depend on unofficial APIs.** Few providers
  document an API for managing WireGuard keys or listing servers. Molebridge
  would be relying on endpoints their own apps use, which can change or
  disappear without notice. When that happens, switching and status checks
  break until someone notices, fixes the code and tests the fix. Traffic
  still can't fall back to the host's connection, but the exit may be
  unusable in the meantime.
- **Features vary.** Port forwarding, IPv6 and a way to confirm egress
  through the tunnel differ from one provider to the next. A provider that
  can't confirm egress itself can still show as connected, through
  Molebridge's own tunnel checks, but the panel labels it "tunnel checks
  only" ([status reporting](architecture.md#status-reporting)).
- **Each provider is more code to maintain.** A provider that nobody tests
  can be dropped again.

## The candidates

Findings from a survey in September 2026. NordVPN, the closest fit, has since
been built ([providers](providers.md#how-nordvpn-differs)); it fetches the
key once at setup, so the exit stores no NordVPN token. Nothing below has
been built or tested in Molebridge; the endpoints come from the providers' own
documentation, their open-source clients, and
[gluetun](https://github.com/qdm12/gluetun), which integrates many of them.

### Could be added

These use plain WireGuard, one key that works on every server (like Mullvad),
and a server list that can be fetched without a browser.

| Provider | How keys work | Server list | Egress check | Port forwarding | What adding it would involve |
|---|---|---|---|---|---|
| **Surfshark** | A key made or uploaded in the dashboard. Automating registration takes the account password through an unofficial API, and keys expire | Public, with keys (`api.surfshark.com/v4/server/clusters`) | `surfshark.com/api/v1/server/user` | No | Likely a dashboard-made key, with Molebridge warning before it expires. Automatic renewal would mean storing the account password. |
| **IVPN** | Your own public key, added in the client area | Public (`api.ivpn.net/v5/servers.json`) | `api.ivpn.net/v4/geo-lookup` | Removed in 2023 | Technically close to Mullvad. |
| **AirVPN** | A per-device config from the client area's generator; there is an official API keyed per user | Public status list; all servers share one public key | `airvpn.org/api/whatismyip/` | Yes: static ports reserved in the client area | Needs preshared-key support (the config converter drops it today), a way to identify the server other than its shared public key, and live testing of the config and forwarding. It would suit people who want port forwarding. |

### Harder

| Provider | Why |
|---|---|
| **Proton VPN** | WireGuard configs are certificates that expire after at most a year and can be revoked only in the dashboard. The server list now needs a logged-in session, possibly with two-factor authentication. It does offer port forwarding (NAT-PMP on P2P servers). Support would probably mean a config you create in the dashboard, plus stored credentials to refresh the server list, and a warning before the certificate expires. |
| **Windscribe** | Manual WireGuard needs a paid account (Pro, or Build-A-Plan for the locations bought), and it hasn't been confirmed whether switching servers needs a per-server API call. Seven-day port forwarding needs Pro. |
| **TorGuard** | Configs are tied to one server and have historically expired. TorGuard publishes [API examples](https://torguard.github.io/openwrt-scripts/#torguards-wireguard-api-v1) for registration and renewal; whether they still work, and how renewal behaves now, needs live testing. It would work like PIA. |

### Not possible now

| Provider | Why |
|---|---|
| **ExpressVPN** | WireGuard runs only inside its own apps, and there's no exportable config. Otherwise it uses its own protocol, Lightway. |
| **CyberGhost** | Manual configurations are OpenVPN only. WireGuard needs its proprietary client. |
| **Mozilla VPN** | It runs on Mullvad's servers, but registering a device needs an interactive browser login. Use Mullvad directly instead. |

Not surveyed: PureVPN, hide.me, Perfect Privacy, PrivateVPN, and smaller
providers. An issue with details about one of them is welcome.

## Adding one yourself

[Providers](providers.md#adding-a-provider) lists what a provider needs in the
code. A pull request should come with the live verification from a real
host and client, recorded in [testing](testing.md). Without it, it can only
be merged as an unverified experiment.
