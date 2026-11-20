# Design: the menu of ways in (retired)

Status: **retired** (2026-11-20). This was the working contract for building
the menu of ways in, and it said it would go once its pieces shipped. They
shipped in 0.14.0, and their user and reference documentation replaces it.
The page stays only so that the links to it in the changelog, in code
comments and in the 0.14.0 binary's messages still lead somewhere. Each
heading below is a section the contract had, and says where it went.

## The pieces

The menu: [choosing ways in and extras](../menu.md). What was built when:
[the roadmap's direction](../../ROADMAP.md#direction).

## The guarantee

Each way in's guarantee is stated first on its own page and in
[the menu](../menu.md#the-ways-in); the proxy's in [the proxy](../proxy.md).

## The tunnel dialer

How the proxy binds every connection and its DNS to the tunnel interface:
[how it keeps the guarantee](../proxy.md#how-it-keeps-the-guarantee), and the
code in `internal/tunneldial`.

## Relay proxies

Locations, Mullvad's relay proxies, choosing and benching servers:
[the username](../proxy.md#choosing-where-a-connection-leaves-the-username). The code
is `internal/relayproxy`.

## The proxy

[The proxy](../proxy.md): set-up, settings, where it listens, the password,
limits. Every setting is also in [configuration](../configuration.md#the-proxy).

## The proxy's status

`proxy.json` and `molebridge status --proxy`: [status](../proxy.md#status) and
[state files](../configuration.md#state-files).

## The menu

`molebridge init`: [setup](../setup.md#molebridge-init) runs it, and
[what combines](../menu.md#what-combines) lists the combinations it writes
and the ones it refuses, with its messages.

## NetBird as a module

How the exit reaches NetBird through one boundary:
[architecture](../architecture.md).

## Testing

The proxy's live drill: [verification](../verification.md#the-proxy). Its
system-rig drill: [the system rig](../../CONTRIBUTING.md#the-system-rig). What
has run: [testing](../testing.md).
