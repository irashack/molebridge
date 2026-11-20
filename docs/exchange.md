# The network exchange

The network exchange is an extra for an exit and a Switchyard that can't
share a filesystem: on Kubernetes, an exit and a panel in different pods or
on different nodes. It carries the files they would otherwise share over
HTTP, so neither mounts the other's directory. It is **experimental**.

It changes nothing about the guarantee of the way in it runs beside. The exit
still serves no HTTP: it makes outbound requests only, from a child process
that holds none of the exit's secrets except its own exchange token, and the
panel still only writes the name of the server you picked.

## Status

Run live on Kubernetes with a NordVPN NetBird exit only
([testing](testing.md#v0100-rc2-2026-11-03-released)), and every release's
live acceptance since includes the exchange drill
([verification](verification.md#the-network-exchange) lists what it checks).
CI runs it in the system rig. It has not been run with the gluetun backend,
with Mullvad or PIA, or with the native sidecar. A
[multi-provider exit](multi-provider.md) refuses it.

## How it works

By default the panel reads the exit's `state/applier/` through a read-only
mount, and the exit reads the panel's `state/panel/`. With the exchange:

- **On the exit**, `EXCHANGE_URL` makes the exit's supervisor start
  `molebridge exit --exchange`. Every 2 seconds it fetches the panel's
  request into the exit's own `state/panel/desired.json`, and sends
  `result.json`, `relay-error.json` and `relays.json` when they changed.
- **On the panel's side**, a container running the `exchange` role receives
  those files and writes them to `state/<id>/applier/`, and hands out
  `state/<id>/panel/desired.json`. It shares the panel's state directory, in
  the panel's pod or on the panel's host, and is the one listener for every
  exit.
- **In the panel**, `PANEL_NETWORK_EXITS` names the exits reached this way,
  so the panel judges each by the link as well as by its record.

Nothing changes for an exit without `EXCHANGE_URL`, and the panel can serve
exits reached by files and by the exchange side by side. The design is in
[architecture](architecture.md); the protocol is two requests,
`GET /v1/exits/<id>` and `PUT /v1/exits/<id>/files/<file>`, each with the
exit's token as a bearer token and the exit's clock in
`X-Molebridge-Sent-At`.

## Set it up

### 1. Make a token per exit

```sh
head -c 32 /dev/urandom | base64 | tr -d '=+/'
```

Put it in the exit's `secrets/applier.env` as `EXCHANGE_TOKEN=…` (beside
`GATUS_TOKEN`), and in the exchange's tokens directory as a file named by the
exit's id, mode 0600 for the exchange's user. The file must be a regular
file, not a symbolic link. It is read on every request, so a changed file
takes effect at once.

On Kubernetes, mount each token file with `subPath`: a Secret volume presents
its files as symbolic links, which the exchange refuses (as the exit refuses
them for its own key and token files), and it would then warn at start and
answer that exit with 401. A file mounted with `subPath` doesn't follow later
changes to the Secret, so after you rotate a token restart the exchange, and
the exit, whose `EXCHANGE_TOKEN` comes from its environment.

### 2. The exit

| Setting | Default | Meaning |
|---|---|---|
| `EXCHANGE_URL` | empty | The exchange's base URL, `https://` or `http://`, with a host and no credentials, query or fragment. Empty: files only. |
| `EXCHANGE_EXIT_ID` | empty | The exit's id at the exchange, its id in the panel's `PANEL_EXITS`: 1 to 32 of `a-z`, `0-9` and `-`. Required with `EXCHANGE_URL`. |
| `EXCHANGE_TOKEN` | empty | In `secrets/applier.env`: at least 32 printable characters with no spaces. Required with `EXCHANGE_URL`. |
| `EXCHANGE_CA_FILE` | empty | A PEM file of the authority the exchange's certificate must chain to, instead of the system's. |
| `EXCHANGE_TLS_NAME` | empty | The name the exchange's certificate must carry, when it isn't the URL's host. |

The bundled Compose files don't pass `EXCHANGE_URL` and its settings; set
them on the `exit` service in an override (the token already arrives through
`secrets/applier.env`):

```yaml
services:
  exit:
    environment:
      EXCHANGE_URL: https://exchange.example.net:8097
      EXCHANGE_EXIT_ID: home
```

The exchange client's connections carry the control mark, so they take the
exit's host path, as the provider downloads do. It gets only its own
settings, the state directory, the provider and the mark: never the tunnel
key, the provider's login, the setup key or the Gatus token. When it ends,
the supervisor starts it again after a second, doubling to a minute; nothing
else stops.

The client writes `desired.json` only when the panel's request differs from
the one there, after checking it as the exit itself does, and never deletes
it. An exchange that can't be reached, or has no request, leaves the exit on
its last request. So the exit's `state/panel/` is the exit's own here: keep
it on the exit's volume, writable by the exit, beside `state/applier/`.
Moving the exit then means moving that one volume, with `netbird-data` and
the mounted secrets.

### 3. The exchange

Run the image with the command `exchange`, beside the panel, sharing its
state directory. It runs with no capabilities (`cap_drop: [ALL]`) and not as
root: as `PANEL_USER`, so it can read the panel's `desired.json`
(`PANEL_ALLOW_ROOT` works as for the panel).

| Setting | Default | Meaning |
|---|---|---|
| `PANEL_EXITS` | empty | The panel's list. The exchange serves each exit in it, by id; it can't be empty. |
| `STATE_DIR` | `/state` | The panel's state directory. The exchange writes `<id>/applier/` and `<id>/exchange.json` and reads `<id>/panel/desired.json`. |
| `EXCHANGE_LISTEN` | `0.0.0.0:8097` | Address and port, with a host. Publish it to the exits only, never through the panel's proxy or sign-in. |
| `EXCHANGE_TOKENS_DIR` | `/run/secrets/exchange` | One token file per exit, named by its id. |
| `EXCHANGE_CERT_FILE`, `EXCHANGE_KEY_FILE` | empty | A certificate and key to serve HTTPS; both or neither. |

The exchange answers an unknown exit and a wrong token alike, with 401. It
refuses a file over its limit (the status record 16 KiB, the refresh error
4 KiB, the server list its provider's), invalid UTF-8, duplicate keys or
anything but a JSON object, and writes what it accepts with mode 0644. Its
first log line is `molebridge exchange: molebridge <version>`.

### 4. The panel

`PANEL_NETWORK_EXITS` lists, comma-separated, the ids of the exits in
`PANEL_EXITS` that are reached through the exchange. For each, the panel
reads `state/<id>/exchange.json`, which the exchange writes after every
request on its own clock:

- with none, or none in the last 15 seconds, the verdict is `unknown` with
  the reason `exit-unreachable` and the label "exit unreachable", whatever
  the copy of the record says;
- with the exit's and the exchange's clocks more than 10 seconds apart, it
  is `unknown` with `clock-skew` and the label "clocks differ". Keep both
  hosts on time sync.

Such an exit can't have a proxy view: the exchange does not carry
`proxy.json` ([the proxy view](switchyard.md#the-proxy-view)).

## The log

On the exit, a failed round is logged when it starts, when the reason
changes and every 10 minutes, and recovery once:

```text
molebridge-exit: exchange: round failed: <reason>
molebridge-exit: exchange: works again
```

A 401 means a wrong `EXCHANGE_TOKEN` or `EXCHANGE_EXIT_ID`, or a token file
the exchange refused. With an `http://` URL whose host isn't `localhost` or
a loopback address, the exit warns at start:

```text
molebridge-exit: exchange: warning: EXCHANGE_URL is plain http:// to a host other than loopback; the exchange token crosses the network unencrypted (use https://)
```

On the exchange, at start, for each exit without a usable token file:

```text
molebridge exchange: warning: no usable token for exit <id>; its requests are refused
```

## Refusals

The exit stops at start with one line, before anything changes:

| Message | Cause |
|---|---|
| `molebridge-exit: EXCHANGE_URL must be an http:// or https:// URL with a host and no credentials, query or fragment` | A bad URL |
| `molebridge-exit: EXCHANGE_EXIT_ID must be the exit's id at the exchange: 1-32 of a-z, 0-9 and -` | Missing or malformed id |
| `molebridge-exit: EXCHANGE_TOKEN (in secrets/applier.env) must be at least 32 printable characters with no spaces` | Missing or short token |
| `molebridge-exit: EXCHANGE_CA_FILE: <reason>` | The CA file can't be read or holds no PEM certificate |
| `molebridge-exit: EXCHANGE_URL is not supported on a multi-provider exit (PROVIDERS) yet` | With `PROVIDERS` set |

The exchange stops at start with one line:

| Message | Cause |
|---|---|
| `molebridge exchange: PANEL_EXITS names no exit; the exchange serves exits by their ids` | `PANEL_EXITS` empty |
| `molebridge exchange: EXCHANGE_LISTEN is host:port with a host, such as 0.0.0.0:8097` | A bad listen address |
| `molebridge exchange: EXCHANGE_CERT_FILE and EXCHANGE_KEY_FILE go together` | Only one of them |
| `molebridge exchange: refusing to start: the exchange must run with no capabilities (cap_drop: [ALL]); its effective capability set is not empty` | Capabilities left |
| `molebridge exchange: refusing to start: the exchange cannot read its capability set from /proc/self/status, so it cannot show it has none` | No `/proc/self/status` |
| `molebridge exchange: refusing to start: the exchange must not run as root; run it as PANEL_USER, the panel's uid:gid (on a rootless engine, 0:0 with PANEL_ALLOW_ROOT=1)` | Running as root |
| `molebridge exchange: cannot listen: <reason>` | The port is taken or not allowed |

The panel stops at start with:

| Message | Cause |
|---|---|
| `molebridge panel: PANEL_NETWORK_EXITS: '<id>' is not an exit in PANEL_EXITS` | An unknown id |
| `molebridge panel: PANEL_NETWORK_EXITS: '<id>' is a multi-provider exit, which the network exchange does not carry` | A multi-provider exit |
| `molebridge panel: PANEL_PROXY_STATUS: '<id>' is reached through the network exchange, which does not carry proxy.json` | A proxy view for an exchange exit |

[Troubleshooting](troubleshooting.md#the-network-exchange) covers a panel
that shows "exit unreachable" or "clocks differ".
