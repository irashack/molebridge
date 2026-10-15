# File tools reference

Molebridge's setup and repair tools are roles of the one image, run as a
throwaway container: `ghcr.io/irashack/molebridge:<tag> <tool> [arguments]`.
Nothing is installed on the host and no Python is needed. The role is always
the first argument; it is never guessed from the environment. Each tool takes
its inputs and outputs as explicit paths *inside the container*, so every
invocation mounts them. Replace `<tag>` with the release you run, ideally the
exact reference your Compose file pins (tag and digest), so the tool is the
image you verified: [setup](setup.md#2-configure) sets `IMAGE` to it, and the
commands there use `"$IMAGE"` where this page shows the reference.

The image's other roles are not tools: `exit` and `panel` are the two
containers, `health` is the exit's container health check, `status` prints the
exit's verdict from inside it ([other roles](#other-roles)), and `port-sync` is a
container of a [native sidecar](native-sidecar.md) ([port-sync](#port-sync)).

This page is the reference. Where the tools sit in the setup order is in
[setup.md](setup.md).

## Running a tool

**Docker.** Run as yourself so private files are never owned by root:

```sh
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/<host dir>:/out" \
  ghcr.io/irashack/molebridge:<tag> <tool> ...
```

**Rootless Podman.** Leave `--user` out. The default user-namespace mapping
turns the container's root into you, so the files are yours:

```sh
podman run --rm -v "$PWD/<host dir>:/out" \
  ghcr.io/irashack/molebridge:<tag> <tool> ...
```

On an SELinux host add `:z` to each Podman mount (`-v "$PWD/dir:/out:z"`). A
rootful Podman run takes the Docker form.

Rules that hold for every tool:

- The tools write only to the paths you give them. If you forget a mount, the
  tool writes inside the container and the file is gone when it exits, while
  the message still names the path you gave. Check that the file appeared on
  the host.
- Private files are mode `0600`. All but the `nordvpn-key` output are written
  to a temporary file in the same directory and renamed into place, so a reader
  sees the old file or the new one; `nordvpn-key` instead creates its output
  exclusively and never replaces a file. A failure leaves no temporary or
  partial file behind.
- No tool prints a key, token, API key or any text taken from a file it read.
  Messages are fixed text, with only the paths and setting names you supplied.
- Exit status: `0` success, `1` a refusal, `2` a usage error. For
  `prepare-config`, `nordvpn-key`, `gluetun-auth` and `gluetun-post-rules`,
  `-h` or `--help` prints the tool's help and exits `0`. `fix-blacklist` and
  `check-config` take no arguments and answer any with their usage line and `2`.
- A role name the binary doesn't know prints `molebridge: unknown role "<name>"`
  and the list of roles, and exits `2`; so does running it with no role.
- A tool never reads the network except `nordvpn-key`, which makes the one
  request described below.

Settings that a tool reads from the environment are passed with `-e NAME=value`.
An `--env-file` works only when its lines are plain `NAME=value`: Docker does
not strip quotes or an `export` prefix, so a Compose `.env` written that way
must be edited or the values passed with `-e`.

| Tool | Writes | Environment | Section |
|---|---|---|---|
| `prepare-config` | `<out>/mullvad.conf` or `<out>/pia.conf` (0600) | `EXIT_TABLE` | [below](#prepare-config) |
| `nordvpn-key` | `<out>/nordvpn.conf` (0600) | `EXIT_TABLE` | [below](#nordvpn-key) |
| `gluetun-auth` | `<dir>/auth.toml`, `<dir>/api_key` (0600) | none | [below](#gluetun-auth) |
| `gluetun-post-rules` | `<dir>/post-rules.txt` (0644) | routing settings | [below](#gluetun-post-rules) |
| `fix-blacklist` | the NetBird profile, in place | `EXIT_IF`, `TUNNEL_BACKEND`, `NB_STATE_DIR` | [below](#fix-blacklist) |
| `check-config` | nothing | the exit's settings | [below](#check-config) |

## prepare-config

Turns a WireGuard config downloaded from Mullvad into Molebridge's tunnel
config, or creates a new PIA tunnel config with a fresh private key.

```
molebridge prepare-config DOWNLOADED.conf OUTPUT
molebridge prepare-config --pia OUTPUT
```

**Mullvad.**

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/tunnel/wg_confs:/out" \
  -v "$HOME/Downloads/mullvad.conf:/in.conf:ro" \
  ghcr.io/irashack/molebridge:<tag> prepare-config /in.conf /out/mullvad.conf
```

The same with `podman run --rm` and no `--user`. The output name must be
`<EXIT_IF>.conf`; the exit reads `tunnel/wg_confs/mullvad.conf` by default.

- Input: the file Mullvad's WireGuard configuration generator produced, at most
  64 KiB and valid UTF-8. Only the private key, the tunnel addresses and the
  first peer are kept. The first value of a repeated key wins; sections other
  than `[Interface]` and the first `[Peer]` are ignored. The `DNS` line is
  dropped on purpose (clients keep their own resolvers).
- Output: mode `0600`, replaced atomically if it exists, parent directories
  created. It has `MTU = 1420`, `Table = off` and the two route hooks for the
  exit table, which the exit reads as route operations and never runs as shell.
  The downloaded server becomes the starting peer with
  `PersistentKeepalive = 25`; the panel changes it later.
- `EXIT_TABLE` (default `51821`) sets the table in the hooks. Pass
  `-e EXIT_TABLE=<n>` only if you changed it for the exit; the exit refuses a
  config written for another table.
- Requirements, each a refusal: a canonical 32-byte base64 `PrivateKey` and
  `PublicKey`; an `Address` with exactly one IPv4 host address and at most one
  IPv6 host address (`/32` and `/128`); an IPv4 `Endpoint` with a port from 1 to
  65535; `EXIT_TABLE` from 256 to 2147483647.
- Prints `wrote OUTPUT (mode 0600); delete DOWNLOADED now`. The names are the
  in-container paths. Delete the original file on the host.

**PIA.** Creates a new config with a new private key and no address or peer;
the exit registers the key with PIA and sets both for each region.

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/tunnel/wg_confs:/out" \
  ghcr.io/irashack/molebridge:<tag> prepare-config --pia /out/pia.conf
```

- The key is 32 bytes from the system random source, clamped as `wg genkey`
  does. It is never printed.
- An existing OUTPUT is never overwritten.
- Prints `wrote OUTPUT (mode 0600)`.

Messages (standard error, exit status 1; each starts `error: `):

| Message | Cause |
|---|---|
| `Interface PrivateKey is missing or is not a WireGuard key` | no key, or not 32-byte canonical base64 |
| `Peer PublicKey is missing or is not a WireGuard key` | same, for the peer |
| `Interface Address is not valid` | an address that does not parse |
| `Interface Address has no IPv4 tunnel address` | no IPv4 address |
| `Interface Address has more than one address in a family` | two IPv4 or two IPv6 addresses |
| `Interface Address must be host addresses (/32 and /128)` | a subnet prefix |
| `Peer Endpoint must be an IPv4 address and port` | hostname, IPv6 or no port |
| `Peer Endpoint port must be 1..65535` | port out of range |
| `EXIT_TABLE must be an unreserved table number (256..2147483647)` | bad `EXIT_TABLE` |
| `the downloaded config is larger than 64 KiB` | input too large |
| `the downloaded config is not valid UTF-8` | input not text |
| `<OUTPUT> exists; keep it, or remove it deliberately to make a new key` | `--pia` with an existing file |
| `open <path>: <reason>` | the input cannot be opened, or a file or directory for the output cannot be created (`mkdir <path>: <reason>` for the latter) |
| `the tunnel config could not be written` | any other failure writing the output |

Usage errors (`usage: molebridge prepare-config DOWNLOADED.conf OUTPUT` and
`       molebridge prepare-config --pia OUTPUT`) exit `2`.

## nordvpn-key

Fetches your NordLynx private key with a NordVPN access token and writes
Molebridge's tunnel config for NordVPN. Create the token in your Nord Account
under NordVPN, Advanced settings, Get access token.

```
molebridge nordvpn-key TOKEN_FILE OUTPUT
molebridge nordvpn-key - OUTPUT
```

From a token file (mode `0600` or stricter on the host):

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/tunnel/wg_confs:/out" \
  -v "$PWD/nordvpn-token:/token:ro" \
  ghcr.io/irashack/molebridge:<tag> nordvpn-key /token /out/nordvpn.conf
```

From standard input (the container needs `-i`):

```sh
printf %s "$TOKEN" | docker run --rm -i --user "$(id -u):$(id -g)" \
  -v "$PWD/tunnel/wg_confs:/out" \
  ghcr.io/irashack/molebridge:<tag> nordvpn-key - /out/nordvpn.conf
```

The same with `podman run` and no `--user`. A bind-mounted file keeps its host
mode, so `chmod 600` the token file first.

- The token is never read from a command-line argument or the environment. As a
  file it must be a regular file (not a symlink), mode `0600` or stricter; from
  standard input it is read up to 512 bytes. It is 1 to 256 printable ASCII
  characters other than space, quote and backslash, with one trailing newline
  (LF or CRLF) allowed.
- The one request: `GET https://api.nordvpn.com/v1/users/services/credentials`
  with HTTP Basic credentials `token:<token>`. No proxy from the environment is
  used, TLS 1.2 or later is required, redirects are not followed, the whole
  request has a 20 second deadline and the response is limited to 64 KiB. Only
  the `nordlynx_private_key` field of the response is used.
- Output: created exclusively with mode `0600` (never overwritten, a symlink is
  refused), parent directories created. It carries the key and the NordLynx
  address `10.5.0.2/32` but no peer; the exit sets the peer when you pick a
  server. `EXIT_TABLE` (default `51821`) is read as for `prepare-config`.
- Prints one line, `wrote the NordVPN tunnel config (mode 0600)`, and nothing
  else. Delete the token file, or revoke the token in your Nord Account, when it
  succeeds: only the key is needed afterwards.

Messages (standard error, exit status 1; each starts `error: `):

| Message | Cause |
|---|---|
| `the output file exists; keep it, or remove it deliberately` | OUTPUT exists, even as a dangling symlink |
| `the token could not be read` | the file is missing, a symlink, or unreadable |
| `the token file is not a regular file` | a directory, FIFO or device |
| `the token file must be mode 0600 or stricter` | group or other bits set |
| `the token is too long` | more than 512 bytes |
| `the token is not valid` | not printable ASCII, or empty |
| `the request to NordVPN failed` | network error, HTTP status 400 or above, timeout, oversize response |
| `the NordVPN response is not valid` | not strict JSON |
| `the NordVPN response has no usable key` | no valid `nordlynx_private_key` |
| `the output file could not be created` | the directory cannot be created or the file opened |
| `the tunnel config could not be written` | any other failure, including a bad `EXIT_TABLE` |

The image carries the CA certificates the request needs. A usage error exits
`2` with `usage: molebridge nordvpn-key TOKEN_FILE|- OUTPUT`.

## gluetun-auth

Writes gluetun's control-server role file and the exit's copy of its API key,
both mode `0600`, from one key generated here (32 random bytes, URL-safe
base64, 43 characters). The key is never printed. Needed for the gluetun
backend and the gluetun sidecar.

```
molebridge gluetun-auth [--rotate] DIR
```

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/secrets/gluetun:/out" \
  ghcr.io/irashack/molebridge:<tag> gluetun-auth /out
```

The same with `podman run` and no `--user`. The Compose files read
`./secrets/gluetun/auth.toml` (gluetun's role file) and
`./secrets/gluetun/api_key` (the exit's copy), so `DIR` is that directory.

- Output: `DIR/auth.toml`, exactly one role named `molebridge` with `auth =
  "apikey"`, the key, and these five routes and no others: `PUT
  /v1/vpn/settings`, `GET /v1/vpn/status`, `GET /v1/publicip/ip`, `GET
  /v1/updater/status`, `PUT /v1/updater/status`. `DIR/api_key` holds the same
  key and a newline. `DIR` is created with mode `0700` if it does not exist.
  `routing/gluetun-preflight` refuses to start gluetun with any other role
  file.
- With both files present nothing changes (exit status `0`). With one present,
  the tool refuses until you pass `--rotate`. `--rotate` replaces both with a
  new key; recreate gluetun and the exit container afterwards so both use it.
- Symlinks are refused: `DIR` itself, `api_key` and `auth.toml`.

Messages (the refusals go to standard error with exit status 1; everything
else to standard output):

| Message | Cause |
|---|---|
| `Wrote <DIR>/auth.toml and <DIR>/api_key (mode 0600, key not shown); recreate gluetun and the exit container to use them.` | written |
| `<DIR>/auth.toml and api_key already exist; --rotate replaces them.` | both exist, nothing changed |
| `FAIL Only one of <DIR>/api_key and auth.toml exists; run gluetun-auth --rotate to write both again.` | one file only |
| `FAIL <DIR> and its files must not be symlinks.` | a symlink |
| `FAIL unable to inspect local configuration.` | any operating-system error; its text is withheld |

Usage error: `usage: molebridge gluetun-auth [--rotate] DIR`, exit `2`.

## gluetun-post-rules

Writes gluetun's post-rules file, the iptables accepts an overlay exit needs
under gluetun's DROP policies, from the routing settings. Needed for the
gluetun backend only; a sidecar must not have the file
(`routing/gluetun-preflight` refuses to start gluetun if it is mounted).

```
molebridge gluetun-post-rules [--ipv4-only] DIR
```

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/tunnel/gluetun:/out" \
  -e OVERLAY_CIDR=<your NetBird range> \
  ghcr.io/irashack/molebridge:<tag> gluetun-post-rules /out
```

The same with `podman run` and no `--user`. The Compose file mounts
`./tunnel/gluetun/post-rules.txt` into gluetun, so `DIR` is `./tunnel/gluetun`.

Settings, validated exactly as the exit validates them. An unset or empty
setting is its default, as in Compose's `${NAME:-default}`:

| Variable | Default |
|---|---|
| `OVERLAY_CIDR` | none; required |
| `OVERLAY6_CIDR` | none; optional |
| `OVERLAY_IF` | `wt0` |
| `EXIT_IF` | `wg0` |
| `EXIT_TABLE` | `51821` |
| `HOST_IF` | `eth0` |
| `HOST_TABLE` | `51822` |
| `CONTROL_MARK` | `0x1bd00` |
| `NB_WIREGUARD_PORT` | `51820` (1 to 65535) |

Pass the same values your `.env` gives the Compose project; the tool does not
read `.env`.

- Output: `DIR/post-rules.txt`, mode `0644` (gluetun reads it as another user),
  replaced atomically. Eight rule lines (`iptables` and `ip6tables`): forward
  overlay to tunnel and back for established connections, accept output on the
  host interface, accept NetBird's WireGuard port in. `--ipv4-only` leaves the
  `ip6tables` lines out, for a host where gluetun finds no `ip6tables`. Every
  line is one gluetun's chain parser accepts.
- The file is regenerated, never edited. Recreate gluetun to apply it.
- A symlinked `DIR`, a symlinked `post-rules.txt` and a non-regular file there
  are refused. The settings are validated before anything is created.

Messages:

| Message | Cause |
|---|---|
| `Wrote <DIR>/post-rules.txt; recreate gluetun to apply it.` | written |
| `FAIL Invalid gluetun routing settings; check OVERLAY_CIDR, CONTROL_MARK, HOST_IF, EXIT_IF, EXIT_TABLE, HOST_TABLE and NB_WIREGUARD_PORT in the environment passed with -e or --env-file (docs/configuration.md).` | any setting is invalid; no value is echoed |
| `FAIL <DIR>/post-rules.txt must be a regular file; remove what is there.` | a symlink, directory or device |
| `FAIL unable to inspect local configuration.` | any operating-system error |

Refusals exit `1`. Usage error: `usage: molebridge gluetun-post-rules
[--ipv4-only] DIR`, exit `2`.

## fix-blacklist

Adds the tunnel interface to the interface blacklist of the stored NetBird
profile, for an exit that refused to start because the profile lacks it. Run it
with the exit **stopped**. It is operator-invoked and never runs by itself. The
daemon created the identity files, so the tool runs as their owner.

```
molebridge fix-blacklist
```

Docker, as the owner of the profile (find the uid and gid with `ls -ln` on the
volume's `default.json`, or on the legacy `config.json`):

```sh
docker run --rm --user <owner uid>:<owner gid> \
  -e EXIT_IF=<name> -e TUNNEL_BACKEND=<native|gluetun> \
  -v <identity volume>:/var/lib/netbird \
  ghcr.io/irashack/molebridge:<tag> fix-blacklist
```

Rootless Podman:

```sh
podman run --rm --userns=keep-id:uid=<owner uid>,gid=<owner gid> \
  -e EXIT_IF=<name> -e TUNNEL_BACKEND=<native|gluetun> \
  -v <identity volume>:/var/lib/netbird \
  ghcr.io/irashack/molebridge:<tag> fix-blacklist
```

For a legacy profile at `/etc/netbird/config.json`, add the containing
directory: `-v <legacy directory>:/etc/netbird`. It takes no arguments; the
settings are the exit's non-secret ones, so it resolves the same profile the
daemon will load: `TUNNEL_BACKEND` (`native`, the default, or `gluetun`; the older
spelling `wireguard` is accepted too),
`EXIT_IF` (default `mullvad`, `wg0` with gluetun) and `NB_STATE_DIR` (default
`/var/lib/netbird`).

It refuses without changing anything when it can see a NetBird daemon (its
socket answers, or a process named `netbird` runs; it can't see one in
another container, which is why you stop the exit first), when the active
profile is not the default, when no identity exists (it never creates one),
when the JSON is malformed or ambiguous (a repeated key, or a field name
outside printable ASCII), when `IFaceBlackList` isn't a list of strings, or
when it cannot preserve the file's mode, owner and group. It
reproduces NetBird's default filling when the list is absent, null or empty,
keeps every operator exclusion and every other field byte for byte, and
replaces the file atomically.

Prints `fix-blacklist: added the tunnel interface <if> to the interface
blacklist of the stored NetBird profile <path>` or `fix-blacklist: the stored
NetBird profile <path> already excludes the tunnel interface <if>; nothing
changed`. Refusals go to standard error with exit status `1`; a usage error
exits `2`.

## check-config

Validates what the exit validates when it starts, with the exit's own environment, and
changes nothing: the routing settings, `PROVIDER` against the backend and kind, the tunnel
config (native exits: the grammar, the table and the file's type and size), NetBird's
environment and stored profile, the interface blacklist, and that `state/applier` is
writable by the process. It does not create the state directory, which the exit does at a
real start, and it makes no network request.

```
molebridge check-config
```

It takes no arguments; the settings are the exit's, so run it through Compose, which
supplies them, the mounts and the capabilities:

```sh
docker compose run --rm --no-deps exit check-config
```

(For the gluetun forms, start gluetun first: the exit joins its namespace.) On success it
prints, for a native exit,
`molebridge-exit: configuration accepted (/config/wg_confs/<EXIT_IF>.conf: an IPv4 address and an IPv6 address)`
(or `an IPv4 address`, or `no address (the exit sets it)` for PIA; a native sidecar prints the same line), and for the other kinds
`molebridge-exit: configuration accepted`; then, for an overlay exit,
`NetBird gate: configuration accepted`. A refusal is the one line the exit would print at start,
on standard error, with exit status `1` ([troubleshooting](troubleshooting.md#startup)). A usage error
(`usage: molebridge check-config (settings come from the environment)`) exits `2`.

## port-sync

Keeps qBittorrent's listening port on the port PIA forwarded to a
[native sidecar](native-sidecar.md#port-forwarding). It is a container, not a
throwaway tool: run it with no capabilities, in the same network namespace as
qBittorrent (in Compose, `network_mode: service:exit`; in Kubernetes, a further
container of the pod), so the exit never holds qBittorrent's credentials. It
writes nothing and starts no process.

```
molebridge port-sync
```

It takes no arguments; settings come from the environment
([configuration](configuration.md#the-port-sync-role)):

| Setting | Default | Meaning |
|---|---|---|
| `PORT_SYNC_CLIENT` | required | `qbittorrent`, the only client |
| `PORT_SYNC_URL` | `http://127.0.0.1:8080` | qBittorrent's Web API: `http`, a loopback IP address (`127.0.0.0/8` or `[::1]`), an optional port, no user name, path, query or fragment |
| `PORT_SYNC_USERNAME_FILE`, `PORT_SYNC_PASSWORD_FILE` | empty | The Web UI login, one value per file (at most 1 KiB, one trailing newline removed, not empty). Both or neither. With neither the role sends no login |
| `PORT_SYNC_INTERVAL` | `30` | Seconds between passes, a whole number from 10 to 300 |
| `STATE_DIR` | `/state` | The exit's state directory; the role reads `applier/result.json` there |

**What it does.** At once, and then every `PORT_SYNC_INTERVAL` seconds, it reads
`result.json` with the same strict reader the panel uses (at most 16 KiB,
duplicate keys refused). It acts only when the record is no more than 150
seconds old, its `kind` is `sidecar`, and `forwarded_port` is an integer from
1024 to 65535. Then it asks qBittorrent for `GET /api/v2/app/preferences`, and
if `listen_port` is not that port, sends `POST /api/v2/app/setPreferences` with
`json={"listen_port":<port>,"random_port":false,"upnp":false}`. With
credentials it logs in first (`POST /api/v2/auth/login`) and keeps the session
cookie in memory; after a 403 it logs in again once and repeats the request.
It sends qBittorrent's own address as the `Referer`, which qBittorrent checks.
Neither the password nor the cookie is ever logged.

**Messages.** Every line goes to standard error, starts `molebridge-port-sync: `
and is fixed text. A change is logged every time:
`molebridge-port-sync: qBittorrent listens on <old>; set to <new>`. A pass that
finds the port already right logs nothing. Each kind of failure is logged at
most once a minute:

| Message | Meaning |
|---|---|
| `no current status record from the exit` | `result.json` is missing, malformed, over 16 KiB or older than 150 seconds |
| `the status record is not a sidecar's` | `kind` is not `sidecar` |
| `no forwarded port yet` | The record has no `forwarded_port`. Said once, until a port appears |
| `the status record's forwarded_port is not an integer from 1024 to 65535` | The record's value is out of range |
| `qBittorrent could not be reached (<reason>)` | `<reason>` is `request timed out` (10 seconds), `request failed`, `response exceeds its size limit` or `request canceled` |
| `qBittorrent refused the request (HTTP 403); it needs the login: set PORT_SYNC_USERNAME_FILE and PORT_SYNC_PASSWORD_FILE` | No credentials are set and qBittorrent wants them |
| `qBittorrent refused the request (HTTP 403) after a new login` | The login worked and the request was refused anyway |
| `the login credential files cannot be read (PORT_SYNC_USERNAME_FILE, PORT_SYNC_PASSWORD_FILE)` | A file changed or vanished after the start check |
| `qBittorrent refused the login (HTTP 403); it may have banned this address after failed logins` | qBittorrent bans an address after repeated failed logins |
| `qBittorrent answered the login with HTTP <n>` | Any other status |
| `qBittorrent refused the user name or password` | qBittorrent answered `Fails.` |
| `qBittorrent answered the login with an unexpected body` | Neither `Ok.` nor `Fails.` |
| `qBittorrent accepted the login but sent no session cookie` | No `SID` (or, from qBittorrent 5, `QBT_SID_<port>`) cookie |
| `qBittorrent answered the preferences request with HTTP <n>` | Not 200 |
| `qBittorrent's preferences are not a JSON object`, `qBittorrent's preferences have no integer listen_port` | An answer in a shape the role does not accept (bounded to 256 KiB) |
| `qBittorrent answered the port change with HTTP <n>` | The `setPreferences` request was not 200 |

**Refusals at start.** A bad setting prints one line of the form
`molebridge-port-sync: <reason>` and exits with status `1`, before anything is
sent. The reasons are:

- `PORT_SYNC_CLIENT is required (the only client is qbittorrent)` and
  `PORT_SYNC_CLIENT must be qbittorrent`;
- `PORT_SYNC_URL must be an http URL (https is refused: the application is on a loopback address)`,
  `PORT_SYNC_URL must not contain a user name or password`,
  `PORT_SYNC_URL must not contain a query or fragment`,
  `PORT_SYNC_URL must not contain a path`,
  `PORT_SYNC_URL must name a loopback IP address (127.0.0.0/8 or [::1])` (a host
  name such as `localhost` is refused too) and `PORT_SYNC_URL has an invalid port`;
- `PORT_SYNC_USERNAME_FILE and PORT_SYNC_PASSWORD_FILE must be set together or not at all`;
- `PORT_SYNC_USERNAME_FILE: <reason>` or `PORT_SYNC_PASSWORD_FILE: <reason>`, where
  the reason is `cannot be opened`, `is not a regular file`, `cannot be read`,
  `is larger than 1 KiB` or `is empty`;
- `PORT_SYNC_INTERVAL must be a whole number of seconds from 10 to 300`.

**Exit status.** `0` after `SIGTERM` or `SIGINT`, `1` for a refusal at start,
`2` for an argument (`usage: molebridge port-sync (settings come from the environment)`).
It never exits because qBittorrent or the record is unavailable: it logs and
tries again at the next interval.

## Other roles

These run as containers or inside the exit, not as throwaway tools. Settings
come from the environment, and none takes arguments.

| Role | What it does | Exit status |
|---|---|---|
| `exit` | The exit container's supervisor. It starts itself again as `--worker` and `--cleanup`; those two flags are internal, and any other argument prints `molebridge-exit: the only arguments are the internal --worker and --cleanup`. A refused setting prints one line on standard error and the exit stops; most settings are refused before anything changes, and the provider's own settings after the routing rules are in place, still before NetBird starts ([what the exit checks at start](operations.md#what-the-exit-checks-at-start)). | `1` a refusal or an unexpected stop, `2` bad arguments; the stop statuses are in [the stop sequence](architecture.md#the-stop-sequence) |
| `panel` | Switchyard. A refused setting prints `molebridge panel: <reason>`; a failed isolation check prints `molebridge panel: refusing to start: <reason>` ([the panel's isolation check](configuration.md#the-panels-isolation-check)). | `1` a refusal, `2` for an argument (`usage: molebridge panel (settings come from the environment)`) |
| `health` | The container health check. Prints nothing and exits `0` while the worker's heartbeat is no more than 15 seconds old (written every 5 seconds while the operational checks pass); otherwise prints `unhealthy: <reason>`. A failed provider verification never makes it fail ([health](architecture.md#health)). | `0` healthy, `1` unhealthy, `2` for an argument (`usage: molebridge health`) |
| `port-sync` | Keeps qBittorrent's listening port on a native sidecar's forwarded port; see [port-sync](#port-sync). | `0` after a stop signal, `1` a refusal at start, `2` for an argument |
| `status` | Prints the exit's verdict from `state/applier/result.json` and the panel's request: `state: <state> (<label>)`, `reasons:`, `egress tier:` when there is one, `checks:`, `message:` and `configured server:` when present, then `heartbeat:` (fresh, stale or none) and `lease:`. Run it inside the exit: `docker compose exec exit molebridge status`. Nothing printed is secret. It doesn't check a sidecar's attachment or the host. | `0` when the state is `ok`, `1` otherwise or for a bad `PROVIDER` or `EXIT_KIND`, `2` for an argument (`usage: molebridge status`) |
