# Setup

This takes the signed release bundle to a running stack, for any way in:
the NetBird exit, a sidecar or the proxy. You verify the bundle, let
`molebridge init` write a Compose file and an `.env` for what you chose,
create the secrets, start it and check it. Choose the ways in and extras
first ([the menu](menu.md)), and have everything in
[requirements](prerequisites.md) ready. Plan for about half an hour; for a
NetBird exit most of it is in the NetBird dashboard.

**What was tested.** Molebridge is experimental. Its live runs used Quadlet
units on a Debian host with rootless Podman 5.8, and Kubernetes manifests,
neither of which this repository ships. The Compose commands on this page are
what the bundle is for, but they have not been run on any engine, and Docker
Engine on Linux and NetBird Cloud are untested too
([testing](testing.md#not-tested-at-080)). `molebridge init` has been checked
by CI only: every combination it accepts resolves with `docker compose config`,
and each service it writes resolves exactly as the same service of the
shipped file it comes from (`tools/check-compose.sh`). No stack it wrote has
been started on any host, and running it from the image, as below, has not
been tried. If you use Quadlet, a unit needs the settings in `compose.yaml`
([the list in the upgrade notes](operations.md#upgrading-from-07x), step 3).
Keep a way into the host that doesn't depend on the exit.

**Rootless Podman.** Use `podman-compose` where this page says
`docker compose`, and `podman run` where it says `docker run`, and leave
`--user "$(id -u):$(id -g)"` out of the `run` commands: the default mapping
makes the container's root you ([tools reference](tools-reference.md#running-a-tool)).
podman-compose doesn't read `COMPOSE_FILE` from `.env`: where you set it,
pass the same files with `-f` on every command
(`podman-compose -f compose.yaml -f compose.apps.yaml up -d`). The [rootless
Podman notes](prerequisites.md#rootless-podman) list the other differences.

## 1. Download and verify

The release is a signed container image and a small bundle of Compose files
that pins that image by tag and digest. Check both before you run anything.
The release notes print every command below with this release's values
filled in; copy from there. This page explains the order and what each step
proves.

You need `cosign` v3.1.3, the GitHub CLI (`gh`) 2.102.0 or later and `jq`.
`gh attestation verify` asks GitHub for the attestations; if it asks you to
sign in, do. Set these from the release notes, which also list the source
commit and the image digests:

```sh
TAG=v0.14.0           # the release tag
RC=v0.14.0-rc.1       # the candidate tag the release notes name: the build ran under it
COMMIT=<source commit from the release notes>
DIGEST=sha256:<index digest from the release notes>
REPO=irashack/molebridge
ISSUER=https://token.actions.githubusercontent.com
WF=https://github.com/$REPO/.github/workflows
```

A release is promoted from a candidate without being rebuilt, so three
different workflow identities sign different things, and you check each one:
the build workflow (`release.yml` at the candidate's tag) for the provenance
and the SBOMs, the acceptance workflow (`acceptance.yml` on `main`) for the
live-acceptance attestation, and the release workflow (`release.yml` at the
release tag) for the image signature and the bundle. Do the steps in this
order.

**a. The bundle.** Download `molebridge-$TAG.tar.gz` and
`molebridge-$TAG.tar.gz.sigstore.json` from the release's assets. Verify
the archive, then extract it:

```sh
cosign verify-blob \
  --bundle molebridge-$TAG.tar.gz.sigstore.json \
  --certificate-identity $WF/release.yml@refs/tags/$TAG \
  --certificate-oidc-issuer $ISSUER \
  molebridge-$TAG.tar.gz
gh attestation verify molebridge-$TAG.tar.gz --repo $REPO \
  --cert-identity $WF/release.yml@refs/tags/$TAG \
  --cert-oidc-issuer $ISSUER
tar -xzf molebridge-$TAG.tar.gz
cd molebridge-$TAG
```

The bundle is signed so that a signed image can't be paired with an unsigned
Compose file that changes privileges, mounts or entrypoints.

**b. The image index.** The image to verify is the one the extracted
`compose.yaml` names, `ghcr.io/irashack/molebridge:$TAG@sha256:...`. Its
digest must equal `$DIGEST`. The signature is bound to the repository, the
workflow, the issuer and the source commit:

```sh
cosign verify \
  --certificate-identity $WF/release.yml@refs/tags/$TAG \
  --certificate-oidc-issuer $ISSUER \
  --certificate-github-workflow-repository $REPO \
  --certificate-github-workflow-sha $COMMIT \
  ghcr.io/$REPO@$DIGEST
```

**c. The build provenance** names this commit and the build workflow:

```sh
gh attestation verify oci://ghcr.io/$REPO@$DIGEST --repo $REPO \
  --cert-identity $WF/release.yml@refs/tags/$RC \
  --cert-oidc-issuer $ISSUER \
  --source-digest $COMMIT \
  --predicate-type https://slsa.dev/provenance/v1
```

**d. The live-acceptance attestation.** A release is promoted only when a
maintainer's acceptance run attested that this exact image passed the live
drills:

```sh
gh attestation verify oci://ghcr.io/$REPO@$DIGEST --repo $REPO \
  --cert-identity $WF/acceptance.yml@refs/heads/main \
  --cert-oidc-issuer $ISSUER \
  --predicate-type https://github.com/irashack/molebridge/attestations/live-acceptance/v1 \
  --format json | jq '.[].verificationResult.statement.predicate'
```

`result` must be `passed`, `commit` must be `$COMMIT`, and the platforms,
providers, kinds and drills it lists must be the ones you need. A candidate
(`-rc`) has no such attestation and says so in its notes; don't install a
candidate on an exit you rely on.

**e. The SBOMs.** The signed index references one manifest per architecture,
and each has an SBOM attestation from the build workflow. The release notes
list the two manifest digests:

```sh
for manifest in sha256:<amd64 manifest> sha256:<arm64 manifest>; do
  gh attestation verify oci://ghcr.io/$REPO@$manifest --repo $REPO \
    --cert-identity $WF/release.yml@refs/tags/$RC \
    --cert-oidc-issuer $ISSUER \
    --predicate-type https://spdx.dev/Document/v2.3
done
```

The SBOM documents are also attached to the release.

**f. molebridge-core**, if you run a sidecar or the proxy. Steps b to e
check `ghcr.io/irashack/molebridge`. The sidecars and the proxy run
`ghcr.io/irashack/molebridge-core`, built from the same commit and promoted
with it. Verify it the same way, with the same identities and commit: steps b
to d with `ghcr.io/irashack/molebridge-core@<core index digest>` in place of
`ghcr.io/$REPO@$DIGEST`, and step e with its two manifest digests. The
release notes list its digests and print these commands filled in.

What this proves and what it doesn't: the bundle's Compose files and the
images are the ones this repository's workflows built from `$COMMIT`, and
they passed the acceptance run. It says nothing about your `.env`, local
Compose overrides, or files on your host. Those are yours to review.

**Which tags exist.** Each candidate is pushed as `:vX.Y.Z-rc.N` and each
release as `:vX.Y.Z`; the release workflow refuses to move either once it
exists. A release also moves a floating tag without the `v`, such as
`ghcr.io/irashack/molebridge:0.10`, to the highest release of that minor
version. It is a convenience for `docker pull`, nothing more: it changes
with every patch release, and what cosign signed is the image digest, not
the tag, so `cosign verify` on `:0.10` checks whichever digest the tag names
when you ask. The bundle's Compose files never use it; they pin `:$TAG`
together with `@$DIGEST`, and you should too. Every image reports the tag it
was built as with `docker run --rm ghcr.io/irashack/molebridge@$DIGEST version`:
a release prints its candidate's tag (`molebridge $RC`), because promotion
does not rebuild it.

## 2. Configure

From the extracted bundle directory, take the two image references the bundle
pins. Every command on this page that runs the image uses them, so the tools
are the ones you verified:

```sh
IMAGE=$(awk '/^ *image:/ {print $2; exit}' compose.yaml)
CORE=$(grep -o 'ghcr.io/irashack/molebridge-core:[^ "]*' compose.native-sidecar.yaml | head -1)
```

### molebridge init

**Experimental.** `molebridge init` asks three questions (the provider, the
ways in, the extras) and writes `compose.yaml` and `.env` for your answers
into a directory of your own. Run it from the verified image into a new
directory, here `~/molebridge`:

```sh
DIR=$HOME/molebridge
mkdir -p "$DIR"
docker run --rm -it --user "$(id -u):$(id -g)" -v "$DIR:/out" "$IMAGE" init --out /out
```

The names it takes are those on [the menu](menu.md): a provider (`mullvad`,
`pia`, `nordvpn`, or `gluetun-<id>` for a provider gluetun drives:
`gluetun-fastestvpn`, `gluetun-ivpn`, `gluetun-mullvad`, `gluetun-nordvpn`,
`gluetun-surfshark`, `gluetun-windscribe`); one or more ways in
(`netbird-exit`, `sidecar`, `proxy`), comma-separated; and the extras
(`switchyard`, `port-sync`), or nothing for none. `docker run ... init --help`
prints the same.

To answer from a file instead, which is how to run it from a script, write
one JSON object of at most 4096 bytes with exactly these members (`extras`
may be left out), and mount it:

```json
{"schema": 1, "provider": "pia", "ways_in": ["sidecar"], "extras": ["switchyard", "port-sync"]}
```

```sh
docker run --rm --user "$(id -u):$(id -g)" -v "$DIR:/out" \
  -v "$PWD/answers.json:/answers.json:ro" "$IMAGE" init --out /out --answers /answers.json
```

Unknown members, repeated keys and names listed twice are refused. So are
the combinations that don't exist, such as `netbird-exit` with `sidecar` or
the proxy with a gluetun provider; [what combines](menu.md#what-combines)
lists them with the messages. A refusal writes nothing. Without a terminal
and without `--answers`, it stops with `molebridge init: no terminal to ask
on; pass --answers FILE (docs/setup.md#molebridge-init).`

On success it prints what it wrote, for example `Wrote /out/compose.yaml,
/out/.env: the services of compose.yaml with exit, switchyard, proxy.` It
never replaces a file: if `compose.yaml` or `.env` is there already it stops
with `molebridge init: <path> exists; pass --force to replace it, or choose
another --out.`; `--force` replaces regular files, never a symbolic link.

**The 0.14.0 image's `init` doesn't offer the proxy.** It refuses it with
`molebridge init: the proxy is being built and init does not offer it yet;
see docs/design/menu.md.` With that release, leave the proxy out and add it
afterwards with the bundle's `compose.proxy.yaml`, as [the
proxy](proxy.md#set-it-up-with-compose) says.

What it writes comes from the shipped Compose file of the same source, with
that file's settings:

| You choose | Services | From |
|---|---|---|
| `mullvad`, `pia` or `nordvpn` with `netbird-exit` | `exit` (`EXIT_KIND=overlay`, `TUNNEL_BACKEND=native`) | `compose.yaml` |
| `mullvad`, `pia` or `nordvpn` with `sidecar` | `exit` (`EXIT_KIND=sidecar`, `TUNNEL_BACKEND=native`) and `example-app` | `compose.native-sidecar.yaml` |
| `gluetun-<id>` with `netbird-exit` | `gluetun` and `exit` (`EXIT_KIND=overlay`, `TUNNEL_BACKEND=gluetun`) | `compose.gluetun.yaml` |
| `gluetun-<id>` with `sidecar` | `gluetun`, `exit` (`EXIT_KIND=sidecar`, `TUNNEL_BACKEND=gluetun`) and `example-app` | `compose.sidecar.yaml` |
| `proxy` | `proxy` | `compose.proxy.yaml` |
| `switchyard` | that form's `switchyard` | the same file |
| `port-sync` | the native sidecar's `port-sync`, without its profile, and `PIA_PORT_FORWARD=on` in `.env` | `compose.native-sidecar.yaml` |

The `.env` holds the settings of the form's example file (`.env.example`,
`.env.gluetun.example`, `.env.sidecar.example` or
`.env.native-sidecar.example`) with their example values, your provider in
`PROVIDER` and `EXIT_IF` (or `GLUETUN_PROVIDER`), the panel's settings only
with `switchyard`, and `PROXY_LISTEN` with `proxy`. With a gluetun provider
it also writes `routing/gluetun-preflight`, the script the `gluetun` service
mounts, as the [`gluetun-preflight`](tools-reference.md#gluetun-preflight)
tool does.

**Put the verified pins in.** `init` writes the image pins of the source it
was built from, and a release's source pins the release before it, so the
`compose.yaml` that the 0.14.0 image writes names the 0.13.0 images. Replace
them with the ones you verified, and check the result:

```sh
sed -i "s#ghcr.io/irashack/molebridge:[^ \"]*#$IMAGE#; s#ghcr.io/irashack/molebridge-core:[^ \"]*#$CORE#" "$DIR/compose.yaml"
grep -n 'image:' "$DIR/compose.yaml"
cd "$DIR"
```

Every Molebridge `image:` line must now name `$TAG` and a digest from the
release notes. The gluetun and busybox pins come from the
same source as the bundle's and need no change. Work in `$DIR` from here
on.

### Edit .env

Settings you must look at, by way in; everything else can wait, and
[configuration](configuration.md) lists every setting and its default.

| Setting | Way in | Value |
|---|---|---|
| `PROVIDER` and `EXIT_IF` | native forms | Written by `init`: `mullvad`, `pia` or `nordvpn`, both the same. `EXIT_IF` names the tunnel interface and its config file |
| `SERVER` | every form | A server or PIA region to keep the exit on, if you want one set in configuration rather than in the panel ([a server set in configuration](configuration.md#a-server-set-in-configuration)) |
| `OVERLAY_CIDR` | NetBird exit | Your NetBird peer range. The example's `192.0.2.0/24` is a documentation range |
| `OVERLAY6_CIDR` | NetBird exit | Your NetBird IPv6 range, if you have one |
| `NB_HOSTNAME` | NetBird exit | The peer name the exit should have in NetBird |
| `NB_MANAGEMENT_URL` | NetBird exit | Your management URL if you self-host NetBird; the example's is NetBird Cloud's |
| `SIDECAR_LAN_CIDRS` | native sidecar | The networks your applications must reach outside the tunnel; the example's `198.51.100.0/24` is a documentation range ([the native sidecar](native-sidecar.md#set-up)) |
| `GLUETUN_PROVIDER` and the other `GLUETUN_` settings | gluetun forms | As [gluetun as a NetBird exit](gluetun-netbird-exit.md#set-up) or [the gluetun sidecar](gluetun-sidecar.md#set-up) says |
| `PROXY_LISTEN` | proxy | Where it listens: the exit's NetBird address and a port for your NetBird devices, or `127.0.0.1:1080` for the sidecar's containers ([where it listens](proxy.md#where-it-listens)) |
| `PANEL_PUBLIC_HOSTS` | Switchyard | The hostname your proxy serves the panel under, if you use one ([access](access.md)) |
| `PANEL_USER` | Switchyard, proxy, sidecars | Add it: the uid:gid that owns `state/` (your `id -u`:`id -g`) on Docker. On rootless Podman, `0:0`, together with `PANEL_ALLOW_ROOT=1`. The proxy runs as this user too |

### Create the directories

Create them as your own user, as these commands do. Compose refuses to start,
rather than create a root-owned directory in its place, when a bind-mounted
one is missing.

**Native forms** (the NetBird exit or the native sidecar with Mullvad, PIA or
NordVPN):

```sh
mkdir -p state/panel state/applier secrets/pia tunnel/wg_confs
chmod 700 secrets secrets/pia tunnel/wg_confs
```

`secrets/pia` must exist for every provider. It stays empty unless you use
PIA.

**gluetun forms:** the directories in [gluetun as a NetBird
exit](gluetun-netbird-exit.md#set-up) or [the gluetun
sidecar](gluetun-sidecar.md#set-up), step 1, without the `cp` of the example
file.

**With `port-sync`:** `mkdir -p secrets/port-sync && chmod 700 secrets/port-sync`.

**With the proxy:** `mkdir -p state/proxy secrets/proxy`. Both must belong
to the user in `PANEL_USER`, which the proxy runs as; if that isn't you
(the default is `1000:1000`), run `sudo chown -R 1000:1000 state/proxy
secrets/proxy`, with your `PANEL_USER`, after writing the password in step 4.

## 3. Create the tunnel config

For the native providers. With a gluetun provider there is no tunnel config:
gluetun takes the provider's key from a file, as [gluetun as a NetBird
exit](gluetun-netbird-exit.md#set-up) and [the gluetun
sidecar](gluetun-sidecar.md#set-up) say.

These run the image as a throwaway container; nothing is installed on the
host and no Python is needed. Each tool writes only the paths you mount, as
you, with mode 0600. The [tools reference](tools-reference.md) has the details,
the messages and the Podman forms.

**Mullvad.** Convert the file you downloaded from Mullvad's WireGuard
configuration generator (one `.conf`, not the zip), then delete the original:

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/tunnel/wg_confs:/out" \
  -v "$HOME/Downloads/<your-file>.conf:/in.conf:ro" \
  "$IMAGE" prepare-config /in.conf /out/mullvad.conf &&
  rm "$HOME/Downloads/<your-file>.conf"
```

It keeps the key, the tunnel addresses and the starting server, and drops the
DNS line. Nothing secret is printed. The exit accepts only the files these
tools write ([the tunnel config](configuration.md#the-tunnel-config)), so
don't add fields by hand.

**PIA.** Generate a key, then store the login, one value per file:

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/tunnel/wg_confs:/out" \
  "$IMAGE" prepare-config --pia /out/pia.conf

(umask 077; printf '%s' 'p1234567' > secrets/pia/username)
(umask 077; read -rs pia_password && printf '%s' "$pia_password" > secrets/pia/password)
```

Replace `p1234567` with your username, and type the password at the prompt,
so it stays out of your shell history. `--pia` writes `tunnel/wg_confs/pia.conf`,
which holds only the private key, and refuses to overwrite an existing one.

**NordVPN** (experimental). Sign in to your Nord Account and open its
[manual setup page](https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/server-recommendation/),
or choose NordVPN in the left panel, then "Set up NordVPN manually" under
Manual setup. On the "Server recommendation" tab, pick a country and a
server, choose "Get setup configuration" and save the WireGuard file. Every server's file carries the
same account key, so which one you pick doesn't matter. Convert it, replacing `<your-file>` with the downloaded
file's name:

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD/tunnel/wg_confs:/out" \
  -v "$HOME/Downloads/<your-file>.conf:/in.conf:ro" \
  "$IMAGE" prepare-config --nordvpn /in.conf /out/nordvpn.conf &&
  rm "$HOME/Downloads/<your-file>.conf"
```

It writes `tunnel/wg_confs/nordvpn.conf`: the key and the address
`10.5.0.2/32`, with no peer and no DNS line; you pick the server in the panel.
A file downloaded on Windows may have Windows line endings; the tool accepts
them, and the config it writes has none. Nothing secret is printed.

If your Nord Account offers no WireGuard download, fetch the same key with an
access token instead: in your Nord Account, open NordVPN, then Advanced
settings, and choose "Get access token". Pass the token on standard input,
typed at the prompt so it stays out of your shell history and every command
line:

```sh
(read -rs nord_token && printf '%s' "$nord_token" |
  docker run --rm -i --user "$(id -u):$(id -g)" \
    -v "$PWD/tunnel/wg_confs:/out" \
    "$IMAGE" nordvpn-key - /out/nordvpn.conf)
```

It writes the same config, prints `wrote the NordVPN tunnel config (mode
0600)` and nothing secret, and never overwrites an existing config. The token
isn't needed again; revoke it in your Nord Account. For a token file instead
of standard input, see the [tools reference](tools-reference.md#nordvpn-key).

**Who can read it.** Keep the config mode 0600, owned by you, in the 0700
`tunnel/wg_confs` directory. The `exit` container runs as its own root with
every capability dropped except `NET_ADMIN`, `NET_RAW` and `DAC_OVERRIDE`:

- **Docker (rootful):** container root is the host's root. It reads your file
  and the directory through `DAC_OVERRIDE`, which the Compose files grant.
  Without it the container can't open the directory or the file and refuses
  to start.
- **Rootless Podman:** container root is your own user, the file's owner, so
  ordinary owner access is enough.
- **A container root remapped to another host ID** (some Quadlet setups):
  `DAC_OVERRIDE` only applies to files whose owner and group are both mapped
  into the container. Otherwise give that ID read access to the file and
  search access to the directories, for example with an ACL.

## 4. Add the secrets

Each secret is a file of its own, mode 0600, written so that it stays out of
your shell history.

**NetBird exit: the setup key.** Open `secrets/netbird.env` in an editor:

```sh
(umask 077 && ${EDITOR:-vi} secrets/netbird.env)
```

Write one line: `NB_SETUP_KEY=` followed by the key. You delete the file
after the first start (step 5).

**Proxy: its password**, one line, which clients send with every connection
([the password](proxy.md#the-password)):

```sh
(umask 077; head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n' > secrets/proxy/password)
```

**`port-sync`: qBittorrent's Web UI login**, one value per file, in
`secrets/port-sync/username` and `secrets/port-sync/password`, as
[port forwarding](native-sidecar.md#port-forwarding) says.

**gluetun forms:** the provider's key and the files `gluetun-auth` and
`gluetun-post-rules` write, as their guides say.

**Sidecars: your applications.** Add them in a Compose file of your own,
such as `compose.apps.yaml`, with `network_mode: service:exit` (native) or
`service:gluetun` (gluetun), and set `COMPOSE_FILE=compose.yaml:compose.apps.yaml`
in `.env`. Until then the example application, a busybox that only sleeps,
stands in. [The native sidecar](native-sidecar.md#set-up) and [the gluetun
sidecar](gluetun-sidecar.md#set-up), step 4, show the service and what it
must not have.

## 5. Check, then start

Check your settings and the tunnel config without starting anything (with
gluetun, start it first: `docker compose up -d gluetun`, because the check
joins its namespace):

```sh
docker compose config --quiet
docker compose run --rm --no-deps exit check-config
```

For a native NetBird exit it prints `molebridge-exit: configuration accepted (/config/wg_confs/mullvad.conf: an IPv4 address and an IPv6 address)`
(or `an IPv4 address`, or for PIA `no address (the exit sets it)`) and
`NetBird gate: configuration accepted`, or the one line naming the setting,
file or NetBird configuration it refused
([troubleshooting](troubleshooting.md#startup)). It changes no routing and
creates no tunnel. Then fetch every image the Compose file names, by the
digests it pins, and start the stack:

```sh
docker compose pull
docker compose up -d
docker compose ps
docker compose logs exit
```

For a NetBird exit the log should start with `molebridge-exit: molebridge <version>`, the
candidate tag the image was built as, and then show, in order, `molebridge-exit: rules installed; the exit table holds its unreachable fallback`,
`molebridge-exit: bringing the tunnel up`, `molebridge-exit: tunnel up`,
`molebridge-exit: ready`, `molebridge-exit: starting NetBird` and
`molebridge-exit: NetBird is up (launch 1)`, with NetBird's own output
between, each line starting `netbird: `. On a first start it also says
`molebridge-exit: no NetBird identity found in the state directory or the legacy profile paths; NetBird will enroll a new peer`,
which is what you want here: if you expected the exit to keep an existing
peer, stop and look at [the identity volume](operations.md#backups). A native
sidecar logs `molebridge-exit: the sidecar firewall is installed` before the
rules ([the native sidecar](native-sidecar.md#set-up), step 6).

`exit` becomes healthy about a minute after it starts. A new PIA exit stays
unhealthy until you pick a region in step 8 (or set `SERVER`), because its
tunnel has no address before PIA registers it; a native sidecar with PIA or
NordVPN does too ([the native sidecar](native-sidecar.md#set-up), step 7).
Services that wait for a healthy exit, such as the proxy and your
applications, start after that.
Healthy means the namespace is intact (the tunnel, the routing rules and, on
a NetBird exit, NetBird); it does not mean traffic is verified, which the
panel, `/readyz` and `molebridge status` report ([health](operations.md#health)).
With Mullvad the first check verifies the starting server. If `exit` refuses
to start, its log names the setting or config line it rejected
([troubleshooting](troubleshooting.md#startup)); if the tunnel won't come up,
it keeps retrying and stays unhealthy.

On a NetBird exit, check in the NetBird dashboard that the peer appears under
`NB_HOSTNAME` and is in `exit-nodes`. Then delete `secrets/netbird.env`: the
peer's identity now lives in the `netbird-data` volume. Revoke the setup key
if it was reusable.

## 6. Keep ICE off the tunnel interface

NetBird exit only. NetBird shares a network namespace with the tunnel, so by
default it would look for connection candidates on the tunnel interface too:
direct connections would fail and the exit's VPN tunnel address could be
offered to other peers. A peer enrolled with these Compose files already has
the tunnel interface in its ICE blacklist (`NB_EXTRA_IFACE_BLACKLIST` sets it
on the first enrollment), and the exit doesn't admit traffic unless it is
there. A peer enrolled earlier, or without the variable, makes the exit refuse
to start and name the repair tool, `fix-blacklist`
([operations](operations.md#netbird-interface-blacklist),
[the NetBird exit](netbird-exit.md)).

## 7. Check the namespace

Run the checks for your way in now, while nothing depends on the stack:
[inside the namespace](verification.md#inside-the-namespace) for a NetBird
exit, [a native sidecar](verification.md#a-native-sidecar),
[the gluetun form's checks](gluetun-netbird-exit.md#verification), and
[the proxy](verification.md#the-proxy). With PIA, the egress check needs a
region, and with NordVPN a server, so come back to it after step 8.

## 8. Open the panel

With `switchyard`, choose an [access method](access.md). Behind a proxy, set
`PANEL_PUBLIC_HOSTS` to its public hostname. For SSH forwarding you can leave
it empty. A proxy on the host should forward to
`http://127.0.0.1:${PANEL_PORT}` (8095 by default). The first page load can
take a few seconds while the exit fetches the server list.

With PIA, choose a region now. Until you do, the exit reports "No PIA region
is registered yet; choose one in the panel." and carries no traffic. With
NordVPN, choose a server; until then it reports "No NordVPN server is selected
yet; choose one in the panel." Without Switchyard, set `SERVER` instead.

## 9. Create the route and try a device

**NetBird exit.** In NetBird, create the exit-node route and the access
policy described in [requirements](prerequisites.md#netbird). On a device in
`exit-users`, select the exit in the NetBird client and open the provider's
check page:

- Mullvad: <https://mullvad.net/check> should show a Mullvad server in the
  starting server's city.
- PIA: PIA's own "what is my IP" page, or any IP check, should show an
  address in the region you picked.
- NordVPN: NordVPN's own IP check page should say you are protected, at an
  address in the city you picked.

Then run the [client checks](verification.md#from-a-client).

**Sidecars.** Run the attachment check after every start, recreation or
reboot ([operations](operations.md#checking-that-containers-share-gluetuns-namespace)).

**Proxy.** Point a client at it with the password, as in [the
username](proxy.md#the-username-where-a-connection-leaves), and read
`docker compose exec proxy molebridge status --proxy`.

For every form, read `docker compose exec exit molebridge status`. A passing
status isn't a leak test; the [verification](verification.md) drills are.

## With the gluetun backend instead

**Experimental.** A gluetun exit with NordVPN has run live on rootless Podman
with Quadlet units and on Kubernetes. No other provider has, and no Docker
host since the Go rewrite ([testing](testing.md)). gluetun owns the tunnel
and brings its provider support ([providers](providers.md#the-gluetun-backend)).
Steps 1, 2 and 5 to 9 work the same way, with these differences:

- `PROVIDER` doesn't apply; `GLUETUN_PROVIDER` names the provider
  ([configuration](configuration.md#gluetun-backend)).
- There is no tunnel config (step 3). You put the provider's WireGuard private
  key in a file, and the image's `gluetun-auth` and `gluetun-post-rules`
  tools write gluetun's role file and firewall post-rules.
- Start gluetun first (`docker compose up -d gluetun`), because `check-config`
  needs its namespace; then `docker compose up -d`.
- The tunnel interface is `wg0` (your `EXIT_IF`) wherever this page and
  [verification](verification.md) name it.

[gluetun as a NetBird exit](gluetun-netbird-exit.md#set-up) and [the gluetun
sidecar](gluetun-sidecar.md#set-up) are the procedures for those forms, with
the reasons.

## Without init

The shipped Compose files stay valid, and `init` writes nothing they can't
do. To use them, work in the extracted bundle directory, whose pins are
already the release's, and copy the form's example in place of running
`init`:

| Form | `.env` from | `COMPOSE_FILE` |
|---|---|---|
| NetBird exit | `.env.example` | (`compose.yaml`, the default) |
| NetBird exit with gluetun | `.env.gluetun.example` | `compose.gluetun.yaml` |
| Native sidecar | `.env.native-sidecar.example` | `compose.native-sidecar.yaml` |
| gluetun sidecar | `.env.sidecar.example` | `compose.sidecar.yaml` |

The examples set `COMPOSE_FILE` where it isn't the default. The proxy goes on
top with `compose.proxy.yaml` ([the proxy](proxy.md#set-it-up-with-compose)),
and `port-sync` is the native sidecar's `port-sync` profile. Then follow
steps 2 (from [Edit .env](#edit-env)) to 9 here.

From a checkout of the source, with Go installed, `go run ./cmd/molebridge
init --out ~/molebridge` runs the same menu. A checkout's Compose files, and
so its `init`, pin the latest release that has been recorded, so check the
`image:` lines against the release you want ([upgrades](operations.md#upgrades)).
How to get a [multi-provider exit](multi-provider.md) from `init` is on its
page.

Next: [Switchyard](switchyard.md) covers using the panel, and
[operations](operations.md) covers upgrades, recovery and boot on Podman.
