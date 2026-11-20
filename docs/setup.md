# Setup

This takes the signed release bundle to a working exit. It assumes everything
in [requirements](prerequisites.md) is ready. It is for the NetBird exit; the
[gluetun sidecar](gluetun-sidecar.md) and the [native sidecar](native-sidecar.md)
have their own set-up pages and share step 1. Plan for about half an hour,
most of it in the NetBird dashboard.

**What was tested.** Molebridge is experimental. Its live runs used Quadlet
units on a Debian host with rootless Podman 5.8, and Kubernetes manifests,
neither of which this repository ships. The Compose commands on this page are
what the bundle is for, but they have not been run on any engine, and Docker
Engine on Linux and NetBird Cloud are untested too
([testing](testing.md#not-tested-at-080)). If you use Quadlet, a unit needs the settings in
`compose.yaml` ([the list in the upgrade notes](operations.md#upgrading-from-07x),
step 3). Keep a way into the host that doesn't depend on the exit.

**Rootless Podman.** Use `podman-compose` where this page says
`docker compose`, and `podman run` where it says `docker run`, and leave
`--user "$(id -u):$(id -g)"` out of the `run` commands: the default mapping
makes the container's root you ([tools reference](tools-reference.md#running-a-tool)).
The [rootless Podman notes](prerequisites.md#rootless-podman) list the other
differences.

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
TAG=v0.13.0           # the release tag
RC=v0.13.0-rc.1       # the candidate tag the release notes name: the build ran under it
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

What this proves and what it doesn't: the bundle's Compose files and the
image are the ones this repository's workflows built from `$COMMIT`, and the
image passed the acceptance run. It says nothing about your `.env`, local
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

From the extracted directory:

```sh
cp .env.example .env
mkdir -p state/panel state/applier secrets/pia tunnel/wg_confs
chmod 700 secrets secrets/pia tunnel/wg_confs
```

Create the directories as your own user, as the commands do. `secrets/pia`
must exist for every provider: Compose refuses to start, rather than create a
root-owned directory in its place, when it is missing. It stays empty unless
you use PIA.

Every command below that runs the image uses the reference your Compose file
pins, so the tools are the ones you verified:

```sh
IMAGE=$(awk '/^ *image:/ {print $2; exit}' compose.yaml)
```

Edit `.env`. The settings you must look at:

| Setting | Value |
|---|---|
| `OVERLAY_CIDR` | Your NetBird peer range |
| `OVERLAY6_CIDR` | Your NetBird IPv6 range, if you have one |
| `PROVIDER` and `EXIT_IF` | `mullvad` and `mullvad` (the default). For PIA, `pia` and `pia`; for NordVPN (experimental), `nordvpn` and `nordvpn`. `EXIT_IF` names the tunnel interface and its config file |
| `NB_HOSTNAME` | The peer name the exit should have in NetBird |
| `NB_MANAGEMENT_URL` | Your management URL, if you self-host NetBird |
| `PANEL_PUBLIC_HOSTS` | The hostname your proxy serves the panel under, if you use one ([access](access.md)) |
| `PANEL_USER` | Add it: your `id -u`:`id -g` on Docker. On rootless Podman, `0:0`, together with `PANEL_ALLOW_ROOT=1` |

Everything else can wait; [configuration](configuration.md) lists every
setting and its default.

## 3. Create the tunnel config

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
  and the directory through `DAC_OVERRIDE`, which `compose.yaml` grants.
  Without it the container can't open the directory or the file and refuses
  to start.
- **Rootless Podman:** container root is your own user, the file's owner, so
  ordinary owner access is enough.
- **A container root remapped to another host ID** (some Quadlet setups):
  `DAC_OVERRIDE` only applies to files whose owner and group are both mapped
  into the container. Otherwise give that ID read access to the file and
  search access to the directories, for example with an ACL.

## 4. Add the NetBird setup key

Open `secrets/netbird.env` in an editor, so the key never lands in shell
history:

```sh
(umask 077 && ${EDITOR:-vi} secrets/netbird.env)
```

Write one line: `NB_SETUP_KEY=` followed by the key.

## 5. Check, then start

Check your settings and the tunnel config without starting anything:

```sh
docker compose run --rm --no-deps exit check-config
```

It prints `molebridge-exit: configuration accepted (/config/wg_confs/mullvad.conf: an IPv4 address and an IPv6 address)`
(or `an IPv4 address`, or for PIA `no address (the exit sets it)`) and
`NetBird gate: configuration accepted`, or the one line naming the setting,
file or NetBird configuration it refused
([troubleshooting](troubleshooting.md#startup)). It changes no routing and
creates no tunnel. Then fetch every image the Compose file names, by the
digests the bundle pins, and start both containers:

```sh
docker compose pull
docker compose up -d
docker compose ps
docker compose logs exit
```

The log should start with `molebridge-exit: molebridge <version>`, the
candidate tag the image was built as, and then show, in order, `molebridge-exit: rules installed; the exit table holds its unreachable fallback`,
`molebridge-exit: bringing the tunnel up`, `molebridge-exit: tunnel up`,
`molebridge-exit: ready`, `molebridge-exit: starting NetBird` and
`molebridge-exit: NetBird is up (launch 1)`, with NetBird's own output
between, each line starting `netbird: `. On a first start it also says
`molebridge-exit: no NetBird identity found in the state directory or the legacy profile paths; NetBird will enroll a new peer`,
which is what you want here: if you expected the exit to keep an existing
peer, stop and look at [the identity volume](operations.md#backups).

`exit` becomes healthy about a minute after it starts; a new PIA exit stays
unhealthy until you pick a region in step 8, because its tunnel has no
address before PIA registers it. Healthy means the
namespace is intact (the tunnel, the routing rules and NetBird); it does not
mean traffic is verified, which the panel, `/readyz` and `molebridge status`
report ([health](operations.md#health)). With Mullvad the first check
verifies the starting server; PIA and NordVPN need you to choose one first
(step 8). If `exit` refuses to start, its log names the setting or config line it rejected
([troubleshooting](troubleshooting.md#startup)); if the tunnel won't come up,
it keeps retrying and stays unhealthy.

In the NetBird dashboard, check that the peer appears under `NB_HOSTNAME` and
is in `exit-nodes`. Then delete `secrets/netbird.env`: the peer's identity now
lives in the `netbird-data` volume. Revoke the setup key if it was reusable.

## 6. Keep ICE off the tunnel interface

NetBird shares a network namespace with the tunnel, so by default it looks
for connection candidates on the tunnel interface too. Direct connections then
fail and clients fall back to a relay, and the exit's VPN tunnel address can
be offered to other peers. The tunnel interface belongs in the peer's ICE
blacklist.

A peer enrolled with these Compose files already has it:
`NB_EXTRA_IFACE_BLACKLIST` sets it on the first enrollment. You don't have to
check it. The exit reads the stored NetBird profile before it starts NetBird
and again after `netbird up`, and doesn't admit traffic unless the tunnel
interface is in the blacklist. A peer enrolled earlier, or without the
variable, fails that check: the exit refuses to start and names the repair
tool, `fix-blacklist`. [Operations](operations.md#netbird-interface-blacklist)
has the commands. [Architecture](architecture.md#netbird-and-its-checks)
explains the failure in more detail.

## 7. Check the namespace

Run the checks in [verification](verification.md#inside-the-namespace) now,
while no device can route through the exit yet. With PIA, the egress check
needs a region, and with NordVPN a server, so come back to it after step 8.

## 8. Open the panel

Choose an [access method](access.md). Behind a proxy, set `PANEL_PUBLIC_HOSTS`
to its public hostname. For SSH forwarding you can leave it empty. A proxy on
the host should forward to `http://127.0.0.1:${PANEL_PORT}` (8095 by default).
The first page load can take a few seconds while the exit fetches the server
list.

With PIA, choose a region now. Until you do, the exit reports "No PIA region
is registered yet; choose one in the panel." and carries no traffic. With
NordVPN, choose a server; until then it reports "No NordVPN server is selected
yet; choose one in the panel."

## 9. Create the route and try a device

In NetBird, create the exit-node route and the access policy described in
[requirements](prerequisites.md#netbird). On a device in `exit-users`, select
the exit in the NetBird client and open the provider's check page:

- Mullvad: <https://mullvad.net/check> should show a Mullvad server in the
  starting server's city.
- PIA: PIA's own "what is my IP" page, or any IP check, should show an
  address in the region you picked.
- NordVPN: NordVPN's own IP check page should say you are protected, at an
  address in the city you picked.

Then run the [client checks](verification.md#from-a-client), and read
`docker compose exec exit molebridge status`. A passing status isn't a leak
test; the [verification](verification.md) drills are.

## molebridge init

**Experimental, and in no release yet.** `molebridge init` writes a Compose
file and an `.env` for the ways in you choose, in place of copying one of the
shipped Compose files and its example ([the menu](design/menu.md)).
It has been checked by CI only: every combination it accepts resolves with
`docker compose config`, and each service it writes resolves exactly as the
same service of the shipped file it comes from (`tools/check-compose.sh`).
No stack it wrote has been started on any host.

Until a release has it, run it from a checkout with Go installed:

```sh
go run ./cmd/molebridge init --out ~/molebridge
```

On a terminal it asks three questions. `--answers FILE` reads the same
answers from a JSON file instead, which is how to run it from a script:

```json
{"schema": 1, "provider": "pia", "ways_in": ["sidecar"], "extras": ["switchyard", "port-sync"]}
```

The file holds one object with exactly these members, at most 4096 bytes:
`schema` is `1`; `provider` is `mullvad`, `pia`, `nordvpn`, or
`gluetun-<id>` for a provider gluetun drives (`gluetun-fastestvpn`,
`gluetun-ivpn`, `gluetun-mullvad`, `gluetun-nordvpn`, `gluetun-surfshark`,
`gluetun-windscribe`); `ways_in` lists `netbird-exit` or `sidecar`;
`extras`, which may be left out, lists `switchyard`,
`port-sync` or neither. Unknown members, repeated keys and names listed twice
are refused.

What it writes comes from the shipped file of the same source, with that
file's settings and image pins:

| You choose | Services | From |
|---|---|---|
| `mullvad`, `pia` or `nordvpn` with `netbird-exit` | `exit` (`EXIT_KIND=overlay`, `TUNNEL_BACKEND=native`) | `compose.yaml` |
| `mullvad`, `pia` or `nordvpn` with `sidecar` | `exit` (`EXIT_KIND=sidecar`, `TUNNEL_BACKEND=native`) and `example-app` | `compose.native-sidecar.yaml` |
| `gluetun-<id>` with `netbird-exit` | `gluetun` and `exit` (`EXIT_KIND=overlay`, `TUNNEL_BACKEND=gluetun`) | `compose.gluetun.yaml` |
| `gluetun-<id>` with `sidecar` | `gluetun`, `exit` (`EXIT_KIND=sidecar`, `TUNNEL_BACKEND=gluetun`) and `example-app` | `compose.sidecar.yaml` |
| `switchyard` | that form's `switchyard` | the same file |
| `port-sync` | the native sidecar's `port-sync`, without its profile, and `PIA_PORT_FORWARD=on` in `.env` | `compose.native-sidecar.yaml` |

`EXIT_KIND` and `TUNNEL_BACKEND` are written as the shipped files write them
and mean the same. The `.env` holds the settings of the form's example file
(`.env.example`, `.env.gluetun.example`, `.env.sidecar.example` or
`.env.native-sidecar.example`) with their example values, your provider in
`PROVIDER` and `EXIT_IF` (or `GLUETUN_PROVIDER`), the panel's settings only
with `switchyard`. With a gluetun provider it
also writes `routing/gluetun-preflight`, the script the `gluetun` service
mounts, as the [`gluetun-preflight`](tools-reference.md#gluetun-preflight)
tool does.

**The proxy** is a way in that is being built
([design](design/menu.md)): every connection it opens would leave through the
tunnel, or fail, with no promise about traffic not sent to it. The proxy
choice arrives in `init` with the `molebridge proxy` role. Until a release
has that role, `init` doesn't offer it and refuses it in an answers file:
`molebridge init: the proxy is being built and init does not offer it yet;
see docs/design/menu.md.`

It refuses combinations that don't exist, and writes nothing then:

- `molebridge init: netbird-exit and sidecar can't share one exit: the NetBird
  exit is EXIT_KIND=overlay and the sidecar EXIT_KIND=sidecar, and init writes
  one exit. Choose one of them; the other needs a Compose project of its own.`
- `port-sync` with another provider than PIA, or without `sidecar`.

It writes `compose.yaml` and `.env` (and `routing/gluetun-preflight`) into
the `--out` directory, creating it if needed. If one of them is there
already it stops with `molebridge init: <path> exists; pass --force to
replace it, or choose another --out.`; `--force` replaces regular files, never
a symbolic link.

Then, in that directory, continue with the set-up of the form you chose, from
its configuration step, with the `.env` init wrote in place of the copied
example: [step 2](#2-configure) here for the NetBird exit,
[gluetun as a NetBird exit](gluetun-netbird-exit.md#set-up), [the gluetun
sidecar](gluetun-sidecar.md) or [the native sidecar](native-sidecar.md). The
directories are the same (`state/panel`, `state/applier`, `secrets/pia` for
every native provider).

The image pins are the ones in the source init was built from. The Compose
files of a release's source pin the release before it until the release is
recorded, so check the `image:` lines against the release you want
([upgrades](operations.md#upgrades)).

## With the gluetun backend instead

**Experimental.** A gluetun exit with NordVPN has run live on rootless Podman
with Quadlet units and on Kubernetes. No other provider has, and no Docker
host since the Go rewrite ([testing](testing.md)). gluetun owns the
tunnel and brings its provider support ([providers](providers.md#the-gluetun-backend)).

[gluetun as a NetBird exit](gluetun-netbird-exit.md#set-up) is the
installation procedure for this form, and replaces steps 2 to 5 here. Step 1
(download and verify), the NetBird setup in step 9 and the checks work the same
way, with these differences:

- Your `.env` comes from `.env.gluetun.example`, which sets
  `COMPOSE_FILE=compose.gluetun.yaml`; `PROVIDER` doesn't apply
  ([configuration](configuration.md#gluetun-backend)).
- There is no tunnel config. You put the provider's WireGuard private key in a
  file, and the image's `gluetun-auth` and `gluetun-post-rules` tools write
  gluetun's role file and firewall post-rules.
- Start gluetun first (`docker compose up -d gluetun`), because `check-config`
  needs its namespace; then `docker compose up -d`.
- The tunnel interface is `wg0` (your `EXIT_IF`) wherever this page and
  [verification](verification.md) name it. The gluetun form has its own checks:
  [verification in the gluetun guide](gluetun-netbird-exit.md#verification).

The two sidecar forms have no NetBird. For an ordinary gluetun that your other
containers share, see [the gluetun sidecar](gluetun-sidecar.md). For a tunnel
Molebridge builds itself, which is how to use PIA over WireGuard for your
containers, see [the native sidecar](native-sidecar.md); it follows steps 1 and 3
here (verify the download, create the tunnel config) and has its own set-up.

Next: [Switchyard](switchyard.md) covers using the panel, and
[operations](operations.md) covers upgrades, recovery and boot on Podman.
