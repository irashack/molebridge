# Setup

This takes the signed release bundle to a working exit. It assumes everything
in [requirements](prerequisites.md) is ready. On rootless Podman, use
`podman-compose` wherever this page says `docker compose`, and `podman run`
where it says `docker run` (the [rootless Podman notes](prerequisites.md#rootless-podman)
list the few differences).

Plan for about half an hour, most of it in the NetBird dashboard.

Molebridge 0.8.0 is experimental, and nothing in it has had a live pass yet
([testing](testing.md#080)). Keep a way into the host that doesn't depend on
the exit.

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
TAG=v0.8.0            # the release tag
RC=v0.8.0-rc.1        # the candidate tag the release notes name: the build ran under it
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

**NordVPN** (experimental). In your Nord Account, open NordVPN, then Advanced
settings, and choose "Get access token". Fetch the key with the token on
standard input, typed at the prompt so it stays out of your shell history and
every command line:

```sh
(read -rs nord_token && printf '%s' "$nord_token" |
  docker run --rm -i --user "$(id -u):$(id -g)" \
    -v "$PWD/tunnel/wg_confs:/out" \
    "$IMAGE" nordvpn-key - /out/nordvpn.conf)
```

The tool asks NordVPN for the account's NordLynx private key and writes
`tunnel/wg_confs/nordvpn.conf`: the key and the address `10.5.0.2/32`, with no
peer. It prints `wrote the NordVPN tunnel config (mode 0600)` and nothing
secret, and never overwrites an existing config. The token isn't needed
again; revoke it in your Nord Account. For a token file instead of standard
input, see the [tools reference](tools-reference.md#nordvpn-key).

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
(or `an IPv4 address`, or for PIA `no address (the applier sets it)`) and
`NetBird gate: configuration accepted`, or the one line naming the setting,
file or NetBird configuration it refused
([troubleshooting](troubleshooting.md#startup)). It changes no routing and
creates no tunnel. Then start both containers:

```sh
docker compose up -d
docker compose ps
docker compose logs exit
```

The log should show, in order, `molebridge-exit: rules installed; the exit table holds its unreachable fallback`,
`molebridge-exit: bringing the tunnel up`, `molebridge-exit: tunnel up`,
`molebridge-exit: ready`, `molebridge-exit: starting NetBird` and
`molebridge-exit: NetBird is up (launch 1)`, with NetBird's own output
between, each line starting `netbird: `. On a first start it also says
`molebridge-exit: no NetBird identity found in the state directory or the legacy profile paths; NetBird will enroll a new peer`,
which is what you want here: if you expected the exit to keep an existing
peer, stop and look at [the identity volume](operations.md#backups).

`exit` becomes healthy once its first check completes, which takes about a
minute. With Mullvad that check verifies the starting server, and the panel
shows whether it did. With PIA, `exit` stays unhealthy until you pick a region
in step 8, because a fresh PIA tunnel has no address yet. NordVPN's exit can be
healthy before you pick a server; until then the panel shows "No NordVPN server
is selected yet; choose one in the panel." If `exit` refuses to start, its log
names the setting or config line it rejected
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

## With the gluetun backend instead

**Experimental.** At 0.7.0 it had live passes with NordVPN, on Docker and on
rootless Podman; none at 0.8.0 ([testing](testing.md#080)). gluetun owns the
tunnel and brings its provider support ([providers](providers.md#the-gluetun-backend)).
The steps above still apply, with these changes:

1. Use `.env.gluetun.example` as your `.env` instead of `.env.example`. It sets
   `COMPOSE_FILE=compose.gluetun.yaml`, which replaces `compose.yaml`.
   Set `GLUETUN_PROVIDER` (one of `fastestvpn`, `ivpn`, `mullvad`, `nordvpn`,
   `surfshark`, `windscribe`), `EXIT_IF` (`wg0`), `GLUETUN_WIREGUARD_ADDRESSES`
   if your provider assigned your key an address, `OVERLAY_CIDR`, and `HOST_IF`
   on rootless Podman. For the first start, set `GLUETUN_SERVER_COUNTRIES` to
   your own country, as gluetun names it (`Netherlands`, `United States`), and
   leave the city and hostname empty. gluetun only knows its built-in server
   list then, which can be years old: it refuses to start when a hostname or
   city isn't in it, and picks among that list's servers, some of which may be
   gone. A whole country is unlikely to be gone, and nearby servers answer
   best. Left empty, gluetun picks from every country. The settings are in
   [configuration](configuration.md#gluetun-backend). `PROVIDER` doesn't apply.
2. Instead of a tunnel config, put the provider's WireGuard private key in a
   file, and write gluetun's role file, the exit's copy of the API key and
   gluetun's firewall post-rules:

   ```sh
   mkdir -p secrets/gluetun tunnel/gluetun state/panel state/applier
   chmod 700 secrets/gluetun
   (umask 077 && ${EDITOR:-vi} secrets/gluetun/wireguard_private_key)
   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/secrets/gluetun:/out" "$IMAGE" gluetun-auth /out
   docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/tunnel/gluetun:/out" \
     -e OVERLAY_CIDR=<your NetBird range> "$IMAGE" gluetun-post-rules /out
   ```

   The key file holds one line, the private key. Add `--ipv4-only` to the
   `gluetun-post-rules` command if gluetun later logs that it found no working
   ip6tables. Pass the same `HOST_IF`, `EXIT_IF` and other routing settings you
   put in `.env` with `-e` if they aren't the defaults: the tool doesn't read
   `.env` ([tools reference](tools-reference.md#gluetun-post-rules)).
3. The NetBird setup key is the same (step 4).
4. `docker compose run --rm --no-deps exit check-config` needs gluetun's
   namespace, so start gluetun first with `docker compose up -d gluetun`.
   Then `docker compose up -d`. Read `docker compose logs exit`: before it
   starts NetBird it waits for gluetun's control server to listen on
   loopback and installs the routing rules.
5. Use `wg0` (your `EXIT_IF`) wherever the later steps and
   [verification](verification.md) name the tunnel interface. The gluetun form
   has its own checks: [gluetun as a NetBird exit](gluetun-netbird-exit.md#verification).
6. The panel shows the provider's name "via gluetun", and the date of
   gluetun's server data in Diagnostics. On a first start that data is
   gluetun's built-in list; once gluetun's tunnel carries traffic (a fresh
   handshake), the exit asks gluetun to refresh it, Diagnostics says `updating
   server list`, and a minute or two after it finishes the panel lists the
   current servers. Choose a server after that. gluetun starts on any server
   (or the one from `GLUETUN_SERVER_*`); picking one in the panel takes over.
7. Create the route and try a device the same way. For providers other than
   Mullvad and NordVPN, the panel shows a connected exit as "tunnel checks
   only": there is no provider check.

For the gluetun sidecar, which has no NetBird, see [the sidecar](gluetun-sidecar.md).

Next: [Switchyard](switchyard.md) covers using the panel, and
[operations](operations.md) covers upgrades, recovery and boot on Podman.
