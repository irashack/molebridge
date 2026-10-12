# Operations

Commands assume Docker Compose from the directory you extracted the bundle
into. Rootless Podman has its own section [below](#rootless-podman); where a
Podman command differs from the Docker one, it is given there. The exit
container is `<project>-exit` and the panel `<project>-switchyard`, with
`molebridge` as the project name unless you set `COMPOSE_PROJECT_NAME`.
Nothing in 0.8.0 needs Python or a helper on the host: the commands here are
the engine's own and the image's roles.

## Health

The exit publishes `state/applier/result.json` about once a minute. Every
reader judges it the same way ([the verdict](architecture.md#the-verdict)),
and the exit counts as connected only when the record is fresh, names the
server you selected (or `SERVER`), and every check its kind requires has
passed in the last 150 seconds:

- a recent handshake;
- egress confirmed by the provider (Mullvad's `am.i.mullvad.net` for each
  address family the tunnel has; PIA's `connected: true`; NordVPN's
  `protected: true`), or, for a provider without such a check, by the
  [tunnel checks](architecture.md#egress-tiers);
- a server list less than 24 hours old that includes the current server;
- the NetBird interface present, as a kernel WireGuard link, with NetBird's
  kernel firewall in place;
- every routing rule and fallback route in place, including the
  local-delivery rule that replaces the kernel's priority-0 rule;
- with a native exit, a live lease: the supervisor's `owner_record` check.

A [gluetun sidecar](gluetun-sidecar.md) has no NetBird or routing checks.
A record older than 150 seconds, malformed or dated in the future counts as
unknown, whatever it says, and so does one written for another kind or
provider than the panel is configured for.

- `/healthz` on the panel only checks that the panel process is up.
- `/readyz` returns 200 for a fresh, verified connection and 503 otherwise.
  Point your monitoring at this one.
- `docker compose exec exit molebridge status` prints the verdict from inside
  the exit: the state and label, the reason codes, the egress tier, every
  check's state, the heartbeat's age and the lease. It exits 0 only when the
  state is `ok`, and 1 otherwise. For example:

  ```text
  state: ok (connected)
  reasons: none
  egress tier: provider
  checks: routing=pass traffic_protection=pass netbird=pass owner_record=pass peer=pass handshake=pass egress=pass app_attachment=n/a
  heartbeat: fresh (3 s old)
  lease: held, 27 s to expiry
  ```

  `status` reads the exit's own files only. It does not prove that client
  traffic is forwarded ([verification](verification.md) does that), and it
  does not make the checks that need the engine or the host: that
  containers share the namespace, or that the files on the host have the
  right permissions ([host checks](#host-checks)). Its `app_attachment` stays
  `n/a` or `not-checked`.
- The exit container's health check is operational only: the worker's
  heartbeat is fresh (at most 15 seconds old), which the worker writes every
  5 seconds while the tunnel interface exists, the contract holds, NetBird is
  running and a completed check, `ok` or `failed`, is less than 150 seconds
  old. An exit that is up but not verified, on another server than `SERVER`,
  or without a peer stays healthy; the panel, `/readyz` and `status` report it,
  and the exit repairs a missing peer itself. If your engine or a supervisor
  kills unhealthy containers, killing the exit would only delay that repair.
  A hung worker is not the health check's job: the supervisor's lease stops
  NetBird and the container itself ([the lease](architecture.md#the-lease)).

### Gatus

To push health to [Gatus](https://gatus.io), set `GATUS_URL` and
`GATUS_ENDPOINT`, and put `GATUS_TOKEN=…` in `secrets/applier.env` (mode 0600).
Use HTTPS unless the connection is local and trusted. In Gatus, treat a
missing push as a failure: a stopped exit can't report that it's down.

The exit pushes the [verdict](architecture.md#the-verdict) against its
own target, so it agrees with the panel and `/readyz`; anything but `ok` is
a failure, with the exit's message or the verdict's label as the error.
It pushes after each periodic check and each outcome of a switch, never
while a switch is in progress, so an ordinary switch isn't a failed sample.

## Retries

The exit retries by itself
([the admission pipeline](architecture.md#the-admission-pipeline)):

- **A change that failed** (the peer update, PIA's registration, gluetun's
  control server, or a switch that timed out on another server) is applied
  again after 1, 2, 4 and 8 minutes, then every 15. The panel's note says
  when: "Retrying at … UTC."
- **A change that was applied but not verified** (the handshake, the egress
  check or its service failing while the selected server is live) is
  re-checked about once a minute, not switched again: "Re-checking at …
  UTC." A brief outage of the provider's check therefore doesn't move the
  exit. The one exception is PIA: a handshake stale for 180 seconds while
  the selected region is live registers the same region again, after a fresh
  inspection and on the backoff above. An egress-check failure alone never
  does.
- **A request that waits for a prerequisite** (a fresh server list, routing,
  NetBird, the WireGuard interface) is tried on every pass, every 5 seconds.
- **A refused request** isn't retried by itself. A server not in the list
  is tried again when the list's server names change; a malformed request
  needs a new request. With PIA, a refused login isn't retried until
  `secrets/pia/username` or `secrets/pia/password` changes. A passing
  check doesn't clear a refusal; a new request (**Retry**) always does.

To retry now, press **Retry** in the panel, or select the same server again.
Either is a new request: it applies at once and starts the backoff over.
While a switch runs the panel answers 409, "A switch is in progress; wait
for it to finish.", so wait for it first.

An exit with `SERVER` set has no Retry. Changing `SERVER` is a new target.
To retry the same configured server before its backoff is up, stop the
exit, delete its attempt record and start it again. The exit then
inspects first: the configured server already live is re-checked, anything
else is switched at once.

```sh
docker compose stop exit
rm state/applier/attempt.json
docker compose start exit
```

`state/applier/attempt.json` holds the exit's current attempt: the
target and why, its state, the backoff step, when to act next, and the last
refused panel request. It is written before every change, so a restart
resumes it instead of repeating a change blindly. Deleting it while the
exit is stopped is safe: a missing or unreadable record starts idle, with
the backoff from the start, and the exit inspects the live server before
it changes anything, unless the panel's request is less than 150 seconds
old. A refused request is then tried once more, and refused again if
nothing changed. Don't edit it while the exit runs.

## Recovery

An exit repairs most things by itself, and stops and restarts itself when its
worker stops answering ([the lease](architecture.md#the-lease)). There is no
recovery helper in 0.8.0. What you do by hand is recreate containers, and the
rule that decides which ones is about network namespaces.

**Why it matters.** A container that joins another's network namespace
(`network_mode: service:gluetun`) stays in the namespace the owner had when it
joined. If the owner is recreated, or restarted in a way that gives it a new
namespace, the dependents stay behind in the old one, where they carry no
traffic. The engine doesn't restart them for it. So you recreate the owner and
every dependent together.

**A native exit** owns its namespace alone: the panel is on its own network.
To apply a change in `.env` or an override, or to restart the whole exit:

```sh
docker compose up -d --force-recreate exit
```

A stop takes up to 13 seconds of the 15 the Compose files allow
([the stop sequence](architecture.md#the-stop-sequence)); the rules and the
fallback stay until the container is gone, and the new container installs them
before it starts the tunnel. The NetBird identity stays in the `netbird-data`
volume.

**The gluetun forms** have a namespace owner, `gluetun`, and dependents:

```sh
docker compose up -d --force-recreate
```

recreates every service in the project, which covers `gluetun`, `exit` and
`switchyard`. That is not always every dependent. Applications in a Compose
file of your own, and any container started by hand or from another project
with `--network container:<gluetun>`, are dependents too and must be recreated
after gluetun. To list every container that currently joins gluetun, including
ones outside the project (this prints names and a network mode, nothing
else; run it before you recreate anything):

```sh
GLUETUN_ID=$(docker inspect -f '{{.Id}}' molebridge-gluetun)
docker ps -aq | xargs docker inspect -f '{{.Name}} {{.HostConfig.NetworkMode}}' | grep "container:$GLUETUN_ID"
```

For a sidecar, `SIDECAR_APPS` names the applications you declared. The
sidecar's `compose.apps.yaml` services are in the project when it is listed in
`COMPOSE_FILE`; services you run elsewhere need their own recreate command, in
the order gluetun first, then the dependents.

**Then check, in this order.** Recovery has succeeded in two different senses,
and only the second is about traffic:

1. *Operational.* The containers are healthy (`docker compose ps`), and every
   dependent is in gluetun's current namespace. That second part is not
   visible from inside any container; use the
   [attachment procedure](#checking-that-containers-share-gluetuns-namespace).
2. *Verified.* `docker compose exec exit molebridge status` reports
   `state: ok`. After a recreation the exit starts from its saved selection,
   which can take a few minutes: a first check, then the egress check. With
   gluetun it may first put your last server back.

A recreated exit is not proof that traffic is verified, and an application in
the old namespace can look healthy while carrying nothing. Keep a way into the
host that doesn't depend on this exit.

## Upgrades

Read the [changelog](../CHANGELOG.md) first. Then, for an upgrade within 0.8:

1. [Verify the new download](setup.md#1-download-and-verify) as for a first
   install. The signature covers the bundle's Compose files and the image, not
   your `.env` or overrides.
2. Compare the new example environment with yours, and replace the Compose
   files and the preflight script. Your `.env`, `state/`, `tunnel/`, `secrets/`
   and the `netbird-data` volume stay:

   ```sh
   mkdir ../molebridge-new && tar -xzf molebridge-<tag>.tar.gz -C ../molebridge-new --strip-components=1
   diff .env.example ../molebridge-new/.env.example      # new or changed settings
   cp ../molebridge-new/compose*.yaml .
   cp ../molebridge-new/.env*.example .
   mkdir -p routing && cp ../molebridge-new/routing/gluetun-preflight routing/
   ```

   If you keep local Compose overrides, check them against the new files.
3. `docker compose pull`, then `docker compose up -d`. The Compose files pin
   the image by tag and digest, so this pulls the one you verified. NetBird
   updates arrive inside the image, as a new Molebridge release.
4. After any change to routing or the image, run the
   [verification](verification.md) drills again.

To roll back, put the previous bundle's files back and run the same two
commands. State files have stayed readable across releases so far, but take
the [backup](#backups) first in case one changes.

### Upgrading from 0.7.x

0.8.0 keeps your state directory, the selections, PIA's registrations and the
NetBird peer's identity, and replaces everything around them: one signed
image instead of three local builds, two containers instead of four, no Python
on the host. A 0.7.0 Switchyard reads a 0.8.0 exit's status, so the order is
the same as before: **Switchyard first** if you run a separate one, then the
exits in any order.

Upgrading from 0.6.x or earlier directly has not been tried; go to 0.7.0
first, with its own documentation.

**Before you start**, as for any upgrade: [back up](#backups), and note
that you can roll back by putting 0.7's files back.

1. **Verify the 0.8.0 download** ([setup](setup.md#1-download-and-verify)) and
   extract it somewhere new. Don't extract over the 0.7 checkout; 0.8.0 needs
   none of it. Copy in what carries over:

   ```sh
   cp ~/molebridge-0.7/.env .
   cp -a ~/molebridge-0.7/state ~/molebridge-0.7/tunnel ~/molebridge-0.7/secrets .
   ```

   Keep the same `COMPOSE_PROJECT_NAME` (the default is `molebridge`): it names
   the identity volume, `<project>_netbird-data`.
2. **Edit `.env` against the new `.env.example`.** What changed:
   - `COMPOSE_FILE=compose.yaml:compose.pia.yaml` and `...compose.nordvpn.yaml`
     are gone, with those files. Set `PROVIDER` and `EXIT_IF` instead, and remove
     `COMPOSE_FILE` unless you use a gluetun form.
   - `PUID`, `PGID` and `OWNER_RECORD` are not read.
   - `ROUTING_RECONCILE_INTERVAL` now defaults to 30, not 2: a notification
     starts a repair at once, and the interval is the fallback.
   - `GUARD_GRACE` is now the lease's length, with the same range, 5 to 30.
   - `PANEL_ALLOW_ROOT=1` is needed with `PANEL_USER=0:0` on rootless Podman.
   - A rootless engine's `PANEL_USER=0:0` is otherwise as before.
3. **Move your overrides.** Settings you put on `wireguard`, `netbird`,
   `applier`, `guard` or `control-panel` in a `compose.override.yaml` belong on
   `exit` (the first four) and `switchyard` (the last) now. A Quadlet unit or a
   Compose file of your own needs the same changes `compose.yaml` shows: one
   `exit` unit with `NET_ADMIN`, `NET_RAW` and `DAC_OVERRIDE`, read-only, with
   tmpfs on `/run` and `/var/log/netbird`, `stop_grace_period` 15 seconds, and the
   `netbird-data` volume at `/var/lib/netbird`.
4. **Check the identity volume is the one you mean.** An empty volume would
   enroll a new peer. The exit says so at start (the line is in
   [NetBird and its checks](architecture.md#netbird-and-its-checks)), but check
   first:

   ```sh
   docker volume inspect -f '{{.Name}} {{.CreatedAt}}' molebridge_netbird-data
   docker run --rm -v molebridge_netbird-data:/data:ro \
     docker.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e \
     ls -ln /data
   ```

   You should see `default.json`, the peer's profile, with an owner and a recent
   modification time. (Use `podman` for both on rootless Podman.) Don't print the file.
5. **Stop 0.7 and start 0.8.0.** From the 0.7 directory, `docker compose down`
   (without `-v`: the identity volume is the peer), then from the new one:

   ```sh
   docker compose run --rm --no-deps exit check-config
   docker compose up -d
   docker compose logs exit
   ```

   `check-config` reports a refused setting or tunnel config without changing
   anything. A stored profile that lacks the tunnel interface in its ICE
   blacklist is refused here with the repair tool named
   ([below](#netbird-interface-blacklist)); a peer enrolled with 0.7's Compose
   file already has it.
6. **Check** `docker compose exec exit molebridge status`, the panel, and the
   [host checks](#host-checks) below. Your selection is kept: with no attempt
   record the exit inspects the live server before it applies `SERVER` or a
   panel request older than 150 seconds, and changes it only if it isn't that
   server. A panel request newer than 150 seconds is applied even when its server is
   already live. PIA and NordVPN start without a peer and get the saved selection
   applied again; Mullvad starts on its config's server and is changed only when
   that isn't the selection.
7. **Remove what 0.7 left.** The `exit-run` volume (`docker volume rm
   molebridge_exit-run`), and the images 0.7 built locally (`docker image ls |
   grep molebridge` lists them). Keep the `netbird-data` volume.

**What the exit checks at start.** It reports before it changes anything, with
one line per refusal and nothing taken from a secret file: that the provider,
backend and kind agree; that the tunnel config (native only) is a regular
readable file, not a symlink, within 4 KiB, with no NUL or carriage return, and
in the exact grammar the tools write, with its table the same as `EXIT_TABLE`;
that `state/applier` exists and is writable; that `NB_INTERFACE_NAME` is
`OVERLAY_IF`; that NetBird's environment and stored profile are the supported
ones and the profile excludes the tunnel interface; what it found of the
NetBird identity; for gluetun, that the control server listens on loopback only
and the API key file is a regular file of mode 0600 or stricter; and, as a
warning, the namespace's `icmp_errors_use_inbound_ifaddr` sysctl. It does not
check the mode of the tunnel config or of the PIA credential files: they are
only read, and a wrong mode is yours to check ([below](#host-checks)).

#### Host checks

The exit and the panel check what they can see from inside their own
containers. These they can't, so they are steps you take, each with its
command. The signed bundle authenticates the stock Compose files, not local
overrides or the files on your host.

- **Permissions of the files that reach a container through `env_file`, and
  of the secrets mounted only into gluetun.** They should be mode 0600, owned
  by you:

  ```sh
  stat -c '%a %U %n' secrets/netbird.env secrets/applier.env \
    secrets/gluetun/wireguard_private_key secrets/gluetun/auth.toml secrets/gluetun/api_key 2>/dev/null
  stat -c '%a %U %n' tunnel/wg_confs/*.conf secrets/pia/*
  ```

  (On macOS and the BSDs use `stat -f '%Lp %Su %N'`.) A file that doesn't exist
  for your provider is simply not listed.
- **Credential-mount separation: the panel must not mount a credential.** The
  panel can't see what else was mounted into it. This fails if any tunnel,
  credential or gluetun secret directory is among its mounts (the one
  documented exception is the OIDC client secret file, which you mount on
  purpose):

  ```sh
  docker inspect -f '{{range .Mounts}}{{.Source}}{{"\n"}}{{end}}' molebridge-switchyard |
    grep -E '/(tunnel|secrets)(/|$)' && echo 'FAIL: the panel mounts a credential' || echo 'ok'
  ```
- **gluetun starts through the retained preflight.** In the gluetun forms,
  gluetun's entrypoint must be the wrapper, in the expected mode. A stock
  gluetun entrypoint would apply a default control-server role:

  ```sh
  docker inspect -f '{{json .Config.Entrypoint}}' molebridge-gluetun
  # ["/bin/sh","/usr/local/bin/molebridge-gluetun-preflight","/gluetun-entrypoint"]
  docker inspect -f '{{range .Mounts}}{{.Source}} {{.Destination}}{{"\n"}}{{end}}' molebridge-gluetun | grep preflight
  stat -c '%a %U' routing/gluetun-preflight    # 755 from the bundle
  ```
- **Provider agreement.** In a gluetun form the exit's `PROVIDER` must be
  `gluetun-` plus gluetun's `VPN_SERVICE_PROVIDER`. Read only those two
  fields, from the resolved deployment and from the running containers.
  Don't run `docker compose config` without selecting a field: it expands the
  `env_file`s, including the setup key.

  ```sh
  docker compose config --format json | jq -r '.services.exit.environment.PROVIDER, .services.gluetun.environment.VPN_SERVICE_PROVIDER'
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' molebridge-exit | grep '^PROVIDER='
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' molebridge-gluetun | grep '^VPN_SERVICE_PROVIDER='
  ```

  A mismatch (an exit that selects `gluetun-nordvpn` servers beside a gluetun
  that connects to Surfshark) is refused by nothing else; fix one of the two.
- **Published ports.** Nothing may publish gluetun's control server, port
  8000, and the only published port on a native exit is the panel's, on
  loopback:

  ```sh
  docker port molebridge-gluetun
  docker port molebridge-switchyard    # 127.0.0.1:8095 by default
  ```
- **The identity volume is the intended one** (step 4 above), before any
  recovery that might leave it empty.
- **Every dependent shares the namespace** (the next section), for the gluetun
  forms.

### Checking that containers share gluetun's namespace

For a gluetun overlay exit or a sidecar, the owner is `gluetun` and the exit
and your applications are dependents. The engine's record of a dependent
(`container:<id>`) names the owner by id, and an id survives a restart that
gives the owner a new namespace, so the record isn't proof. The test compares
the **namespace objects themselves**: a throwaway probe container joins each
member in turn, by id, and reads its own `/proc/self/ns/net`. It needs
nothing from your applications' images, not even a shell, because the probe is
the one that runs. It reads each member's id and start time before and after,
so a restart in the middle can't pass, and it fails on a member that is
missing or stopped.

Put this in a file and run `sh attach.sh gluetun-container member...`. Set
`ENGINE=podman` for rootless Podman. List the exit and each application:

```sh
#!/bin/sh
# usage: attach.sh <owner container> <member container>...
set -u
ENGINE=${ENGINE:-docker}
OWNER=$1; shift
PROBE=docker.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e
"$ENGINE" pull -q "$PROBE" >/dev/null || exit 1
snapshot() {
  for c in "$OWNER" "$@"; do
    "$ENGINE" inspect -f '{{.Id}} {{.State.StartedAt}} {{.State.Running}}' "$c" 2>/dev/null ||
      { echo "FAIL $c is missing" >&2; return 1; }
  done
}
ns_of() {
  "$ENGINE" run --rm --pull never --network "container:$1" --cap-drop ALL --read-only \
    --security-opt no-new-privileges --entrypoint readlink "$PROBE" /proc/self/ns/net
}
before=$(snapshot "$@") || exit 1
echo "$before" | grep -q ' false$' && { echo "FAIL a container is not running" >&2; exit 1; }
owner_ns=$(ns_of "$(echo "$before" | sed -n 1p | cut -d' ' -f1)") || exit 1
status=0; i=1
for c in "$@"; do
  i=$((i + 1))
  ns=$(ns_of "$(echo "$before" | sed -n "${i}p" | cut -d' ' -f1)") ||
    { echo "FAIL cannot read the namespace of $c" >&2; status=1; continue; }
  if [ "$ns" = "$owner_ns" ]; then echo "PASS $c is in $OWNER's namespace"
  else echo "FAIL $c is not in $OWNER's current namespace"; status=1; fi
done
after=$(snapshot "$@") || exit 1
[ "$before" = "$after" ] || { echo "FAIL a container changed while the check ran; run it again" >&2; status=1; }
exit $status
```

For example, `sh attach.sh molebridge-gluetun molebridge-exit my-downloader`.
Every line must be `PASS`. A `FAIL ... is not in ...'s current namespace` means
that member was left behind: recreate gluetun and the member together
([recovery](#recovery)). On Docker this was run against throwaway containers,
including an owner restarted under the same id (the case the check exists
for), a stopped member and a missing one; see [testing](testing.md#080). On rootless Podman it
has not been run in this form; the probe is the same one the 0.7 sidecar
doctor used there.

## NetBird interface blacklist

When the exit refuses to start with a line that ends `stop the exit and run
fix-blacklist (docs/operations.md#netbird-interface-blacklist)`, the NetBird
peer's stored profile lacks the tunnel interface in its `IFaceBlackList`, so
NetBird would offer the tunnel as a connection candidate
([why that matters](architecture.md#netbird-and-its-checks)). This happens to a
peer enrolled before the tunnel interface was blacklisted, or re-enrolled without
`NB_EXTRA_IFACE_BLACKLIST`. Environment variables can't change a stored profile;
`fix-blacklist` does, and nothing else does it for you: the exit never rewrites
the identity file unless you run the tool.

**Two prerequisites.**

1. **The exit is stopped.** `docker compose stop exit`. The daemon must not be
   running while the file is replaced. The tool looks for a daemon it can see,
   but it runs in its own container and can't see one in the exit's, so this is
   on you.
2. **The identity volume is the one you mean.** The tool never creates an
   identity (it refuses when there is none), but check you are about to edit the
   right peer's profile. The volume name is `<project>_netbird-data`.

**Find who owns the profile.** The tool must run as the identity files' owner,
because the daemon created them and the tool preserves owner, group and mode.
Read the numeric owner of `default.json` (names only; the file is not printed):

```sh
docker run --rm -v molebridge_netbird-data:/data:ro \
  docker.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e \
  ls -ln /data
```

The third and fourth columns are the owner uid and gid. For a legacy profile, at
`/etc/netbird/config.json`, read its directory the same way.

**Docker**, with the owner's uid and gid in place of `<owner uid>:<owner gid>`,
your `EXIT_IF`, and `native` or `gluetun` for the backend:

```sh
docker run --rm --user <owner uid>:<owner gid> \
  -e PROVIDER=<provider> -e EXIT_IF=<name> -e TUNNEL_BACKEND=<native|gluetun> \
  -v molebridge_netbird-data:/var/lib/netbird \
  "$IMAGE" fix-blacklist
```

**Rootless Podman:**

```sh
podman run --rm --userns=keep-id:uid=<owner uid>,gid=<owner gid> \
  -e PROVIDER=<provider> -e EXIT_IF=<name> -e TUNNEL_BACKEND=<native|gluetun> \
  -v molebridge_netbird-data:/var/lib/netbird \
  "$IMAGE" fix-blacklist
```

For a **legacy profile** (NetBird copies `/etc/netbird/config.json` into the default
profile when the default is absent), add the profile's containing directory so the
replacement can be atomic: `-v <legacy directory>:/etc/netbird`. The settings are the
exit's non-secret ones, so the tool resolves the same profile the daemon will load.
`$IMAGE` is the reference from your `compose.yaml` (`IMAGE=$(awk '/^ *image:/ {print $2; exit}' compose.yaml)`).

What it does, and refuses: it adds the tunnel interface to the list, keeps every
operator exclusion and every other field byte for byte, and reproduces NetBird's
default list when yours is absent, null or empty (NetBird fills its defaults only
into an empty list, so adding one entry to an empty list would suppress them). It
replaces the file atomically with the original's mode, owner and group, and prints
`fix-blacklist: added the tunnel interface <if> to the interface blacklist of the stored NetBird profile <path>`
(or `... already excludes the tunnel interface <if>; nothing changed`). It
changes nothing, and says why, when the daemon is visible, when the active
profile isn't the default, when there is no identity, when the JSON is malformed or
ambiguous, or when it cannot give the replacement the original's owner and group
(run it as the owner then). The full messages are in [the tools
reference](tools-reference.md#fix-blacklist) and
[troubleshooting](troubleshooting.md#startup).

Then start the exit: `docker compose up -d exit`. After `netbird up` the exit reads
the profile again and admits traffic only if the entry is there. To see the result
without printing the profile, check the direct path:
`docker compose exec exit netbird status -d` should show `P2P` for a device on a
direct connection.

## Backups

The state worth keeping is small:

| What | Why | If lost |
|---|---|---|
| `netbird-data` volume | The peer's identity | The exit enrolls as a new peer; recreate its route and group membership |
| `tunnel/wg_confs/*.conf` | The tunnel private key | Mullvad: generate a new device config. PIA: generate a new key; the exit registers it again on its own. NordVPN: run `nordvpn-key` again with a new access token |
| `secrets/` | Setup key, PIA login, Gatus token; with gluetun, the provider's WireGuard key, the role file and the API key | Re-create them; for gluetun, `gluetun-auth --rotate` writes a new role file and key |
| `.env` | Settings | Re-create it |
| `state/panel/desired.json` | The chosen server | Pick again in the panel |

`state/applier/` rebuilds itself, including `attempt.json` ([retries](#retries)),
except one file with the gluetun backend:
`gluetun-selection.json` remembers the last server the exit put, the
last one live after a change and the last one it verified, which it puts
back after gluetun restarts when the panel's request is absent or was
refused. Without it, the request in
`state/panel/desired.json` is still applied again; only that fallback is
lost. Saved and recent servers in
the panel live in each browser, not on the exit. The key files, `secrets/` and
the volume are secrets: back them up only to encrypted storage.

The volume is the one item that isn't a plain file. Stop the exit so the copy
is consistent, then archive it (the volume name is `<project>_netbird-data`,
`molebridge_netbird-data` by default):

```sh
docker compose stop exit
docker run --rm -v molebridge_netbird-data:/data:ro -v "$PWD":/backup \
  docker.io/library/busybox tar czf /backup/netbird-data.tgz -C /data .
docker compose start exit
```

On Podman, `podman volume export molebridge_netbird-data > netbird-data.tar`
does the same. To restore on a fresh install, fill the volume before the
first start:

```sh
docker volume create molebridge_netbird-data
docker run --rm -v molebridge_netbird-data:/data -v "$PWD":/backup \
  docker.io/library/busybox tar xzf /backup/netbird-data.tgz -C /data
```

Compose then warns that it didn't create the volume, and uses it anyway. On
Podman, use `podman volume create` and `podman volume import`. Put back `.env`, `tunnel/` and `secrets/` with mode 0600 files in 0700
directories. Then check that the peer appears in NetBird under its old name,
rather than as a new peer.

## DNS

Molebridge configures no DNS. Devices keep the resolver they already use, and
their traffic leaves through the provider.

With Mullvad, plain DNS (port 53) from a device appears not to reach that
resolver. This is observed, not documented by Mullvad, from one device check
and the exit's connection table: an iPhone set to Quad9 sent its lookups through a
Mullvad exit, the exit's connection table showed them addressed to 9.9.9.9
port 53, and mullvad.net/check reported no DNS leak and named the Mullvad
server itself as the resolver. The Mullvad server answers plain DNS that
passes through it with its own resolver, whichever server the device asked.
A leak test therefore shows Mullvad, not your usual resolver. PIA has not been
tested; don't assume its servers behave the same way.

### When a leak test flags DNS

The check is reporting lookups that the provider's server did not answer.
There are two ways that happens:

- **A resolver on the local network**, such as a home router or a hotel
  gateway, reached outside the exit. This is a real leak.
- **Encrypted DNS**, such as DNS over HTTPS or TLS from a browser's secure-DNS
  setting, iCloud Private Relay or a configuration profile. It goes through the
  exit, but the server can't redirect it, so the check names the outside
  resolver.

The DNS list in the check's result tells which: a resolver run by your local
network or ISP is the first case, and the service you configured for
encrypted DNS is the second. To see where a device's plain DNS goes, run this
on the exit, inside the namespace
([how to get a shell there](verification.md#inside-the-namespace)), with the
device's overlay address in place of `<device overlay IP>`:

```sh
grep <device overlay IP> /proc/net/nf_conntrack | grep 'dport=53 '
```

Each line is one lookup flow from that device. The `dst=` address is the
resolver the device asked. If you use encrypted DNS and want a clean check,
use Mullvad's own encrypted DNS service.

### Why there is no DNS option

Molebridge has no option to send DNS through the provider. One way to build
it would be a resolver in the exit's namespace forwarding over the tunnel,
plus a NetBird nameserver group. That would apply even when the exit isn't
selected, and DNS would fail whenever the tunnel is down. A resolver that only
works inside the tunnel, pushed through NetBird, also gives slow, flaky DNS
off the exit rather than none, because NetBird eventually gives up on it and
falls back.

That design can't work on this exit now in any case. The exit no longer
answers anything addressed to itself that arrives over NetBird: a packet
that arrives on the overlay interface never reaches a process on the exit
([architecture](architecture.md#netbird-and-its-checks)). A NetBird nameserver
group served by the exit therefore gets no answers. Point NetBird's
nameservers at a resolver somewhere else.

## Direct connections

Check how devices reach the exit with `docker compose exec exit netbird
status -d`. `P2P` is good. `Relayed` works, but it adds a relay server's round
trip to every packet.

The exit peer must keep ICE off the tunnel interface
([the blacklist](#netbird-interface-blacklist)); the exit checks it at start. To see what a peer is doing, raise the log level, read the local and
remote candidates, then put it back:

```sh
docker compose exec exit netbird debug log level debug
docker compose exec exit netbird debug log level info
```

Treat candidate addresses as private.

### Exits on a private container network

Rootless engines and Docker's default bridge put the exit's namespace on a
private network. The peer's only host candidate is then an address that
nothing outside the host can reach, and whether STUN finds a usable public
candidate depends on the engine's NAT. On the tested rootless host it found
none. Devices then fall back to a relay silently: the exit works, just more
slowly, and nothing reports a fault.

The fix is to get a UDP port to the peer and tell NetBird to use and advertise
it. How you get the port there depends on the engine. Put the change for
`exit` in a `compose.override.yaml`. Compose reads that file
automatically unless `COMPOSE_FILE` is set, as it is for the gluetun forms; then
add it to the list (`COMPOSE_FILE=compose.gluetun.yaml:compose.override.yaml`).

**Docker:** publish the port on the `exit` service (or, with gluetun, on the
`gluetun` service, which owns the namespace).

```yaml
services:
  exit:
    ports:
      - "51825:51825/udp"
```

**Rootless Podman with pasta:** don't publish the port. Publishing it holds
the host port, so pasta can't bind it for NetBird's outgoing STUN; remote
devices stay relayed and only devices on the same LAN connect directly. Give
`exit` its own pasta network that forwards the port instead, with
`network_mode` and no `ports:` entry for that port. Use your host's LAN
address in place of `198.51.100.10`:

```yaml
services:
  exit:
    network_mode: "pasta:-4,-a,10.0.2.100,-n,24,-g,10.0.2.2,-I,eth0,-u,198.51.100.10/51825:51825"
```

The pasta options are:

- `-4` uses IPv4 only on the host side.
- `-a 10.0.2.100 -n 24 -g 10.0.2.2` gives the namespace a fixed private
  address and gateway.
- `-I eth0` keeps the interface name `eth0`, which `--external-ip-map` refers
  to below.
- `-u 198.51.100.10/51825:51825` forwards that UDP port, bound to that one LAN
  address only.

The namespace gets no `--map-host-loopback`, so it can't reach the host's
loopback. With the native exit nothing else shares the exit's network
namespace, and the panel is on its own network. With the gluetun form, put the
`network_mode` on `gluetun`, which owns the namespace the exit joins.

Recreate the exit so the change applies ([recovery](#recovery)), then set
NetBird's side, using your `EXIT_IF` in place of `mullvad`:

```sh
docker compose exec exit netbird down
docker compose exec exit netbird up \
  --extra-iface-blacklist mullvad \
  --wireguard-port 51825 \
  --external-ip-map 198.51.100.10/eth0
```

- The published or forwarded port and `--wireguard-port` must match. Pick a free one; a
  NetBird client on the host itself already uses 51820.
- `--external-ip-map` is the address the peer advertises instead of the
  container's: the host's LAN address for devices on the same LAN, or your
  public address, with the port forwarded, for devices on the Internet.
- A published or forwarded port is new exposure. Prefer the LAN address unless remote
  devices really need the direct path.
- The remote candidate may show as `prflx`. Rootless port forwarding rewrites
  the source address, and ICE handles that; it isn't a fault.

What was tested, at 0.7.0: on Debian with passt 0.0~git20261002 and Podman 5.8.6, with
the routing container as a Quadlet unit using the `Network=pasta:` form of
the options above. One pasta process then owns
the port. NetBird's outgoing STUN leaves from a socket bound to the LAN
address and port, the STUN server reported the public mapping on that same
port, and a LAN datagram arrived with its real source address. `ss -ulnp` on
the host showed the port held by pasta, not by `rootlessport`; the pasta log
had no `Dropping datagram`; NetBird no longer logged `wait for gathering timed
out`; and NetBird showed a P2P pair. A LAN client connected directly. On
2026-10-08 a phone on cellular, off Wi-Fi, also got a direct (P2P) path, with
host and server-reflexive (`srflx`) candidates, to two exits set up this way,
one Mullvad and one NordVPN, and held it through a speed test. The
podman-compose form shown above, Docker with this method, and rootless Docker
are untested, and so is all of it at 0.8.0, where the exit container owns the
namespace that the routing container did.

## Rootless Podman

Tested at 0.7.0 on Debian 13, rootless Podman 5.4, podman-compose 1.6 on amd64;
not retested at 0.8.0. Replace `molebridge` with your `COMPOSE_PROJECT_NAME` if
you changed it.

Before the first start, load the kernel module and set `PANEL_USER=0:0` and
`PANEL_ALLOW_ROOT=1` ([requirements](prerequisites.md#rootless-podman)).

With the gluetun backend, the exit refuses `secrets/gluetun/api_key` if its
mode allows anything beyond `0600`, so a group-readable file with an ACL
doesn't work. Under podman-compose the container's root is your own user, and
the file `gluetun-auth` writes works as it is. If you remap the container's
root to another host ID, as some Quadlet setups do, the file must belong to
that ID with mode `0600`.

**Setup** is [setup](setup.md) with `podman-compose` in place of `docker
compose` and `podman run` in place of `docker run` (leave out `--user`: the
default mapping turns the container's root into you):

```sh
podman-compose run --rm --no-deps exit check-config
podman-compose up -d
podman logs molebridge-exit 2>&1 | grep -e 'molebridge-exit' -e 'NetBird gate'
```

**Upgrade or recover.** Recreate both together:

```sh
podman-compose pull
podman-compose up -d --force-recreate
```

With the gluetun backend, recreate everything that joins gluetun's namespace, in
the order gluetun first ([recovery](#recovery)), since a new `gluetun` container
is a new namespace.

podman-compose has no `--wait`, so check health yourself, then the status:

```sh
for c in exit switchyard; do
  podman inspect --format '{{.State.Health.Status}}' molebridge-$c
done
podman exec molebridge-exit molebridge status
```

With the gluetun backend, also run the [attachment procedure](#checking-that-containers-share-gluetuns-namespace)
with `ENGINE=podman`, and use `podman ps -aq | xargs podman inspect -f '{{.Name}} {{.HostConfig.NetworkMode}}'`
in place of the `docker` form to list every container that joins gluetun.

Never run `down -v`: the named volume is the peer's identity.

**Starting at boot.** Rootless containers start at boot only through a
systemd user session. This lingering user unit is the tested arrangement:

```sh
loginctl enable-linger "$USER"
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/molebridge.service <<'UNIT'
[Unit]
Description=Molebridge rootless Podman project
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=%h/molebridge
ExecStart=/usr/bin/podman-compose up -d
ExecStop=/usr/bin/podman-compose stop
TimeoutStartSec=900
TimeoutStopSec=180

[Install]
WantedBy=default.target
UNIT
systemctl --user daemon-reload
systemctl --user enable --now molebridge.service
```

Set `WorkingDirectory` to your install directory. On the tested host, a reboot
brought the 0.7.0 exit back healthy in 76 seconds with no intervention. That's
one reboot on one host, so check health and the namespaces after a reboot
anyway. Podman doesn't act on failing healthchecks: a hung exit is stopped by
its own supervisor, but a dependent stranded in an old namespace stays stranded
until you recreate it together with its owner.

Expect relayed devices on rootless Podman until you follow
[exits on a private container network](#exits-on-a-private-container-network).

## Rotating keys

**Mullvad.** Generate a config for a new device on mullvad.net, run
`prepare-config` on it ([tools](tools-reference.md#prepare-config)), then
recreate the exit. Once the exit works, remove the old device on mullvad.net.

**PIA.** Move `tunnel/wg_confs/pia.conf` aside, run
`prepare-config --pia`, then recreate the exit. The exit registers
the new key in the saved region on its own. To change the PIA password, rewrite
`secrets/pia/password` and restart the exit.

**NordVPN.** NordVPN's API returns the account's one NordLynx key; how to make
it issue a new one hasn't been checked. To rebuild the config, move
`tunnel/wg_confs/nordvpn.conf` aside, run `nordvpn-key` with a new
access token as in [setup](setup.md#3-create-the-tunnel-config), then
recreate the exit. The exit applies the saved server again on its own.

## Removing

1. In NetBird, delete the exit route and the access policy.
2. On rootless Podman, disable the boot unit first:
   `systemctl --user disable --now molebridge.service`.
3. `docker compose down`. Add `-v` to also delete the peer's identity volume.
4. If a separate Switchyard serves this exit, remove the exit from its
   `PANEL_EXITS` and its volume mounts.
5. Delete the peer in NetBird. With Mullvad, also delete the device on
   mullvad.net.
6. Delete `.env`, `tunnel/wg_confs/`, `secrets/` and `state/`, or keep them
   if you might reinstall.
