# Compatibility

This page says what an upgrade within one major version leaves alone, so you
can write a health bridge, a Kubernetes manifest or a dashboard against
Molebridge and keep it working. It is written for 1.x.

**Before 1.0 this is a draft.** Molebridge 0.x follows it as far as it can,
but a 0.x release may still break an item on the list below. When one does,
its [changelog](../CHANGELOG.md) entry says so, under the release that made
the change. The list is here now so that each 0.x release can be checked
against it before 1.0 fixes it.

## What stays the same through 1.x

Each item below keeps its name, its place and its meaning in every 1.x
release. Where it is a document, a 1.x release may add members to it; a
reader must ignore members it doesn't know, as Molebridge's own readers do.
Nothing on the list is removed or renamed, and no member changes its type,
before 2.0.

### The status record

`state/applier/result.json` is schema 2, as described in
[the status record](architecture.md#the-status-record) and listed in
[state files](configuration.md#state-files):

- `schema` is `2` in every record a 1.x exit writes.
- The top-level members (`kind`, `backend`, `provider`, `status`, `message`,
  `checked_at`, `server`, `requested_server`, `configured_server`,
  `request_id`, `selection`, `checks` and the egress fields) and the provider
  members (PIA's `port_forward`, `forwarded_port` and `port_forward_error`,
  gluetun's `server_list_update`) keep their meaning. `routing_activity`
  (since 0.9.3) is on the list too, but no reader judges it.
- The eight checks (`routing`, `traffic_protection`, `netbird`,
  `owner_record`, `peer`, `handshake`, `egress`, `app_attachment`), their five
  states (`pass`, `fail`, `unknown`, `n/a`, `not-checked`), and which of them
  each kind and backend requires, as the table in
  [the status record](architecture.md#the-status-record) gives it.
- The values of `status` (`unknown`, `applying`, `ok`, `failed`), of
  `selection.outcome` and of `selection.next_action`.
- The timestamp format and the 150-second freshness bound.

A new check, a new check state or a new required check would change what an
existing reader concludes, so none of them comes within schema 2. Such a
change needs schema 3 and a major release. `message` is wording for people:
read `status` and the checks, not the text.

### The state files

The names, paths and fields in [state files](configuration.md#state-files):
`applier/result.json`, `applier/relays.json`, `applier/relay-error.json`,
`applier/attempt.json`, `applier/tunnel.json` (PIA),
`applier/gluetun-selection.json` (gluetun backend) and `panel/desired.json`,
and which component writes and reads each. The three private files may live
under `PRIVATE_STATE_DIR` instead
([keeping the published files in memory](configuration.md#keeping-the-published-files-in-memory)).
The files under the exit's `/run` tmpfs (the heartbeat, the guard heartbeat
and the lease) are internal; read their state with `molebridge status` or
`molebridge health`.

### Settings

The settings in `.env.example`, `.env.gluetun.example`, `.env.sidecar.example`
and `.env.native-sidecar.example`, and the
[overrides](configuration.md#overrides) and form-specific settings in
[configuration](configuration.md), keep their names and their defaults. A
value that a release accepts stays accepted with the same meaning; a later
release may accept more values, never fewer. The variables that
[configuration](configuration.md#other-settings-the-compose-files-fix) calls
internal to the supervisor or the tests (`MOLEBRIDGE_GENERATION`,
`MOLEBRIDGE_RTNL_NOTIFY_LOCKED`, `MOLEBRIDGE_DRILL_CPUPROFILE`,
`MOLEBRIDGE_PANEL_LISTEN`, `MOLEBRIDGE_PANEL_ISOLATION_CHECK`) are not on the
list.

### The Compose files

- The four files, `compose.yaml`, `compose.gluetun.yaml`, `compose.sidecar.yaml`
  and `compose.native-sidecar.yaml`, and their project names (`molebridge`,
  `molebridge-sidecar`, `molebridge-native-sidecar`).
- The service names: `exit` and `switchyard` in every form, `gluetun` in the two
  gluetun forms, `example-app` in both sidecar forms and `port-sync` in the
  native sidecar's, with the profiles `example` and `port-sync`.
- The named volumes, `netbird-data` above all: it holds the NetBird identity,
  and a renamed volume would enroll a new peer. Also `gluetun-data` and
  `gluetun-servers`.
- The host directories the services mount (`state/`, `tunnel/`, `secrets/`)
  and the paths inside the containers they are mounted at (`/state`,
  `/config/wg_confs`, `/run/secrets/pia`, `/var/lib/netbird` and the gluetun
  paths in [configuration](configuration.md#gluetun-backend)), so a manifest
  written for one release mounts the next.
- The image's role names (`exit`, `panel`, `health`, `status`,
  `check-config`, `prepare-config` and the other tools in the
  [tools reference](tools-reference.md)).

### The routing contract

The rule priorities and what each rule does, as the tables in
[routing contract](architecture.md#routing-contract) (native overlay),
[why the routing contract is policy routing](architecture.md#why-the-routing-contract-is-policy-routing)
(gluetun overlay) and [the native sidecar](native-sidecar.md#the-routing-contract)
give them; the priority ranges the exit owns (0 to 98 on a native overlay
exit, 0 to 97 and 102 to 104 with gluetun, 1 to 98 in a native sidecar); and
the defaults `EXIT_TABLE=51821`, `HOST_TABLE=51822` and
`CONTROL_MARK=0x1bd00`. Anything else you install in the exit's namespace
should stay outside those ranges and tables, and it can count on them not
moving.

### Exit codes

| Command | `0` | `1` | `2` |
|---|---|---|---|
| `molebridge status` | the verdict's state is `ok` | any other state, or a bad `PROVIDER` or `EXIT_KIND` | a usage error |
| `molebridge health` and `health --guarded` | healthy | unhealthy | a usage error |

The text they print is for people and is not on the list; a script should
use the exit status, or read `/api/status` or `result.json`.

### The panel's status endpoints

`/api/status` (with `?exit=<id>` for a panel that serves several exits)
answers with a JSON object of three members:

- `desired`: the panel's request as in `state/panel/desired.json`, or null
  (always null for an exit set in configuration);
- `result`: the exit's status record as the exit wrote it, or null when there
  is none;
- `verdict`: the one judgment every reader makes
  ([the verdict](architecture.md#the-verdict)), with `state` (`ok`, `failed`,
  `applying` or `unknown`), `reasons` (the reason codes in
  [health](operations.md#health)), `message`, `tier`, `checks` (every check
  named, each with its state), `not_checked_by`, `schema`, `kind`,
  `configured_server`, `next_action` and `next_action_at`. `label` is display
  text, not on the list.

An unknown exit is 404, and with sign-in on, no session is 401 with
`{"error": "sign in required"}` ([panel endpoints](configuration.md#panel-endpoints)).
A later release may add reason codes; the existing ones keep their meaning.

`/readyz` (and `/readyz?exit=<id>`) answers 200 with `ready` when every exit,
or the named one, has the verdict `ok`, 503 with `not ready` otherwise, and
404 for an exit it doesn't know. `/healthz` answers 200 while the panel runs.

Before 0.10, `/api/status` also sent `view` and, in `result`, the 0.6
diagnostic fields. They were deprecated at 0.7.0 and are gone in 0.10; this
description is without them.

## What is not promised

- **Log lines.** The wording and format of what the exit, the panel and the
  tools print to their logs can change in any release. 0.9.3 changed the
  panel's request log, for example ([changelog](../CHANGELOG.md#093--2026-10-20)).
  The [troubleshooting](troubleshooting.md) page quotes the lines of the
  release it describes. Alert on the status record, `/readyz` or the exit
  codes above, not on log text.
- **The panel's pages and their wording**, `/embed` included, and
  `/api/exits` and `/api/latency`, which serve the page.
- **Anything you reach only from inside the code**: Go packages, the
  supervisor's protocol with its worker, the run files, the drills.
- **Platforms, providers and forms marked experimental.** Their settings and
  files follow this page, but whether they are offered at all is not
  promised; [testing](testing.md) says what has run where.
- **The image's contents** beyond the roles: the NetBird client version, the
  base image and the files in it change when they are updated.

## Image tags

- `vX.Y.Z` is a release. It is never moved or deleted, and its index digest is
  the one the live acceptance attested. Pin it
  with its digest, as the Compose files and the bundle do.
- `X.Y`, without the `v` (for example `ghcr.io/irashack/molebridge:0.9`),
  follows the newest `vX.Y.Z` patch release. It moves, so it is a
  convenience for pulling, not something to verify: cosign signs the image
  digest, not the tag, so check the digest a pull gave you against the
  release notes as in [setup](setup.md#1-download-and-verify).
- `vX.Y.Z-rc.N` is a release candidate. It is published so it can be tested
  and is never promised to be released.

## Deprecation

The rule is one minor release of overlap. When something on this page, or
anything else the docs describe, is to be removed or replaced:

1. The release that deprecates it says so in its changelog, under the item's
   own name, and says what replaces it. The docs mark it deprecated where
   they describe it.
2. It keeps working beside its replacement for one minor release: deprecated
   in 1.3, it is still there in every 1.3 patch release, and goes in 1.4 at
   the earliest.
3. The release that removes it says so in its changelog.

For an item on the list above, the removal also waits for the next major
release. Before 1.0 the overlap rule applies to everything, the list
included. The one deprecation before this page, `view` in `/api/status`,
was announced at 0.7.0 for one release and stayed until 0.10.
