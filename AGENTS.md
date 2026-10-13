# Working on Molebridge

Read `README.md`, `docs/architecture.md` and the layout in `CONTRIBUTING.md`
first. Molebridge is MIT-licensed; the bundled font keeps its own license.
Create releases or tags only when the owner asks: a `v*-rc.N` tag builds,
signs and publishes a candidate image, and a `vX.Y.Z` tag promotes the
candidate that live acceptance attested (`.github/workflows/release.yml`).
The Compose files in the source pin the latest release by tag and digest,
so a checkout runs a published image; after a release, update them to it
(the release bundle rewrites them to its own image either way).
Handle suspected vulnerabilities through the private route in `SECURITY.md`,
never in a public issue or commit message.

## Write for someone else's machine

- Design for a person installing on an ordinary supported host: Docker Engine
  with Compose, or rootless Podman (podman-compose, or Quadlet units you
  write), a NetBird account, and a Mullvad, PIA or NordVPN account or a
  provider gluetun supports. Never require the author's infrastructure,
  hostnames, directory layout, identity provider, secret store, monitoring or
  deployment tooling.
- Site-specific deployment records and policies belong with that deployment,
  not here. A deployment's conventions are not product requirements.
- Keep credentials, real hostnames, IP addresses, account numbers, peer names and
  personal network details out of source, tests, fixtures, logs and docs. Use
  fictitious values: `example.net`/`.test` names, documentation address ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`), and
  all-zero keys. Document secrets by file and field name only.

## Preserve the properties

- **Fail-closed:** forwarded client traffic must never egress anywhere but the
  tunnel. Changes to routing, the tunnel config, compose networking or the
  exit need the checks in `docs/verification.md`, run on a real host, before
  a claim that they work.
- **Privilege split:** the panel is its own container, holds no capabilities,
  never runs `wg`, `ip` or subprocesses, and only writes the desired server
  name; it checks its own isolation at start and refuses to run otherwise.
  The exit container holds `NET_ADMIN`, the tunnel key and the provider
  credentials (with the gluetun backend gluetun also holds `NET_ADMIN` and its
  key). The exit's binary starts no shell: the only programs it runs are the
  pinned NetBird client and its own worker and cleanup roles.
- **Untrusted input:** Mullvad's relay list, PIA's region list and API
  responses, NordVPN's server list, gluetun's `servers.json` and control
  server answers, the tunnel config, the stored NetBird profile,
  desired-state files and form posts are untrusted. Validate before use
  (bounded reads, strict UTF-8, duplicate JSON keys refused); escape before
  rendering.
- **Exits only:** Molebridge never ships its own tunnel for other containers'
  traffic; that is gluetun's job. The image holds no credentials: keys,
  logins and tokens come from files you mount.
- **Honest status:** state what was tested and where. Untested platforms, and
  behavior described but not verified, say so.

## Changes

- Pin images to exact releases with multi-arch digests; update deliberately.
- The panel and the exit are Go. Use the standard library wherever it
  reaches; the only modules are the vendored set in `vendor/modules.txt`
  (netlink, WireGuard control, nftables), and a new one needs a reason in
  the commit message. Front-end code (`panel/static/`) stays dependency-free.
- Validate in proportion to impact: `gofmt -l`, `go vet ./...` and
  `go test ./...` (CI also runs staticcheck and govulncheck); the namespace
  drills (`sh internal/nstest/drill.sh`, which needs Docker and runs
  privileged in a throwaway container) for anything that touches routing, the
  tunnel or the mutation owner; `node --test panel/js-tests/*.test.js` for the
  panel script, which asks the Go toolchain for the panel's answers; `sh -n`
  and `shellcheck` on the shell scripts (`routing/gluetun-preflight` and
  `tools/*.sh`); and `docker compose config` against `.env.example` (with
  `PROVIDER` set to each of `mullvad`, `pia` and `nordvpn`),
  `compose.gluetun.yaml` against `.env.gluetun.example` and
  `compose.sidecar.yaml` against `.env.sidecar.example` (`tools/check-compose.sh`
  checks the trust boundary as Compose resolves it). Update the docs a change
  affects in the same commit, and run `sh tools/check-doc-links.sh`.

## Writing docs

- Write for someone installing this on their own machine: plain sentences,
  "you", specific numbers and commands. No marketing language, feature grids
  or slogans.
- Say what was tested, where and at which revision, and say what wasn't.
  Link to `docs/testing.md` rather than restating results.
- Use "never", "every" and "always" only where the code guarantees it.
- Quote messages exactly as the code prints them.
- Keep one canonical place for each procedure and link to it.
