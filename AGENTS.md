# Working on Molebridge

Read `README.md` and `docs/architecture.md` first. Keep the GitHub repository
private and unlicensed until the owner explicitly asks to publish it.

## Write for someone else's machine

- Design for a person installing on an ordinary supported host: Docker with
  Compose, a NetBird account, a Mullvad account. Never require the author's
  infrastructure, hostnames, directory layout, identity provider, secret store,
  monitoring or deployment tooling.
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
  applier need the checks in `docs/verification.md`, run on a real host, before
  a claim that they work.
- **Privilege split:** the panel holds no capabilities, never runs `wg`, `ip` or
  subprocesses, and only writes the desired server name. The applier validates
  everything it reads and never mounts the tunnel config.
- **Untrusted input:** Mullvad's relay list, desired-state files and form posts
  are untrusted. Validate before use; escape before rendering.
- **Honest status:** state what was tested and where. Untested platforms, and
  behavior described but not verified, say so.

## Changes

- Pin images to exact releases with multi-arch digests; update deliberately.
- The panel stays Python standard library only; front-end code stays
  dependency-free.
- Validate in proportion to impact: `pytest -q panel tools`, `sh -n` and
  `shellcheck` on shell scripts, `docker compose config` against
  `.env.example`. Update the docs a change affects in the same commit.
