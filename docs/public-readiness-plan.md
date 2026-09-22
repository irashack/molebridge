# Molebridge public-readiness plan

Status: draft for Fable review. Prepared 2026-09-22 against `984a703`.

## Outcome

Prepare Molebridge for public sharing as an **experimental, self-hosted
NetBird-to-Mullvad exit**. Close the installation and diagnostic gaps found in
the readiness review, make the testing claims precise, and prepare the small
amount of publication material needed for someone else's machine.

This document is a plan. It authorizes no implementation, live deployment,
host restart, license change, repository visibility change, or release.
Publishing remains a separate owner decision under [AGENTS.md](../AGENTS.md).

The first public version should retain the existing scope: one shared exit,
Mullvad, NetBird, and an externally authenticated panel. Additional providers,
built-in login, automatic failover, and a runtime watchdog are outside this pass.

## Review baseline

The September 22 review found no new critical routing or panel-boundary defect
in the inspected code. That is a bounded review result, not proof of leak-free
operation across clients and platforms.

- Locally verified at `984a703`: 231 tests passed, 31 subtests passed, one
  expected platform-specific skip; shell syntax, Compose validation against
  `.env.example`, and whitespace checks passed. Panel integration tests needed
  local loopback sockets permitted by the execution environment.
- A targeted scan of the 17 locally reachable commits, covering 129 text blobs,
  found no obvious committed credentials. This was not a dedicated secret
  scanner or a review of hosted Actions logs and artifacts.
- Image builds, ShellCheck, Linux namespace drills, and real-client/reboot
  testing were not rerun during that review. Remote CI could not be checked
  with the available GitHub access.
- The repo reports live OrbStack testing and a newer Debian/rootless Podman
  deployment. Its records do not yet clearly associate every outcome with a
  tested revision; the README still says the hardening pass has not been rerun.

Rebase this plan's assumptions on the actual implementation revision before
starting work. Preserve any newer changes.

## 1. Verify the required NetBird interface exclusion

**Problem:** [setup](setup.md#5-keep-ice-off-the-tunnel-interface) requires
`mullvad` in NetBird's ICE interface blacklist. The host doctor does not inspect
that setting, and the upgrade recipe does not explicitly apply it. An existing
installation can complete recovery and pass doctor while missing it.

**Changes:**

1. Inspect the pinned NetBird 0.78.2 implementation to establish how to read the
   effective blacklist and how the documented flag updates existing settings.
   Prefer a supported CLI/RPC query. Do not assume a new environment variable
   overrides persisted peer configuration.
2. Add a read-only host-doctor check for the actual exit interface. Report a
   fixed PASS/FAIL label and an actionable correction. An unavailable or
   unparseable setting must not pass silently.
3. If a configuration-file read is necessary, select only the relevant field
   without logging or displaying the complete file. Keep NetBird identity
   files out of the panel and applier; do not add capabilities or a runtime
   socket mount to either component.
4. Document the correction for both fresh installs and upgrades, including
   preservation of existing blacklist entries and other peer settings. Keep
   `doctor` free of `netbird down/up` side effects.
5. Consider setting the exclusion at first enrollment only if the pinned
   client's supported startup path makes that straightforward and testable.
   The minimum deliverable is a checked, explicit setup/upgrade step; avoid
   introducing a new enrollment controller for this release.

**Acceptance:** absent exclusion fails; present exclusion passes; malformed or
unavailable inspection fails clearly; existing settings and peer identity
survive the correction and recreation. Tests cover these outcomes and verify
that diagnostics contain no configuration contents or credentials. A relayed
connection alone does not fail this check: direct connectivity depends on the
network and is a separate observation.

Likely files: `tools/molebridge.py`, `tools/test_host_and_routing.py`,
`docs/setup.md`, `docs/operations.md`, and `docs/verification.md`.

## 2. Complete the documented Podman path

**Problem:** rootless Podman is advertised as supported, while setup and
recovery examples use Docker and the Python helper invokes `docker compose`
directly. The prerequisites acknowledge this but leave the replacement
procedure to the reader. Boot startup is also unspecified and unverified.

**Changes:**

1. Provide exact setup, upgrade, and recovery commands for the tested Debian
   13 / Podman 5.4 / podman-compose 1.6 combination. Keep the existing Docker
   helper; a general engine abstraction is not required for this pass.
2. Document the sequence that rebuilds before interrupting service, recreates
   the namespace owner and its dependents together, preserves the identity
   volume and project name, and verifies namespace agreement and applier
   health afterward. The applier's internal doctor alone does not perform all
   the host helper's checks.
3. Specify the tested rootless boot-start arrangement and user-session
   requirements. Verify the actual Podman/systemd integration before writing
   commands. `restart: unless-stopped` is not a complete boot-start recipe;
   [Podman's restart documentation](https://docs.podman.io/en/v5.4.0/markdown/podman-update.1.html#restart-policy)
   describes the separate systemd restart service.
4. Scope the NAT/direct-connection advice to observed conditions. Establish
   the failure using candidate and connectivity evidence before recommending
   port publication or an external-address mapping. Do not generalize one
   rootless deployment's behavior to every Docker bridge or NAT.

**Acceptance:** a reader can execute the documented Podman path without
inventing commands or using Docker. On an authorized test host, recreation
preserves identity and restores the shared namespace and verified egress.
Claim unattended boot support only after a reboot test passes; otherwise mark
that part of Podman support explicitly experimental and describe manual start.
No default inbound port exposure is added.

Likely files: `docs/prerequisites.md`, `docs/setup.md`, `docs/operations.md`,
`docs/verification.md`, and the README support table.

## 3. Reconcile testing evidence and remaining checks

**Changes:**

1. Collect the existing sanitized testing outcomes before scheduling more
   drills. Do not discard the recent Podman evidence or turn a historical
   failure into a claim that the current code still fails.
2. Give each reported result its revision, date, host/runtime versions,
   architecture, NetBird versions, client type, test method, and outcome.
   Separate unit tests, isolated Linux drills, namespace probes, and traffic
   from a real client. Use one detailed record in `docs/homelab-testing.md`
   with a short, consistent README summary.
3. Verify CI for the publication candidate, including the existing image
   builds, shell lint, and Linux routing drills. A workflow definition or a
   green result for an older commit is not evidence for a newer candidate.
4. For runtime changes made in this pass, run the applicable real-host checks
   required by AGENTS.md. Live work belongs to a separately authorized test
   session, following that deployment's own rules.

Use [verification.md](verification.md) for the procedures. Reuse valid existing
evidence, and identify the remaining checks explicitly:

| Check | Evidence needed |
| --- | --- |
| Ordinary use and switching | Real client reaches Mullvad and follows a relay change; DNS and IPv6 observations are recorded separately. |
| Client held on the exit during failure | Tunnel down and per-family route loss block the affected exit traffic without fallback through the host; surviving-family behavior is recorded. |
| UDP/QUIC and return-path handling | Oversized replies work with the current ICMP-only return rule; distinguish a real UDP result from browser TCP fallback. |
| Client access to the exit host's LAN | An explicitly selected test destination on that LAN is unreachable through the exit; distinguish separately distributed NetBird routes and the client's own LAN. |
| Recreation and boot | Peer identity is preserved, dependents rejoin the right namespace, guards precede forwarding, and status recovers honestly. |

**Acceptance:** every positive testing claim has a traceable scope and
revision. Missing evidence is labeled unverified. Do not mark reboot or
real-client checks complete based on unit tests or simulated forwarding.
Public records contain no private addresses, hostnames, identities, or keys.

## 4. Prepare publication material

After the owner authorizes publication:

- Add the owner-selected project license and preserve the bundled font's
  existing license. Until that decision, retain the repo's current unlicensed
  status.
- Add a short `SECURITY.md` with a working private reporting route. Verify the
  chosen route before advertising it; do not invent an address or promise
  response times the maintainer has not agreed to.
- Update private-development wording in README and AGENTS.md. State the
  experimental support level, tested platforms, shared-server behavior,
  external-authentication requirement, and client DNS/IPv6 boundary plainly.
- Add one panel screenshot using fictitious data if readily available. This
  improves discovery but is not a publication blocker.
- Run an established secret scanner over all reachable history with redacted
  output. Review findings without copying secrets into reports. Inspect any
  hosted logs/artifacts that will become public, and commit metadata for
  unintended workstation names or private email addresses. Repository file
  contents alone are not the whole publication surface.

## Completion and publication decision

Implement in reviewable groups: ICE diagnostics and instructions; Podman
operations documentation; consolidated verification record; publication
metadata after the owner decision. Run checks proportional to each change.
No runtime deployment is needed for documentation-only edits.

**Ready for public experimental sharing when:**

- The mandatory ICE setting is checked and its setup/upgrade path is clear.
- Advertised platform support matches the procedures and evidence available.
- Candidate CI and applicable runtime checks pass; there is no known
  unresolved fail-open defect in the advertised configuration.
- The testing record clearly identifies remaining experimental limitations.
- License, private reporting route, and publication-surface review are complete.
- The owner has explicitly authorized the visibility change. Creating a
  release/tag is a separate choice; it is not required to share the source.

Missing reboot or broader client/platform evidence can remain documented
limitations for experimental sharing. It prevents claims of verified
unattended operation or stable, general-purpose support. It must not excuse a
known traffic leak or a failed required check after changing routing behavior.

## Questions for Fable

1. Is checking the effective ICE exclusion plus an explicit correction enough
   for the first public version, or is first-enrollment enforcement necessary?
   Verify the pinned client's behavior before selecting the mechanism.
2. Is the documented Podman lifecycle sufficient, or is a specific helper
   change essential for correctness? Prefer the smallest supported path.
3. Which current live results close the listed gaps, and which need a fresh
   test? Challenge both unsupported success claims and unnecessary reruns.
4. Are the experimental-publication criteria proportionate to the product's
   privacy claims? Identify any concrete blocker this plan misses, with a
   failure scenario and the smallest fix.

Review the plan and current code; do not implement or operate the live exit as
part of that review.
