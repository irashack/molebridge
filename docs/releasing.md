# Releasing

This is the maintainer's runbook for a release: a candidate tag, the live
acceptance, the attestation of that acceptance, the promotion and the Compose
pins afterwards. The workflows that do the work are
`.github/workflows/release.yml` and `.github/workflows/acceptance.yml`; this
page says what you run and in which order. Only the owner creates release
tags ([AGENTS.md](../AGENTS.md)), or the release automation does
([automatic releases](#automatic-releases)).

Two rules hold throughout. A `v*` tag can't be moved or deleted, and a
published release is immutable. So a candidate that fails is never re-tagged:
you fix `main` and tag the next `-rc.N` ([superseding a
candidate](#superseding-a-candidate)). And the release tag goes on the commit
the accepted candidate was built from, so anything you write after the
acceptance (the testing record, the changelog's date, the Compose pins) lands
on `main` after the release, not in it.

The examples use `0.10.0` and its first candidate. Replace the version, and
use your own values where the examples have placeholders in angle brackets.

## 1. Prepare `main`

1. The changelog has an entry for the release, headed `unreleased` until the
   acceptance dates it.
2. The acceptance policy, `tools/acceptance-policy.json`, names what the live
   acceptance must cover: `platforms`, `providers`, `kinds` and `drills`. For
   each release, raise its `version` by one and change the upgrade drill to the
   release before this one (`upgrade-from-0.9.4` for 0.10.0). Change the same
   drill in `tools/test-make-acceptance-predicate.sh`, whose coverage must
   satisfy the policy.
3. CI's five jobs passed on the commit you'll tag, and that commit is on
   `main`. The candidate job refuses a tag whose commit isn't on `main`
   (`the tagged commit is not on main`).

```sh
git switch main && git pull --ff-only
gh run list --workflow ci.yml --commit "$(git rev-parse HEAD)"
```

If you changed `release.yml` or the actions it uses, run the signing
rehearsal first. It builds, signs and attests both images to throwaway
packages, `ghcr.io/irashack/molebridge-ci` and
`ghcr.io/irashack/molebridge-core-ci`, never the release ones, and checks the
whole promotion policy against a synthetic acceptance for each:

```sh
gh workflow run release.yml --ref main
```

## 2. Tag the candidate

```sh
git tag v0.10.0-rc.1
git push origin v0.10.0-rc.1
```

Candidate tags have the form `vX.Y.Z-rc.N`. The push starts the `Release
candidate` job of `release.yml`, which:

1. checks the tag's form and that its commit is on `main`;
2. builds the image for amd64 and arm64, pushes it as
   `ghcr.io/irashack/molebridge:v0.10.0-rc.1`, signs the index digest with
   cosign (keyless, under the workflow's identity) and attaches build
   provenance and an SBOM for each architecture; then does the same for
   molebridge-core, the Dockerfile's `core` target without the NetBird
   client, as `ghcr.io/irashack/molebridge-core:v0.10.0-rc.1`. Both images
   come from the same commit and run, and both carry the candidate's version;
3. builds `molebridge-v0.10.0-rc.1.tar.gz` with `tools/make-bundle.sh`, which
   rewrites every image reference in the Compose files to that tag and
   digest, signs it (`.sigstore.json`) and attests its provenance;
4. writes the release notes (`tools/release-notes.sh`), with the commit and
   both images' digests;
5. creates a GitHub pre-release with the bundle, its signature and the SBOMs
   (`sbom-linux-<arch>.spdx.json` for the image with NetBird,
   `sbom-core-linux-<arch>.spdx.json` for molebridge-core).

CI also runs on the tag push. The `ci-namespace-drills` drill in the
acceptance policy is CI's namespace-drill job passing on the tag:

```sh
gh run list --workflow ci.yml --branch v0.10.0-rc.1
gh run list --workflow release.yml --branch v0.10.0-rc.1
```

## 3. Run the live acceptance

Install the candidate the way its users will: download the pre-release's
bundle, verify it as in [setup](setup.md#1-download-and-verify) with
`TAG=v0.10.0-rc.1` and `RC=v0.10.0-rc.1`, and move the exits under test to the
candidate's digest. Then run what the policy names:

- **platforms**, **providers** and **kinds**: an exit of each listed kind
  (`native`, `gluetun`, `sidecar`, `native-sidecar`), each listed provider, on
  each listed platform, comes back `ok` on the candidate;
- **drills**: the upgrade from the previous release, changing only what the
  changelog's **Breaking** items for this release ask for
  (`upgrade-from-0.9.4`; for 0.10.0, `net.ipv4.icmp_errors_use_inbound_ifaddr`
  on Kubernetes, and check that a native exit without it doesn't start
  NetBird); the tunnel deleted and recovered (`tunnel-loss`); a client on the
  exit while the panel switches
  its server ([from a client](verification.md#from-a-client), `client-switch`);
  the required [status drills](verification.md#status-drills)
  (`status-drills`: a stopped exit showing stale with `/readyz` 503, the
  egress-check failure and recheck, the 409 for a second switch, and a
  failed switch retried; the rest of that section is recorded when it runs,
  not required); the
  [network exchange](verification.md#the-network-exchange) between an exit and
  a panel on different nodes (`network-exchange`); since 0.11.0, a selected
  server taken out of gluetun's server list and put back
  ([a retired server](verification.md#a-retired-server),
  `retired-server-move`); and CI's namespace drills on the tag
  (`ci-namespace-drills`). The procedures are in [verification](verification.md). The policy
  is a list, not a matrix: say in the record which exits each drill ran on,
  and in which address families.

  Since policy 15, rule-drift repair and the lease lapse are no longer run
  by hand: CI's namespace drills test both on a real kernel for every
  commit and on the tag (rule drift: `internal/drill` `drift_drill_test.go`,
  `guard_drill_test.go` and `partial_drill_test.go`; the lease:
  `TestDrillFrozenWorkerStopsNetBirdWithinGraceAndBudget` and
  `TestDrillWedgedMutatorLapsesTheLeaseEvenWithRenewalsRunnable` in
  `internal/exit`), and they count through `ci-namespace-drills`. The tunnel
  loss stays live, because it is the policy's one check that nothing leaves
  off the tunnel on a real host with a real provider
  ([#54](https://github.com/irashack/molebridge/issues/54)).

Write down what ran, where and with which results as you go. The record goes
into [testing](testing.md) afterwards, in the form of the earlier candidates'
records, and the evidence you attest should point at notes you keep.

If anything fails, don't attest. [Supersede the
candidate](#superseding-a-candidate).

## 4. Attest the acceptance

`acceptance.yml` writes the attestation that promotion looks for, once for
each image: one run, one coverage and evidence, an attestation on the image
with NetBird and another on molebridge-core. It takes three inputs:

- `rc_tag`: the candidate tag, `v0.10.0-rc.1`;
- `coverage`: a JSON object with `platforms`, `providers` and `kinds` (arrays
  of names) and `drills` (an array of objects, each with an `id` and a
  `result`). Names and ids are 1 to 64 characters of letters, digits, `.`,
  `_` and `-`; a result is 1 to 16 lowercase letters;
- `evidence`: a JSON array of 1 to 50 references (URLs, run IDs, notes), each
  1 to 500 printable characters.

For the policy above, the coverage is:

```json
{"platforms":["podman-rootless-quadlet","kubernetes"],
 "providers":["mullvad","pia","nordvpn"],
 "kinds":["native","gluetun","sidecar","native-sidecar"],
 "drills":[{"id":"ci-namespace-drills","result":"passed"},
           {"id":"tunnel-loss","result":"passed"},
           {"id":"upgrade-from-0.9.4","result":"passed"},
           {"id":"client-switch","result":"passed"},
           {"id":"status-drills","result":"passed"},
           {"id":"network-exchange","result":"passed"}]}
```

Dispatch the workflow on `main`: the attestation is signed with the identity
`acceptance.yml@refs/heads/main`, and its job doesn't run from any other ref.

```sh
gh workflow run acceptance.yml --ref main \
  -f rc_tag=v0.10.0-rc.1 \
  -f coverage="$(jq -c . coverage.json)" \
  -f evidence='["https://github.com/irashack/molebridge/actions/runs/<ci-run-id>","<your notes reference>"]'
gh run watch "$(gh run list --workflow acceptance.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

The workflow refuses a candidate whose commit is not on `main`, then resolves
the candidate's commit and index digest, checks the
digest's build provenance and the bundle's attestation against
`release.yml` at that tag, and writes the predicate with
`tools/make-acceptance-predicate.sh`. That script refuses unless the coverage
includes everything the policy names and every drill has the result
`passed`; it prints `make-acceptance-predicate: refused: coverage is
incomplete or a drill did not pass:` and the missing items. The tools run from
`main`'s checkout; only `tools/acceptance-policy.json` is taken from the
candidate, so the policy that counts is the candidate's own. The
attestations are then pushed to the registry beside each image and checked
with the same policy promotion uses.

Nothing checks the coverage against what actually ran: the attestation
records your statement. Attest only what you ran.

## 5. Promote

Tag the release on the candidate's commit and push it:

```sh
git tag v0.10.0 v0.10.0-rc.1^{commit}
git push origin v0.10.0
```

The push starts the `Promote the accepted candidate` job, which builds
nothing. It:

1. checks the tag's form (`vX.Y.Z`) and that its commit is on `main`;
2. considers the candidate tags `v0.10.0-rc.*` that point at the same commit,
   highest first, and takes the first whose signature, build provenance and
   acceptance attestation all verify on both images. With none it stops with
   `no accepted release candidate for v0.10.0 at <commit>; run live
   acceptance (acceptance.yml) for a candidate of this commit`;
3. copies each image's digest to its `v0.10.0` tag
   (`ghcr.io/irashack/molebridge:v0.10.0`,
   `ghcr.io/irashack/molebridge-core:v0.10.0`), refusing before it tags
   either if a tag already exists with another digest, and moves each image's
   floating `0.10` tag when this is the highest `v0.10.*` release
   ([image tags](compatibility.md#image-tags));
4. signs both digests again under the release tag's workflow identity;
5. builds and signs `molebridge-v0.10.0.tar.gz` for the image with NetBird's
   digest, fetches both images' SBOMs from the candidate, writes the release notes (which name the candidate
   the build ran under) and creates the GitHub release.

Then verify the published release from a clean directory with
[setup](setup.md#1-download-and-verify), with `TAG=v0.10.0` and the `RC` the
release notes name.

## 6. After the release

On `main`, in separate commits as before:

1. **The record.** Add the candidate's live acceptance to
   [testing](testing.md), with the candidate, its digest, its commit and the
   acceptance run, and give the changelog entry its date.
2. **The Compose pins.** The Compose files in the source pin the latest
   release by tag and digest, so a checkout runs a published image. Replace
   the image reference in `compose.yaml`, `compose.gluetun.yaml`,
   `compose.sidecar.yaml` and `compose.native-sidecar.yaml` (every service
   that runs the Molebridge image) with
   `ghcr.io/irashack/molebridge:v0.10.0@sha256:<index digest>`, from the
   release notes. Update the example tags that follow it: the bundle example
   in the README, `TAG` and `RC` in [setup](setup.md#1-download-and-verify)
   and the placeholder in `.github/ISSUE_TEMPLATE/bug.yml`. Then run
   `docker compose config` for each form and `sh tools/check-compose.sh`, as
   in [CONTRIBUTING](../CONTRIBUTING.md#checks). The bundle rewrites these
   references to its own image either way, so the pins matter for people who
   run from a checkout.

```sh
grep -rn 'ghcr.io/irashack/molebridge:' compose*.yaml README.md docs/setup.md .github/ISSUE_TEMPLATE/bug.yml
```

## Automatic releases

`tools/auto-release.py` runs these steps without a person. The maintainer
runs it hourly against a clean clone of the repository, with a token of the
release bot (`MOLEBRIDGE_RELEASE_TOKEN_COMMAND`, a command that prints one,
run again for a fresh token every two minutes and after a 401; else
`GH_TOKEN`). A tag pushed with a workflow's own `GITHUB_TOKEN` doesn't
start `release.yml`, so this can't run as a workflow. Each run picks up where
the repository stands:

1. **Prepare.** When the changelog's `## Unreleased` section has entries, or
   the open "Scheduled scan findings" issue lists an Alpine package with a fix
   for the current release's image, it opens a pull request with
   [step 1](#1-prepare-main): the heading `## X.Y.Z — unreleased`, the policy's
   version and upgrade drill. Changelog entries make a minor release; Alpine
   fixes alone make a patch release, a rebuild. It merges the pull request once
   CI passes, then tags `vX.Y.Z-rc.1` on `main` once CI passes there.
2. **Ask for the live acceptance.** Once the candidate is published, it
   comments `Live acceptance requested: vX.Y.Z-rc.1` on
   [#45](https://github.com/irashack/molebridge/issues/45) with both images'
   references and digests.
3. **Read the result.** Whoever runs the live acceptance answers on #45. The
   comment starts `Live acceptance result: vX.Y.Z-rc.1` and has a fenced
   `json` block:

   ```json
   {"rc_tag":"v0.12.0-rc.1","result":"passed",
    "digests":{"molebridge":"sha256:<index digest>","molebridge-core":"sha256:<index digest>"},
    "coverage":{"platforms":[],"providers":[],"kinds":[],"drills":[]},
    "evidence":["<reference>"]}
   ```

   In a `passed` result a drill may be given by its id alone
   (`"tunnel-loss"`), which stands for `{"id":"tunnel-loss","result":"passed"}`.
   It may also carry a fenced `markdown` block, the record of what ran, for
   [testing](testing.md). `result` is `passed`, `failed` or
   `needs-attended`. Only comments from the accepted author
   (`RESULT_AUTHORS` in the script) count, and only unedited ones. The
   newest one for the candidate decides.
4. **Attest and promote.** On `passed`, with both digests matching the
   candidate's, it dispatches `acceptance.yml` ([step 4](#4-attest-the-acceptance)).
   Once that run passes, it tags `vX.Y.Z` on the candidate's commit
   ([step 5](#5-promote)).
5. **Record.** After the promotion it opens and merges, on green CI, the pull
   request for [step 6](#6-after-the-release): the record in testing, the
   changelog's date, and the Compose pins and examples.

It stops and opens an issue titled `Release blocked: ...` on a **Breaking**
item in the changelog, a failed workflow or CI, a failed live acceptance, or
digests that don't match, and when the script itself fails two runs in a row.
While that issue, or any issue or pull request
labeled `hold-release`, is open, it does nothing. Close the issue to let it go
on. After a failed acceptance it tags the next candidate from `main` once
`main` has moved on and CI passes. A `needs-attended` result waits for a later
result on the same candidate. A Breaking release is prepared and tagged by a
person; the automation then carries on from the live acceptance.

## Superseding a candidate

A candidate that fails its acceptance, or that you don't want to release,
stays published as a pre-release; you can't delete or move its tag. Fix the
problem on `main`, then tag the fix as the next candidate:

```sh
git tag v0.10.0-rc.2
git push origin v0.10.0-rc.2
```

and run the acceptance again from [step 3](#3-run-the-live-acceptance). An
attestation names one digest and one commit, so nothing carries over from the
earlier candidate, and a change to the policy in `tools/` is a new commit too:
the acceptance reads the candidate's own. Say in the testing record why the
earlier candidate was not released.

When the candidate was fine and the acceptance failed outside it (the test
host, a typing mistake in the coverage, which makes the predicate writer
refuse and attests nothing), run the acceptance again for the same candidate;
no new tag is needed.
