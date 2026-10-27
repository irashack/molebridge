# Releasing

This is the maintainer's runbook for a release: a candidate tag, the live
acceptance, the attestation of that acceptance, the promotion and the Compose
pins afterwards. The workflows that do the work are
`.github/workflows/release.yml` and `.github/workflows/acceptance.yml`; this
page says what you run and in which order. Only the owner creates release
tags ([AGENTS.md](../AGENTS.md)).

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
rehearsal first. It builds, signs and attests to a throwaway package,
`ghcr.io/irashack/molebridge-ci`, never the release one, and checks the whole
promotion policy against a synthetic acceptance:

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
   provenance and an SBOM for each architecture;
3. builds `molebridge-v0.10.0-rc.1.tar.gz` with `tools/make-bundle.sh`, which
   rewrites every image reference in the Compose files to that tag and
   digest, signs it (`.sigstore.json`) and attests its provenance;
4. writes the release notes (`tools/release-notes.sh`), with the commit and
   the digests;
5. creates a GitHub pre-release with the bundle, its signature and the SBOMs.

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
- **drills**: the upgrade from the previous release with no setting changed,
  rule drift repaired (`live-drift-repair`), the tunnel deleted and recovered
  (`tunnel-loss`), the worker frozen until the lease lapses and the exit
  restarts (`lease-lapse`), and CI's namespace drills on the tag. The
  procedures are in [verification](verification.md).

Write down what ran, where and with which results as you go. The record goes
into [testing](testing.md) afterwards, in the form of the earlier candidates'
records, and the evidence you attest should point at notes you keep.

If anything fails, don't attest. [Supersede the
candidate](#superseding-a-candidate).

## 4. Attest the acceptance

`acceptance.yml` writes the attestation that promotion looks for. It takes
three inputs:

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
           {"id":"live-drift-repair","result":"passed"},
           {"id":"lease-lapse","result":"passed"},
           {"id":"tunnel-loss","result":"passed"},
           {"id":"upgrade-from-0.9.4","result":"passed"}]}
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
attestation is then pushed to the registry beside the image and checked with
the same policy promotion uses.

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
   highest first, and takes the first whose image signature, build
   provenance and acceptance attestation all verify. With none it stops with
   `no accepted release candidate for v0.10.0 at <commit>; run live
   acceptance (acceptance.yml) for a candidate of this commit`;
3. copies that digest to `ghcr.io/irashack/molebridge:v0.10.0`, refusing if
   the tag already exists with another digest, and moves the floating `0.10`
   tag to it when this is the highest `v0.10.*` release
   ([image tags](compatibility.md#image-tags));
4. signs the digest again under the release tag's workflow identity;
5. builds and signs `molebridge-v0.10.0.tar.gz` for the same digest, fetches
   the candidate's SBOMs, writes the release notes (which name the candidate
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
