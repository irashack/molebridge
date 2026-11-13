---
name: release
description: Cut a Molebridge release - the order of the steps in docs/releasing.md with the command for each (prepare main, candidate tag, live acceptance, attestation, promotion, the record and Compose pins afterwards) and the points that cannot be undone. Use when the owner asks for a release or a candidate, or to check whether main is ready for one.
---

# Releasing Molebridge

`docs/releasing.md` is the runbook and stays authoritative; this is the short path through it.
Read the runbook's step when a command here surprises you.

Tags are the owner's call: create a `v*` tag only when the owner asked for this release
(AGENTS.md). A `v*` tag cannot be moved or deleted and a published release is immutable, so
nothing below is retried in place: a failed candidate is superseded by the next `-rc.N`.

Set these once (the examples in the runbook use 0.10.0):

```sh
V=0.10.3; RC=v$V-rc.1; PREV=0.10.2
```

## 1. Prepare `main` (a pull request)

- CHANGELOG.md has the release's entry, headed `unreleased`.
- `tools/acceptance-policy.json`: `version` raised by one, the upgrade drill renamed to
  `upgrade-from-$PREV`; the same drill in `tools/test-make-acceptance-predicate.sh`.
  `sh tools/test-make-acceptance-predicate.sh` passes.
- If `release.yml` or an action it uses changed: `gh workflow run release.yml --ref main`
  (the signing rehearsal, against the throwaway package) and wait for it.
- After the merge, CI's five jobs are green on the commit to be tagged:

  ```sh
  git switch --detach origin/main
  gh run list --workflow ci.yml --commit "$(git rev-parse HEAD)"    # the full SHA; a short one finds nothing
  ```

## 2. Candidate

```sh
git tag $RC "$(git rev-parse origin/main)" && git push origin $RC
gh run list --workflow release.yml --branch $RC     # builds, signs, publishes the pre-release
gh run list --workflow ci.yml --branch $RC          # the ci-namespace-drills drill is this run
```

Both green before anything else. From here the release commit is fixed: whatever is written
later lands on `main` after the release.

## 3. Live acceptance

Not something this checkout can do: it runs on real hosts with real provider accounts. Whoever
operates them installs the candidate from its bundle (docs/setup.md, `TAG=$RC`) and runs what
the candidate's policy names; give them the list:

```sh
git show $RC:tools/acceptance-policy.json
```

Ask back for: each platform, provider and kind with its result, each drill with its result,
the candidate's digest as installed, and a reference to their notes. Any failure: do not
attest; fix `main` and go to 2 with the next `-rc.N`. A failure outside the candidate (the
test host, a typo in the coverage) needs no new tag.

## 4. Attest

Write `coverage.json` from what actually ran (the shape is in the runbook's step 4; ids and
names must match the policy exactly). Nothing checks it against reality: attest only what
ran. Keep it outside the checkout.

```sh
gh workflow run acceptance.yml --ref main \
  -f rc_tag=$RC -f coverage="$(jq -c . coverage.json)" \
  -f evidence='["https://github.com/irashack/molebridge/actions/runs/<ci run on the tag>","<notes reference>"]'
gh run watch "$(gh run list --workflow acceptance.yml --limit 1 --json databaseId --jq '.[0].databaseId')"
```

`refused: coverage is incomplete or a drill did not pass` lists what is missing; correct the
coverage and dispatch again for the same candidate.

## 5. Promote

```sh
git tag v$V "$RC^{commit}" && git push origin v$V
gh run list --workflow release.yml --branch v$V
```

Builds nothing: it copies the accepted candidate's digest. Then verify the published release
from a clean directory as docs/setup.md does, with `TAG=v$V` and the `RC` the release notes
name.

## 6. Afterwards (a pull request, separate commits)

- The record: the live acceptance in docs/testing.md in the form of the earlier records
  (candidate, digest, commit, acceptance run), and the changelog entry's date.
- The pins: `ghcr.io/irashack/molebridge:v$V@sha256:<index digest>` in the four Compose
  files, and the example tags that follow it:

  ```sh
  grep -rn 'ghcr.io/irashack/molebridge:' compose*.yaml README.md docs/setup.md .github/ISSUE_TEMPLATE/bug.yml
  sh tools/check-compose.sh && sh tools/check-doc-links.sh
  ```

  `docker compose config` for each form runs in CI when the host has no Docker.
- Tell whoever runs a deployment that the release is there: the tag, the index digest, and
  whether any setting changes.
