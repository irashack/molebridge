#!/usr/bin/env python3
"""Molebridge's automatic releases: candidates and promotion without a person.

The owner's decision (2026-11-19): Molebridge releases are fully automatic, the
candidate and its promotion to a release, without asking. The maintainer runs
this hourly, as the release bot, against a clean clone of main. It drives the
existing workflows and changes neither; docs/releasing.md says what each step
is, and this does those steps in order:

  candidate  main has entries under "## Unreleased" in CHANGELOG.md, or the
             open "Scheduled scan findings" issue lists an Alpine package with
             a fix for the current release's image: open a release-prep pull
             request (the changelog heading, the acceptance policy's version
             and upgrade drill), merge it on green CI, and tag vX.Y.Z-rc.1 on
             main once CI has passed on that commit. A minor release waits
             RELEASE_EVERY_DAYS after the last release and needs an entry
             that isn't "- Internal"; an Alpine rebuild doesn't wait
  hand-off   ask for live acceptance on issue #45 with both images' digests;
             the homelab runs the canary and posts "Live acceptance result:
             <rc>" with fenced JSON (result, digests, coverage, evidence)
  attest     dispatch acceptance.yml on main with that coverage and evidence,
             once the result is "passed" and its digests are the candidate's
  promote    tag vX.Y.Z on the candidate's commit (release.yml promotes both
             images), then the record pull request: docs/testing.md, the
             changelog's date, the Compose pins and examples; merge on green CI

It stops, with an issue titled "Release blocked: ...", on a Breaking item in
the changelog, a failed workflow or CI, a failed acceptance, or digests that
do not match. While such an issue, or an issue or pull request labeled
`hold-release`, is open it does nothing. A "needs-attended" result waits for a
later result on the same candidate.

Tags, branches and pull requests are made with the maintainer's token
(MOLEBRIDGE_RELEASE_TOKEN_COMMAND, else GH_TOKEN or gh's login), never a
workflow's GITHUB_TOKEN: a tag pushed with that does not start release.yml.
The token stays in this process's environment and is never printed or
written. Run it with --workdir, a clone of the repository it may reset.

Exit status: 0 when there is nothing to do, it is waiting, or it is held or
locked; 1 after a failure it filed an issue for (or could not).
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = "irashack/molebridge"
IMAGE = "ghcr.io/irashack/molebridge"
CORE_IMAGE = "ghcr.io/irashack/molebridge-core"
HANDOFF_ISSUE = 45
SCAN_TITLE = "Scheduled scan findings"
BLOCKED = "Release blocked: "
HOLD_LABEL = "hold-release"
# The owner (2026-11-20): roll several changes into a release instead of one
# release per merge. A minor release is prepared at most this many days after
# the last release, and only for a change people can see.
RELEASE_EVERY_DAYS = 7
# Who may post a live acceptance result: the homelab's GitHub identity
# (homelab-ops#3118 names it). Nobody else's comment counts.
RESULT_AUTHORS = ("irashack-homelab-broker", "irashack-homelab-broker[bot]")
ME_NAME = "irashack-products[bot]"
ME_EMAIL = "351314153+irashack-products[bot]@users.noreply.github.com"
# A command that prints a GitHub token for the repository, read once a run; without
# it the token in GH_TOKEN (or gh's own login) is used.
TOKEN_ENV = "MOLEBRIDGE_RELEASE_TOKEN_COMMAND"
# Seconds a token from that command is used before the next call mints another.
TOKEN_AGE = 120
STATE = Path.home() / ".local/state/molebridge-auto-release"
# internal/tools/initmenu/compose.tmpl holds the services `molebridge init`
# writes, pinned as the Compose files are (its tests fail when they differ).
PIN_FILES = ["compose.yaml", "compose.gluetun.yaml", "compose.sidecar.yaml",
             "compose.native-sidecar.yaml", "compose.proxy.yaml",
             "internal/tools/initmenu/compose.tmpl",
             "README.md", "docs/setup.md", ".github/ISSUE_TEMPLATE/bug.yml"]
# Inside one hourly run, how long to keep following workflows and CI.
FOLLOW_SECONDS = 50 * 60
ACCEPT_TYPE = "https://github.com/irashack/molebridge/attestations/live-acceptance/v1"

STABLE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
RC = re.compile(r"^v(\d+)\.(\d+)\.(\d+)-rc\.(\d+)$")
DIGEST = r"sha256:[0-9a-f]{64}"


class Blocked(Exception):
    """A stop that needs a person: the message becomes an issue."""

    def __init__(self, title: str, body: str):
        super().__init__(title)
        self.title, self.body = title, body


# Outcomes of one step.
DONE = "done"        # did something; look again at once
SHORT = "short"      # a workflow or CI is running; look again in a minute
LONG = "long"        # waiting on the homelab or a person; end this run
IDLE = "idle"        # nothing to do


# --- pure helpers (tools/test-auto-release.py) ---------------------------------

def version(tag: str):
    """(x, y, z, rc) for vX.Y.Z or vX.Y.Z-rc.N (rc None for a release)."""
    m = STABLE.match(tag)
    if m:
        return (int(m[1]), int(m[2]), int(m[3]), None)
    m = RC.match(tag)
    if m:
        return (int(m[1]), int(m[2]), int(m[3]), int(m[4]))
    return None


def vstr(v) -> str:
    return f"{v[0]}.{v[1]}.{v[2]}"


def unreleased(changelog: str) -> str:
    """The body of the "## Unreleased" section, or ''."""
    m = re.search(r"^## Unreleased[ \t]*\n(.*?)(?=^## |\Z)", changelog, re.M | re.S)
    return m.group(1) if m else ""


def has_entries(body: str) -> bool:
    return any(line.startswith("- ") for line in body.splitlines())


def has_breaking(body: str) -> bool:
    return re.search(r"\*\*Breaking", body) is not None


def user_visible(body: str) -> bool:
    """An entry that isn't marked internal ("- Internal, ..." or "- Internal:")."""
    return any(line.startswith("- ") and not line.startswith("- Internal")
               for line in body.splitlines())


def release_due(body: str, last_release: datetime, now: datetime):
    """Whether a minor release is due for these Unreleased entries, and why not."""
    if not user_visible(body):
        return False, "only internal changes since the last release"
    days = (now - last_release).total_seconds() / 86400
    if days < RELEASE_EVERY_DAYS:
        return False, (f"the last release was {days:.1f} days ago; the next minor "
                       f"waits until {RELEASE_EVERY_DAYS} days")
    return True, ""


def pending_heading(changelog: str):
    """The X.Y.Z of a "## X.Y.Z — unreleased" heading, or None."""
    m = re.search(r"^## (\d+\.\d+\.\d+) — unreleased[ \t]*$", changelog, re.M)
    return m.group(1) if m else None


def prep_changelog(changelog: str, new: str, prev: str, apk_fixes: list[str]) -> str:
    """Turn "## Unreleased" into "## <new> — unreleased", or add a rebuild entry."""
    body = unreleased(changelog)
    if has_entries(body):
        intro = (f"**Experimental.** Upgrade from {prev} by moving to the new image;\n"
                 "what changed is below.\n")
        return re.sub(r"^## Unreleased[ \t]*\n\n?", f"## {new} — unreleased\n\n{intro}\n",
                      changelog, count=1, flags=re.M)
    entry = (f"## {new} — unreleased\n\n"
             "**Experimental.** A security rebuild: no change to Molebridge's code or\n"
             f"behaviour. Upgrade from {prev} by moving to the new image; nothing else\n"
             "changes.\n\n**Security**:\n"
             "- The image takes Alpine's package updates when it is built: "
             + ", ".join(apk_fixes) + ".\n\n")
    m = re.search(r"^## ", changelog, re.M)
    if not m:
        return changelog.rstrip("\n") + "\n\n" + entry
    # An empty "## Unreleased" heading stays above the new entry.
    if changelog[m.start():].startswith("## Unreleased"):
        nxt = re.search(r"^## ", changelog[m.end():], re.M)
        at = m.end() + nxt.start() if nxt else len(changelog)
        return changelog[:at] + entry + changelog[at:]
    return changelog[:m.start()] + entry + changelog[m.start():]


def date_changelog(changelog: str, ver: str, day: str) -> str:
    return re.sub(rf"^## {re.escape(ver)} — unreleased[ \t]*$", f"## {ver} — {day}",
                  changelog, count=1, flags=re.M)


def bump_policy(policy: str, prev: str) -> str:
    def inc(m):
        return f'{m[1]}{int(m[2]) + 1}"'
    out = re.sub(r'("version":\s*")(\d+)"', inc, policy, count=1)
    return re.sub(r"upgrade-from-\d+\.\d+\.\d+", f"upgrade-from-{prev}", out)


def policy_ready(policy: str, prev: str) -> bool:
    """True when a change on main already raised the policy for this release:
    its upgrade drill is from <prev>, the release being upgraded from."""
    return f'"upgrade-from-{prev}"' in policy


def bump_policy_test(script: str, prev: str) -> str:
    def inc(m):
        return f'{m[1]}{int(m[2]) + 1}"'
    out = re.sub(r'(\.policy_version == ")(\d+)"', inc, script)
    return re.sub(r"upgrade-from-\d+\.\d+\.\d+", f"upgrade-from-{prev}", out)


def apk_fixes(scan_body: str, stable: str) -> list[str]:
    """Alpine packages with a fix that the scan of v<stable>'s image lists."""
    if not re.search(rf"^## The v{re.escape(stable)} image\b", scan_body, re.M):
        return []
    out = []
    for m in re.finditer(r"^\|[^|]*\|[^|]*\|\s*(\S+) (\S+) \(apk\)\s*\|\s*([^|]+?)\s*\|",
                         scan_body, re.M):
        if m[3] != "none yet":
            fix = f"{m[1]} {m[3]}"
            if fix not in out:
                out.append(fix)
    return out


def release_digests(body: str, tag: str) -> dict:
    """{"molebridge": digest, "molebridge-core": digest} from release notes."""
    out = {}
    for name, image in (("molebridge", IMAGE), ("molebridge-core", CORE_IMAGE)):
        m = re.search(rf"{re.escape(image)}:{re.escape(tag)}@({DIGEST})", body)
        if m:
            out[name] = m[1]
    return out


def parse_result(body: str, rc: str):
    """A live acceptance result comment for <rc>: its JSON plus "record", or None."""
    first = body.lstrip().splitlines()[0] if body.strip() else ""
    if first.strip().rstrip(".") != f"Live acceptance result: {rc}":
        return None
    m = re.search(r"^```json[ \t]*\n(.*?)^```", body, re.M | re.S)
    if not m:
        return None
    try:
        data = json.loads(m[1])
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("rc_tag") != rc:
        return None
    if data.get("result") not in ("passed", "failed", "needs-attended"):
        return None
    rec = re.search(r"^```markdown[ \t]*\n(.*?)^```", body, re.M | re.S)
    data["record"] = rec[1].rstrip() + "\n" if rec else ""
    return data


NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


def expand_drills(coverage):
    """In a passed result a drill may be named alone: it passed. Give it the
    {"id","result"} form acceptance.yml takes; anything else stays as it is."""
    if isinstance(coverage, dict) and isinstance(coverage.get("drills"), list):
        coverage = dict(coverage, drills=[{"id": d, "result": "passed"} if isinstance(d, str)
                                          else d for d in coverage["drills"]])
    return coverage


def coverage_problems(coverage, evidence) -> list[str]:
    """Why acceptance.yml would refuse this coverage and evidence (docs/releasing.md,
    step 4), or [] when it takes them."""
    out = []
    if not isinstance(coverage, dict):
        return ["`coverage` is not an object"]
    for key in ("platforms", "providers", "kinds"):
        v = coverage.get(key)
        if not isinstance(v, list) or not v or \
                not all(isinstance(x, str) and NAME.match(x) for x in v):
            out.append(f"`coverage.{key}` must be a non-empty array of names")
    drills = coverage.get("drills")
    if not isinstance(drills, list) or not drills:
        out.append("`coverage.drills` must be a non-empty array")
    else:
        bad = [d for d in drills if not (isinstance(d, dict) and isinstance(d.get("id"), str)
                                         and NAME.match(d["id"])
                                         and d.get("result") == "passed")]
        if bad:
            out.append("each drill must be an object like "
                       '`{"id":"tunnel-loss","result":"passed"}`, and these are not: '
                       + ", ".join(json.dumps(d) for d in bad[:5]))
    if not isinstance(evidence, list) or not 1 <= len(evidence) <= 50 or \
            not all(isinstance(e, str) and 1 <= len(e) <= 500 and e.isprintable() for e in evidence):
        out.append("`evidence` must be 1 to 50 printable strings of 1 to 500 characters")
    return out


def compose_pin(compose: str, image: str = IMAGE):
    m = re.search(rf"{re.escape(image)}:(v\d+\.\d+\.\d+)@({DIGEST})", compose)
    return (m[1], m[2]) if m else None


def rewrite_pins(text: str, old: str, old_digest: str, old_rc: str | None,
                 new: str, digest: str, rc: str,
                 core: tuple[str, str] | None = None) -> str:
    """Pins moved from old to new. core is (old core digest, new core digest)
    for the molebridge-core pins of the sidecar Compose files."""
    if core:
        text = text.replace(f"{CORE_IMAGE}:{old}@{core[0]}", f"{CORE_IMAGE}:{new}@{core[1]}")
        text = text.replace(core[0], core[1])
    text = text.replace(f"{IMAGE}:{old}@{old_digest}", f"{IMAGE}:{new}@{digest}")
    if old_rc:
        text = text.replace(old_rc, rc)
    text = re.sub(rf"{re.escape(old)}(?!\d|\.\d|-)", new, text)
    return text.replace(old_digest, digest)


def testing_record(stable: str, rc: str, day: str, commit: str, digests: dict,
                   policy_version: str, accept_run: str, result: dict) -> str:
    cov = result.get("coverage", {})
    lines = [f"## {stable}", "",
             f"Released from `{rc}` by the release automation. The acceptance policy "
             f"(`tools/acceptance-policy.json`, version {policy_version}) is the one the "
             "candidate was attested against.", "",
             f"### {rc}, {day}: released", "",
             f"The candidate `{IMAGE}:{rc}`, index digest `{digests['molebridge']}`, and "
             f"`{CORE_IMAGE}:{rc}`, index digest `{digests['molebridge-core']}` (commit "
             f"`{commit[:7]}`). Attested by [run {accept_run}]"
             f"(https://github.com/{REPO}/actions/runs/{accept_run}) and promoted as "
             f"`v{stable}`.", ""]
    if result.get("record"):
        lines += [result["record"].rstrip(), ""]
    else:
        lines += ["- **Platforms:** " + ", ".join(cov.get("platforms", [])),
                  "- **Providers:** " + ", ".join(cov.get("providers", [])),
                  "- **Kinds:** " + ", ".join(cov.get("kinds", [])),
                  "- **Drills:** " + ", ".join(f"{d['id']} ({d['result']})"
                                               for d in cov.get("drills", [])), ""]
    lines += ["Evidence:", ""] + [f"- {e}" for e in result.get("evidence", [])] + [""]
    return "\n".join(lines) + "\n"


def insert_record(testing: str, record: str) -> str:
    m = re.search(r"^## \d", testing, re.M)
    if not m:
        return testing.rstrip("\n") + "\n\n" + record
    return testing[:m.start()] + record + testing[m.start():]


# --- the world -------------------------------------------------------------------

class World:
    def __init__(self, workdir: Path, dry_run: bool):
        self.dir, self.dry = workdir, dry_run
        self.env = dict(os.environ)
        self.env.pop("GITHUB_TOKEN", None)
        self.minted = float("-inf")

    def login(self, force=False):
        """A token from the token command, minted again once it is TOKEN_AGE old:
        a minted token can be revoked long before its own expiry (an OpenBao
        lease ends with the login that created it)."""
        cmd = self.env.get(TOKEN_ENV)
        if cmd:
            if force or time.monotonic() - self.minted > TOKEN_AGE:
                out = subprocess.run(cmd.split(), capture_output=True, text=True, check=True)
                self.env["GH_TOKEN"] = out.stdout.strip()
                self.minted = time.monotonic()
        elif not self.env.get("GH_TOKEN"):
            self.env["GH_TOKEN"] = subprocess.run(["gh", "auth", "token"], capture_output=True,
                                                  text=True, check=True).stdout.strip()

    def run(self, *cmd, check=True, input=None) -> str:
        uses_token = cmd[0] == "gh" or "push" in cmd
        if uses_token:
            self.login()
        p = subprocess.run(cmd, cwd=self.dir, env=self.env, capture_output=True,
                           text=True, input=input)
        if p.returncode and uses_token and self.env.get(TOKEN_ENV) and \
                re.search(r"Bad credentials|HTTP 401|Authentication failed", p.stderr):
            # Revoked under us: mint once more and try again.
            self.login(force=True)
            p = subprocess.run(cmd, cwd=self.dir, env=self.env, capture_output=True,
                               text=True, input=input)
        if check and p.returncode:
            raise RuntimeError(f"{cmd[0]} {cmd[1] if len(cmd) > 1 else ''} failed: "
                               f"{p.stderr.strip()[-800:]}")
        return p.stdout

    def gh(self, *args, input=None):
        return self.run("gh", *args, input=input)

    def api(self, path, *args, input=None):
        out = self.gh("api", path, *args, input=input)
        return json.loads(out) if out.strip() else None

    def write(self, what: str) -> bool:
        """Say what a write would do; False in a dry run."""
        print(("would " if self.dry else "") + what)
        return not self.dry

    def git(self, *args, check=True):
        return self.run("git", "-c", f"user.name={ME_NAME}", "-c", f"user.email={ME_EMAIL}",
                        *args, check=check)

    def push(self, *args):
        # The token reaches git through the helper's environment, never argv.
        helper = '!f() { echo username=x-access-token; echo "password=$GH_TOKEN"; }; f'
        return self.run("git", "-c", "credential.helper=", "-c", f"credential.helper={helper}",
                        "push", *args)


def tags(w: World) -> list[str]:
    w.git("fetch", "-q", "--tags", "--force", "origin")
    return [t for t in w.git("tag", "-l", "v*").split() if version(t)]


def commit_of(w: World, ref: str) -> str:
    return w.git("rev-parse", f"{ref}^{{commit}}").strip()


def checks(w: World, sha: str) -> str:
    """'success', 'pending' or 'failure' for a commit's check runs."""
    runs = w.api(f"repos/{REPO}/commits/{sha}/check-runs?per_page=100")["check_runs"]
    if not runs:
        return "pending"
    if any(r["status"] != "completed" for r in runs):
        return "pending"
    bad = [r["name"] for r in runs if r["conclusion"] not in ("success", "skipped", "neutral")]
    return "failure: " + ", ".join(bad) if bad else "success"


def workflow_run(w: World, workflow: str, branch: str):
    runs = w.api(f"repos/{REPO}/actions/workflows/{workflow}/runs?branch={branch}&per_page=5")
    runs = runs["workflow_runs"]
    return runs[0] if runs else None


def open_issues(w: World, label: str | None = None) -> list[dict]:
    q = f"repos/{REPO}/issues?state=open&per_page=100" + (f"&labels={label}" if label else "")
    return w.api(q)


def file_issue(w: World, title: str, body: str):
    for i in open_issues(w):
        if i["title"] == title:
            return i["number"]
    if not w.write(f"open issue: {title}"):
        return None
    return w.api(f"repos/{REPO}/issues", "-X", "POST", "--input", "-",
                 input=json.dumps({"title": title, "body": body}))["number"]


def comment(w: World, number: int, body: str):
    if w.write(f"comment on #{number}: {body.splitlines()[0]}"):
        w.api(f"repos/{REPO}/issues/{number}/comments", "-X", "POST", "--input", "-",
              input=json.dumps({"body": body}))


def comments(w: World, number: int) -> list[dict]:
    out, page = [], 1
    while True:
        got = w.api(f"repos/{REPO}/issues/{number}/comments?per_page=100&page={page}")
        out += got
        if len(got) < 100:
            return out
        page += 1


def state(name: str):
    p = STATE / name
    return json.loads(p.read_text()) if p.exists() else None


def save(name: str, value):
    p = STATE / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(value))


# --- steps -----------------------------------------------------------------------

def open_pr(w: World, branch: str):
    prs = w.api(f"repos/{REPO}/pulls?state=open&head=irashack:{branch}")
    return prs[0] if prs else None


def merge_when_green(w: World, pr: dict, what: str) -> str:
    sha = pr["head"]["sha"]
    c = checks(w, sha)
    if c == "pending":
        print(f"{what}: PR #{pr['number']} CI running")
        return SHORT
    if c != "success":
        raise Blocked(f"{BLOCKED}{what} CI failed",
                      f"CI on PR #{pr['number']} ({sha[:7]}) did not pass: {c[9:]}. "
                      "Fix it, merge or close the PR, then close this issue.")
    if w.write(f"merge PR #{pr['number']} ({what})"):
        w.api(f"repos/{REPO}/pulls/{pr['number']}/merge", "-X", "PUT", "--input", "-",
              input=json.dumps({"merge_method": "squash", "sha": sha,
                                "commit_title": f"{pr['title']} (#{pr['number']})"}))
    return DONE


def make_pr(w: World, branch: str, title: str, body: str, files: dict) -> str:
    """Commit <files> (path -> text) on a branch from origin/main and open a PR."""
    w.git("checkout", "-q", "-B", branch, "origin/main")
    for path, text in files.items():
        (w.dir / path).write_text(text)
    w.git("add", *files)
    if not w.git("diff", "--cached", "--name-only").strip():
        raise Blocked(f"{BLOCKED}{title} changes nothing",
                      f"The automation's `{branch}` would change no file; check the "
                      "changelog and the pins by hand.")
    msg = f"{title}\n\n{body}\n\nAuto-release: {branch}\n"
    w.run("git", "-c", f"user.name={ME_NAME}", "-c", f"user.email={ME_EMAIL}",
          "commit", "-q", "-F", "-", input=msg)
    if not w.write(f"push {branch} and open PR: {title}"):
        w.git("checkout", "-q", "--detach", "origin/main")
        return IDLE
    w.push("--force", "origin", f"{branch}:refs/heads/{branch}")
    w.api(f"repos/{REPO}/pulls", "-X", "POST", "--input", "-",
          input=json.dumps({"title": title, "head": branch, "base": "main",
                            "body": body + "\n\nOpened by the release automation "
                            "(`tools/auto-release.py`, #45)."}))
    w.git("checkout", "-q", "--detach", "origin/main")
    return DONE


def create_tag(w: World, tag: str, sha: str):
    if w.write(f"create tag {tag} at {sha[:7]}"):
        w.api(f"repos/{REPO}/git/refs", "-X", "POST", "--input", "-",
              input=json.dumps({"ref": f"refs/tags/{tag}", "sha": sha}))


def step_candidate(w: World, rc: str, all_tags: list[str]) -> str:
    """A published candidate on its way to a release."""
    v = version(rc)
    sha = commit_of(w, rc)
    try:
        rel = w.api(f"repos/{REPO}/releases/tags/{rc}")
    except RuntimeError:
        rel = None
    if not rel:
        run = workflow_run(w, "release.yml", rc)
        if run and run["status"] != "completed":
            print(f"{rc}: release.yml running")
            return SHORT
        if run and run["conclusion"] != "success":
            raise Blocked(f"{BLOCKED}{rc} failed to publish",
                          f"release.yml on `{rc}` ended {run['conclusion']}: {run['html_url']}. "
                          "Fix main and let the automation tag the next candidate, then close "
                          "this issue.")
        print(f"{rc}: no release yet")
        return SHORT
    digests = release_digests(rel["body"] or "", rc)
    if len(digests) != 2:
        raise Blocked(f"{BLOCKED}{rc} release notes lack digests",
                      f"The pre-release notes of `{rc}` do not name both images' digests.")

    # The hand-off: ask once.
    notes = comments(w, HANDOFF_ISSUE)
    asked = f"Live acceptance requested: {rc}"
    if not any(c["body"].startswith(asked) for c in notes):
        comment(w, HANDOFF_ISSUE,
                f"{asked}\n\nCommit `{sha}`. Both images, from one candidate:\n\n"
                f"- `{IMAGE}:{rc}@{digests['molebridge']}`\n"
                f"- `{CORE_IMAGE}:{rc}@{digests['molebridge-core']}`\n\n"
                f"Pre-release: {rel['html_url']}. Reply with `Live acceptance result: {rc}` "
                "and fenced JSON (`rc_tag`, `result`, `digests`, `coverage`, `evidence`), "
                "and optionally a fenced `markdown` record for docs/testing.md.")
        return DONE

    results = [(c, parse_result(c["body"], rc)) for c in notes
               if c["user"]["login"] in RESULT_AUTHORS and c["created_at"] == c["updated_at"]]
    results = [(c, r) for c, r in results if r]
    if not results:
        print(f"{rc}: waiting for the live acceptance result")
        return LONG
    note, result = results[-1]
    if result["result"] == "needs-attended":
        print(f"{rc}: needs an attended run; waiting for a later result")
        return LONG
    if result["result"] == "failed":
        mark = f"failed-{rc}"
        if not state(mark):
            n = file_issue(w, f"{BLOCKED}{rc} failed live acceptance",
                           f"The live acceptance of `{rc}` failed: {note['html_url']}. "
                           "Either fix main and close this issue (the automation then tags "
                           "the next candidate from main), or, if the test host was at fault, "
                           "ask the homelab to run it again and close this issue.")
            if not w.dry:
                save(mark, {"issue": n})
            return LONG
        head = commit_of(w, "origin/main")
        if head == sha:
            print(f"{rc}: failed; waiting for a fix on main or a new result")
            return LONG
        c = checks(w, head)
        if c == "pending":
            return SHORT
        if c != "success":
            print(f"{rc}: failed; main's CI is not green yet ({c})")
            return LONG
        n = max(version(t)[3] for t in all_tags
                if version(t)[:3] == v[:3] and version(t)[3] is not None)
        nxt = f"v{vstr(v)}-rc.{n + 1}"
        create_tag(w, nxt, head)
        return DONE

    # Passed.
    got = result.get("digests") or {}
    if got.get("molebridge") != digests["molebridge"] or \
            got.get("molebridge-core") != digests["molebridge-core"]:
        raise Blocked(f"{BLOCKED}{rc} result digests do not match",
                      f"The result {note['html_url']} names digests {json.dumps(got)}, but "
                      f"`{rc}` is {json.dumps(digests)}. Nothing was attested.")
    result["coverage"] = expand_drills(result.get("coverage"))
    problems = coverage_problems(result.get("coverage"), result.get("evidence"))
    if problems:
        # acceptance.yml would refuse it: ask once for a corrected result.
        asked = f"Live acceptance result for {rc} not usable"
        if not any(c["body"].startswith(asked) for c in notes):
            comment(w, HANDOFF_ISSUE,
                    f"{asked} ({note['html_url']}): " + "; ".join(problems) + ". Nothing was "
                    "attested. Post a new `Live acceptance result` comment in the shape "
                    "docs/releasing.md gives; the newest one counts.")
        print(f"{rc}: result not usable ({'; '.join(problems)}); waiting for a corrected one")
        return LONG
    mark = f"accept-{rc}-{note['id']}"
    disp = state(mark)
    if not disp:
        if not w.write(f"dispatch acceptance.yml for {rc}"):
            return LONG
        since = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        w.gh("workflow", "run", "acceptance.yml", "-R", REPO, "--ref", "main",
             "-f", f"rc_tag={rc}", "-f", f"coverage={json.dumps(result['coverage'])}",
             "-f", f"evidence={json.dumps(result['evidence'])}")
        for _ in range(30):
            time.sleep(5)
            runs = w.api(f"repos/{REPO}/actions/workflows/acceptance.yml/runs"
                         f"?event=workflow_dispatch&created=%3E%3D{since}")["workflow_runs"]
            if runs:
                save(mark, {"run": runs[0]["id"]})
                return SHORT
        raise RuntimeError("acceptance.yml was dispatched but no run appeared")
    run = w.api(f"repos/{REPO}/actions/runs/{disp['run']}")
    if run["status"] != "completed":
        print(f"{rc}: acceptance.yml running")
        return SHORT
    if run["conclusion"] != "success":
        raise Blocked(f"{BLOCKED}{rc} attestation failed",
                      f"acceptance.yml for `{rc}` ended {run['conclusion']}: {run['html_url']}.")
    save(f"accepted-{vstr(v)}", {"rc": rc, "run": disp["run"], "comment": note["id"],
                                  "digests": digests, "commit": sha,
                                  "day": note["created_at"][:10]})
    create_tag(w, f"v{vstr(v)}", sha)
    return DONE


def step_record(w: World, stable: str) -> str:
    """After promotion: the record pull request, merged on green CI."""
    tag = f"v{stable}"
    branch = f"auto/record-{stable}"
    pr = open_pr(w, branch)
    if pr:
        return merge_when_green(w, pr, f"{tag} record")
    run = workflow_run(w, "release.yml", tag)
    if not run or run["status"] != "completed":
        print(f"{tag}: promotion running")
        return SHORT
    if run["conclusion"] != "success":
        raise Blocked(f"{BLOCKED}{tag} promotion failed",
                      f"release.yml on `{tag}` ended {run['conclusion']}: {run['html_url']}.")
    acc = state(f"accepted-{stable}")
    if not acc:
        raise Blocked(f"{BLOCKED}{tag} record needs a person",
                      f"`{tag}` was not promoted by the automation, so it has no acceptance "
                      "result to record. Write the record by hand (docs/releasing.md, step 6).")
    note = w.api(f"repos/{REPO}/issues/comments/{acc['comment']}")
    result = parse_result(note["body"], acc["rc"])
    result["coverage"] = expand_drills(result.get("coverage"))
    root = w.dir
    files = {}
    changelog = (root / "CHANGELOG.md").read_text()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    files["CHANGELOG.md"] = date_changelog(changelog, stable, today)
    policy = json.loads((root / "tools/acceptance-policy.json").read_text())
    files["docs/testing.md"] = insert_record(
        (root / "docs/testing.md").read_text(),
        testing_record(stable, acc["rc"], acc["day"], acc["commit"], acc["digests"],
                       policy["version"], str(acc["run"]), result))
    old = compose_pin((root / "compose.yaml").read_text())
    if old:
        old_rc = None
        setup = (root / "docs/setup.md").read_text()
        m = re.search(rf"{re.escape(old[0])}-rc\.\d+", setup)
        if m:
            old_rc = m[0]
        # The sidecar forms pin molebridge-core at the same tag.
        old_core = compose_pin((root / "compose.sidecar.yaml").read_text(), CORE_IMAGE)
        if old_core and old_core[0] != old[0]:
            raise Blocked(f"{BLOCKED}{tag} Compose pins disagree",
                          f"compose.yaml pins `{old[0]}` but compose.sidecar.yaml pins "
                          f"molebridge-core `{old_core[0]}`. Pin both to one release by hand.")
        core = (old_core[1], acc["digests"]["molebridge-core"]) if old_core else None
        for path in PIN_FILES:
            if (root / path).exists():
                files[path] = rewrite_pins((root / path).read_text(), old[0], old[1], old_rc,
                                           tag, acc["digests"]["molebridge"], acc["rc"], core)
    return make_pr(w, branch, f"{tag}: changelog dated, live acceptance recorded, Compose pins",
                   f"The record of `{tag}`, promoted from `{acc['rc']}` by the release "
                   f"automation: docs/testing.md, the changelog's date, and the Compose files "
                   f"and examples pinned to `{tag}` (docs/releasing.md, step 6).", files)


def record_done(w: World, stable: str) -> bool:
    changelog = (w.dir / "CHANGELOG.md").read_text()
    pin = compose_pin((w.dir / "compose.yaml").read_text())
    return pending_heading(changelog) != stable and (pin is None or pin[0] == f"v{stable}")


def step_prepare(w: World, stable: str) -> str:
    """Nothing in flight: a prep PR when there is something to release."""
    root = w.dir
    changelog = (root / "CHANGELOG.md").read_text()
    pending = pending_heading(changelog)
    if pending:
        # Prep merged: tag the first candidate once main's CI passed.
        head = commit_of(w, "origin/main")
        c = checks(w, head)
        if c == "pending":
            return SHORT
        if c != "success":
            raise Blocked(f"{BLOCKED}{pending} main CI failed",
                          f"CI on main ({head[:7]}) did not pass: {c[9:]}.")
        create_tag(w, f"v{pending}-rc.1", head)
        return DONE
    branch_prefix = "auto/prep-"
    prs = [p for p in w.api(f"repos/{REPO}/pulls?state=open&per_page=100")
           if p["head"]["ref"].startswith(branch_prefix)]
    if prs:
        return merge_when_green(w, prs[0], f"{prs[0]['head']['ref'][len(branch_prefix):]} prep")
    body = unreleased(changelog)
    x, y, z = (int(n) for n in stable.split("."))
    fixes = []
    due = False
    if has_entries(body):
        published = w.api(f"repos/{REPO}/releases/tags/v{stable}")["published_at"]
        last = datetime.fromisoformat(published.replace("Z", "+00:00"))
        due, why = release_due(body, last, datetime.now(timezone.utc))
        if not due:
            print(f"not yet: {why}")
    if due:
        if has_breaking(body):
            raise Blocked(f"{BLOCKED}Breaking changes need an attended release",
                          "CHANGELOG.md's Unreleased section has a **Breaking** item. The "
                          "upgrade drill needs config changes nobody can script ahead of time, "
                          "so a person prepares and tags this candidate (docs/releasing.md). "
                          "Close this issue once its candidate is tagged; the automation then "
                          "carries on from the live acceptance.")
        new = f"{x}.{y + 1}.0"
    else:
        scan = [i for i in open_issues(w) if i["title"] == SCAN_TITLE]
        fixes = apk_fixes(scan[0]["body"] or "", stable) if scan else []
        if not fixes:
            print("nothing to release")
            return IDLE
        new = f"{x}.{y}.{z + 1}"
    files = {"CHANGELOG.md": prep_changelog(changelog, new, stable, fixes)}
    policy = (root / "tools/acceptance-policy.json").read_text()
    if not policy_ready(policy, stable):
        files["tools/acceptance-policy.json"] = bump_policy(policy, stable)
        files["tools/test-make-acceptance-predicate.sh"] = bump_policy_test(
            (root / "tools/test-make-acceptance-predicate.sh").read_text(), stable)
    why = ("the changes under Unreleased in CHANGELOG.md" if not fixes else
           "Alpine fixes the weekly scan found for the current image: " + ", ".join(fixes))
    return make_pr(w, f"{branch_prefix}{new}", f"Release prep: {new}",
                   f"Prepares {new} for its first candidate, for {why}: the changelog "
                   f"heading, acceptance policy version +1 and the upgrade drill from "
                   f"{stable} (docs/releasing.md, step 1).", files)


def step(w: World) -> str:
    w.git("fetch", "-q", "origin", "main")
    w.git("checkout", "-q", "--detach", "origin/main")
    w.git("reset", "-q", "--hard", "origin/main")
    w.git("clean", "-qfdx")
    all_tags = tags(w)
    stables = sorted((version(t) for t in all_tags if version(t)[3] is None), reverse=True)
    if not stables:
        raise RuntimeError("no release tags")
    latest = stables[0]
    rcs = sorted((version(t) for t in all_tags
                  if version(t)[3] is not None and version(t)[:3] > latest[:3]), reverse=True)
    if rcs:
        rc = rcs[0]
        return step_candidate(w, f"v{vstr(rc)}-rc.{rc[3]}", all_tags)
    stable = vstr(latest)
    if not record_done(w, stable):
        return step_record(w, stable)
    return step_prepare(w, stable)


def held(w: World):
    for i in open_issues(w, HOLD_LABEL):
        return f"#{i['number']} is labeled {HOLD_LABEL}"
    for i in open_issues(w):
        if i["title"].startswith(BLOCKED):
            return f"#{i['number']} ({i['title']}) is open"
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dry-run", action="store_true", help="read only; print what it would do")
    ap.add_argument("--workdir", type=Path, default=Path.cwd(),
                    help="a clone of irashack/molebridge to work in (reset to origin/main)")
    args = ap.parse_args()
    # Lines reach a log file in the order they happened.
    sys.stdout.reconfigure(line_buffering=True)
    STATE.mkdir(parents=True, exist_ok=True)
    lock = open(STATE / "lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("another run holds the lock")
        return 0
    w = World(args.workdir, args.dry_run)
    deadline = time.monotonic() + FOLLOW_SECONDS
    try:
        w.login()
        while True:
            why = held(w)
            if why:
                print(f"held: {why}")
                return 0
            outcome = step(w)
            if not w.dry:
                save("failures", 0)
            if outcome in (LONG, IDLE) or w.dry or time.monotonic() > deadline:
                return 0
            if outcome == SHORT:
                time.sleep(60)
    except Blocked as b:
        n = file_issue(w, b.title, b.body + "\n\nFiled by the release automation "
                       "(`tools/auto-release.py`, #45). It does nothing until this is closed.")
        print(f"blocked: {b.title} (#{n})", file=sys.stderr)
        return 1
    except Exception as e:  # noqa: BLE001 - one place reports any failure
        # One failure may be the network; the second in a row files an issue.
        print(f"failed: {e}", file=sys.stderr)
        failures = (state("failures") or 0) + 1
        save("failures", failures)
        if failures >= 2:
            try:
                file_issue(w, f"{BLOCKED}the automation failed",
                           f"`tools/auto-release.py` failed {failures} runs in a row; the last: {e}")
            except Exception as again:  # noqa: BLE001 - no token, no issue
                print(f"could not file the issue: {again}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
