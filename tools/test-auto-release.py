#!/usr/bin/env python3
"""Tests for tools/auto-release.py's parsing and editing, against the real files."""

import importlib.util
import json
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("auto_release", ROOT / "tools/auto-release.py")
ar = importlib.util.module_from_spec(spec)
sys.modules["auto_release"] = ar
spec.loader.exec_module(ar)

D1 = "sha256:" + "a" * 64
D2 = "sha256:" + "b" * 64


def result_comment(rc, result="passed", digests=None, record=None, rc_in_json=None):
    data = {"rc_tag": rc_in_json or rc, "result": result,
            "digests": digests or {"molebridge": D1, "molebridge-core": D2},
            "coverage": {"platforms": ["kubernetes"], "providers": ["mullvad"],
                         "kinds": ["native"], "drills": [{"id": "tunnel-loss", "result": "passed"}]},
            "evidence": ["https://example.net/run/1"]}
    body = f"Live acceptance result: {rc}\n\n```json\n{json.dumps(data, indent=1)}\n```\n"
    if record:
        body += f"\n```markdown\n{record}\n```\n"
    return body


class Versions(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(ar.version("v0.11.1"), (0, 11, 1, None))
        self.assertEqual(ar.version("v0.12.0-rc.3"), (0, 12, 0, 3))
        self.assertIsNone(ar.version("v0.12"))
        self.assertIsNone(ar.version("0.12.0"))
        self.assertIsNone(ar.version("v0.12.0-beta.1"))


class Changelog(unittest.TestCase):
    TEXT = ("# Changelog\n\nIntro.\n\n## Unreleased\n\n- A thing.\n- Another.\n\n"
            "## 0.11.1 — 2026-11-19\n\nOld.\n")

    def test_unreleased(self):
        body = ar.unreleased(self.TEXT)
        self.assertTrue(ar.has_entries(body))
        self.assertFalse(ar.has_breaking(body))
        self.assertTrue(ar.has_breaking("**Breaking**:\n- x\n"))
        self.assertTrue(ar.has_breaking("- A fix.\n\n**Breaking**:\n- x\n"))
        self.assertTrue(ar.has_breaking("- **Breaking:** the x setting is gone.\n"))
        # The word in an entry's prose is not a Breaking item.
        self.assertFalse(ar.has_breaking("- It checks for a **Breaking** item again.\n"))
        self.assertFalse(ar.has_entries(ar.unreleased("## Unreleased\n\n## 0.1.0 — x\n- y\n")))

    def test_real_changelog_parses(self):
        text = (ROOT / "CHANGELOG.md").read_text()
        ar.unreleased(text)
        self.assertIsNone(ar.pending_heading(text.replace("## Unreleased", "## Nope")) and None)

    def test_prep_minor(self):
        out = ar.prep_changelog(self.TEXT, "0.12.0", "0.11.1", [])
        self.assertIn("## 0.12.0 — unreleased\n\n**Experimental.** Upgrade from 0.11.1", out)
        self.assertTrue(out.index("## Unreleased\n\n## 0.12.0") > 0)
        self.assertFalse(ar.has_entries(ar.unreleased(out)))
        self.assertIn("- A thing.", out)
        self.assertEqual(ar.pending_heading(out), "0.12.0")
        dated = ar.date_changelog(out, "0.12.0", "2026-11-20")
        self.assertIn("## 0.12.0 — 2026-11-20\n", dated)
        self.assertIsNone(ar.pending_heading(dated))

    def test_prep_rebuild(self):
        text = "# Changelog\n\nIntro.\n\n## 0.11.1 — 2026-11-19\n\nOld.\n"
        out = ar.prep_changelog(text, "0.11.2", "0.11.1", ["zlib 1.4-r0"])
        self.assertLess(out.index("## 0.11.2 — unreleased"), out.index("## 0.11.1"))
        self.assertIn("built: zlib 1.4-r0.", out)

    def test_prep_rebuild_keeps_empty_unreleased_on_top(self):
        text = "# C\n\n## Unreleased\n\n## 0.11.1 — 2026-11-19\n\nOld.\n"
        out = ar.prep_changelog(text, "0.11.2", "0.11.1", ["zlib 1.4-r0"])
        self.assertLess(out.index("## Unreleased"), out.index("## 0.11.2"))
        self.assertLess(out.index("## 0.11.2"), out.index("## 0.11.1"))


class Policy(unittest.TestCase):
    def test_bump_real_policy(self):
        text = (ROOT / "tools/acceptance-policy.json").read_text()
        old = json.loads(text)
        new = json.loads(ar.bump_policy(text, "0.11.1"))
        self.assertEqual(int(new["version"]), int(old["version"]) + 1)
        self.assertIn("upgrade-from-0.11.1", new["drills"])
        self.assertEqual(len(new["drills"]), len(old["drills"]))

    def test_ready_policy_is_left_alone(self):
        text = (ROOT / "tools/acceptance-policy.json").read_text()
        self.assertFalse(ar.policy_ready(text, "0.0.1"))
        self.assertTrue(ar.policy_ready(ar.bump_policy(text, "0.0.1"), "0.0.1"))

    def test_bump_real_test_script(self):
        text = (ROOT / "tools/test-make-acceptance-predicate.sh").read_text()
        policy = json.loads((ROOT / "tools/acceptance-policy.json").read_text())
        out = ar.bump_policy_test(text, "0.11.1")
        self.assertIn(f'.policy_version == "{int(policy["version"]) + 1}"', out)
        self.assertIn("upgrade-from-0.11.1", out)
        self.assertNotRegex(out, r"upgrade-from-(?!0\.11\.1)\d")


class Scan(unittest.TestCase):
    BODY = ("## The v0.11.1 image (grype, medium and above)\n\n"
            "| Vulnerability | Severity | Package | Fixed in |\n|---|---|---|---|\n"
            "| CVE-1 | Critical | zlib 1.3.2-r1 (apk) | 1.4-r0 |\n"
            "| GO-1 | High | golang.org/x/net v0.58.0 (go-module) | 0.60.0 |\n"
            "| CVE-2 | Medium | busybox 1.37.0-r31 (apk) | none yet |\n")

    def test_fixable_apk_only(self):
        self.assertEqual(ar.apk_fixes(self.BODY, "0.11.1"), ["zlib 1.4-r0"])

    def test_stale_scan_ignored(self):
        self.assertEqual(ar.apk_fixes(self.BODY, "0.11.2"), [])


class Results(unittest.TestCase):
    def test_passed_with_record(self):
        r = ar.parse_result(result_comment("v0.12.0-rc.1", record="- **Upgrade:** ok"),
                            "v0.12.0-rc.1")
        self.assertEqual(r["result"], "passed")
        self.assertEqual(r["digests"]["molebridge-core"], D2)
        self.assertEqual(r["record"], "- **Upgrade:** ok\n")

    def test_other_states(self):
        for state in ("failed", "needs-attended"):
            self.assertEqual(ar.parse_result(result_comment("v1.0.0-rc.1", state),
                                             "v1.0.0-rc.1")["result"], state)

    def test_refusals(self):
        rc = "v0.12.0-rc.1"
        self.assertIsNone(ar.parse_result(result_comment(rc), "v0.12.0-rc.2"))
        self.assertIsNone(ar.parse_result(result_comment(rc, rc_in_json="v0.12.0-rc.2"), rc))
        self.assertIsNone(ar.parse_result(result_comment(rc, "maybe"), rc))
        self.assertIsNone(ar.parse_result("Live acceptance result: " + rc + "\n\nno json", rc))
        self.assertIsNone(ar.parse_result("Nice!\n" + result_comment(rc), rc))
        self.assertIsNone(ar.parse_result("", rc))


class Coverage(unittest.TestCase):
    GOOD = {"platforms": ["kubernetes"], "providers": ["mullvad"], "kinds": ["native"],
            "drills": [{"id": "tunnel-loss", "result": "passed"}]}

    def test_good(self):
        self.assertEqual(ar.coverage_problems(self.GOOD, ["notes 1"]), [])

    def test_drills_as_names_refused(self):
        cov = dict(self.GOOD, drills=["tunnel-loss", "client-switch"])
        problems = ar.coverage_problems(cov, ["notes 1"])
        self.assertEqual(len(problems), 1)
        self.assertIn('"tunnel-loss"', problems[0])

    def test_names_in_a_passed_result_expand(self):
        cov = ar.expand_drills(dict(self.GOOD, drills=["tunnel-loss", {"id": "x", "result": "failed"}]))
        self.assertEqual(cov["drills"][0], {"id": "tunnel-loss", "result": "passed"})
        self.assertEqual(cov["drills"][1], {"id": "x", "result": "failed"})
        self.assertEqual(len(ar.coverage_problems(cov, ["n"])), 1)
        self.assertIsNone(ar.expand_drills(None))

    def test_failed_drill_and_bad_evidence(self):
        cov = dict(self.GOOD, drills=[{"id": "tunnel-loss", "result": "failed"}])
        self.assertEqual(len(ar.coverage_problems(cov, [])), 2)
        self.assertTrue(ar.coverage_problems(dict(self.GOOD, kinds=[]), ["x"]))
        self.assertTrue(ar.coverage_problems(None, ["x"]))


class Release(unittest.TestCase):
    def test_digests_from_notes(self):
        body = (f"Image index: `ghcr.io/irashack/molebridge:v0.12.0-rc.1@{D1}`\n"
                f"Core: `ghcr.io/irashack/molebridge-core:v0.12.0-rc.1@{D2}`\n")
        self.assertEqual(ar.release_digests(body, "v0.12.0-rc.1"),
                         {"molebridge": D1, "molebridge-core": D2})
        self.assertEqual(ar.release_digests(body, "v0.12.0-rc.2"), {})


class Pins(unittest.TestCase):
    def test_real_compose_pin(self):
        pin = ar.compose_pin((ROOT / "compose.yaml").read_text())
        self.assertIsNotNone(pin)
        self.assertRegex(pin[0], r"^v\d+\.\d+\.\d+$")

    def test_real_core_pin(self):
        # The sidecar forms pin molebridge-core at compose.yaml's tag.
        pin = ar.compose_pin((ROOT / "compose.yaml").read_text())
        core = ar.compose_pin((ROOT / "compose.sidecar.yaml").read_text(), ar.CORE_IMAGE)
        self.assertIsNotNone(core)
        self.assertEqual(core[0], pin[0])
        self.assertNotEqual(core[1], pin[1])

    def test_rewrite_real_files(self):
        old, old_d = ar.compose_pin((ROOT / "compose.yaml").read_text())
        _, old_core = ar.compose_pin((ROOT / "compose.sidecar.yaml").read_text(), ar.CORE_IMAGE)
        for path in ar.PIN_FILES:
            text = (ROOT / path).read_text()
            out = ar.rewrite_pins(text, old, old_d, f"{old}-rc.1", "v9.9.9", D1, "v9.9.9-rc.2",
                                  (old_core, D2))
            self.assertNotIn(old_d, out, path)
            self.assertNotIn(old_core, out, path)
            self.assertNotRegex(out, rf"{old.replace('.', '[.]')}(?!\d|\.\d|-)", path)
            if f"ghcr.io/irashack/molebridge:{old}@{old_d}" in text:
                self.assertIn(f"ghcr.io/irashack/molebridge:v9.9.9@{D1}", out, path)
            if f"ghcr.io/irashack/molebridge-core:{old}@{old_core}" in text:
                self.assertIn(f"ghcr.io/irashack/molebridge-core:v9.9.9@{D2}", out, path)
                self.assertNotIn(f"ghcr.io/irashack/molebridge-core:v9.9.9@{D1}", out, path)
            self.assertEqual(text.count("molebridge-core"), out.count("molebridge-core"), path)

    def test_proxy_overlay_is_pinned_and_rewritten(self):
        # compose.proxy.yaml runs molebridge-core, pinned exactly as the
        # sidecar forms pin it, and moves with them.
        path = "compose.proxy.yaml"
        self.assertIn(path, ar.PIN_FILES)
        core = ar.compose_pin((ROOT / "compose.sidecar.yaml").read_text(), ar.CORE_IMAGE)
        self.assertEqual(ar.compose_pin((ROOT / path).read_text(), ar.CORE_IMAGE), core)
        old, old_d = ar.compose_pin((ROOT / "compose.yaml").read_text())
        out = ar.rewrite_pins((ROOT / path).read_text(), old, old_d, f"{old}-rc.1", "v9.9.9", D1,
                              "v9.9.9-rc.2", (core[1], D2))
        self.assertIn(f"ghcr.io/irashack/molebridge-core:v9.9.9@{D2}", out)
        self.assertNotIn(core[1], out)

    def test_init_templates_are_pinned_and_rewritten(self):
        # molebridge init's service blocks carry both pins, and the release
        # rewrite moves them with the Compose files.
        path = "internal/tools/initmenu/compose.tmpl"
        self.assertIn(path, ar.PIN_FILES)
        old, old_d = ar.compose_pin((ROOT / "compose.yaml").read_text())
        _, old_core = ar.compose_pin((ROOT / "compose.sidecar.yaml").read_text(), ar.CORE_IMAGE)
        text = (ROOT / path).read_text()
        self.assertIn(f"{ar.IMAGE}:{old}@{old_d}", text)
        self.assertIn(f"{ar.CORE_IMAGE}:{old}@{old_core}", text)
        out = ar.rewrite_pins(text, old, old_d, None, "v9.9.9", D1, "v9.9.9-rc.1", (old_core, D2))
        self.assertIn(f"{ar.IMAGE}:v9.9.9@{D1}", out)
        self.assertIn(f"{ar.CORE_IMAGE}:v9.9.9@{D2}", out)
        self.assertNotIn(old_d, out)
        self.assertNotIn(old_core, out)

    def test_rewrite_core_takes_its_own_digest(self):
        d3, d4 = "sha256:" + "c" * 64, "sha256:" + "d" * 64
        text = (f"ghcr.io/irashack/molebridge:v0.12.0@{D1}\n"
                f"ghcr.io/irashack/molebridge-core:v0.12.0@{D2}\n")
        out = ar.rewrite_pins(text, "v0.12.0", D1, None, "v0.13.0", d3, "v0.13.0-rc.1", (D2, d4))
        self.assertEqual(out, f"ghcr.io/irashack/molebridge:v0.13.0@{d3}\n"
                              f"ghcr.io/irashack/molebridge-core:v0.13.0@{d4}\n")

    def test_rewrite_does_not_touch_longer_versions(self):
        out = ar.rewrite_pins("v0.11.1 v0.11.10 v0.11.1-rc.1 v0.11.1.", "v0.11.1", D2,
                              "v0.11.1-rc.1", "v0.12.0", D1, "v0.12.0-rc.1")
        self.assertEqual(out, "v0.12.0 v0.11.10 v0.12.0-rc.1 v0.12.0.")


class Token(unittest.TestCase):
    def test_minted_again_when_old(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            counter = Path(d) / "n"
            script = Path(d) / "mint"
            script.write_text(f"#!/bin/sh\necho x >> {counter}\nwc -l < {counter}\n")
            script.chmod(0o755)
            old = os.environ.get(ar.TOKEN_ENV)
            os.environ[ar.TOKEN_ENV] = str(script)
            try:
                w = ar.World(Path(d), dry_run=True)
                w.login()
                first = w.env["GH_TOKEN"]
                w.login()
                self.assertEqual(w.env["GH_TOKEN"], first)
                w.minted -= ar.TOKEN_AGE + 1
                w.login()
                self.assertNotEqual(w.env["GH_TOKEN"], first)
                w.login(force=True)
                self.assertEqual(w.env["GH_TOKEN"].strip(), "3")
            finally:
                if old is None:
                    del os.environ[ar.TOKEN_ENV]
                else:
                    os.environ[ar.TOKEN_ENV] = old


class Record(unittest.TestCase):
    def test_insert_into_real_testing(self):
        text = (ROOT / "docs/testing.md").read_text()
        result = ar.parse_result(result_comment("v9.9.9-rc.1"), "v9.9.9-rc.1")
        rec = ar.testing_record("9.9.9", "v9.9.9-rc.1", "2026-11-20", "0123456789abcdef",
                                {"molebridge": D1, "molebridge-core": D2}, "15", "42", result)
        out = ar.insert_record(text, rec)
        first = out.index("## 9.9.9")
        self.assertLess(first, out.index("\n## 0."))
        self.assertIn("- **Drills:** tunnel-loss (passed)", out)
        self.assertIn("- https://example.net/run/1", out)
        self.assertTrue(out.startswith(text[:first]))


def pr(ref, repo="irashack/molebridge", user=None, base="main"):
    return {"number": 1, "head": {"ref": ref, "repo": {"full_name": repo} if repo else None},
            "base": {"ref": base}, "user": {"login": user or ar.ME_NAME}}


class ReviewHardening(unittest.TestCase):
    """The review of 2026-11-26 (homelab-ops#4204): what the automation trusts."""

    def test_only_own_prep_prs(self):
        mine = pr("auto/prep-0.14.6")
        prs = [pr("auto/prep-0.14.6", repo="someone/molebridge", user="someone"),
               pr("auto/prep-0.14.6", user="someone"),
               pr("auto/prep-0.14.6", base="release"),
               pr("auto/prep-0.14.6", repo=None),
               pr("feature/x"),
               mine]
        self.assertEqual(ar.own_prs(prs, "auto/prep-"), [mine])

    def test_ci_job_names_of_real_ci(self):
        names = ar.ci_job_names((ROOT / ".github/workflows/ci.yml").read_text())
        self.assertIn("Release tooling", names)
        self.assertIn("System rig", names)
        self.assertGreaterEqual(len(names), 5)

    def test_ci_job_names_id_without_name(self):
        text = "on: push\njobs:\n  a:\n    runs-on: x\n  b:\n    name: Bee\n    runs-on: x\n"
        self.assertEqual(ar.ci_job_names(text), ["a", "Bee"])

    def test_check_state_needs_every_job(self):
        ok = lambda n: {"name": n, "status": "completed", "conclusion": "success"}
        req = ["Go", "System rig"]
        self.assertEqual(ar.check_state([], req), "pending")
        # Another app's check finished before CI created its jobs: not green.
        self.assertEqual(ar.check_state([ok("Analyze (go)")], req), "pending")
        self.assertEqual(ar.check_state([ok("Go"), ok("System rig"), ok("Dependabot")], req), "success")
        skipped = {"name": "System rig", "status": "completed", "conclusion": "skipped"}
        self.assertEqual(ar.check_state([ok("Go"), skipped], req), "failure: System rig did not run")
        failed = {"name": "Go", "status": "completed", "conclusion": "failure"}
        self.assertEqual(ar.check_state([failed, ok("System rig")], req), "failure: Go")
        running = {"name": "Go", "status": "in_progress", "conclusion": None}
        self.assertEqual(ar.check_state([running, ok("System rig")], req), "pending")

    def test_breaking_stop_before_a_candidate(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            w = ar.World(Path(d), dry_run=True)
            (Path(d) / "CHANGELOG.md").write_text(
                "# C\n\n## Unreleased\n\n**Breaking**:\n- x\n\n## 0.14.6 — unreleased\n\n- y\n")
            with self.assertRaises(ar.Blocked):
                ar.refuse_breaking(w)
            (Path(d) / "CHANGELOG.md").write_text(
                "# C\n\n## Unreleased\n\n## 0.14.6 — unreleased\n\n- y\n")
            ar.refuse_breaking(w)

    def test_dry_clone_leaves_the_checkout_alone(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "src"
            git = lambda *a, cwd=src: subprocess.run(["git", *a], cwd=cwd, check=True,
                                                      capture_output=True, text=True).stdout
            src.mkdir()
            git("init", "-q")
            git("remote", "add", "origin", "https://example.net/irashack/molebridge.git")
            (src / "f").write_text("committed\n")
            git("add", "f")
            git("-c", "user.name=t", "-c", "user.email=t@example.net", "commit", "-qm", "c")
            (src / "f").write_text("local change\n")
            (src / "untracked").write_text("keep me\n")
            clone = ar.dry_clone(src, Path(d) / "clone")
            self.assertEqual(git("remote", "get-url", "origin", cwd=clone).strip(),
                             "https://example.net/irashack/molebridge.git")
            git("checkout", "-q", "--detach", "HEAD", cwd=clone)
            git("clean", "-qfdx", cwd=clone)
            self.assertEqual((src / "f").read_text(), "local change\n")
            self.assertTrue((src / "untracked").exists())



class ReviewHardening2(unittest.TestCase):
    """The second pass of the 2026-11-26 review: which issues the automation trusts."""

    def test_apk_fixes_take_only_names_and_versions(self):
        body = ("## The v0.14.5 image\n\n| a | b | zlib 1.3-r0 (apk) | 1.3.1-r0 |\n"
                "| a | b | evil 1 (apk) | [x](https://example.net) **y** |\n"
                "| a | b | musl 1.2 (apk) | none yet |\n")
        self.assertEqual(ar.apk_fixes(body, "0.14.5"), ["zlib 1.3.1-r0"])

    def test_trusted_issues(self):
        bot = {"user": {"login": ar.ME_NAME}, "author_association": "NONE"}
        owner = {"user": {"login": "someone"}, "author_association": "OWNER"}
        stranger = {"user": {"login": "someone"}, "author_association": "NONE"}
        self.assertTrue(ar.trusted(bot))
        self.assertTrue(ar.trusted(owner))
        self.assertFalse(ar.trusted(stranger))
        self.assertIn("github-actions[bot]", ar.SCAN_AUTHORS)

    def test_own_acceptance_runs_by_run_name(self):
        runs = [{"id": 1, "display_title": "Acceptance v0.14.6-rc.1"},
                {"id": 2, "display_title": "Acceptance v0.14.6-rc.2"},
                {"id": 3, "display_title": "Acceptance"}]
        self.assertEqual([r["id"] for r in ar.own_acceptance_runs(runs, "v0.14.6-rc.1")], [1])
        self.assertEqual(ar.own_acceptance_runs(runs, "v0.14.7-rc.1"), [])
        accept = (ROOT / ".github/workflows/acceptance.yml").read_text()
        self.assertIn("run-name: Acceptance ${{ inputs.rc_tag }}", accept)


if __name__ == "__main__":
    unittest.main()
