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
        self.assertFalse(ar.has_entries(ar.unreleased("## Unreleased\n\n## 0.1.0 — x\n- y\n")))

    def test_real_changelog_parses(self):
        text = (ROOT / "CHANGELOG.md").read_text()
        ar.unreleased(text)
        self.assertIsNone(ar.pending_heading(text.replace("## Unreleased", "## Nope")) and None)

    def test_prep_minor(self):
        out = ar.prep_changelog(self.TEXT, "0.12.0", "0.11.1", [])
        self.assertIn("## 0.12.0 — unreleased\n\n**Experimental.** Upgrade from 0.11.1", out)
        self.assertNotIn("## Unreleased", out)
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

    def test_rewrite_real_files(self):
        old, old_d = ar.compose_pin((ROOT / "compose.yaml").read_text())
        for path in ar.PIN_FILES:
            text = (ROOT / path).read_text()
            out = ar.rewrite_pins(text, old, old_d, f"{old}-rc.1", "v9.9.9", D1, "v9.9.9-rc.2")
            self.assertNotIn(old_d, out, path)
            self.assertNotRegex(out, rf"{old.replace('.', '[.]')}(?!\d|\.\d|-)", path)
            if f"ghcr.io/irashack/molebridge:{old}@{old_d}" in text:
                self.assertIn(f"ghcr.io/irashack/molebridge:v9.9.9@{D1}", out, path)
            # molebridge-core references and other versions are left alone.
            self.assertEqual(text.count("molebridge-core"), out.count("molebridge-core"), path)

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


if __name__ == "__main__":
    unittest.main()
