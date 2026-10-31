#!/usr/bin/env python3
"""Regression tests for release gates; execute on the remote test host or CI."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load("check-test-results")
notes = load("prepare-release-notes")
candidate = load("candidate-prerelease")


class ReleaseToolsTest(unittest.TestCase):
    def test_candidate_policy_uses_pr_target_not_source_branch(self):
        branch = "feature/pqcauth-sdk-keyring"
        for event, ref, base, expected in [
            ("pull_request", "42/merge", branch, True),
            ("pull_request", branch, "main", False),
            ("pull_request", "42/merge", "main", False),
            ("pull_request", branch, "", False),
            ("push", branch, "", True),
            ("workflow_dispatch", branch, "", True),
            ("push", "main", branch, False),
            ("workflow_dispatch", "main", branch, False),
            ("release", branch, branch, False),
            ("pull_request_target", branch, branch, False),
            ("", "", "", False),
        ]:
            with self.subTest(event=event, ref=ref, base=base):
                self.assertEqual(candidate.allow_prerelease(event, ref, base), expected)

    def test_gate_accepts_required_pass(self):
        gate.check([{"Action": "pass", "Package": "app", "Test": "required"}], {"required"}, "app")

    def test_gate_rejects_omitted_skipped_failed_wrong_package_or_duplicate(self):
        passing = {"Action": "pass", "Package": "app", "Test": "required"}
        for events in [[], [{**passing, "Action": "skip"}], [{**passing, "Action": "fail"}],
                       [{**passing, "Package": "other"}], [passing, passing],
                       [passing, {"Action": "fail", "Package": "other"}]]:
            with self.subTest(events=events), self.assertRaises(ValueError):
                gate.check(events, {"required"}, "app")

    def test_tag_must_match_source_version(self):
        notes.validate_tag("v1.0.0", "v1.0.0")
        for tag in ["1.0.0", "v1.0.0-rc.1", "v1.0.1", "v1x0x0", "v1.0.0\n"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                notes.validate_tag(tag, "v1.0.0")

    def test_candidate_version_requires_explicit_opt_in(self):
        candidate = "v1.1.0-dev"
        with self.assertRaises(ValueError):
            notes.validate_tag(candidate, candidate)
        notes.validate_tag(candidate, candidate, allow_prerelease=True)
        with self.assertRaises(ValueError):
            notes.validate_tag(candidate, "v1.0.0", allow_prerelease=True)

    def test_binary_build_gate_rejects_unsafe_identity_before_building(self):
        script = Path(__file__).with_name("build-bridge-release.sh").resolve()
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "VERSION").write_text("v1.1.0-dev\n")
            for version, allow, commit, error in [
                ("v1.1.0-dev", "false", "a" * 40, "Release version must match"),
                ("v1.1.0", "true", "a" * 40, "Release version must match"),
                ("v1.1.0-dev", "true", "unknown", "Full source commit required"),
            ]:
                with self.subTest(version=version, allow=allow, commit=commit):
                    result = subprocess.run(
                        ["bash", str(script)], cwd=directory, text=True,
                        capture_output=True, timeout=10,
                        env={**os.environ, "VERSION": version,
                             "ALLOW_PRERELEASE": allow, "COMMIT_SHA": commit},
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(error, result.stderr)
                    self.assertFalse(Path(directory, "release").exists())

    def test_changelog_requires_exact_unique_nonempty_section(self):
        self.assertEqual(notes.extract_notes("## [Unreleased]\n\n## [v1.0.0]\nNew\n## [0.5.0]\nOld\n", "v1.0.0"), "New\n")
        for text in ["## [1.0.0]\nWrong", "## [v1.0.0]\n\n## [0.5.0]\nOld",
                     "## [v1.0.0]\nOne\n## [v1.0.0]\nTwo"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                notes.extract_notes(text, "v1.0.0")


if __name__ == "__main__":
    unittest.main()
