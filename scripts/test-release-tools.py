#!/usr/bin/env python3
"""Regression tests for release gates; execute on the remote test host or CI."""
import importlib.util
from pathlib import Path
import unittest


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load("check-test-results")
notes = load("prepare-release-notes")


class ReleaseToolsTest(unittest.TestCase):
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

    def test_changelog_requires_exact_unique_nonempty_section(self):
        self.assertEqual(notes.extract_notes("## [Unreleased]\n\n## [v1.0.0]\nNew\n## [0.5.0]\nOld\n", "v1.0.0"), "New\n")
        for text in ["## [1.0.0]\nWrong", "## [v1.0.0]\n\n## [0.5.0]\nOld",
                     "## [v1.0.0]\nOne\n## [v1.0.0]\nTwo"]:
            with self.subTest(text=text), self.assertRaises(ValueError):
                notes.extract_notes(text, "v1.0.0")


if __name__ == "__main__":
    unittest.main()
