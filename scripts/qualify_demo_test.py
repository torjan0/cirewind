#!/usr/bin/env python3
"""Linux-local regression tests for the native demo qualification harness."""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

import qualify_demo


@unittest.skipUnless(platform.system() == "Linux", "Linux-local harness test")
class QualificationHarnessTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cirewind-qualify-test-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def fake_binary(self, *, drift: bool = False, omit: str = "") -> Path:
        path = self.root / "fake-cirewind"
        script = textwrap.dedent(
            f"""\
            #!{sys.executable}
            import json
            import os
            from pathlib import Path
            import sys

            required = {qualify_demo.REQUIRED_CASE_FILES!r}
            if len(sys.argv) == 4 and sys.argv[1:3] == ["demo", "--out"]:
                case = Path(sys.argv[3])
                case.mkdir()
                payload = "stable\\n"
                if {drift!r}:
                    payload = Path.cwd().name + "\\n"
                for name in required:
                    if name != {omit!r}:
                        (case / name).write_text(payload, encoding="utf-8")
                observed = {{
                    "keys": sorted(os.environ),
                    "path": os.environ.get("PATH", ""),
                    "home": os.environ.get("HOME", ""),
                    "cache": os.environ.get("XDG_CACHE_HOME", ""),
                    "httpProxy": os.environ.get("HTTP_PROXY", ""),
                }}
                (Path.cwd() / "observed-environment.json").write_text(
                    json.dumps(observed, sort_keys=True), encoding="utf-8"
                )
                print("manifest: verified")
                raise SystemExit(0)
            if len(sys.argv) == 3 and sys.argv[1] == "verify":
                print("case manifest verified (cirewind.case/v1alpha2)")
                raise SystemExit(0)
            raise SystemExit(2)
            """
        )
        path.write_text(script, encoding="utf-8")
        path.chmod(0o700)
        return path

    def run_harness(self, binary: Path, work_root: Path) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        for name in qualify_demo.GITHUB_CREDENTIAL_VARIABLES:
            environment[name] = "synthetic-parent-credential-that-must-not-pass"
        return subprocess.run(
            [
                sys.executable,
                str(Path(qualify_demo.__file__).resolve()),
                "--binary",
                str(binary),
                "--work-root",
                str(work_root),
            ],
            cwd=self.root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
            check=False,
        )

    def test_five_clean_identical_trials_and_isolated_environment(self) -> None:
        work_root = self.root / "qualification"
        result = self.run_harness(self.fake_binary(), work_root)
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["trialCount"], 5)
        self.assertEqual(payload["status"], "PASS")
        self.assertTrue(payload["completeCasesByteIdentical"])
        self.assertEqual(
            payload,
            json.loads((work_root / "qualification-result.json").read_text()),
        )

        homes: set[str] = set()
        caches: set[str] = set()
        for trial_number in range(1, qualify_demo.TRIAL_COUNT + 1):
            trial = work_root / f"trial-{trial_number:02d}"
            observed = json.loads(
                (trial / "observed-environment.json").read_text(encoding="utf-8")
            )
            for credential in qualify_demo.GITHUB_CREDENTIAL_VARIABLES:
                self.assertNotIn(credential, observed["keys"])
            self.assertEqual(observed["path"], str(trial / "unusable-path"))
            self.assertFalse(Path(observed["path"]).exists())
            self.assertEqual(observed["httpProxy"], "http://127.0.0.1:1")
            homes.add(observed["home"])
            caches.add(observed["cache"])
        self.assertEqual(len(homes), qualify_demo.TRIAL_COUNT)
        self.assertEqual(len(caches), qualify_demo.TRIAL_COUNT)

    def test_refuses_existing_work_root_without_deleting_it(self) -> None:
        work_root = self.root / "existing"
        work_root.mkdir()
        sentinel = work_root / "preserve.txt"
        sentinel.write_text("preserve", encoding="utf-8")
        result = self.run_harness(self.fake_binary(), work_root)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("work root already exists", result.stderr)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")

    def test_rejects_nonidentical_complete_cases(self) -> None:
        result = self.run_harness(
            self.fake_binary(drift=True), self.root / "drifting-qualification"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("complete demo cases differ", result.stderr)

    def test_rejects_missing_required_case_file(self) -> None:
        result = self.run_harness(
            self.fake_binary(omit="graph.svg"), self.root / "missing-qualification"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing=graph.svg", result.stderr)

    def test_native_platform_gate_fails_closed(self) -> None:
        with self.assertRaisesRegex(qualify_demo.QualificationError, "not native macOS"):
            qualify_demo.require_native_platform(
                {"system": "Linux", "machine": "x86_64"}, 15, "arm64"
            )
        with self.assertRaisesRegex(qualify_demo.QualificationError, "want arm64"):
            qualify_demo.require_native_platform(
                {
                    "system": "Darwin",
                    "machine": "x86_64",
                    "macosVersion": "15.6.1",
                },
                15,
                "arm64",
            )

    def test_homebrew_gate_is_explicit_and_fails_closed(self) -> None:
        with mock.patch.object(qualify_demo.shutil, "which", return_value=None):
            with self.assertRaisesRegex(
                qualify_demo.QualificationError, "Homebrew is unavailable"
            ):
                qualify_demo.record_homebrew({}, self.root, True)
        with mock.patch.object(
            qualify_demo.shutil,
            "which",
            side_effect=AssertionError("optional check must not resolve Homebrew"),
        ):
            qualify_demo.record_homebrew({}, self.root, False)

    def test_source_commit_requires_a_full_lowercase_object_id(self) -> None:
        commit = "0123456789abcdef0123456789abcdef01234567"
        self.assertEqual(qualify_demo.source_commit(commit), commit)
        self.assertEqual(qualify_demo.source_commit(""), "")
        for invalid in ("0123456", commit.upper(), "g" * 40, commit + "\n"):
            with self.assertRaisesRegex(
                qualify_demo.QualificationError, "lowercase full Git object ID"
            ):
                qualify_demo.source_commit(invalid)


if __name__ == "__main__":
    unittest.main()
