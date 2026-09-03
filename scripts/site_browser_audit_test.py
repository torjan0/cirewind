#!/usr/bin/env python3
"""Focused tests for the sample-site browser audit's server and policy helpers."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

from browser_audit import AuditError
from site_browser_audit import (
    EXPECTED_SECTIONS,
    LOOPBACK,
    SiteServer,
    allowed_external_urls,
    check_headings,
    content_type_for,
    resolve_site_path,
    severe_console_entries,
    site_chromium_arguments,
    validate_base_path,
)


class LaunchPolicyTest(unittest.TestCase):
    def test_site_policy_keeps_sandbox_and_denies_dns(self) -> None:
        arguments = site_chromium_arguments(Path("/synthetic/profile"))
        self.assertNotIn("--no-sandbox", arguments)
        self.assertNotIn("--disable-setuid-sandbox", arguments)
        rules = [item for item in arguments if item.startswith("--host-resolver-rules=")]
        self.assertEqual(rules, [f"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE {LOOPBACK}"])
        self.assertFalse(any("localhost" in item for item in arguments))
        self.assertIn("--proxy-server=direct://", arguments)
        self.assertIn("--headless", arguments)
        self.assertFalse(any(item.startswith("--headless=") for item in arguments))

    def test_base_path_is_bounded(self) -> None:
        self.assertEqual(validate_base_path("/cirewind/"), "/cirewind/")
        self.assertEqual(validate_base_path("/"), "/")
        for hostile in ("cirewind/", "/cirewind", "/../", "/a/../b/", "/a b/", ""):
            with self.assertRaises(AuditError):
                validate_base_path(hostile)

    def test_content_types_are_reviewed(self) -> None:
        self.assertEqual(content_type_for("SHA256SUMS"), "text/plain; charset=utf-8")
        self.assertEqual(content_type_for("cirewind-synthetic-case-v0.2.0.tar.gz"), "application/gzip")
        self.assertEqual(content_type_for("graph.svg"), "image/svg+xml")
        self.assertEqual(content_type_for("case.db"), "application/octet-stream")
        with self.assertRaises(AuditError):
            content_type_for("payload.exe")

    def test_external_allowlist_is_exactly_three_urls(self) -> None:
        self.assertEqual(
            allowed_external_urls("0.2.0"),
            {
                "https://github.com/torjan0/cirewind",
                "https://github.com/torjan0/cirewind/releases/tag/v0.2.0",
                "https://github.com/torjan0/cirewind-lab/tree/main/reproductions",
            },
        )

    def test_heading_hierarchy_is_enforced(self) -> None:
        good = [{"level": 1, "text": "Headline"}] + [{"level": 2, "text": text} for text in EXPECTED_SECTIONS]
        check_headings(good)
        for bad in (
            good[1:],
            good + [{"level": 1, "text": "Second h1"}],
            good[:1] + [{"level": 3, "text": "skip"}] + good[1:],
            good[:-1],
            good[:1] + list(reversed(good[1:])),
        ):
            with self.assertRaises(AuditError):
                check_headings(bad)

    def test_favicon_lookup_is_the_only_tolerated_console_error(self) -> None:
        console = [
            {"level": "SEVERE", "message": "http://127.0.0.1:1/favicon.ico - Failed to load resource: 404"},
            {"level": "WARNING", "message": "deprecation notice"},
            {"level": "SEVERE", "message": "Refused to load the image because it violates CSP"},
        ]
        self.assertEqual(len(severe_console_entries(console)), 1)


class SiteServerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="cirewind-site-server-test.")
        self.site = Path(self.directory.name)
        (self.site / "v0.2.0" / "sample-case").mkdir(parents=True)
        (self.site / "index.html").write_text("<html><body>root</body></html>", encoding="utf-8")
        (self.site / "v0.2.0" / "index.html").write_text("<html><body>landing</body></html>", encoding="utf-8")
        (self.site / "v0.2.0" / "graph.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'/>", encoding="utf-8")
        (self.site / "v0.2.0" / "sample-case" / "SHA256SUMS").write_text("x\n", encoding="utf-8")
        (self.site / ".secret").write_text("hidden", encoding="utf-8")
        self.server = SiteServer(self.site, "/cirewind/")

    def tearDown(self) -> None:
        self.server.close()
        self.directory.cleanup()

    def status(self, path: str) -> tuple[int, str]:
        try:
            with urlopen(self.server.origin + path, timeout=5) as response:
                return int(response.status), response.headers.get("Content-Type", "")
        except HTTPError as error:
            return int(error.code), ""

    def test_serves_only_below_the_base_path(self) -> None:
        self.assertEqual(self.status("/cirewind/"), (200, "text/html; charset=utf-8"))
        self.assertEqual(self.status("/cirewind/v0.2.0/"), (200, "text/html; charset=utf-8"))
        self.assertEqual(self.status("/cirewind/v0.2.0/graph.svg"), (200, "image/svg+xml"))
        self.assertEqual(self.status("/cirewind/v0.2.0/sample-case/SHA256SUMS"), (200, "text/plain; charset=utf-8"))
        self.assertEqual(self.status("/")[0], 404)
        self.assertEqual(self.status("/index.html")[0], 404)
        self.assertEqual(self.status("/other/")[0], 404)
        self.assertEqual(self.status("/cirewind/.secret")[0], 404)
        self.assertEqual(self.status("/cirewind/v0.2.0")[0], 404)
        self.assertEqual(self.status("/cirewind/missing.html")[0], 404)
        self.assertEqual(sorted(status for _, status in self.server.requests).count(200), 4)

    def test_path_resolution_rejects_traversal_and_links(self) -> None:
        self.assertIsNone(resolve_site_path(self.site, "/cirewind/", "/cirewind/../index.html"))
        self.assertIsNone(resolve_site_path(self.site, "/cirewind/", "/cirewind/v0.2.0/../../index.html"))
        self.assertIsNone(resolve_site_path(self.site, "/cirewind/", "/cirewind/v0.2.0/./graph.svg"))
        self.assertIsNone(resolve_site_path(self.site, "/cirewind/", "/cirewind/v0.2.0\\graph.svg"))
        link = self.site / "v0.2.0" / "linked.svg"
        try:
            link.symlink_to(self.site / "v0.2.0" / "graph.svg")
        except OSError:
            self.skipTest("symbolic links are unavailable")
        self.assertIsNone(resolve_site_path(self.site, "/cirewind/", "/cirewind/v0.2.0/linked.svg"))


if __name__ == "__main__":
    unittest.main()
