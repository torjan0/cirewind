#!/usr/bin/env python3
"""Focused launch-policy tests for the Chromium report audit."""

from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest import mock

from browser_audit import Driver, chromium_arguments, first_executable, remove_work_tree


class ChromiumLaunchPolicyTest(unittest.TestCase):
    def test_host_security_policy_keeps_browser_sandbox_enabled(self) -> None:
        profile = Path("/synthetic/browser-profile")
        arguments = chromium_arguments(profile)

        self.assertNotIn("--no-sandbox", arguments)
        self.assertNotIn("--disable-setuid-sandbox", arguments)
        self.assertIn("--host-resolver-rules=MAP * ~NOTFOUND", arguments)
        self.assertFalse(any("EXCLUDE localhost" in item for item in arguments))
        self.assertEqual(arguments.count(f"--user-data-dir={profile}"), 1)

    def test_workspace_cleanup_retries_a_lingering_browser_writer(self) -> None:
        workspace = Path("/synthetic/browser-workspace")
        with (
            mock.patch(
                "browser_audit.shutil.rmtree",
                side_effect=[OSError("directory not empty"), None],
            ) as remove,
            mock.patch("browser_audit.time.sleep") as sleep,
        ):
            remove_work_tree(workspace, attempts=2)
        self.assertEqual(remove.call_count, 2)
        sleep.assert_called_once_with(0.05)

    @unittest.skipUnless(
        os.environ.get("CIREWIND_BROWSER_INTEGRATION") == "1",
        "set CIREWIND_BROWSER_INTEGRATION=1 for the offline Chromium probe",
    )
    def test_host_security_policy_denies_loopback_requests(self) -> None:
        requested = threading.Event()
        received_paths: list[str] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                received_paths.append(self.path)
                requested.set()
                self.send_response(204)
                self.end_headers()

            def log_message(self, _format: str, *args: object) -> None:
                del args

        class IPv6Server(http.server.ThreadingHTTPServer):
            address_family = socket.AF_INET6

        servers: list[http.server.ThreadingHTTPServer] = [
            http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        ]
        try:
            servers.append(IPv6Server(("::1", 0), Handler))
        except OSError:
            # A host without an IPv6 loopback route has no IPv6 loopback egress
            # surface to exercise. IPv4 and localhost remain mandatory below.
            pass
        server_threads: list[threading.Thread] = []
        for server in servers:
            server.daemon_threads = True
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            server_threads.append(thread)
        driver = None
        try:
            chrome = first_executable(
                os.environ.get("CIREWIND_CHROME"),
                (
                    "/snap/chromium/current/usr/lib/chromium-browser/chrome",
                    "chromium",
                    "chromium-browser",
                    "google-chrome",
                ),
            )
            chromedriver = first_executable(
                os.environ.get("CIREWIND_CHROMEDRIVER"),
                (
                    "/snap/chromium/current/usr/lib/chromium-browser/chromedriver",
                    "chromedriver",
                ),
            )
            with tempfile.TemporaryDirectory(prefix="cirewind-browser-policy-test.") as directory:
                root = Path(directory)
                ipv4_port = int(servers[0].server_address[1])
                probe_urls = [
                    f"http://localhost:{ipv4_port}/localhost",
                    f"http://127.0.0.1:{ipv4_port}/ipv4",
                ]
                if len(servers) == 2:
                    ipv6_port = int(servers[1].server_address[1])
                    probe_urls.append(f"http://[::1]:{ipv6_port}/ipv6")
                probe = root / "hostile-report.html"
                probe.write_text(
                    "<html><body>"
                    + "".join(f'<img src="{url}">' for url in probe_urls)
                    + "</body></html>",
                    encoding="utf-8",
                )
                driver = Driver(
                    chromedriver,
                    chrome,
                    root / "profile",
                    root / "chromedriver.log",
                )
                driver.session_call("POST", "/log", {"type": "performance"})
                driver.session_call("POST", "/url", {"url": probe.as_uri()})
                self.assertFalse(
                    requested.wait(timeout=1.0),
                    "sandboxed offline browser contacted a loopback HTTP service",
                )
                entries = driver.session_call(
                    "POST", "/log", {"type": "performance"}
                )["value"]
                messages = [json.loads(item["message"])["message"] for item in entries]
                for probe_url in probe_urls:
                    request_ids = {
                        message["params"]["requestId"]
                        for message in messages
                        if message.get("method") == "Network.requestWillBeSent"
                        and message["params"]["request"]["url"] == probe_url
                    }
                    self.assertTrue(
                        request_ids,
                        f"loopback probe was not attempted: {probe_url}",
                    )
                    self.assertTrue(
                        any(
                            message.get("method") == "Network.loadingFailed"
                            and message["params"].get("requestId") in request_ids
                            and message["params"].get("errorText")
                            == "net::ERR_NAME_NOT_RESOLVED"
                            for message in messages
                        ),
                        f"loopback probe escaped the fixed resolver policy: {probe_url}",
                    )
                self.assertEqual(received_paths, [])
        finally:
            if driver is not None:
                driver.close()
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in server_threads:
                thread.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
