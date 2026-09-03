#!/usr/bin/env python3
"""Audit the generated sample site in Chromium behind a loopback server.

The site is served under a GitHub project Pages style base path so that every
relative link is exercised the way the public deployment would resolve it. The
browser keeps the report audit's host-security policy (sandbox on, DNS denied)
with exactly one exception: the literal loopback address of the audit server.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import threading
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from browser_audit import (
    AuditError,
    Driver,
    chromium_arguments,
    first_executable,
    page_request_urls,
    parse_csp,
    remove_work_tree,
    sha256_source,
)

PROJECT_URL = "https://github.com/torjan0/cirewind"
LAB_INDEX_URL = "https://github.com/torjan0/cirewind-lab/tree/main/reproductions"
LOOPBACK = "127.0.0.1"
EXPECTED_SECTIONS = (
    "Temporal evidence path",
    "Result counts",
    "Sample case",
    "Two-minute local run",
    "What the A-to-B-to-A case demonstrates",
    "Mandatory distinctions",
    "Installation lanes",
    "Experimental qualification and limitations",
    "Privacy and provenance",
)
EXPECTED_CSP = {
    "default-src": ["'none'"],
    "img-src": ["'self'"],
    "script-src": ["'none'"],
    "connect-src": ["'none'"],
    "font-src": ["'none'"],
    "media-src": ["'none'"],
    "object-src": ["'none'"],
    "frame-src": ["'none'"],
    "worker-src": ["'none'"],
    "manifest-src": ["'none'"],
    "base-uri": ["'none'"],
    "form-action": ["'none'"],
}
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".svg": "image/svg+xml",
    ".json": "application/json",
    ".jsonl": "application/jsonl",
    ".md": "text/markdown; charset=utf-8",
    ".csv": "text/csv; charset=utf-8",
    ".sha256": "text/plain; charset=utf-8",
    ".db": "application/octet-stream",
}
VIEWPORTS = ((1440, 900), (1024, 768), (768, 768), (390, 844), (320, 720))
FIRST_VIEWPORT = (1440, 900)
VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$")
BASE_PATH_PATTERN = re.compile(r"^/([A-Za-z0-9._-]+/)*$")


def release_url(version: str) -> str:
    return f"{PROJECT_URL}/releases/tag/v{version}"


def allowed_external_urls(version: str) -> set[str]:
    return {PROJECT_URL, release_url(version), LAB_INDEX_URL}


def content_type_for(name: str) -> str:
    if name == "SHA256SUMS":
        return "text/plain; charset=utf-8"
    if name.endswith(".tar.gz"):
        return "application/gzip"
    suffix = Path(name).suffix.lower()
    if suffix not in CONTENT_TYPES:
        raise AuditError(f"no reviewed content type for {name}")
    return CONTENT_TYPES[suffix]


def site_chromium_arguments(profile: Path) -> list[str]:
    """Report launch policy with one literal loopback exception; DNS stays denied."""
    arguments = []
    replaced = False
    for argument in chromium_arguments(profile):
        if argument.startswith("--host-resolver-rules="):
            argument = f"--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE {LOOPBACK}"
            replaced = True
        arguments.append(argument)
    if not replaced:
        raise AuditError("report launch policy no longer carries a host-resolver rule")
    if {"--no-sandbox", "--disable-setuid-sandbox"}.intersection(arguments):
        raise AuditError("site browser audit cannot disable Chromium sandboxing")
    return arguments


def validate_base_path(base_path: str) -> str:
    if not BASE_PATH_PATTERN.match(base_path) or ".." in base_path.split("/"):
        raise AuditError(f"base path must look like /project/: {base_path}")
    return base_path


def resolve_site_path(site: Path, base_path: str, request_path: str) -> Path | None:
    """Map a request path below the base path to a regular file, or None."""
    if not request_path.startswith(base_path):
        return None
    remainder = request_path[len(base_path):]
    if "\\" in remainder or "\x00" in remainder:
        return None
    segments = remainder.split("/") if remainder else []
    target = site
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if segment == "" and last:
            break
        if segment in ("", ".", "..") or segment.startswith("."):
            return None
        target = target / segment
    if target.is_dir():
        if not request_path.endswith("/"):
            return None
        target = target / "index.html"
    if target.is_symlink() or not target.is_file():
        return None
    try:
        target.resolve().relative_to(site.resolve())
    except ValueError:
        return None
    return target


class SiteServer:
    """Loopback static server for one site tree below a fixed base path."""

    def __init__(self, site: Path, base_path: str):
        self.site = site.resolve()
        self.base_path = validate_base_path(base_path)
        self.requests: list[tuple[str, int]] = []
        self._lock = threading.Lock()
        self.server = http.server.ThreadingHTTPServer((LOOPBACK, 0), self._handler())
        self.server.daemon_threads = True
        self.port = int(self.server.server_address[1])
        self.origin = f"http://{LOOPBACK}:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def _record(self, path: str, status: int) -> None:
        with self._lock:
            self.requests.append((path, status))

    def _handler(self) -> type[http.server.BaseHTTPRequestHandler]:
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                self._serve(True)

            def do_HEAD(self) -> None:
                self._serve(False)

            def _serve(self, body: bool) -> None:
                path = urlsplit(self.path).path
                target = resolve_site_path(server.site, server.base_path, path)
                if target is None:
                    server._record(path, 404)
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    return
                data = target.read_bytes()
                server._record(path, 200)
                self.send_response(200)
                self.send_header("Content-Type", content_type_for(target.name))
                self.send_header("Content-Length", str(len(data)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                if body:
                    self.wfile.write(data)

            def log_message(self, _format: str, *args: object) -> None:
                del args

        return Handler

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def fetch_status(url: str) -> tuple[int, str]:
    request = Request(url, method="GET")
    try:
        with urlopen(request, timeout=10) as response:
            return int(response.status), response.headers.get("Content-Type", "")
    except HTTPError as error:
        return int(error.code), ""
    except URLError as error:
        raise AuditError(f"loopback fetch failed for {url}: {error}") from error


def execute(driver: Driver, script: str, *args: object) -> object:
    return driver.session_call("POST", "/execute/sync", {"script": script, "args": list(args)})["value"]


def execute_async(driver: Driver, script: str) -> object:
    return driver.session_call("POST", "/execute/async", {"script": script, "args": []})["value"]


def cdp(driver: Driver, command: str, params: dict | None = None) -> dict:
    return driver.session_call("POST", "/goog/cdp/execute", {"cmd": command, "params": params or {}})


def set_viewport(driver: Driver, width: int, height: int) -> None:
    """Emulate an exact CSS viewport; headless windows cannot shrink to 320px."""
    cdp(
        driver,
        "Emulation.setDeviceMetricsOverride",
        {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": False},
    )
    actual = execute(driver, "return {width: window.innerWidth, height: window.innerHeight}")
    if actual["width"] != width or actual["height"] < height:
        raise AuditError(f"viewport emulation produced {actual}, not {width}x{height}")


def clear_viewport(driver: Driver) -> None:
    cdp(driver, "Emulation.clearDeviceMetricsOverride")


def navigate(driver: Driver, url: str) -> None:
    driver.session_call("POST", "/url", {"url": url})
    ready = execute(driver, "return document.readyState")
    if ready != "complete":
        raise AuditError(f"{url} did not reach the complete ready state")


LANDING_STATE_SCRIPT = r"""
const meta = name => document.querySelector(`meta[name="${name}"]`)?.content ?? null;
const main = document.querySelector('main');
const img = main ? main.querySelector('img') : null;
const label = document.querySelector('p.label');
const table = document.querySelector('table');
const command = [...document.querySelectorAll('pre code')].find(item => item.textContent.includes('cirewind demo')) ?? null;
const reportLink = [...document.querySelectorAll('a')].find(item => item.getAttribute('href') === './sample-case/report.html') ?? null;
const experimental = [...document.querySelectorAll('main p, main li, main h1, main h2')].find(item => item.textContent.includes('experimental')) ?? null;
const top = element => element ? element.getBoundingClientRect().top : null;
const bottom = element => element ? element.getBoundingClientRect().bottom : null;
const bodyStyle = getComputedStyle(document.body);
const mainStyle = main ? getComputedStyle(main) : null;
return {
  ready: document.readyState,
  title: document.title,
  csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content ?? null,
  referrer: meta('referrer'),
  colorScheme: meta('color-scheme'),
  viewportMeta: meta('viewport'),
  scripts: document.scripts.length,
  styles: [...document.querySelectorAll('style')].map(item => item.textContent),
  linkElements: document.querySelectorAll('link').length,
  forms: document.forms.length,
  embedded: document.querySelectorAll('iframe,object,embed,video,audio,canvas,frame,applet').length,
  images: [...document.images].map(item => ({src: item.currentSrc || item.src, alt: item.alt, complete: item.complete, naturalWidth: item.naturalWidth, naturalHeight: item.naturalHeight, width: item.getAttribute('width'), height: item.getAttribute('height')})),
  links: [...document.querySelectorAll('a[href]')].map(item => ({href: item.href, raw: item.getAttribute('href'), rel: item.rel, target: item.getAttribute('target'), text: item.textContent.trim()})),
  headings: [...document.querySelectorAll('h1,h2,h3,h4,h5,h6')].map(item => ({level: Number(item.tagName.slice(1)), text: item.textContent.trim()})),
  bodyBackground: bodyStyle.backgroundColor,
  bodyColor: bodyStyle.color,
  mainMaxWidth: mainStyle ? mainStyle.maxWidth : null,
  tableHeaders: table ? table.querySelectorAll('th').length : 0,
  tableCaption: table?.caption?.textContent ?? null,
  storage: {local: localStorage.length, session: sessionStorage.length, cookie: document.cookie},
  firstViewport: {
    innerHeight: window.innerHeight,
    headline: bottom(document.querySelector('h1')),
    visual: top(img),
    label: bottom(label),
    counts: top(table),
    report: bottom(reportLink),
    command: bottom(command),
    experimental: bottom(experimental)
  },
  labelText: label?.textContent ?? null,
  innerWidth: window.innerWidth,
  clientWidth: document.documentElement.clientWidth,
  scrollWidth: document.documentElement.scrollWidth
};
"""

OVERFLOW_SCRIPT = "return {innerWidth: window.innerWidth, clientWidth: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth, bodyScrollWidth: document.body.scrollWidth}"

CONTRAST_SCRIPT = r"""
const label = document.querySelector('p.label');
const heading = document.querySelector('h1');
const link = document.querySelector('main a');
const bodyStyle = getComputedStyle(document.body);
return {
  background: bodyStyle.backgroundColor,
  labelColor: label ? getComputedStyle(label).color : null,
  labelBorder: label ? getComputedStyle(label).borderTopWidth : null,
  headingColor: heading ? getComputedStyle(heading).color : null,
  linkColor: link ? getComputedStyle(link).color : null,
  linkDecoration: link ? getComputedStyle(link).textDecorationLine : null
};
"""

FOCUS_SCRIPT = r"""
const link = document.querySelector('main a');
link.focus();
const style = getComputedStyle(link);
return {focused: document.activeElement === link, outlineWidth: Number.parseFloat(style.outlineWidth) || 0, outlineStyle: style.outlineStyle};
"""

SERVICE_WORKER_SCRIPT = r"""
const done = arguments[arguments.length - 1];
if (!navigator.serviceWorker) { done(0); return; }
navigator.serviceWorker.getRegistrations().then(items => done(items.length), () => done(0));
"""


def check_requests(performance: list[dict], page_url: str, server: SiteServer) -> dict[str, int]:
    urls = page_request_urls(performance, page_url)
    favicon = f"{server.origin}/favicon.ico"
    counted = 0
    for url in urls:
        if url == favicon:
            continue
        parts = urlsplit(url)
        if parts.scheme != "http" or f"{parts.scheme}://{parts.netloc}" != server.origin:
            raise AuditError(f"page initiated a request outside the loopback audit server: {url}")
        if not parts.path.startswith(server.base_path):
            raise AuditError(f"page requested a path outside the Pages base path: {url}")
        counted += 1
    return {"pageRequests": counted}


def severe_console_entries(console: list[dict]) -> list[str]:
    entries = []
    for item in console:
        if item.get("level") != "SEVERE":
            continue
        message = str(item.get("message", ""))
        if "favicon.ico" in message:
            continue
        entries.append("".join(character for character in message if character.isprintable())[:512])
    return entries


def check_headings(headings: list[dict]) -> None:
    if not headings or headings[0]["level"] != 1:
        raise AuditError("landing page does not begin with its h1")
    if sum(1 for item in headings if item["level"] == 1) != 1:
        raise AuditError("landing page must carry exactly one h1")
    previous = 1
    for item in headings[1:]:
        if item["level"] > previous + 1:
            raise AuditError(f"heading level skips from h{previous} to h{item['level']}")
        previous = item["level"]
    sections = tuple(item["text"] for item in headings if item["level"] == 2)
    if sections != EXPECTED_SECTIONS:
        raise AuditError(f"section order {sections} differs from the reviewed hierarchy")


def check_links(links: list[dict], landing_url: str, version: str) -> dict[str, int]:
    allowed = allowed_external_urls(version)
    relative = 0
    external = 0
    seen_external: set[str] = set()
    for link in links:
        if link["target"] is not None:
            raise AuditError(f"link {link['raw']!r} sets a target")
        if not link["text"]:
            raise AuditError(f"link {link['raw']!r} has no visible name")
        parts = urlsplit(link["href"])
        if parts.scheme == "https":
            if link["href"] not in allowed:
                raise AuditError(f"landing page links to a non-allowlisted URL: {link['href']}")
            if "noreferrer" not in link["rel"].split():
                raise AuditError(f"external link {link['href']} lacks rel=noreferrer")
            seen_external.add(link["href"])
            external += 1
            continue
        if parts.scheme != "http" or not link["href"].startswith(landing_url):
            raise AuditError(f"link {link['raw']!r} resolved outside the versioned tree: {link['href']}")
        if not link["raw"].startswith("./"):
            raise AuditError(f"sample-content link {link['raw']!r} is not a fixed relative path")
        status, content_type = fetch_status(link["href"])
        if status != 200:
            raise AuditError(f"relative link {link['raw']!r} returned HTTP {status} under the base path")
        if link["raw"].endswith(".html") or link["raw"].endswith("/"):
            if not content_type.startswith("text/html"):
                raise AuditError(f"relative link {link['raw']!r} is not served as HTML")
        relative += 1
    if seen_external != allowed:
        raise AuditError(f"external links {sorted(seen_external)} differ from the reviewed set")
    return {"relativeLinks": relative, "externalLinks": external}


def check_csp(csp: str | None, styles: list[str]) -> None:
    if not csp:
        raise AuditError("landing page carries no meta content security policy")
    if len(styles) != 1:
        raise AuditError("landing page must contain exactly one inline stylesheet")
    directives = parse_csp(csp)
    expected = dict(EXPECTED_CSP)
    expected["style-src"] = [sha256_source(styles[0])]
    if directives != expected:
        raise AuditError(f"landing CSP {directives} differs from the reviewed policy")


def check_first_viewport(state: dict) -> None:
    viewport = state["firstViewport"]
    height = viewport["innerHeight"]
    for name in ("headline", "visual", "label", "counts", "report", "command", "experimental"):
        position = viewport[name]
        if position is None:
            raise AuditError(f"first-viewport element {name} is missing")
        if position > height:
            raise AuditError(f"first-viewport element {name} sits at {position:.0f}px, below the {height}px fold")


def responsive_checks(driver: Driver) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for width, height in VIEWPORTS:
        set_viewport(driver, width, height)
        metrics = execute(driver, OVERFLOW_SCRIPT)
        if metrics["scrollWidth"] > metrics["clientWidth"] or metrics["bodyScrollWidth"] > metrics["clientWidth"]:
            raise AuditError(f"landing page overflows horizontally at {width}px: {metrics}")
        results.append({"width": width, "height": height, **metrics})
    for width in (1280, 640):
        set_viewport(driver, width, 900)
        execute(driver, "document.body.style.zoom = '2'")
        metrics = execute(driver, OVERFLOW_SCRIPT)
        execute(driver, "document.body.style.zoom = ''")
        if metrics["scrollWidth"] > metrics["clientWidth"] or metrics["bodyScrollWidth"] > metrics["clientWidth"]:
            raise AuditError(f"landing page overflows horizontally at 200% zoom in a {width}px viewport: {metrics}")
        results.append({"width": width, "zoom": 2, **metrics})
    set_viewport(driver, *FIRST_VIEWPORT)
    return results


def forced_color_checks(driver: Driver) -> list[dict[str, object]]:
    results = []
    for features in (
        [{"name": "prefers-color-scheme", "value": "dark"}],
        [{"name": "forced-colors", "value": "active"}, {"name": "prefers-color-scheme", "value": "dark"}],
        [{"name": "forced-colors", "value": "active"}, {"name": "prefers-color-scheme", "value": "light"}],
    ):
        cdp(driver, "Emulation.setEmulatedMedia", {"features": features})
        state = execute(driver, CONTRAST_SCRIPT)
        for name in ("labelColor", "headingColor", "linkColor"):
            if state[name] is None or state[name] == state["background"]:
                raise AuditError(f"{name} disappears into the background under {features}")
        results.append({"features": features, **state})
    cdp(driver, "Emulation.setEmulatedMedia", {"features": []})
    return results


def images_blocked_check(driver: Driver, landing_url: str) -> dict[str, object]:
    cdp(driver, "Network.enable")
    cdp(driver, "Network.setBlockedURLs", {"urls": ["*graph.svg"]})
    try:
        navigate(driver, landing_url)
        state = execute(
            driver,
            "const img = document.querySelector('main img'); const table = document.querySelector('table');"
            "return {naturalWidth: img ? img.naturalWidth : null, alt: img ? img.alt : null, caption: table?.caption?.textContent ?? null, rows: table ? table.querySelectorAll('th[scope=\"row\"]').length : 0}",
        )
    finally:
        cdp(driver, "Network.setBlockedURLs", {"urls": []})
        cdp(driver, "Network.disable")
        clear_viewport(driver)
    if state["naturalWidth"] != 0:
        raise AuditError("image blocking did not take effect; the text-equivalent check is inconclusive")
    if not state["alt"] or len(state["alt"]) < 40:
        raise AuditError("visual lacks meaningful alt text when images are unavailable")
    if not state["caption"] or state["rows"] < 10:
        raise AuditError("text-equivalent count table is unavailable when images are blocked")
    return state


def audit_root(driver: Driver, server: SiteServer, version: str) -> dict[str, object]:
    root_url = f"{server.origin}{server.base_path}"
    driver.session_call("POST", "/log", {"type": "performance"})
    driver.session_call("POST", "/log", {"type": "browser"})
    navigate(driver, root_url)
    state = execute(
        driver,
        "return {scripts: document.scripts.length, forms: document.forms.length,"
        "csp: document.querySelector('meta[http-equiv=\"Content-Security-Policy\"]')?.content ?? null,"
        "styles: [...document.querySelectorAll('style')].map(item => item.textContent),"
        "links: [...document.querySelectorAll('a[href]')].map(item => ({href: item.href, raw: item.getAttribute('href'), text: item.textContent.trim()}))}",
    )
    if state["scripts"] != 0 or state["forms"] != 0:
        raise AuditError("root page carries a script or form")
    check_csp(state["csp"], state["styles"])
    expected = {f"./v{version}/", f"./v{version}/sample-case/report.html"}
    raw = {link["raw"] for link in state["links"]}
    if raw != expected:
        raise AuditError(f"root page links {sorted(raw)} differ from {sorted(expected)}")
    for link in state["links"]:
        status, content_type = fetch_status(link["href"])
        if status != 200 or not content_type.startswith("text/html"):
            raise AuditError(f"root link {link['raw']!r} does not resolve to HTML under the base path")
    performance = driver.session_call("POST", "/log", {"type": "performance"})["value"]
    console = driver.session_call("POST", "/log", {"type": "browser"})["value"]
    requests = check_requests(performance, root_url, server)
    severe = severe_console_entries(console)
    if severe:
        raise AuditError(f"root page produced a severe console error: {severe[0]}")
    return {"url": root_url, **requests}


def audit_landing(driver: Driver, server: SiteServer, version: str) -> dict[str, object]:
    landing_url = f"{server.origin}{server.base_path}v{version}/"
    set_viewport(driver, *FIRST_VIEWPORT)
    driver.session_call("POST", "/log", {"type": "performance"})
    driver.session_call("POST", "/log", {"type": "browser"})
    navigate(driver, landing_url)
    state = execute(driver, LANDING_STATE_SCRIPT)
    performance = driver.session_call("POST", "/log", {"type": "performance"})["value"]
    console = driver.session_call("POST", "/log", {"type": "browser"})["value"]

    if state["scripts"] != 0 or state["linkElements"] != 0 or state["forms"] != 0 or state["embedded"] != 0:
        raise AuditError("landing page carries a script, link element, form, or embedded frame or media")
    check_csp(state["csp"], state["styles"])
    if state["bodyBackground"] != "rgb(255, 255, 255)" or state["mainMaxWidth"] != "1024px":
        raise AuditError("hashed stylesheet did not apply; the policy or hash is wrong")
    if state["referrer"] != "no-referrer" or state["colorScheme"] != "light":
        raise AuditError("landing page referrer or color-scheme meta is not the reviewed value")
    if not state["viewportMeta"] or "width=device-width" not in state["viewportMeta"]:
        raise AuditError("landing page lacks a device-width viewport")
    if len(state["images"]) != 1:
        raise AuditError("landing page must embed exactly one image")
    image = state["images"][0]
    if image["src"] != landing_url + "graph.svg":
        raise AuditError(f"visual is not the same-origin graph copy: {image['src']}")
    if not image["complete"] or image["naturalWidth"] <= 0 or image["naturalHeight"] <= 0:
        raise AuditError("same-origin SVG visual failed to load under the policy")
    if not image["width"] or not image["height"] or not image["alt"] or len(image["alt"]) < 40:
        raise AuditError("visual lacks explicit dimensions or meaningful alt text")
    check_headings(state["headings"])
    if state["labelText"] != "SYNTHETIC — PARTIAL COVERAGE":
        raise AuditError("synthetic partial-coverage label is missing or altered")
    if state["tableHeaders"] < 12 or not state["tableCaption"]:
        raise AuditError("count table lacks headers or a caption")
    if state["storage"] != {"local": 0, "session": 0, "cookie": ""}:
        raise AuditError("landing page touched browser storage")
    check_first_viewport(state)
    links = check_links(state["links"], landing_url, version)
    requests = check_requests(performance, landing_url, server)
    severe = severe_console_entries(console)
    if severe:
        raise AuditError(f"landing page produced a severe console error: {severe[0]}")
    # A headless window is never OS-focused, so :focus would not match without
    # focus emulation; the styles themselves are what is being checked.
    cdp(driver, "Emulation.setFocusEmulationEnabled", {"enabled": True})
    focus = execute(driver, FOCUS_SCRIPT)
    if not focus["focused"] or focus["outlineWidth"] <= 0 or focus["outlineStyle"] == "none":
        raise AuditError("focused link has no visible focus indicator")
    responsive = responsive_checks(driver)
    forced = forced_color_checks(driver)
    workers = execute_async(driver, SERVICE_WORKER_SCRIPT)
    if workers != 0:
        raise AuditError("a service worker is registered for the site origin")
    blocked = images_blocked_check(driver, landing_url)
    return {
        "url": landing_url,
        "image": {"naturalWidth": image["naturalWidth"], "naturalHeight": image["naturalHeight"]},
        "sections": len(EXPECTED_SECTIONS),
        "firstViewport": state["firstViewport"],
        "focus": focus,
        "responsive": responsive,
        "forcedColors": forced,
        "imagesBlocked": blocked,
        **links,
        **requests,
    }


def audit_case_pages(driver: Driver, server: SiteServer, version: str) -> dict[str, object]:
    base = f"{server.origin}{server.base_path}v{version}/"
    results: dict[str, object] = {}
    for name in ("sample-case/report.html", "graph.svg"):
        url = base + name
        driver.session_call("POST", "/log", {"type": "performance"})
        driver.session_call("POST", "/log", {"type": "browser"})
        navigate(driver, url)
        content_type = execute(driver, "return document.contentType")
        performance = driver.session_call("POST", "/log", {"type": "performance"})["value"]
        console = driver.session_call("POST", "/log", {"type": "browser"})["value"]
        requests = check_requests(performance, url, server)
        severe = severe_console_entries(console)
        if severe:
            raise AuditError(f"{name} produced a severe console error: {severe[0]}")
        expected_type = "text/html" if name.endswith(".html") else "image/svg+xml"
        if content_type != expected_type:
            raise AuditError(f"{name} rendered as {content_type}, not {expected_type}")
        results[name] = {"contentType": content_type, **requests}
    return results


def audit_site(site: Path, version: str, base_path: str, driver: Driver) -> dict[str, object]:
    server = SiteServer(site, base_path)
    try:
        root = audit_root(driver, server, version)
        landing = audit_landing(driver, server, version)
        case_pages = audit_case_pages(driver, server, version)
        with server._lock:
            served = list(server.requests)
        if any(status != 200 and not path.endswith("/favicon.ico") for path, status in served):
            raise AuditError(f"the audit server refused a request the site depends on: {served}")
    finally:
        server.close()
    return {
        "browser": driver.capabilities.get("browserVersion", "unknown"),
        "browserSandboxPolicy": "chromium-default",
        "basePath": base_path,
        "version": version,
        "root": root,
        "landing": landing,
        "casePages": case_pages,
        "servedRequests": len(served),
        "externalRequests": 0,
    }


def preflight(chrome: str, chromedriver: str, work: Path) -> int:
    """Launch Chrome directly under the audit policy and report why it fails."""
    import subprocess

    print(json.dumps({"chrome": chrome, "chromedriver": chromedriver}))
    for executable in (chrome, chromedriver):
        try:
            version = subprocess.run([executable, "--version"], capture_output=True, text=True, timeout=30, check=False)
            print(f"{executable} --version: exit={version.returncode} {version.stdout.strip()} {version.stderr.strip()}"[:400])
        except (OSError, subprocess.TimeoutExpired) as error:
            print(f"{executable} --version failed: {error}")
    sysctl = Path("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
    if sysctl.is_file():
        print(f"apparmor_restrict_unprivileged_userns={sysctl.read_text(encoding='utf-8').strip()}")
    helper = Path(chrome).resolve().parent / "chrome-sandbox"
    if helper.exists():
        mode = helper.stat().st_mode
        print(f"chrome-sandbox helper: {helper} mode={oct(mode & 0o7777)} uid={helper.stat().st_uid}")
    else:
        print(f"chrome-sandbox helper absent beside {Path(chrome).resolve()}")
    profile = work / "preflight-profile"
    command = [chrome, *site_chromium_arguments(profile), "--dump-dom", "about:blank"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    except subprocess.TimeoutExpired:
        print("preflight: Chrome did not exit within 60 seconds")
        return 1
    stderr_lines = [line for line in result.stderr.splitlines() if line.strip()]
    print(f"preflight: exit={result.returncode} dom_bytes={len(result.stdout)}")
    for line in stderr_lines[-40:]:
        print("chrome stderr: " + "".join(character for character in line if character.isprintable())[:300])
    if result.returncode != 0 or "<html" not in result.stdout.lower():
        print("preflight: sandboxed headless Chrome cannot start on this host under the audit policy")
        return 1
    print("preflight: sandboxed headless Chrome started under the audit policy")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("site", type=Path, nargs="?")
    parser.add_argument("--version")
    parser.add_argument("--base-path", default="/cirewind/")
    parser.add_argument("--chrome")
    parser.add_argument("--chromedriver")
    parser.add_argument("--work-root", type=Path)
    parser.add_argument("--preflight", action="store_true", help="launch Chrome directly under the audit policy and report the outcome")
    args = parser.parse_args()

    if args.preflight:
        work_root = args.work_root.expanduser().resolve() if args.work_root else None
        chrome = first_executable(args.chrome or os.environ.get("CIREWIND_CHROME"), ("/snap/chromium/current/usr/lib/chromium-browser/chrome", "chromium", "chromium-browser", "google-chrome"))
        chromedriver = first_executable(args.chromedriver or os.environ.get("CIREWIND_CHROMEDRIVER"), ("/snap/chromium/current/usr/lib/chromium-browser/chromedriver", "chromedriver"))
        work = Path(tempfile.mkdtemp(prefix="cirewind-site-preflight.", dir=work_root))
        try:
            return preflight(chrome, chromedriver, work)
        finally:
            remove_work_tree(work)
    if args.site is None or not args.version:
        raise AuditError("site directory and --version are required unless --preflight is given")

    site = args.site.expanduser().resolve()
    if not VERSION_PATTERN.match(args.version):
        raise AuditError(f"version must be canonical SemVer without a v prefix: {args.version}")
    if not (site / f"v{args.version}" / "index.html").is_file():
        raise AuditError(f"site does not contain v{args.version}/index.html: {site}")
    base_path = validate_base_path(args.base_path)
    work_root = args.work_root.expanduser().resolve() if args.work_root else None
    if work_root is not None and not work_root.is_dir():
        raise AuditError(f"work root is unavailable: {work_root}")
    chrome = first_executable(
        args.chrome or os.environ.get("CIREWIND_CHROME"),
        (
            "/snap/chromium/current/usr/lib/chromium-browser/chrome",
            "chromium",
            "chromium-browser",
            "google-chrome",
        ),
    )
    chromedriver = first_executable(
        args.chromedriver or os.environ.get("CIREWIND_CHROMEDRIVER"),
        (
            "/snap/chromium/current/usr/lib/chromium-browser/chromedriver",
            "chromedriver",
        ),
    )
    work = Path(tempfile.mkdtemp(prefix="cirewind-site-audit.", dir=work_root))
    driver: Driver | None = None
    try:
        driver = SiteDriver(chromedriver, chrome, work / "profile", work / "chromedriver.log")
        result = audit_site(site, args.version, base_path, driver)
        print(json.dumps(result, sort_keys=True))
    finally:
        if driver is not None:
            driver.close()
        remove_work_tree(work)
    return 0


class SiteDriver(Driver):
    """The report driver with the site launch policy."""

    def __init__(self, executable: str, chrome: str, profile: Path, log_path: Path):
        import browser_audit

        original = browser_audit.chromium_arguments
        browser_audit.chromium_arguments = site_chromium_arguments
        try:
            super().__init__(executable, chrome, profile, log_path)
        finally:
            browser_audit.chromium_arguments = original


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AuditError as error:
        print(f"site browser audit failed: {error}", file=sys.stderr)
        raise SystemExit(1)
