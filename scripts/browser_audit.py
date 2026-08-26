#!/usr/bin/env python3
"""Audit a generated report in Chromium through the W3C WebDriver protocol."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class AuditError(RuntimeError):
    pass


def first_executable(explicit: str | None, candidates: tuple[str, ...]) -> str:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise AuditError(f"executable is unavailable: {path}")
        return str(path)
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    raise AuditError(f"none of these executables is available: {', '.join(candidates)}")


def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class Driver:
    def __init__(self, executable: str, chrome: str, profile: Path, log_path: Path):
        self.port = reserve_loopback_port()
        self.base = f"http://127.0.0.1:{self.port}"
        self.log_path = log_path
        self.log_file = log_path.open("wb")
        self.process = subprocess.Popen(
            [
                executable,
                f"--port={self.port}",
                "--allowed-ips=127.0.0.1",
                "--verbose",
            ],
            stdin=subprocess.DEVNULL,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
        )
        self.session_id = ""
        try:
            self._wait_ready()
            created = self.call(
                "POST",
                "/session",
                {
                    "capabilities": {
                        "alwaysMatch": {
                            "browserName": "chrome",
                            "goog:chromeOptions": {
                                "binary": chrome,
                                "args": [
                                    "--headless=new",
                                    "--no-sandbox",
                                    "--disable-gpu",
                                    "--disable-dev-shm-usage",
                                    "--disable-background-networking",
                                    "--disable-component-update",
                                    "--disable-default-apps",
                                    "--disable-domain-reliability",
                                    "--disable-sync",
                                    "--metrics-recording-only",
                                    "--no-first-run",
                                    "--no-default-browser-check",
                                    "--password-store=basic",
                                    "--use-mock-keychain",
                                    "--proxy-server=direct://",
                                    "--proxy-bypass-list=*",
                                    "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE localhost",
                                    f"--user-data-dir={profile}",
                                ],
                            },
                            "goog:loggingPrefs": {
                                "performance": "ALL",
                                "browser": "ALL",
                            },
                        }
                    }
                },
            )
            self.session_id = created["value"]["sessionId"]
            self.capabilities = created["value"]["capabilities"]
        except Exception as error:
            self.close()
            detail = ""
            try:
                lines = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
                detail = " | ".join(lines[-12:])
                detail = "".join(character for character in detail if character.isprintable())[:2048]
            except OSError:
                pass
            suffix = f"; chromedriver: {detail}" if detail else ""
            raise AuditError(f"{error}{suffix}") from error

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AuditError("chromedriver exited before becoming ready")
            try:
                if self.call("GET", "/status")["value"]["ready"]:
                    return
            except (AuditError, URLError):
                time.sleep(0.05)
        raise AuditError("chromedriver did not become ready within 15 seconds")

    def call(self, method: str, path: str, body: object | None = None) -> dict:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(
            self.base + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json;charset=UTF-8"},
        )
        try:
            with urlopen(request, timeout=20) as response:
                result = json.load(response)
        except HTTPError as error:
            detail = ""
            try:
                payload = json.loads(error.read().decode("utf-8", errors="replace"))
                value = payload.get("value", {}) if isinstance(payload, dict) else {}
                message = value.get("message", "") if isinstance(value, dict) else ""
                detail = "".join(character for character in str(message) if character.isprintable())
                detail = detail[:1024]
            except (json.JSONDecodeError, OSError, UnicodeError):
                pass
            suffix = f": {detail}" if detail else ""
            raise AuditError(
                f"webdriver {method} {path} returned HTTP {error.code}{suffix}"
            ) from error
        if isinstance(result, dict) and isinstance(result.get("value"), dict):
            error_name = result["value"].get("error")
            if error_name:
                raise AuditError(f"webdriver {method} {path} failed: {error_name}")
        return result

    def session_call(self, method: str, path: str, body: object | None = None) -> dict:
        if not self.session_id:
            raise AuditError("webdriver session is unavailable")
        return self.call(method, f"/session/{self.session_id}{path}", body)

    def close(self) -> None:
        if self.session_id:
            try:
                self.session_call("DELETE", "")
            except Exception:
                pass
            self.session_id = ""
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.log_file.close()


def sha256_source(source: str) -> str:
    digest = hashlib.sha256(source.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def parse_csp(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for section in value.split(";"):
        fields = section.strip().split()
        if not fields:
            continue
        if fields[0] in directives:
            raise AuditError(f"duplicate CSP directive: {fields[0]}")
        directives[fields[0]] = fields[1:]
    return directives


def page_request_urls(entries: list[dict], report_url: str) -> list[str]:
    urls: list[str] = []
    for entry in entries:
        message = json.loads(entry["message"])["message"]
        if message.get("method") != "Network.requestWillBeSent":
            continue
        params = message["params"]
        request_url = params["request"]["url"]
        if params.get("documentURL") == report_url or request_url == report_url:
            urls.append(request_url)
    return urls


def focus_temporal_region_by_keyboard(driver: Driver) -> None:
    for _ in range(64):
        active = driver.session_call(
            "POST",
            "/execute/sync",
            {
                "script": "return document.activeElement?.classList.contains('temporal-path') === true;",
                "args": [],
            },
        )["value"]
        if active:
            return
        driver.session_call(
            "POST",
            "/actions",
            {
                "actions": [
                    {
                        "type": "key",
                        "id": "graph-focus",
                        "actions": [
                            {"type": "keyDown", "value": "\ue004"},
                            {"type": "keyUp", "value": "\ue004"},
                        ],
                    }
                ]
            },
        )
    raise AuditError("keyboard traversal did not reach the temporal-path region")


def responsive_report_checks(driver: Driver) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for width, height in ((1440, 900), (1024, 768), (768, 768), (390, 844)):
        driver.session_call(
            "POST", "/window/rect", {"x": 0, "y": 0, "width": width, "height": height}
        )
        focus_temporal_region_by_keyboard(driver)
        driver.session_call(
            "POST",
            "/execute/sync",
            {
                "script": "const r=document.querySelector('.temporal-path');r.scrollTop=0;r.scrollLeft=0;",
                "args": [],
            },
        )
        before = driver.session_call(
            "POST",
            "/execute/sync",
            {
                "script": r"""
const region = document.querySelector('.temporal-path[role="region"]');
const svg = region?.querySelector('svg');
const text = svg ? [...svg.querySelectorAll('text')].find(item => item.getAttribute('font-size') === '16') : null;
if (!region || !svg || !text) return null;
const matrix = text.getScreenCTM();
const viewBox = svg.viewBox.baseVal;
const style = getComputedStyle(text);
const regionStyle = getComputedStyle(region);
return {
  innerWidth: window.innerWidth,
  documentClientWidth: document.documentElement.clientWidth,
  documentScrollWidth: document.documentElement.scrollWidth,
  svgWidthAttribute: Number(svg.getAttribute('width')),
  svgHeightAttribute: Number(svg.getAttribute('height')),
  viewBoxWidth: viewBox.width,
  viewBoxHeight: viewBox.height,
  renderedSVGWidth: svg.getBoundingClientRect().width,
  renderedSVGHeight: svg.getBoundingClientRect().height,
  effectiveFontSize: Number.parseFloat(style.fontSize) * Math.abs(matrix?.a || 0),
  scaleX: Math.abs(matrix?.a || 0),
  scaleY: Math.abs(matrix?.d || 0),
  regionClientWidth: region.clientWidth,
  regionClientHeight: region.clientHeight,
  regionScrollWidth: region.scrollWidth,
  regionScrollHeight: region.scrollHeight,
  focused: document.activeElement === region,
  outlineWidth: Number.parseFloat(regionStyle.outlineWidth) || 0,
  outlineStyle: regionStyle.outlineStyle,
  boxShadow: regionStyle.boxShadow
};
""",
                "args": [],
            },
        )["value"]
        if before is None:
            raise AuditError("responsive report lacks its temporal-path region, SVG, or 16px text")
        driver.session_call(
            "POST",
            "/actions",
            {
                "actions": [
                    {
                        "type": "key",
                        "id": "graph-scroll",
                        "actions": [
                            {"type": "keyDown", "value": "\ue00f"},
                            {"type": "keyUp", "value": "\ue00f"},
                            {"type": "keyDown", "value": "\ue014"},
                            {"type": "keyUp", "value": "\ue014"},
                        ],
                    }
                ]
            },
        )
        time.sleep(0.05)
        after = driver.session_call(
            "POST",
            "/execute/sync",
            {
                "script": "const r=document.querySelector('.temporal-path');return {top:r.scrollTop,left:r.scrollLeft};",
                "args": [],
            },
        )["value"]
        if before["documentScrollWidth"] > before["documentClientWidth"] + 1:
            raise AuditError(f"report has document-wide horizontal overflow at {width}px")
        if before["svgWidthAttribute"] != before["viewBoxWidth"] or before["svgHeightAttribute"] != before["viewBoxHeight"]:
            raise AuditError(f"inline SVG intrinsic dimensions disagree with its viewBox at {width}px")
        if abs(before["renderedSVGWidth"] - before["viewBoxWidth"]) > 0.5 or abs(before["renderedSVGHeight"] - before["viewBoxHeight"]) > 0.5:
            raise AuditError(f"inline SVG was scaled away from its intrinsic vector dimensions at {width}px")
        if before["effectiveFontSize"] < 15.99 or before["scaleX"] < 0.999 or before["scaleY"] < 0.999:
            raise AuditError(f"inline graph text was scaled below 16px at {width}px")
        if before["regionScrollWidth"] <= before["regionClientWidth"] or before["regionScrollHeight"] <= before["regionClientHeight"]:
            raise AuditError(f"temporal-path region is not locally two-dimensionally scrollable at {width}px")
        visible_focus = (
            before["outlineStyle"] != "none" and before["outlineWidth"] >= 3
        ) or before["boxShadow"] != "none"
        if not before["focused"] or not visible_focus:
            raise AuditError(
                f"temporal-path keyboard focus is not visibly indicated at {width}px: "
                f"focused={before['focused']} style={before['outlineStyle']} "
                f"width={before['outlineWidth']} shadow={before['boxShadow']}"
            )
        if after["top"] <= 0 or after["left"] <= 0:
            raise AuditError(f"keyboard input did not scroll the temporal-path region at {width}px")
        before["keyboardScrollTop"] = after["top"]
        before["keyboardScrollLeft"] = after["left"]
        results.append(before)
    return results


def accessible_text_skip_check(driver: Driver) -> dict[str, object]:
    prepared = driver.session_call(
        "POST",
        "/execute/sync",
        {
            "script": r"""
const link = document.getElementById('temporal-path-text-link');
const details = document.getElementById('temporal-path-text');
const summary = document.getElementById('temporal-path-text-summary');
if (!link || !details || !summary) return false;
details.open = false;
link.focus();
return document.activeElement === link;
""",
            "args": [],
        },
    )["value"]
    if not prepared:
        raise AuditError("accessible text skip link could not receive keyboard focus")
    driver.session_call(
        "POST",
        "/actions",
        {
            "actions": [
                {
                    "type": "key",
                    "id": "text-equivalent-skip",
                    "actions": [
                        {"type": "keyDown", "value": "\ue007"},
                        {"type": "keyUp", "value": "\ue007"},
                    ],
                }
            ]
        },
    )
    state = driver.session_call(
        "POST",
        "/execute/sync",
        {
            "script": r"""
const details = document.getElementById('temporal-path-text');
const summary = document.getElementById('temporal-path-text-summary');
return {
  open: details?.open === true,
  summaryFocused: document.activeElement === summary,
  hash: window.location.hash
};
""",
            "args": [],
        },
    )["value"]
    if not state["open"] or not state["summaryFocused"] or state["hash"] != "#temporal-path-text-summary":
        raise AuditError(
            "accessible text skip link did not open and focus its target: "
            f"open={state['open']} focused={state['summaryFocused']} hash={state['hash']}"
        )
    return state


def audit_standalone_svg(graph: Path, driver: Driver) -> dict[str, object]:
    graph_url = graph.resolve().as_uri()
    driver.session_call("POST", "/log", {"type": "performance"})
    driver.session_call("POST", "/log", {"type": "browser"})
    driver.session_call("POST", "/window/rect", {"x": 0, "y": 0, "width": 1440, "height": 900})
    driver.session_call("POST", "/url", {"url": graph_url})
    state = driver.session_call(
        "POST",
        "/execute/sync",
        {
            "script": r"""
const svg = document.documentElement;
const text = [...svg.querySelectorAll('text')].find(item => item.getAttribute('font-size') === '16');
const matrix = text?.getScreenCTM();
const edgeGroups = [...svg.querySelectorAll('g[data-edge-id]')];
let ledgerTextOverflows = 0;
let maximumLedgerOverflow = 0;
for (const group of edgeGroups) {
  const rect = group.querySelector(':scope > rect');
  const lines = [...group.querySelectorAll(':scope > text')];
  if (!rect || lines.length !== 2) {
    ledgerTextOverflows += 1;
    maximumLedgerOverflow = Number.POSITIVE_INFINITY;
    continue;
  }
  const bounds = {
    left: Number(rect.getAttribute('x')),
    top: Number(rect.getAttribute('y')),
    right: Number(rect.getAttribute('x')) + Number(rect.getAttribute('width')),
    bottom: Number(rect.getAttribute('y')) + Number(rect.getAttribute('height'))
  };
  let rowOverflow = 0;
  for (const line of lines) {
    const box = line.getBBox();
    rowOverflow = Math.max(
      rowOverflow,
      bounds.left - box.x,
      bounds.top - box.y,
      box.x + box.width - bounds.right,
      box.y + box.height - bounds.bottom
    );
  }
  if (rowOverflow > 0.01) ledgerTextOverflows += 1;
  maximumLedgerOverflow = Math.max(maximumLedgerOverflow, rowOverflow);
}
return {
  root: svg.localName,
  widthAttribute: Number(svg.getAttribute('width')),
  heightAttribute: Number(svg.getAttribute('height')),
  viewBoxWidth: svg.viewBox.baseVal.width,
  viewBoxHeight: svg.viewBox.baseVal.height,
  renderedWidth: svg.getBoundingClientRect().width,
  renderedHeight: svg.getBoundingClientRect().height,
  effectiveFontSize: text ? Number.parseFloat(getComputedStyle(text).fontSize) * Math.abs(matrix?.a || 0) : 0,
  scaleX: Math.abs(matrix?.a || 0),
  scaleY: Math.abs(matrix?.d || 0),
  scrollWidth: document.scrollingElement.scrollWidth,
  scrollHeight: document.scrollingElement.scrollHeight,
  clientWidth: document.scrollingElement.clientWidth,
  clientHeight: document.scrollingElement.clientHeight,
  relationshipLedgerRows: edgeGroups.length,
  ledgerTextOverflows,
  maximumLedgerOverflow
};
""",
            "args": [],
        },
    )["value"]
    performance = driver.session_call("POST", "/log", {"type": "performance"})["value"]
    console = driver.session_call("POST", "/log", {"type": "browser"})["value"]
    if state["root"] != "svg" or state["widthAttribute"] != state["viewBoxWidth"] or state["heightAttribute"] != state["viewBoxHeight"]:
        raise AuditError("standalone SVG intrinsic dimensions disagree with its viewBox")
    if abs(state["renderedWidth"] - state["viewBoxWidth"]) > 0.5 or abs(state["renderedHeight"] - state["viewBoxHeight"]) > 0.5:
        raise AuditError("standalone SVG was fit to the viewport instead of retaining intrinsic scale")
    if state["effectiveFontSize"] < 15.99 or state["scaleX"] < 0.999 or state["scaleY"] < 0.999:
        raise AuditError("standalone SVG text was scaled below 16px")
    if state["relationshipLedgerRows"] < 1 or state["ledgerTextOverflows"] != 0:
        raise AuditError(
            "standalone SVG relationship-ledger text exceeds its row bounds: "
            f"rows={state['relationshipLedgerRows']} overflows={state['ledgerTextOverflows']} "
            f"maximum={state['maximumLedgerOverflow']}"
        )
    if state["scrollWidth"] < state["widthAttribute"] or state["scrollHeight"] < state["heightAttribute"]:
        raise AuditError("standalone SVG right or bottom extent is unreachable")
    requests = page_request_urls(performance, graph_url)
    external = sorted({url for url in requests if urlsplit(url).scheme in {"http", "https", "ws", "wss"}})
    files = sorted({url for url in requests if urlsplit(url).scheme == "file"})
    severe = [item for item in console if item.get("level") == "SEVERE"]
    if external or files != [graph_url] or severe:
        raise AuditError("standalone SVG initiated an unexpected request or console error")
    state["pageRequests"] = len(requests)
    state["externalRequests"] = len(external)
    state["consoleErrors"] = len(severe)
    return state


def audit(report: Path, driver: Driver) -> dict[str, object]:
    report_url = report.resolve().as_uri()
    driver.session_call("POST", "/log", {"type": "performance"})
    driver.session_call("POST", "/log", {"type": "browser"})
    driver.session_call("POST", "/url", {"url": report_url})
    state = driver.session_call(
        "POST",
        "/execute/sync",
        {
            "script": r"""
const counted = [...document.querySelectorAll('[data-finding-item][data-counted="true"]')];
const visible = () => counted.filter(item => !item.hidden).length;
const displayed = () => document.getElementById('visible-count').textContent;
const laneElements = [...document.querySelectorAll('[data-graph-item][data-visual-lane="true"][data-revision]')];
const unique = values => [...new Set(values)].sort();
const tableRevisions = unique(counted.map(item => item.dataset.revision));
const laneRevisions = unique(laneElements.map(item => item.dataset.revision));
const visualSnapshot = () => {
  const visibleFindings = unique(counted.filter(item => !item.hidden).map(item => item.dataset.revision));
  const visibleLanes = unique(laneElements.filter(item => !item.hasAttribute('hidden')).map(item => item.dataset.revision));
  const expectedShown = visibleFindings.filter(revision => laneRevisions.includes(revision));
  return {
    visibleFindings,
    visibleLanes,
    expectedShown,
    expectedOmitted: visibleFindings.length - expectedShown.length,
    shownText: Number(document.getElementById('visual-shown').textContent),
    omittedText: Number(document.getElementById('visual-omitted').textContent),
    laneVisibilityConsistent: laneRevisions.every(revision => {
      const values = laneElements.filter(item => item.dataset.revision === revision).map(item => item.hasAttribute('hidden'));
      return values.every(value => value === values[0]);
    })
  };
};
const filter = document.querySelector('[data-filter="state"]');
const option = filter ? [...filter.options].find(candidate => candidate.value) : null;
const initial = {visible: visible(), displayed: displayed(), visual: visualSnapshot()};
let filtered = null;
if (filter && option) {
  filter.value = option.value;
  filter.dispatchEvent(new Event('change'));
  filtered = {
    state: option.value,
    visible: visible(),
    displayed: displayed(),
    expected: counted.filter(item => item.dataset.state === option.value).length,
    tableRows: counted.length,
    tableRevisions: unique(counted.map(item => item.dataset.revision)),
    visual: visualSnapshot()
  };
  document.getElementById('filter-reset').click();
}
return {
  ready: document.readyState,
  csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]').content,
  scripts: [...document.scripts].map(element => ({src: element.src, text: element.textContent})),
  styles: [...document.querySelectorAll('style')].map(element => element.textContent),
  counted: counted.length,
  tableRevisions,
  laneRevisions,
  initial,
  filtered,
  reset: {visible: visible(), displayed: displayed(), visual: visualSnapshot()}
};
""",
            "args": [],
        },
    )["value"]
    responsive = responsive_report_checks(driver)
    accessible_text_skip = accessible_text_skip_check(driver)
    performance = driver.session_call("POST", "/log", {"type": "performance"})["value"]
    console = driver.session_call("POST", "/log", {"type": "browser"})["value"]

    if state["ready"] != "complete":
        raise AuditError("report document did not reach complete state")
    if len(state["scripts"]) != 1 or state["scripts"][0]["src"]:
        raise AuditError("report must contain exactly one inline script")
    if len(state["styles"]) != 1:
        raise AuditError("report must contain exactly one inline stylesheet")
    if state["initial"]["visible"] != state["counted"]:
        raise AuditError("initial report filter hid findings")
    if state["initial"]["displayed"] != str(state["counted"]):
        raise AuditError("initial visible-count text is inconsistent")
    if len(state["tableRevisions"]) != state["counted"]:
        raise AuditError("complete findings table contains duplicate or missing revisions")
    if not set(state["laneRevisions"]).issubset(state["tableRevisions"]):
        raise AuditError("visual contains a lane absent from the complete findings table")
    if state["filtered"] is None:
        raise AuditError("report has no usable state filter")
    if state["filtered"]["visible"] != state["filtered"]["expected"]:
        raise AuditError("state filter displayed the wrong findings")
    if state["filtered"]["displayed"] != str(state["filtered"]["expected"]):
        raise AuditError("filtered visible-count text is inconsistent")
    if state["filtered"]["tableRows"] != state["counted"]:
        raise AuditError("filter removed a finding from the complete findings table")
    if state["filtered"]["tableRevisions"] != state["tableRevisions"]:
        raise AuditError("filter changed the complete findings-table revision set")
    if state["reset"]["visible"] != state["counted"]:
        raise AuditError("filter reset did not restore all findings")

    def assert_visual_intersection(label: str, snapshot: dict[str, object]) -> None:
        visible_lanes = snapshot["visibleLanes"]
        expected_shown = snapshot["expectedShown"]
        if visible_lanes != expected_shown:
            raise AuditError(
                f"{label} filter admitted a nonmatching/non-rendered lane or hid a matching rendered lane"
            )
        if snapshot["shownText"] != len(expected_shown):
            raise AuditError(f"{label} visual shown-count is inconsistent")
        if snapshot["omittedText"] != snapshot["expectedOmitted"]:
            raise AuditError(f"{label} visual omitted-count is inconsistent")
        if not snapshot["laneVisibilityConsistent"]:
            raise AuditError(f"{label} inline and accessible lane copies disagree")

    assert_visual_intersection("initial", state["initial"]["visual"])
    assert_visual_intersection("filtered", state["filtered"]["visual"])
    assert_visual_intersection("reset", state["reset"]["visual"])

    directives = parse_csp(state["csp"])
    required_none = (
        "default-src",
        "img-src",
        "connect-src",
        "object-src",
        "base-uri",
        "form-action",
    )
    for name in required_none:
        if directives.get(name) != ["'none'"]:
            raise AuditError(f"CSP {name} must be exactly 'none'")
    expected_script = sha256_source(state["scripts"][0]["text"])
    expected_style = sha256_source(state["styles"][0])
    if directives.get("script-src") != [expected_script]:
        raise AuditError("CSP script hash does not match the inline script")
    if directives.get("style-src") != [expected_style]:
        raise AuditError("CSP style hash does not match the inline stylesheet")
    if "frame-ancestors" in directives:
        raise AuditError("frame-ancestors is ineffective in a meta-delivered CSP")

    requests = page_request_urls(performance, report_url)
    external = sorted(
        {url for url in requests if urlsplit(url).scheme in {"http", "https", "ws", "wss"}}
    )
    files = sorted({url for url in requests if urlsplit(url).scheme == "file"})
    if external:
        raise AuditError("report initiated an external request")
    if files != [report_url]:
        raise AuditError("report loaded an unexpected local file")
    severe = [item for item in console if item.get("level") == "SEVERE"]
    if severe:
        raise AuditError("browser console contains a severe report error")

    return {
        "browser": driver.capabilities.get("browserVersion", "unknown"),
        "findings": state["counted"],
        "filterState": state["filtered"]["state"],
        "filterMatches": state["filtered"]["visible"],
        "visualLanes": len(state["laneRevisions"]),
        "visualOmittedForFilter": state["filtered"]["visual"]["omittedText"],
        "pageRequests": len(requests),
        "externalRequests": len(external),
        "consoleErrors": len(severe),
        "cspHashesVerified": True,
        "responsive": responsive,
        "accessibleTextSkip": accessible_text_skip,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--chrome")
    parser.add_argument("--chromedriver")
    parser.add_argument("--work-root", type=Path)
    args = parser.parse_args()

    report = args.report.expanduser().resolve()
    if not report.is_file():
        raise AuditError(f"report is unavailable: {report}")
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
    work = Path(tempfile.mkdtemp(prefix="cirewind-browser-audit.", dir=work_root))
    driver: Driver | None = None
    try:
        driver = Driver(chromedriver, chrome, work / "profile", work / "chromedriver.log")
        result = audit(report, driver)
        graph = report.parent / "graph.svg"
        if not graph.is_file():
            raise AuditError(f"standalone graph is unavailable: {graph}")
        result["standaloneGraph"] = audit_standalone_svg(graph, driver)
        print(json.dumps(result, sort_keys=True))
    finally:
        if driver is not None:
            driver.close()
        shutil.rmtree(work)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AuditError as error:
        print(f"browser audit failed: {error}", file=sys.stderr)
        raise SystemExit(1)
