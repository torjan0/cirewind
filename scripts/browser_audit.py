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


def chromium_arguments(profile: Path) -> list[str]:
    """Return the fixed host-security launch policy for hostile report bytes."""
    arguments = [
        "--headless=new",
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
        "--host-resolver-rules=MAP * ~NOTFOUND",
        f"--user-data-dir={profile}",
    ]
    prohibited = {"--no-sandbox", "--disable-setuid-sandbox"}
    if prohibited.intersection(arguments):
        raise AuditError("host-security browser audit cannot disable Chromium sandboxing")
    return arguments


def remove_work_tree(path: Path, attempts: int = 20) -> None:
    """Remove the controlled browser workspace after child processes settle."""
    if attempts < 1:
        raise AuditError("browser workspace cleanup requires at least one attempt")
    for attempt in range(attempts):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError as error:
            if attempt == attempts - 1:
                raise AuditError(f"could not remove browser workspace: {path}") from error
            time.sleep(min(0.05 * (attempt + 1), 0.25))


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
                                "args": chromium_arguments(profile),
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
    for width, height in ((1440, 900), (1024, 768), (768, 768), (390, 844), (320, 720)):
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
const rootStyle = getComputedStyle(document.documentElement);
const bodyStyle = getComputedStyle(document.body);
const legend = svg.querySelector('g[aria-label="Legend"]');
const temporalLabel = legend ? [...legend.querySelectorAll('text')].find(item => item.textContent.startsWith('Observed after;')) : null;
const contradictionLine = legend ? [...legend.querySelectorAll('line')].find(item => (item.getAttribute('stroke') || '').toUpperCase() === '#B42318') : null;
const temporalBox = temporalLabel?.getBBox();
const contradictionPaintStart = contradictionLine ? Number(contradictionLine.getAttribute('x1')) - Number(contradictionLine.getAttribute('stroke-width') || 0) / 2 : Number.NaN;
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
  boxShadow: regionStyle.boxShadow,
  rootColorScheme: rootStyle.colorScheme,
  rootColor: rootStyle.color,
  rootBackground: rootStyle.backgroundColor,
  bodyColor: bodyStyle.color,
  bodyBackground: bodyStyle.backgroundColor,
  legendSeparation: temporalBox ? contradictionPaintStart - (temporalBox.x + temporalBox.width) : Number.NEGATIVE_INFINITY
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
        if before["innerWidth"] != width:
            raise AuditError(
                f"browser viewport width={before['innerWidth']}, requested {width}px"
            )
        if before["rootColor"] != "rgb(17, 24, 39)" or before["bodyColor"] != "rgb(17, 24, 39)" or before["rootBackground"] != "rgb(255, 255, 255)" or before["bodyBackground"] != "rgb(255, 255, 255)":
            raise AuditError(
                f"fixed light palette changed at {width}px: root={before['rootColor']}/{before['rootBackground']} "
                f"body={before['bodyColor']}/{before['bodyBackground']} scheme={before['rootColorScheme']}"
            )
        if before["legendSeparation"] < 12:
            raise AuditError(
                f"inline legend relationship samples overlap at {width}px: separation={before['legendSeparation']}"
            )
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
    forced_colors = audit_forced_color_routes(driver, "svg")
    state = driver.session_call(
        "POST",
        "/execute/sync",
        {
            "script": r"""
const svg = document.documentElement;
const text = [...svg.querySelectorAll('text')].find(item => item.getAttribute('font-size') === '16');
const matrix = text?.getScreenCTM();
const edgeGroups = [...svg.querySelectorAll('g[data-edge-id]')];
const routeUnderlays = edgeGroups.flatMap(group => [...group.querySelectorAll(':scope > polyline[data-route-underlay="true"]')]);
const invalidRouteUnderlays = routeUnderlays.filter(item =>
  item.getAttribute('aria-hidden') !== 'true' ||
  item.getAttribute('stroke') !== '#FFFFFF' ||
  item.getAttribute('stroke-linejoin') !== 'round' ||
  item.getAttribute('stroke-linecap') !== 'butt'
);
const nodeGroups = [...svg.querySelectorAll('g[data-node-id]')];
const laneGroups = [...svg.querySelectorAll('g[data-finding-revision]')];
const noticeGroups = [...svg.querySelectorAll('g[data-projection-notice="true"]')];
const legend = svg.querySelector('g[aria-label="Legend"]');
const temporalLabel = legend ? [...legend.querySelectorAll('text')].find(item => item.textContent.startsWith('Observed after;')) : null;
const contradictionLine = legend ? [...legend.querySelectorAll('line')].find(item => (item.getAttribute('stroke') || '').toUpperCase() === '#B42318') : null;
const temporalBox = temporalLabel?.getBBox();
const contradictionPaintStart = contradictionLine ? Number(contradictionLine.getAttribute('x1')) - Number(contradictionLine.getAttribute('stroke-width') || 0) / 2 : Number.NaN;
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
let nodeTextOverflows = 0;
let maximumNodeOverflow = 0;
for (const group of nodeGroups) {
  const rect = group.querySelector(':scope > rect');
  const texts = [...group.querySelectorAll(':scope > text')];
  if (!rect || texts.length !== 2) {
    nodeTextOverflows += 1;
    maximumNodeOverflow = Number.POSITIVE_INFINITY;
    continue;
  }
  const bounds = {
    left: Number(rect.getAttribute('x')),
    top: Number(rect.getAttribute('y')),
    right: Number(rect.getAttribute('x')) + Number(rect.getAttribute('width')),
    bottom: Number(rect.getAttribute('y')) + Number(rect.getAttribute('height'))
  };
  let overflow = 0;
  for (const text of texts) {
    const box = text.getBBox();
    overflow = Math.max(
      overflow,
      bounds.left - box.x,
      bounds.top - box.y,
      box.x + box.width - bounds.right,
      box.y + box.height - bounds.bottom
    );
  }
  if (overflow > 0.01) nodeTextOverflows += 1;
  maximumNodeOverflow = Math.max(maximumNodeOverflow, overflow);
}
let laneScopeOverflows = 0;
let gapReasonOverflows = 0;
let noticeTextOverflows = 0;
let maximumLaneTextOverflow = 0;
for (const group of laneGroups) {
  const rect = group.querySelector(':scope > rect');
  const texts = [...group.querySelectorAll(':scope > text')];
  if (!rect || texts.length < 2) {
    laneScopeOverflows += 1;
    maximumLaneTextOverflow = Number.POSITIVE_INFINITY;
    continue;
  }
  const left = Number(rect.getAttribute('x'));
  const right = left + Number(rect.getAttribute('width'));
  const scope = texts[1];
  const scopeBox = scope.getBBox();
  const scopeOverflow = Math.max(left - scopeBox.x, scopeBox.x + scopeBox.width - right);
  if (scopeOverflow > 0.01) laneScopeOverflows += 1;
  maximumLaneTextOverflow = Math.max(maximumLaneTextOverflow, scopeOverflow);
  for (const gap of texts.filter(item => item.textContent.startsWith('UNKNOWN_EVIDENCE_GAP'))){
    const box = gap.getBBox();
    const overflow = Math.max(left - box.x, box.x + box.width - right);
    if (overflow > 0.01) gapReasonOverflows += 1;
    maximumLaneTextOverflow = Math.max(maximumLaneTextOverflow, overflow);
  }
}
for (const group of noticeGroups) {
  const rect = group.querySelector(':scope > rect');
  const texts = [...group.querySelectorAll(':scope > text')];
  if (!rect || texts.length !== 2) {
    noticeTextOverflows += 1;
    maximumLaneTextOverflow = Number.POSITIVE_INFINITY;
    continue;
  }
  const left = Number(rect.getAttribute('x'));
  const right = left + Number(rect.getAttribute('width'));
  for (const item of texts) {
    const box = item.getBBox();
    const overflow = Math.max(left - box.x, box.x + box.width - right);
    if (overflow > 0.01) noticeTextOverflows += 1;
    maximumLaneTextOverflow = Math.max(maximumLaneTextOverflow, overflow);
  }
}
const firstNodeRect = nodeGroups[0]?.querySelector(':scope > rect');
const firstNodeLabel = nodeGroups[0]?.querySelectorAll(':scope > text')[1];
const firstLaneRect = laneGroups[0]?.querySelector(':scope > rect');
const firstScope = laneGroups[0]?.querySelectorAll(':scope > text')[1];
const firstGap = [...laneGroups.flatMap(group => [...group.querySelectorAll(':scope > text')])].find(item => item.textContent.startsWith('UNKNOWN_EVIDENCE_GAP'));
const horizontalOverflow = (text, left, right) => {
  const box = text.getBBox();
  return Math.max(0, left - box.x, box.x + box.width - right);
};
let wideNodeProbeOverflow = Number.POSITIVE_INFINITY;
let wideScopeProbeOverflow = Number.POSITIVE_INFINITY;
let wideGapProbeOverflow = Number.POSITIVE_INFINITY;
let maximumNoticeProbeOverflow = Number.POSITIVE_INFINITY;
if (firstNodeRect && firstNodeLabel) {
  firstNodeLabel.textContent = '界'.repeat(14) + '…';
  const left = Number(firstNodeRect.getAttribute('x'));
  wideNodeProbeOverflow = horizontalOverflow(firstNodeLabel, left, left + Number(firstNodeRect.getAttribute('width')));
}
if (firstLaneRect && firstScope) {
  firstScope.textContent = '界'.repeat(79) + '…';
  const left = Number(firstLaneRect.getAttribute('x'));
  wideScopeProbeOverflow = horizontalOverflow(firstScope, left, left + Number(firstLaneRect.getAttribute('width')));
}
if (firstLaneRect && firstGap) {
  firstGap.textContent = 'UNKNOWN_EVIDENCE_GAP — ' + '界'.repeat(59) + '…';
  const left = Number(firstLaneRect.getAttribute('x'));
  wideGapProbeOverflow = horizontalOverflow(firstGap, left, left + Number(firstLaneRect.getAttribute('width')));
}
if (firstLaneRect) {
  const probe = document.createElementNS('http://www.w3.org/2000/svg', 'text');
  probe.setAttribute('x', '100');
  probe.setAttribute('y', String(Number(firstLaneRect.getAttribute('y')) + 30));
  probe.setAttribute('font-family', 'ui-monospace, monospace');
  probe.setAttribute('font-size', '16');
  probe.textContent = 'visual relationship omitted — legacy evidence basis unavailable · HAD_TOKEN_PERMISSION · E001, E002, E003, E004, E005 · +507 more';
  svg.appendChild(probe);
  const noticeRect = noticeGroups[0]?.querySelector(':scope > rect');
  const noticeLeft = noticeRect ? Number(noticeRect.getAttribute('x')) : 52;
  const noticeRight = noticeRect
    ? noticeLeft + Number(noticeRect.getAttribute('width'))
    : svg.viewBox.baseVal.width - 70;
  maximumNoticeProbeOverflow = horizontalOverflow(probe, noticeLeft, noticeRight);
  probe.remove();
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
  routeUnderlays: routeUnderlays.length,
  invalidRouteUnderlays: invalidRouteUnderlays.length,
  ledgerTextOverflows,
  maximumLedgerOverflow,
  nodeRows: nodeGroups.length,
  nodeTextOverflows,
  maximumNodeOverflow,
  laneRows: laneGroups.length,
  laneScopeOverflows,
  gapReasonOverflows,
  noticeRows: noticeGroups.length,
  noticeTextOverflows,
  maximumLaneTextOverflow,
  wideNodeProbeOverflow,
  wideScopeProbeOverflow,
  wideGapProbeOverflow,
  maximumNoticeProbeOverflow,
  legendSeparation: temporalBox ? contradictionPaintStart - (temporalBox.x + temporalBox.width) : Number.NEGATIVE_INFINITY
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
    if state["routeUnderlays"] != state["relationshipLedgerRows"] or state["invalidRouteUnderlays"] != 0:
        raise AuditError(
            "standalone SVG route crossings lack one inert bounded underlay per relationship: "
            f"edges={state['relationshipLedgerRows']} underlays={state['routeUnderlays']} "
            f"invalid={state['invalidRouteUnderlays']}"
        )
    if state["nodeRows"] < 1 or state["nodeTextOverflows"] != 0:
        raise AuditError(
            "standalone SVG node text exceeds its fixed box: "
            f"nodes={state['nodeRows']} overflows={state['nodeTextOverflows']} "
            f"maximum={state['maximumNodeOverflow']}"
        )
    if state["laneRows"] < 1 or state["laneScopeOverflows"] != 0 or state["gapReasonOverflows"] != 0 or state["noticeTextOverflows"] != 0:
        raise AuditError(
            "standalone SVG scope, gap, or projection-notice text exceeds its lane: "
            f"lanes={state['laneRows']} scope={state['laneScopeOverflows']} "
            f"gaps={state['gapReasonOverflows']} notices={state['noticeTextOverflows']} "
            f"maximum={state['maximumLaneTextOverflow']}"
        )
    if state["wideNodeProbeOverflow"] > 0.01 or state["wideScopeProbeOverflow"] > 0.01 or state["wideGapProbeOverflow"] > 0.01 or state["maximumNoticeProbeOverflow"] > 0.01:
        raise AuditError(
            "standalone SVG conservative text geometry probe overflowed: "
            f"node={state['wideNodeProbeOverflow']} scope={state['wideScopeProbeOverflow']} "
            f"gap={state['wideGapProbeOverflow']} notice={state['maximumNoticeProbeOverflow']}"
        )
    if state["scrollWidth"] < state["widthAttribute"] or state["scrollHeight"] < state["heightAttribute"]:
        raise AuditError("standalone SVG right or bottom extent is unreachable")
    if state["legendSeparation"] < 12:
        raise AuditError(
            "standalone SVG legend relationship samples overlap: "
            f"separation={state['legendSeparation']}"
        )
    requests = page_request_urls(performance, graph_url)
    external = sorted({url for url in requests if urlsplit(url).scheme in {"http", "https", "ws", "wss"}})
    files = sorted({url for url in requests if urlsplit(url).scheme == "file"})
    severe = [item for item in console if item.get("level") == "SEVERE"]
    if external or files != [graph_url] or severe:
        raise AuditError("standalone SVG initiated an unexpected request or console error")
    state["pageRequests"] = len(requests)
    state["externalRequests"] = len(external)
    state["consoleErrors"] = len(severe)
    state["forcedColors"] = forced_colors
    return state


def audit_forced_color_routes(driver: Driver, selector: str) -> dict[str, object]:
    driver.session_call(
        "POST",
        "/goog/cdp/execute",
        {
            "cmd": "Emulation.setEmulatedMedia",
            "params": {
                "features": [
                    {"name": "prefers-color-scheme", "value": "dark"},
                    {"name": "forced-colors", "value": "active"},
                ]
            },
        },
    )
    state = driver.session_call(
        "POST",
        "/execute/sync",
        {
            "script": r"""
const svg = document.querySelector(arguments[0]);
const underlay = svg?.querySelector('polyline[data-route-underlay="true"]');
const foreground = underlay?.nextElementSibling;
return {
  active: matchMedia('(forced-colors: active)').matches,
  adjustment: svg ? getComputedStyle(svg).forcedColorAdjust : '',
  underlayStroke: underlay ? getComputedStyle(underlay).stroke : '',
  foregroundStroke: foreground ? getComputedStyle(foreground).stroke : ''
};
""",
            "args": [selector],
        },
    )["value"]
    driver.session_call(
        "POST",
        "/goog/cdp/execute",
        {
            "cmd": "Emulation.setEmulatedMedia",
            "params": {
                "features": [{"name": "prefers-color-scheme", "value": "dark"}]
            },
        },
    )
    if (
        not state["active"]
        or state["adjustment"] != "none"
        or not state["underlayStroke"]
        or not state["foregroundStroke"]
        or state["underlayStroke"] == state["foregroundStroke"]
    ):
        raise AuditError(f"forced-colors route topology is not preserved: {state}")
    return state


def audit(report: Path, driver: Driver) -> dict[str, object]:
    report_url = report.resolve().as_uri()
    driver.session_call(
        "POST",
        "/goog/cdp/execute",
        {
            "cmd": "Emulation.setEmulatedMedia",
            "params": {
                "features": [{"name": "prefers-color-scheme", "value": "dark"}]
            },
        },
    )
    driver.session_call("POST", "/log", {"type": "performance"})
    driver.session_call("POST", "/log", {"type": "browser"})
    driver.session_call("POST", "/url", {"url": report_url})
    forced_colors = audit_forced_color_routes(driver, ".temporal-path svg")
    state = driver.session_call(
        "POST",
        "/execute/sync",
        {
            "script": r"""
const counted = [...document.querySelectorAll('[data-finding-item][data-counted="true"]')];
const visible = () => counted.filter(item => !item.hidden).length;
const displayed = () => document.getElementById('visible-count').textContent;
const laneElements = [...document.querySelectorAll('[data-graph-item][data-visual-lane="true"][data-revision]')];
const inlineEdgeGroups = [...document.querySelectorAll('.temporal-path g[data-edge-id]')];
const inlineRouteUnderlays = inlineEdgeGroups.flatMap(group => [...group.querySelectorAll(':scope > polyline[data-route-underlay="true"]')]);
const invalidInlineRouteUnderlays = inlineRouteUnderlays.filter(item =>
  item.getAttribute('aria-hidden') !== 'true' ||
  item.getAttribute('stroke') !== '#FFFFFF' ||
  item.getAttribute('stroke-linejoin') !== 'round' ||
  item.getAttribute('stroke-linecap') !== 'butt'
);
const unique = values => [...new Set(values)].sort();
const tableRevisions = unique(counted.map(item => item.dataset.revision));
const laneRevisions = unique(laneElements.map(item => item.dataset.revision));
const filterStatus = document.getElementById('filter-status');
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
    shownLabel: document.getElementById('visual-shown-label')?.textContent || '',
    omittedText: Number(document.getElementById('visual-omitted').textContent),
    omittedLabel: document.getElementById('visual-omitted-label')?.textContent || '',
    statusText: filterStatus?.textContent || '',
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
let noMatch = null;
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
  const impossible = document.createElement('option');
  impossible.value = '__cirewind_no_match__';
  impossible.textContent = 'No-match audit value';
  filter.append(impossible);
  filter.value = impossible.value;
  filter.dispatchEvent(new Event('change'));
  noMatch = {
    visible: visible(),
    displayed: displayed(),
    emptyHidden: document.getElementById('filter-empty').hidden,
    statusText: filterStatus?.textContent || ''
  };
  impossible.remove();
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
  inlineEdgeGroups: inlineEdgeGroups.length,
  inlineRouteUnderlays: inlineRouteUnderlays.length,
  invalidInlineRouteUnderlays: invalidInlineRouteUnderlays.length,
  filterStatus: filterStatus ? {
    role: filterStatus.getAttribute('role'),
    live: filterStatus.getAttribute('aria-live'),
    atomic: filterStatus.getAttribute('aria-atomic')
  } : null,
  initial,
  filtered,
  noMatch,
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
    if state["filterStatus"] != {"role": "status", "live": "polite", "atomic": "true"}:
        raise AuditError("filter result summary is not a polite atomic live status")
    if state["initial"]["visible"] != state["counted"]:
        raise AuditError("initial report filter hid findings")
    if state["initial"]["displayed"] != str(state["counted"]):
        raise AuditError("initial visible-count text is inconsistent")
    if len(state["tableRevisions"]) != state["counted"]:
        raise AuditError("complete findings table contains duplicate or missing revisions")
    if not set(state["laneRevisions"]).issubset(state["tableRevisions"]):
        raise AuditError("visual contains a lane absent from the complete findings table")
    if state["inlineRouteUnderlays"] != state["inlineEdgeGroups"] or state["invalidInlineRouteUnderlays"] != 0:
        raise AuditError(
            "inline SVG route crossings lack one inert bounded underlay per relationship: "
            f"edges={state['inlineEdgeGroups']} underlays={state['inlineRouteUnderlays']} "
            f"invalid={state['invalidInlineRouteUnderlays']}"
        )
    if state["filtered"] is None:
        raise AuditError("report has no usable state filter")
    if state["filtered"]["visible"] != state["filtered"]["expected"]:
        raise AuditError("state filter displayed the wrong findings")
    if state["filtered"]["displayed"] != str(state["filtered"]["expected"]):
        raise AuditError("filtered visible-count text is inconsistent")
    visible_noun = "finding visible" if state["filtered"]["expected"] == 1 else "findings visible"
    if f"{state['filtered']['expected']} {visible_noun}" not in state["filtered"]["visual"]["statusText"]:
        raise AuditError("filtered live status does not announce its visible finding count")
    if state["filtered"]["tableRows"] != state["counted"]:
        raise AuditError("filter removed a finding from the complete findings table")
    if state["filtered"]["tableRevisions"] != state["tableRevisions"]:
        raise AuditError("filter changed the complete findings-table revision set")
    if state["reset"]["visible"] != state["counted"]:
        raise AuditError("filter reset did not restore all findings")
    if state["noMatch"] is None or state["noMatch"]["visible"] != 0 or state["noMatch"]["displayed"] != "0" or state["noMatch"]["emptyHidden"]:
        raise AuditError("no-match filter state is not represented visually")
    if "No findings match every selected filter." not in state["noMatch"]["statusText"]:
        raise AuditError("no-match filter state is absent from the live status")

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
        expected_shown_label = (
            "matching finding shown"
            if snapshot["shownText"] == 1
            else "matching findings shown"
        )
        if snapshot["shownLabel"] != expected_shown_label:
            raise AuditError(f"{label} visual shown-count grammar is inconsistent")
        expected_omitted_label = (
            "matching finding omitted"
            if snapshot["omittedText"] == 1
            else "matching findings omitted"
        )
        if snapshot["omittedLabel"] != expected_omitted_label:
            raise AuditError(f"{label} visual omitted-count grammar is inconsistent")
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
        "browserSandboxPolicy": "chromium-default",
        "findings": state["counted"],
        "filterState": state["filtered"]["state"],
        "filterMatches": state["filtered"]["visible"],
        "visualLanes": len(state["laneRevisions"]),
        "visualOmittedForFilter": state["filtered"]["visual"]["omittedText"],
        "pageRequests": len(requests),
        "externalRequests": len(external),
        "consoleErrors": len(severe),
        "cspHashesVerified": True,
        "forcedColors": forced_colors,
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
        remove_work_tree(work)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AuditError as error:
        print(f"browser audit failed: {error}", file=sys.stderr)
        raise SystemExit(1)
