#!/usr/bin/env python3
"""Qualify the installed CIRewind demo on one native host.

The timed region is exactly the `cirewind demo` subprocess. That command does
not return successfully until its staged case has passed the production
manifest verifier. A second `cirewind verify` process then independently
checks each published case outside the timed region.
"""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import statistics
import subprocess
import sys
import time


TRIAL_COUNT = 5
P50_LIMIT_SECONDS = 15.0
MAX_LIMIT_SECONDS = 30.0
PROCESS_TIMEOUT_SECONDS = 31.0
REQUIRED_CASE_FILES = (
    "affected-runs.csv",
    "case.db",
    "collection-metadata.json",
    "evidence.jsonl",
    "findings.json",
    "graph.json",
    "graph.svg",
    "manifest.sha256",
    "report.html",
    "summary.md",
)
GITHUB_CREDENTIAL_VARIABLES = (
    "CIREWIND_GITHUB_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
)


class QualificationError(RuntimeError):
    """A qualification precondition or assertion failed."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def regular_file(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and not stat.S_ISLNK(mode)


def case_inventory(case_dir: Path) -> dict[str, tuple[int, str]]:
    if not case_dir.is_dir() or case_dir.is_symlink():
        raise QualificationError("demo did not publish a regular case directory")

    entries: dict[str, tuple[int, str]] = {}
    for entry in sorted(case_dir.iterdir(), key=lambda item: item.name):
        if not regular_file(entry):
            raise QualificationError(
                f"case contains a non-regular or nested entry: {entry.name}"
            )
        entries[entry.name] = (entry.stat().st_size, sha256_file(entry))

    expected = set(REQUIRED_CASE_FILES)
    actual = set(entries)
    missing = sorted(expected - actual)
    extras = sorted(actual - expected)
    if missing or extras:
        raise QualificationError(
            "case file contract mismatch: "
            f"missing={','.join(missing) or 'none'} "
            f"extra={','.join(extras) or 'none'}"
        )
    return entries


def compare_cases(reference: Path, candidate: Path) -> None:
    reference_inventory = case_inventory(reference)
    candidate_inventory = case_inventory(candidate)
    if reference_inventory != candidate_inventory:
        raise QualificationError("complete demo cases differ by size or SHA-256")
    for name in REQUIRED_CASE_FILES:
        if not filecmp.cmp(reference / name, candidate / name, shallow=False):
            raise QualificationError(f"complete demo cases differ in {name}")


def isolated_environment(trial_dir: Path) -> dict[str, str]:
    home = trial_dir / "home"
    temporary = trial_dir / "tmp"
    cache = trial_dir / "cache"
    unusable_path = trial_dir / "unusable-path"
    for directory in (home, temporary, cache):
        directory.mkdir(mode=0o700)

    environment = {
        "HOME": str(home),
        "XDG_CACHE_HOME": str(cache),
        "TMPDIR": str(temporary),
        "TMP": str(temporary),
        "TEMP": str(temporary),
        "PATH": str(unusable_path),
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HTTP_PROXY": "http://127.0.0.1:1",
        "HTTPS_PROXY": "http://127.0.0.1:1",
        "ALL_PROXY": "http://127.0.0.1:1",
        "NO_PROXY": "",
        "http_proxy": "http://127.0.0.1:1",
        "https_proxy": "http://127.0.0.1:1",
        "all_proxy": "http://127.0.0.1:1",
        "no_proxy": "",
    }
    # Go binaries are self-contained on the supported Windows targets, but
    # Windows still needs these non-secret OS variables for normal process
    # startup and path handling. No parent variable is copied by pattern.
    if os.name == "nt":
        for name in ("SystemRoot", "WINDIR", "COMSPEC", "PATHEXT"):
            if value := os.environ.get(name):
                environment[name] = value

    for name in GITHUB_CREDENTIAL_VARIABLES:
        if name in environment:
            raise QualificationError(f"isolated environment retained {name}")
    return environment


def run_checked(
    arguments: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    purpose: str,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            arguments,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=PROCESS_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise QualificationError(
            f"{purpose} exceeded {PROCESS_TIMEOUT_SECONDS:.0f} seconds"
        ) from error
    if result.returncode != 0:
        raise QualificationError(
            f"{purpose} failed with exit code {result.returncode}"
        )
    return result


def native_metadata() -> dict[str, object]:
    macos_version = platform.mac_ver()[0]
    metadata: dict[str, object] = {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "logicalCpuCount": os.cpu_count(),
    }
    if macos_version:
        metadata["macosVersion"] = macos_version
    if hasattr(os, "sysconf"):
        try:
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
            page_count = int(os.sysconf("SC_PHYS_PAGES"))
            metadata["physicalMemoryBytes"] = page_size * page_count
        except (OSError, TypeError, ValueError):
            pass
    return metadata


def require_native_platform(
    metadata: dict[str, object], require_macos_major: int | None, require_machine: str | None
) -> None:
    if require_macos_major is not None:
        if metadata.get("system") != "Darwin":
            raise QualificationError("host is not native macOS")
        version = str(metadata.get("macosVersion", ""))
        try:
            major = int(version.split(".", 1)[0])
        except ValueError as error:
            raise QualificationError("native macOS version is unavailable") from error
        if major != require_macos_major:
            raise QualificationError(
                f"native macOS major version is {major}, want {require_macos_major}"
            )
    if require_machine is not None:
        machine = str(metadata.get("machine", "")).lower()
        if machine != require_machine.lower():
            raise QualificationError(
                f"native machine is {machine or 'unknown'}, want {require_machine.lower()}"
            )


def record_homebrew(metadata: dict[str, object], work_root: Path, required: bool) -> None:
    if not required:
        return
    brew_name = shutil.which("brew")
    if not brew_name:
        raise QualificationError("Homebrew is unavailable on the reference host")
    brew = Path(brew_name).resolve(strict=True)
    if not regular_file(brew) or not os.access(brew, os.X_OK):
        raise QualificationError("Homebrew path is not a regular executable")

    check_dir = work_root / "homebrew-check"
    check_dir.mkdir(mode=0o700)
    environment = isolated_environment(check_dir)
    environment["PATH"] = os.pathsep.join(
        (str(brew.parent), "/usr/bin", "/bin", "/usr/sbin", "/sbin")
    )
    version = run_checked(
        [str(brew), "--version"],
        cwd=check_dir,
        environment=environment,
        purpose="Homebrew reference-host check",
    )
    first_line = version.stdout.splitlines()[0].strip() if version.stdout else ""
    if not first_line or any(ord(character) < 0x20 for character in first_line):
        raise QualificationError("Homebrew returned an invalid version line")
    metadata["homebrewVersion"] = first_line[:160]


def resolve_binary(binary: str, work_root: Path, source_root: Path) -> Path:
    if binary:
        path = Path(binary).expanduser().resolve(strict=True)
        if not regular_file(path) or not os.access(path, os.X_OK):
            raise QualificationError("specified CIRewind binary is not executable")
        return path

    go = shutil.which("go")
    if not go:
        raise QualificationError("go is unavailable and --binary was not provided")
    output = work_root / "bin" / ("cirewind.exe" if os.name == "nt" else "cirewind")
    output.parent.mkdir(mode=0o700)
    result = subprocess.run(
        [go, "build", "-trimpath", "-o", str(output), "./cmd/cirewind"],
        cwd=source_root,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=300,
        check=False,
    )
    if result.returncode != 0:
        raise QualificationError(
            f"build current CIRewind binary failed with exit code {result.returncode}"
        )
    if not regular_file(output) or not os.access(output, os.X_OK):
        raise QualificationError("build did not produce an executable CIRewind binary")
    return output.resolve(strict=True)


def source_commit(value: str) -> str:
    if not value:
        return ""
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise QualificationError("source commit must be a lowercase full Git object ID")
    return value


def qualify(arguments: argparse.Namespace) -> dict[str, object]:
    source_root = Path(arguments.source_root).expanduser().resolve(strict=True)
    work_root = Path(arguments.work_root).expanduser().resolve(strict=False)
    if work_root.exists() or work_root.is_symlink():
        raise QualificationError("work root already exists; qualification requires a clean path")
    work_root.mkdir(mode=0o700, parents=True)

    metadata = native_metadata()
    require_native_platform(
        metadata, arguments.require_macos_major, arguments.require_machine
    )
    record_homebrew(metadata, work_root, arguments.require_homebrew)
    binary = resolve_binary(arguments.binary, work_root, source_root)
    qualified_commit = source_commit(arguments.source_commit)
    binary_hash = sha256_file(binary)
    binary_size = binary.stat().st_size

    durations: list[float] = []
    case_dirs: list[Path] = []
    for trial_number in range(1, TRIAL_COUNT + 1):
        trial_dir = work_root / f"trial-{trial_number:02d}"
        trial_dir.mkdir(mode=0o700)
        case_dir = trial_dir / "case"
        environment = isolated_environment(trial_dir)

        started = time.monotonic_ns()
        demo = run_checked(
            [str(binary), "demo", "--out", str(case_dir)],
            cwd=trial_dir,
            environment=environment,
            purpose=f"demo trial {trial_number}",
        )
        elapsed = (time.monotonic_ns() - started) / 1_000_000_000
        durations.append(elapsed)
        if "manifest: verified" not in demo.stdout:
            raise QualificationError(
                f"demo trial {trial_number} omitted its built-in verification result"
            )
        if elapsed > MAX_LIMIT_SECONDS:
            raise QualificationError(
                f"demo trial {trial_number} took {elapsed:.3f}s; limit is {MAX_LIMIT_SECONDS:.0f}s"
            )

        case_inventory(case_dir)
        verified = run_checked(
            [str(binary), "verify", str(case_dir)],
            cwd=trial_dir,
            environment=environment,
            purpose=f"independent verification for trial {trial_number}",
        )
        if "case manifest verified (cirewind.case/v1alpha2)" not in verified.stdout:
            raise QualificationError(
                f"independent verification for trial {trial_number} returned an unexpected contract"
            )
        case_dirs.append(case_dir)

    reference = case_dirs[0]
    for candidate in case_dirs[1:]:
        compare_cases(reference, candidate)
    if sha256_file(binary) != binary_hash or binary.stat().st_size != binary_size:
        raise QualificationError("CIRewind binary changed during qualification")

    p50 = statistics.median(durations)
    maximum = max(durations)
    if p50 > P50_LIMIT_SECONDS:
        raise QualificationError(
            f"T_demo p50 is {p50:.3f}s; limit is {P50_LIMIT_SECONDS:.0f}s"
        )

    reference_inventory = case_inventory(reference)
    result: dict[str, object] = {
        "schemaVersion": "cirewind.demo-qualification/v1alpha1",
        "platform": metadata,
        "binarySha256": binary_hash,
        "binaryBytes": binary_size,
        "trialCount": TRIAL_COUNT,
        "tDemoSeconds": [round(value, 6) for value in durations],
        "tDemoP50Seconds": round(p50, 6),
        "tDemoMaxSeconds": round(maximum, 6),
        "limits": {
            "p50Seconds": P50_LIMIT_SECONDS,
            "perRunSeconds": MAX_LIMIT_SECONDS,
        },
        "caseFileCount": len(reference_inventory),
        "caseSha256": {
            name: reference_inventory[name][1] for name in REQUIRED_CASE_FILES
        },
        "credentialsInherited": False,
        "pathUsableByDemo": False,
        "perTrialCache": True,
        "independentVerification": True,
        "completeCasesByteIdentical": True,
        "status": "PASS",
    }
    if qualified_commit:
        result["sourceCommit"] = qualified_commit
    result_path = work_root / "qualification-result.json"
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    os.chmod(result_path, 0o600)
    return result


def parse_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run five clean native CIRewind demo trials, independently verify "
            "them, and enforce the v0.2 T_demo launch gate."
        )
    )
    parser.add_argument(
        "--binary",
        default="",
        help="existing CIRewind binary; otherwise build the current checkout",
    )
    parser.add_argument(
        "--source-root",
        default=str(Path(__file__).resolve().parent.parent),
        help="repository root used when --binary is omitted",
    )
    parser.add_argument(
        "--source-commit",
        default="",
        help="optional lowercase full Git object ID bound to the result",
    )
    parser.add_argument(
        "--work-root",
        required=True,
        help="new directory that will retain the five cases and result JSON",
    )
    parser.add_argument(
        "--require-macos-major",
        type=int,
        default=None,
        help="fail unless running natively on this macOS major version",
    )
    parser.add_argument(
        "--require-machine",
        default=None,
        help="fail unless platform.machine() exactly matches this value",
    )
    parser.add_argument(
        "--require-homebrew",
        action="store_true",
        help="fail unless Homebrew is installed and reports its version",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    try:
        result = qualify(parse_arguments(argv))
    except (QualificationError, OSError) as error:
        print(f"demo qualification: FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
