#!/bin/sh
# Build a sample site from the current source and audit it in sandboxed,
# network-denied Chromium behind a loopback server under the project Pages
# base path. Usage: site-browser-audit.sh [VERSION]

set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
version=${1:-0.2.0}
work_root=${CIREWIND_BROWSER_AUDIT_ROOT:-${TMPDIR:-/tmp}}
work_root=$(CDPATH='' cd -- "$work_root" && pwd)
work=$(mktemp -d "$work_root/cirewind-site-audit.XXXXXX")

case "$work" in
  "$work_root"/cirewind-site-audit.*) ;;
  *)
    printf '%s\n' "refusing unsafe site audit workspace: $work" >&2
    exit 1
    ;;
esac

cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/tmp"
export TMPDIR="$work/tmp"
export GOTMPDIR="$work/tmp"

go_version=$(awk '/^go / { print $2; exit }' "$root/go.mod")
case "$go_version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *)
    printf '%s\n' "invalid Go version in go.mod: $go_version" >&2
    exit 1
    ;;
esac
export GOTOOLCHAIN="go$go_version"
export GOFLAGS=-mod=readonly
export CGO_ENABLED=0

cd "$root"
PYTHONDONTWRITEBYTECODE=1 python3 "$root/scripts/site_browser_audit_test.py"
TMPDIR="$work_root" PYTHONDONTWRITEBYTECODE=1 python3 "$root/scripts/site_browser_audit.py" --preflight --work-root "$work_root"

source_commit=$(git rev-parse --verify 'HEAD^{commit}')
toolchain_version=$(go env GOVERSION)
go build -trimpath -o "$work/cirewind" ./cmd/cirewind
go build -trimpath -o "$work/samplesite" ./tools/samplesite
"$work/cirewind" demo --out "$work/case" >/dev/null
"$work/samplesite" build \
  --case "$work/case" \
  --out "$work/site" \
  --version "$version" \
  --source-commit "$source_commit" \
  --go-version "$toolchain_version" >/dev/null

TMPDIR="$work_root" PYTHONDONTWRITEBYTECODE=1 python3 "$root/scripts/site_browser_audit.py" \
  "$work/site" --version "$version" --base-path /cirewind/ --work-root "$work_root"

printf '%s\n' "offline sandboxed Chromium sample-site audit passed"
