#!/bin/sh

set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work_root=${CIREWIND_BROWSER_AUDIT_ROOT:-${TMPDIR:-/tmp}}
work_root=$(CDPATH='' cd -- "$work_root" && pwd)
work=$(mktemp -d "$work_root/cirewind-browser-audit.XXXXXX")

case "$work" in
  "$work_root"/cirewind-browser-audit.*) ;;
  *)
    printf '%s\n' "refusing unsafe browser audit workspace: $work" >&2
    exit 1
    ;;
esac

cleanup() {
  rm -r -- "$work"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/tmp" "$work/go-cache"
export TMPDIR="$work/tmp"
export GOTMPDIR="$work/tmp"
export GOCACHE="$work/go-cache"

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
go build -trimpath -o "$work/cirewind" "$root/cmd/cirewind"
"$root/scripts/demo.sh" "$work/case" "$work/cirewind"
TMPDIR="$work_root" python3 "$root/scripts/browser_audit.py" \
  "$work/case/report.html" --work-root "$work_root"

printf '%s\n' "offline Chromium report audit passed"
