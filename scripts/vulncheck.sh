#!/bin/sh

set -eu

platform=$(uname -s 2>/dev/null || printf '%s' unknown)
if [ "$platform" != Linux ]; then
  printf '%s\n' "vulnerability check requires Linux for isolated Go telemetry configuration (detected: $platform)" >&2
  exit 2
fi

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
toolchain=${GO_TOOLCHAIN:-}

case "$toolchain" in
  go[0-9]*.[0-9]*.[0-9]*) ;;
  *)
    printf '%s\n' "invalid or missing GO_TOOLCHAIN: $toolchain" >&2
    exit 1
    ;;
esac

work=$(mktemp -d "$root/.cirewind-vuln-tmp.XXXXXX")
case "$work" in
  "$root"/.cirewind-vuln-tmp.*) ;;
  *)
    printf '%s\n' "refusing unsafe vulnerability-check workspace: $work" >&2
    exit 1
    ;;
esac

cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/config"
export XDG_CONFIG_HOME="$work/config"
export GOTOOLCHAIN="$toolchain"

# Go telemetry is process-global user state. Isolate it from the operator's
# profile and explicitly disable it before running the scanner.
go telemetry off >/dev/null
go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...
