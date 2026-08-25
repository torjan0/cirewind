#!/bin/sh

set -eu

platform=$(uname -s 2>/dev/null || printf '%s' unknown)
if [ "$platform" != Linux ]; then
  printf '%s\n' "complete preflight requires Linux because its vulnerability check isolates Go telemetry there (detected: $platform)" >&2
  exit 2
fi

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d "$root/.cirewind-preflight-tmp.XXXXXX")

case "$work" in
  "$root"/.cirewind-preflight-tmp.*) ;;
  *)
    printf '%s\n' "refusing unsafe preflight workspace: $work" >&2
    exit 1
    ;;
esac

cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/tmp" "$work/go-cache" "$work/bin"
export TMPDIR="$work/tmp"
export GOTMPDIR="$work/tmp"
export GOCACHE="$work/go-cache"
export GOFLAGS=-mod=readonly

cd "$root"

go_version=$(awk '/^go / { print $2; exit }' go.mod)
case "$go_version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *)
    printf '%s\n' "invalid Go version in go.mod: $go_version" >&2
    exit 1
    ;;
esac
export GOTOOLCHAIN="go$go_version"

actual_toolchain=$(go env GOVERSION)
if [ "$actual_toolchain" != "$GOTOOLCHAIN" ]; then
  printf '%s\n' "Go toolchain mismatch: got $actual_toolchain, want $GOTOOLCHAIN" >&2
  exit 1
fi
gofmt_bin=$(go env GOROOT)/bin/gofmt

unformatted=$("$gofmt_bin" -l cmd internal third_party)
if [ -n "$unformatted" ]; then
  printf '%s\n' "gofmt is required for:" "$unformatted" >&2
  exit 1
fi

git diff --check
git diff --cached --check
if [ "${CIREWIND_PREFLIGHT_REQUIRE_STAGED:-0}" = 1 ]; then
  if ! git diff --quiet; then
    printf '%s\n' "unstaged changes differ from the reviewed index" >&2
    exit 1
  fi
  untracked=$(git ls-files --others --exclude-standard)
  if [ -n "$untracked" ]; then
    printf '%s\n' "untracked files are outside the reviewed index:" "$untracked" >&2
    exit 1
  fi
fi
go mod tidy -diff
go mod verify
PYTHONDONTWRITEBYTECODE=1 python3 scripts/qualify_demo_test.py
go test ./... -count=1
go vet ./...
go test -race ./... -count=1
make vuln
make licenses

for target in \
  linux/amd64 linux/arm64 \
  darwin/amd64 darwin/arm64 \
  windows/amd64 windows/arm64
do
  target_os=${target%/*}
  target_arch=${target#*/}
  suffix=
  if [ "$target_os" = windows ]; then
    suffix=.exe
  fi
  CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
    go build -trimpath -o "$work/bin/cirewind-$target_os-$target_arch$suffix" ./cmd/cirewind
done

make demo BINARY="$work/bin/cirewind" DEMO_OUT="$work/case"
"$work/bin/cirewind" verify "$work/case"

printf '%s\n' "pre-public source preflight passed"
