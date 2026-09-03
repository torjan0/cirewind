#!/bin/sh
# Build the deterministic synthetic sample site twice from the current source
# revision and publish one audited copy.
#
# Usage: build-sample-site.sh OUTPUT_DIR VERSION
#
# VERSION is canonical SemVer without a v prefix. The working tree must be
# clean unless CIREWIND_SITE_ALLOW_DIRTY=1 is set for a local trial; the
# provenance record names the exact HEAD commit, so a dirty tree would
# misattribute the bytes. Set CIREWIND_SITE_WORK_ROOT to place the private
# workspace somewhere other than TMPDIR.

set -eu

usage='usage: build-sample-site.sh OUTPUT_DIR VERSION'
output=${1:?$usage}
version=${2:?$usage}

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

case "$version" in
  v*)
    printf '%s\n' "version must not carry a v prefix: $version" >&2
    exit 2
    ;;
  *[!0-9A-Za-z.-]*|'')
    printf '%s\n' "version contains characters outside SemVer: $version" >&2
    exit 2
    ;;
esac

if [ -e "$output" ]; then
  printf '%s\n' "output already exists and will not be overwritten: $output" >&2
  exit 1
fi

work_root=${CIREWIND_SITE_WORK_ROOT:-${TMPDIR:-/tmp}}
work_root=$(CDPATH='' cd -- "$work_root" && pwd)
work=$(mktemp -d "$work_root/cirewind-sample-site.XXXXXX")

case "$work" in
  "$work_root"/cirewind-sample-site.*) ;;
  *)
    printf '%s\n' "refusing unsafe sample-site workspace: $work" >&2
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

if [ "${CIREWIND_SITE_ALLOW_DIRTY:-0}" != 1 ]; then
  if ! git diff --quiet || ! git diff --cached --quiet; then
    printf '%s\n' "working tree is not clean; commit first or set CIREWIND_SITE_ALLOW_DIRTY=1 for a local trial" >&2
    exit 1
  fi
fi

source_commit=$(git rev-parse --verify 'HEAD^{commit}')
toolchain_version=$(go env GOVERSION)

go build -trimpath -o "$work/cirewind" ./cmd/cirewind
go build -trimpath -o "$work/samplesite" ./tools/samplesite

"$work/cirewind" demo --out "$work/case-a" >/dev/null
"$work/cirewind" demo --out "$work/case-b" >/dev/null
"$work/cirewind" verify "$work/case-a" >/dev/null
"$work/cirewind" verify "$work/case-b" >/dev/null
if ! diff -r "$work/case-a" "$work/case-b" >/dev/null; then
  printf '%s\n' "two demo generations from the same source differ; refusing to publish" >&2
  exit 1
fi

for side in a b; do
  "$work/samplesite" build \
    --case "$work/case-$side" \
    --out "$work/site-$side" \
    --version "$version" \
    --source-commit "$source_commit" \
    --go-version "$toolchain_version" >"$work/build-$side.json"
done
if ! diff -r "$work/site-a" "$work/site-b" >/dev/null; then
  printf '%s\n' "two site builds from the same case differ; refusing to publish" >&2
  exit 1
fi
grep -v '"siteDir"' "$work/build-a.json" >"$work/build-a.compare"
grep -v '"siteDir"' "$work/build-b.json" >"$work/build-b.compare"
if ! cmp -s "$work/build-a.compare" "$work/build-b.compare"; then
  printf '%s\n' "two site build records differ beyond their staging paths; refusing to publish" >&2
  exit 1
fi

"$work/samplesite" verify --site "$work/site-a" --version "$version" >"$work/verify.json"

output_parent=$(dirname -- "$output")
mkdir -p -- "$output_parent"
mv -- "$work/site-a" "$output"
cat "$work/verify.json"
printf '%s\n' "sample site v$version published to $output from $source_commit ($toolchain_version)" >&2
