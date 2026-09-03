#!/bin/sh

set -eu

if [ "$#" -ne 5 ]; then
	printf '%s\n' "usage: $0 RELEASE_DIRECTORY VERSION COMMIT BUILD_DATE WORK_ROOT" >&2
	exit 2
fi

distribution=$1
version=$2
commit=$3
build_date=$4
work_root=$5
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

CIREWIND_RELEASE_WORK_ROOT="$work_root" "$root/scripts/verify-release.sh" "$distribution"

case "$(uname -s)" in
	Linux) target_os=linux ;;
	Darwin) target_os=darwin ;;
	*)
		printf '%s\n' "native release smoke supports Linux and macOS hosts" >&2
		exit 2
		;;
esac
case "$(uname -m)" in
	x86_64|amd64) target_arch=amd64 ;;
	aarch64|arm64) target_arch=arm64 ;;
	*)
		printf '%s\n' "unsupported native architecture: $(uname -m)" >&2
		exit 2
		;;
esac

work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-release-smoke.XXXXXX")
case "$work" in
	"$work_root"/cirewind-release-smoke.*) ;;
	*)
		printf '%s\n' "refusing unsafe smoke workspace: $work" >&2
		exit 1
		;;
esac
cleanup() {
	trap - EXIT HUP INT TERM
	if [ -d "$work" ]; then rm -r -- "$work"; fi
}
trap cleanup EXIT HUP INT TERM

base="cirewind_${version}_${target_os}_${target_arch}"
archive="$distribution/$base.tar.gz"
if [ ! -f "$archive" ]; then
	printf '%s\n' "native release archive is missing: $archive" >&2
	exit 1
fi
tar -xzf "$archive" -C "$work"
bundle="$work/$base"
binary="$bundle/cirewind"

unset CIREWIND_GITHUB_TOKEN GITHUB_TOKEN GH_TOKEN
actual_version=$("$binary" version)
expected_version="cirewind $version (commit $commit, built $build_date)"
if [ "$actual_version" != "$expected_version" ]; then
	printf '%s\n' "release version metadata mismatch" "got:  $actual_version" "want: $expected_version" >&2
	exit 1
fi

"$binary" --help >/dev/null
"$binary" investigate --help >/dev/null 2>&1
"$binary" pack validate "$bundle/incidents/synthetic/mutable-tag.yaml" >/dev/null
if [ ! -f "$bundle/incidents/reviewed/index.json" ]; then
	printf '%s\n' "release archive omits the reviewed-pack index" >&2
	exit 1
fi
for reviewed in "$bundle"/incidents/reviewed/*/*.yaml; do
	[ -e "$reviewed" ] || continue
	"$binary" pack validate "$reviewed" >/dev/null
done
"$binary" archive --import-fixture synthetic --store "$work/archive.db" >/dev/null
"$binary" replay \
	--archive "$work/archive.db" \
	--incident "$bundle/incidents/synthetic/mutable-tag.yaml" \
	--out "$work/case" \
	--fixed-collection-time 2026-08-20T00:00:00Z >/dev/null
"$binary" verify "$work/case" >/dev/null

# The release binary must generate the complete deterministic synthetic case
# outside the checkout, twice, without raw materialization.
"$binary" demo --out "$work/demo" >/dev/null
"$binary" verify "$work/demo" >/dev/null
"$binary" demo --out "$work/demo-again" >/dev/null
for name in report.html graph.svg graph.json findings.json affected-runs.csv summary.md collection-metadata.json evidence.jsonl case.db manifest.sha256; do
	if [ ! -f "$work/demo/$name" ]; then
		printf '%s\n' "release demo omitted $name" >&2
		exit 1
	fi
	if ! cmp -s "$work/demo/$name" "$work/demo-again/$name"; then
		printf '%s\n' "release demo is not deterministic: $name differs between runs" >&2
		exit 1
	fi
done
if [ -e "$work/demo/raw" ]; then
	printf '%s\n' "release demo materialized raw content" >&2
	exit 1
fi

printf '%s\n' "native release smoke passed for $target_os/$target_arch (network credentials unset; demo deterministic)"
