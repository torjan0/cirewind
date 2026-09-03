#!/bin/sh

set -eu

if [ "$#" -ne 6 ]; then
	printf '%s\n' "usage: $0 RELEASE_DIRECTORY VERSION COMMIT BUILD_DATE WORK_ROOT WINE_PREFIX" >&2
	exit 2
fi

distribution=$1
version=$2
commit=$3
build_date=$4
work_root=$5
wine_prefix=$6
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v wine >/dev/null 2>&1; then
	printf '%s\n' "Wine is not installed" >&2
	exit 1
fi

CIREWIND_RELEASE_WORK_ROOT="$work_root" "$root/scripts/verify-release.sh" "$distribution"
mkdir -p -- "$work_root" "$wine_prefix"
work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
wine_prefix=$(CDPATH='' cd -- "$wine_prefix" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-release-wine.XXXXXX")
case "$work" in
"$work_root"/cirewind-release-wine.*) ;;
*)
	printf '%s\n' "refusing unsafe Wine smoke workspace: $work" >&2
	exit 1
	;;
esac
cleanup() {
	trap - EXIT HUP INT TERM
	if [ -d "$work" ]; then rm -r -- "$work"; fi
}
trap cleanup EXIT HUP INT TERM

base="cirewind_${version}_windows_amd64"
archive="$distribution/$base.zip"
if [ ! -f "$archive" ]; then
	printf '%s\n' "Windows amd64 release archive is missing: $archive" >&2
	exit 1
fi
mkdir "$work/bundle"
(cd "$work/bundle" && unzip -qq "$archive")
bundle="$work/bundle/$base"

unset CIREWIND_GITHUB_TOKEN GITHUB_TOKEN GH_TOKEN
export WINEPREFIX="$wine_prefix"
export WINEARCH=win64
export WINEDEBUG=-all
export WINEDLLOVERRIDES=mscoree,mshtml=
export TMPDIR="$work"
export TMP="$work"
export TEMP="$work"

cd "$bundle"
actual_version=$(wine ./cirewind.exe version | tr -d '\r')
expected_version="cirewind $version (commit $commit, built $build_date)"
if [ "$actual_version" != "$expected_version" ]; then
	printf '%s\n' "Wine release version metadata mismatch" "got:  $actual_version" "want: $expected_version" >&2
	exit 1
fi

wine ./cirewind.exe --help >/dev/null
wine ./cirewind.exe investigate --help >/dev/null 2>&1
wine ./cirewind.exe pack validate 'incidents\synthetic\mutable-tag.yaml' >/dev/null
if [ ! -f incidents/reviewed/index.json ]; then
	printf '%s\n' "release archive omits the reviewed-pack index" >&2
	exit 1
fi
for reviewed in incidents/reviewed/*/*.yaml; do
	[ -e "$reviewed" ] || continue
	wine ./cirewind.exe pack validate "$reviewed" >/dev/null
done
wine ./cirewind.exe archive --import-fixture synthetic --store "$work/archive.db" >/dev/null
wine ./cirewind.exe replay \
	--archive "$work/archive.db" \
	--incident 'incidents\synthetic\mutable-tag.yaml' \
	--out "$work/case" \
	--fixed-collection-time 2026-08-20T00:00:00Z >/dev/null
wine ./cirewind.exe verify "$work/case" >/dev/null
wine ./cirewind.exe demo --out "$work/demo" >/dev/null
wine ./cirewind.exe verify "$work/demo" >/dev/null
wine ./cirewind.exe demo --out "$work/demo-again" >/dev/null
for name in report.html graph.svg graph.json findings.json affected-runs.csv summary.md collection-metadata.json evidence.jsonl case.db manifest.sha256; do
	if [ ! -f "$work/demo/$name" ]; then
		printf '%s\n' "Wine release demo omitted $name" >&2
		exit 1
	fi
	if ! cmp -s "$work/demo/$name" "$work/demo-again/$name"; then
		printf '%s\n' "Wine release demo is not deterministic: $name differs between runs" >&2
		exit 1
	fi
done

printf '%s\n' "Windows/amd64 archive compatibility smoke passed under Wine (not native Windows qualification; demo deterministic)"
