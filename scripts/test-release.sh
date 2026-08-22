#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
	printf '%s\n' "usage: $0 WORK_ROOT" >&2
	exit 2
fi

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work_root=$1
mkdir -p -- "$work_root"
work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-release-contract.XXXXXX")
case "$work" in
	"$work_root"/cirewind-release-contract.*) ;;
	*)
		printf '%s\n' "refusing unsafe release contract workspace: $work" >&2
		exit 1
		;;
esac
cleanup() {
	trap - EXIT HUP INT TERM
	if [ -d "$work" ]; then rm -r -- "$work"; fi
}
trap cleanup EXIT HUP INT TERM

# Create a disposable, deterministic source commit so the test exercises the
# clean-tag and immutable-snapshot wrapper without touching the project index.
version=0.0.0-repro.test
build_date=2000-01-01T00:00:00Z
mkdir "$work/source"
git -C "$root" ls-files --cached --others --exclude-standard -z >"$work/source-files"
tar -C "$root" --null --files-from="$work/source-files" -cf "$work/source.tar"
tar -xf "$work/source.tar" -C "$work/source"
git -C "$work/source" init -q -b main
git -C "$work/source" config user.name "CIRewind Release Fixture"
git -C "$work/source" config user.email "release-fixture@invalid.example"
git -C "$work/source" add -A
GIT_AUTHOR_DATE="$build_date" GIT_COMMITTER_DATE="$build_date" \
	git -C "$work/source" -c commit.gpgSign=false commit -q -s -m "release packaging fixture"
GIT_COMMITTER_DATE="$build_date" \
	git -C "$work/source" -c tag.gpgSign=false tag -a "v$version" -m "release packaging fixture"
commit=$(git -C "$work/source" rev-parse --verify HEAD)

export CIREWIND_RELEASE_WORK_ROOT="$work_root"
"$work/source/scripts/release.sh" "$work/first" "v$version"
"$work/source/scripts/release.sh" "$work/second" "v$version"

mkdir -p "$work/tool-tmp" "$work/go-tmp" "$work/go-cache"
export TMPDIR="$work/tool-tmp"
export GOTMPDIR="$work/go-tmp"
if [ -z "${GOCACHE:-}" ]; then
	export GOCACHE="$work/go-cache"
fi
go_version=$(awk '/^go / { print $2; exit }' "$root/go.mod")
export GOTOOLCHAIN="go$go_version"
export GOFLAGS=-mod=readonly
cd "$root"
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$work/releasetool" ./internal/releasetool
"$work/releasetool" compare --first "$work/first" --second "$work/second"
"$root/scripts/smoke-release.sh" "$work/first" "$version" "$commit" "$build_date" "$work_root"

# Integrity verification must fail after a one-byte material-file change.
printf '%s' x >>"$work/first/cirewind_${version}_linux_amd64.spdx.json"
if "$work/releasetool" verify --dist "$work/first" >/dev/null 2>&1; then
	printf '%s\n' "release verifier accepted a tampered SBOM" >&2
	exit 1
fi

printf '%s\n' "release packaging contract passed for clean annotated-tag snapshot, all six archives, native runtime, and tamper rejection"
