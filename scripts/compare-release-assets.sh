#!/bin/sh

set -eu

if [ "$#" -ne 3 ]; then
	printf '%s\n' "usage: $0 EXPECTED_DIRECTORY DOWNLOADED_DIRECTORY WORK_ROOT" >&2
	exit 2
fi

expected=$1
downloaded=$2
work_root=$3
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

CIREWIND_RELEASE_WORK_ROOT="$work_root" "$root/scripts/verify-release.sh" "$expected" >/dev/null
CIREWIND_RELEASE_WORK_ROOT="$work_root" "$root/scripts/verify-release.sh" "$downloaded" >/dev/null

mkdir -p -- "$work_root"
work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-release-compare.XXXXXX")
case "$work" in
"$work_root"/cirewind-release-compare.*) ;;
*)
	printf '%s\n' "refusing unsafe release comparison workspace: $work" >&2
	exit 1
	;;
esac
cleanup() {
	trap - EXIT HUP INT TERM
	if [ -d "$work" ]; then rm -r -- "$work"; fi
}
trap cleanup EXIT HUP INT TERM

go_version=$(awk '/^go / { print $2; exit }' "$root/go.mod")
GOTOOLCHAIN="go$go_version" GOFLAGS=-mod=readonly CGO_ENABLED=0 \
	go build -trimpath -buildvcs=false -o "$work/releasetool" "$root/internal/releasetool"
"$work/releasetool" compare --first "$expected" --second "$downloaded"
