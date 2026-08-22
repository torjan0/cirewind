#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
	printf '%s\n' "usage: $0 RELEASE_DIRECTORY" >&2
	exit 2
fi

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
distribution=$(CDPATH='' cd -- "$1" && pwd -P)
work_root=${CIREWIND_RELEASE_WORK_ROOT:-${TMPDIR:-/tmp}}
mkdir -p -- "$work_root"
work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-release-verify.XXXXXX")
case "$work" in
	"$work_root"/cirewind-release-verify.*) ;;
	*)
		printf '%s\n' "refusing unsafe release verification workspace: $work" >&2
	exit 1
	;;
esac
cleanup() {
	trap - EXIT HUP INT TERM
	if [ -d "$work" ]; then rm -r -- "$work"; fi
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/tmp" "$work/go-tmp" "$work/go-cache"
export TMPDIR="$work/tmp"
export GOTMPDIR="$work/go-tmp"
if [ -z "${GOCACHE:-}" ]; then
	export GOCACHE="$work/go-cache"
fi
export GOFLAGS=-mod=readonly
go_version=$(awk '/^go / { print $2; exit }' "$root/go.mod")
export GOTOOLCHAIN="go$go_version"
cd "$root"
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$work/releasetool" ./internal/releasetool
"$work/releasetool" verify --dist "$distribution"
