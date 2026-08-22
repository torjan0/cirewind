#!/bin/sh

set -eu

if [ "$#" -ne 2 ]; then
	printf '%s\n' "usage: $0 OUTPUT_DIR vSEMVER" >&2
	exit 2
fi

output=$1
tag=$2
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

cd "$root"
if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
	printf '%s\n' "release candidates require a completely clean, committed source tree" >&2
	exit 1
fi

head_commit=$("$root/scripts/verify-release-ref.sh" "$tag")

if git ls-tree -r "$head_commit" | awk '$1 == "160000" { found=1 } END { exit !found }'; then
	printf '%s\n' "release source contains a Git submodule; snapshot behavior must be reviewed explicitly" >&2
	exit 1
fi

version=${tag#v}
source_date_epoch=$(git show -s --format=%ct "$head_commit")

# Build from an immutable Git-object snapshot so a concurrent working-tree edit
# cannot produce a mixed-source target matrix after the cleanliness check.
work_root=${CIREWIND_RELEASE_WORK_ROOT:-${TMPDIR:-/tmp}}
mkdir -p -- "$work_root"
work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-release-source.XXXXXX")
case "$work" in
	"$work_root"/cirewind-release-source.*) ;;
	*)
		printf '%s\n' "refusing unsafe release source workspace: $work" >&2
		exit 1
		;;
esac
cleanup() {
	trap - EXIT HUP INT TERM
	if [ -d "$work" ]; then rm -r -- "$work"; fi
}
trap cleanup EXIT HUP INT TERM

mkdir "$work/source"
git archive --format=tar --output="$work/source.tar" "$head_commit"
tar -xf "$work/source.tar" -C "$work/source"
if find "$work/source" -type l -print -quit | grep -q .; then
	printf '%s\n' "release source snapshot contains a symbolic link; review is required" >&2
	exit 1
fi

"$work/source/scripts/build-release.sh" "$version" "$head_commit" "$source_date_epoch" "$output"
