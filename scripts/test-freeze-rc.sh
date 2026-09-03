#!/bin/sh

# Exercise the release-candidate freeze driver on a disposable synthetic commit.
#
# Usage: test-freeze-rc.sh WORK_ROOT
#
# Creates a deterministic throwaway repository from the current source set,
# proves the driver's argument rejections, runs a freeze with a fast subset of
# gates, and checks the frozen tree, the subject byte identity across the
# driver's three builds, the acquisition record round trip, and the ledger's
# recorded subset. Nothing touches the project index or any remote.

set -eu

if [ "$#" -ne 1 ]; then
	printf '%s\n' "usage: $0 WORK_ROOT" >&2
	exit 2
fi

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work_root=$1
mkdir -p -- "$work_root"
work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-rc-freeze-test.XXXXXX")
case "$work" in
	"$work_root"/cirewind-rc-freeze-test.*) ;;
	*)
		printf '%s\n' "refusing unsafe test workspace: $work" >&2
		exit 1
		;;
esac
cleanup() {
	trap - EXIT HUP INT TERM
	if [ -d "$work" ]; then rm -r -- "$work"; fi
}
trap cleanup EXIT HUP INT TERM

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
	git -C "$work/source" -c commit.gpgSign=false commit -q -s -m "release candidate freeze fixture"
commit=$(git -C "$work/source" rev-parse --verify HEAD)
driver="$work/source/scripts/freeze-rc.sh"

expect_rejection() {
	label=$1
	shift
	if "$@" >"$work/reject.log" 2>&1; then
		printf '%s\n' "freeze accepted $label" >&2
		exit 1
	fi
}
export CIREWIND_RELEASE_WORK_ROOT="$work_root"
expect_rejection "a v-prefixed version" env CIREWIND_RC_VERSION=v0.0.0 CIREWIND_RC_EXPECTED_DEFAULT_TIP="$commit" "$driver" "$work/out-v" "$commit"
expect_rejection "a pre-release version" env CIREWIND_RC_VERSION=0.0.0-rc.1 CIREWIND_RC_EXPECTED_DEFAULT_TIP="$commit" "$driver" "$work/out-rc" "$commit"
expect_rejection "a short commit" env CIREWIND_RC_VERSION=0.0.0 CIREWIND_RC_EXPECTED_DEFAULT_TIP="$commit" "$driver" "$work/out-short" "${commit%??????}"
expect_rejection "a missing default tip" env CIREWIND_RC_VERSION=0.0.0 "$driver" "$work/out-tip" "$commit"
printf '%s\n' "scratch" >"$work/source/DIRTY.tmp"
expect_rejection "a dirty tree" env CIREWIND_RC_VERSION=0.0.0 CIREWIND_RC_EXPECTED_DEFAULT_TIP="$commit" "$driver" "$work/out-dirty" "$commit"
rm -- "$work/source/DIRTY.tmp"
mkdir "$work/out-exists"
expect_rejection "an existing output directory" env CIREWIND_RC_VERSION=0.0.0 CIREWIND_RC_EXPECTED_DEFAULT_TIP="$commit" "$driver" "$work/out-exists" "$commit"

CIREWIND_RC_VERSION=0.0.0 CIREWIND_RC_EXPECTED_DEFAULT_TIP="$commit" CIREWIND_RC_SUITES=vet,history-scan \
	"$driver" "$work/frozen" "$commit"

for entry in subjects cirewind.rb README.md qualification.tsv rc-acquisition-record.json rc-acquisition-record.sha256; do
	if [ ! -e "$work/frozen/$entry" ]; then
		printf '%s\n' "frozen tree lacks $entry" >&2
		exit 1
	fi
done
(cd "$work/frozen" && sha256sum -c --quiet rc-acquisition-record.sha256)
grep -q '"intendedVersion":"0.0.0"' "$work/frozen/rc-acquisition-record.json"
grep -q "\"sourceCommit\":\"$commit\"" "$work/frozen/rc-acquisition-record.json"
grep -q '"immutableArtifact":null' "$work/frozen/rc-acquisition-record.json"
grep -q '"complete":false' "$work/frozen/rc-acquisition-record.json"
grep -q '"publication":"not-published' "$work/frozen/rc-acquisition-record.json"
awk -F'\t' '$1 == "vet" && $2 == "pass" { found++ } $1 == "history-scan" && $2 == "pass" { found++ } $1 == "test" && $2 == "skipped" { found++ } $1 == "suite-selection" && $2 == "skipped" { found++ } END { exit found == 4 ? 0 : 1 }' "$work/frozen/qualification.tsv"
grep -q "cirewind_0.0.0_linux_amd64" "$work/frozen/cirewind.rb"
grep -q "releases/download/v0.0.0/" "$work/frozen/cirewind.rb"

mkdir -p "$work/tool-tmp" "$work/go-tmp" "$work/go-cache"
export TMPDIR="$work/tool-tmp" GOTMPDIR="$work/go-tmp"
if [ -z "${GOCACHE:-}" ]; then export GOCACHE="$work/go-cache"; fi
go_version=$(awk '/^go / { print $2; exit }' "$root/go.mod")
export GOTOOLCHAIN="go$go_version" GOFLAGS=-mod=readonly
cd "$root"
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$work/releasetool" ./internal/releasetool
"$work/releasetool" verify-acquisition-record --dist "$work/frozen/subjects" --record "$work/frozen/rc-acquisition-record.json" >/dev/null
"$work/releasetool" verify --dist "$work/frozen/subjects" >/dev/null
printf '%s\n' "tampered" >"$work/frozen/subjects/extra.txt"
if "$work/releasetool" verify-acquisition-record --dist "$work/frozen/subjects" --record "$work/frozen/rc-acquisition-record.json" >/dev/null 2>&1; then
	printf '%s\n' "a distribution with an extra subject verified against the record" >&2
	exit 1
fi
printf '%s\n' "release candidate freeze driver test passed"
