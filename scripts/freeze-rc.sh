#!/bin/sh

# Freeze and locally qualify one exact release candidate (DIST-007 preparation).
#
# Usage: freeze-rc.sh OUTPUT_DIR COMMIT
#
# Required environment:
#   CIREWIND_RC_VERSION              intended final version, plain MAJOR.MINOR.PATCH
#                                    (never a v prefix, never a pre-release suffix)
#   CIREWIND_RC_EXPECTED_DEFAULT_TIP full commit recorded as the old default-branch
#                                    tip for the merge freeze; recorded, never fetched
# Optional environment:
#   CIREWIND_RC_SOURCE_DATE_EPOCH    fixed source date (default: committer time of COMMIT)
#   CIREWIND_RELEASE_WORK_ROOT       large private work directory
#   CIREWIND_RC_SUITES               "all" (default) or a comma-separated subset of the
#                                    local gates; a subset is itself recorded as skipped
#   CIREWIND_BREW                    Homebrew executable for the formula install gate
#
# The driver builds from an immutable snapshot of COMMIT, never from the working
# tree, and requires COMMIT to be HEAD of a clean checkout because the gate
# suites run against the checkout. It publishes nothing: no tag, release,
# artifact, attestation, or network write. Gates that exit with status 2 for a
# missing prerequisite are recorded as skipped; any other failure stops the
# freeze. The resulting acquisition record states that nothing is published and
# leaves the immutable artifact fields empty for an authorized hosted run.

set -eu

if [ "$#" -ne 2 ]; then
	printf '%s\n' "usage: $0 OUTPUT_DIR COMMIT" >&2
	exit 2
fi

output=$1
commit=$2
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
version=${CIREWIND_RC_VERSION:-}
expected_tip=${CIREWIND_RC_EXPECTED_DEFAULT_TIP:-}
suites_selection=${CIREWIND_RC_SUITES:-all}

fail() {
	printf '%s\n' "$1" >&2
	exit 1
}

case "$version" in
	'') fail "CIREWIND_RC_VERSION is required" ;;
	v*) fail "CIREWIND_RC_VERSION must not carry a v prefix; the source tag is never the version" ;;
	*-*|*+*) fail "CIREWIND_RC_VERSION must be the intended final version without a pre-release or build suffix" ;;
esac
if ! printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
	fail "CIREWIND_RC_VERSION must be MAJOR.MINOR.PATCH"
fi
for object in "$commit" "$expected_tip"; do
	if ! printf '%s\n' "$object" | grep -Eq '^[0-9a-f]{40}$'; then
		fail "commit and expected default tip must be full lowercase SHA-1 object IDs"
	fi
done
if [ -e "$output" ]; then
	fail "output directory already exists: $output"
fi
output_parent=$(dirname -- "$output")
mkdir -p -- "$output_parent"
output_parent=$(CDPATH='' cd -- "$output_parent" && pwd -P)
output="$output_parent/$(basename -- "$output")"

cd "$root"
if [ -n "$(git status --porcelain=v1 --untracked-files=all)" ]; then
	fail "the freeze requires a completely clean, committed source tree"
fi
if ! git rev-parse --verify --quiet "$commit^{commit}" >/dev/null; then
	fail "commit $commit is not present in this repository"
fi
if [ "$(git rev-parse --verify HEAD)" != "$commit" ]; then
	fail "commit $commit must be HEAD of the checkout so the gate suites run against the frozen bytes"
fi
source_date_epoch=${CIREWIND_RC_SOURCE_DATE_EPOCH:-$(git show -s --format=%ct "$commit")}
case "$source_date_epoch" in
	''|*[!0-9]*) fail "CIREWIND_RC_SOURCE_DATE_EPOCH must be a non-negative integer" ;;
esac

work_root=${CIREWIND_RELEASE_WORK_ROOT:-${TMPDIR:-/tmp}}
mkdir -p -- "$work_root"
work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-rc-freeze.XXXXXX")
case "$work" in
	"$work_root"/cirewind-rc-freeze.*) ;;
	*) fail "refusing unsafe freeze workspace: $work" ;;
esac
cleanup() {
	trap - EXIT HUP INT TERM
	if [ -d "$work" ]; then rm -r -- "$work"; fi
}
trap cleanup EXIT HUP INT TERM
export CIREWIND_RELEASE_WORK_ROOT="$work_root"

# 1. Immutable snapshot of the frozen commit; the working tree is never built.
mkdir "$work/source"
git archive --format=tar --output="$work/source.tar" "$commit"
tar -xf "$work/source.tar" -C "$work/source"
if find "$work/source" -type l -print -quit | grep -q .; then
	fail "frozen source snapshot contains a symbolic link; review is required"
fi

# 2. Two builds from the snapshot with the fixed metadata, compared byte for byte.
"$work/source/scripts/build-release.sh" "$version" "$commit" "$source_date_epoch" "$work/first"
"$work/source/scripts/build-release.sh" "$version" "$commit" "$source_date_epoch" "$work/second"
"$root/scripts/compare-release-assets.sh" "$work/first" "$work/second" "$work_root"
"$root/scripts/verify-release.sh" "$work/first"

# 3. A third build from a fresh local clone proves the bytes do not depend on
#    this checkout's state.
git clone -q --no-hardlinks -- "$root" "$work/clone"
git -C "$work/clone" checkout -q "$commit"
"$work/clone/scripts/build-release.sh" "$version" "$commit" "$source_date_epoch" "$work/clone-dist"
"$root/scripts/compare-release-assets.sh" "$work/first" "$work/clone-dist" "$work_root"

# 4. Final formula from the exact subject hashes.
mkdir -p "$work/tool-tmp" "$work/go-tmp" "$work/go-cache"
go_version=$(awk '/^go / { print $2; exit }' "$work/source/go.mod")
(
	cd "$work/source"
	export TMPDIR="$work/tool-tmp" GOTMPDIR="$work/go-tmp" GOTOOLCHAIN="go$go_version" GOFLAGS=-mod=readonly
	if [ -z "${GOCACHE:-}" ]; then export GOCACHE="$work/go-cache"; fi
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$work/releasetool" ./internal/releasetool
)
"$work/releasetool" formula --dist "$work/first" --out "$work/cirewind.rb"

# 5. Local gates through the existing Make targets, recorded in a ledger.
ledger="$work/qualification.tsv"
: >"$ledger"
selected() {
	case "$suites_selection" in
		all) return 0 ;;
	esac
	case ",$suites_selection," in
		*",$1,"*) return 0 ;;
	esac
	return 1
}
run_gate() {
	name=$1
	shift
	command_text=$*
	if ! selected "$name"; then
		printf '%s\t%s\t%s\t%s\t%s\n' "$name" skipped 0 "$command_text" "not selected by CIREWIND_RC_SUITES" >>"$ledger"
		return 0
	fi
	started=$(date +%s)
	set +e
	(cd "$root" && "$@" >"$work/gate-$name.log" 2>&1)
	status=$?
	set -e
	elapsed=$(( ($(date +%s) - started) * 1000 ))
	case "$status" in
		0) printf '%s\t%s\t%s\t%s\t%s\n' "$name" pass "$elapsed" "$command_text" "" >>"$ledger" ;;
		2) printf '%s\t%s\t%s\t%s\t%s\n' "$name" skipped "$elapsed" "$command_text" "prerequisite missing or unsupported host (exit status 2)" >>"$ledger" ;;
		*)
			printf '%s\t%s\t%s\t%s\t%s\n' "$name" fail "$elapsed" "$command_text" "exit status $status" >>"$ledger"
			cp -- "$ledger" "$output_parent/.cirewind-rc-freeze-failed-$name.tsv" 2>/dev/null || true
			printf '%s\n' "gate $name failed (exit status $status); last log lines:" >&2
			tail -n 40 "$work/gate-$name.log" >&2 || true
			fail "the freeze stops at the first failed gate"
			;;
	esac
}
# The history gate prefers gitleaks (its rules and allowlists are maintained
# upstream and its output is redacted); without it, a bounded built-in scan
# looks for exact GitHub, AWS, Slack, and private-key shapes across every
# commit reachable from the frozen commit.
history_scan() {
	if command -v gitleaks >/dev/null 2>&1; then
		gitleaks git --no-banner --redact --exit-code 1 --log-opts "$commit" "$root"
		return
	fi
	if git log --format=%H -p --no-color "$commit" | grep -Eq 'gh[posr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9]{10,}-[A-Za-z0-9-]{10,}'; then
		printf '%s\n' "the frozen commit's history contains token or private-key material" >&2
		return 1
	fi
	return 0
}
run_gate test make test
run_gate vet make vet
run_gate race make race
run_gate vuln make vuln
run_gate licenses make licenses
run_gate safety-audit make safety-audit
run_gate browser-audit make browser-audit
run_gate sample-site-check make sample-site-check
run_gate sample-site-browser-audit make sample-site-browser-audit
run_gate readme-candidate-check make readme-candidate-check "README_VERSION=$version"
run_gate pack-review-check make pack-review-check
run_gate release-workflow-audit make release-workflow-audit
run_gate brew-formula-check make brew-formula-check "BREW_WORK_ROOT=$work/brew"
run_gate demo-timing python3 scripts/qualify_demo.py --source-root "$root" --source-commit "$commit" --work-root "$work/demo-timing"
if command -v gitleaks >/dev/null 2>&1; then
	run_gate history-scan history_scan gitleaks-git-history
else
	run_gate history-scan history_scan builtin-pattern-history
fi
if [ "$suites_selection" != all ]; then
	printf '%s\t%s\t%s\t%s\t%s\n' suite-selection skipped 0 "CIREWIND_RC_SUITES=$suites_selection" "a subset of the local gates was selected; the freeze is preparation only" >>"$ledger"
fi

# 6. The bounded acquisition record and the frozen output tree.
stage=$(mktemp -d "$output_parent/.cirewind-rc-freeze-stage.XXXXXX")
case "$stage" in
	"$output_parent"/.cirewind-rc-freeze-stage.*) ;;
	*) fail "refusing unsafe freeze stage: $stage" ;;
esac
cp -R -- "$work/first" "$stage/subjects"
cp -- "$work/cirewind.rb" "$stage/cirewind.rb"
cp -- "$work/source/README.md" "$stage/README.md"
cp -- "$ledger" "$stage/qualification.tsv"
"$work/releasetool" acquisition-record \
	--dist "$stage/subjects" --out "$stage/rc-acquisition-record.json" \
	"--version=$version" "--commit=$commit" "--expected-default-tip=$expected_tip" "--source-date-epoch=$source_date_epoch" \
	"--host-os=$(go env GOHOSTOS)" "--host-arch=$(go env GOHOSTARCH)" \
	--formula "$stage/cirewind.rb" --readme "$stage/README.md" --suites "$stage/qualification.tsv"
(cd "$stage" && sha256sum rc-acquisition-record.json >rc-acquisition-record.sha256)
"$work/releasetool" verify-acquisition-record --dist "$stage/subjects" --record "$stage/rc-acquisition-record.json"
chmod 0755 "$stage"
mv -- "$stage" "$output"

complete=$(grep -c '"complete":true' "$output/rc-acquisition-record.json" || true)
printf '%s\n' \
	"release candidate frozen locally: $output" \
	"intended version: $version" \
	"source commit: $commit" \
	"expected old default tip: $expected_tip" \
	"source date epoch: $source_date_epoch" \
	"qualification complete: $([ "$complete" = 1 ] && printf '%s' yes || printf '%s' no)" \
	"publication: none; no tag, release, artifact, or attestation exists for this candidate"
