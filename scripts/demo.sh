#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd)
output=${1:-"$project_dir/demo-case"}
binary=${2:-"$project_dir/bin/cirewind"}
pack="$project_dir/incidents/synthetic/mutable-tag.yaml"
temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/cirewind-demo.XXXXXX")
archive_path="$temp_dir/archive.db"

cleanup() {
	rm -f -- "$archive_path" "$archive_path-wal" "$archive_path-shm"
	rmdir -- "$temp_dir" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

if [ -e "$output" ]; then
	printf '%s\n' "demo output already exists: $output" >&2
	exit 2
fi

"$binary" pack validate "$pack"
"$binary" archive --import-fixture synthetic --store "$archive_path"
"$binary" replay \
	--archive "$archive_path" \
	--incident "$pack" \
	--out "$output" \
	--fixed-collection-time 2026-08-20T00:00:00Z
"$binary" verify "$output"

required_files='report.html findings.json affected-runs.csv evidence.jsonl manifest.sha256 case.db collection-metadata.json graph.json summary.md'
for name in $required_files; do
	test -f "$output/$name"
done

expect_state_count() {
	state=$1
	expected=$2
	actual=$(grep -c "\"state\": \"$state\"" "$output/findings.json" || true)
	if [ "$actual" -ne "$expected" ]; then
		printf '%s\n' "unexpected $state count: got $actual, want $expected" >&2
		exit 1
	fi
}

expect_state_count CONFIRMED_EXECUTED 1
expect_state_count CONFIRMED_DOWNLOADED 1
expect_state_count CONFIRMED_CALLED_WORKFLOW 1
expect_state_count DECLARED_AT_RUN_SHA 1
expect_state_count RUN_IN_WINDOW_MUTABLE_REF 1
expect_state_count POTENTIAL_TRANSITIVE 2
expect_state_count CURRENT_REFERENCE_ONLY 1
expect_state_count NO_MATCH_CONFIRMED 0
expect_state_count UNKNOWN_EVIDENCE_GAP 1
expect_state_count CONTRADICTORY_EVIDENCE 1

printf '%s\n' "offline demo passed: $output"
