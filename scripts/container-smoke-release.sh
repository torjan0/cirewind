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
image=${CIREWIND_SMOKE_IMAGE_ID:-}

case "$image" in
	sha256:*) ;;
	*)
		printf '%s\n' "CIREWIND_SMOKE_IMAGE_ID must be an explicit local sha256 image ID" >&2
		exit 2
		;;
esac
image_digest=${image#sha256:}
case "$image_digest" in
	*[!0-9a-f]*)
		printf '%s\n' "CIREWIND_SMOKE_IMAGE_ID must contain only lowercase hex digits" >&2
		exit 2
		;;
esac
if [ "${#image_digest}" -ne 64 ]; then
	printf '%s\n' "CIREWIND_SMOKE_IMAGE_ID must contain exactly 64 lowercase hex digits" >&2
	exit 2
fi

CIREWIND_RELEASE_WORK_ROOT="$work_root" "$root/scripts/verify-release.sh" "$distribution"
if ! docker image inspect "$image" >/dev/null 2>&1; then
	printf '%s\n' "clean-container image ID is not already present: $image" "the script will not pull it automatically" >&2
	exit 2
fi
resolved_image=$(docker image inspect --format '{{.Id}}' "$image")
if [ "$resolved_image" != "$image" ]; then
	printf '%s\n' "local container image did not resolve to the required immutable ID" >&2
	exit 1
fi

archive=$(CDPATH='' cd -- "$distribution" && pwd -P)/cirewind_${version}_linux_amd64.tar.gz
if [ ! -f "$archive" ]; then
	printf '%s\n' "Linux amd64 release archive is missing: $archive" >&2
	exit 1
fi

docker run --rm \
	--network none \
	--log-driver none \
	--read-only \
	--cap-drop ALL \
	--security-opt no-new-privileges \
	--user 65534:65534 \
	--tmpfs /work:rw,exec,nosuid,nodev,size=256m,mode=1777 \
	--mount "type=bind,src=$archive,dst=/input/release.tar.gz,readonly" \
	-e "EXPECTED_VERSION=$version" \
	-e "EXPECTED_COMMIT=$commit" \
	-e "EXPECTED_DATE=$build_date" \
	"$image" /bin/sh -eu -c '
		tar -xzf /input/release.tar.gz -C /work
		bundle=/work/cirewind_${EXPECTED_VERSION}_linux_amd64
		binary=$bundle/cirewind
		actual=$($binary version)
		expected="cirewind $EXPECTED_VERSION (commit $EXPECTED_COMMIT, built $EXPECTED_DATE)"
		[ "$actual" = "$expected" ]
		$binary --help >/dev/null
		$binary investigate --help >/dev/null 2>&1
		$binary pack validate "$bundle/incidents/synthetic/mutable-tag.yaml" >/dev/null
		[ -f "$bundle/incidents/reviewed/index.json" ]
		for reviewed in "$bundle"/incidents/reviewed/*/*.yaml; do
			[ -e "$reviewed" ] || continue
			$binary pack validate "$reviewed" >/dev/null
		done
		$binary archive --import-fixture synthetic --store /work/archive.db >/dev/null
		$binary replay --archive /work/archive.db --incident "$bundle/incidents/synthetic/mutable-tag.yaml" --out /work/case --fixed-collection-time 2026-08-20T00:00:00Z >/dev/null
		$binary verify /work/case >/dev/null
		$binary demo --out /work/demo >/dev/null
		$binary verify /work/demo >/dev/null
		$binary demo --out /work/demo-again >/dev/null
		for name in report.html graph.svg graph.json findings.json affected-runs.csv summary.md collection-metadata.json evidence.jsonl case.db manifest.sha256; do
			[ -f "/work/demo/$name" ]
			cmp -s "/work/demo/$name" "/work/demo-again/$name"
		done
		[ ! -e /work/demo/raw ]
	'

printf '%s\n' "network-disabled, read-only-root clean-container smoke passed for linux/amd64 with image $resolved_image"
