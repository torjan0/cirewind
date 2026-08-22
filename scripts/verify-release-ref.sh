#!/bin/sh

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	printf '%s\n' "usage: $0 vSEMVER [EXPECTED_COMMIT]" >&2
	exit 2
fi

LC_ALL=C
export LC_ALL

tag=$1
expected_commit=${2:-}

if [ "${#tag}" -gt 129 ] || ! printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'; then
	printf '%s\n' "release tag must use canonical vSEMVER syntax: $tag" >&2
	exit 2
fi

# SemVer forbids leading zeroes in numeric prerelease identifiers. The regular
# expression above intentionally remains readable; enforce that additional
# canonical rule separately.
version=${tag#v}
without_build=${version%%+*}
case "$without_build" in
*-*)
	prerelease=${without_build#*-}
	old_ifs=$IFS
	IFS=.
	for identifier in $prerelease; do
		case "$identifier" in
		*[!0-9]*) ;;
		0|[1-9]*) ;;
		*)
			printf '%s\n' "release tag has a noncanonical numeric prerelease identifier: $tag" >&2
			exit 2
			;;
		esac
	done
	IFS=$old_ifs
	;;
esac

if ! git show-ref --verify --quiet "refs/tags/$tag"; then
	printf '%s\n' "release tag does not exist locally: $tag" >&2
	exit 1
fi
if [ "$(git cat-file -t "refs/tags/$tag")" != tag ]; then
	printf '%s\n' "release tag must be annotated: $tag" >&2
	exit 1
fi

head_commit=$(git rev-parse --verify HEAD)
tag_commit=$(git rev-parse --verify "refs/tags/$tag^{commit}")
if [ "$head_commit" != "$tag_commit" ]; then
	printf '%s\n' "release tag $tag does not identify checked-out HEAD $head_commit" >&2
	exit 1
fi

if [ -n "$expected_commit" ]; then
	if ! printf '%s\n' "$expected_commit" | grep -Eq '^([0-9a-f]{40}|[0-9a-f]{64})$'; then
		printf '%s\n' "expected release commit must be a full lowercase Git object ID" >&2
		exit 2
	fi
	if [ "$tag_commit" != "$expected_commit" ]; then
		printf '%s\n' "release tag resolves to $tag_commit, not expected commit $expected_commit" >&2
		exit 1
	fi
fi

printf '%s\n' "$tag_commit"
