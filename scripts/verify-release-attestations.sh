#!/bin/sh

set -eu

if [ "$#" -ne 5 ]; then
	printf '%s\n' "usage: $0 RELEASE_DIRECTORY vSEMVER COMMIT OWNER/REPO WORKFLOW_PATH" >&2
	exit 2
fi

distribution=$1
tag=$2
commit=$3
repository=$4
workflow_path=$5

case "$repository" in
*[!A-Za-z0-9_./-]*|/*|*/|*/*/*)
	printf '%s\n' "repository must use OWNER/REPO syntax" >&2
	exit 2
	;;
esac
owner=${repository%%/*}
name=${repository#*/}
if [ "$owner" = "$repository" ] || [ -z "$owner" ] || [ -z "$name" ]; then
	printf '%s\n' "repository must use OWNER/REPO syntax" >&2
	exit 2
fi
case "$workflow_path" in
.github/workflows/*.yml|.github/workflows/*.yaml) ;;
*)
	printf '%s\n' "signer workflow must be a repository workflow path" >&2
	exit 2
	;;
esac
if ! printf '%s\n' "$tag" | grep -Eq '^v[0-9A-Za-z.+-]+$'; then
	printf '%s\n' "invalid release tag" >&2
	exit 2
fi
if ! printf '%s\n' "$commit" | grep -Eq '^([0-9a-f]{40}|[0-9a-f]{64})$'; then
	printf '%s\n' "invalid release commit" >&2
	exit 2
fi
if [ ! -d "$distribution" ]; then
	printf '%s\n' "release directory does not exist: $distribution" >&2
	exit 1
fi
if ! command -v gh >/dev/null 2>&1; then
	printf '%s\n' "GitHub CLI is required for attestation verification" >&2
	exit 1
fi

# Fail before making any verification request if the runner's gh is too old to
# enforce the complete signer/source policy used by this release workflow.
help=$(gh attestation verify --help 2>&1) || {
	printf '%s\n' "GitHub CLI does not provide attestation verification" >&2
	exit 1
}
for option in --signer-workflow --signer-digest --source-ref --source-digest --deny-self-hosted-runners; do
	case "$help" in
	*"$option"*) ;;
	*)
		printf '%s\n' "GitHub CLI is missing required attestation policy option $option" >&2
		exit 1
		;;
	esac
done

signer_workflow="github.com/$repository/$workflow_path"
source_ref="refs/tags/$tag"
asset_count=0
for asset in "$distribution"/*; do
	if [ ! -f "$asset" ] || [ -L "$asset" ]; then
		printf '%s\n' "release distribution contains a non-regular root entry" >&2
		exit 1
	fi
	gh attestation verify "$asset" \
		--repo "$repository" \
		--signer-workflow "$signer_workflow" \
		--signer-digest "$commit" \
		--source-ref "$source_ref" \
		--source-digest "$commit" \
		--deny-self-hosted-runners >/dev/null
	asset_count=$((asset_count + 1))
done

if [ "$asset_count" -ne 14 ]; then
	printf '%s\n' "expected 14 attested release subjects, found $asset_count" >&2
	exit 1
fi

printf '%s\n' "verified build-provenance attestations for all $asset_count release subjects"
