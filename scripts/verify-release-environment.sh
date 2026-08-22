#!/bin/sh

set -eu

if [ "$#" -ne 3 ]; then
	printf '%s\n' "usage: $0 OWNER/REPO ENVIRONMENT EXPECTED_SOLO_REVIEWER" >&2
	exit 2
fi

repository=$1
environment=$2
expected_reviewer=$3
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
case "$environment" in
release-draft|release-publish) ;;
*)
	printf '%s\n' "unexpected release environment: $environment" >&2
	exit 2
	;;
esac
case "$expected_reviewer" in
''|*[!A-Za-z0-9-]*|-*|*-)
	printf '%s\n' "expected reviewer must be a GitHub user login" >&2
	exit 2
	;;
esac
if [ "${#expected_reviewer}" -gt 39 ]; then
	printf '%s\n' "expected reviewer must be a GitHub user login" >&2
	exit 2
fi
expected_reviewer=$(printf '%s' "$expected_reviewer" | LC_ALL=C tr '[:upper:]' '[:lower:]')

if ! command -v gh >/dev/null 2>&1; then
	printf '%s\n' "GitHub CLI is required to inspect the release environment" >&2
	exit 1
fi

environment_policy=$(gh api \
	--method GET \
	-H 'Accept: application/vnd.github+json' \
	-H 'X-GitHub-Api-Version: 2026-03-10' \
	"repos/$repository/environments/$environment" \
	--jq ".name == \"$environment\" and
		.can_admins_bypass == false and
		.deployment_branch_policy.protected_branches == false and
		.deployment_branch_policy.custom_branch_policies == true and
		([.protection_rules[]? | select(.type == \"required_reviewers\")] as \$rules |
			(\$rules | length) == 1 and
			\$rules[0].prevent_self_review == false and
			(\$rules[0].reviewers | length) == 1 and
			\$rules[0].reviewers[0].type == \"User\" and
			(\$rules[0].reviewers[0].reviewer.login | ascii_downcase) == \"$expected_reviewer\")")
if [ "$environment_policy" != true ]; then
	printf '%s\n' "$environment must require only $expected_reviewer as reviewer, permit that initiator's review, deny administrator bypass, and use selected deployment policies" >&2
	exit 1
fi

tag_policy=$(gh api \
	--method GET \
	-H 'Accept: application/vnd.github+json' \
	-H 'X-GitHub-Api-Version: 2026-03-10' \
	"repos/$repository/environments/$environment/deployment-branch-policies?per_page=100" \
	--jq '.total_count == 1 and (.branch_policies | length) == 1 and .branch_policies[0].type == "tag" and .branch_policies[0].name == "v*"')
if [ "$tag_policy" != true ]; then
	printf '%s\n' "$environment must allow exactly one deployment policy: tag v*" >&2
	exit 1
fi

printf '%s\n' "$environment solo-reviewer, no-bypass, and tag-only deployment rules verified"
