#!/bin/sh
set -eu

script_root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
guard=$script_root/pack-review-candidate-change-guard.sh
work=$(mktemp -d "${TMPDIR:-/tmp}/cirewind-candidate-change-test.XXXXXX")
case "$work" in
  "${TMPDIR:-/tmp}"/cirewind-candidate-change-test.*) ;;
  *)
    printf '%s\n' 'refusing unsafe candidate-guard test directory' >&2
    exit 1
    ;;
esac
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

case_number=0
new_repository() {
  case_number=$((case_number + 1))
  repository=$work/case-$case_number
  git init -q "$repository"
  git -C "$repository" config user.name 'Synthetic Test Maintainer'
  git -C "$repository" config user.email 'synthetic@example.invalid'
  printf '%s\n' '*.ignored' >"$repository/.gitignore"
  printf '%s\n' baseline >"$repository/README.md"
  git -C "$repository" add .gitignore README.md
  git -C "$repository" commit -q -m 'synthetic base'
  base=$(git -C "$repository" rev-parse HEAD)
}

commit_all() {
  git -C "$repository" add -A
  git -C "$repository" commit -q -m "${1:-synthetic change}"
  head=$(git -C "$repository" rev-parse HEAD)
}

expect_accept() {
  if ! "$guard" --repository-root "$repository" --base "$base" --head "$head" >"$work/result" 2>"$work/error"; then
    printf '%s\n' 'candidate change-set guard unexpectedly rejected a test case' >&2
    cat "$work/error" >&2
    exit 1
  fi
}

expect_reject() {
  if "$guard" --repository-root "$repository" --base "$base" --head "$head" >"$work/result" 2>"$work/error"; then
    printf '%s\n' 'candidate change-set guard unexpectedly accepted a test case' >&2
    cat "$work/result" >&2
    exit 1
  fi
}

# Infrastructure changes are unrestricted when no candidate bytes change.
new_repository
mkdir -p "$repository/internal/validator" "$repository/review-packets/synthetic/1.0.0/approvals/review-1"
printf '%s\n' 'package validator' >"$repository/internal/validator/validator.go"
printf '%s\n' '{}' >"$repository/review-packets/synthetic/1.0.0/approvals/review-1/review.json"
commit_all 'infrastructure only'
expect_accept

# Both canonical candidate families may change together, including SemVer
# prerelease/build metadata and conservative safe identifiers.
new_repository
mkdir -p "$repository/incidents/candidates/CIR.synthetic_1" \
  "$repository/review-packets/CIR.synthetic_1/1.2.3-rc.1+fixture.2/candidate-content/fixtures/scenario-1"
printf '%s\n' synthetic >"$repository/incidents/candidates/CIR.synthetic_1/1.2.3-rc.1+fixture.2.yaml"
printf '%s\n' synthetic >"$repository/review-packets/CIR.synthetic_1/1.2.3-rc.1+fixture.2/candidate-content/pack.yaml"
printf '%s\n' synthetic >"$repository/review-packets/CIR.synthetic_1/1.2.3-rc.1+fixture.2/candidate-content/fixtures/scenario-1/archive.json"
commit_all 'candidate only'
expect_accept

# Candidate bytes may not share a change set with code, policy, approvals,
# registry, schemas, or workflows.
for mixed_path in \
  internal/packreview/validator.go \
  pack-review-policy.json \
  review-packets/synthetic/1.0.0/approvals/review-1/review.json \
  review-registry.json \
  schema/review-packet-v1alpha1.json \
  .github/workflows/ci.yml
do
  new_repository
  mkdir -p "$repository/incidents/candidates/synthetic" "$(dirname -- "$repository/$mixed_path")"
  printf '%s\n' synthetic >"$repository/incidents/candidates/synthetic/1.0.0.yaml"
  printf '%s\n' synthetic >"$repository/$mixed_path"
  commit_all 'mixed candidate and infrastructure'
  expect_reject
done

# Disabling rename detection must expose both sides of a move out of the
# candidate family.
new_repository
mkdir -p "$repository/incidents/candidates/synthetic"
printf '%s\n' synthetic >"$repository/incidents/candidates/synthetic/1.0.0.yaml"
git -C "$repository" add incidents/candidates/synthetic/1.0.0.yaml
git -C "$repository" commit -q -m 'candidate rename source'
base=$(git -C "$repository" rev-parse HEAD)
mkdir -p "$repository/schema"
git -C "$repository" mv incidents/candidates/synthetic/1.0.0.yaml schema/renamed.json
commit_all 'rename candidate into infrastructure'
expect_reject

# A force-added ignored candidate is still a tracked tree change and cannot be
# hidden by ignore rules.
new_repository
mkdir -p "$repository/review-packets/synthetic/1.0.0/candidate-content"
printf '%s\n' synthetic >"$repository/review-packets/synthetic/1.0.0/candidate-content/pack.ignored"
printf '%s\n' infrastructure >"$repository/validator.go"
git -C "$repository" add -f review-packets/synthetic/1.0.0/candidate-content/pack.ignored
git -C "$repository" add validator.go
git -C "$repository" commit -q -m 'ignored candidate and infrastructure'
head=$(git -C "$repository" rev-parse HEAD)
expect_reject

# A changed gitlink is a visible non-candidate path and cannot accompany a
# candidate. No submodule checkout or network access is needed for this test.
new_repository
mkdir -p "$repository/incidents/candidates/synthetic"
printf '%s\n' synthetic >"$repository/incidents/candidates/synthetic/1.0.0.yaml"
git -C "$repository" add incidents/candidates/synthetic/1.0.0.yaml
git -C "$repository" update-index --add --cacheinfo "160000,$base,external-validator"
git -C "$repository" commit -q -m 'candidate and synthetic gitlink'
head=$(git -C "$repository" rev-parse HEAD)
expect_reject

# Malformed candidate-root paths fail closed even without another change.
for malformed_path in \
  incidents/candidates/synthetic/01.0.0.yaml \
  incidents/candidates/synthetic/1.0.0.yml \
  review-packets/CON/1.0.0/candidate-content/pack.yaml \
  review-packets/synthetic/not-semver/candidate-content/pack.yaml
do
  new_repository
  mkdir -p "$(dirname -- "$repository/$malformed_path")"
  printf '%s\n' synthetic >"$repository/$malformed_path"
  commit_all 'malformed candidate root'
  expect_reject
done

# Exact full commit IDs are mandatory.
new_repository
printf '%s\n' infrastructure >"$repository/validator.go"
commit_all 'exact oid check'
short_head=$(printf '%.12s' "$head")
if "$guard" --repository-root "$repository" --base "$base" --head "$short_head" >/dev/null 2>&1; then
  printf '%s\n' 'candidate change-set guard accepted an abbreviated commit ID' >&2
  exit 1
fi

# Use the PR merge base: a base-branch-only infrastructure advance must not be
# misclassified as part of a candidate-only topic branch.
new_repository
topic_base=$base
git -C "$repository" checkout -q -b topic
mkdir -p "$repository/incidents/candidates/synthetic"
printf '%s\n' synthetic >"$repository/incidents/candidates/synthetic/1.0.0.yaml"
commit_all 'topic candidate'
topic_head=$head
git -C "$repository" checkout -q -b advanced-base "$topic_base"
printf '%s\n' base-only >"$repository/base-policy.json"
commit_all 'base branch advanced'
advanced_base=$head
base=$advanced_base
head=$topic_head
expect_accept

# A nested directory cannot be substituted for the exact worktree root.
mkdir -p "$repository/nested"
if "$guard" --repository-root "$repository/nested" --base "$base" --head "$head" >/dev/null 2>&1; then
  printf '%s\n' 'candidate change-set guard accepted a nested repository root' >&2
  exit 1
fi

printf '%s\n' 'candidate change-set guard tests passed'
