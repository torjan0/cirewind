#!/bin/sh
set -eu

script_root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/cirewind-pack-review-guard.XXXXXX")
case "$work" in
  "${TMPDIR:-/tmp}"/cirewind-pack-review-guard.*) ;;
  *)
    printf '%s\n' 'refusing unsafe Git-guard test directory' >&2
    exit 1
    ;;
esac
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

repository=$work/repository
git init -q "$repository"
printf '%s\n' synthetic >"$repository/input.txt"
git -C "$repository" add input.txt
git -C "$repository" -c user.name='Synthetic Test Maintainer' -c user.email='synthetic@example.invalid' commit -q -m 'synthetic guard fixture'
head=$(git -C "$repository" rev-parse HEAD)

# The single-quoted child program intentionally expands $1 in the child shell.
# shellcheck disable=SC2016
"$script_root/pack-review-git-guard.sh" --repository-root "$repository" --expected-head "$head" -- sh -c 'test "$1" = expected' guard expected

guard_temporary_parent=$work/guard-temporary-parent
mkdir "$guard_temporary_parent"
TMPDIR=$guard_temporary_parent "$script_root/pack-review-git-guard.sh" --repository-root "$repository" --expected-head "$head" -- true
if find "$guard_temporary_parent" -mindepth 1 -print -quit | grep -q .; then
  printf '%s\n' 'Git guard leaked its validated temporary directory before exec' >&2
  exit 1
fi

if [ -e /dev/full ]; then
  marker=$work/git-failure-command-must-not-run
  # shellcheck disable=SC2016
  if GIT_INDEX_FILE=/dev/full "$script_root/pack-review-git-guard.sh" --repository-root "$repository" --expected-head "$head" -- sh -c 'touch "$1"' guard "$marker" 2>/dev/null; then
    printf '%s\n' 'Git guard accepted a producer-side Git failure' >&2
    exit 1
  fi
  if [ -e "$marker" ]; then
    printf '%s\n' 'Git guard executed its command after a producer-side Git failure' >&2
    exit 1
  fi
fi

marker=$work/must-not-exist
# shellcheck disable=SC2016
if "$script_root/pack-review-git-guard.sh" --repository-root "$repository" --expected-head '0000000000000000000000000000000000000000' -- sh -c 'touch "$1"' guard "$marker" 2>/dev/null; then
  printf '%s\n' 'Git guard accepted the wrong HEAD' >&2
  exit 1
fi
test ! -e "$marker"

printf '%s\n' dirty >>"$repository/input.txt"
if "$script_root/pack-review-git-guard.sh" --repository-root "$repository" --expected-head "$head" -- true 2>/dev/null; then
  printf '%s\n' 'Git guard accepted an unstaged change' >&2
  exit 1
fi
git -C "$repository" restore input.txt

printf '%s\n' untracked >"$repository/untracked.txt"
if "$script_root/pack-review-git-guard.sh" --repository-root "$repository" --expected-head "$head" -- true 2>/dev/null; then
  printf '%s\n' 'Git guard accepted an untracked file' >&2
  exit 1
fi
"$script_root/pack-review-git-guard.sh" --repository-root "$repository" --expected-head "$head" --allow-dirty-path untracked.txt -- true
rm -- "$repository/untracked.txt"

mkdir "$repository/outside" "$repository/approvals"
printf '%s\n' candidate >"$repository/outside/pack.yaml"
git -C "$repository" add outside/pack.yaml
git -C "$repository" -c user.name='Synthetic Test Maintainer' -c user.email='synthetic@example.invalid' commit -q -m 'synthetic rename source'
head=$(git -C "$repository" rev-parse HEAD)
git -C "$repository" mv outside/pack.yaml approvals/pack.yaml
if "$script_root/pack-review-git-guard.sh" --repository-root "$repository" --expected-head "$head" --allow-dirty-path approvals -- true 2>/dev/null; then
  printf '%s\n' 'Git guard hid the source of an outside-to-allowlisted rename' >&2
  exit 1
fi
git -C "$repository" reset -q --hard HEAD

printf '%s\n' ignored.tmp >"$repository/.gitignore"
git -C "$repository" add .gitignore
git -C "$repository" -c user.name='Synthetic Test Maintainer' -c user.email='synthetic@example.invalid' commit -q -m 'synthetic ignore policy'
head=$(git -C "$repository" rev-parse HEAD)
printf '%s\n' ignored >"$repository/ignored.tmp"
if "$script_root/pack-review-git-guard.sh" --repository-root "$repository" --expected-head "$head" -- true 2>/dev/null; then
  printf '%s\n' 'Git guard ignored an untracked ignored file' >&2
  exit 1
fi
"$script_root/pack-review-git-guard.sh" --repository-root "$repository" --expected-head "$head" --allow-dirty-path ignored.tmp -- true
rm -- "$repository/ignored.tmp"

git -C "$repository" update-index --add --cacheinfo "160000,$head,synthetic-gitlink"
if "$script_root/pack-review-git-guard.sh" --repository-root "$repository" --expected-head "$head" -- true 2>/dev/null; then
  printf '%s\n' 'Git guard ignored a staged gitlink change' >&2
  exit 1
fi
git -C "$repository" reset -q --hard HEAD

mkdir "$repository/nested"
if "$script_root/pack-review-git-guard.sh" --repository-root "$repository/nested" --expected-head "$head" -- true 2>/dev/null; then
  printf '%s\n' 'Git guard accepted a nested path as repository root' >&2
  exit 1
fi

printf '%s\n' 'pack-review Git guard tests passed'
