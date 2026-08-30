#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'Usage: scripts/pack-review-git-guard.sh --repository-root DIR --expected-head COMMIT [--allow-dirty-path RELATIVE_PATH]... -- COMMAND [ARG...]' \
    '' \
    'Checks that DIR is the exact Git worktree root, HEAD equals the supplied full' \
    'commit, and tracked, staged, and untracked changes stay within explicitly' \
    'allowlisted review-record paths before executing the maintainer command.' \
    'With no allowlist, the worktree must be clean. Never pass arguments from incident' \
    'packs, fixtures, logs, or other hostile content.'
}

repository_root=''
expected_head=''
declare -a allowed_dirty_paths=()
while (($# > 0)); do
  case "$1" in
    --repository-root)
      (($# >= 2)) || { usage >&2; exit 2; }
      repository_root=$2
      shift 2
      ;;
    --expected-head)
      (($# >= 2)) || { usage >&2; exit 2; }
      expected_head=$2
      shift 2
      ;;
    --allow-dirty-path)
      (($# >= 2)) || { usage >&2; exit 2; }
      if [[ ! $2 =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ || $2 == '.' || $2 == '..' || $2 == */../* || $2 == ../* || $2 == */.. ]]; then
        printf '%s\n' 'pack-review Git guard: unsafe dirty-path allowlist entry' >&2
        exit 2
      fi
      allowed_dirty_paths+=("$2")
      shift 2
      ;;
    --)
      shift
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z $repository_root || ! $expected_head =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ || $# -eq 0 ]]; then
  usage >&2
  exit 2
fi

repository_root=$(cd -- "$repository_root" && pwd -P)
git_root=$(git -C "$repository_root" rev-parse --show-toplevel)
git_root=$(cd -- "$git_root" && pwd -P)
if [[ $git_root != "$repository_root" ]]; then
  printf '%s\n' 'pack-review Git guard: repository root is not the exact worktree root' >&2
  exit 2
fi

actual_head=$(git -C "$repository_root" rev-parse --verify 'HEAD^{commit}')
if [[ $actual_head != "$expected_head" ]]; then
  printf '%s\n' 'pack-review Git guard: HEAD does not equal the required commit' >&2
  exit 2
fi

path_is_allowed() {
  local changed_path=$1
  local allowed
  for allowed in "${allowed_dirty_paths[@]}"; do
    if [[ $changed_path == "$allowed" || $changed_path == "$allowed"/* ]]; then
      return 0
    fi
  done
  return 1
}

temporary_parent=${TMPDIR:-/tmp}
temporary_parent=$(cd -- "$temporary_parent" && pwd -P) || {
  printf '%s\n' 'pack-review Git guard: temporary parent is unavailable' >&2
  exit 2
}
temporary_root=$(mktemp -d "$temporary_parent/cirewind-pack-review-git-guard.XXXXXX")
case "$temporary_root" in
  "$temporary_parent"/cirewind-pack-review-git-guard.*) ;;
  *)
    printf '%s\n' 'pack-review Git guard: refusing unsafe temporary directory' >&2
    exit 2
    ;;
esac
cleanup() { rm -rf -- "$temporary_root"; }
trap cleanup EXIT HUP INT TERM

# Check each producer before reading any output. Process substitution would hide
# a producer-side Git failure and could otherwise allow the guarded command to
# execute against an incompletely inspected worktree.
if ! git -C "$repository_root" diff --no-renames --name-only -z --submodule=short -- >"$temporary_root/unstaged"; then
  printf '%s\n' 'pack-review Git guard: unable to inspect unstaged changes' >&2
  exit 2
fi
if ! git -C "$repository_root" diff --cached --no-renames --name-only -z --submodule=short -- >"$temporary_root/staged"; then
  printf '%s\n' 'pack-review Git guard: unable to inspect staged changes' >&2
  exit 2
fi
if ! git -C "$repository_root" ls-files --others -z >"$temporary_root/untracked"; then
  printf '%s\n' 'pack-review Git guard: unable to inspect untracked and ignored files' >&2
  exit 2
fi

check_changed_paths() {
  local changes_file=$1
  local changed_path
  while IFS= read -r -d '' changed_path; do
    if ! path_is_allowed "$changed_path"; then
      printf '%s\n' 'pack-review Git guard: worktree change is outside the explicit review-record allowlist' >&2
      exit 2
    fi
  done <"$changes_file"
}

# Disable rename collapsing so a move from outside an allowlisted path exposes
# and rejects its source. Include gitlinks and ignored untracked files: neither
# may become an invisible promotion input.
check_changed_paths "$temporary_root/unstaged"
check_changed_paths "$temporary_root/staged"
check_changed_paths "$temporary_root/untracked"

cleanup
trap - EXIT HUP INT TERM
exec "$@"
