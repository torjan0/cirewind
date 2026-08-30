#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

usage() {
  printf '%s\n' \
    'Usage: scripts/pack-review-candidate-change-guard.sh --repository-root DIR --base COMMIT --head COMMIT' \
    '' \
    'Allows infrastructure-only changes and candidate-material-only changes, but' \
    'rejects a change set that combines the two. COMMIT values must be exact full' \
    'lowercase object IDs. The comparison uses the single merge base of BASE and' \
    'HEAD, matching pull-request change semantics without rename collapsing.'
}

repository_root=''
base_commit=''
head_commit=''
while (($# > 0)); do
  case "$1" in
    --repository-root)
      (($# >= 2)) || { usage >&2; exit 2; }
      repository_root=$2
      shift 2
      ;;
    --base)
      (($# >= 2)) || { usage >&2; exit 2; }
      base_commit=$2
      shift 2
      ;;
    --head)
      (($# >= 2)) || { usage >&2; exit 2; }
      head_commit=$2
      shift 2
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

if [[ -z $repository_root || ! $base_commit =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ || ! $head_commit =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
  usage >&2
  exit 2
fi

repository_root=$(cd -- "$repository_root" && pwd -P)
git_root=$(git -C "$repository_root" rev-parse --show-toplevel 2>/dev/null) || {
  printf '%s\n' 'candidate change-set guard: repository root is not a Git worktree' >&2
  exit 2
}
git_root=$(cd -- "$git_root" && pwd -P)
if [[ $git_root != "$repository_root" ]]; then
  printf '%s\n' 'candidate change-set guard: repository root is not the exact worktree root' >&2
  exit 2
fi

resolve_exact_commit() {
  local supplied=$1
  local label=$2
  local resolved
  resolved=$(git -C "$repository_root" rev-parse --verify "${supplied}^{commit}" 2>/dev/null) || {
    printf 'candidate change-set guard: %s commit is unavailable\n' "$label" >&2
    exit 2
  }
  if [[ $resolved != "$supplied" ]]; then
    printf 'candidate change-set guard: %s must be an exact full commit ID\n' "$label" >&2
    exit 2
  fi
}

resolve_exact_commit "$base_commit" base
resolve_exact_commit "$head_commit" head

temporary_parent=${TMPDIR:-/tmp}
temporary_parent=$(cd -- "$temporary_parent" && pwd -P) || {
  printf '%s\n' 'candidate change-set guard: temporary parent is unavailable' >&2
  exit 2
}
temporary_root=$(mktemp -d "$temporary_parent/cirewind-candidate-change.XXXXXX")
case "$temporary_root" in
  "$temporary_parent"/cirewind-candidate-change.*) ;;
  *)
    printf '%s\n' 'candidate change-set guard: refusing unsafe temporary directory' >&2
    exit 2
    ;;
esac
cleanup() { rm -rf -- "$temporary_root"; }
trap cleanup EXIT HUP INT TERM

merge_bases_file=$temporary_root/merge-bases
if ! git -C "$repository_root" merge-base --all "$base_commit" "$head_commit" >"$merge_bases_file"; then
  printf '%s\n' 'candidate change-set guard: base and head have no merge base' >&2
  exit 2
fi
mapfile -t merge_bases <"$merge_bases_file"
if ((${#merge_bases[@]} != 1)); then
  printf '%s\n' 'candidate change-set guard: base and head must have exactly one merge base' >&2
  exit 2
fi
merge_base=${merge_bases[0]}

changed_paths_file=$temporary_root/changed-paths
git -C "$repository_root" diff \
  --no-ext-diff \
  --no-textconv \
  --no-renames \
  --name-only \
  -z \
  --diff-filter=ACDMRTUXB \
  "$merge_base" "$head_commit" -- >"$changed_paths_file"

safe_id() {
  local identifier=$1
  local reserved_base
  [[ $identifier =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$ ]] || return 1
  [[ $identifier != *. ]] || return 1
  reserved_base=${identifier%%.*}
  reserved_base=${reserved_base^^}
  case "$reserved_base" in
    CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]) return 1 ;;
  esac
}

canonical_semver() {
  local version=$1
  ((${#version} <= 128)) || return 1
  [[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]
}

# Return 0 for candidate material, 1 for ordinary infrastructure, and 2 for a
# malformed candidate-root path. Rejecting malformed roots prevents an unsafe
# identifier or version from bypassing the separation rule.
classify_path() {
  local changed_path=$1
  local incident_id
  local pack_version

  if [[ $changed_path =~ ^incidents/candidates/([^/]+)/([^/]+)\.yaml$ ]]; then
    incident_id=${BASH_REMATCH[1]}
    pack_version=${BASH_REMATCH[2]}
    if safe_id "$incident_id" && canonical_semver "$pack_version"; then
      return 0
    fi
    return 2
  fi
  if [[ $changed_path == incidents/candidates || $changed_path == incidents/candidates/* ]]; then
    return 2
  fi

  if [[ $changed_path =~ ^review-packets/([^/]+)/([^/]+)/candidate-content/(.+)$ ]]; then
    incident_id=${BASH_REMATCH[1]}
    pack_version=${BASH_REMATCH[2]}
    if safe_id "$incident_id" && canonical_semver "$pack_version"; then
      return 0
    fi
    return 2
  fi
  if [[ $changed_path == review-packets/*/candidate-content || $changed_path == review-packets/*/candidate-content/* ]]; then
    return 2
  fi

  return 1
}

candidate_count=0
infrastructure_count=0
invalid_candidate_path_count=0
while IFS= read -r -d '' changed_path; do
  if classify_path "$changed_path"; then
    ((candidate_count += 1))
  else
    case $? in
      1) ((infrastructure_count += 1)) ;;
      2) ((invalid_candidate_path_count += 1)) ;;
      *)
        printf '%s\n' 'candidate change-set guard: internal path-classification failure' >&2
        exit 2
        ;;
    esac
  fi
done <"$changed_paths_file"

if ((invalid_candidate_path_count > 0)); then
  printf 'candidate change-set guard: rejected %d malformed candidate-root path(s)\n' "$invalid_candidate_path_count" >&2
  exit 1
fi
if ((candidate_count > 0 && infrastructure_count > 0)); then
  printf 'candidate change-set guard: rejected mixed change set (%d candidate path(s), %d non-candidate path(s))\n' "$candidate_count" "$infrastructure_count" >&2
  exit 1
fi
if ((candidate_count > 0)); then
  printf 'candidate change-set guard: candidate-only change set accepted (%d path(s))\n' "$candidate_count"
else
  printf 'candidate change-set guard: infrastructure-only change set accepted (%d path(s))\n' "$infrastructure_count"
fi
