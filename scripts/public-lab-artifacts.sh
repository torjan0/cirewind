#!/bin/sh

set -eu

mode=${1:-}
case "$mode" in
  build|check) ;;
  *)
    printf '%s\n' "usage: public-lab-artifacts.sh build|check" >&2
    exit 2
    ;;
esac

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
source_dir="$root/lab/public/source"
checked_dir=${CIREWIND_PUBLIC_LAB_ARTIFACT_DIR:-$root/lab/public/artifacts}
work_root=${CIREWIND_PUBLIC_LAB_WORK_ROOT:-${TMPDIR:-/tmp}}
go_command=${GO:-go}

case "$checked_dir" in
  /*) ;;
  *) checked_dir="$root/$checked_dir" ;;
esac
case "$work_root" in
  /*) ;;
  *) work_root="$root/$work_root" ;;
esac

if [ ! -d "$work_root" ] || [ -L "$work_root" ]; then
  printf '%s\n' "public-lab work root must be an existing real directory" >&2
  exit 2
fi
work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-public-lab-artifacts.XXXXXX")
case "$work" in
  "$work_root"/cirewind-public-lab-artifacts.*) ;;
  *)
    printf '%s\n' "refusing unsafe public-lab artifact workspace" >&2
    exit 1
    ;;
esac

cleanup() {
  rm -r -- "$work"
}
trap cleanup EXIT HUP INT TERM

generated="$work/generated"
(cd "$root" && "$go_command" run ./tools/publiclab build --source "$source_dir" --out "$generated")
(cd "$root" && "$go_command" run ./tools/publiclab verify --source "$source_dir" --artifact-dir "$generated")

assert_artifact_directory() {
  directory=$1
  if [ ! -d "$directory" ] || [ -L "$directory" ]; then
    printf '%s\n' "public-lab artifact path must be a real directory: $directory" >&2
    return 1
  fi
  count=0
  for entry in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
    [ -e "$entry" ] || [ -L "$entry" ] || continue
    name=${entry##*/}
    case "$name" in
      cirewind-lab.bundle|object-manifest.json) ;;
      *)
        printf '%s\n' "unexpected public-lab artifact entry" >&2
        return 1
        ;;
    esac
    if [ ! -f "$entry" ] || [ -L "$entry" ]; then
      printf '%s\n' "public-lab artifact is not a regular non-symlink file: $name" >&2
      return 1
    fi
    count=$((count + 1))
  done
  if [ "$count" -ne 2 ]; then
    printf '%s\n' "public-lab artifact directory must contain exactly two files" >&2
    return 1
  fi
}

if [ "$mode" = build ]; then
  if [ -e "$checked_dir" ] || [ -L "$checked_dir" ]; then
    assert_artifact_directory "$checked_dir"
  else
    mkdir -p -- "$checked_dir"
  fi
  for name in cirewind-lab.bundle object-manifest.json; do
    temporary="$checked_dir/.$name.tmp.$$"
    if [ -e "$temporary" ] || [ -L "$temporary" ]; then
      printf '%s\n' "refusing pre-existing temporary artifact path" >&2
      exit 1
    fi
    install -m 0644 "$generated/$name" "$temporary"
    mv -f -- "$temporary" "$checked_dir/$name"
  done
  assert_artifact_directory "$checked_dir"
  (cd "$root" && "$go_command" run ./tools/publiclab verify --source "$source_dir" --artifact-dir "$checked_dir")
  printf '%s\n' "checked public-lab artifacts regenerated from deterministic source"
  exit 0
fi

assert_artifact_directory "$checked_dir"
for name in cirewind-lab.bundle object-manifest.json; do
  if ! cmp -s "$generated/$name" "$checked_dir/$name"; then
    printf '%s\n' "checked public-lab artifact differs from deterministic regeneration: $name" >&2
    exit 1
  fi
done
(cd "$root" && "$go_command" run ./tools/publiclab verify --source "$source_dir" --artifact-dir "$checked_dir")

if ! command -v git >/dev/null 2>&1; then
  printf '%s\n' "public-lab check requires Git for bundle verify, strict fsck, and independent import tests" >&2
  exit 2
fi
sh "$root/scripts/public-lab-marker-audit.sh" --source-only
(cd "$root" && "$go_command" test ./internal/publiclab -run '^TestBundleImportsTwiceAndPassesGitVerification$' -count=1)
(cd "$root" && "$go_command" test ./internal/publiclab ./tools/publiclab)

if command -v actionlint >/dev/null 2>&1; then
  mkdir "$work/home" "$work/import.git" "$work/workflows"
  env -i PATH="$PATH" HOME="$work/home" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null \
    git clone --bare --quiet "$generated/cirewind-lab.bundle" "$work/import.git"
  for workflow in composite.yml direct.yml matrix.yml rerun.yml reusable-caller.yml skipped.yml; do
    env -i PATH="$PATH" HOME="$work/home" GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null \
      git --git-dir="$work/import.git" show "refs/heads/main:.github/workflows/$workflow" >"$work/workflows/$workflow"
  done
  actionlint "$work/workflows"/*.yml
  printf '%s\n' "actionlint validated all generated public-lab workflows"
elif [ "${CIREWIND_PUBLIC_LAB_REQUIRE_ACTIONLINT:-0}" = 1 ]; then
  printf '%s\n' "actionlint is required but unavailable" >&2
  exit 2
else
  printf '%s\n' "SKIP: actionlint unavailable; set CIREWIND_PUBLIC_LAB_REQUIRE_ACTIONLINT=1 to make this fatal" >&2
fi

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$checked_dir" && sha256sum cirewind-lab.bundle object-manifest.json)
else
  (cd "$checked_dir" && shasum -a 256 cirewind-lab.bundle object-manifest.json)
fi
printf '%s\n' "public-lab checked artifacts exactly match deterministic regeneration"
