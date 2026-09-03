#!/bin/sh

set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
test_root=${TMPDIR:-/tmp}
test_root=$(CDPATH='' cd -- "$test_root" && pwd)
work=$(mktemp -d "$test_root/cirewind-public-lab-artifact-test.XXXXXX")
case "$work" in
  "$test_root"/cirewind-public-lab-artifact-test.*) ;;
  *)
    printf '%s\n' "refusing unsafe public-lab artifact test workspace" >&2
    exit 1
    ;;
esac

cleanup() {
  rm -r -- "$work"
}
trap cleanup EXIT HUP INT TERM

copy_checked() {
  destination=$1
  mkdir "$destination"
  cp "$root/lab/public/artifacts/cirewind-lab.bundle" "$destination/cirewind-lab.bundle"
  cp "$root/lab/public/artifacts/object-manifest.json" "$destination/object-manifest.json"
}

tampered="$work/tampered"
copy_checked "$tampered"
printf '%s' x >>"$tampered/cirewind-lab.bundle"
if CIREWIND_PUBLIC_LAB_ARTIFACT_DIR="$tampered" CIREWIND_PUBLIC_LAB_WORK_ROOT="$work" \
  GO="${GO:-go}" sh "$root/scripts/public-lab-artifacts.sh" check >"$work/tampered.out" 2>&1; then
  printf '%s\n' "tampered checked public-lab bundle was accepted" >&2
  exit 1
fi
grep -F "checked public-lab artifact differs from deterministic regeneration: cirewind-lab.bundle" "$work/tampered.out" >/dev/null

unexpected="$work/unexpected"
copy_checked "$unexpected"
printf '%s\n' "synthetic unexpected entry" >"$unexpected/extra"
if CIREWIND_PUBLIC_LAB_ARTIFACT_DIR="$unexpected" CIREWIND_PUBLIC_LAB_WORK_ROOT="$work" \
  GO="${GO:-go}" sh "$root/scripts/public-lab-artifacts.sh" check >"$work/unexpected.out" 2>&1; then
  printf '%s\n' "unexpected checked public-lab artifact entry was accepted" >&2
  exit 1
fi
grep -F "unexpected public-lab artifact entry" "$work/unexpected.out" >/dev/null

hostile="$work/hostile"
copy_checked "$hostile"
hostile_name=$(printf 'entry\033[2J\nforged')
printf '%s\n' "synthetic hostile entry" >"$hostile/$hostile_name"
if CIREWIND_PUBLIC_LAB_ARTIFACT_DIR="$hostile" CIREWIND_PUBLIC_LAB_WORK_ROOT="$work" \
  GO="${GO:-go}" sh "$root/scripts/public-lab-artifacts.sh" check >"$work/hostile.out" 2>&1; then
  printf '%s\n' "hostile checked public-lab artifact entry was accepted" >&2
  exit 1
fi
grep -F "unexpected public-lab artifact entry" "$work/hostile.out" >/dev/null
if grep -F "forged" "$work/hostile.out" >/dev/null || LC_ALL=C grep "$(printf '\033')" "$work/hostile.out" >/dev/null; then
  printf '%s\n' "hostile checked artifact name reached terminal output" >&2
  exit 1
fi

linked="$work/linked"
copy_checked "$linked"
mv "$linked/cirewind-lab.bundle" "$work/real-bundle"
ln -s "$work/real-bundle" "$linked/cirewind-lab.bundle"
if CIREWIND_PUBLIC_LAB_ARTIFACT_DIR="$linked" CIREWIND_PUBLIC_LAB_WORK_ROOT="$work" \
  GO="${GO:-go}" sh "$root/scripts/public-lab-artifacts.sh" check >"$work/linked.out" 2>&1; then
  printf '%s\n' "symlinked checked public-lab artifact was accepted" >&2
  exit 1
fi
grep -F "public-lab artifact is not a regular non-symlink file: cirewind-lab.bundle" "$work/linked.out" >/dev/null

printf '%s\n' "public-lab artifact closure rejects byte drift, hostile or unexpected entries, and symlinks"
