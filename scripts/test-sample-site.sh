#!/bin/sh
# Exercise build-sample-site.sh end to end: publish a site, verify it through
# the tool, and prove a one-byte mutation fails verification.

set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work_root=${CIREWIND_SITE_WORK_ROOT:-${TMPDIR:-/tmp}}
work_root=$(CDPATH='' cd -- "$work_root" && pwd)
work=$(mktemp -d "$work_root/cirewind-sample-site-test.XXXXXX")

case "$work" in
  "$work_root"/cirewind-sample-site-test.*) ;;
  *)
    printf '%s\n' "refusing unsafe test workspace: $work" >&2
    exit 1
    ;;
esac

cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT HUP INT TERM

version=0.2.0
site="$work/site"

CIREWIND_SITE_ALLOW_DIRTY=1 CIREWIND_SITE_WORK_ROOT="$work" \
  sh "$root/scripts/build-sample-site.sh" "$site" "$version" >"$work/publish.json"

for required in \
  "index.html" \
  "v$version/index.html" \
  "v$version/site-manifest.sha256" \
  "v$version/graph.svg" \
  "v$version/findings.json" \
  "v$version/summary.md" \
  "v$version/provenance.json" \
  "v$version/downloads/cirewind-synthetic-case-v$version.tar.gz" \
  "v$version/downloads/SHA256SUMS" \
  "v$version/sample-case/manifest.sha256" \
  "v$version/sample-case/case.db"; do
  if [ ! -f "$site/$required" ]; then
    printf '%s\n' "published site lacks $required" >&2
    exit 1
  fi
done

if find "$site" -type l | grep -q .; then
  printf '%s\n' "published site contains a symbolic link" >&2
  exit 1
fi
if find "$site" -type f -perm -u+x | grep -q .; then
  printf '%s\n' "published site contains an executable file" >&2
  exit 1
fi
if grep -q '"operation": "verify"' "$work/publish.json"; then :; else
  printf '%s\n' "publish record is not the verify result" >&2
  exit 1
fi

if [ "$(sha256sum "$site/v$version/downloads/cirewind-synthetic-case-v$version.tar.gz" | cut -c1-64)" != "$(cut -c1-64 "$site/v$version/downloads/SHA256SUMS")" ]; then
  printf '%s\n' "SHA256SUMS does not match the archive" >&2
  exit 1
fi

go_version=$(awk '/^go / { print $2; exit }' "$root/go.mod")
export GOTOOLCHAIN="go$go_version"
export GOFLAGS=-mod=readonly
cd "$root"

go run ./tools/samplesite verify --site "$site" --version "$version" >/dev/null

cp -R "$site" "$work/site-copy-a"
printf ' ' >>"$work/site-copy-a/v$version/summary.md"
if go run ./tools/samplesite verify --site "$work/site-copy-a" --version "$version" >/dev/null 2>"$work/tamper-a.err"; then
  printf '%s\n' "site with a mutated copied file verified" >&2
  exit 1
fi

cp -R "$site" "$work/site-copy-b"
printf ' ' >>"$work/site-copy-b/v$version/downloads/SHA256SUMS"
if go run ./tools/samplesite verify --site "$work/site-copy-b" --version "$version" >/dev/null 2>"$work/tamper-b.err"; then
  printf '%s\n' "site with a mutated checksum file verified" >&2
  exit 1
fi
if ! grep -q 'manifest' "$work/tamper-b.err"; then
  printf '%s\n' "checksum tamper diagnostic does not name the site manifest:" >&2
  cat "$work/tamper-b.err" >&2
  exit 1
fi

printf '%s\n' "sample-site build, verify, and tamper checks passed"
