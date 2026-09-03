#!/bin/sh

# Dry-run test of the public go install qualifier: serves the current tree as
# a synthetic module version through file-based proxies, runs the qualifier
# against it, and checks the record, the rejections, and the offline demo.
# No network is used and nothing is published.

set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
module=github.com/torjan0/cirewind
version=${CIREWIND_SYNTHETIC_MODULE_VERSION:-v0.2.0-synthetic}
go_command=${GO:-go}
toolchain=${GOTOOLCHAIN:-$(awk '/^go / { print "go" $2; exit }' "$root/go.mod")}
work_root=${CIREWIND_GO_INSTALL_WORK_ROOT:-${TMPDIR:-/tmp}}
case "$work_root" in
  /*) ;;
  *) work_root="$root/$work_root" ;;
esac
mkdir -p -- "$work_root"
work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-public-go-install-test.XXXXXX")
case "$work" in
  "$work_root"/cirewind-public-go-install-test.*) ;;
  *)
    printf '%s\n' "refusing unsafe test workspace" >&2
    exit 1
    ;;
esac
cleanup() {
  trap - EXIT HUP INT TERM
  chmod -R u+w -- "$work" 2>/dev/null || true
  rm -r -- "$work"
}
trap cleanup EXIT HUP INT TERM

goroot=$(GOTOOLCHAIN="$toolchain" "$go_command" env GOROOT)
go_exact="$goroot/bin/go"
if [ ! -x "$go_exact" ]; then
  printf '%s\n' "pinned Go toolchain is unavailable at $goroot" >&2
  exit 2
fi
local_cache=$(GOTOOLCHAIN="$toolchain" "$go_command" env GOMODCACHE)/cache/download
if [ ! -d "$local_cache" ]; then
  printf '%s\n' "local module download cache is unavailable; build the project once first" >&2
  exit 2
fi
mkdir -p "$work/proxy"
sh "$root/scripts/go-install-proxy.sh" "$work/proxy" "$version" >/dev/null
qualifier="$root/scripts/qualify-public-go-install.sh"

expect_rejection() {
  label=$1
  shift
  if "$@" >"$work/reject.log" 2>&1; then
    printf '%s\n' "qualifier accepted $label" >&2
    exit 1
  fi
}
# Rejections happen before any install, so they never reach a proxy.
expect_rejection "an unprefixed tag" env GO="$go_exact" CIREWIND_GO_INSTALL_WORK_ROOT="$work_root" "$qualifier" 0.2.0 "$work/out-a"
expect_rejection "a pre-release tag in public mode" env GO="$go_exact" CIREWIND_GO_INSTALL_WORK_ROOT="$work_root" "$qualifier" v0.2.0-rc.1 "$work/out-b"
expect_rejection "a non-file proxy override" env GO="$go_exact" CIREWIND_GO_INSTALL_WORK_ROOT="$work_root" CIREWIND_PUBLIC_GO_INSTALL_PROXY=https://example.invalid "$qualifier" v0.2.0 "$work/out-c"
mkdir "$work/out-d"
expect_rejection "an existing output directory" env GO="$go_exact" CIREWIND_GO_INSTALL_WORK_ROOT="$work_root" CIREWIND_PUBLIC_GO_INSTALL_PROXY="file://$work/proxy,file://$local_cache" "$qualifier" "$version" "$work/out-d"

env GO="$go_exact" CIREWIND_GO_INSTALL_WORK_ROOT="$work_root" \
  CIREWIND_PUBLIC_GO_INSTALL_PROXY="file://$work/proxy,file://$local_cache" \
  "$qualifier" "$version" "$work/out" >"$work/qualify.out"

record="$work/out/public-go-install-record.json"
(cd "$work/out" && sha256sum -c --quiet public-go-install-record.sha256)
grep -q '"dryRun":true' "$record"
grep -q "\"tag\":\"$version\"" "$record"
grep -q "\"versionOutput\":\"cirewind ${version#v} (commit unknown, built unknown)\"" "$record"
grep -q '"moduleHash":"h1:' "$record"
grep -q '"demoVerified":true' "$record"
grep -q '"checksumDatabase":"off-dry-run"' "$record"
test -x "$work/out/bin/cirewind"
grep -F "	mod	$module	$version	" "$work/out/go-version-m.txt" >/dev/null
grep -F "manifest: verified" "$work/out/demo.out" >/dev/null
printf '%s\n' "public go install qualifier dry run passed for synthetic $version"
