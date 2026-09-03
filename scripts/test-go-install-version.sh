#!/bin/sh

# Proves the versioned `go install` version-reporting contract without a public
# tag: the current tree is served as a synthetic module version through a
# file-based GOPROXY, installed from a directory outside the checkout, and the
# installed binary must report exactly that module version with an unknown
# commit and build time. Dependencies come from the existing local module
# download cache through a second file-based proxy, so no network is used.

set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
module=github.com/torjan0/cirewind
version=${CIREWIND_SYNTHETIC_MODULE_VERSION:-v0.2.0-synthetic}
go_command=${GO:-go}
toolchain=${GOTOOLCHAIN:-$(awk '/^go / { print "go" $2; exit }' "$root/go.mod")}
work_root=${CIREWIND_GO_INSTALL_WORK_ROOT:-${TMPDIR:-/tmp}}

case "$version" in
  v[0-9]*) ;;
  *)
    printf '%s\n' "synthetic module version must start with v and a digit: $version" >&2
    exit 2
    ;;
esac
case "$work_root" in
  /*) ;;
  *) work_root="$root/$work_root" ;;
esac
if [ ! -d "$work_root" ] || [ -L "$work_root" ]; then
  printf '%s\n' "go-install work root must be an existing real directory" >&2
  exit 2
fi
work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-go-install.XXXXXX")
case "$work" in
  "$work_root"/cirewind-go-install.*) ;;
  *)
    printf '%s\n' "refusing unsafe go-install workspace" >&2
    exit 1
    ;;
esac

cleanup() {
  chmod -R u+w -- "$work" 2>/dev/null || true
  rm -r -- "$work"
}
trap cleanup EXIT HUP INT TERM

# Resolve the exact pinned toolchain once, then pin it so the installing
# environment cannot switch toolchains or reach the network for one.
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

mkdir -p "$work/proxy" "$work/cwd" "$work/bin" "$work/gopath" "$work/modcache" "$work/gocache" "$work/tmp" "$work/home"

# Snapshot the current tree as the synthetic module version. The helper uses a
# temporary Git index, so the real index and worktree are not modified.
sh "$root/scripts/go-install-proxy.sh" "$work/proxy" "$version" >/dev/null

# Install from outside the checkout so the current go.mod cannot influence the
# module graph. Only the two file proxies are consulted.
(
  cd "$work/cwd"
  env -i \
    PATH="$goroot/bin:/usr/bin:/bin" HOME="$work/home" \
    GOTOOLCHAIN=local GOFLAGS= GOPROXY="file://$work/proxy,file://$local_cache" \
    GOSUMDB=off GONOSUMDB="$module" GOMODCACHE="$work/modcache" GOPATH="$work/gopath" \
    GOBIN="$work/bin" GOCACHE="$work/gocache" GOTMPDIR="$work/tmp" CGO_ENABLED=0 \
    "$go_exact" install "$module/cmd/cirewind@$version"
)

binary="$work/bin/cirewind"
if [ ! -x "$binary" ]; then
  printf '%s\n' "go install produced no executable" >&2
  exit 1
fi

# The module build carries the module version and no VCS data.
embedded=$("$go_exact" version -m "$binary")
printf '%s\n' "$embedded" | grep -F "	mod	$module	$version	" >/dev/null
if printf '%s\n' "$embedded" | grep -E '^	build	vcs' >/dev/null; then
  printf '%s\n' "module build unexpectedly embeds VCS settings" >&2
  exit 1
fi

expected="cirewind ${version#v} (commit unknown, built unknown)"
actual=$(cd "$work/cwd" && "$binary" version)
if [ "$actual" != "$expected" ]; then
  printf '%s\n' "installed binary reported: $actual" "expected:                 $expected" >&2
  exit 1
fi

# Warm pass: the caches left by the cold install must reproduce the same
# executable identity without touching the proxies again for the module.
rm -f -- "$binary"
(
  cd "$work/cwd"
  env -i \
    PATH="$goroot/bin:/usr/bin:/bin" HOME="$work/home" \
    GOTOOLCHAIN=local GOFLAGS= GOPROXY="file://$work/proxy,file://$local_cache" \
    GOSUMDB=off GONOSUMDB="$module" GOMODCACHE="$work/modcache" GOPATH="$work/gopath" \
    GOBIN="$work/bin" GOCACHE="$work/gocache" GOTMPDIR="$work/tmp" CGO_ENABLED=0 \
    "$go_exact" install "$module/cmd/cirewind@$version"
)
warm=$(cd "$work/cwd" && "$binary" version)
if [ "$warm" != "$expected" ]; then
  printf '%s\n' "warm install reported: $warm" "expected:              $expected" >&2
  exit 1
fi

# The installed binary must still produce and verify the offline demo from an
# unrelated directory with no credentials or network.
(
  cd "$work/cwd"
  env -i PATH=/usr/bin:/bin HOME="$work/home" "$binary" demo --out "$work/case" >"$work/demo.out" 2>&1
  env -i PATH=/usr/bin:/bin HOME="$work/home" "$binary" verify "$work/case" >"$work/verify.out" 2>&1
)
grep -F "manifest: verified" "$work/demo.out" >/dev/null

printf '%s\n' "versioned go install reported '$actual' and produced a verified offline demo"
