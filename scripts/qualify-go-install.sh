#!/bin/sh

# Clean-container qualification of the versioned `go install` evaluation lane.
#
# The current tree is served as a synthetic module version through a file-based
# Go module proxy, and an already-present minimal Linux image installs it twice
# from a directory outside any checkout: once with empty module and build caches
# (cold) and once with the caches left by the first install (warm). The
# container has no network, a read-only root filesystem, no capabilities, an
# unprivileged user, and only read-only mounts for the pinned Go toolchain and
# the two file proxies. Dependencies come from the host's existing module
# download cache, so no download from a public proxy occurs.
#
# Required: CIREWIND_GO_INSTALL_IMAGE_ID=sha256:<64 hex> naming a local image
# that is already present. The script never pulls an image and never accepts a
# mutable tag. Optional: CIREWIND_SYNTHETIC_MODULE_VERSION (default
# v0.2.0-synthetic) and CIREWIND_GO_INSTALL_WORK_ROOT (default TMPDIR).
#
# This exercises the install shape only. It makes no claim that a public tag
# exists or that the installing environment matches a reference host.

set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
module=github.com/torjan0/cirewind
version=${CIREWIND_SYNTHETIC_MODULE_VERSION:-v0.2.0-synthetic}
image=${CIREWIND_GO_INSTALL_IMAGE_ID:-}
go_command=${GO:-go}
toolchain=${GOTOOLCHAIN:-$(awk '/^go / { print "go" $2; exit }' "$root/go.mod")}
work_root=${CIREWIND_GO_INSTALL_WORK_ROOT:-${TMPDIR:-/tmp}}

case "$image" in
  sha256:*) ;;
  *)
    printf '%s\n' "CIREWIND_GO_INSTALL_IMAGE_ID must be an explicit local sha256 image ID" >&2
    exit 2
    ;;
esac
image_digest=${image#sha256:}
case "$image_digest" in
  *[!0-9a-f]*)
    printf '%s\n' "CIREWIND_GO_INSTALL_IMAGE_ID must contain only lowercase hex digits" >&2
    exit 2
    ;;
esac
if [ "${#image_digest}" -ne 64 ]; then
  printf '%s\n' "CIREWIND_GO_INSTALL_IMAGE_ID must contain exactly 64 lowercase hex digits" >&2
  exit 2
fi
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
  printf '%s\n' "the container trial mounts the host's linux/amd64 Go toolchain and requires a Linux x86_64 host" >&2
  exit 2
fi
if ! docker image inspect "$image" >/dev/null 2>&1; then
  printf '%s\n' "clean-container image ID is not already present: $image" "the script will not pull it automatically" >&2
  exit 2
fi
resolved_image=$(docker image inspect --format '{{.Id}}' "$image")
if [ "$resolved_image" != "$image" ]; then
  printf '%s\n' "local container image did not resolve to the required immutable ID" >&2
  exit 1
fi

case "$work_root" in
  /*) ;;
  *) work_root="$root/$work_root" ;;
esac
if [ ! -d "$work_root" ] || [ -L "$work_root" ]; then
  printf '%s\n' "go-install work root must be an existing real directory" >&2
  exit 2
fi
work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-go-install-qualify.XXXXXX")
case "$work" in
  "$work_root"/cirewind-go-install-qualify.*) ;;
  *)
    printf '%s\n' "refusing unsafe qualification workspace" >&2
    exit 1
    ;;
esac
cleanup() {
  chmod -R u+w -- "$work" 2>/dev/null || true
  rm -r -- "$work"
}
trap cleanup EXIT HUP INT TERM

goroot=$(GOTOOLCHAIN="$toolchain" "$go_command" env GOROOT)
if [ ! -x "$goroot/bin/go" ]; then
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
expected="cirewind ${version#v} (commit unknown, built unknown)"

docker run --rm \
  --network none \
  --log-driver none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user 65534:65534 \
  --tmpfs /work:rw,exec,nosuid,nodev,size=2g,mode=1777 \
  --mount "type=bind,src=$goroot,dst=/opt/go,readonly" \
  --mount "type=bind,src=$work/proxy,dst=/proxy/synthetic,readonly" \
  --mount "type=bind,src=$local_cache,dst=/proxy/cache,readonly" \
  -e "MODULE=$module" \
  -e "VERSION=$version" \
  -e "EXPECTED=$expected" \
  "$image" /bin/sh -eu -c '
    mkdir -p /work/home /work/modcache /work/gocache /work/tmp /work/bin /work/cwd /work/gopath
    export HOME=/work/home PATH=/opt/go/bin:/usr/bin:/bin
    export GOTOOLCHAIN=local GOFLAGS= GOPROXY=file:///proxy/synthetic,file:///proxy/cache
    export GOSUMDB=off GONOSUMDB="$MODULE" GOMODCACHE=/work/modcache GOPATH=/work/gopath
    export GOBIN=/work/bin GOCACHE=/work/gocache GOTMPDIR=/work/tmp CGO_ENABLED=0
    cd /work/cwd
    now() { date +%s%N; }
    start=$(now); go install "$MODULE/cmd/cirewind@$VERSION"; end=$(now)
    echo "cold_install_ms=$(( (end - start) / 1000000 ))"
    actual=$(/work/bin/cirewind version)
    [ "$actual" = "$EXPECTED" ] || { echo "cold install reported: $actual" >&2; exit 1; }
    rm /work/bin/cirewind
    start=$(now); go install "$MODULE/cmd/cirewind@$VERSION"; end=$(now)
    echo "warm_install_ms=$(( (end - start) / 1000000 ))"
    actual=$(/work/bin/cirewind version)
    [ "$actual" = "$EXPECTED" ] || { echo "warm install reported: $actual" >&2; exit 1; }
    go version -m /work/bin/cirewind | grep -F "	mod	$MODULE	$VERSION	" >/dev/null
    if go version -m /work/bin/cirewind | grep -E "^	build	vcs" >/dev/null; then
      echo "module build unexpectedly embeds VCS settings" >&2; exit 1
    fi
    start=$(now); /work/bin/cirewind demo --out /work/case >/work/demo.out 2>&1; end=$(now)
    echo "demo_ms=$(( (end - start) / 1000000 ))"
    grep -F "manifest: verified" /work/demo.out >/dev/null
    start=$(now); /work/bin/cirewind verify /work/case >/dev/null; end=$(now)
    echo "verify_ms=$(( (end - start) / 1000000 ))"
    echo "container_arch=$(uname -m)"
    echo "toolchain=$(go version)"
    echo "installed_version_line=$actual"
  '

printf '%s\n' "clean-container cold and warm go install trials passed for synthetic $version"
