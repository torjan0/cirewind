#!/bin/sh

# Post-publication qualification of the public versioned `go install` lane
# (DIST-010 preparation).
#
# usage: qualify-public-go-install.sh TAG OUTPUT_DIR
#
# Installs github.com/torjan0/cirewind/cmd/cirewind@TAG from a fresh, empty
# GOPATH, module cache, build cache, and HOME in a directory outside any
# checkout, twice: cold with empty caches and warm with the caches left by the
# first install. The default GOTOOLCHAIN=auto is kept, so a timing includes any
# automatic toolchain download, as the reference protocol requires. The
# installed binary must report exactly the tag version with an unknown commit
# and build time, because module zips carry no VCS data, and must produce and
# verify the offline demo with an empty environment. The record written to
# OUTPUT_DIR binds the host, the Go that ran the install, the module hash and
# toolchain embedded in the binary, the binary SHA-256, both timings, and the
# case manifest hash.
#
# Public mode uses Go's default module proxy and checksum database on purpose:
# the public module must resolve the exact release tag anonymously. Setting
# CIREWIND_PUBLIC_GO_INSTALL_PROXY to a file:// proxy list switches to a dry
# run for this script's own test; the record then says so and proves nothing
# about the public module. Optional: CIREWIND_GO_INSTALL_WORK_ROOT, GO.

set -eu

if [ "$#" -ne 2 ]; then
  printf '%s\n' "usage: qualify-public-go-install.sh TAG OUTPUT_DIR" >&2
  exit 2
fi

tag=$1
output=$2
module=github.com/torjan0/cirewind
go_command=${GO:-go}
proxy=${CIREWIND_PUBLIC_GO_INSTALL_PROXY:-}
work_root=${CIREWIND_GO_INSTALL_WORK_ROOT:-${TMPDIR:-/tmp}}

dry_run=false
case "$proxy" in
  '') ;;
  file://*) dry_run=true ;;
  *)
    printf '%s\n' "CIREWIND_PUBLIC_GO_INSTALL_PROXY may only name file:// proxies for a dry run; public mode keeps Go's default proxy" >&2
    exit 2
    ;;
esac
if printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
  :
elif [ "$dry_run" = true ] && printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-[a-z0-9.]+$'; then
  :
else
  printf '%s\n' "TAG must be a published release tag of the form vMAJOR.MINOR.PATCH (a suffixed synthetic version is accepted only in a file-proxy dry run)" >&2
  exit 2
fi
if [ -e "$output" ]; then
  printf '%s\n' "output directory already exists: $output" >&2
  exit 2
fi
case "$work_root" in
  /*) ;;
  *)
    printf '%s\n' "work root must be an absolute path" >&2
    exit 2
    ;;
esac
if [ ! -d "$work_root" ] || [ -L "$work_root" ]; then
  printf '%s\n' "work root must be an existing real directory" >&2
  exit 2
fi
work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-public-go-install.XXXXXX")
case "$work" in
  "$work_root"/cirewind-public-go-install.*) ;;
  *)
    printf '%s\n' "refusing unsafe workspace" >&2
    exit 1
    ;;
esac
cleanup() {
  trap - EXIT HUP INT TERM
  chmod -R u+w -- "$work" 2>/dev/null || true
  rm -r -- "$work"
}
trap cleanup EXIT HUP INT TERM

go_bin=$(command -v "$go_command" || true)
if [ -z "$go_bin" ]; then
  printf '%s\n' "a Go toolchain is required on PATH or in GO" >&2
  exit 2
fi
go_dir=$(dirname -- "$go_bin")
host_go_version=$("$go_bin" version)
host_os=$(uname -s)
host_machine=$(uname -m)

mkdir -p "$work/cwd" "$work/bin" "$work/gopath" "$work/modcache" "$work/gocache" "$work/tmp" "$work/home"

now_ms() {
  ms=$(date +%s%N 2>/dev/null || true)
  case "$ms" in
    *N|'') printf '%s' "$(( $(date +%s) * 1000 ))" ;;
    *) printf '%s' "$(( ms / 1000000 ))" ;;
  esac
}

install_once() {
  if [ "$dry_run" = true ]; then
    (
      cd "$work/cwd"
      env -i PATH="$go_dir:/usr/bin:/bin" HOME="$work/home" \
        GOTOOLCHAIN=local GOFLAGS= GOPROXY="$proxy" GOSUMDB=off GONOSUMDB="$module" \
        GOMODCACHE="$work/modcache" GOPATH="$work/gopath" GOBIN="$work/bin" \
        GOCACHE="$work/gocache" GOTMPDIR="$work/tmp" CGO_ENABLED=0 \
        "$go_bin" install "$module/cmd/cirewind@$tag"
    )
  else
    (
      cd "$work/cwd"
      env -i PATH="$go_dir:/usr/bin:/bin" HOME="$work/home" GOFLAGS= \
        GOMODCACHE="$work/modcache" GOPATH="$work/gopath" GOBIN="$work/bin" \
        GOCACHE="$work/gocache" GOTMPDIR="$work/tmp" CGO_ENABLED=0 \
        "$go_bin" install "$module/cmd/cirewind@$tag"
    )
  fi
}

started=$(now_ms)
install_once
cold_ms=$(( $(now_ms) - started ))
binary="$work/bin/cirewind"
if [ ! -x "$binary" ]; then
  printf '%s\n' "go install produced no executable" >&2
  exit 1
fi
expected="cirewind ${tag#v} (commit unknown, built unknown)"
actual=$(cd "$work/cwd" && env -i PATH=/usr/bin:/bin HOME="$work/home" "$binary" version)
if [ "$actual" != "$expected" ]; then
  printf '%s\n' "installed binary reported: $actual" "expected:                 $expected" >&2
  exit 1
fi
embedded=$("$go_bin" version -m "$binary")
module_line=$(printf '%s\n' "$embedded" | grep -E "^	mod	$module	" | head -n 1 || true)
if [ -z "$module_line" ]; then
  printf '%s\n' "installed binary carries no module line for $module" >&2
  exit 1
fi
module_version=$(printf '%s\n' "$module_line" | awk -F'\t' '{ print $4 }')
module_hash=$(printf '%s\n' "$module_line" | awk -F'\t' '{ print $5 }')
if [ "$module_version" != "$tag" ]; then
  printf '%s\n' "installed module version $module_version differs from the requested $tag" >&2
  exit 1
fi
if printf '%s\n' "$embedded" | grep -Eq '^	build	vcs'; then
  printf '%s\n' "module build unexpectedly embeds VCS settings" >&2
  exit 1
fi
embedded_go=$(printf '%s\n' "$embedded" | head -n 1 | awk '{ print $2 }')
binary_sha256=$(sha256sum "$binary" | cut -c1-64)

rm -f -- "$binary"
started=$(now_ms)
install_once
warm_ms=$(( $(now_ms) - started ))
warm=$(cd "$work/cwd" && env -i PATH=/usr/bin:/bin HOME="$work/home" "$binary" version)
if [ "$warm" != "$expected" ]; then
  printf '%s\n' "warm install reported: $warm" >&2
  exit 1
fi
if [ "$(sha256sum "$binary" | cut -c1-64)" != "$binary_sha256" ]; then
  printf '%s\n' "warm install produced a different executable" >&2
  exit 1
fi

mkdir -p "$output"
(
  cd "$work/cwd"
  env -i PATH=/usr/bin:/bin HOME="$work/home" "$binary" demo --out "$output/case" >"$output/demo.out" 2>&1
  env -i PATH=/usr/bin:/bin HOME="$work/home" "$binary" verify "$output/case" >"$output/verify.out" 2>&1
)
grep -F "manifest: verified" "$output/demo.out" >/dev/null
manifest=$(find "$output/case" -maxdepth 1 -type f -name '*manifest*' | head -n 1)
if [ -z "$manifest" ]; then
  printf '%s\n' "demo output carries no manifest file" >&2
  exit 1
fi
manifest_sha256=$(sha256sum "$manifest" | cut -c1-64)
mkdir -p "$output/bin"
cp -- "$binary" "$output/bin/cirewind"
printf '%s\n' "$embedded" >"$output/go-version-m.txt"

for value in "$module_hash" "$embedded_go" "$host_go_version" "$host_os" "$host_machine" "$proxy"; do
  case "$value" in
    *[!A-Za-z0-9+/=:._,\ -]*)
      printf '%s\n' "a recorded value carries characters outside the safe set: $value" >&2
      exit 1
      ;;
  esac
done
recorded_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
proxy_mode=public-default
if [ "$dry_run" = true ]; then
  proxy_mode="$proxy"
fi
printf '{"schemaVersion":"cirewind.public-go-install/v1alpha1","module":"%s","tag":"%s","dryRun":%s,"proxy":"%s","checksumDatabase":"%s","host":{"os":"%s","machine":"%s"},"installerGo":"%s","embeddedGo":"%s","moduleHash":"%s","binarySha256":"%s","versionOutput":"%s","coldInstallMs":%s,"warmInstallMs":%s,"demoVerified":true,"caseManifestSha256":"%s","recordedAt":"%s"}\n' \
  "$module" "$tag" "$dry_run" "$proxy_mode" "$([ "$dry_run" = true ] && printf '%s' off-dry-run || printf '%s' public-default)" \
  "$host_os" "$host_machine" "$host_go_version" "$embedded_go" "$module_hash" "$binary_sha256" "$expected" \
  "$cold_ms" "$warm_ms" "$manifest_sha256" "$recorded_at" >"$output/public-go-install-record.json"
(cd "$output" && sha256sum public-go-install-record.json >public-go-install-record.sha256)

printf '%s\n' \
  "public go install lane: $module@$tag" \
  "mode: $([ "$dry_run" = true ] && printf '%s' 'file-proxy dry run (proves nothing about the public module)' || printf '%s' 'public proxy and checksum database')" \
  "version output: $actual" \
  "module hash: $module_hash" \
  "binary sha256: $binary_sha256" \
  "cold install: ${cold_ms} ms; warm install: ${warm_ms} ms (toolchain download included when it occurred)" \
  "record: $output/public-go-install-record.json"
