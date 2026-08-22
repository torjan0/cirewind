#!/bin/sh

set -eu

if [ "$#" -ne 4 ]; then
	printf '%s\n' "usage: $0 VERSION COMMIT SOURCE_DATE_EPOCH OUTPUT_DIR" >&2
	exit 2
fi

version=$1
commit=$2
source_date_epoch=$3
requested_output=$4
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

output_parent=$(dirname -- "$requested_output")
output_name=$(basename -- "$requested_output")
mkdir -p -- "$output_parent"
output_parent=$(CDPATH='' cd -- "$output_parent" && pwd -P)
case "$output_name" in
	''|.|..|*/*|*\\*)
		printf '%s\n' "unsafe release output name: $output_name" >&2
		exit 2
		;;
esac
output="$output_parent/$output_name"
if [ -e "$output" ] || [ -L "$output" ]; then
	printf '%s\n' "release output already exists: $output" >&2
	exit 2
fi

work_root=${CIREWIND_RELEASE_WORK_ROOT:-${TMPDIR:-/tmp}}
mkdir -p -- "$work_root"
work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-release-build.XXXXXX")
stage=$(mktemp -d "$output_parent/.cirewind-release-stage.XXXXXX")

case "$work" in
	"$work_root"/cirewind-release-build.*) ;;
	*)
		printf '%s\n' "refusing unsafe release work directory: $work" >&2
		exit 1
		;;
esac
case "$stage" in
	"$output_parent"/.cirewind-release-stage.*) ;;
	*)
		printf '%s\n' "refusing unsafe release stage: $stage" >&2
		exit 1
		;;
esac

cleanup() {
	trap - EXIT HUP INT TERM
	if [ -d "$work" ]; then
		rm -r -- "$work"
	fi
	if [ -n "$stage" ] && [ -d "$stage" ]; then
		rm -r -- "$stage"
	fi
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/tmp" "$work/go-tmp" "$work/go-cache" "$work/bin" "$work/descriptors"
export TMPDIR="$work/tmp"
export GOTMPDIR="$work/go-tmp"
if [ -z "${GOCACHE:-}" ]; then
	export GOCACHE="$work/go-cache"
fi
export GOFLAGS=-mod=readonly
export GOENV=off
export GOWORK=off
export GOEXPERIMENT=
export GOFIPS140=off
unset GOAMD64 GOARM64
cd "$root"

go_version=$(awk '/^go / { print $2; exit }' "$root/go.mod")
case "$go_version" in
	[0-9]*.[0-9]*.[0-9]*) ;;
	*)
		printf '%s\n' "go.mod does not declare an exact patch toolchain" >&2
		exit 1
		;;
esac
export GOTOOLCHAIN="go$go_version"
if [ "$(go env GOVERSION)" != "$GOTOOLCHAIN" ]; then
	printf '%s\n' "exact Go toolchain $GOTOOLCHAIN is unavailable" >&2
	exit 1
fi
go mod verify

CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$work/releasetool" ./internal/releasetool

# Each metadata value is strictly revalidated by releasetool before use. Pass
# flags independently so shell field splitting cannot change their boundaries.
build_date=$("$work/releasetool" build-date \
	"--version=$version" "--commit=$commit" "--go-version=$GOTOOLCHAIN" "--source-date-epoch=$source_date_epoch")
ldflags=$("$work/releasetool" ldflags \
	"--version=$version" "--commit=$commit" "--go-version=$GOTOOLCHAIN" "--source-date-epoch=$source_date_epoch")

for target in \
	linux/amd64 linux/arm64 \
	darwin/amd64 darwin/arm64 \
	windows/amd64 windows/arm64
do
	target_os=${target%/*}
	target_arch=${target#*/}
	suffix=
	if [ "$target_os" = windows ]; then
		suffix=.exe
	fi
	arch_env=GOAMD64=v1
	if [ "$target_arch" = arm64 ]; then
		arch_env=GOARM64=v8.0
	fi
	binary="$work/bin/cirewind-$target_os-$target_arch$suffix"
	descriptor="$work/descriptors/$target_os-$target_arch.json"
	env "$arch_env" CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" \
		go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$binary" ./cmd/cirewind
	"$work/releasetool" package \
		--root "$root" --binary "$binary" --out "$stage" --target "$target" \
		--descriptor "$descriptor" \
		"--version=$version" "--commit=$commit" "--go-version=$GOTOOLCHAIN" "--source-date-epoch=$source_date_epoch"
done

"$work/releasetool" finalize --out "$stage" "$work"/descriptors/*.json
"$work/releasetool" verify --dist "$stage"

chmod 0755 "$stage"
mv -- "$stage" "$output"
stage=

printf '%s\n' \
	"release candidate assembled: $output" \
	"version: $version" \
	"commit: $commit" \
	"source date: $build_date" \
	"authentication: unsigned; maintainer signature or platform attestation still required"
