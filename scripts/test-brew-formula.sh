#!/bin/sh
# Qualify the Homebrew formula generator against synthetic release subjects.
#
# Usage: test-brew-formula.sh WORK_ROOT
#
# Builds a synthetic release distribution at the current commit, renders the
# upstream-shaped formula and audits it, then renders a fixture formula whose
# subjects are served from a loopback address and installs and tests it with
# the Homebrew found at CIREWIND_BREW or on PATH. Nothing is published, no
# tap is created, and no subject hash is called final.

set -eu

if [ "$#" -ne 1 ]; then
	printf '%s\n' "usage: $0 WORK_ROOT" >&2
	exit 2
fi

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work_root=$1
mkdir -p -- "$work_root"
work_root=$(CDPATH='' cd -- "$work_root" && pwd -P)
work=$(mktemp -d "$work_root/cirewind-brew-formula.XXXXXX")
case "$work" in
	"$work_root"/cirewind-brew-formula.*) ;;
	*)
		printf '%s\n' "refusing unsafe formula workspace: $work" >&2
		exit 1
		;;
esac
server_pid=
tap_root=
cleanup() {
	trap - EXIT HUP INT TERM
	if [ -n "$server_pid" ]; then kill "$server_pid" 2>/dev/null || true; fi
	if [ -n "$tap_root" ] && [ -d "$tap_root" ]; then rm -r -- "$tap_root"; fi
	if [ -d "$work" ]; then rm -r -- "$work"; fi
}
trap cleanup EXIT HUP INT TERM

brew_bin=${CIREWIND_BREW:-$(command -v brew || true)}
if [ -z "$brew_bin" ] || [ ! -x "$brew_bin" ]; then
	printf '%s\n' "Homebrew is required: set CIREWIND_BREW to a brew executable or add brew to PATH" >&2
	exit 2
fi
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_INSTALL_CLEANUP=1 \
	HOMEBREW_NO_ENV_HINTS=1 HOMEBREW_NO_INSTALL_FROM_API=1 HOMEBREW_NO_INSTALL_UPGRADE=1

version=0.0.1
commit=$(git -C "$root" rev-parse --verify 'HEAD^{commit}')
epoch=946684800
mkdir -p "$work/tmp" "$work/go-tmp" "$work/go-cache"
export TMPDIR="$work/tmp"
export GOTMPDIR="$work/go-tmp"
if [ -z "${GOCACHE:-}" ]; then
	export GOCACHE="$work/go-cache"
fi
go_version=$(awk '/^go / { print $2; exit }' "$root/go.mod")
export GOTOOLCHAIN="go$go_version"
export GOFLAGS=-mod=readonly
cd "$root"

CIREWIND_RELEASE_WORK_ROOT="$work_root" "$root/scripts/build-release.sh" "$version" "$commit" "$epoch" "$work/dist" >/dev/null
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o "$work/releasetool" ./internal/releasetool

# Upstream-shaped formula: audited and style-checked, never installed here.
"$work/releasetool" formula --dist "$work/dist" --out "$work/cirewind.rb" >/dev/null
"$work/releasetool" formula --dist "$work/dist" --out "$work/cirewind-again.rb" >/dev/null
cmp -s "$work/cirewind.rb" "$work/cirewind-again.rb" || {
	printf '%s\n' "formula rendering is not deterministic" >&2
	exit 1
}
grep -q 'releases/download/v0.0.1/cirewind_0.0.1_linux_amd64.tar.gz' "$work/cirewind.rb"

# Homebrew audits, installs, and tests formulae only through a tap, so the
# candidate formula is exposed through a throwaway local tap that is removed
# on exit. Nothing is pushed anywhere.
tap_root="$("$brew_bin" --repository)/Library/Taps/cirewind-qualification"
tap_dir="$tap_root/homebrew-fixture"
if [ -e "$tap_root" ]; then
	printf '%s\n' "refusing to reuse an existing qualification tap: $tap_root" >&2
	exit 1
fi
mkdir -p "$tap_dir/Formula"
cp "$work/cirewind.rb" "$tap_dir/Formula/cirewind.rb"
"$brew_bin" style "$tap_dir/Formula/cirewind.rb"
"$brew_bin" audit --strict cirewind-qualification/fixture/cirewind

# Fixture formula: subjects served from a loopback address that mirrors the
# upstream path shape, so install and test exercise the real archive bytes.
port=$(python3 -c 'import socket
s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
mkdir -p "$work/serve/torjan0/cirewind/releases/download/v$version"
cp "$work/dist/cirewind_${version}_"*.tar.gz "$work/serve/torjan0/cirewind/releases/download/v$version/"
python3 -m http.server --bind 127.0.0.1 --directory "$work/serve" "$port" >"$work/server.log" 2>&1 &
server_pid=$!
mkdir -p "$work/fixture"
"$work/releasetool" formula --dist "$work/dist" --out "$work/fixture/cirewind.rb" \
	--download-base "http://127.0.0.1:$port/torjan0/cirewind/releases/download/v$version/" >/dev/null
head -1 "$work/fixture/cirewind.rb" | grep -q 'FIXTURE FORMULA'
cp "$work/fixture/cirewind.rb" "$tap_dir/Formula/cirewind.rb"

"$brew_bin" install cirewind-qualification/fixture/cirewind
installed_version=$("$("$brew_bin" --prefix)/bin/cirewind" version)
case "$installed_version" in
	"cirewind $version (commit $commit, built "*) ;;
	*)
		printf '%s\n' "installed formula reports unexpected version: $installed_version" >&2
		exit 1
		;;
esac
"$brew_bin" test cirewind-qualification/fixture/cirewind
"$brew_bin" uninstall cirewind-qualification/fixture/cirewind

printf '%s\n' "Homebrew formula generator qualified against synthetic subjects (audit, style, install, test; nothing published)"
