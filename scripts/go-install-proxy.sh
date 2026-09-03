#!/bin/sh

# Builds a file-based Go module proxy tree that serves the current source tree
# as exactly one synthetic module version. The tree is a snapshot of the
# tracked and untracked (not ignored) files taken through a temporary Git index,
# so the real index and worktree are never modified. Nothing is published and
# no network is used.
#
# usage: go-install-proxy.sh PROXY_ROOT VERSION
#
# PROXY_ROOT must be an existing absolute directory; VERSION must start with
# "v" followed by a digit. On success the proxy root is printed.

set -eu

if [ "$#" -ne 2 ]; then
  printf '%s\n' "usage: go-install-proxy.sh PROXY_ROOT VERSION" >&2
  exit 2
fi
proxy_root=$1
version=$2
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
module=github.com/torjan0/cirewind

case "$version" in
  v[0-9]*) ;;
  *)
    printf '%s\n' "synthetic module version must start with v and a digit: $version" >&2
    exit 2
    ;;
esac
case "$proxy_root" in
  /*) ;;
  *)
    printf '%s\n' "proxy root must be an absolute path" >&2
    exit 2
    ;;
esac
if [ ! -d "$proxy_root" ] || [ -L "$proxy_root" ]; then
  printf '%s\n' "proxy root must be an existing real directory" >&2
  exit 2
fi

proxy="$proxy_root/$module/@v"
mkdir -p "$proxy"
index=$(mktemp "$proxy_root/.index.XXXXXX")
tree=$(cd "$root" && GIT_INDEX_FILE="$index" sh -c 'git read-tree HEAD && git add -A && git write-tree')
rm -f -- "$index"
(cd "$root" && git archive --format=zip --prefix="$module@$version/" -o "$proxy/$version.zip" "$tree")
cp "$root/go.mod" "$proxy/$version.mod"
printf '{"Version":"%s","Time":"2026-01-01T00:00:00Z"}\n' "$version" >"$proxy/$version.info"
printf '%s\n' "$version" >"$proxy/list"
printf '%s\n' "$proxy_root"
