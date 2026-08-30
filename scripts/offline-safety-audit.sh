#!/bin/sh

set -eu

if [ "$(uname -s 2>/dev/null || printf '%s' unknown)" != Linux ]; then
  printf '%s\n' "offline syscall audit requires Linux strace" >&2
  exit 2
fi
if ! command -v strace >/dev/null 2>&1; then
  printf '%s\n' "offline syscall audit requires strace" >&2
  exit 2
fi

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
work_root=${CIREWIND_SAFETY_AUDIT_ROOT:-${TMPDIR:-/tmp}}
work_root=$(CDPATH='' cd -- "$work_root" && pwd)
work=$(mktemp -d "$work_root/cirewind-safety-audit.XXXXXX")

case "$work" in
  "$work_root"/cirewind-safety-audit.*) ;;
  *)
    printf '%s\n' "refusing unsafe safety-audit workspace: $work" >&2
    exit 1
    ;;
esac

cleanup() {
  rm -r -- "$work"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$work/tmp" "$work/go-cache"
export TMPDIR="$work/tmp"
export GOTMPDIR="$work/tmp"
export GOCACHE="$work/go-cache"
export GOFLAGS=-mod=readonly

go_version=$(awk '/^go / { print $2; exit }' "$root/go.mod")
case "$go_version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *)
    printf '%s\n' "invalid Go version in go.mod: $go_version" >&2
    exit 1
    ;;
esac
export GOTOOLCHAIN="go$go_version"
export CGO_ENABLED=0

binary="$work/cirewind"
packreview_binary="$work/packreview"
archive="$work/archive.db"
case_dir="$work/case"
demo_dir="$work/demo"
pack="$root/incidents/synthetic/mutable-tag.yaml"

cd "$root"
go build -trimpath -o "$binary" ./cmd/cirewind
go build -trimpath -o "$packreview_binary" ./tools/packreview

audit_command() {
	label=$1
	shift
	audit_binary "$label" "$binary" "$@"
}

audit_binary() {
	label=$1
	program=$2
	shift 2
	trace="$work/$label.trace"
	strace -f -qq -e trace=network,execve,execveat -o "$trace" "$program" "$@"

  exec_count=$(grep -Ec 'execve(at)?\(' "$trace" || true)
  if [ "$exec_count" -ne 1 ]; then
    printf '%s\n' "$label launched a child process (exec count: $exec_count)" >&2
    exit 1
  fi
  if grep -Eq '[[:space:]](socket|socketpair|bind|listen|accept|accept4|connect|sendto|recvfrom|sendmsg|recvmsg|sendmmsg|recvmmsg|shutdown|getsockname|getpeername|getsockopt|setsockopt)\(' "$trace"; then
    printf '%s\n' "$label made a network-system-call attempt" >&2
    exit 1
  fi
  printf '%s\n' "$label: no network syscall and no child exec"
}

audit_command pack-validate pack validate "$pack"
audit_command archive-fixture archive --import-fixture synthetic --store "$archive"
audit_command replay replay \
  --archive "$archive" \
  --incident "$pack" \
  --out "$case_dir" \
  --fixed-collection-time 2026-08-20T00:00:00Z
audit_command verify verify "$case_dir"
audit_command demo demo --out "$demo_dir"
audit_binary pack-review-governance "$packreview_binary" validate-governance --repository-root "$root"

printf '%s\n' "offline syscall safety audit passed"
