#!/bin/sh

set -eu

mode=${1:-syscall}
case "$mode" in
  --source-only) mode=source ;;
  syscall) ;;
  *)
    printf '%s\n' "usage: public-lab-marker-audit.sh [--source-only]" >&2
    exit 2
    ;;
esac

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
marker_a="$root/lab/public/source/marker-a/actions/marker/action.yml"
marker_b="$root/lab/public/source/marker-b/actions/marker/action.yml"
restored_a="$root/lab/public/source/wrapper/actions/marker/action.yml"

cmp "$marker_a" "$restored_a"
expected_a=$(printf '%s\n' \
  'name: CIRewind lab marker' \
  'description: Print a fixed public marker for the harmless temporal evidence lab' \
  'runs:' \
  '  using: composite' \
  '  steps:' \
  '    - name: Print fixed marker' \
  '      shell: bash' \
  "      run: printf '%s\\n' 'cirewind-lab-marker=A'")
expected_b=$(printf '%s\n' \
  'name: CIRewind lab marker' \
  'description: Print a fixed public marker for the harmless temporal evidence lab' \
  'runs:' \
  '  using: composite' \
  '  steps:' \
  '    - name: Print fixed marker' \
  '      shell: bash' \
  "      run: printf '%s\\n' 'cirewind-lab-marker=B'")
[ "$(cat "$marker_a")" = "$expected_a" ]
[ "$(cat "$marker_b")" = "$expected_b" ]

if [ "$mode" = source ]; then
  printf '%s\n' "public-lab marker sources are exact fixed-output A/B definitions and restored A is byte-identical"
  exit 0
fi

if [ "$(uname -s 2>/dev/null || printf '%s' unknown)" != Linux ]; then
  printf '%s\n' "public-lab marker syscall audit requires Linux strace" >&2
  exit 2
fi
if ! command -v strace >/dev/null 2>&1; then
  printf '%s\n' "public-lab marker syscall audit requires strace" >&2
  exit 2
fi

audit_root=${CIREWIND_PUBLIC_LAB_AUDIT_ROOT:-${TMPDIR:-/tmp}}
audit_root=$(CDPATH='' cd -- "$audit_root" && pwd)
work=$(mktemp -d "$audit_root/cirewind-public-lab-marker.XXXXXX")

case "$work" in
  "$audit_root"/cirewind-public-lab-marker.*) ;;
  *)
    printf '%s\n' "refusing unsafe public-lab audit workspace: $work" >&2
    exit 1
    ;;
esac

cleanup() {
  rm -r -- "$work"
}
trap cleanup EXIT HUP INT TERM

audit_marker() {
  label=$1
  value=$2
  directory="$work/$label"
  output="$work/$label.out"
  trace="$work/$label.trace"
  mkdir "$directory"
  (
    cd "$directory"
    env -i PATH=/usr/bin:/bin strace -f -qq -e trace=network,process,file \
      -o "$trace" /bin/bash --noprofile --norc -c \
      "printf '%s\\n' 'cirewind-lab-marker=$value'" >"$output"
  )
  [ "$(cat "$output")" = "cirewind-lab-marker=$value" ]
  [ -z "$(find "$directory" -mindepth 1 -print -quit)" ]
  exec_count=$(grep -Ec 'execve(at)?\(' "$trace" || true)
  if [ "$exec_count" -ne 1 ]; then
    printf '%s\n' "$label launched a child process (exec count: $exec_count)" >&2
    exit 1
  fi
  if grep -Eq 'socket\(AF_(INET|INET6|NETLINK|PACKET)|sin(6)?_(port|addr)|connect\([^,]+, \{sa_family=AF_(INET|INET6|NETLINK|PACKET)' "$trace"; then
    printf '%s\n' "$label attempted an IP or kernel-network endpoint" >&2
    exit 1
  fi
  if grep -E '(^|[[:space:]])(socket|connect)\(' "$trace" | grep -Ev 'socket\(AF_UNIX, SOCK_STREAM\|SOCK_CLOEXEC\|SOCK_NONBLOCK, 0\)|connect\([^,]+, \{sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"\}.* = -1 ENOENT' >/dev/null; then
    printf '%s\n' "$label made an unexpected socket call" >&2
    exit 1
  fi
  if grep -Eq '(^|[[:space:]])(creat|unlink|unlinkat|rename|renameat|renameat2|mkdir|mkdirat|rmdir|link|linkat|symlink|symlinkat|mknod|mknodat|chmod|fchmod|fchmodat|chown|fchown|lchown|fchownat|truncate|ftruncate)\(' "$trace" ||
     grep -E '(^|[[:space:]])open(at|at2)?\(.*O_(WRONLY|RDWR|CREAT|TRUNC|APPEND|TMPFILE)' "$trace" | grep -Ev 'openat\(AT_FDCWD, "/dev/tty", O_RDWR\|O_NONBLOCK\) = -1 ENXIO' >/dev/null; then
    printf '%s\n' "$label attempted a filesystem mutation" >&2
    exit 1
  fi
}

audit_marker marker-a A
audit_marker marker-b B

printf '%s\n' "public-lab markers emitted fixed output with no child process, IP endpoint, or filesystem mutation"
