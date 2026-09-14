#!/bin/sh
set -eu

usage() {
  printf '%s\n' \
    'Usage: scripts/local-instruction-files-guard.sh [--repository-root DIR]' \
    '' \
    'Fails when the Git index of DIR (default: this repository) tracks a local' \
    'instruction file for a coding assistant, or when the ignore rules of DIR do' \
    'not exclude such files. AGENTS.md, CLAUDE.md, GEMINI.md, .cursorrules, and' \
    'the .claude, .codex, .codex-tmp, and .cursor directories stay on the' \
    'maintainer'"'"'s machine and are never part of the public tree.'
}

repository_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
while [ $# -gt 0 ]; do
  case "$1" in
    --repository-root)
      [ $# -ge 2 ] || { usage >&2; exit 2; }
      repository_root=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

repository_root=$(CDPATH='' cd -- "$repository_root" && pwd -P)
git_root=$(git -C "$repository_root" rev-parse --show-toplevel)
git_root=$(CDPATH='' cd -- "$git_root" && pwd -P)
if [ "$git_root" != "$repository_root" ]; then
  printf '%s\n' 'local instruction files guard: repository root is not the exact worktree root' >&2
  exit 2
fi

temporary_parent=${TMPDIR:-/tmp}
temporary_parent=$(CDPATH='' cd -- "$temporary_parent" && pwd -P) || {
  printf '%s\n' 'local instruction files guard: temporary parent is unavailable' >&2
  exit 2
}
temporary_root=$(mktemp -d "$temporary_parent/cirewind-local-instruction-files-guard.XXXXXX")
case "$temporary_root" in
  "$temporary_parent"/cirewind-local-instruction-files-guard.*) ;;
  *)
    printf '%s\n' 'local instruction files guard: refusing unsafe temporary directory' >&2
    exit 2
    ;;
esac
cleanup() { rm -rf -- "$temporary_root"; }
trap cleanup EXIT HUP INT TERM

# Check the producer before reading its output so a Git failure cannot pass as
# an empty index.
if ! git -C "$repository_root" ls-files --cached --full-name -z >"$temporary_root/tracked"; then
  printf '%s\n' 'local instruction files guard: unable to list the index' >&2
  exit 2
fi

# Names are compared in lower case because the assistants that read these
# files also run on case-insensitive filesystems.
tracked=$(tr '\0' '\n' <"$temporary_root/tracked" | awk -F/ '
{
  for (i = 1; i <= NF; i++) {
    segment = tolower($i)
    if (segment == ".claude" || segment == ".codex" || segment == ".codex-tmp" || segment == ".cursor") {
      print
      next
    }
  }
  segment = tolower($NF)
  if (segment == "agents.md" || segment == "claude.md" || segment == "gemini.md" || segment == ".cursorrules") {
    print
  }
}')

status=0
if [ -n "$tracked" ]; then
  printf '%s\n' 'local instruction files guard: the index tracks local instruction files for coding assistants:' "$tracked" >&2
  status=1
fi

missing=''
for probe in AGENTS.md CLAUDE.md GEMINI.md .cursorrules .claude/probe .codex/probe .codex-tmp/probe .cursor/probe nested/AGENTS.md nested/.claude/probe; do
  probe_status=0
  git -C "$repository_root" check-ignore -q --no-index -- "$probe" || probe_status=$?
  case $probe_status in
    0) ;;
    1) missing="$missing $probe" ;;
    *)
      printf '%s\n' 'local instruction files guard: unable to evaluate the ignore rules' >&2
      exit 2
      ;;
  esac
done
if [ -n "$missing" ]; then
  printf '%s\n' "local instruction files guard: the ignore rules do not exclude:$missing" >&2
  status=1
fi

cleanup
trap - EXIT HUP INT TERM
exit "$status"
