#!/bin/sh
set -eu

script_root=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
guard=$script_root/local-instruction-files-guard.sh
work=$(mktemp -d "${TMPDIR:-/tmp}/cirewind-local-instruction-files.XXXXXX")
case "$work" in
  "${TMPDIR:-/tmp}"/cirewind-local-instruction-files.*) ;;
  *)
    printf '%s\n' 'refusing unsafe local-instruction-files test directory' >&2
    exit 1
    ;;
esac
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT HUP INT TERM

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

repository=$work/repository
commit() {
  git -C "$repository" -c user.name='Synthetic Test Maintainer' -c user.email='synthetic@example.invalid' commit -q -m "$1"
}

git init -q "$repository"
printf '%s\n' synthetic >"$repository/input.txt"
git -C "$repository" add input.txt
commit 'synthetic fixture'

# Without ignore rules the guard must refuse, because a plain git add would
# stage the local files.
if sh "$guard" --repository-root "$repository" 2>/dev/null; then
  fail 'guard accepted a repository whose ignore rules do not exclude local instruction files'
fi

printf '%s\n' AGENTS.md CLAUDE.md GEMINI.md .claude/ .codex/ .codex-tmp/ .cursor/ .cursorrules >"$repository/.gitignore"
git -C "$repository" add .gitignore
commit 'synthetic ignore policy'
sh "$guard" --repository-root "$repository"

# The maintainer's own copies stay on disk: untracked files never fail the guard.
printf '%s\n' 'local only' >"$repository/AGENTS.md"
mkdir "$repository/.claude"
printf '%s\n' '{}' >"$repository/.claude/settings.json"
sh "$guard" --repository-root "$repository"
git -C "$repository" add .
sh "$guard" --repository-root "$repository"
test -z "$(git -C "$repository" diff --cached --name-only)" || fail 'ignore rules let git add stage a local instruction file'

# Files with merely similar names are not local instruction files.
mkdir -p "$repository/docs" "$repository/internal/agents"
printf '%s\n' control >"$repository/docs/agent-roles.md"
printf '%s\n' control >"$repository/internal/agents/agents.go"
printf '%s\n' control >"$repository/docs/claude-shannon.md"
git -C "$repository" add docs internal
commit 'synthetic controls'
sh "$guard" --repository-root "$repository"

# Every local instruction path is rejected once staged, at any depth, in any
# letter case, and the failure names the path. Untracking it restores the pass
# while the file stays on disk.
for path in AGENTS.md CLAUDE.md GEMINI.md .cursorrules docs/AGENTS.md tools/agents.md \
  .claude/settings.json .codex/config.toml .codex-tmp/note .cursor/rules/a.mdc \
  internal/x/.claude/local.json docs/.Codex/prompt.md
do
  mkdir -p "$repository/$(dirname -- "$path")"
  printf '%s\n' 'local only' >"$repository/$path"
  git -C "$repository" add -f -- "$path"
  if output=$(sh "$guard" --repository-root "$repository" 2>&1); then
    fail "guard accepted staged $path"
  fi
  case "$output" in
    *"$path"*) ;;
    *) fail "guard did not name $path: $output" ;;
  esac
  commit "track $path"
  if sh "$guard" --repository-root "$repository" 2>/dev/null; then
    fail "guard accepted committed $path"
  fi
  git -C "$repository" rm -q --cached -- "$path"
  commit "untrack $path"
  test -f "$repository/$path" || fail "untracking removed $path from disk"
  sh "$guard" --repository-root "$repository"
done

# A nested directory is not accepted as the repository root.
mkdir "$repository/nested"
if sh "$guard" --repository-root "$repository/nested" 2>/dev/null; then
  fail 'guard accepted a nested path as repository root'
fi

if sh "$guard" --repository-root "$repository" --unknown 2>/dev/null; then
  fail 'guard accepted an unknown option'
fi

printf '%s\n' 'local instruction files guard tests passed'
