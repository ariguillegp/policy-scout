#!/usr/bin/env sh
set -eu

commit_msg_file="${1:-}"

if [ -z "$commit_msg_file" ] || [ ! -f "$commit_msg_file" ]; then
  echo "commit message file not found" >&2
  exit 1
fi

subject="$(sed -n '1p' "$commit_msg_file")"

case "$subject" in
  Merge\ *|Revert\ *|fixup!\ *|squash!\ *)
    exit 0
    ;;
esac

if printf '%s\n' "$subject" | grep -Eq '^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)(\([A-Za-z0-9._/-]+\))?!?: .+'; then
  exit 0
fi

cat >&2 <<'EOF'
Commit message must use Conventional Commits:
  <type>[optional scope][!]: <description>

Allowed types: build, chore, ci, docs, feat, fix, perf, refactor, revert, style, test
EOF
exit 1
