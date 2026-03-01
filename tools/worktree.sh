#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  tools/worktree.sh create <branch> <dir>
  tools/worktree.sh remove <dir>
  tools/worktree.sh list
EOF
  exit 1
}

action="${1:-}"
case "$action" in
  create)
    branch="${2:-}"; dir="${3:-}"
    [[ -n "$branch" && -n "$dir" ]] || usage
    git worktree add -b "$branch" "$dir"
    ;;
  remove)
    dir="${2:-}"
    [[ -n "$dir" ]] || usage
    git worktree remove "$dir"
    ;;
  list)
    git worktree list
    ;;
  *)
    usage
    ;;
esac