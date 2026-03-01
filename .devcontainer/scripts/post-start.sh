#!/usr/bin/env bash
set -euo pipefail

workspace_dir="${containerWorkspaceFolder:-$PWD}"
mkdir -p "${CARGO_TARGET_DIR:-/workspaces/.cargo-target}"

git config --global --add safe.directory "$workspace_dir" || true

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  repo_root="$(git rev-parse --show-toplevel)"
  git config --global --add safe.directory "$repo_root" || true
fi