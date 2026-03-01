#!/usr/bin/env bash
set -euo pipefail

if ! command -v rustc >/dev/null 2>&1; then
  echo "rustc not found on PATH" >&2
  exit 1
fi

workspace_dir="${containerWorkspaceFolder:-$PWD}"

mkdir -p "${CARGO_TARGET_DIR:-/workspaces/.cargo-target}"

git config --global --add safe.directory "$workspace_dir" || true
git config --global fetch.prune true
git config --global pull.rebase false
git config --global push.autoSetupRemote true
git config --global rerere.enabled true
git config --global worktree.guessRemote true

if [[ -f Cargo.toml ]]; then
  cargo fetch
fi