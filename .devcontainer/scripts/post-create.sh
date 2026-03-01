#!/usr/bin/env bash
set -euo pipefail

required_rust="1.93.1"
actual_rust="$(rustc --version | awk '{print $2}')"

if [[ "$actual_rust" != "$required_rust" ]]; then
  echo "Expected rustc ${required_rust}, got ${actual_rust}" >&2
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