#!/usr/bin/env bash
set -euo pipefail

spec_folder="${1:-}"
if [[ -z "$spec_folder" ]]; then
  echo "Usage: tools/spec_init.sh <SPEC_FOLDER_NAME> (e.g. 2026-03-01-feature-x)" >&2
  exit 1
fi

dir="specs/$spec_folder"
if [[ -e "$dir" ]]; then
  echo "❌ Spec folder exists: $dir" >&2
  exit 1
fi

mkdir -p "$dir/artifacts"
cp "specs/_templates/spec.md" "$dir/00-spec.md"
printf "# Plan\n\n" > "$dir/01-plan.md"
cat > "$dir/02-tasks.md" <<'EOF'
# Tasks

## T1
- Scope:
- Files:
- AC:
- DoD:
EOF
printf "# Decisions\n\n" > "$dir/03-decisions.md"
printf "# Progress\n\n- [ ] T1\n" > "$dir/04-progress.md"

echo "✅ Created spec folder: $dir"