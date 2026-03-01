#!/usr/bin/env bash
set -euo pipefail

if [[ -f "Cargo.toml" || -f "Cargo.lock" ]]; then
  cargo run --quiet --manifest-path tools/specguard/Cargo.toml -- specs
  exit 0
fi

echo "❌ No verifier configured for this repo's primary language."
echo "   Detected: no Cargo.toml/Cargo.lock."
echo "   Add a verifier implementation (Go/Python/etc.) following the same interface."
exit 1