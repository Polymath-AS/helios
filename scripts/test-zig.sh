#!/usr/bin/env bash
# Runs the unit tests of every Zig package, then builds libhelios.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for pkg in "$ROOT"/pkg/*/; do
  echo "== $(basename "$pkg")"
  (cd "$pkg" && zig build test -Dcpu=native --summary failures)
done
echo "== libhelios"
(cd "$ROOT/core" && zig build -Doptimize=ReleaseFast -Dcpu=native)
