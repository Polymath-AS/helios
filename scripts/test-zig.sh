#!/usr/bin/env bash
# Runs the unit tests of every Zig package, then builds libhelios. Tests run
# in Debug and in ReleaseFast, which libhelios ships with: std skips some
# checks without runtime safety.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for pkg in "$ROOT"/pkg/*/; do
  for mode in Debug ReleaseFast; do
    echo "== $(basename "$pkg") ($mode)"
    (cd "$pkg" && zig build test -Doptimize=$mode -Dcpu=native --summary failures)
  done
done
echo "== libhelios"
(cd "$ROOT/core" && zig build -Doptimize=ReleaseFast -Dcpu=native)
