#!/usr/bin/env bash
# Whole-process comparisons with poop (https://github.com/andrewrk/poop):
# wall time, peak RSS, cycles, instructions, cache and branch misses, on the
# same work, counting child processes:
#
#   1. NAR serialise + SHA-256 of a closure: pkg/nix-archive (one pass of
#      the bench binary) vs `nix hash path`
#   2. flake.lock canonicalisation and validation: pkg/nix-flake-lock vs the
#      nix-flake-lock crate, on every flake.lock under $FLAKE_LOCK_SEARCH
#   3. Pushing a closure: `helios push` to a fresh local server (started,
#      populated and stopped each run) vs `nix copy` to a fresh zstd file
#      cache, both compressing at level 3 and signing. Nix reads the store
#      itself (read-only), so none of its work hides in the nix-daemon.
#
# poop counts user-space events only; I/O shows in wall time. Results go to
# the terminal, never to files in the tree.
#
# Usage (inside `nix develop`): bench/poop.sh [store-path]
#   default store path: python3's closure (about 200 MiB of NAR)
#   DURATION=ms per command (default 5000)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEARCH="${FLAKE_LOCK_SEARCH:-$HOME}"
DURATION="${DURATION:-5000}"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

echo "building..." >&2
(cd "$ROOT" && cargo build --release -q)
(cd "$ROOT/bench/zig" && zig build -Doptimize=ReleaseFast -Dcpu=native)
cargo build -q --release --manifest-path "$ROOT/bench/flake-lock-rs/Cargo.toml"
POOP="$(nix build --no-link --print-out-paths --inputs-from "$ROOT" nixpkgs#poop)/bin/poop"
TARGET="$(readlink -f "${1:-$(nix build --no-link --print-out-paths --inputs-from "$ROOT" nixpkgs#python3)}")"
BIN="$ROOT/target/release"

nix-store -qR "$TARGET" >"$W/paths"
while read -r p; do printf '%s\0' "$p"; done <"$W/paths" >"$W/paths.bin"
: >"$W/narinfo.bin"
: >"$W/drv.bin"
nix key generate-secret --key-name poop-1 >"$W/key"
find "$SEARCH" -name flake.lock -not -path '*/.cache/*' -not -path '*/node_modules/*' -size -16M 2>/dev/null >"$W/locks" || true
echo "closure of $TARGET: $(wc -l <"$W/paths") paths, $(nix path-info -rs "$TARGET" | awk '{s+=$2} END {printf "%.0f", s/1048576}') MiB of NAR" >&2
echo "flake.lock files: $(wc -l <"$W/locks")" >&2

# poop splits each command on spaces without a shell, so every side runs
# from a small script; both sides pay the same shell start.
script() {
  local name=$1
  shift
  printf '#!/bin/sh\nset -e\n%s\n' "$*" >"$W/$name"
  chmod +x "$W/$name"
}

script helios-nar "BENCH_DIR=$W BENCH_ONLY=nar-once exec $ROOT/bench/zig/zig-out/bin/bench"
script nix-nar "exec xargs nix hash path --type sha256 <$W/paths >/dev/null 2>&1"

script helios-flake-lock "FL_MODE=canon FL_LIST=$W/locks exec $ROOT/bench/zig/zig-out/bin/flake-lock >/dev/null"
script rust-flake-lock "exec xargs $ROOT/bench/flake-lock-rs/target/release/flake-lock-rs canon <$W/locks >/dev/null"

script helios-push "
d=\$(mktemp -d -p $W)
$BIN/helios-server generate-secrets --dir \$d/s >/dev/null 2>&1
HELIOS_LOG=error $BIN/helios-server --listen 127.0.0.1:18299 --data-dir \$d/data \\
  --signing-key-file \$d/s/signing-key --jwt-secret-file \$d/s/jwt-secret --admin-secret-file \$d/s/admin-secret &
pid=\$!
until curl -sf http://127.0.0.1:18299/healthz >/dev/null; do sleep 0.01; done
export XDG_CONFIG_HOME=\$d/cfg HELIOS_LOG=error
$BIN/helios login admin http://127.0.0.1:18299 \$(cat \$d/s/admin-secret) >/dev/null 2>&1
$BIN/helios cache create main >/dev/null
$BIN/helios login ci http://127.0.0.1:18299 \$($BIN/helios token create ci --caches main --perms push 2>/dev/null | sed -n 's/.*\"token\": *\"\\([^\"]*\\)\".*/\\1/p') >/dev/null 2>&1
$BIN/helios push main --closure \"\$@\" $TARGET >/dev/null 2>&1
kill \$pid; wait \$pid || true
rm -rf \$d"
# The same, without the long window: zstd level 3 exactly as Nix runs it.
sed 's|--closure "\$@"|--closure --window-log 0|' "$W/helios-push" >"$W/helios-push-plain"
chmod +x "$W/helios-push-plain"
script nix-copy "
d=\$(mktemp -d -p $W)
nix copy --extra-experimental-features read-only-local-store --from 'local?read-only=true' --to \"file://\$d?compression=zstd&compression-level=3&parallel-compression=true&secret-key=$W/key\" $TARGET
rm -rf \$d"

echo
echo "== NAR serialise + SHA-256"
"$POOP" -d "$DURATION" "$W/nix-nar" "$W/helios-nar"
echo
echo "== flake.lock canonicalise + validate"
"$POOP" -d "$DURATION" "$W/rust-flake-lock" "$W/helios-flake-lock"
echo
echo "== push a closure (compress at zstd 3, sign, store)"
"$POOP" -d "$DURATION" "$W/nix-copy" "$W/helios-push-plain" "$W/helios-push"
