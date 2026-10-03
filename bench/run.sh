#!/usr/bin/env bash
# Benchmarks pkg/* (Zig) against the Haskell Nix libraries (nix-narinfo,
# nix-derivation, hnix-store) and Nix's own C++ NAR serialiser.
# Single-threaded, same corpus for both.
#
# Usage: bench/run.sh [store-path]   (inside `nix develop`)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-/run/current-system}"
WORK="$(mktemp -d)"
trap 'kill ${SERVER_PID:-} 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "building..." >&2
(cd "$ROOT" && cargo build --release -q)
(cd "$ROOT/bench/zig" && zig build -Doptimize=ReleaseFast -Dcpu=native)
GHC="$(nix build --no-link --print-out-paths --impure --expr "import $ROOT/bench/haskell/ghc.nix {}")/bin/ghc"
"$GHC" -O2 -fno-full-laziness -rtsopts -outputdir "$WORK/hs" -o "$WORK/bench-hs" "$ROOT/bench/haskell/Bench.hs" >/dev/null

echo "building corpus from $TARGET..." >&2
C="$WORK/corpus"; mkdir -p "$C"
nix key generate-secret --key-name bench-1 >"$C/key"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$WORK/secret"
"$ROOT/target/release/helios-server" --listen 127.0.0.1:18099 --data-dir "$WORK/data" \
  --signing-key-file "$C/key" --jwt-secret-file "$WORK/secret" --admin-secret-file "$WORK/secret" 2>/dev/null &
SERVER_PID=$!
for _ in $(seq 50); do curl -sf http://127.0.0.1:18099/healthz >/dev/null && break; sleep 0.1; done
export XDG_CONFIG_HOME="$WORK/config"
H="$ROOT/target/release/helios"
"$H" login a http://127.0.0.1:18099 "$(cat "$WORK/secret")" >/dev/null
"$H" cache create main >/dev/null
"$H" login ci http://127.0.0.1:18099 "$("$H" --server a token create bench --caches main 2>/dev/null | jq -r .token)" >/dev/null
"$H" push main -r "$TARGET" >/dev/null 2>&1
nix-store -qR "$TARGET" >"$WORK/paths"
while read -r p; do printf '%s\0' "$p"; done <"$WORK/paths" >"$C/paths.bin"
while read -r p; do curl -s "http://127.0.0.1:18099/main/$(basename "$p" | cut -c1-32).narinfo"; printf '\0'; done <"$WORK/paths" >"$C/narinfo.bin"
mapfile -t DRVS < <(find /nix/store -maxdepth 1 -name '*.drv' -print 2>/dev/null | head -3000 || true)
for d in "${DRVS[@]}"; do cat "$d"; printf '\0'; done >"$C/drv.bin"
kill "$SERVER_PID"; SERVER_PID=

export BENCH_DIR="$C"
ZIG="$ROOT/bench/zig/zig-out/bin/bench"
"$ZIG" 2>&1 | sort >"$WORK/zig.txt"
"$WORK/bench-hs" +RTS -A64m -RTS | sort >"$WORK/hs.txt"

# NAR: warm the page cache once, then time each implementation on the closure.
BENCH_ONLY=nar "$ZIG" >/dev/null 2>&1
BENCH_ONLY=nar "$ZIG" 2>&1 >/dev/null | sed 's/^/zig /' >"$WORK/nar.txt"
BENCH_ONLY=nar "$WORK/bench-hs" +RTS -A64m -RTS | sed 's/^/hs /' >>"$WORK/nar.txt"
t0=$(date +%s%N); xargs nix hash path --type sha256 <"$WORK/paths" >/dev/null; t1=$(date +%s%N)
echo "cpp nar-dump-sha256 $(awk '{print $3}' "$WORK/nar.txt" | head -1) $((t1 - t0))" >>"$WORK/nar.txt"

echo
echo "corpus: $(wc -l <"$WORK/paths") store paths, $(tr -cd '\0' <"$C/drv.bin" | wc -c) .drv files"
echo
printf '%-26s %14s %14s %9s\n' benchmark "helios ns/op" "haskell ns/op" speedup
join "$WORK/zig.txt" "$WORK/hs.txt" | awk '{z=$3/$2; h=$5/$4; printf "%-26s %14.1f %14.1f %8.1fx\n", $1, z, h, h/z}'
join -v1 "$WORK/zig.txt" "$WORK/hs.txt" | awk '{printf "%-26s %14.1f %14s\n", $1, $3/$2, "-"}'
echo
printf '%-30s %12s\n' "NAR serialise + SHA-256" "GiB/s (1 core)"
awk '{printf "%-30s %12.2f\n", ($1=="zig"?"helios (pkg/nix-archive)":($1=="hs"?"hnix-store-nar + crypton":"nix hash path (Nix C++)")), $3/$4*1e9/1073741824}' "$WORK/nar.txt"
