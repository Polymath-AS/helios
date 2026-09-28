#!/usr/bin/env bash
# pkg/nix-flake-lock (Zig) vs the nix-flake-lock crate (Rust, pinned in
# bench/flake-lock-rs): a differential check that both produce identical
# canonical output and validation results, then a single-threaded benchmark.
#
# Corpus: upstream's fixtures and generated benchmark inputs, every
# flake.lock under $FLAKE_LOCK_SEARCH (default: $HOME), and FUZZ mutated
# documents. Usage (inside `nix develop`): bench/flake-lock.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEARCH="${FLAKE_LOCK_SEARCH:-$HOME}"
FUZZ="${FUZZ:-20000}"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

cargo build -q --release --manifest-path "$ROOT/bench/flake-lock-rs/Cargo.toml"
(cd "$ROOT/bench/zig" && zig build -Doptimize=ReleaseFast -Dcpu=native)
RS="$ROOT/bench/flake-lock-rs/target/release/flake-lock-rs"
ZIG="$ROOT/bench/zig/zig-out/bin/flake-lock"

mkdir -p "$W/fixtures" "$W/real" "$W/fuzz"
UPSTREAM="$(find "${CARGO_HOME:-$HOME/.cargo}/registry/src" -path '*/nix-flake-lock-0.1.0/tests/fixtures' -type d | head -1)"| head -1)"
cp "$UPSTREAM"/*.lock "$W/fixtures/"
"$RS" gen "$W/fixtures"
i=0
while IFS= read -r -d '' f; do
  cp "$f" "$W/real/$(printf '%04d' $i).lock"; i=$((i + 1))
done < <(find "$SEARCH" -name flake.lock -not -path '*/.cache/*' -not -path '*/node_modules/*' -size -16M -print0 2>/dev/null)
mapfile -t SEEDS < <(ls "$W"/real/*.lock 2>/dev/null | head -50 || true)
"$RS" fuzz "$W/fuzz" "$FUZZ" 42 "$W"/fixtures/{tiny,typical,legacy-v5,legacy-v6}.lock "${SEEDS[@]}"

echo "== differential: $(ls "$W/fixtures" | wc -l) fixtures, $i real-world lock files, $FUZZ mutations"
find "$W/fixtures" "$W/real" "$W/fuzz" -name '*.lock' | sort >"$W/all"
xargs "$RS" canon <"$W/all" >"$W/rs.out"
FL_MODE=canon FL_LIST="$W/all" "$ZIG" >"$W/zig.out"
if cmp -s "$W/rs.out" "$W/zig.out"; then
  echo "identical output on $(wc -l <"$W/all") documents" \
    "($(grep -c -- '-- valid' "$W/rs.out") valid, $(grep -c -- '-- invalid' "$W/rs.out") invalid follows, $(grep -c -- '-- parse error' "$W/rs.out") rejected)"
else
  echo "MISMATCH"; diff <(cat "$W/rs.out") <(cat "$W/zig.out") | head -40; exit 1
fi

echo
echo "== benchmark (best of 7, ns per operation)"
mapfile -t BIGGEST < <(ls -S "$W"/real/*.lock 2>/dev/null | head -3 || true)
for f in "${BIGGEST[@]}"; do cp "$f" "$W/fixtures/real-$(basename "$f")"; done
find "$W/fixtures" -name '*.lock' | sort >"$W/bench"
xargs "$RS" bench <"$W/bench" | sort >"$W/rs.bench"
FL_MODE=bench FL_LIST="$W/bench" "$ZIG" | sort >"$W/zig.bench"
printf '%-38s %9s %12s %12s %8s\n' operation bytes "zig ns" "rust ns" speedup
join "$W/zig.bench" "$W/rs.bench" | while read -r key zi zn ri rn; do
  file="${key#*:}"; bytes=$(stat -c %s "$W/fixtures/$file")
  awk -v k="$key" -v b="$bytes" -v z="$zn" -v zi="$zi" -v r="$rn" -v ri="$ri" \
    'BEGIN { zz = z / zi; rr = r / ri; printf "%-38s %9d %12.0f %12.0f %7.2fx\n", k, b, zz, rr, rr / zz }'
done
