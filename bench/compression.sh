#!/usr/bin/env bash
# Compares NAR compression codecs that Nix clients can decode (the narinfo
# `Compression` field), plus how much a closure dedups across NARs.
# Every NAR is compressed on its own, the way a cache serves it. Times are
# single-threaded CPU seconds (user+sys), summed over the closure; jobs run
# in parallel across NARs.
#
# Usage: bench/compression.sh [store-path]
#   CODECS="zstd-3 xz-6"   only these codecs (default: all below)
#   JOBS=N                 parallel jobs (default: nproc)
#   OUT=file.tsv           keep the per-NAR results (default: discarded)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Pin every codec to the flake's nixpkgs so runs are comparable.
if [ -z "${HELIOS_BENCH_SHELL:-}" ]; then
  export HELIOS_BENCH_SHELL=1
  exec nix shell --inputs-from "$ROOT" nixpkgs#{zstd,xz,brotli,lz4,lzop,lzip,gzip,bzip2,coreutils,findutils,gawk} -c "$0" "$@"
fi

TARGET="$(readlink -f "${1:-/run/current-system}")"
JOBS="${JOBS:-$(nproc)}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# name|narinfo Compression|compress|decompress. zstd windows stay at 2^27
# and brotli at its default, the largest a stock Nix decoder accepts.
ALL=(
  "none|none|cat|cat"
  "lz4-1|lz4|lz4 -q -1 -c|lz4 -q -d -c"
  "lz4-9|lz4|lz4 -q -9 -c|lz4 -q -d -c"
  "lzop-1|lzop|lzop -q -1 -c|lzop -q -d -c"
  "gzip-6|gzip|gzip -6 -c|gzip -d -c"
  "gzip-9|gzip|gzip -9 -c|gzip -d -c"
  "bzip2-9|bzip2|bzip2 -9 -c|bzip2 -d -c"
  "zstd-1|zstd|zstd -q -T1 -1 -c|zstd -q -d -c"
  "zstd-2|zstd|zstd -q -T1 -2 -c|zstd -q -d -c"
  "zstd-3|zstd|zstd -q -T1 -3 -c|zstd -q -d -c"
  "zstd-9|zstd|zstd -q -T1 -9 -c|zstd -q -d -c"
  "zstd-19|zstd|zstd -q -T1 -19 -c|zstd -q -d -c"
  "zstd-3-long|zstd|zstd -q -T1 -3 --long=27 -c|zstd -q -d -c"
  "zstd-6-long|zstd|zstd -q -T1 -6 --long=27 -c|zstd -q -d -c"
  "zstd-9-long|zstd|zstd -q -T1 -9 --long=27 -c|zstd -q -d -c"
  "zstd-12-long|zstd|zstd -q -T1 -12 --long=27 -c|zstd -q -d -c"
  "zstd-19-long|zstd|zstd -q -T1 -19 --long=27 -c|zstd -q -d -c"
  "zstd-22-long|zstd|zstd -q -T1 --ultra -22 --long=27 -c|zstd -q -d -c"
  "br-6|br|brotli -q 6 -c|brotli -d -c"
  "br-11|br|brotli -q 11 -c|brotli -d -c"
  "xz-6|xz|xz -T1 -6 -c|xz -d -c"
  "xz-9e|xz|xz -T1 -9e -c|xz -d -c"
  "lzip-6|lzip|lzip -q -6 -c|lzip -q -d -c"
)
: >"$WORK/codecs"
for c in "${ALL[@]}"; do
  if [ -z "${CODECS:-}" ] || [[ " $CODECS " == *" ${c%%|*} "* ]]; then echo "$c" >>"$WORK/codecs"; fi
done

echo "dumping closure of $TARGET..." >&2
mkdir -p "$WORK/nar"
nix-store -qR "$TARGET" >"$WORK/paths"
xargs -P "$JOBS" -I{} sh -c 'nix-store --dump "$1" >"$2/nar/$(basename "$1").nar"' _ {} "$WORK" <"$WORK/paths"
RAW=$(du -cb "$WORK"/nar/*.nar | tail -1 | cut -f1)
echo "$(wc -l <"$WORK/paths") paths, $((RAW / 1048576)) MiB of NAR" >&2

# One job per (codec, NAR), largest NARs first so the pool drains evenly.
job() {
  IFS='|' read -r name _ comp decomp <<<"$1"
  local nar=$2 tmp; tmp="$(mktemp -p "$WORK")"
  TIMEFORMAT='%3U %3S'
  local ct dt
  ct=$( { time $comp <"$nar" >"$tmp"; } 2>&1 )
  dt=$( { time $decomp <"$tmp" >/dev/null; } 2>&1 )
  $decomp <"$tmp" | cmp -s - "$nar" || { echo "roundtrip failed: $name $nar" >&2; exit 1; }
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$(basename "$nar")" "$(stat -c%s "$nar")" "$(stat -c%s "$tmp")" \
    "$(awk '{print $1+$2}' <<<"$ct")" "$(awk '{print $1+$2}' <<<"$dt")"
  rm -f "$tmp"
}
export -f job; export WORK
ls -S "$WORK"/nar/*.nar >"$WORK/nars"
while read -r c; do while read -r n; do printf '%s\0%s\0' "$c" "$n"; done <"$WORK/nars"; done <"$WORK/codecs" \
  | xargs -0 -n2 -P "$JOBS" bash -c 'job "$1" "$2"' _ >"$WORK/results.tsv"
[ -n "${OUT:-}" ] && cp "$WORK/results.tsv" "$OUT"

echo
printf '%-14s %-6s %11s %7s %9s %12s %12s\n' codec narinfo "size MiB" ratio "vs zstd-3" "comp MB/s" "decomp MB/s"
awk -F'\t' -v order="$(cut -d'|' -f1,2 "$WORK/codecs" | tr '\n' ' ')" '
  { raw[$1]+=$3; out[$1]+=$4; ct[$1]+=$5; dt[$1]+=$6 }
  END {
    n = split(order, o, " "); base = ("zstd-3" in out) ? out["zstd-3"] : 0
    for (i = 1; i <= n; i++) {
      split(o[i], f, "|"); c = f[1]
      printf "%-14s %-6s %11.1f %7.2f %9s %12.0f %12.0f\n", c, f[2], out[c]/1048576, raw[c]/out[c],
        base ? sprintf("%+.1f%%", (out[c]/base-1)*100) : "-",
        ct[c] ? raw[c]/ct[c]/1e6 : 0, dt[c] ? raw[c]/dt[c]/1e6 : 0
    }
  }' "$WORK/results.tsv"

# Headroom beyond per-NAR compression, which only the storage side can use.
echo
echo "storage-side redundancy (not servable as-is):"
find "$WORK/nar" -name '*.nar' -print0 | xargs -0 cat | zstd -q -T"$JOBS" -9 --long=31 -c | wc -c \
  | awk -v raw="$RAW" '{printf "  whole closure as one zstd-9 --long=31 stream: %.1f MiB (%.2fx)\n", $1/1048576, raw/$1}'
xargs -I{} find {} -type f -printf '%s\t%p\n' <"$WORK/paths" | LC_ALL=C sort -t $'\t' -k2,2 >"$WORK/sizes"
xargs -I{} find {} -type f -print0 <"$WORK/paths" | xargs -0 -n 2000 -P "$JOBS" sha256sum \
  | awk '{h=$1; $1=""; sub(/^ \*?/, ""); print $0 "\t" h}' | LC_ALL=C sort -t $'\t' -k1,1 >"$WORK/hashes"
LC_ALL=C join -t $'\t' -1 2 -2 1 "$WORK/sizes" "$WORK/hashes" \
  | awk -F'\t' '{ tot+=$2; if (!seen[$3]++) uniq+=$2 } END {
      printf "  regular files: %.1f MiB, %.1f MiB unique by content (%.1f%% duplicate)\n", tot/1048576, uniq/1048576, (1-uniq/tot)*100 }'
