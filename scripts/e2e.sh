#!/usr/bin/env bash
# End-to-end test: start helios-server on a scratch data dir, push a real
# closure with the CLI, then have Nix substitute it back into a fresh store
# with signature checking on.
#
# Usage: scripts/e2e.sh [store-path]   (run inside `nix develop`, after `cargo build --release`)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$ROOT/target/release}"
PORT="${PORT:-18080}"
URL="http://127.0.0.1:$PORT"
TARGET="${1:-$(readlink -f "$(command -v zstd)" | cut -d/ -f1-4)}"

WORK="$(mktemp -d)"
cleanup() {
  [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null || true
  chmod -R u+w "$WORK" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

PASS=0
FAIL=0
check() {
  if [ "$2" = "$3" ]; then
    echo "  ok: $1"
    PASS=$((PASS + 1))
  else
    echo "  FAIL: $1 (expected=$2 got=$3)"
    FAIL=$((FAIL + 1))
  fi
}
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

nix key generate-secret --key-name e2e-1 >"$WORK/key"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$WORK/jwt"
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' >"$WORK/admin"
PUBKEY="$("$BIN/helios-server" --print-public-key --signing-key-file "$WORK/key")"

# Debug logs each request, which the chunked-upload checks count.
HELIOS_LOG=warn,helios_server=debug "$BIN/helios-server" 2>"$WORK/server.log" \
  --listen "127.0.0.1:$PORT" \
  --data-dir "$WORK/data" \
  --signing-key-file "$WORK/key" \
  --jwt-secret-file "$WORK/jwt" \
  --admin-secret-file "$WORK/admin" \
  --admin-socket "$WORK/admin.sock" &
SERVER_PID=$!
for _ in $(seq 50); do curl -sf "$URL/healthz" >/dev/null && break; sleep 0.1; done

export XDG_CONFIG_HOME="$WORK/config"
# Nix caches narinfo per substituter URL; keep runs (and their keys) apart.
export XDG_CACHE_HOME="$WORK/cache"
helios() { "$BIN/helios" "$@"; }

echo "=== admin"
helios login admin "$URL" "$(cat "$WORK/admin")" >/dev/null
helios cache create main >/dev/null
helios cache create secret --private >/dev/null
helios cache create chunked >/dev/null
helios cache create plain >/dev/null
PUSH_TOKEN="$(helios token create ci --caches main,secret,chunked,plain --perms push,pull 2>/dev/null | jq -r .token)"
PULL_ONLY="$(helios token create reader --caches secret 2>/dev/null | jq -r .token)"
PUSH_ONLY="$(helios token create builder --caches secret --perms push 2>/dev/null | jq -r .token)"
check "tokens are read-only by default" '["pull"]' "$(helios token list | jq -c '.tokens[] | select(.subject=="reader") | .perms')"
check "admin rejects push token" 403 "$(status -H "authorization: Bearer $PUSH_TOKEN" "$URL/_api/v2/admin/tokens")"

echo "=== chunked upload"

helios login ci "$URL" "$PUSH_TOKEN" >/dev/null
# 1 MiB chunks: the closure's larger NARs go in pieces, the rest in one request.
helios push chunked --closure --chunk-size 1 "$TARGET" 2>&1 | tail -1
check "large NARs were sent in chunks" true "$([ "$(grep -c 'method=PATCH' "$WORK/server.log")" -gt 1 ] && echo true)"
NIX_CONFIG="trusted-public-keys = $PUBKEY
require-sigs = true" nix copy --from "$URL/chunked" --to "$WORK/chunked-store" "$TARGET" 2>&1 | tail -3
check "chunked closure substitutes" "$(nix-store -qR "$TARGET" | wc -l)" "$(nix-store --store "$WORK/chunked-store" -qR "$TARGET" | wc -l)"

# Level 0: raw NARs, served as such. A fresh path, so no NAR is reused.
head -c 100000 /dev/urandom >"$WORK/plain-file"
PLAIN="$(nix-store --add "$WORK/plain-file")"
helios push plain --level 0 "$PLAIN" 2>&1 | tail -1
check "level 0 publishes uncompressed NARs" "none" "$(curl -s "$URL/plain/$(basename "$PLAIN" | cut -c1-32).narinfo" | sed -n 's/^Compression: //p')"
NIX_CONFIG="trusted-public-keys = $PUBKEY
require-sigs = true" nix copy --from "$URL/plain" --to "$WORK/plain-store" "$PLAIN" 2>&1 | tail -3
check "an uncompressed NAR substitutes" "$(nix-store -q --hash "$PLAIN")" "$(nix-store --store "$WORK/plain-store" -q --hash "$PLAIN")"
check "the server advertises compression defaults to pushers" '3 27' "$(curl -s -H "authorization: Bearer $PUSH_ONLY" "$URL/_api/v2/caches/secret" | jq -r '"\(.compression.level) \(.compression.windowLog)"')"

AUTH=(-H "authorization: Bearer $PUSH_TOKEN")
new_upload() { curl -s -X POST "${AUTH[@]}" "$URL/_api/v2/caches/chunked/uploads" | jq -r .id; }
NAR="$WORK/one.nar.zst"
nix-store --dump "$TARGET" | zstd -q >"$NAR"
NAR_BYTES="$(stat -c %s "$NAR")"
HALF=$((NAR_BYTES / 2))
ID="$(new_upload)"
head -c "$HALF" "$NAR" >"$WORK/part1"
tail -c +$((HALF + 1)) "$NAR" >"$WORK/part2"
check "chunk at the wrong offset" 409 "$(status -X PATCH "${AUTH[@]}" --data-binary @"$WORK/part2" "$URL/_api/v2/caches/chunked/uploads/$ID?offset=$HALF")"
curl -s -o /dev/null -X PATCH "${AUTH[@]}" --data-binary @"$WORK/part1" "$URL/_api/v2/caches/chunked/uploads/$ID?offset=0"
check "resume reads the offset" "$HALF" "$(curl -s "${AUTH[@]}" "$URL/_api/v2/caches/chunked/uploads/$ID" | jq .offset)"
check "another token cannot see the upload" 404 "$(status -H "authorization: Bearer $PUSH_ONLY" "$URL/_api/v2/caches/secret/uploads/$ID")"
curl -s -o /dev/null -X PATCH "${AUTH[@]}" --data-binary @"$WORK/part2" "$URL/_api/v2/caches/chunked/uploads/$ID?offset=$HALF"
EXPECT="sha256:$(nix-store -q --hash "$TARGET" | cut -d: -f2)"
check "completed upload has the NAR hash" "$EXPECT" "$(curl -s -X POST "${AUTH[@]}" "$URL/_api/v2/caches/chunked/uploads/$ID/complete" | jq -r .narHash)"
check "completed upload is gone" 404 "$(status "${AUTH[@]}" "$URL/_api/v2/caches/chunked/uploads/$ID")"
ID="$(new_upload)"
check "garbage chunk rejected" 400 "$(status -X PATCH "${AUTH[@]}" --data-binary 'not zstd' "$URL/_api/v2/caches/chunked/uploads/$ID?offset=0")"
check "rejected upload is dropped" 404 "$(status "${AUTH[@]}" "$URL/_api/v2/caches/chunked/uploads/$ID")"

echo "=== push $TARGET"
helios login ci "$URL" "$PUSH_TOKEN" >/dev/null
helios push main --closure "$TARGET"
CLOSURE_SIZE="$(nix-store -qR "$TARGET" | wc -l)"
AGAIN="$(helios push main --closure "$TARGET" 2>&1)"
check "second push is a no-op" "all $CLOSURE_SIZE paths already in 'main'" "$AGAIN"

echo "=== read path"
HASH="$(basename "$TARGET" | cut -c1-32)"
check "narinfo HEAD" 200 "$(status -I "$URL/main/$HASH.narinfo")"
check "narinfo miss" 404 "$(status "$URL/main/00000000000000000000000000000000.narinfo")"
check "unknown cache" 404 "$(status "$URL/nope/$HASH.narinfo")"
NAR_URL="$(curl -s "$URL/main/$HASH.narinfo" | sed -n 's/^URL: //p')"
check "nar not served from a cache that lacks it" 404 "$(status -H "authorization: Bearer $PUSH_TOKEN" "$URL/secret/$NAR_URL")"

echo "=== substitute into a fresh store (signatures required)"
NIX_CONFIG="trusted-public-keys = $PUBKEY
require-sigs = true" nix copy --from "$URL/main" --to "$WORK/store" "$TARGET" 2>&1 | tail -3
check "substituted closure is valid" "$CLOSURE_SIZE" "$(nix-store --store "$WORK/store" -qR "$TARGET" | wc -l)"
nix store verify --store "$WORK/store" --trusted-public-keys "$PUBKEY" -r "$TARGET" && check "nix store verify" 0 0

echo "=== private cache"
helios push secret "$TARGET" >/dev/null 2>&1
check "private narinfo without auth" 401 "$(status "$URL/secret/$HASH.narinfo")"
check "private narinfo with netrc-style basic auth" 200 "$(status -u "reader:$PULL_ONLY" "$URL/secret/$HASH.narinfo")"
check "pull-only token cannot push" 403 "$(status -X POST -H "authorization: Bearer $PULL_ONLY" -H 'content-type: application/json' -d '{"hashes":[]}' "$URL/_api/v2/caches/secret/missing")"
check "push-only token cannot read" 403 "$(status -u "builder:$PUSH_ONLY" "$URL/secret/$HASH.narinfo")"
check "refusals say why" "token does not grant push on cache 'secret'" "$(curl -s -X POST -H "authorization: Bearer $PULL_ONLY" -H 'content-type: application/json' -d '{"hashes":[]}' "$URL/_api/v2/caches/secret/missing" | jq -r .error)"

echo "=== helios use"
helios login reader "$URL" "$PULL_ONLY" >/dev/null 2>&1
helios use secret 2>/dev/null
helios use secret 2>/dev/null
NIXCONF="$XDG_CONFIG_HOME/nix/nix.conf"
check "nix.conf gets the login URL, once" 1 "$(grep -cx "extra-substituters = $URL/secret" "$NIXCONF")"
check "netrc is private" 600 "$(stat -c %a "$XDG_CONFIG_HOME/nix/netrc")"
check "netrc holds the token once" 1 "$(grep -c "password $PULL_ONLY" "$XDG_CONFIG_HOME/nix/netrc")"
# Signatures checked against the configured key, fetched with netrc auth.
nix store verify --no-contents --store "$URL/secret" "$TARGET" && check "nix reads the private cache with this config" 0 0
check "and not without it" fails "$(XDG_CONFIG_HOME="$WORK/empty" nix store verify --no-contents --store "$URL/secret" "$TARGET" >/dev/null 2>&1 || echo fails)"
check "--print shows system-wide settings" 1 "$(helios use secret --print | grep -c "^machine 127.0.0.1 *\$")"
helios login ci "$URL" "$PUSH_TOKEN" >/dev/null 2>&1

echo "=== pins"
# Auto-GC takes its candidates from /v1/lru; main is cache 1, chunked cache 3.
lru_count() { curl -s --unix-socket "$WORK/admin.sock" "http://x/v1/lru?limit=10000" | jq --argjson c "$1" --argjson closure "$(nix-store -qR "$TARGET" | jq -R . | jq -s .)" '[.paths[] | select(.cache == $c and ((.storePath | if startswith("/nix/store/") then . else "/nix/store/" + . end) as $p | $closure | index($p)))] | length'; }
check "the closure starts as a GC candidate" "$CLOSURE_SIZE" "$(lru_count 1)"
helios pin main "$TARGET" 2>/dev/null
check "pins are listed" "$TARGET" "$(helios pins main | jq -r '.pins[0].storePath')"
check "a pinned closure is not a GC candidate" 0 "$(lru_count 1)"
check "the same paths in another cache still are" "$CLOSURE_SIZE" "$(lru_count 3)"
check "pull-only token cannot pin" 403 "$(status -X POST -H "authorization: Bearer $PULL_ONLY" -H 'content-type: application/json' -d "{\"storePaths\":[\"$TARGET\"]}" "$URL/_api/v2/caches/secret/pins")"
check "invalid pin rejected" 400 "$(status -X POST "${AUTH[@]}" -H 'content-type: application/json' -d '{"storePaths":["/etc/passwd"]}' "$URL/_api/v2/caches/main/pins")"
helios unpin main "$TARGET" 2>/dev/null
check "unpinned closure is a candidate again" "$CLOSURE_SIZE" "$(lru_count 1)"

echo "=== private NARs stay private"
OTHER="$(helios --server admin token create other --caches main --perms push 2>/dev/null | jq -r .token)"
head -c 4096 /dev/urandom >"$WORK/secret-file"
nix-store --dump "$WORK/secret-file" | zstd -q >"$WORK/secret.nar.zst"
SECRET_NAR="$(curl -s -X PUT -H "authorization: Bearer $PUSH_TOKEN" --data-binary @"$WORK/secret.nar.zst" "$URL/_api/v2/caches/secret/nar" | jq -r .narHash)"
SECRET_SIZE="$(nix-store --dump "$WORK/secret-file" | wc -c)"
FAKE_PATH="/nix/store/$(printf 'a%.0s' $(seq 32))-leak"
LEAK="{\"paths\":[{\"storePath\":\"$FAKE_PATH\",\"narHash\":\"$SECRET_NAR\",\"narSize\":$SECRET_SIZE}]}"
check "another cache does not see a private NAR as known" "[]" "$(curl -s -X POST -H "authorization: Bearer $OTHER" -H 'content-type: application/json' -d "{\"narHashes\":[\"$SECRET_NAR\"]}" "$URL/_api/v2/caches/main/nars/known" | jq -c .known)"
check "nor can it publish a path over it" 409 "$(status -X POST -H "authorization: Bearer $OTHER" -H 'content-type: application/json' -d "$LEAK" "$URL/_api/v2/caches/main/paths")"
curl -s -o /dev/null -X PUT -H "authorization: Bearer $OTHER" --data-binary @"$WORK/secret.nar.zst" "$URL/_api/v2/caches/main/nar"
check "uploading the NAR itself entitles it" 201 "$(status -X POST -H "authorization: Bearer $OTHER" -H 'content-type: application/json' -d "$LEAK" "$URL/_api/v2/caches/main/paths")"

echo "=== build traces"
OUT_BASE="$(basename "$TARGET")"
HEX="$(printf '%064d' 0 | tr 0 a)"
traces() { curl -s -o /dev/null -w '%{http_code}' -X POST "${AUTH[@]}" -H 'content-type: application/json' -d "{\"entries\":[$1]}" "$URL/_api/v2/caches/main/build-traces"; }
check "a current-format trace publishes" 201 "$(traces "{\"key\":{\"drvPath\":\"$HASH-x.drv\",\"outputName\":\"out\"},\"value\":{\"outPath\":\"$OUT_BASE\",\"signatures\":[]}}")"
check "a legacy trace publishes" 201 "$(traces "{\"id\":\"sha256:$HEX!out\",\"outPath\":\"$OUT_BASE\",\"signatures\":[],\"dependentRealisations\":{}}")"
check "a trace needs its output published" 409 "$(traces "{\"id\":\"sha256:$HEX!dev\",\"outPath\":\"00000000000000000000000000000000-x\"}")"
check "an invalid trace id is refused" 400 "$(traces "{\"id\":\"sha1:abc!out\",\"outPath\":\"$OUT_BASE\"}")"
CURRENT="$(curl -sf "$URL/main/build-trace-v2/$HASH-x.drv/out.doi")"
check "current trace served, signed by the cache" "$OUT_BASE ${PUBKEY%%:*}" "$(echo "$CURRENT" | jq -r '.outPath + " " + .signatures[0].keyName')"
LEGACY="$(curl -sf "$URL/main/realisations/sha256:$HEX!out.doi")"
check "legacy trace served, signed by the cache" "sha256:$HEX!out ${PUBKEY%%:*}" "$(echo "$LEGACY" | jq -r '.id + " " + (.signatures[0] | split(":")[0])')"
check "legacy trace served percent-encoded" 200 "$(status "$URL/main/realisations/sha256%3A$HEX%21out.doi")"
check "each format only under its prefix" 404 "$(status "$URL/main/build-trace-v2/sha256:$HEX!out.doi")"

echo "=== abuse"
check "garbage upload rejected" 400 "$(status -X PUT -H "authorization: Bearer $PUSH_TOKEN" --data-binary 'not a zstd stream' "$URL/_api/v2/caches/main/nar")"
check "raw non-NAR upload rejected" 400 "$(status -X PUT -H "authorization: Bearer $PUSH_TOKEN" --data-binary 'hello' "$URL/_api/v2/caches/main/nar?compression=none")"
INJECT='{"paths":[{"storePath":"/nix/store/'"$HASH"'-x\nSig: evil","narHash":"sha256:'"$(printf 0%.0s $(seq 52))"'","narSize":1}]}'
check "narinfo injection rejected" 400 "$(status -X POST -H "authorization: Bearer $PUSH_TOKEN" -H 'content-type: application/json' -d "$INJECT" "$URL/_api/v2/caches/main/paths")"
FAKE='{"paths":[{"storePath":"/nix/store/00000000000000000000000000000000-fake","narHash":"sha256:'"$(printf 0%.0s $(seq 52))"'","narSize":1}]}'
check "publish without uploaded NAR" 409 "$(status -X POST -H "authorization: Bearer $PUSH_TOKEN" -H 'content-type: application/json' -d "$FAKE" "$URL/_api/v2/caches/main/paths")"
JTI="$(helios --server admin token list | jq -r '.tokens[] | select(.subject=="reader") | .jti')"
helios --server admin token revoke "$JTI" "e2e" >/dev/null
check "revocation is immediate" 401 "$(status -u "reader:$PULL_ONLY" "$URL/secret/$HASH.narinfo")"
check "revoked token says so" "token has been revoked" "$(curl -s -u "reader:$PULL_ONLY" "$URL/secret/$HASH.narinfo" | jq -r .error)"

echo
echo "passed=$PASS failed=$FAIL"
[ "$FAIL" -eq 0 ]
