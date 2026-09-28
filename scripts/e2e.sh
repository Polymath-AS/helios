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

RUST_LOG=helios_server=warn "$BIN/helios-server" \
  --listen "127.0.0.1:$PORT" \
  --data-dir "$WORK/data" \
  --signing-key-file "$WORK/key" \
  --jwt-secret-file "$WORK/jwt" \
  --admin-secret-file "$WORK/admin" &
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
PUSH_TOKEN="$(helios token create ci --caches main,secret --perms push,pull 2>/dev/null | jq -r .token)"
PULL_ONLY="$(helios token create reader --caches secret 2>/dev/null | jq -r .token)"
PUSH_ONLY="$(helios token create builder --caches secret --perms push 2>/dev/null | jq -r .token)"
check "tokens are read-only by default" '["pull"]' "$(helios token list | jq -c '.tokens[] | select(.subject=="reader") | .perms')"
check "token issued" true "$([ -n "$PUSH_TOKEN" ] && echo true)"
check "admin rejects push token" 403 "$(status -H "authorization: Bearer $PUSH_TOKEN" "$URL/_api/v2/admin/tokens")"

echo "=== push $TARGET"
helios login ci "$URL" "$PUSH_TOKEN" >/dev/null
helios push main --closure "$TARGET"
CLOSURE_SIZE="$(nix-store -qR "$TARGET" | wc -l)"
AGAIN="$(helios push main --closure "$TARGET" 2>&1)"
check "second push is a no-op" "all $CLOSURE_SIZE paths already in 'main'" "$AGAIN"

echo "=== read path"
HASH="$(basename "$TARGET" | cut -c1-32)"
check "nix-cache-info" 200 "$(status "$URL/main/nix-cache-info")"
check "narinfo hit" 200 "$(status "$URL/main/$HASH.narinfo")"
check "narinfo HEAD" 200 "$(status -I "$URL/main/$HASH.narinfo")"
check "narinfo miss" 404 "$(status "$URL/main/00000000000000000000000000000000.narinfo")"
check "unknown cache" 404 "$(status "$URL/nope/$HASH.narinfo")"
NAR_URL="$(curl -s "$URL/main/$HASH.narinfo" | sed -n 's/^URL: //p')"
check "nar download" 200 "$(status "$URL/main/$NAR_URL")"
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
