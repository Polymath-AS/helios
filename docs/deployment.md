# Deployment Checklist

## Cloudflare Resources

Create these resources before deploying:

1. **R2 Bucket**: `odin-cache`
   ```bash
   wrangler r2 bucket create odin-cache
   ```

2. **D1 Database**: `odin-cache`
   ```bash
   wrangler d1 create odin-cache
   ```
   Update the `database_id` in `workers/cache/wrangler.jsonc` with the
   returned ID.

3. **Apply D1 migrations**:
   ```bash
   wrangler d1 migrations apply odin-cache --remote
   ```

## Secrets

Set these secrets before the first deploy:

```bash
wrangler secret put AUTH_TOKEN
wrangler secret put SIGNING_PRIVATE_KEY
wrangler secret put SIGNING_KEY_NAME
```

- `AUTH_TOKEN`: bearer token for write API authentication
- `SIGNING_PRIVATE_KEY`: base64-encoded Ed25519 private key for narinfo signing
- `SIGNING_KEY_NAME`: the key name prefix for signatures (e.g., `odin-cache-1`)

## Deploy

```bash
pnpm deploy
```

## Post-Deploy Verification

```bash
# Health check
curl https://your-worker.workers.dev/healthz

# Cache info (requires a cache to exist)
curl https://your-worker.workers.dev/your-cache/nix-cache-info
```
