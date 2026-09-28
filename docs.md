# Helios Documentation

## Storage

Everything lives under `--data-dir`:

| Path | Contents |
|------|----------|
| `helios.db` | SQLite (WAL): caches, blobs, published paths, tokens, audit log |
| `nar/<xx>/<hash>.nar.zst` | Content-addressed compressed NARs |
| `tmp/` | In-flight uploads, renamed into `nar/` once verified |

Uploads are decompressed and hashed by the server as they stream in, so a
path is only published against a NAR whose hash the server computed itself.
Narinfo is rendered and signed once, at publish time.

## Server configuration

Every flag can also be set through its environment variable.

| Flag | Env | Default |
|------|-----|---------|
| `--listen` | `HELIOS_LISTEN` | `127.0.0.1:8080` |
| `--data-dir` | `HELIOS_DATA_DIR` | `/var/lib/helios` |
| `--signing-key-file` | `HELIOS_SIGNING_KEY_FILE` | unset: narinfo is unsigned |
| `--jwt-secret-file` | `HELIOS_JWT_SECRET_FILE` | unset: no API tokens |
| `--admin-secret-file` | `HELIOS_ADMIN_SECRET_FILE` | unset: no admin API |
| `--accel-redirect` | `HELIOS_ACCEL_REDIRECT` | unset: server streams NARs itself |
| `--trust-proxy` | `HELIOS_TRUST_PROXY` | `false` (audit IPs from `X-Forwarded-For`) |
| `--narinfo-cache-entries` | `HELIOS_NARINFO_CACHE_ENTRIES` | `262144` |
| `--max-upload-bytes` | `HELIOS_MAX_UPLOAD_BYTES` | 64 GiB |
| `--gc-interval-hours` | `HELIOS_GC_INTERVAL_HOURS` | `6` |
| `--audit-retention-days` | `HELIOS_AUDIT_RETENTION_DAYS` | `30` |

Secret files must hold at least 16 bytes. `HELIOS_LOG` sets the log level
(`error`, `warn`, `info` or `debug`; default `info`). Under systemd, log lines
carry journald priorities.

The server links the system SQLite; build with `--features bundled-sqlite`
to compile SQLite in instead.

## Reverse proxy and zero-copy downloads

Terminate TLS in a reverse proxy. With `--accel-redirect /_nar`, the server
answers NAR requests with an `X-Accel-Redirect` header after the access
check, and nginx serves the file with `sendfile`:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_request_buffering off;   # stream uploads
    client_max_body_size 0;
}
location /_nar/ {
    internal;
    alias /var/lib/helios/nar/;
}
```

## Caches and tokens

```bash
helios cache create main              # public: anyone can read
helios cache create team --private    # reads need a token with `pull`
helios cache list

helios token create ci --caches main --perms push --expires 90
helios token create reader --caches team --perms pull
helios token list
helios token revoke <jti> "reason"    # takes effect immediately
```

Admin commands use a server logged in with the admin secret; pass
`--server <name>` to pick one. Tokens are HS256 JWTs scoped to cache names
(or `*`) and to `push` and/or `pull`.

For private caches, give Nix the token through netrc. Nix sends it as HTTP
Basic auth, and the server reads the password:

```
machine cache.example.com
password <token>
```

```nix
nix.settings.netrc-file = "/etc/nix/netrc";
```

## Pushing

```bash
helios push main /nix/store/...-hello                  # single paths
helios push main --closure .#nixosConfigurations.host.config.system.build.toplevel
helios push main --closure /run/current-system --jobs 8 --level 3
```

The CLI serialises, zstd-compresses and hashes each NAR in one pass and
streams it straight into the upload, without temp files. It checks every
NAR hash against the Nix database. NARs the server already holds under any
cache are reused, and paths are published dependencies-first, in batches.

## HTTP API

Substituter endpoints (`GET`/`HEAD`):

| Path | |
|------|--|
| `/<cache>/nix-cache-info` | |
| `/<cache>/<hash>.narinfo` | misses are answered from memory |
| `/<cache>/nar/<file-hash>.nar.zst` | only served by caches that publish it |

Push endpoints (bearer token with `push` on the cache):

| Method and path | Body | |
|-----------------|------|--|
| `POST /_api/v2/caches/<cache>/missing` | `{"hashes": [...]}` | store path hashes absent from the cache |
| `POST /_api/v2/caches/<cache>/nars/known` | `{"narHashes": [...]}` | NAR hashes the server already has |
| `PUT /_api/v2/caches/<cache>/nar?compression=zstd` | compressed NAR | returns the verified hashes and sizes |
| `POST /_api/v2/caches/<cache>/paths` | `{"paths": [...]}` | publishes a batch in one transaction; `409 nar_required` lists paths without an uploaded NAR |

Admin endpoints (bearer admin secret): `GET/POST /_api/v2/admin/caches`,
`GET/POST /_api/v2/admin/tokens`, `POST /_api/v2/admin/tokens/<jti>/revoke`.

## Garbage collection

Every `--gc-interval-hours`, the server removes stale temp uploads, blobs no
path references (after a one-hour grace period, so an upload is never
collected before it is published), expired tokens, and old audit log rows.

## Benchmarks

```bash
bench/run.sh            # pkg/* vs Cachix's Haskell libraries and Nix C++
bench/flake-lock.sh     # pkg/nix-flake-lock vs cachix/nix-flake-lock
```

Both use the local store as their corpus and run single-threaded.
