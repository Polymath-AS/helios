# Helios Documentation

## Storage

Everything lives under `--data-dir`:

| Path | Contents |
|------|----------|
| `helios.db` | SQLite (WAL): caches, blobs, published paths, tokens, audit log |
| `nar/<xx>/<hash>.nar.zst` | Content-addressed compressed NARs |
| `tmp/` | In-flight uploads, renamed into `nar/` once verified |
| `backups/` | Database backups made on request of helios-daemon |
| `quarantine/` | NARs the integrity scrub found missing or corrupt |

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
| `--upload-grace-seconds` | `HELIOS_UPLOAD_GRACE_SECONDS` | `3600`: an unpublished upload is kept this long |
| `--admin-socket` | `HELIOS_ADMIN_SOCKET` | unset: no maintenance API (see helios-daemon) |

Secret files must hold at least 16 bytes. `HELIOS_LOG` sets the log level
(`error`, `warn`, `info` or `debug`; default `info`). Under systemd, log lines
carry journald priorities.

The server links the system SQLite; build with `--features bundled-sqlite`
to compile SQLite in instead.

## NixOS

The flake exports `nixosModules.default`. It runs the server as a hardened
systemd service and, when `domain` is set, puts nginx in front of it with
TLS from Let's Encrypt and zero-copy NAR downloads:

```nix
# flake.nix
{
  inputs.helios.url = "github:Polymath-AS/helios";
  outputs = { nixpkgs, helios, ... }: {
    nixosConfigurations.cache = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [ helios.nixosModules.default ./configuration.nix ];
    };
  };
}
```

```nix
# configuration.nix
{
  services.helios = {
    enable = true;
    domain = "cache.example.com";
    signingKeyFile = "/run/secrets/helios-signing-key";
    jwtSecretFile = "/run/secrets/helios-jwt-secret";
    adminSecretFile = "/run/secrets/helios-admin-secret";
  };
  security.acme = {
    acceptTerms = true;
    defaults.email = "ops@example.com";
  };
}
```

Secret files are handed to the service as systemd credentials, so they can
be root-only and come from any secret manager (agenix, sops-nix, or files
placed by hand). Without `domain`, the module runs only the server on
`listen`, for use behind another proxy or on a private network.

| Option | Default | |
|--------|---------|--|
| `listen` | `127.0.0.1:8080` | keep on loopback behind nginx |
| `dataDir` | `/var/lib/helios` | any other path, such as a mounted disk, is created and allowed in the sandbox |
| `domain` | `null` | enables nginx for this host name |
| `nginx.acme` | `true` | set `false` for plain HTTP or your own certificates |
| `openFirewall` | on with nginx | opens 80 and 443 |
| `logLevel` | `info` | |
| `settings.*` | | `narinfoCacheEntries`, `maxUploadBytes`, `gcIntervalHours`, `auditRetentionDays` |

`services.helios.daemon` (on by default) runs helios-daemon beside the
server; see [Maintenance](#maintenance). To keep the cache under a size:

```nix
services.helios.daemon = {
  quota = "500G";
  minFree = "20G";
  metrics.listen = "127.0.0.1:9120";
};
```

`services.helios.watchStore` goes on build machines, and needs no server
there. It installs a Nix post-build hook, so every path the machine builds is
pushed to a cache:

```nix
services.helios.watchStore = {
  enable = true;
  url = "https://cache.example.com";
  cache = "main";
  tokenFile = "/run/secrets/helios-push-token";
};
```

`overlays.default` adds `pkgs.helios`. `nix flake check` runs a VM test of
all of the above: push, signed substitution, sandboxing, metrics, backups,
a scrub that catches a corrupted NAR, watch-store, eviction and shutdown.

## Docker

`ghcr.io/polymath-as/helios` is an OCI image with the server and the
maintenance daemon for x86_64 and aarch64, running as uid 10000 with all
state in `/var/lib/helios`. CI publishes `latest` and the version for each
`v*` tag, `master` for the branch, and `sha-<commit>` for every build. To
build it yourself, `nix build .#docker` gives a tarball for `docker load`.

```sh
docker run -d --name helios -p 8080:8080 -v helios:/var/lib/helios \
  -e HELIOS_QUOTA=500G ghcr.io/polymath-as/helios:latest
docker exec helios helios-public-key      # for trusted-public-keys
docker exec helios helios-admin cache create main
docker exec helios helios-admin token create ci --caches main --perms push,pull
```

On first start the entrypoint generates a signing key (named by
`HELIOS_KEY_NAME`, default `helios-1`), a token secret and an admin secret
into `/var/lib/helios/secrets`, and logs the public key. It never overwrites
them, so keep the volume and the keys survive upgrades. To provide your own
instead, for example as Docker secrets, set all three of
`HELIOS_SIGNING_KEY_FILE`, `HELIOS_JWT_SECRET_FILE` and
`HELIOS_ADMIN_SECRET_FILE`.

Both binaries take their flags as `HELIOS_*` environment variables (see
`helios-server --help` and `helios-daemon --help`), such as `HELIOS_QUOTA`,
`HELIOS_MIN_FREE`, `HELIOS_METRICS_LISTEN` and `HELIOS_LOG`. Set
`HELIOS_DAEMON=0` to run the server alone. `docker stop` shuts both down
cleanly; if either exits on its own, the container exits non-zero so the
restart policy takes over. The image has no reverse proxy: put one in front
for TLS. `nix build .#checks.x86_64-linux.docker` runs the image in a VM
under real Docker.

## Reverse proxy and zero-copy downloads

Outside NixOS, terminate TLS in a reverse proxy. With `--accel-redirect /_nar`, the server
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

helios token create reader --caches team       # read-only (the default)
helios token create ci --caches main --perms push --expires 90
helios token list
helios token revoke <jti> "reason"    # takes effect immediately
```

Admin commands use a server logged in with the admin secret; pass
`--server <name>` to pick one. Tokens are HS256 JWTs scoped to cache names
(or `*`) and to `pull` and/or `push`. Tokens are read-only unless created
with `push`, and `push` does not imply `pull`: a builder can upload to a
private cache without being able to read it. A refused request says why,
such as `token does not grant push on cache 'main'` or `token has been
revoked`.

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
path references (once past `--upload-grace-seconds`, so an upload is never
collected before it is published), expired tokens, and old audit log rows.

## Maintenance

helios-daemon keeps a cache healthy without touching the database itself:
it decides what to do and asks the server, over the Unix socket given to
the server as `--admin-socket`, so the server's in-memory index always
agrees with SQLite. The socket's permissions are its access control.

- **Auto-GC.** With `--quota`, stored NARs are kept under that size.
  Eviction starts above `--quota-high` (0.9) and removes the least recently
  used paths down to `--quota-low` (0.8). Recency comes from narinfo hits,
  which the server records in memory and flushes once a minute.
  `--min-free` also evicts while the disk is short on space. NARs another
  path still uses stay, and an evicted NAR is deleted once its upload grace
  period has passed.
- **Integrity scrub.** Every `--scrub-interval` (7d), every NAR is read at up
  to `--scrub-rate` (64M per second), then decompressed and re-hashed. A
  missing or corrupt NAR is quarantined, which unpublishes its paths, so no
  client downloads bad data.
- **SQLite.** WAL checkpoints (`--checkpoint-interval`, 15m), `PRAGMA
  optimize` (`--optimize-interval`, 1d) and online backups to
  `<data-dir>/backups` (`--backup-interval`, 1d; `--backup-keep`, 7).
- **Metrics.** `--metrics-listen` serves Prometheus metrics:
  - cache paths, NAR bytes, and narinfo hits and misses;
  - uploads;
  - auto-GC, scrub and backup results;
  - disk space.

Intervals take a unit (`30s`, `5m`, `24h`, `7d`) and sizes an optional
binary suffix (`64M`, `500G`). A failed run is logged, counted in
`helios_maintenance_errors_total`, and retried on the next tick.

The maintenance API (`/v1/stats`, `/v1/lru`, `/v1/evict`, `/v1/blobs`,
`/v1/quarantine`, `/v1/gc`, `/v1/db/checkpoint`, `/v1/db/optimize`,
`/v1/db/backup`) is internal and may change between versions.

## Watch-store

On a build machine, `helios queue-paths` works as Nix's `post-build-hook`.
It spools each build's outputs and returns at once, so builds never wait on
the network. `helios watch-store <cache>` pushes the spooled closures and
retries with backoff while the server is unreachable. Both take `--spool`,
and the CLI accepts `--url` with `--token-file` (or `HELIOS_URL` and
`HELIOS_TOKEN`) instead of a saved login.

## Benchmarks

```bash
bench/run.sh            # pkg/* vs Cachix's Haskell libraries and Nix C++
bench/flake-lock.sh     # pkg/nix-flake-lock vs cachix/nix-flake-lock
```

Both use the local store as their corpus and run single-threaded.
