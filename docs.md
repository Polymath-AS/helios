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
| `--caches` | `HELIOS_CACHES` | unset: caches to create at startup, such as `main,team:private`; a listed cache that exists takes the listed visibility, and unlisted caches are left alone |

Secret files must hold at least 16 bytes.

## Logging

The server, daemon and CLI log through `tracing`, configured the same way:

| Variable | |
|----------|--|
| `HELIOS_LOG` | a level (`error`, `warn`, `info`, `debug`, `trace`; default `info`), optionally with per-target directives, such as `info,helios_server=debug` |
| `HELIOS_LOG_FORMAT` | `journald`, `json` or `text`. The default is `journald` under systemd and `text` otherwise |

Under journald, events are structured entries: their fields (`blob`,
`cache`, `bytes` and so on) are journal fields, so `journalctl -u helios
PRIORITY=4` or `journalctl BLOB=<hash>` filters on them. `json` writes one
object per line for container log collectors. Requests log at `debug`; a
request that fails with a 5xx logs at `warn` with its method and path.

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

Caches can be declared instead of created by hand:

```nix
services.helios.caches = {
  main = { };
  team.public = false;   # reads need a token with pull
};
```

A declared cache that exists takes the declared visibility. Removing one from
the list leaves it and its paths in place; there is no declarative delete.

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
| `caches.<name>.public` | `true` | caches created at startup; see below |

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
`HELIOS_CACHES=main,team:private`, `HELIOS_MIN_FREE`, `HELIOS_METRICS_LISTEN`,
`HELIOS_LOG` and
`HELIOS_LOG_FORMAT=json` (see [Logging](#logging)). Set
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

## Substituting

`helios use` configures Nix to pull from a cache, using the URL given to
`helios login` (not an address the server reports, which behind a proxy is
the wrong one):

```bash
helios login reader https://cache.example.com "$READ_TOKEN"
helios use team            # adds to ~/.config/nix/nix.conf and netrc
helios use team --print    # system-wide settings, for NixOS or /etc/nix
```

It adds the substituter and the cache's signing key and, for a private
cache, a netrc entry with the login's token (Nix sends it as HTTP Basic
auth; the server reads the password). Running it again changes nothing, and
logging in with a new token replaces the old entry. The Nix daemon ignores
substituters from users it does not trust; `helios use` warns when that is
the case, and `--print` gives the `nix.settings` to use instead.

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

A NAR larger than `--chunk-size` (MiB, default 32) is uploaded in chunks of
that size, so pushes work through proxies that cap request bodies, such as
Cloudflare (100 MB on the free plan) and Cloud Run (32 MiB). Each chunk is
retried on its own after a network or server error, and the server's offset
decides whether it has to be sent again. `--chunk-size 0` streams every NAR
in one request.

## HTTP API

Substituter endpoints (`GET`/`HEAD`):

| Path | |
|------|--|
| `/<cache>/nix-cache-info` | |
| `/<cache>/<hash>.narinfo` | misses are answered from memory |
| `/<cache>/nar/<file-hash>.nar.zst` | only served by caches that publish it |
| `/<cache>/build-trace-v2/<drv>/<output>.doi`, `/<cache>/realisations/<id>.doi` | build traces of CA derivations, from memory |

`GET /_api/v2/caches/<cache>` returns `{"name", "public", "publicKey"}` to
anyone who can read the cache.

Push endpoints (bearer token with `push` on the cache):

| Method and path | Body | |
|-----------------|------|--|
| `POST /_api/v2/caches/<cache>/missing` | `{"hashes": [...]}` | store path hashes absent from the cache |
| `POST /_api/v2/caches/<cache>/nars/known` | `{"narHashes": [...]}` | NAR hashes the server already has |
| `PUT /_api/v2/caches/<cache>/nar?compression=zstd` | compressed NAR | returns the verified hashes and sizes |
| `POST /_api/v2/caches/<cache>/uploads?compression=zstd` | | starts a chunked upload: `{"id", "offset": 0}` |
| `PATCH /_api/v2/caches/<cache>/uploads/<id>?offset=<n>` | the next chunk, up to 64 MiB | appends it whole or not at all: `{"offset"}`; a stale offset gets `409` with the current one |
| `GET /_api/v2/caches/<cache>/uploads/<id>` | | `{"offset"}`, to resume after a failed request |
| `POST /_api/v2/caches/<cache>/uploads/<id>/complete` | | as `PUT /nar` |
| `DELETE /_api/v2/caches/<cache>/uploads/<id>` | | abandons it |
| `POST /_api/v2/caches/<cache>/paths` | `{"paths": [...]}` | publishes a batch in one transaction; `409 nar_required` lists paths without an uploaded NAR |

Chunks are verified as they arrive, as in a single `PUT`. An upload belongs
to the token that started it, is dropped after an hour without a chunk or
after an invalid one, and does not survive a server restart (the client
then starts that NAR again).

`POST /_api/v2/caches/<cache>/build-traces` (`push`) takes `{"entries": [...]}`
as `nix store build-trace info --json` (or `nix realisation info --json`)
prints them.

Pin endpoints: `GET /_api/v2/caches/<cache>/pins` (`pull`), `POST
/_api/v2/caches/<cache>/pins` with `{"storePaths": [...]}` and `DELETE
/_api/v2/caches/<cache>/pins/<store path basename>` (`push`).

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
  Pinned paths stay too; see [Pins](#pins).
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

## Pins

A pin keeps a store path and its closure in a cache through auto-GC, for
releases or systems that must stay substitutable however rarely they are
fetched:

```bash
helios push main --closure --pin .#nixosConfigurations.host.config.system.build.toplevel
helios pin main /nix/store/...-release    # or an installable
helios pins main
helios unpin main /nix/store/...-release
```

The closure is followed through the References of the published narinfo
when auto-GC runs, so dependencies pushed after the pin are protected too.
It stops at a dependency the cache does not have: pin after pushing the
closure (as `--pin` does). Pinning and unpinning need `push` on the cache,
listing needs `pull`. Pins only hold back eviction: the integrity scrub
still unpublishes a corrupt NAR, and pushing the closure again restores it.
When what is left over quota is pinned, the daemon logs that it cannot
free enough.

## Content-addressed derivations

A content-addressed (CA) derivation's output path is only known once it is
built, so Nix looks it up in the cache's build traces ("realisations")
before it can substitute. `helios push` publishes them for the CA outputs it
pushes, when Nix has the experimental `ca-derivations` feature enabled.

The cache serves whichever format the pushing Nix produces: Nix 2.35 and
later use `/<cache>/build-trace-v2/<drv>/<output>.doi`, earlier versions
`/<cache>/realisations/sha256:<hash>!<output>.doi`. Push and substitute
with the same side of that change. An entry is accepted only when its output
path is published in the cache, and is signed with the cache's key over the
fingerprint Nix defines. Current Nix does not check those signatures when
substituting (a wrong one is accepted too); what it checks is the output
path's signed narinfo. Both formats are experimental upstream and may
change.

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
