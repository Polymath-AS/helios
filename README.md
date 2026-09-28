# Helios

A self-hosted Nix binary cache for a single server: a Rust HTTP server and
CLI on top of a Zig core library for NAR serialisation, hashing,
compression, narinfo and signing.

## Layout

```
pkg/          Zig packages: nix-base32, nix-store-path, nix-archive,
              nix-narinfo, nix-derivation, nix-flake-lock
core/         libhelios: C ABI over pkg/*, built as a static library
crates/       helios-core (Rust bindings), helios-server, helios-cli,
              helios-daemon (auto-GC, scrub, backups, metrics)
nix/          NixOS module (services.helios) and its VM test
bench/        benchmarks against Cachix's Nix libraries and Nix C++
scripts/      e2e.sh (end-to-end test), test-zig.sh (Zig unit tests)
```

## Develop

```bash
nix develop                  # zig, rust, zstd, pkg-config
cargo build --release        # builds libhelios via zig automatically
cargo test --release
./scripts/test-zig.sh        # unit tests for every pkg/*
./scripts/e2e.sh             # server + CLI + real `nix copy` substitution
```

`nix build` produces `helios` (CLI) and `helios-server`.

## Run the server

```bash
nix key generate-secret --key-name cache.example.com-1 > /var/lib/helios/signing.key
openssl rand -hex 32 > /var/lib/helios/jwt.secret
openssl rand -hex 32 > /var/lib/helios/admin.secret

helios-server \
  --listen 127.0.0.1:8080 \
  --data-dir /var/lib/helios \
  --signing-key-file /var/lib/helios/signing.key \
  --jwt-secret-file /var/lib/helios/jwt.secret \
  --admin-secret-file /var/lib/helios/admin.secret

helios-server --print-public-key --signing-key-file /var/lib/helios/signing.key
```

## Push and substitute

```bash
helios login admin https://cache.example.com "$(cat admin.secret)"
helios cache create main
helios token create ci --caches main --perms push,pull   # prints the token once

helios login ci https://cache.example.com "$TOKEN"
helios push main --closure /run/current-system
```

```bash
helios use main            # this user's Nix pulls from the cache
helios use main --print    # settings for NixOS or /etc/nix/nix.conf
```

On NixOS, use the flake's `nixosModules.default` (`services.helios`): the
server, the maintenance daemon, and push-on-build for build machines.
Elsewhere, run the `ghcr.io/polymath-as/helios` image: the server and daemon
in one container that generates its keys on first start.

See [docs.md](docs.md) for the NixOS module, configuration, private caches,
the HTTP API and deployment behind a reverse proxy.

## License

Source-available. See [LICENSE](LICENSE).
