# Helios

A self-hosted Nix binary cache: Rust server and CLI over a Zig core.

## Workspace Layout

- `pkg/*`: Zig packages for Nix formats and the NAR pipeline, one concern
  each. Each builds and tests on its own (`zig build test`).
- `core/`: libhelios, the C ABI over `pkg/*`, compiled to a static library
  by `crates/helios-core/build.rs`. `core/include/helios.h` is the contract.
- `crates/helios-core`: safe Rust bindings to libhelios.
- `crates/helios-server`, `crates/helios-cli`: the binaries.
- `bench/`: comparisons against Cachix's libraries and Nix C++. Not part of
  the Cargo workspace.

Put Nix format logic in a `pkg/*` package and expose it through
`core/src/root.zig` only when Rust needs it. Keep calls across the C ABI
coarse, such as a whole NAR or narinfo per call.

## Tooling

- Use `nix develop` for zig 0.16, cargo, zstd and pkg-config.
- Zig 0.16 APIs changed a lot; check `zig env` for the std source rather
  than relying on older examples.
- `HELIOS_ZIG_CPU` sets libhelios's `-Dcpu` (default `native`; the Nix
  package uses `baseline`).

## Performance Rules

- Measure before and after; `bench/run.sh` and `bench/flake-lock.sh`
  compare against the reference implementations on the same corpus.
- Keep the narinfo read path free of SQLite on misses and of per-request
  signing.
- Keep a scalar reference for every SIMD routine, with a test asserting the
  two agree.

## Verification

- `cargo test --release`
- `./scripts/test-zig.sh`
- `./scripts/e2e.sh` before finishing changes to the server, the CLI or wire
  formats; it substitutes a real closure through Nix with signatures
  required.
