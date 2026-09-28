{
  description = "Helios: self-hosted Nix binary cache (Rust server and CLI, Zig core)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      # NAR serialisation is implemented for Linux; macOS builds are untested.
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = fn: nixpkgs.lib.genAttrs systems (system: fn nixpkgs.legacyPackages.${system});

      helios' = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "helios";
        version = "0.1.0";
        src = pkgs.lib.cleanSourceWith {
          src = self;
          filter = path: _type:
            let base = baseNameOf path; in
            !(builtins.elem base [ "target" ".zig-cache" "zig-out" "bench" ]);
        };
        cargoLock.lockFile = ./Cargo.lock;

        nativeBuildInputs = [ pkgs.zig pkgs.pkg-config ];
        buildInputs = [ pkgs.zstd ];

        # Nix builds must not depend on the build machine's CPU. `baseline`
        # loses SHA-NI accelerated hashing; for a dedicated host, build with
        # HELIOS_ZIG_CPU=native (or e.g. x86_64_v3+sha) instead.
        HELIOS_ZIG_CPU = "baseline";
        # zig is a build tool of helios-core's build.rs, not the package builder.
        dontUseZigBuild = true;
        dontUseZigCheck = true;
        dontUseZigInstall = true;

        meta = {
          description = "Self-hosted Nix binary cache";
          mainProgram = "helios";
        };
      };
    in
    {
      packages = forAllSystems (pkgs: rec {
        helios = helios' pkgs;
        default = helios;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.zig
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.pkg-config
            pkgs.zstd
            pkgs.jq
            pkgs.curl
          ];
        };
      });

      checks = forAllSystems (pkgs: {
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.helios;
      });
    };
}
