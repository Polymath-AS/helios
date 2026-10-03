{
  description = "Helios: self-hosted Nix binary cache (Rust server and CLI, Zig core)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      # NAR serialisation is implemented for Linux only.
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = fn: nixpkgs.lib.genAttrs systems (system: fn nixpkgs.legacyPackages.${system});

      helios' = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "helios";
        version = "0.1.0";
        # Only what the build reads, so docs and module edits do not rebuild it.
        src = pkgs.lib.cleanSourceWith {
          src = self;
          filter = path: _type:
            let
              rel = pkgs.lib.removePrefix "${toString self}/" (toString path);
              top = builtins.head (pkgs.lib.splitString "/" rel);
              base = baseNameOf path;
            in
            builtins.elem top [ "Cargo.toml" "Cargo.lock" "core" "crates" "pkg" ]
            && !(builtins.elem base [ "target" ".zig-cache" "zig-out" ]);
        };
        cargoLock.lockFile = ./Cargo.lock;

        nativeBuildInputs = [ pkgs.zig pkgs.pkg-config ];
        buildInputs = [ pkgs.zstd pkgs.sqlite ];

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
        # OCI image with the server and maintenance daemon; see nix/docker.nix.
        docker = import ./nix/docker.nix { inherit pkgs helios; };
      });

      overlays.default = final: _prev: { helios = helios' final; };

      # services.helios; the package defaults to this flake's build.
      nixosModules.default =
        { lib, pkgs, ... }:
        {
          imports = [ ./nix/module.nix ];
          services.helios.package = lib.mkDefault (helios' pkgs);
        };
      nixosModules.helios = self.nixosModules.default;

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
            pkgs.sqlite
            pkgs.jq
            pkgs.curl
          ];
        };
      });

      checks = forAllSystems (pkgs: {
        package = self.packages.${pkgs.stdenv.hostPlatform.system}.helios;
        nixos = import ./nix/test.nix {
          inherit pkgs;
          module = ./nix/module.nix;
          helios = self.packages.${pkgs.stdenv.hostPlatform.system}.helios;
        };
        docker = import ./nix/docker-test.nix {
          inherit pkgs;
          image = self.packages.${pkgs.stdenv.hostPlatform.system}.docker;
          helios = self.packages.${pkgs.stdenv.hostPlatform.system}.helios;
        };
      });
    };
}
