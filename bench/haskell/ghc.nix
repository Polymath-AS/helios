# GHC with the Haskell Nix libraries (nix-narinfo, nix-derivation, hnix-store).
{ pkgs ? import <nixpkgs> { } }:
pkgs.haskellPackages.ghcWithPackages (p: [
  p.nix-narinfo
  p.nix-derivation
  p.hnix-store-core
  p.hnix-store-nar
  p.ed25519
  p.crypton
  p.base64-bytestring
  p.attoparsec
])
