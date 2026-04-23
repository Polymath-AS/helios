import type {
  CacheName,
  Compression,
  FileHash,
  NarHash,
  ParseError,
  R2ObjectKey,
  StorePathHash,
} from './types.js';

const NIX_BASE32_CHARS = "0123456789abcdfghijklmnpqrsvwxyz";
const NIX_BASE32_RE = new RegExp(`^[${NIX_BASE32_CHARS}]+$`);
const HEX_RE = /^[0-9a-f]{64}$/;
const CACHE_NAME_RE = /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/;
const VALID_COMPRESSIONS = new Set<Compression>(["zstd", "xz", "bzip2", "none"]);

function err(message: string): ParseError {
  return { kind: "ParseError", message };
}

export function parseCacheName(raw: string): CacheName | ParseError {
  if (!CACHE_NAME_RE.test(raw)) {
    return err(
      "CacheName must be 1-64 lowercase alphanumeric chars or hyphens, no leading/trailing hyphen",
    );
  }
  return raw as CacheName;
}

export function parseStorePathHash(raw: string): StorePathHash | ParseError {
  if (raw.length !== 32) {
    return err("StorePathHash must be exactly 32 characters");
  }
  if (!NIX_BASE32_RE.test(raw)) {
    return err("StorePathHash contains invalid nix base-32 characters");
  }
  return raw as StorePathHash;
}

export function parseNarHash(raw: string): NarHash | ParseError {
  if (!raw.startsWith("sha256:")) {
    return err("NarHash must start with 'sha256:'");
  }
  const hash = raw.slice(7);
  if (hash.length !== 52) {
    return err("NarHash hash part must be exactly 52 characters");
  }
  if (!NIX_BASE32_RE.test(hash)) {
    return err("NarHash contains invalid nix base-32 characters");
  }
  return raw as NarHash;
}

export function parseFileHash(raw: string): FileHash | ParseError {
  if (!HEX_RE.test(raw)) {
    return err("FileHash must be exactly 64 lowercase hex characters");
  }
  return raw as FileHash;
}

export function parseCompression(raw: string): Compression | ParseError {
  if (!VALID_COMPRESSIONS.has(raw as Compression)) {
    return err(`Compression must be one of: ${[...VALID_COMPRESSIONS].join(", ")}`);
  }
  return raw as Compression;
}

export function buildR2ObjectKey(fileHash: FileHash, compression: Compression): R2ObjectKey {
  return `nars/sha256/${fileHash}/${compression}.nar` as R2ObjectKey;
}
