import { describe, it, expect } from 'vitest';
import {
  parseCacheName,
  parseStorePathHash,
  parseNarHash,
  parseFileHash,
  parseCompression,
  buildR2ObjectKey,
} from '../src/index.js';
import type { FileHash, Compression } from '../src/index.js';

function isParseError(result: unknown): result is { kind: 'ParseError'; message: string } {
  return (
    typeof result === 'object' &&
    result !== null &&
    (result as { kind?: string }).kind === 'ParseError'
  );
}

describe('parseCacheName', () => {
  it.each(['my-cache', 'a', 'a1b2', 'abc', 'a-b'])('accepts valid name %j', (input) => {
    const result = parseCacheName(input);
    expect(isParseError(result)).toBe(false);
    expect(result).toBe(input);
  });

  it.each([
    { input: '', label: 'empty string' },
    { input: 'My-Cache', label: 'uppercase' },
    { input: '-leading', label: 'leading hyphen' },
    { input: 'trailing-', label: 'trailing hyphen' },
    { input: 'has spaces', label: 'spaces' },
    { input: 'a'.repeat(65), label: '65-char string' },
    { input: 'has_underscore', label: 'underscore' },
  ])('rejects $label', ({ input }) => {
    const result = parseCacheName(input);
    expect(isParseError(result)).toBe(true);
  });
});

describe('parseStorePathHash', () => {
  it('accepts 32 valid nix-base32 chars', () => {
    const input = '0v9z1234abcdfghijklmnpqrsvwxyz01';
    const result = parseStorePathHash(input);
    expect(isParseError(result)).toBe(false);
    expect(result).toBe(input);
  });

  it.each([
    { input: '0'.repeat(31), label: '31 chars (too short)' },
    { input: '0'.repeat(33), label: '33 chars (too long)' },
    { input: '0'.repeat(31) + 'e', label: "contains 'e'" },
    { input: '0'.repeat(31) + 'o', label: "contains 'o'" },
    { input: '0'.repeat(31) + 't', label: "contains 't'" },
    { input: '0'.repeat(31) + 'u', label: "contains 'u'" },
    { input: '0'.repeat(31) + 'A', label: 'uppercase letters' },
  ])('rejects $label', ({ input }) => {
    const result = parseStorePathHash(input);
    expect(isParseError(result)).toBe(true);
  });
});

describe('parseNarHash', () => {
  it('accepts sha256: prefix + 52 valid nix-base32 chars (zeros)', () => {
    const input = 'sha256:' + '0'.repeat(52);
    const result = parseNarHash(input);
    expect(isParseError(result)).toBe(false);
    expect(result).toBe(input);
  });

  it('accepts sha256: prefix + 52 mixed valid nix-base32 chars', () => {
    const input = 'sha256:' + 'abcdfghijklmnpqrsvwxyz0123456789abcdfghijklmnpqrsvwx';
    const result = parseNarHash(input);
    expect(isParseError(result)).toBe(false);
    expect(result).toBe(input);
  });

  it.each([
    { input: '0'.repeat(52), label: 'no sha256: prefix' },
    { input: 'md5:' + '0'.repeat(52), label: 'md5: prefix' },
    { input: 'sha256:' + '0'.repeat(51), label: '51 hash chars' },
    { input: 'sha256:' + '0'.repeat(53), label: '53 hash chars' },
    { input: 'sha256:' + '0'.repeat(51) + 'e', label: "hash contains 'e'" },
  ])('rejects $label', ({ input }) => {
    const result = parseNarHash(input);
    expect(isParseError(result)).toBe(true);
  });
});

describe('parseFileHash', () => {
  it('accepts 64 lowercase hex chars (repeated a)', () => {
    const input = 'a'.repeat(64);
    const result = parseFileHash(input);
    expect(isParseError(result)).toBe(false);
    expect(result).toBe(input);
  });

  it('accepts 64 lowercase hex chars (mixed)', () => {
    const input = '0123456789abcdef'.repeat(4);
    const result = parseFileHash(input);
    expect(isParseError(result)).toBe(false);
    expect(result).toBe(input);
  });

  it.each([
    { input: 'a'.repeat(63), label: '63 chars' },
    { input: 'a'.repeat(65), label: '65 chars' },
    { input: 'a'.repeat(63) + 'g', label: "contains 'g'" },
    { input: 'A'.repeat(64), label: 'uppercase hex' },
  ])('rejects $label', ({ input }) => {
    const result = parseFileHash(input);
    expect(isParseError(result)).toBe(true);
  });
});

describe('parseCompression', () => {
  it.each(['zstd', 'xz', 'bzip2', 'none'] as const)('accepts %j', (input) => {
    const result = parseCompression(input);
    expect(isParseError(result)).toBe(false);
    expect(result).toBe(input);
  });

  it.each([
    { input: 'gzip', label: 'gzip' },
    { input: '', label: 'empty string' },
    { input: 'ZSTD', label: 'uppercase ZSTD' },
  ])('rejects $label', ({ input }) => {
    const result = parseCompression(input);
    expect(isParseError(result)).toBe(true);
  });
});

describe('buildR2ObjectKey', () => {
  const fileHash = 'a'.repeat(64) as FileHash;

  it('builds key with zstd compression', () => {
    const result = buildR2ObjectKey(fileHash, 'zstd' as Compression);
    expect(result).toBe(`nars/sha256/${'a'.repeat(64)}/zstd.nar`);
  });

  it('builds key with none compression', () => {
    const result = buildR2ObjectKey(fileHash, 'none' as Compression);
    expect(result).toBe(`nars/sha256/${'a'.repeat(64)}/none.nar`);
  });
});
