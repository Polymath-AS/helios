//! Nix's base-32 encoding: a custom alphabet (no e, o, t, u) with the
//! digits emitted from the most significant 5-bit group down.
//!
//! Character classification is vectorised (Zig @Vector): a whole store path
//! hash (32 chars) is validated and mapped to 5-bit digits in one pass.
//! The scalar table path handles tails and is kept as the reference.

const std = @import("std");

pub const alphabet = "0123456789abcdfghijklmnpqrsvwxyz";

const invalid: u8 = 0xff;

const reverse: [256]u8 = blk: {
    var table = [_]u8{invalid} ** 256;
    for (alphabet, 0..) |c, i| table[c] = @intCast(i);
    break :blk table;
};

/// Lanes per vector step. 32 covers a store path hash exactly and lowers to
/// one AVX2 register (two SSE registers, one half of an AVX-512 one).
pub const lanes = 32;
const V = @Vector(lanes, u8);
const Mask = std.meta.Int(.unsigned, lanes);

fn splat(c: u8) V {
    return @splat(c);
}

fn bits(b: @Vector(lanes, bool)) Mask {
    return @bitCast(b);
}

/// Maps 32 characters to their 5-bit digit values. Returns a bitmask with a
/// set bit for every lane that is not in the alphabet.
///
/// Digits map to c - '0'. Letters map to c - 'a' + 10 minus one for every
/// skipped letter (e, o, t, u) below c.
inline fn classify(v: V, out: *V) Mask {
    const is_digit = bits(v >= splat('0')) & bits(v <= splat('9'));
    const is_lower = bits(v >= splat('a')) & bits(v <= splat('z'));
    const skipped = bits(v == splat('e')) | bits(v == splat('o')) | bits(v == splat('t')) | bits(v == splat('u'));
    const valid = is_digit | (is_lower & ~skipped);

    const one = splat(1);
    const zero = splat(0);
    const gaps = @select(u8, v > splat('e'), one, zero) +
        @select(u8, v > splat('o'), one, zero) +
        @select(u8, v > splat('t'), one, zero) +
        @select(u8, v > splat('u'), one, zero);
    const letter = v -% splat('a' - 10) -% gaps;
    const digit = v -% splat('0');
    out.* = @select(u8, @as(@Vector(lanes, bool), @bitCast(is_digit)), digit, letter);
    return ~valid;
}

pub fn encodedLen(byte_len: usize) usize {
    if (byte_len == 0) return 0;
    return (byte_len * 8 - 1) / 5 + 1;
}

/// Writes exactly `encodedLen(bytes.len)` characters into `out`.
///
/// 5 bytes hold exactly 8 digits, so full groups are unpacked from one u64
/// without cross-byte carries; only the last partial group goes bit by bit.
pub fn encode(out: []u8, bytes: []const u8) void {
    const len = encodedLen(bytes.len);
    std.debug.assert(out.len >= len);
    var k: usize = 0;
    while (5 * k + 5 <= bytes.len) : (k += 1) {
        const v = std.mem.readInt(u40, bytes[5 * k ..][0..5], .little);
        inline for (0..8) |i| out[len - 1 - (8 * k + i)] = alphabet[@as(u5, @truncate(v >> (5 * i)))];
    }
    for (8 * k..len) |n| out[len - 1 - n] = alphabet[digitAt(bytes, n)];
}

fn digitAt(bytes: []const u8, n: usize) u8 {
    const b = n * 5;
    const i = b / 8;
    const j: u3 = @intCast(b % 8);
    var c: u16 = bytes[i] >> j;
    if (i + 1 < bytes.len) c |= @as(u16, bytes[i + 1]) << (@as(u4, 8) - j);
    return @intCast(c & 0x1f);
}

pub fn encodeScalar(out: []u8, bytes: []const u8) void {
    const len = encodedLen(bytes.len);
    for (0..len) |n| out[len - 1 - n] = alphabet[digitAt(bytes, n)];
}

pub const DecodeError = error{InvalidNix32};

/// Converts characters to digit values in place order, vector-at-a-time.
fn digits(dst: []u8, in: []const u8) DecodeError!void {
    var i: usize = 0;
    while (i + lanes <= in.len) : (i += lanes) {
        var d: V = undefined;
        if (classify(in[i..][0..lanes].*, &d) != 0) return error.InvalidNix32;
        dst[i..][0..lanes].* = d;
    }
    for (in[i..], dst[i..in.len]) |c, *d| {
        d.* = reverse[c];
        if (d.* == invalid) return error.InvalidNix32;
    }
}

/// Packs digits (most significant first) into little-endian bytes: full
/// 8-digit groups become 5 bytes via one u64, the tail goes bit by bit.
fn pack(out: []u8, d: []const u8) DecodeError!void {
    const len = d.len;
    var k: usize = 0;
    while (8 * k + 8 <= len and 5 * k + 5 <= out.len) : (k += 1) {
        var v: u40 = 0;
        inline for (0..8) |i| v |= @as(u40, d[len - 1 - (8 * k + i)]) << (5 * i);
        std.mem.writeInt(u40, out[5 * k ..][0..5], v, .little);
    }
    @memset(out[5 * k ..], 0);
    return packBits(out, d, 8 * k);
}

fn packBits(out: []u8, d: []const u8, from: usize) DecodeError!void {
    for (from..d.len) |n| {
        const digit = d[d.len - n - 1];
        const b = n * 5;
        const i = b / 8;
        const j: u3 = @intCast(b % 8);
        out[i] |= digit << j;
        const carry: u8 = @intCast(@as(u16, digit) >> (@as(u4, 8) - j));
        if (i + 1 < out.len) {
            out[i + 1] |= carry;
        } else if (carry != 0) {
            return error.InvalidNix32;
        }
    }
}

/// Decodes `in` into exactly `out.len` bytes. `in.len` must equal
/// `encodedLen(out.len)`, and no bits may overflow the output.
pub fn decode(out: []u8, in: []const u8) DecodeError!void {
    if (in.len != encodedLen(out.len)) return error.InvalidNix32;
    var buf: [128]u8 = undefined;
    if (in.len > buf.len) return decodeScalar(out, in);
    try digits(buf[0..in.len], in);
    try pack(out, buf[0..in.len]);
}

/// Table-driven reference implementation.
pub fn decodeScalar(out: []u8, in: []const u8) DecodeError!void {
    if (in.len != encodedLen(out.len)) return error.InvalidNix32;
    var buf: [256]u8 = undefined;
    if (in.len > buf.len) return error.InvalidNix32;
    for (in, buf[0..in.len]) |c, *d| {
        d.* = reverse[c];
        if (d.* == invalid) return error.InvalidNix32;
    }
    @memset(out, 0);
    try packBits(out, buf[0..in.len], 0);
}

pub fn isValid(in: []const u8) bool {
    var i: usize = 0;
    var scratch: V = undefined;
    while (i + lanes <= in.len) : (i += lanes) {
        if (classify(in[i..][0..lanes].*, &scratch) != 0) return false;
    }
    for (in[i..]) |c| if (reverse[c] == invalid) return false;
    return true;
}

pub fn isValidScalar(in: []const u8) bool {
    for (in) |c| if (reverse[c] == invalid) return false;
    return true;
}

test "sha256 of empty string round-trips" {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("", &digest, .{});
    var text: [52]u8 = undefined;
    encode(&text, &digest);
    try std.testing.expectEqualStrings("0mdqa9w1p6cmli6976v4wi0sw9r4p5prkj7lzfd1877wk11c9c73", &text);
    var back: [32]u8 = undefined;
    try decode(&back, &text);
    try std.testing.expectEqualSlices(u8, &digest, &back);
}

test "store path hash length" {
    try std.testing.expectEqual(@as(usize, 32), encodedLen(20));
    try std.testing.expectEqual(@as(usize, 52), encodedLen(32));
}

test "rejects invalid characters and overflow" {
    var out: [20]u8 = undefined;
    try std.testing.expectError(error.InvalidNix32, decode(&out, "e" ** 32));
    // 52 chars carry 260 bits; the top 4 must be zero for a 32-byte digest.
    var digest: [32]u8 = undefined;
    try std.testing.expectError(error.InvalidNix32, decode(&digest, "z" ** 52));
}

test "vector classifier agrees with the table for every byte in every lane" {
    for (0..256) |c| {
        for (0..lanes) |lane| {
            var in = [_]u8{'0'} ** lanes;
            in[lane] = @intCast(c);
            try std.testing.expectEqual(isValidScalar(&in), isValid(&in));
            var d: V = undefined;
            const bad = classify(in, &d);
            if (bad == 0) {
                const arr: [lanes]u8 = d;
                try std.testing.expectEqual(reverse[c], arr[lane]);
            }
        }
    }
}

test "vector and scalar decode agree on random inputs" {
    var prng: std.Random.DefaultPrng = .init(7);
    const r = prng.random();
    for (0..10_000) |_| {
        var bytes: [20]u8 = undefined;
        r.bytes(&bytes);
        var text: [32]u8 = undefined;
        encode(&text, &bytes);
        if (r.boolean()) text[r.uintLessThan(usize, 32)] = r.int(u8);
        var a: [20]u8 = undefined;
        var b: [20]u8 = undefined;
        const ra = decode(&a, &text);
        const rb = decodeScalar(&b, &text);
        if (rb) |_| {
            try ra;
            try std.testing.expectEqualSlices(u8, &b, &a);
        } else |_| {
            try std.testing.expectError(error.InvalidNix32, ra);
        }
    }
}

test "grouped encode/decode agree with the bitwise reference at every length" {
    var prng: std.Random.DefaultPrng = .init(11);
    const r = prng.random();
    for (1..64) |n| {
        for (0..200) |_| {
            var bytes: [64]u8 = undefined;
            r.bytes(bytes[0..n]);
            var fast: [128]u8 = undefined;
            var slow: [128]u8 = undefined;
            const len = encodedLen(n);
            encode(fast[0..len], bytes[0..n]);
            encodeScalar(slow[0..len], bytes[0..n]);
            try std.testing.expectEqualStrings(slow[0..len], fast[0..len]);
            var back: [64]u8 = undefined;
            try decode(back[0..n], fast[0..len]);
            try std.testing.expectEqualSlices(u8, bytes[0..n], back[0..n]);
            var back_slow: [64]u8 = undefined;
            try decodeScalar(back_slow[0..n], fast[0..len]);
            try std.testing.expectEqualSlices(u8, bytes[0..n], back_slow[0..n]);
        }
    }
}
