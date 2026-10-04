//! Store path parsing and validation, matching what Nix's StorePath accepts:
//! `/nix/store/<32 nix32 chars>-<name>`, name 1-211 chars of
//! `[A-Za-z0-9+-._?=]`, not starting with '.'.
//!
//! The name check is vectorised: 32 characters are classified per step.

const std = @import("std");
const base32 = @import("nix-base32");

pub const store_dir = "/nix/store/";
pub const hash_len = 32;
pub const max_name_len = 211;

const lanes = 32;
const V = @Vector(lanes, u8);
const Mask = @Int(.unsigned, lanes);

fn splat(c: u8) V {
    return @splat(c);
}

fn bits(b: @Vector(lanes, bool)) Mask {
    return @bitCast(b);
}

inline fn invalidNameLanes(v: V) Mask {
    const lower = v | splat(0x20); // folds A-Z onto a-z; no other byte lands in a-z from outside letters
    const alpha = bits(lower >= splat('a')) & bits(lower <= splat('z'));
    const digit = bits(v >= splat('0')) & bits(v <= splat('9'));
    const special = bits(v == splat('+')) | bits(v == splat('-')) | bits(v == splat('.')) |
        bits(v == splat('_')) | bits(v == splat('?')) | bits(v == splat('='));
    return ~(alpha | digit | special);
}

fn isNameChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or switch (c) {
        '+', '-', '.', '_', '?', '=' => true,
        else => false,
    };
}

// Out of line: Zig 0.17 inlines this vector loop into callers such as
// baseName, which made store path parsing about 7% slower than a call.
pub noinline fn isValidName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_len or name[0] == '.') return false;
    var i: usize = 0;
    while (i + lanes <= name.len) : (i += lanes) {
        if (invalidNameLanes(name[i..][0..lanes].*) != 0) return false;
    }
    for (name[i..]) |c| if (!isNameChar(c)) return false;
    return true;
}

pub fn isValidNameScalar(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_len or name[0] == '.') return false;
    for (name) |c| if (!isNameChar(c)) return false;
    return true;
}

/// `<32 nix32 chars>-<name>`.
pub fn isValidBaseName(base: []const u8) bool {
    if (base.len < hash_len + 2) return false;
    return base[hash_len] == '-' and base32.isValid(base[0..hash_len]) and isValidName(base[hash_len + 1 ..]);
}

/// The basename of a full store path, or null if it is not a valid one.
pub fn baseName(store_path: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, store_path, store_dir)) return null;
    const base = store_path[store_dir.len..];
    return if (isValidBaseName(base)) base else null;
}

/// The decoded 20-byte hash of a valid basename.
pub fn hashOf(base: []const u8) ?[20]u8 {
    if (base.len < hash_len) return null;
    var out: [20]u8 = undefined;
    base32.decode(&out, base[0..hash_len]) catch return null;
    return out;
}

test "validates base names" {
    try std.testing.expect(isValidBaseName("0mdqa9w1p6cmli6976v4wi0sw9r4p5pr-hello-2.12"));
    try std.testing.expect(!isValidBaseName("0mdqa9w1p6cmli6976v4wi0sw9r4p5pr-hello\nSig: x"));
    try std.testing.expect(!isValidBaseName("0mdqa9w1p6cmli6976v4wi0sw9r4p5pr-.hidden"));
    try std.testing.expect(!isValidBaseName("emdqa9w1p6cmli6976v4wi0sw9r4p5pr-hello"));
    try std.testing.expect(baseName("/nix/store/0mdqa9w1p6cmli6976v4wi0sw9r4p5pr-hello") != null);
    try std.testing.expect(baseName("/nix/store/0mdqa9w1p6cmli6976v4wi0sw9r4p5pr-hello/bin") == null);
}

test "vector name check agrees with scalar for every byte in every lane" {
    for (0..256) |c| {
        for (0..lanes + 3) |pos| {
            var name: [lanes + 3]u8 = @splat('a');
            name[pos] = @intCast(c);
            try std.testing.expectEqual(isValidNameScalar(&name), isValidName(&name));
        }
    }
}
