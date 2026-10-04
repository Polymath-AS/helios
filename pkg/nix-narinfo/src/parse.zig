//! Zero-copy narinfo parser. Fields are slices into the input.
//!
//! Lines are split with a vector newline search (compare 32 bytes against
//! '\n', @ctz the mask); store paths are validated with the vectorised
//! checks in nix-store-path.

const std = @import("std");
const store_path = @import("nix-store-path");

pub const max_sigs = 8;

pub const Error = error{ MissingField, InvalidLine, InvalidNumber, InvalidStorePath, InvalidReference, TooManySignatures };

pub const NarInfo = struct {
    store_path: []const u8 = "",
    url: []const u8 = "",
    compression: []const u8 = "",
    file_hash: []const u8 = "",
    file_size: ?u64 = null,
    nar_hash: []const u8 = "",
    nar_size: u64 = 0,
    /// Space-separated basenames, validated.
    references: []const u8 = "",
    deriver: []const u8 = "",
    system: []const u8 = "",
    ca: []const u8 = "",
    sig_buf: [max_sigs][]const u8 = undefined,
    sig_count: u8 = 0,

    pub fn sigs(self: *const NarInfo) []const []const u8 {
        return self.sig_buf[0..self.sig_count];
    }

    pub fn referenceIterator(self: *const NarInfo) std.mem.TokenIterator(u8, .scalar) {
        return std.mem.tokenizeScalar(u8, self.references, ' ');
    }
};

const lanes = 32;
const V = @Vector(lanes, u8);
const Mask = @Int(.unsigned, lanes);

pub fn findNewline(s: []const u8, start: usize) ?usize {
    var i = start;
    const nl: V = @splat('\n');
    while (i + lanes <= s.len) : (i += lanes) {
        const v: V = s[i..][0..lanes].*;
        const m: Mask = @bitCast(v == nl);
        if (m != 0) return i + @ctz(m);
    }
    while (i < s.len) : (i += 1) if (s[i] == '\n') return i;
    return null;
}

fn number(s: []const u8) Error!u64 {
    return std.fmt.parseInt(u64, s, 10) catch error.InvalidNumber;
}

fn eq(a: []const u8, comptime b: []const u8) bool {
    return a.len == b.len and std.mem.eql(u8, a, b);
}

pub fn parse(text: []const u8) Error!NarInfo {
    var info: NarInfo = .{};
    var have_size = false;
    var pos: usize = 0;
    while (pos < text.len) {
        const end = findNewline(text, pos) orelse text.len;
        const line = text[pos..end];
        pos = end + 1;
        if (line.len == 0) continue;
        const colon = std.mem.findScalar(u8, line, ':') orelse return error.InvalidLine;
        const key = line[0..colon];
        // Nix skips exactly ": "; tolerate a bare ":" before end of line.
        const value = if (colon + 2 <= line.len) line[colon + 2 ..] else "";
        switch (key.len) {
            2 => if (eq(key, "CA")) {
                info.ca = value;
            },
            3 => if (eq(key, "URL")) {
                info.url = value;
            } else if (eq(key, "Sig")) {
                if (info.sig_count == max_sigs) return error.TooManySignatures;
                info.sig_buf[info.sig_count] = value;
                info.sig_count += 1;
            },
            6 => if (eq(key, "System")) {
                info.system = value;
            },
            7 => if (eq(key, "NarHash")) {
                info.nar_hash = value;
            } else if (eq(key, "NarSize")) {
                info.nar_size = try number(value);
                have_size = true;
            } else if (eq(key, "Deriver")) {
                if (value.len > 0 and !eq(value, "unknown-deriver") and !store_path.isValidBaseName(value)) return error.InvalidStorePath;
                info.deriver = value;
            },
            8 => if (eq(key, "FileHash")) {
                info.file_hash = value;
            } else if (eq(key, "FileSize")) {
                info.file_size = try number(value);
            },
            9 => if (eq(key, "StorePath")) {
                if (store_path.baseName(value) == null) return error.InvalidStorePath;
                info.store_path = value;
            },
            10 => if (eq(key, "References")) {
                var it = std.mem.tokenizeScalar(u8, value, ' ');
                while (it.next()) |r| if (!store_path.isValidBaseName(r)) return error.InvalidReference;
                info.references = value;
            },
            11 => if (eq(key, "Compression")) {
                info.compression = value;
            },
            else => {},
        }
    }
    if (info.store_path.len == 0 or info.url.len == 0 or info.nar_hash.len == 0 or !have_size) return error.MissingField;
    if (info.compression.len == 0) info.compression = "bzip2"; // Nix's historical default
    return info;
}

test "parses a narinfo" {
    const text =
        \\StorePath: /nix/store/p7jg95rzvfalb95k3mskk0jqxc9d724n-libunistring-1.4.1
        \\URL: nar/0k1zvrlb2c66njmrbc972fpz7a4ncqr1w4rillf0qwa4cjqa1m6c.nar.zst
        \\Compression: zstd
        \\FileHash: sha256:0k1zvrlb2c66njmrbc972fpz7a4ncqr1w4rillf0qwa4cjqa1m6c
        \\FileSize: 796947
        \\NarHash: sha256:162jnvprzbbglkdxvh3vgcy35j34wva4ni1zj71826vw25ycbdf0
        \\NarSize: 2078944
        \\References: p7jg95rzvfalb95k3mskk0jqxc9d724n-libunistring-1.4.1
        \\Deriver: b3bvrzp605zk7v12ar918r07500gnayv-libunistring-1.4.1.drv
        \\Sig: t-1:vkWbgswaWiUPIgtNgxNf9AYTerK7QJU2O4TfykgO9F8N6akQpbpnF5fNvsWw2ENiX0vqo6zBB4XzdAcT4uAkDQ==
        \\
    ;
    const info = try parse(text);
    try std.testing.expectEqualStrings("zstd", info.compression);
    try std.testing.expectEqual(@as(u64, 2078944), info.nar_size);
    try std.testing.expectEqual(@as(?u64, 796947), info.file_size);
    try std.testing.expectEqual(@as(usize, 1), info.sigs().len);
    var it = info.referenceIterator();
    try std.testing.expectEqualStrings("p7jg95rzvfalb95k3mskk0jqxc9d724n-libunistring-1.4.1", it.next().?);
    try std.testing.expectError(error.MissingField, parse("StorePath: /nix/store/p7jg95rzvfalb95k3mskk0jqxc9d724n-x\n"));
    try std.testing.expectError(error.InvalidStorePath, parse("StorePath: /nix/store/bad\n"));
}

test "vector newline search matches scalar" {
    var buf: [100]u8 = @splat('x');
    for (0..buf.len) |i| {
        buf[i] = '\n';
        for (0..i + 1) |start| try std.testing.expectEqual(@as(?usize, i), findNewline(&buf, start));
        buf[i] = 'x';
    }
    try std.testing.expectEqual(@as(?usize, null), findNewline(&buf, 0));
}
