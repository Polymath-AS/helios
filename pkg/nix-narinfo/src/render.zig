//! Narinfo rendering and Ed25519 fingerprint signing. Every field that ends
//! up in a narinfo line is validated here, so no caller-supplied string can
//! inject extra lines.

const std = @import("std");
const nix32 = @import("nix-base32");
const store_path = @import("nix-store-path");
const Ed25519 = std.crypto.sign.Ed25519;
const Curve = std.crypto.ecc.Edwards25519;
const basemul = @import("basemul.zig");

const store_dir = store_path.store_dir;
const baseName = store_path.baseName;
const isValidBaseName = store_path.isValidBaseName;

pub const Error = error{ InvalidStorePath, InvalidReference, InvalidDeriver, InvalidSystem, InvalidCompression, InvalidKey, OutOfMemory };

fn isValidSystem(s: []const u8) bool {
    if (s.len == 0 or s.len > 64) return false;
    for (s) |c| if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c == '.')) return false;
    return true;
}

pub const Signer = struct {
    name: []u8,
    key_pair: Ed25519.KeyPair,
    /// RFC 8032 expanded secret, derived once. std's KeyPair.sign re-derives
    /// the public key (a full scalar multiplication) on every call to check
    /// for a mismatch; our key pair is validated once at load instead.
    scalar: [32]u8,
    prefix: [32]u8,
    public: [32]u8,
    /// Comb table for the base point: signing does 64 additions, not 252 doublings.
    table: basemul.Table,

    /// Parses a Nix secret key: `<name>:<base64 of 64-byte secret key>`.
    pub fn parse(allocator: std.mem.Allocator, text: []const u8) Error!*Signer {
        const trimmed = std.mem.trim(u8, text, " \t\r\n");
        const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse return error.InvalidKey;
        const name = trimmed[0..colon];
        if (name.len == 0) return error.InvalidKey;
        for (name) |c| if (c == '\n' or c == ' ') return error.InvalidKey;
        var raw: [Ed25519.SecretKey.encoded_length]u8 = undefined;
        const decoder = std.base64.standard.Decoder;
        const b64 = trimmed[colon + 1 ..];
        const n = decoder.calcSizeForSlice(b64) catch return error.InvalidKey;
        if (n != raw.len) return error.InvalidKey;
        decoder.decode(&raw, b64) catch return error.InvalidKey;
        const secret = Ed25519.SecretKey.fromBytes(raw) catch return error.InvalidKey;
        const key_pair = Ed25519.KeyPair.fromSecretKey(secret) catch return error.InvalidKey;

        var expanded: [64]u8 = undefined;
        std.crypto.hash.sha2.Sha512.hash(raw[0..32], &expanded, .{});
        var scalar = expanded[0..32].*;
        Curve.scalar.clamp(&scalar);

        const self = try allocator.create(Signer);
        errdefer allocator.destroy(self);
        self.* = .{
            .name = try allocator.dupe(u8, name),
            .key_pair = key_pair,
            .scalar = scalar,
            .prefix = expanded[32..64].*,
            .public = key_pair.public_key.toBytes(),
            .table = basemul.table(),
        };
        return self;
    }

    pub fn destroy(self: *Signer, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.destroy(self);
    }

    /// Deterministic Ed25519 (RFC 8032 §5.1.6): one base-point multiplication.
    pub fn signRaw(self: *const Signer, msg: []const u8) Error![64]u8 {
        const Sha512 = std.crypto.hash.sha2.Sha512;
        var h = Sha512.init(.{});
        h.update(&self.prefix);
        h.update(msg);
        var r64: [64]u8 = undefined;
        h.final(&r64);
        const r = Curve.scalar.reduce64(r64);
        const big_r = basemul.mulBase(&self.table, r).toBytes();

        h = Sha512.init(.{});
        h.update(&big_r);
        h.update(&self.public);
        h.update(msg);
        var k64: [64]u8 = undefined;
        h.final(&k64);
        const k = Curve.scalar.reduce64(k64);

        var sig: [64]u8 = undefined;
        sig[0..32].* = big_r;
        sig[32..64].* = Curve.scalar.mulAdd(k, self.scalar, r);
        return sig;
    }

    /// `<name>:<base64 signature>`.
    pub fn sign(self: *const Signer, out: *std.ArrayList(u8), allocator: std.mem.Allocator, msg: []const u8) Error!void {
        const bytes = try self.signRaw(msg);
        var b64: [std.base64.standard.Encoder.calcSize(bytes.len)]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&b64, &bytes);
        try out.appendSlice(allocator, self.name);
        try out.append(allocator, ':');
        try out.appendSlice(allocator, &b64);
    }

    /// `<name>:<base64 public key>`, the value for `trusted-public-keys`.
    pub fn publicKey(self: *const Signer, out: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        const bytes = self.key_pair.public_key.toBytes();
        var b64: [std.base64.standard.Encoder.calcSize(bytes.len)]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&b64, &bytes);
        try out.appendSlice(allocator, self.name);
        try out.append(allocator, ':');
        try out.appendSlice(allocator, &b64);
    }
};

pub const Input = struct {
    store_path: []const u8,
    nar_hash: *const [32]u8,
    nar_size: u64,
    file_hash: *const [32]u8,
    file_size: u64,
    compression: []const u8,
    /// Space-separated store path basenames, any order.
    references: []const u8,
    /// Deriver basename, or empty.
    deriver: []const u8,
    /// System, or empty.
    system: []const u8,
};

fn fileExtension(compression: []const u8) Error![]const u8 {
    if (std.mem.eql(u8, compression, "zstd")) return ".nar.zst";
    if (std.mem.eql(u8, compression, "none")) return ".nar";
    if (std.mem.eql(u8, compression, "xz")) return ".nar.xz";
    if (std.mem.eql(u8, compression, "bzip2")) return ".nar.bz2";
    return error.InvalidCompression;
}

fn lessThanStr(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

/// Renders a complete narinfo. `signer` may be null for an unsigned cache.
pub fn render(allocator: std.mem.Allocator, in: Input, signer: ?*const Signer) Error![]u8 {
    _ = baseName(in.store_path) orelse return error.InvalidStorePath;
    const ext = try fileExtension(in.compression);
    if (in.deriver.len > 0 and !(isValidBaseName(in.deriver) and std.mem.endsWith(u8, in.deriver, ".drv"))) return error.InvalidDeriver;
    if (in.system.len > 0 and !isValidSystem(in.system)) return error.InvalidSystem;

    var refs: std.ArrayList([]const u8) = .empty;
    defer refs.deinit(allocator);
    var it = std.mem.tokenizeScalar(u8, in.references, ' ');
    while (it.next()) |r| {
        if (!isValidBaseName(r)) return error.InvalidReference;
        try refs.append(allocator, r);
    }
    std.mem.sort([]const u8, refs.items, {}, lessThanStr);

    var nar_hash: [52]u8 = undefined;
    nix32.encode(&nar_hash, in.nar_hash);
    var file_hash: [52]u8 = undefined;
    nix32.encode(&file_hash, in.file_hash);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const w = struct {
        fn line(o: *std.ArrayList(u8), a: std.mem.Allocator, parts: []const []const u8) Error!void {
            for (parts) |p| try o.appendSlice(a, p);
            try o.append(a, '\n');
        }
    }.line;
    var num_buf: [2][20]u8 = undefined;
    const nar_size = std.fmt.bufPrint(&num_buf[0], "{d}", .{in.nar_size}) catch unreachable;
    const file_size = std.fmt.bufPrint(&num_buf[1], "{d}", .{in.file_size}) catch unreachable;

    try w(&out, allocator, &.{ "StorePath: ", in.store_path });
    try w(&out, allocator, &.{ "URL: nar/", &file_hash, ext });
    try w(&out, allocator, &.{ "Compression: ", in.compression });
    try w(&out, allocator, &.{ "FileHash: sha256:", &file_hash });
    try w(&out, allocator, &.{ "FileSize: ", file_size });
    try w(&out, allocator, &.{ "NarHash: sha256:", &nar_hash });
    try w(&out, allocator, &.{ "NarSize: ", nar_size });
    // Always "References: " with the space, even when empty: Nix's parser
    // skips two bytes after the colon and would otherwise eat the newline.
    try out.appendSlice(allocator, "References: ");
    for (refs.items, 0..) |r, i| {
        if (i > 0) try out.append(allocator, ' ');
        try out.appendSlice(allocator, r);
    }
    try out.append(allocator, '\n');
    if (in.deriver.len > 0) try w(&out, allocator, &.{ "Deriver: ", in.deriver });
    if (in.system.len > 0) try w(&out, allocator, &.{ "System: ", in.system });

    if (signer) |s| {
        // 1;<store path>;sha256:<nar hash>;<nar size>;<comma-separated reference paths>
        var fp: std.ArrayList(u8) = .empty;
        defer fp.deinit(allocator);
        try fp.appendSlice(allocator, "1;");
        try fp.appendSlice(allocator, in.store_path);
        try fp.appendSlice(allocator, ";sha256:");
        try fp.appendSlice(allocator, &nar_hash);
        try fp.append(allocator, ';');
        try fp.appendSlice(allocator, nar_size);
        try fp.append(allocator, ';');
        for (refs.items, 0..) |r, i| {
            if (i > 0) try fp.append(allocator, ',');
            try fp.appendSlice(allocator, store_dir);
            try fp.appendSlice(allocator, r);
        }
        try out.appendSlice(allocator, "Sig: ");
        try s.sign(&out, allocator, fp.items);
        try out.append(allocator, '\n');
    }

    return out.toOwnedSlice(allocator);
}


test "renders and signs a narinfo" {
    const a = std.testing.allocator;
    // Secret key from `nix key generate-secret --key-name test-1`.
    const signer = try Signer.parse(a, "test-1:suJsWimvBNFUIc0JJE18OfOMygH/f2GuTC2/XwD6rPKkV+1VKilMIkXl6Ax9hqeKpUF/BSOH+Fqng4tqZlirhw==");
    defer signer.destroy(a);
    const nar = [_]u8{1} ** 32;
    const file = [_]u8{2} ** 32;
    const text = try render(a, .{
        .store_path = "/nix/store/0mdqa9w1p6cmli6976v4wi0sw9r4p5pr-hello",
        .nar_hash = &nar,
        .nar_size = 1234,
        .file_hash = &file,
        .file_size = 99,
        .compression = "zstd",
        .references = "1mdqa9w1p6cmli6976v4wi0sw9r4p5pr-b 0mdqa9w1p6cmli6976v4wi0sw9r4p5pr-hello",
        .deriver = "",
        .system = "x86_64-linux",
    }, signer);
    defer a.free(text);
    try std.testing.expect(std.mem.indexOf(u8, text, "References: 0mdqa9w1p6cmli6976v4wi0sw9r4p5pr-hello 1mdqa9w1p6cmli6976v4wi0sw9r4p5pr-b\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "\nSig: test-1:") != null);
    const empty = try render(a, .{
        .store_path = "/nix/store/0mdqa9w1p6cmli6976v4wi0sw9r4p5pr-hello",
        .nar_hash = &nar,
        .nar_size = 1,
        .file_hash = &file,
        .file_size = 1,
        .compression = "zstd",
        .references = "",
        .deriver = "0mdqa9w1p6cmli6976v4wi0sw9r4p5pr-hello.drv",
        .system = "",
    }, null);
    defer a.free(empty);
    try std.testing.expect(std.mem.indexOf(u8, empty, "\nReferences: \nDeriver: ") != null);
    try std.testing.expectError(error.InvalidSystem, render(a, .{
        .store_path = "/nix/store/0mdqa9w1p6cmli6976v4wi0sw9r4p5pr-hello",
        .nar_hash = &nar,
        .nar_size = 1,
        .file_hash = &file,
        .file_size = 1,
        .compression = "zstd",
        .references = "",
        .deriver = "",
        .system = "x86\nSig: evil",
    }, null));
}

test "fast signing is byte-identical to std Ed25519" {
    const a = std.testing.allocator;
    const signer = try Signer.parse(a, "test-1:suJsWimvBNFUIc0JJE18OfOMygH/f2GuTC2/XwD6rPKkV+1VKilMIkXl6Ax9hqeKpUF/BSOH+Fqng4tqZlirhw==");
    defer signer.destroy(a);
    var prng: std.Random.DefaultPrng = .init(3);
    var msg: [300]u8 = undefined;
    for (0..200) |i| {
        prng.random().bytes(msg[0 .. i + 1]);
        const ours = try signer.signRaw(msg[0 .. i + 1]);
        const theirs = (try signer.key_pair.sign(msg[0 .. i + 1], null)).toBytes();
        try std.testing.expectEqualSlices(u8, &theirs, &ours);
    }
}
