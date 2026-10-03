//! Benchmarks for the pkg/* Nix libraries. Mirrors bench/haskell/Bench.hs:
//! both read the same NUL-separated corpus files from $BENCH_DIR and print
//! `<name> <ops> <best-round-ns>` lines.

const std = @import("std");
const linux = std.os.linux;
const base32 = @import("nix-base32");
const store_path = @import("nix-store-path");
const narinfo = @import("nix-narinfo");
const derivation = @import("nix-derivation");
const archive = @import("nix-archive");

const gpa = std.heap.c_allocator;
const rounds = 7;

fn now() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn readFile(path: [:0]const u8) ![]u8 {
    const fd: i32 = @intCast(linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0));
    if (fd < 0) return error.Open;
    defer _ = linux.close(fd);
    var list: std.ArrayList(u8) = .empty;
    var buf: [1 << 16]u8 = undefined;
    while (true) {
        const n = linux.read(fd, &buf, buf.len);
        if (linux.errno(n) != .SUCCESS) return error.Read;
        if (n == 0) break;
        try list.appendSlice(gpa, buf[0..n]);
    }
    return list.toOwnedSlice(gpa);
}

fn records(dir: []const u8, name: []const u8) ![]const []const u8 {
    const path = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ dir, name }, 0);
    const data = try readFile(path);
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, data, 0);
    while (it.next()) |r| if (r.len > 0) try out.append(gpa, r);
    return out.toOwnedSlice(gpa);
}

fn report(name: []const u8, ops: usize, ns: u64) void {
    std.debug.print("{s} {d} {d}\n", .{ name, ops, ns });
}

/// Runs `body` `rounds` times and reports the fastest round.
fn bench(name: []const u8, ops: usize, ctx: anytype, comptime body: fn (@TypeOf(ctx)) anyerror!void) !void {
    try body(ctx); // warm up
    var best: u64 = std.math.maxInt(u64);
    for (0..rounds) |_| {
        const t0 = now();
        try body(ctx);
        best = @min(best, now() - t0);
    }
    report(name, ops, best);
}

const Ctx = struct {
    narinfos: []const []const u8,
    parsed: []narinfo.NarInfo,
    drvs: []const []const u8,
    paths: []const []const u8,
    hashes32: []const []const u8,
    hashes52: []const []const u8,
    raw20: [][20]u8,
    fingerprints: []const []const u8,
    signer: *narinfo.Signer,
};

fn narinfoParse(c: *const Ctx) !void {
    for (c.narinfos) |t| std.mem.doNotOptimizeAway(try narinfo.parse(t));
}

fn narinfoRender(c: *const Ctx) !void {
    for (c.parsed) |p| {
        var nar: [32]u8 = undefined;
        var file: [32]u8 = undefined;
        try base32.decode(&nar, p.nar_hash["sha256:".len..]);
        try base32.decode(&file, p.file_hash["sha256:".len..]);
        const text = try narinfo.render(gpa, .{
            .store_path = p.store_path,
            .nar_hash = &nar,
            .nar_size = p.nar_size,
            .file_hash = &file,
            .file_size = p.file_size orelse 0,
            .compression = p.compression,
            .references = p.references,
            .deriver = p.deriver,
            .system = p.system,
        }, null);
        std.mem.doNotOptimizeAway(text.ptr);
        gpa.free(text);
    }
}

fn sign(c: *const Ctx) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    for (c.fingerprints) |fp| {
        out.clearRetainingCapacity();
        try c.signer.sign(&out, gpa, fp);
        std.mem.doNotOptimizeAway(out.items.ptr);
    }
}

fn drvParse(c: *const Ctx) !void {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    for (c.drvs) |d| {
        std.mem.doNotOptimizeAway(try derivation.parse(arena.allocator(), d));
        _ = arena.reset(.retain_capacity);
    }
}

fn decode32(c: *const Ctx) !void {
    for (c.hashes32) |h| {
        var out: [20]u8 = undefined;
        try base32.decode(&out, h);
        std.mem.doNotOptimizeAway(out);
    }
}

fn decode32Scalar(c: *const Ctx) !void {
    for (c.hashes32) |h| {
        var out: [20]u8 = undefined;
        try base32.decodeScalar(&out, h);
        std.mem.doNotOptimizeAway(out);
    }
}

fn decode52(c: *const Ctx) !void {
    for (c.hashes52) |h| {
        var out: [32]u8 = undefined;
        try base32.decode(&out, h);
        std.mem.doNotOptimizeAway(out);
    }
}

fn encode20(c: *const Ctx) !void {
    for (c.raw20) |*r| {
        var out: [32]u8 = undefined;
        base32.encode(&out, r);
        std.mem.doNotOptimizeAway(out);
    }
}

fn storePathParse(c: *const Ctx) !void {
    for (c.paths) |p| {
        const base = store_path.baseName(p) orelse return error.Invalid;
        std.mem.doNotOptimizeAway(store_path.hashOf(base));
    }
}

fn storePathValid(c: *const Ctx) !void {
    for (c.paths) |p| {
        if (!store_path.isValidBaseName(p[store_path.store_dir.len..])) return error.Invalid;
    }
}

fn encode20Scalar(c: *const Ctx) !void {
    for (c.raw20) |*r| {
        var out: [32]u8 = undefined;
        base32.encodeScalar(&out, r);
        std.mem.doNotOptimizeAway(out);
    }
}

fn storePathValidScalar(c: *const Ctx) !void {
    for (c.paths) |p| {
        const base = p[store_path.store_dir.len..];
        if (!(base32.isValidScalar(base[0..32]) and store_path.isValidNameScalar(base[33..]))) return error.Invalid;
    }
}

fn discard(_: ?*anyopaque, _: [*]const u8, _: usize) callconv(.c) c_int {
    return 0;
}

fn narHash(c: *const Ctx) !void {
    for (c.paths) |p| {
        var sink = try archive.Sink.init(gpa, .{ .level = 0 }, discard, null);
        defer sink.deinit(gpa);
        const z = try gpa.dupeZ(u8, p);
        defer gpa.free(z);
        try archive.dump(&sink, z);
        std.mem.doNotOptimizeAway(try sink.finish());
    }
}

pub fn main() !void {
    const dir = std.mem.span(std.c.getenv("BENCH_DIR") orelse return error.NoBenchDir);
    const only = if (std.c.getenv("BENCH_ONLY")) |s| std.mem.span(s) else "";
    if (std.mem.eql(u8, only, "sha")) return shaThroughput();

    const narinfos = try records(dir, "narinfo.bin");
    const parsed = try gpa.alloc(narinfo.NarInfo, narinfos.len);
    for (narinfos, parsed) |t, *p| p.* = try narinfo.parse(t);

    const raw20 = try gpa.alloc([20]u8, parsed.len);
    const hashes32 = try gpa.alloc([]const u8, parsed.len);
    const hashes52 = try gpa.alloc([]const u8, parsed.len);
    const fingerprints = try gpa.alloc([]const u8, parsed.len);
    for (parsed, 0..) |p, i| {
        hashes32[i] = p.store_path[store_path.store_dir.len..][0..32];
        hashes52[i] = p.nar_hash["sha256:".len..];
        try base32.decode(&raw20[i], hashes32[i]);
        fingerprints[i] = try std.fmt.allocPrint(gpa, "1;{s};{s};{d};{s}", .{ p.store_path, p.nar_hash, p.nar_size, p.references });
    }
    const key = try readFile(try std.fmt.allocPrintSentinel(gpa, "{s}/key", .{dir}, 0));
    const ctx: Ctx = .{
        .narinfos = narinfos,
        .parsed = parsed,
        .drvs = try records(dir, "drv.bin"),
        .paths = try records(dir, "paths.bin"),
        .hashes32 = hashes32,
        .hashes52 = hashes52,
        .raw20 = raw20,
        .fingerprints = fingerprints,
        .signer = try narinfo.Signer.parse(gpa, key),
    };

    if (std.mem.eql(u8, only, "nar")) {
        var bytes: u64 = 0;
        for (ctx.paths) |p| {
            var sink = try archive.Sink.init(gpa, .{ .level = 0 }, discard, null);
            defer sink.deinit(gpa);
            try archive.dump(&sink, try gpa.dupeZ(u8, p));
            bytes += (try sink.finish()).nar_size;
        }
        const t0 = now();
        try narHash(&ctx);
        report("nar-dump-sha256", @intCast(bytes), now() - t0);
        return;
    }

    try bench("narinfo-parse", narinfos.len, &ctx, narinfoParse);
    try bench("narinfo-render", parsed.len, &ctx, narinfoRender);
    try bench("ed25519-sign", fingerprints.len, &ctx, sign);
    try bench("drv-parse", ctx.drvs.len, &ctx, drvParse);
    try bench("base32-decode-20", hashes32.len, &ctx, decode32);
    try bench("base32-decode-20-scalar", hashes32.len, &ctx, decode32Scalar);
    try bench("base32-decode-32", hashes52.len, &ctx, decode52);
    try bench("base32-encode-20", raw20.len, &ctx, encode20);
    try bench("storepath-parse", ctx.paths.len, &ctx, storePathParse);
    try bench("storepath-validate-simd", ctx.paths.len, &ctx, storePathValid);
    try bench("storepath-validate-scalar", ctx.paths.len, &ctx, storePathValidScalar);
    try bench("base32-encode-20-scalar", raw20.len, &ctx, encode20Scalar);
}

/// Raw SHA-256 throughput over a 64 MiB buffer, for comparison with
/// `openssl speed -evp sha256`.
fn shaOnce(comptime H: type, name: []const u8, buf: []const u8) void {
    var best: u64 = std.math.maxInt(u64);
    for (0..5) |_| {
        const t0 = now();
        var d: [32]u8 = undefined;
        H.hash(buf, &d, .{});
        std.mem.doNotOptimizeAway(d);
        best = @min(best, now() - t0);
    }
    report(name, buf.len, best);
}

pub fn shaThroughput() void {
    const big = gpa.alloc(u8, 64 << 20) catch unreachable;
    @memset(big, 0xab);
    shaOnce(std.crypto.hash.sha2.Sha256, "sha256-std", big);
    shaOnce(archive.Sha256, "sha256-multiblock", big);
}

pub fn shaThroughputOld() void {
    const buf = gpa.alloc(u8, 64 << 20) catch unreachable;
    @memset(buf, 0xab);
    var best: u64 = std.math.maxInt(u64);
    for (0..5) |_| {
        const t0 = now();
        var d: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(buf, &d, .{});
        std.mem.doNotOptimizeAway(d);
        best = @min(best, now() - t0);
    }
    report("sha256-64MiB", buf.len, best);
}
