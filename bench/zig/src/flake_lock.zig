//! Zig side of bench/flake-lock.sh, mirroring bench/flake-lock-rs.
//! FL_MODE=canon|bench, FL_LIST=<file with one path per line>. Output on stdout.

const std = @import("std");
const linux = std.os.linux;
const fl = @import("nix-flake-lock");

const gpa = std.heap.c_allocator;

fn now() u64 {
    var ts: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn readFile(path: []const u8) ![]u8 {
    const z = try gpa.dupeSentinel(u8, path, 0);
    defer gpa.free(z);
    const fd: i32 = @intCast(@as(isize, @bitCast(linux.openat(linux.AT.FDCWD, z, .{ .ACCMODE = .RDONLY }, 0))));
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

fn flush(out: *std.ArrayList(u8)) void {
    var off: usize = 0;
    while (off < out.items.len) {
        const n = linux.write(1, out.items[off..].ptr, out.items.len - off);
        if (linux.errno(n) != .SUCCESS) return;
        off += n;
    }
    out.clearRetainingCapacity();
}

fn iterations(len: usize) usize {
    return std.math.clamp(4_000_000 / @max(len, 1), 3, 200_000);
}

fn best(iters: usize, ctx: anytype, comptime f: fn (@TypeOf(ctx)) void) u64 {
    for (0..@min(iters, 1000)) |_| f(ctx);
    var b: u64 = std.math.maxInt(u64);
    for (0..7) |_| {
        const t0 = now();
        for (0..iters) |_| f(ctx);
        b = @min(b, now() - t0);
    }
    return b;
}

const ParseCtx = struct { bytes: []const u8 };

fn parseFresh(c: ParseCtx) void {
    // Parse and free each time: the same malloc traffic the Rust API incurs.
    var doc = fl.parse(gpa, c.bytes, .{}, null) catch unreachable;
    std.mem.doNotOptimizeAway(doc.lock.nodes.ptr);
    doc.deinit();
}

const LockCtx = struct { lock: *const fl.LockFile };

fn serialize(c: LockCtx) void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    c.lock.writeNix(gpa, &out) catch unreachable;
    std.mem.doNotOptimizeAway(out.items.ptr);
}

fn validate(c: LockCtx) void {
    c.lock.validate(gpa) catch {};
}

pub fn main() !void {
    const mode = std.mem.span(std.c.getenv("FL_MODE") orelse return error.NoMode);
    const list = try readFile(std.mem.span(std.c.getenv("FL_LIST") orelse return error.NoList));
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, list, '\n');
    while (it.next()) |path| {
        const bytes = try readFile(path);
        defer gpa.free(bytes);
        if (std.mem.eql(u8, mode, "canon")) {
            try out.print(gpa, "== {s}\n", .{path});
            if (fl.parse(gpa, bytes, .{}, null)) |doc_| {
                var doc = doc_;
                defer doc.deinit();
                const lock = &doc.lock;
                try lock.writeNix(gpa, &out);
                const ok = if (lock.validate(gpa)) true else |_| false;
                try out.print(gpa, "-- {s}\n", .{if (ok) "valid" else "invalid"});
            } else |_| {
                try out.appendSlice(gpa, "-- parse error\n");
            }
            if (out.items.len > 1 << 20) flush(&out);
            continue;
        }
        const name = std.fs.path.basename(path);
        const iters = iterations(bytes.len);
        var doc = try fl.parse(gpa, bytes, .{}, null);
        defer doc.deinit();
        const lock = &doc.lock;
        try out.print(gpa, "parse:{s} {d} {d}\n", .{ name, iters, best(iters, ParseCtx{ .bytes = bytes }, parseFresh) });
        try out.print(gpa, "serialize:{s} {d} {d}\n", .{ name, iters, best(iters, LockCtx{ .lock = lock }, serialize) });
        try out.print(gpa, "validate:{s} {d} {d}\n", .{ name, iters, best(iters, LockCtx{ .lock = lock }, validate) });
    }
    flush(&out);
}
