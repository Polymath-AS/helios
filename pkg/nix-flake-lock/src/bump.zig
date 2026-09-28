//! Single-threaded bump allocator. std.heap.ArenaAllocator is lock-free and
//! thread-safe in Zig 0.16, which puts atomics on every allocation; parsing
//! allocates from one thread only, so plain pointer bumping is enough.
//! Chunks are chained through a header at their start, so a document that
//! fits in its first chunk costs exactly one malloc.

const std = @import("std");
const Allocator = std.mem.Allocator;

const Header = struct { next: ?*Header, len: usize };

pub const Bump = struct {
    gpa: Allocator,
    head: ?*Header = null,
    cur: usize = 0,
    end: usize = 0,

    pub fn init(gpa: Allocator, first_chunk: usize) Allocator.Error!Bump {
        var b: Bump = .{ .gpa = gpa };
        try b.grow(first_chunk);
        return b;
    }

    pub fn deinit(b: *Bump) void {
        var h = b.head;
        while (h) |chunk| {
            h = chunk.next;
            const bytes: [*]align(@alignOf(Header)) u8 = @ptrCast(chunk);
            b.gpa.free(bytes[0..chunk.len]);
        }
        b.* = undefined;
    }

    fn grow(b: *Bump, need: usize) Allocator.Error!void {
        const last = if (b.head) |h| h.len else 0;
        const size = @max(need + @sizeOf(Header) + 64, last * 2, 4096);
        const mem = try b.gpa.alignedAlloc(u8, .of(Header), size);
        const h: *Header = @ptrCast(mem.ptr);
        h.* = .{ .next = b.head, .len = size };
        b.head = h;
        b.cur = @intFromPtr(mem.ptr) + @sizeOf(Header);
        b.end = @intFromPtr(mem.ptr) + size;
    }

    inline fn raw(b: *Bump, len: usize, alignment: usize) Allocator.Error![*]u8 {
        var start = std.mem.alignForward(usize, b.cur, alignment);
        if (start + len > b.end) {
            @branchHint(.unlikely);
            try b.grow(len + alignment);
            start = std.mem.alignForward(usize, b.cur, alignment);
        }
        b.cur = start + len;
        return @ptrFromInt(start);
    }

    pub inline fn alloc(b: *Bump, comptime T: type, n: usize) Allocator.Error![]T {
        const p: [*]T = @ptrCast(@alignCast(try b.raw(n * @sizeOf(T), @alignOf(T))));
        return p[0..n];
    }

    pub inline fn dupe(b: *Bump, comptime T: type, items: []const T) Allocator.Error![]T {
        const out = try b.alloc(T, items.len);
        @memcpy(out, items);
        return out;
    }

    pub fn allocator(b: *Bump) Allocator {
        return .{ .ptr = b, .vtable = &.{ .alloc = vAlloc, .resize = vResize, .remap = vRemap, .free = vFree } };
    }

    fn vAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
        const b: *Bump = @ptrCast(@alignCast(ctx));
        return b.raw(len, alignment.toByteUnits()) catch null;
    }

    fn vResize(ctx: *anyopaque, memory: []u8, _: std.mem.Alignment, new_len: usize, _: usize) bool {
        const b: *Bump = @ptrCast(@alignCast(ctx));
        // Only the most recent allocation can grow or shrink in place.
        if (@intFromPtr(memory.ptr) + memory.len != b.cur) return new_len <= memory.len;
        if (@intFromPtr(memory.ptr) + new_len > b.end) return false;
        b.cur = @intFromPtr(memory.ptr) + new_len;
        return true;
    }

    fn vRemap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        return if (vResize(ctx, memory, alignment, new_len, ra)) memory.ptr else null;
    }

    fn vFree(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize) void {}
};

test "bump allocations are aligned and grow across chunks" {
    var b = try Bump.init(std.testing.allocator, 16);
    defer b.deinit();
    for (0..1000) |i| {
        const s = try b.alloc(u64, i % 7 + 1);
        try std.testing.expect(@intFromPtr(s.ptr) % 8 == 0);
        s[0] = i;
        _ = try b.alloc(u8, 3);
    }
    var list: std.ArrayList(u32) = .empty;
    for (0..10_000) |i| try list.append(b.allocator(), @intCast(i));
    try std.testing.expectEqual(@as(u32, 9999), list.items[9999]);
}
