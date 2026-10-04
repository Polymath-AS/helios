//! Nix `flake.lock` parsing (versions 5-7), `follows` validation and
//! resolution, and canonical version 7 serialisation, without Nix.
//!
//! Semantics follow the nix-flake-lock crate (Rust): last duplicate key wins,
//! version 5 `info` is overlaid onto `locked`, unreachable nodes are
//! dropped, and output is byte-identical to Nix's canonical writer.
//!
//! Speed comes from single-pass scanning: strings are scanned 32 bytes at a
//! time for '"', '\\', control and non-ASCII bytes at once (UTF-8 is only
//! validated where it may legally occur, inside strings), whitespace runs are
//! skipped with a vector compare, lists are collected in reusable scratch
//! stacks and copied once into an arena, and canonical names borrow from
//! the input instead of allocating.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Bump = @import("bump.zig").Bump;

pub const Limits = struct {
    max_bytes: usize = 16 * 1024 * 1024,
    max_nodes: usize = 1_000_000,
    max_depth: usize = 256,
    max_path_components: usize = 65_536,
};

pub const ParseError = error{
    InputTooLarge,
    InvalidUtf8,
    UnexpectedEof,
    Syntax,
    TrailingCharacters,
    ControlCharacter,
    InvalidEscape,
    InvalidUnicodeEscape,
    InvalidNumber,
    UnsupportedVersion,
    MissingField,
    MissingNode,
    TooManyNodes,
    NestingTooDeep,
    PathTooLong,
    UnsupportedInputAttributeType,
    CycleToRoot,
    OutOfMemory,
};

pub const ValidationError = error{ FollowsCycle, MissingFollowsTarget, OutOfMemory };

/// Where a parse error happened.
pub const Diagnostic = struct { offset: usize = 0 };

pub const Value = union(enum) {
    string: []const u8,
    integer: u64,
    boolean: bool,
};

pub const Attr = struct { name: []const u8, value: Value };

pub const Path = []const []const u8;

pub const Edge = union(enum) {
    node: u32,
    follows: Path,
};

pub const Input = struct { name: []const u8, edge: Edge };

pub const Locked = struct {
    original: []const Attr,
    locked: []const Attr,
    is_flake: bool,
    parent: ?Path,

    pub fn get(attrs: []const Attr, name: []const u8) ?Value {
        const i = findSorted(Attr, attrs, name) orelse return null;
        return attrs[i].value;
    }
};

pub const Node = struct {
    /// Key in the source document (not graph identity).
    key: []const u8,
    /// Sorted by name.
    inputs: []const Input,
    /// Null for the root node.
    locked: ?Locked,

    pub fn input(self: *const Node, name: []const u8) ?*const Input {
        const i = findSorted(Input, self.inputs, name) orelse return null;
        return &self.inputs[i];
    }
};

pub const root_id: u32 = 0;

pub const LockFile = struct {
    source_version: u8,
    /// Reachable nodes; the root is at index 0.
    nodes: []const Node,

    pub fn resolve(self: *const LockFile, gpa: Allocator, path: Path) ValidationError!?u32 {
        var r: Resolver = .init(gpa, self);
        defer r.deinit();
        return r.resolve(path, false);
    }

    fn hasFollows(self: *const LockFile) bool {
        for (self.nodes) |n| for (n.inputs) |in| switch (in.edge) {
            .follows => |p| if (p.len > 0) return true,
            .node => {},
        };
        return false;
    }

    /// Checks that every `follows` target exists and no chain is cyclic.
    pub fn validate(self: *const LockFile, gpa: Allocator) ValidationError!void {
        // Only `follows` edges can fail, and every parsed node is reachable,
        // so a graph without non-empty follows edges is valid as is.
        if (!self.hasFollows()) return;
        var first: [4096]u8 = undefined;
        var fallback: std.heap.BufferFirstAllocator = .init(&first, gpa);
        var bump = try Bump.init(fallback.allocator(), 2 * 1024);
        defer bump.deinit();
        var r: Resolver = .init(bump.allocator(), self);
        const visited = try bump.alloc(bool, self.nodes.len);
        @memset(visited, false);
        visited[root_id] = true;
        // Each node is pushed at most once.
        const stack_buf = try bump.alloc(u32, self.nodes.len);
        var stack: std.ArrayList(u32) = .initBuffer(stack_buf);
        stack.appendAssumeCapacity(root_id);
        while (stack.pop()) |id| {
            const node = &self.nodes[id];
            var i = node.inputs.len;
            while (i > 0) {
                i -= 1;
                switch (node.inputs[i].edge) {
                    .node => |child| if (!visited[child]) {
                        visited[child] = true;
                        stack.appendAssumeCapacity(child);
                    },
                    .follows => |target| if (target.len > 0) {
                        if (try r.resolve(target, true) == null) return error.MissingFollowsTarget;
                    },
                }
            }
        }
    }

    /// Appends canonical, two-space-indented version 7 JSON (with the
    /// trailing newline Nix writes).
    pub fn writeNix(self: *const LockFile, gpa: Allocator, out: *std.ArrayList(u8)) Allocator.Error!void {
        var w: Writer = .{ .gpa = gpa, .out = out, .lock = self };
        return w.write();
    }
};

fn findSorted(comptime T: type, items: []const T, name: []const u8) ?usize {
    var lo: usize = 0;
    var hi: usize = items.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, items[mid].name, name)) {
            .eq => return mid,
            .lt => lo = mid + 1,
            .gt => hi = mid,
        }
    }
    return null;
}

// ── SIMD scanning ──

const lanes = 32;
const V = @Vector(lanes, u8);
const Mask = @Int(.unsigned, lanes);

inline fn splat(c: u8) V {
    return @splat(c);
}

inline fn bits(b: @Vector(lanes, bool)) Mask {
    return @bitCast(b);
}

/// First byte at or after `i` that ends or interrupts a plain string run:
/// '"', '\\', a control byte, or a non-ASCII byte.
fn scanString(s: []const u8, start: usize) ?usize {
    var i = start;
    while (i + lanes <= s.len) : (i += lanes) {
        const v: V = s[i..][0..lanes].*;
        const m = bits(v == splat('"')) | bits(v == splat('\\')) | bits(v < splat(0x20)) | bits(v >= splat(0x80));
        if (m != 0) return i + @ctz(m);
    }
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '"' or c == '\\' or c < 0x20 or c >= 0x80) return i;
    }
    return null;
}

fn isSpace(c: u8) bool {
    return c == ' ' or c == '\n' or c == '\r' or c == '\t';
}

/// First non-whitespace byte at or after `i`.
fn skipSpace(s: []const u8, start: usize) usize {
    var i = start;
    if (i >= s.len or !isSpace(s[i])) return i;
    while (i + lanes <= s.len) : (i += lanes) {
        const v: V = s[i..][0..lanes].*;
        const ws = bits(v == splat(' ')) | bits(v == splat('\n')) | bits(v == splat('\r')) | bits(v == splat('\t'));
        if (ws != ~@as(Mask, 0)) return i + @ctz(~ws);
    }
    while (i < s.len and isSpace(s[i])) i += 1;
    return i;
}

/// Bytes that must be escaped in JSON output.
fn scanEscape(s: []const u8, start: usize) usize {
    var i = start;
    while (i + lanes <= s.len) : (i += lanes) {
        const v: V = s[i..][0..lanes].*;
        const m = bits(v == splat('"')) | bits(v == splat('\\')) | bits(v < splat(0x20));
        if (m != 0) return i + @ctz(m);
    }
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '"' or c == '\\' or c < 0x20) return i;
    }
    return s.len;
}

// ── Parser ──

const WireEdge = union(enum) { node: []const u8, follows: Path };

const WireInput = struct {
    offset: usize,
    name: []const u8,
    edge: WireEdge,
    target: u32 = 0,
};

const WireNode = struct {
    offset: usize,
    key: []const u8,
    inputs: []WireInput = &.{},
    original: ?[]Attr = null,
    locked: ?[]Attr = null,
    info: ?[]Attr = null,
    is_flake: bool = true,
    parent: ?Path = null,
};

fn Keyed(comptime T: type) type {
    return struct { offset: usize, item: T };
}

/// Sort by name and keep the last occurrence of each duplicate, like Nix.
fn sortDedup(comptime T: type, items: []Keyed(T), nameOf: fn (*const T) []const u8) usize {
    const Ctx = struct {
        fn lessThan(_: void, a: Keyed(T), b: Keyed(T)) bool {
            return switch (std.mem.order(u8, nameOf(&a.item), nameOf(&b.item))) {
                .lt => true,
                .gt => false,
                .eq => a.offset > b.offset,
            };
        }
    };
    if (items.len < 2) return items.len;
    // Inputs are usually already sorted: skip the sort when they are.
    var sorted = true;
    for (items[1..], items[0 .. items.len - 1]) |b, a| {
        if (std.mem.order(u8, nameOf(&a.item), nameOf(&b.item)) != .lt) {
            sorted = false;
            break;
        }
    }
    if (sorted) return items.len;
    // Offsets are unique, so an unstable sort gives the same order.
    std.mem.sortUnstable(Keyed(T), items, {}, Ctx.lessThan);
    var w: usize = 1;
    for (items[1..]) |it| {
        if (!std.mem.eql(u8, nameOf(&it.item), nameOf(&items[w - 1].item))) {
            items[w] = it;
            w += 1;
        }
    }
    return w;
}

fn attrName(a: *const Attr) []const u8 {
    return a.name;
}
fn inputName(i: *const WireInput) []const u8 {
    return i.name;
}
fn nodeKey(n: *const WireNode) []const u8 {
    return n.key;
}

const Parser = struct {
    s: []const u8,
    pos: usize = 0,
    depth: usize = 0,
    limits: Limits,
    bump: *Bump,
    /// The bump allocator as a std Allocator, for growable lists.
    arena: Allocator,
    diag: ?*Diagnostic,
    attr_scratch: std.ArrayList(Keyed(Attr)) = .empty,
    input_scratch: std.ArrayList(Keyed(WireInput)) = .empty,
    path_scratch: std.ArrayList([]const u8) = .empty,

    fn fail(p: *Parser, err: ParseError, at: usize) ParseError {
        if (p.diag) |d| d.offset = at;
        return err;
    }

    inline fn ws(p: *Parser) void {
        p.pos = skipSpace(p.s, p.pos);
    }

    inline fn peek(p: *Parser) ?u8 {
        return if (p.pos < p.s.len) p.s[p.pos] else null;
    }

    inline fn consume(p: *Parser, c: u8) bool {
        if (p.pos < p.s.len and p.s[p.pos] == c) {
            p.pos += 1;
            return true;
        }
        return false;
    }

    fn expect(p: *Parser, c: u8) ParseError!void {
        if (p.consume(c)) return;
        return p.fail(if (p.pos >= p.s.len) error.UnexpectedEof else error.Syntax, p.pos);
    }

    fn enter(p: *Parser) ParseError!void {
        p.depth += 1;
        if (p.depth > p.limits.max_depth) return p.fail(error.NestingTooDeep, p.pos);
    }

    fn leave(p: *Parser) void {
        p.depth -= 1;
    }

    /// After a member: true when the object/array closed, false after ','.
    fn next(p: *Parser, close: u8) ParseError!bool {
        p.ws();
        if (p.consume(close)) {
            p.leave();
            return true;
        }
        try p.expect(',');
        p.ws();
        return false;
    }

    fn startsWith(p: *Parser, lit: []const u8) bool {
        return std.mem.startsWith(u8, p.s[p.pos..], lit);
    }

    fn string(p: *Parser) ParseError![]const u8 {
        try p.expect('"');
        const start = p.pos;
        var decoded: ?std.ArrayList(u8) = null;
        var seg = start;
        while (true) {
            const i = scanString(p.s, p.pos) orelse return p.fail(error.UnexpectedEof, p.s.len);
            const c = p.s[i];
            switch (c) {
                '"' => {
                    p.pos = i + 1;
                    if (decoded) |*d| {
                        try d.appendSlice(p.arena, p.s[seg..i]);
                        return d.items;
                    }
                    return p.s[start..i];
                },
                '\\' => {
                    if (decoded == null) decoded = .empty;
                    try decoded.?.appendSlice(p.arena, p.s[seg..i]);
                    p.pos = i + 1;
                    try p.escape(&decoded.?);
                    seg = p.pos;
                },
                0...0x1f => return p.fail(error.ControlCharacter, i),
                else => {
                    const len = std.unicode.utf8ByteSequenceLength(c) catch return p.fail(error.InvalidUtf8, i);
                    if (i + len > p.s.len) return p.fail(error.InvalidUtf8, i);
                    _ = std.unicode.utf8Decode(p.s[i..][0..len]) catch return p.fail(error.InvalidUtf8, i);
                    p.pos = i + len;
                },
            }
        }
    }

    fn escape(p: *Parser, out: *std.ArrayList(u8)) ParseError!void {
        if (p.pos >= p.s.len) return p.fail(error.UnexpectedEof, p.pos);
        const e = p.s[p.pos];
        p.pos += 1;
        const simple: ?u8 = switch (e) {
            '"' => '"',
            '\\' => '\\',
            '/' => '/',
            'b' => 0x08,
            'f' => 0x0c,
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'u' => null,
            else => return p.fail(error.InvalidEscape, p.pos),
        };
        if (simple) |c| return out.append(p.arena, c);
        const first = try p.hexQuad();
        var cp: u21 = first;
        if (first >= 0xd800 and first <= 0xdbff) {
            if (!p.consume('\\') or !p.consume('u')) return p.fail(error.InvalidUnicodeEscape, p.pos);
            const second = try p.hexQuad();
            if (second < 0xdc00 or second > 0xdfff) return p.fail(error.InvalidUnicodeEscape, p.pos);
            cp = 0x10000 + ((@as(u21, first) - 0xd800) << 10) + (second - 0xdc00);
        } else if (first >= 0xdc00 and first <= 0xdfff) {
            return p.fail(error.InvalidUnicodeEscape, p.pos);
        }
        var buf: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(cp, &buf) catch return p.fail(error.InvalidUnicodeEscape, p.pos);
        try out.appendSlice(p.arena, buf[0..n]);
    }

    fn hexQuad(p: *Parser) ParseError!u16 {
        if (p.pos + 4 > p.s.len) return p.fail(error.UnexpectedEof, p.pos);
        var v: u16 = 0;
        for (p.s[p.pos..][0..4]) |c| {
            const d: u16 = switch (c) {
                '0'...'9' => c - '0',
                'a'...'f' => c - 'a' + 10,
                'A'...'F' => c - 'A' + 10,
                else => return p.fail(error.InvalidUnicodeEscape, p.pos),
            };
            v = (v << 4) | d;
            p.pos += 1;
        }
        return v;
    }

    fn unsigned(p: *Parser) ParseError!u64 {
        const start = p.pos;
        const first = p.peek() orelse return p.fail(error.UnexpectedEof, p.pos);
        if (first < '0' or first > '9') return p.fail(error.InvalidNumber, start);
        p.pos += 1;
        if (first == '0' and p.peek() != null and std.ascii.isDigit(p.peek().?)) return p.fail(error.InvalidNumber, start);
        var v: u64 = first - '0';
        while (p.peek()) |c| {
            if (c < '0' or c > '9') break;
            p.pos += 1;
            v = std.math.mul(u64, v, 10) catch return p.fail(error.InvalidNumber, start);
            v = std.math.add(u64, v, c - '0') catch return p.fail(error.InvalidNumber, start);
        }
        if (p.peek()) |c| if (c == '.' or c == 'e' or c == 'E') return p.fail(error.InvalidNumber, start);
        return v;
    }

    fn boolean(p: *Parser) ParseError!bool {
        if (p.startsWith("true")) {
            p.pos += 4;
            return true;
        }
        if (p.startsWith("false")) {
            p.pos += 5;
            return false;
        }
        return p.fail(error.Syntax, p.pos);
    }

    fn null_(p: *Parser) ParseError!void {
        if (!p.startsWith("null")) return p.fail(error.Syntax, p.pos);
        p.pos += 4;
    }

    fn skipValue(p: *Parser) ParseError!void {
        p.ws();
        const c = p.peek() orelse return p.fail(error.UnexpectedEof, p.pos);
        switch (c) {
            '"' => _ = try p.string(),
            '{' => {
                p.pos += 1;
                try p.enter();
                p.ws();
                if (p.consume('}')) return p.leave();
                while (true) {
                    _ = try p.string();
                    p.ws();
                    try p.expect(':');
                    try p.skipValue();
                    if (try p.next('}')) return;
                }
            },
            '[' => {
                p.pos += 1;
                try p.enter();
                p.ws();
                if (p.consume(']')) return p.leave();
                while (true) {
                    try p.skipValue();
                    if (try p.next(']')) return;
                }
            },
            't', 'f' => _ = try p.boolean(),
            'n' => try p.null_(),
            '-', '0'...'9' => try p.skipNumber(),
            else => return p.fail(error.Syntax, p.pos),
        }
    }

    fn skipNumber(p: *Parser) ParseError!void {
        const start = p.pos;
        _ = p.consume('-');
        const d = p.peek() orelse return p.fail(error.InvalidNumber, start);
        p.pos += 1;
        if (d == '0') {
            if (p.peek() != null and std.ascii.isDigit(p.peek().?)) return p.fail(error.InvalidNumber, start);
        } else if (d >= '1' and d <= '9') {
            while (p.peek() != null and std.ascii.isDigit(p.peek().?)) p.pos += 1;
        } else return p.fail(error.InvalidNumber, start);
        if (p.consume('.')) {
            if (p.peek() == null or !std.ascii.isDigit(p.peek().?)) return p.fail(error.InvalidNumber, start);
            while (p.peek() != null and std.ascii.isDigit(p.peek().?)) p.pos += 1;
        }
        if (p.peek()) |e| if (e == 'e' or e == 'E') {
            p.pos += 1;
            if (p.peek()) |sign| if (sign == '+' or sign == '-') {
                p.pos += 1;
            };
            if (p.peek() == null or !std.ascii.isDigit(p.peek().?)) return p.fail(error.InvalidNumber, start);
            while (p.peek() != null and std.ascii.isDigit(p.peek().?)) p.pos += 1;
        };
    }

    fn key(p: *Parser) ParseError![]const u8 {
        const k = try p.string();
        p.ws();
        try p.expect(':');
        p.ws();
        return k;
    }

    fn path(p: *Parser) ParseError!Path {
        try p.expect('[');
        try p.enter();
        p.ws();
        if (p.consume(']')) {
            p.leave();
            return &.{};
        }
        const mark = p.path_scratch.items.len;
        defer p.path_scratch.shrinkRetainingCapacity(mark);
        while (true) {
            try p.path_scratch.append(p.arena, try p.string());
            if (p.path_scratch.items.len - mark > p.limits.max_path_components) return p.fail(error.PathTooLong, p.pos);
            if (try p.next(']')) break;
        }
        return p.bump.dupe([]const u8, p.path_scratch.items[mark..]);
    }

    fn attrs(p: *Parser) ParseError![]Attr {
        try p.expect('{');
        try p.enter();
        p.ws();
        if (p.consume('}')) {
            p.leave();
            return &.{};
        }
        const mark = p.attr_scratch.items.len;
        defer p.attr_scratch.shrinkRetainingCapacity(mark);
        while (true) {
            const offset = p.pos;
            const name = try p.key();
            const c = p.peek() orelse return p.fail(error.UnexpectedEof, p.pos);
            const value: Value = switch (c) {
                '"' => .{ .string = try p.string() },
                't', 'f' => .{ .boolean = try p.boolean() },
                '0'...'9' => .{ .integer = try p.unsigned() },
                else => return p.fail(error.UnsupportedInputAttributeType, p.pos),
            };
            try p.attr_scratch.append(p.arena, .{ .offset = offset, .item = .{ .name = name, .value = value } });
            if (try p.next('}')) break;
        }
        const items = p.attr_scratch.items[mark..];
        const n = sortDedup(Attr, items, attrName);
        const out = try p.bump.alloc(Attr, n);
        for (items[0..n], out) |k, *o| o.* = k.item;
        return out;
    }

    fn inputs(p: *Parser) ParseError![]WireInput {
        try p.expect('{');
        try p.enter();
        p.ws();
        if (p.consume('}')) {
            p.leave();
            return &.{};
        }
        const mark = p.input_scratch.items.len;
        defer p.input_scratch.shrinkRetainingCapacity(mark);
        while (true) {
            const offset = p.pos;
            const name = try p.key();
            const edge: WireEdge = if (p.peek() == '[') .{ .follows = try p.path() } else .{ .node = try p.string() };
            try p.input_scratch.append(p.arena, .{ .offset = offset, .item = .{ .offset = offset, .name = name, .edge = edge } });
            if (try p.next('}')) break;
        }
        const items = p.input_scratch.items[mark..];
        const n = sortDedup(WireInput, items, inputName);
        const out = try p.bump.alloc(WireInput, n);
        for (items[0..n], out) |k, *o| o.* = k.item;
        return out;
    }

    fn node(p: *Parser, offset: usize, k: []const u8) ParseError!WireNode {
        try p.expect('{');
        try p.enter();
        var n: WireNode = .{ .offset = offset, .key = k };
        p.ws();
        if (p.consume('}')) {
            p.leave();
            return n;
        }
        while (true) {
            const field = try p.key();
            if (eq(field, "inputs")) {
                n.inputs = try p.inputs();
            } else if (eq(field, "original")) {
                n.original = try p.attrs();
            } else if (eq(field, "locked")) {
                n.locked = try p.attrs();
            } else if (eq(field, "info")) {
                n.info = try p.attrs();
            } else if (eq(field, "flake")) {
                n.is_flake = try p.boolean();
            } else if (eq(field, "parent")) {
                if (p.startsWith("null")) {
                    try p.null_();
                    n.parent = null;
                } else n.parent = try p.path();
            } else try p.skipValue();
            if (try p.next('}')) return n;
        }
    }

    fn nodes(p: *Parser) ParseError![]WireNode {
        try p.expect('{');
        try p.enter();
        var list: std.ArrayList(Keyed(WireNode)) = .empty;
        defer list.deinit(p.arena);
        p.ws();
        if (p.consume('}')) {
            p.leave();
        } else while (true) {
            const offset = p.pos;
            const k = try p.key();
            try list.append(p.arena, .{ .offset = offset, .item = try p.node(offset, k) });
            if (try p.next('}')) break;
        }
        const n = sortDedup(WireNode, list.items, nodeKey);
        if (n > p.limits.max_nodes) return p.fail(error.TooManyNodes, p.pos);
        const out = try p.bump.alloc(WireNode, n);
        for (list.items[0..n], out) |k, *o| o.* = k.item;
        return out;
    }
};

fn eq(a: []const u8, comptime b: []const u8) bool {
    return a.len == b.len and std.mem.eql(u8, a, b);
}

/// Overlays `newer` onto `older` (both sorted by name); `newer` wins.
fn overlay(arena: Allocator, older: []const Attr, newer: []const Attr) Allocator.Error![]const Attr {
    var out: std.ArrayList(Attr) = try .initCapacity(arena, older.len + newer.len);
    var i: usize = 0;
    var j: usize = 0;
    while (i < older.len and j < newer.len) {
        switch (std.mem.order(u8, older[i].name, newer[j].name)) {
            .lt => {
                out.appendAssumeCapacity(older[i]);
                i += 1;
            },
            .eq => {
                out.appendAssumeCapacity(newer[j]);
                i += 1;
                j += 1;
            },
            .gt => {
                out.appendAssumeCapacity(newer[j]);
                j += 1;
            },
        }
    }
    out.appendSliceAssumeCapacity(older[i..]);
    out.appendSliceAssumeCapacity(newer[j..]);
    return out.items;
}

fn findNode(nodes: []const WireNode, k: []const u8) ?usize {
    var lo: usize = 0;
    var hi: usize = nodes.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, nodes[mid].key, k)) {
            .eq => return mid,
            .lt => lo = mid + 1,
            .gt => hi = mid,
        }
    }
    return null;
}

/// A parsed lock file and the memory backing it. Unescaped strings borrow
/// from the input, which must outlive the document.
pub const Document = struct {
    lock: LockFile,
    bump: Bump,

    pub fn deinit(self: *Document) void {
        self.bump.deinit();
        self.* = undefined;
    }
};

/// Parses a lock file. All allocations come from one bump allocator owned
/// by the returned document; a typical file needs a single malloc.
pub fn parse(gpa: Allocator, bytes: []const u8, limits: Limits, diag: ?*Diagnostic) ParseError!Document {
    if (bytes.len > limits.max_bytes) return error.InputTooLarge;
    var bump = try Bump.init(gpa, bytes.len * 2 + 4096);
    errdefer bump.deinit();
    var p: Parser = .{ .s = bytes, .limits = limits, .bump = &bump, .arena = bump.allocator(), .diag = diag };

    var version: ?u64 = null;
    var root_key: ?[]const u8 = null;
    var wire: ?[]WireNode = null;
    p.ws();
    try p.expect('{');
    try p.enter();
    p.ws();
    if (p.consume('}')) {
        p.leave();
    } else while (true) {
        const k = try p.key();
        if (eq(k, "version")) {
            version = try p.unsigned();
        } else if (eq(k, "root")) {
            root_key = try p.string();
        } else if (eq(k, "nodes")) {
            wire = try p.nodes();
        } else try p.skipValue();
        if (try p.next('}')) break;
    }
    const v = version orelse return p.fail(error.MissingField, p.pos);
    if (v < 5 or v > 7) return p.fail(error.UnsupportedVersion, p.pos);
    const rk = root_key orelse return p.fail(error.MissingField, p.pos);
    const wn = wire orelse return p.fail(error.MissingField, p.pos);
    p.ws();
    if (p.pos != bytes.len) return p.fail(error.TrailingCharacters, p.pos);
    const lock = try build(&p, @intCast(v), rk, wn);
    return .{ .lock = lock, .bump = bump };
}

fn build(p: *Parser, version: u8, root_key: []const u8, wire: []WireNode) ParseError!LockFile {
    const gpa = p.arena;
    const root_old = findNode(wire, root_key) orelse return p.fail(error.MissingNode, 0);

    const new_id = try gpa.alloc(u32, wire.len);
    defer gpa.free(new_id);
    const unseen = std.math.maxInt(u32);
    @memset(new_id, unseen);
    var stack: std.ArrayList(u32) = .empty;
    defer stack.deinit(gpa);
    try stack.append(gpa, @intCast(root_old));
    var reachable: usize = 0;
    // Mark reachability first (0 = seen), assign dense ids afterwards so the
    // arena order matches source key order, like the reference.
    while (stack.pop()) |idx| {
        if (new_id[idx] != unseen) continue;
        new_id[idx] = 0;
        reachable += 1;
        for (wire[idx].inputs) |*in| switch (in.edge) {
            .node => |target| {
                const t = findNode(wire, target) orelse return p.fail(error.MissingNode, in.offset);
                if (t == root_old) return p.fail(error.CycleToRoot, in.offset);
                in.target = @intCast(t);
                try stack.append(gpa, @intCast(t));
            },
            .follows => {},
        };
    }
    if (reachable > p.limits.max_nodes or reachable > std.math.maxInt(u32)) return p.fail(error.TooManyNodes, 0);
    var next_id: u32 = 1;
    for (new_id, 0..) |*id, old| {
        if (id.* == unseen) continue;
        if (old == root_old) {
            id.* = root_id;
        } else {
            id.* = next_id;
            next_id += 1;
        }
    }

    const nodes = try p.bump.alloc(Node, reachable);
    for (wire, 0..) |*w, old| {
        const id = new_id[old];
        if (id == unseen) continue;
        const ins = try p.bump.alloc(Input, w.inputs.len);
        for (w.inputs, ins) |in, *o| o.* = .{
            .name = in.name,
            .edge = switch (in.edge) {
                .node => .{ .node = new_id[in.target] },
                .follows => |f| .{ .follows = f },
            },
        };
        var locked: ?Locked = null;
        if (old != root_old) {
            const l = w.locked orelse return p.fail(error.MissingField, w.offset);
            const original = w.original orelse return p.fail(error.MissingField, w.offset);
            const merged: []const Attr = if (w.info) |info| try overlay(p.arena, l, info) else l;
            locked = .{ .original = original, .locked = merged, .is_flake = w.is_flake, .parent = w.parent };
        }
        nodes[id] = .{ .key = w.key, .inputs = ins, .locked = locked };
    }
    return .{ .source_version = version, .nodes = nodes };
}

// ── follows resolution ──

const EdgeKey = struct { node: u32, input: u32 };

const Resolver = struct {
    gpa: Allocator,
    lock: *const LockFile,
    /// Resolved follows targets, keyed by the path slice's address.
    cache: std.AutoHashMapUnmanaged(usize, ?u32) = .empty,
    active: std.AutoHashMapUnmanaged(EdgeKey, void) = .empty,

    const Step = union(enum) { component: []const u8, finish: struct { edge: EdgeKey, target: usize } };

    fn init(gpa: Allocator, lock: *const LockFile) Resolver {
        return .{ .gpa = gpa, .lock = lock };
    }

    fn deinit(r: *Resolver) void {
        r.cache.deinit(r.gpa);
        r.active.deinit(r.gpa);
    }

    fn resolve(r: *Resolver, path: Path, use_cache: bool) ValidationError!?u32 {
        var steps: std.ArrayList(Step) = .empty;
        defer steps.deinit(r.gpa);
        var i = path.len;
        while (i > 0) {
            i -= 1;
            try steps.append(r.gpa, .{ .component = path[i] });
        }
        var current: u32 = root_id;
        r.active.clearRetainingCapacity();
        while (steps.pop()) |step| switch (step) {
            .component => |name| {
                const node = &r.lock.nodes[current];
                const idx = findSorted(Input, node.inputs, name) orelse return null;
                switch (node.inputs[idx].edge) {
                    .node => |child| current = child,
                    .follows => |target| {
                        const addr = @intFromPtr(target.ptr);
                        if (use_cache) if (r.cache.get(addr)) |cached| {
                            current = cached orelse return null;
                            continue;
                        };
                        const edge: EdgeKey = .{ .node = current, .input = @intCast(idx) };
                        const gop = try r.active.getOrPut(r.gpa, edge);
                        if (gop.found_existing) return error.FollowsCycle;
                        try steps.append(r.gpa, .{ .finish = .{ .edge = edge, .target = addr } });
                        var j = target.len;
                        while (j > 0) {
                            j -= 1;
                            try steps.append(r.gpa, .{ .component = target[j] });
                        }
                        current = root_id;
                    },
                }
            },
            .finish => |f| {
                _ = r.active.remove(f.edge);
                if (use_cache) try r.cache.put(r.gpa, f.target, current);
            },
        };
        return current;
    }
};

// ── Canonical writer ──

const Writer = struct {
    gpa: Allocator,
    out: *std.ArrayList(u8),
    lock: *const LockFile,

    // Capacity is reserved per node (see `reserveNode`), so every write
    // below is an unchecked copy.
    inline fn raw(w: *Writer, s: []const u8) void {
        w.out.appendSliceAssumeCapacity(s);
    }

    inline fn byte(w: *Writer, c: u8) void {
        w.out.appendAssumeCapacity(c);
    }

    inline fn indent(w: *Writer, level: usize) void {
        w.out.appendNTimesAssumeCapacity(' ', 2 * level);
    }

    fn str(w: *Writer, s: []const u8) void {
        const hex = "0123456789abcdef";
        w.byte('"');
        var start: usize = 0;
        while (true) {
            const i = scanEscape(s, start);
            w.raw(s[start..i]);
            if (i == s.len) break;
            const c = s[i];
            switch (c) {
                '"' => w.raw("\\\""),
                '\\' => w.raw("\\\\"),
                0x08 => w.raw("\\b"),
                0x0c => w.raw("\\f"),
                '\n' => w.raw("\\n"),
                '\r' => w.raw("\\r"),
                '\t' => w.raw("\\t"),
                else => w.raw(&.{ '\\', 'u', '0', '0', hex[c >> 4], hex[c & 15] }),
            }
            start = i + 1;
        }
        w.byte('"');
    }

    fn int(w: *Writer, value: u64) void {
        var buf: [20]u8 = undefined;
        var i: usize = buf.len;
        var v = value;
        while (true) {
            i -= 1;
            buf[i] = @intCast('0' + v % 10);
            v /= 10;
            if (v == 0) break;
        }
        w.raw(buf[i..]);
    }

    fn field(w: *Writer, level: usize, comptime name: []const u8) void {
        w.indent(level);
        w.raw("\"" ++ name ++ "\": ");
    }

    fn sep(w: *Writer, written: usize, total: usize) void {
        if (written != total) w.byte(',');
        w.byte('\n');
    }

    fn path(w: *Writer, p: Path, level: usize) void {
        if (p.len == 0) return w.raw("[]");
        w.raw("[\n");
        for (p, 0..) |c, i| {
            w.indent(level + 1);
            w.str(c);
            if (i + 1 != p.len) w.byte(',');
            w.byte('\n');
        }
        w.indent(level);
        w.byte(']');
    }

    fn attrs(w: *Writer, a: []const Attr, level: usize) void {
        var len: usize = 0;
        for (a) |x| len += @intFromBool(!eq(x.name, "__final"));
        if (len == 0) return w.raw("{}");
        w.raw("{\n");
        var i: usize = 0;
        for (a) |x| {
            if (eq(x.name, "__final")) continue;
            w.indent(level + 1);
            w.str(x.name);
            w.raw(": ");
            switch (x.value) {
                .string => |s| w.str(s),
                .integer => |n| w.int(n),
                .boolean => |b| w.raw(if (b) "true" else "false"),
            }
            i += 1;
            if (i != len) w.byte(',');
            w.byte('\n');
        }
        w.indent(level);
        w.byte('}');
    }

    /// Upper bound on the bytes `node` writes: escaping expands a byte to at
    /// most 6, and a line has at most 2 * (level + 3) indentation plus a few
    /// bytes of punctuation.
    fn reserveNode(w: *Writer, n: *const Node, nm: []const []const u8, name: []const u8) Allocator.Error!void {
        const line = 2 * 6 + 16;
        var bound: usize = 6 * name.len + 4 * line;
        for (n.inputs) |in| {
            bound += 6 * in.name.len + line;
            switch (in.edge) {
                .node => |id| bound += 6 * nm[id].len,
                .follows => |p| for (p) |c| {
                    bound += 6 * c.len + line;
                },
            }
        }
        if (n.locked) |l| {
            for ([_][]const Attr{ l.locked, l.original }) |a| for (a) |x| {
                bound += 6 * x.name.len + line + switch (x.value) {
                    .string => |s| 6 * s.len,
                    else => 20,
                };
            };
            if (l.parent) |p| for (p) |c| {
                bound += 6 * c.len + line;
            };
        }
        try w.out.ensureUnusedCapacity(w.gpa, bound);
    }

    fn node(w: *Writer, n: *const Node, nm: []const []const u8, level: usize) void {
        const has_flake = if (n.locked) |l| !l.is_flake else false;
        const has_inputs = n.inputs.len > 0;
        const has_parent = if (n.locked) |l| l.parent != null else false;
        const total = @as(usize, @intFromBool(has_flake)) + @intFromBool(has_inputs) + @as(usize, if (n.locked != null) 2 else 0) + @intFromBool(has_parent);
        if (total == 0) return w.raw("{}");
        w.raw("{\n");
        var written: usize = 0;
        if (has_flake) {
            w.field(level + 1, "flake");
            w.raw("false");
            written += 1;
            w.sep(written, total);
        }
        if (has_inputs) {
            w.field(level + 1, "inputs");
            w.raw("{\n");
            for (n.inputs, 0..) |in, i| {
                w.indent(level + 2);
                w.str(in.name);
                w.raw(": ");
                switch (in.edge) {
                    .node => |id| w.str(nm[id]),
                    .follows => |p| w.path(p, level + 2),
                }
                if (i + 1 != n.inputs.len) w.byte(',');
                w.byte('\n');
            }
            w.indent(level + 1);
            w.byte('}');
            written += 1;
            w.sep(written, total);
        }
        if (n.locked) |l| {
            w.field(level + 1, "locked");
            w.attrs(l.locked, level + 1);
            written += 1;
            w.sep(written, total);
            w.field(level + 1, "original");
            w.attrs(l.original, level + 1);
            written += 1;
            w.sep(written, total);
            if (l.parent) |p| {
                w.field(level + 1, "parent");
                w.path(p, level + 1);
                written += 1;
                w.sep(written, total);
            }
        }
        w.indent(level);
        w.byte('}');
    }

    /// Nix's naming: depth-first from the root, each node named after the
    /// first input that reaches it, with `_2`, `_3`, ... on collisions.
    fn names(w: *Writer, tmp: Allocator) Allocator.Error![]const []const u8 {
        const lock = w.lock;
        const out = try tmp.alloc([]const u8, lock.nodes.len);
        const named = try tmp.alloc(bool, lock.nodes.len);
        @memset(named, false);
        out[root_id] = "root";
        named[root_id] = true;
        // Small graphs check collisions by scanning assigned names; a hash
        // set only pays off beyond a few dozen nodes.
        const small = lock.nodes.len <= 48;
        var assigned: std.ArrayList([]const u8) = .empty;
        var used: std.StringHashMapUnmanaged(void) = .empty;
        if (small) {
            try assigned.ensureTotalCapacity(tmp, lock.nodes.len);
            assigned.appendAssumeCapacity("root");
        } else {
            try used.ensureTotalCapacity(tmp, @intCast(lock.nodes.len));
            used.putAssumeCapacity("root", {});
        }
        var suffix: std.StringHashMapUnmanaged(u64) = .empty;
        const Frame = struct { node: u32, next: u32 };
        var stack: std.ArrayList(Frame) = .empty;
        try stack.append(tmp, .{ .node = root_id, .next = 0 });
        while (stack.items.len > 0) {
            const top = &stack.items[stack.items.len - 1];
            const n = &lock.nodes[top.node];
            if (top.next >= n.inputs.len) {
                _ = stack.pop();
                continue;
            }
            const in = n.inputs[top.next];
            top.next += 1;
            const child = switch (in.edge) {
                .node => |c| c,
                .follows => continue,
            };
            if (named[child]) continue;
            const taken = struct {
                fn check(s: bool, a: []const []const u8, u: *const std.StringHashMapUnmanaged(void), name: []const u8) bool {
                    if (!s) return u.contains(name);
                    for (a) |x| if (std.mem.eql(u8, x, name)) return true;
                    return false;
                }
            }.check;
            var name = in.name;
            if (taken(small, assigned.items, &used, name)) {
                const gop = try suffix.getOrPut(tmp, in.name);
                if (!gop.found_existing) gop.value_ptr.* = 2;
                while (true) {
                    const candidate = try tmp.print("{s}_{d}", .{ in.name, gop.value_ptr.* });
                    gop.value_ptr.* += 1;
                    if (!taken(small, assigned.items, &used, candidate)) {
                        name = candidate;
                        break;
                    }
                }
            }
            if (small) assigned.appendAssumeCapacity(name) else try used.put(tmp, name, {});
            out[child] = name;
            named[child] = true;
            try stack.append(tmp, .{ .node = child, .next = 0 });
        }
        return out;
    }

    fn write(w: *Writer) Allocator.Error!void {
        var first: [8192]u8 = undefined;
        var fallback: std.heap.BufferFirstAllocator = .init(&first, w.gpa);
        var bump = try Bump.init(fallback.allocator(), 4096);
        defer bump.deinit();
        const tmp = bump.allocator();
        const nm = try w.names(tmp);
        const order = try bump.alloc(u32, nm.len);
        for (order, 0..) |*o, i| o.* = @intCast(i);
        std.mem.sortUnstable(u32, order, nm, struct {
            fn lessThan(ctx: []const []const u8, a: u32, b: u32) bool {
                return std.mem.lessThan(u8, ctx[a], ctx[b]);
            }
        }.lessThan);
        try w.out.ensureUnusedCapacity(w.gpa, 64);
        w.raw("{\n  \"nodes\": {");
        for (order, 0..) |id, i| {
            const n = &w.lock.nodes[id];
            try w.reserveNode(n, nm, nm[id]);
            w.raw(if (i == 0) "\n" else ",\n");
            w.indent(2);
            w.str(nm[id]);
            w.raw(": ");
            w.node(n, nm, 2);
        }
        try w.out.ensureUnusedCapacity(w.gpa, 64);
        w.raw("\n  },\n  \"root\": \"root\",\n  \"version\": 7\n}\n");
    }
};

// ── Tests ──

const testing = std.testing;

const typical =
    \\{
    \\  "nodes": {
    \\    "nixpkgs": {
    \\      "locked": {
    \\        "lastModified": 1750000000,
    \\        "narHash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    \\        "owner": "NixOS",
    \\        "repo": "nixpkgs",
    \\        "rev": "0123456789abcdef0123456789abcdef01234567",
    \\        "type": "github"
    \\      },
    \\      "original": {
    \\        "owner": "NixOS",
    \\        "ref": "nixos-unstable",
    \\        "repo": "nixpkgs",
    \\        "type": "github"
    \\      }
    \\    },
    \\    "root": {
    \\      "inputs": {
    \\        "nixpkgs": "nixpkgs",
    \\        "tools": "tools"
    \\      }
    \\    },
    \\    "tools": {
    \\      "inputs": {
    \\        "nixpkgs": [
    \\          "nixpkgs"
    \\        ]
    \\      },
    \\      "locked": {
    \\        "lastModified": 1750000001,
    \\        "narHash": "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    \\        "owner": "example",
    \\        "repo": "tools",
    \\        "rev": "89abcdef0123456789abcdef0123456789abcdef",
    \\        "type": "github"
    \\      },
    \\      "original": {
    \\        "owner": "example",
    \\        "repo": "tools",
    \\        "type": "github"
    \\      }
    \\    }
    \\  },
    \\  "root": "root",
    \\  "version": 7
    \\}
    \\
;

test "canonical documents round-trip byte for byte" {
    var doc = try parse(testing.allocator, typical, .{}, null);
    defer doc.deinit();
    try doc.lock.validate(testing.allocator);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try doc.lock.writeNix(testing.allocator, &out);
    try testing.expectEqualStrings(typical, out.items);
    try testing.expectEqual(@as(?u32, doc.lock.nodes[root_id].input("nixpkgs").?.edge.node), try doc.lock.resolve(testing.allocator, &.{ "tools", "nixpkgs" }));
}

test "version 5 info overlay, duplicate keys and renaming" {
    const src =
        \\{"version":5,"root":"r","nodes":{"r":{"inputs":{"a":"x","b":"y"}},
        \\"x":{"locked":{"type":"path","path":"1"},"original":{"type":"path"},"info":{"lastModified":7}},
        \\"y":{"inputs":{"a":"z"},"locked":{"type":"path"},"original":{"type":"path"},"flake":false},
        \\"z":{"locked":{"k":"old","k":"new"},"original":{}}, "unused":{"broken":true}}}
    ;
    var doc = try parse(testing.allocator, src, .{}, null);
    defer doc.deinit();
    try testing.expectEqual(@as(usize, 4), doc.lock.nodes.len);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try doc.lock.writeNix(testing.allocator, &out);
    try testing.expect(std.mem.indexOf(u8, out.items, "\"lastModified\": 7,") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "\"a_2\": {") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "\"k\": \"new\"") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "\"flake\": false,") != null);
    // Re-parsing canonical output is a fixed point.
    var doc2 = try parse(testing.allocator, out.items, .{}, null);
    defer doc2.deinit();
    var again: std.ArrayList(u8) = .empty;
    defer again.deinit(testing.allocator);
    try doc2.lock.writeNix(testing.allocator, &again);
    try testing.expectEqualStrings(out.items, again.items);
}

test "large graphs use the hashed collision path" {
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(testing.allocator);
    try src.appendSlice(testing.allocator, "{\"version\":7,\"root\":\"root\",\"nodes\":{\"root\":{\"inputs\":{");
    for (0..100) |i| try src.print(testing.allocator, "{s}\"d{d}\":\"d{d}\"", .{ if (i == 0) "" else ",", i, i });
    try src.appendSlice(testing.allocator, "}}");
    for (0..100) |i| try src.print(testing.allocator, ",\"d{d}\":{{\"inputs\":{{\"s\":\"s{d}\"}},\"locked\":{{}},\"original\":{{}}}},\"s{d}\":{{\"locked\":{{}},\"original\":{{}}}}", .{ i, i, i });
    try src.appendSlice(testing.allocator, "}}");
    var doc = try parse(testing.allocator, src.items, .{}, null);
    defer doc.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try doc.lock.writeNix(testing.allocator, &out);
    try testing.expect(std.mem.indexOf(u8, out.items, "\"s_100\": {") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "\"s_101\"") == null);
}

test "rejects malformed and adversarial inputs" {
    const a = testing.allocator;
    const cases = .{
        .{ "{\"version\":4,\"root\":\"r\",\"nodes\":{\"r\":{}}}", error.UnsupportedVersion },
        .{ "{\"version\":7,\"root\":\"r\",\"nodes\":{\"r\":{\"inputs\":{\"a\":\"r\"}}}}", error.CycleToRoot },
        .{ "{\"version\":7,\"root\":\"r\",\"nodes\":{\"r\":{\"inputs\":{\"a\":\"q\"}}}}", error.MissingNode },
        .{ "{\"version\":7,\"root\":\"r\",\"nodes\":{\"r\":{}}} x", error.TrailingCharacters },
        .{ "{\"version\":07,\"root\":\"r\",\"nodes\":{}}", error.InvalidNumber },
        .{ "{\"version\":7,\"root\":\"r\\x\",\"nodes\":{}}", error.InvalidEscape },
        .{ "{\"version\":7,\"root\":\"\xff\",\"nodes\":{}}", error.InvalidUtf8 },
        .{ "{\"version\":7,\"root\":\"a\x01\",\"nodes\":{}}", error.ControlCharacter },
        .{ "{\"version\":7,\"root\":\"r\",\"nodes\":{\"r\":{\"inputs\":{\"a\":\"b\"}},\"b\":{\"locked\":{}}}}", error.MissingField },
        .{ "{\"version\":7,\"root\":\"r\",\"nodes\":{\"r\":{\"inputs\":{\"a\":\"b\"}},\"b\":{\"locked\":{\"x\":null},\"original\":{}}}}", error.UnsupportedInputAttributeType },
    };
    inline for (cases) |c| try testing.expectError(c[1], parse(a, c[0], .{}, null));
    try testing.expectError(error.NestingTooDeep, parse(a, "{\"x\":" ++ &@as([300]u8, @splat('[')) ++ &@as([300]u8, @splat(']')) ++ "}", .{}, null));
}

test "follows validation detects cycles and missing targets" {
    var cyc = try parse(testing.allocator,
        \\{"version":7,"root":"r","nodes":{"r":{"inputs":{"a":["b"],"b":["a"]}}}}
    , .{}, null);
    defer cyc.deinit();
    try testing.expectError(error.FollowsCycle, cyc.lock.validate(testing.allocator));
    var missing = try parse(testing.allocator,
        \\{"version":7,"root":"r","nodes":{"r":{"inputs":{"a":["nope"]}}}}
    , .{}, null);
    defer missing.deinit();
    try testing.expectError(error.MissingFollowsTarget, missing.lock.validate(testing.allocator));
}

test "unicode escapes and string escaping on output" {
    var doc = try parse(testing.allocator,
        \\{"version":7,"root":"r","nodes":{"r":{"inputs":{"a":"b"}},"b":{"locked":{"s":"\u00e9\ud83d\ude00 \"q\" \t é"},"original":{}}}}
    , .{}, null);
    defer doc.deinit();
    const s = Locked.get(doc.lock.nodes[1].locked.?.locked, "s").?.string;
    try testing.expectEqualStrings("é😀 \"q\" \t é", s);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try doc.lock.writeNix(testing.allocator, &out);
    try testing.expect(std.mem.indexOf(u8, out.items, "\"é😀 \\\"q\\\" \\t é\"") != null);
}

test "vector scanners agree with scalar definitions" {
    var buf: [80]u8 = @splat('a');
    for (0..buf.len) |i| {
        for ([_]u8{ '"', '\\', 0x01, 0x80, 0xff }) |c| {
            buf[i] = c;
            try testing.expectEqual(@as(?usize, i), scanString(&buf, 0));
            if (c < 0x80) try testing.expectEqual(i, scanEscape(&buf, 0));
            buf[i] = 'a';
        }
        var sp: [80]u8 = @splat(' ');
        sp[i] = 'x';
        try testing.expectEqual(i, skipSpace(&sp, 0));
    }
}

test {
    _ = @import("bump.zig");
}
