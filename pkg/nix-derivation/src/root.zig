//! Parser for Nix store derivations (`.drv`, ATerm syntax):
//!
//!   Derive([outputs],[input drvs],[input srcs],"system","builder",[args],[env])
//!
//! Strings without escapes are returned as slices of the input (zero-copy);
//! escaped strings are unescaped into the arena. The string scanner looks
//! for '"' or '\\' 32 bytes at a time.

const std = @import("std");

pub const Error = error{ Syntax, OutOfMemory };

pub const Output = struct {
    name: []const u8,
    path: []const u8,
    hash_algo: []const u8,
    hash: []const u8,
};

pub const InputDrv = struct {
    path: []const u8,
    outputs: []const []const u8,
};

pub const EnvVar = struct {
    name: []const u8,
    value: []const u8,
};

pub const Derivation = struct {
    outputs: []const Output,
    input_drvs: []const InputDrv,
    input_srcs: []const []const u8,
    platform: []const u8,
    builder: []const u8,
    args: []const []const u8,
    env: []const EnvVar,
};

const lanes = 32;
const V = @Vector(lanes, u8);
const Mask = std.meta.Int(.unsigned, lanes);

/// Index of the first '"' or '\\' at or after `start`.
pub fn indexOfQuoteOrEscape(s: []const u8, start: usize) ?usize {
    var i = start;
    const quote: V = @splat('"');
    const backslash: V = @splat('\\');
    while (i + lanes <= s.len) : (i += lanes) {
        const v: V = s[i..][0..lanes].*;
        const m: Mask = @as(Mask, @bitCast(v == quote)) | @as(Mask, @bitCast(v == backslash));
        if (m != 0) return i + @ctz(m);
    }
    while (i < s.len) : (i += 1) if (s[i] == '"' or s[i] == '\\') return i;
    return null;
}

const Parser = struct {
    s: []const u8,
    pos: usize = 0,
    arena: std.mem.Allocator,

    fn expect(p: *Parser, comptime lit: []const u8) Error!void {
        if (!std.mem.startsWith(u8, p.s[p.pos..], lit)) return error.Syntax;
        p.pos += lit.len;
    }

    fn peek(p: *Parser) Error!u8 {
        if (p.pos >= p.s.len) return error.Syntax;
        return p.s[p.pos];
    }

    fn string(p: *Parser) Error![]const u8 {
        try p.expect("\"");
        const start = p.pos;
        var i = indexOfQuoteOrEscape(p.s, start) orelse return error.Syntax;
        if (p.s[i] == '"') {
            p.pos = i + 1;
            return p.s[start..i];
        }
        // Escaped: copy the clean prefix, then unescape the rest.
        var out: std.ArrayList(u8) = .empty;
        try out.appendSlice(p.arena, p.s[start..i]);
        while (true) {
            if (p.s[i] == '"') {
                p.pos = i + 1;
                return out.toOwnedSlice(p.arena);
            }
            // Backslash escape.
            if (i + 1 >= p.s.len) return error.Syntax;
            try out.append(p.arena, switch (p.s[i + 1]) {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                else => |c| c,
            });
            const next = indexOfQuoteOrEscape(p.s, i + 2) orelse return error.Syntax;
            try out.appendSlice(p.arena, p.s[i + 2 .. next]);
            i = next;
        }
    }

    fn list(p: *Parser, comptime T: type, comptime item: fn (*Parser) Error!T) Error![]const T {
        try p.expect("[");
        var items: std.ArrayList(T) = .empty;
        if (try p.peek() == ']') {
            p.pos += 1;
            return &.{};
        }
        while (true) {
            try items.append(p.arena, try item(p));
            switch (try p.peek()) {
                ',' => p.pos += 1,
                ']' => {
                    p.pos += 1;
                    return items.toOwnedSlice(p.arena);
                },
                else => return error.Syntax,
            }
        }
    }

    fn output(p: *Parser) Error!Output {
        try p.expect("(");
        const name = try p.string();
        try p.expect(",");
        const path = try p.string();
        try p.expect(",");
        const algo = try p.string();
        try p.expect(",");
        const hash = try p.string();
        try p.expect(")");
        return .{ .name = name, .path = path, .hash_algo = algo, .hash = hash };
    }

    fn inputDrv(p: *Parser) Error!InputDrv {
        try p.expect("(");
        const path = try p.string();
        try p.expect(",");
        const outs = try p.list([]const u8, string);
        try p.expect(")");
        return .{ .path = path, .outputs = outs };
    }

    fn envVar(p: *Parser) Error!EnvVar {
        try p.expect("(");
        const name = try p.string();
        try p.expect(",");
        const value = try p.string();
        try p.expect(")");
        return .{ .name = name, .value = value };
    }
};

/// Parses a derivation. All allocations go to `arena`; free it as a whole.
pub fn parse(arena: std.mem.Allocator, text: []const u8) Error!Derivation {
    var p: Parser = .{ .s = text, .arena = arena };
    try p.expect("Derive(");
    const outputs = try p.list(Output, Parser.output);
    try p.expect(",");
    const input_drvs = try p.list(InputDrv, Parser.inputDrv);
    try p.expect(",");
    const input_srcs = try p.list([]const u8, Parser.string);
    try p.expect(",");
    const platform = try p.string();
    try p.expect(",");
    const builder = try p.string();
    try p.expect(",");
    const args = try p.list([]const u8, Parser.string);
    try p.expect(",");
    const env = try p.list(EnvVar, Parser.envVar);
    try p.expect(")");
    if (p.pos != text.len) return error.Syntax;
    return .{
        .outputs = outputs,
        .input_drvs = input_drvs,
        .input_srcs = input_srcs,
        .platform = platform,
        .builder = builder,
        .args = args,
        .env = env,
    };
}

test "parses a derivation with escapes" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const text =
        \\Derive([("out","/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello","","")],[("/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-bash.drv",["out"])],["/nix/store/cccccccccccccccccccccccccccccccc-builder.sh"],"x86_64-linux","/bin/sh",["-e","/builder.sh"],[("buildPhase","echo \"hi\"\nmake -j\\$N"),("name","hello")])
    ;
    const d = try parse(arena.allocator(), text);
    try std.testing.expectEqual(@as(usize, 1), d.outputs.len);
    try std.testing.expectEqualStrings("out", d.input_drvs[0].outputs[0]);
    try std.testing.expectEqualStrings("echo \"hi\"\nmake -j\\$N", d.env[0].value);
    try std.testing.expectEqualStrings("x86_64-linux", d.platform);
    try std.testing.expectError(error.Syntax, parse(arena.allocator(), "Derive([],"));
}

test "vector quote search matches scalar" {
    var buf = [_]u8{'x'} ** 100;
    for (0..buf.len) |i| {
        for ([_]u8{ '"', '\\' }) |c| {
            buf[i] = c;
            for (0..i + 1) |start| try std.testing.expectEqual(@as(?usize, i), indexOfQuoteOrEscape(&buf, start));
            buf[i] = 'x';
        }
    }
}
