//! libhelios: the C ABI over the pkg/* Nix packages, linked into the Rust
//! server and CLI as a static library.

const std = @import("std");

const packages = [_][]const u8{ "nix-base32", "nix-store-path", "nix-archive", "nix-narinfo" };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        // Zig 0.17 keeps frame pointers in ReleaseFast, which 0.16 dropped;
        // they cost up to 10% in the hot paths here.
        .omit_frame_pointer = if (optimize == .fast) true else null,
        .link_libc = true,
        // Linked into Rust binaries, which are PIE.
        .pic = true,
    });
    inline for (packages) |name| {
        const dep = b.dependency(comptime underscored(name), .{ .target = target, .optimize = optimize });
        mod.addImport(name, dep.module(name));
    }

    const lib = b.addLibrary(.{ .name = "helios", .linkage = .static, .root_module = mod });
    lib.bundle_compiler_rt = false;
    lib.installHeader(b.path("include/helios.h"), "helios.h");
    b.installArtifact(lib);
}

fn underscored(comptime name: []const u8) []const u8 {
    comptime var out: [name.len]u8 = undefined;
    for (name, 0..) |c, i| out[i] = if (c == '-') '_' else c;
    const final = out;
    return &final;
}
