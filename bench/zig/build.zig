const std = @import("std");

const packages = [_][2][]const u8{
    .{ "nix-base32", "nix_base32" },
    .{ "nix-store-path", "nix_store_path" },
    .{ "nix-narinfo", "nix_narinfo" },
    .{ "nix-derivation", "nix_derivation" },
    .{ "nix-archive", "nix_archive" },
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        // Zig 0.17 keeps frame pointers in ReleaseFast, which 0.16 dropped;
        // they cost up to 10% in the hot paths here.
        .omit_frame_pointer = if (optimize == .fast) true else null,
        .link_libc = true,
    });
    inline for (packages) |p| mod.addImport(p[0], b.dependency(p[1], .{ .target = target, .optimize = optimize }).module(p[0]));
    mod.linkSystemLibrary("zstd", .{});
    b.installArtifact(b.addExecutable(.{ .name = "bench", .root_module = mod }));

    const fl_mod = b.createModule(.{
        .root_source_file = b.path("src/flake_lock.zig"),
        .target = target,
        .optimize = optimize,
        // Zig 0.17 keeps frame pointers in ReleaseFast, which 0.16 dropped;
        // they cost up to 10% in the hot paths here.
        .omit_frame_pointer = if (optimize == .fast) true else null,
        .link_libc = true,
    });
    fl_mod.addImport("nix-flake-lock", b.dependency("nix_flake_lock", .{ .target = target, .optimize = optimize }).module("nix-flake-lock"));
    b.installArtifact(b.addExecutable(.{ .name = "flake-lock", .root_module = fl_mod }));
}
