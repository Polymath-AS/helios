const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("nix-archive", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.link_libc = true;

    const tests = b.addTest(.{ .root_module = mod });
    tests.root_module.linkSystemLibrary("zstd", .{});
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(tests).step);
}
