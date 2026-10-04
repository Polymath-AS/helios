const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("nix-store-path", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        // Zig 0.17 keeps frame pointers in ReleaseFast, which 0.16 dropped;
        // they cost up to 10% in the hot paths here.
        .omit_frame_pointer = if (optimize == .fast) true else null,
    });
    mod.addImport("nix-base32", b.dependency("nix_base32", .{ .target = target, .optimize = optimize }).module("nix-base32"));

    const tests = b.addTest(.{ .root_module = mod });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(tests).step);
}
