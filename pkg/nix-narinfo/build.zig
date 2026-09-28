const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("nix-narinfo", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addImport("nix-base32", b.dependency("nix_base32", .{ .target = target, .optimize = optimize }).module("nix-base32"));
    mod.addImport("nix-store-path", b.dependency("nix_store_path", .{ .target = target, .optimize = optimize }).module("nix-store-path"));

    const tests = b.addTest(.{ .root_module = mod });
    b.step("test", "Run unit tests").dependOn(&b.addRunArtifact(tests).step);
}
