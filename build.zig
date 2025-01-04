const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const clone_exe = clone_blk: {
        const exe = b.addExecutable(.{
            .name = "clone",
            .root_source_file = b.path("src/clone.zig"),
            .target = target,
            .optimize = optimize,
        });
        break :clone_blk exe;
    };
    b.installArtifact(clone_exe);

    const clone_exe_run = b.addRunArtifact(clone_exe);
    clone_exe_run.has_side_effects = true;
    b.step("run-clone", "Run clone").dependOn(&clone_exe_run.step);
}
