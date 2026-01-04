const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const profile = b.option(bool, "profile", "Enable profiling-friendly build settings") orelse false;

    const mod = b.addModule("crucible", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });
    if (profile) {
        mod.omit_frame_pointer = false;
        mod.strip = false;
    }

    const exe = b.addExecutable(.{
        .name = "crucible",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "crucible", .module = mod },
            },
        }),
    });
    if (profile) {
        exe.root_module.omit_frame_pointer = false;
        exe.root_module.strip = false;
    }

    const libxev_dep = b.dependency("libxev", .{
        .target = target,
        .optimize = optimize,
    });
    const xev_mod = libxev_dep.module("xev");
    mod.addImport("xev", xev_mod);

    const lz4_dep = b.dependency("lz4", .{
        .target = target,
        .optimize = optimize,
    });
    const lz4_module = lz4_dep.module("lz4");
    mod.addImport("lz4", lz4_module);

    b.installArtifact(exe);

    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const example_exe = b.addExecutable(.{
        .name = "cache-demo",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/cache_demo.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "crucible", .module = mod },
            },
        }),
    });
    if (profile) {
        example_exe.root_module.omit_frame_pointer = false;
        example_exe.root_module.strip = false;
    }

    const example_step = b.step("example", "Run cache demo example");
    const example_run = b.addRunArtifact(example_exe);
    example_step.dependOn(&example_run.step);
    if (b.args) |args| example_run.addArgs(args);

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });
    if (profile) {
        mod_tests.root_module.omit_frame_pointer = false;
        mod_tests.root_module.strip = false;
    }
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });
    if (profile) {
        exe_tests.root_module.omit_frame_pointer = false;
        exe_tests.root_module.strip = false;
    }
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
