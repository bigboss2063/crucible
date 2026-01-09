const std = @import("std");

fn applyProfileSettings(module: *std.Build.Module, enabled: bool) void {
    if (!enabled) return;
    module.omit_frame_pointer = false;
    module.strip = false;
}

fn configureCompile(compile: *std.Build.Step.Compile, profile_enabled: bool, link_libc: bool) void {
    if (link_libc) {
        compile.linkLibC();
    }
    applyProfileSettings(compile.root_module, profile_enabled);
}

fn configureRun(run: *std.Build.Step.Run) void {
    run.stdio = .inherit;
    run.has_side_effects = true;
}

fn addKcovRun(
    b: *std.Build,
    kcov_cmd: []const u8,
    include_path: []const u8,
    exclude_pattern: []const u8,
    output_dir: []const u8,
    artifact: *std.Build.Step.Compile,
    mkdir_step: *std.Build.Step.Run,
) *std.Build.Step.Run {
    const kcov_run = b.addSystemCommand(&.{ kcov_cmd, include_path, exclude_pattern, output_dir });
    kcov_run.addArtifactArg(artifact);
    configureRun(kcov_run);
    kcov_run.step.dependOn(&mkdir_step.step);
    return kcov_run;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const profile = b.option(bool, "profile", "Enable profiling-friendly build settings") orelse false;
    const coverage = b.option(bool, "coverage", "Enable coverage-friendly build settings") orelse false;
    const profile_enabled = profile or coverage;

    const mod = b.addModule("crucible", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });
    applyProfileSettings(mod, profile_enabled);

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
    configureCompile(exe, profile_enabled, true);

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
    configureCompile(example_exe, profile_enabled, false);

    const example_step = b.step("example", "Run cache demo example");
    const example_run = b.addRunArtifact(example_exe);
    example_step.dependOn(&example_run.step);
    if (b.args) |args| example_run.addArgs(args);

    const tests_module = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "xev", .module = xev_mod },
            .{ .name = "lz4", .module = lz4_module },
        },
    });

    const tests = b.addTest(.{
        .root_module = tests_module,
        .use_llvm = if (coverage) true else null,
    });
    configureCompile(tests, profile_enabled, true);
    const run_tests = b.addRunArtifact(tests);

    const cli_tests = b.addTest(.{
        .root_module = exe.root_module,
        .use_llvm = if (coverage) true else null,
    });
    configureCompile(cli_tests, profile_enabled, true);
    const run_cli_tests = b.addRunArtifact(cli_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_cli_tests.step);

    const coverage_step = b.step("coverage", "Run tests with kcov (use -Dcoverage=true for best results)");
    const kcov_cmd = b.option([]const u8, "kcov", "Path to kcov binary") orelse "kcov";
    const coverage_root = b.pathFromRoot("coverage/kcov");
    const include_path = b.fmt("--include-path={s}", .{b.pathFromRoot("src")});
    const exclude_pattern = b.fmt("--exclude-pattern={s}", .{".zig-cache,zig-out,/usr,/lib,/lib64"});

    const tests_dir = b.pathJoin(&.{ coverage_root, "tests" });
    const cli_dir = b.pathJoin(&.{ coverage_root, "cli-tests" });
    const merge_dir = b.pathJoin(&.{ coverage_root, "merge" });
    const report_dir = b.pathJoin(&.{ coverage_root, "test" });
    const index_html = b.pathJoin(&.{ coverage_root, "index.html" });
    const index_js = b.pathJoin(&.{ coverage_root, "index.js" });
    const merged_dir = b.pathJoin(&.{ merge_dir, "kcov-merged" });

    const cleanup_step = b.addSystemCommand(&.{ "rm", "-rf", "--", tests_dir, cli_dir, merge_dir, report_dir, index_html, index_js });
    configureRun(cleanup_step);

    const mkdir_step = b.addSystemCommand(&.{ "mkdir", "-p", tests_dir, cli_dir });
    configureRun(mkdir_step);
    mkdir_step.step.dependOn(&cleanup_step.step);

    const kcov_tests = addKcovRun(b, kcov_cmd, include_path, exclude_pattern, tests_dir, tests, mkdir_step);
    const kcov_cli = addKcovRun(b, kcov_cmd, include_path, exclude_pattern, cli_dir, cli_tests, mkdir_step);

    const kcov_merge = b.addSystemCommand(&.{ kcov_cmd, "--merge", merge_dir, tests_dir, cli_dir });
    configureRun(kcov_merge);
    kcov_merge.step.dependOn(&kcov_tests.step);
    kcov_merge.step.dependOn(&kcov_cli.step);

    const move_report = b.addSystemCommand(&.{ "mv", merged_dir, report_dir });
    configureRun(move_report);
    move_report.step.dependOn(&kcov_merge.step);

    const prune_step = b.addSystemCommand(&.{ "rm", "-rf", "--", tests_dir, cli_dir, merge_dir });
    configureRun(prune_step);
    prune_step.step.dependOn(&move_report.step);

    coverage_step.dependOn(&prune_step.step);
}
