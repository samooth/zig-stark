const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main library
    const lib = b.addModule("zig-stark", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Tests
    const test_step = b.step("test", "Run library tests");
    const lib_tests = b.addTest(.{
        .name = "zig-stark-tests",
        .root_module = lib,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);
    test_step.dependOn(&run_lib_tests.step);

    // E2E tests
    const e2e_module = b.createModule(.{
        .root_source_file = b.path("tests/e2e_tests.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zig-stark", .module = lib },
        },
    });
    const e2e_tests = b.addTest(.{
        .name = "e2e-tests",
        .root_module = e2e_module,
    });
    const run_e2e_tests = b.addRunArtifact(e2e_tests);
    test_step.dependOn(&run_e2e_tests.step);

    // Examples
    const fib_example = b.addExecutable(.{
        .name = "fibonacci",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/fibonacci/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig-stark", .module = lib },
            },
        }),
    });
    b.installArtifact(fib_example);

    const rescue_example = b.addExecutable(.{
        .name = "rescue",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/rescue/src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(rescue_example);

    const ml_example = b.addExecutable(.{
        .name = "ml_linear",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/ml_linear/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig-stark", .module = lib },
            },
        }),
    });
    b.installArtifact(ml_example);
}
