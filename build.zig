const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Modules: core (field-agnostic crypto primitives), m31 (Mersenne STARK
    // stack), binius (binary-field / BSV sumcheck stack), and the root module
    // `zig-stark` which re-exports the public surface.
    const core_mod = b.addModule("core", .{
        .root_source_file = b.path("src/core/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const m31_mod = b.addModule("m31", .{
        .root_source_file = b.path("src/m31/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const binius_mod = b.addModule("binius", .{
        .root_source_file = b.path("src/binius/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addModule("zig-stark", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "core", .module = core_mod },
            .{ .name = "m31", .module = m31_mod },
            .{ .name = "binius", .module = binius_mod },
        },
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
            .imports = &.{
                .{ .name = "zig-stark", .module = lib },
            },
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

    const adder_example = b.addExecutable(.{
        .name = "binius_adder",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/binius_adder/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig-stark", .module = lib },
            },
        }),
    });
    b.installArtifact(adder_example);

    const bitpack_example = b.addExecutable(.{
        .name = "binius_bitpack",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/binius_bitpack/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig-stark", .module = lib },
            },
        }),
    });
    b.installArtifact(bitpack_example);

    const rangecmp_example = b.addExecutable(.{
        .name = "binius_rangecmp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/binius_rangecmp/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig-stark", .module = lib },
            },
        }),
    });
    b.installArtifact(rangecmp_example);

    // Benchmarks
    const bench_ntt = b.addExecutable(.{
        .name = "bench_ntt",
        .root_module = b.createModule(.{
            .root_source_file = b.path("benchmarks/ntt/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig-stark", .module = lib },
            },
        }),
    });
    b.installArtifact(bench_ntt);
    const run_bench_ntt = b.addRunArtifact(bench_ntt);
    const bench_step = b.step("bench", "Run NTT benchmarks (use -Doptimize=ReleaseFast)");
    bench_step.dependOn(&run_bench_ntt.step);

    const bench_binius = b.addExecutable(.{
        .name = "bench_binius_stark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("benchmarks/binius_stark/src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig-stark", .module = lib },
            },
        }),
    });
    b.installArtifact(bench_binius);
    const run_bench_binius = b.addRunArtifact(bench_binius);
    const bench_binius_step = b.step("bench-binius", "Run Binius STARK benchmarks (use -Doptimize=ReleaseFast)");
    bench_binius_step.dependOn(&run_bench_binius.step);

    // Formatting check
    const fmt_check = b.addFmt(.{ .paths = &.{"."}, .check = true });
    const fmt_step = b.step("fmt", "Check code formatting (zig fmt --check)");
    fmt_step.dependOn(&fmt_check.step);
}
