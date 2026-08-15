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

    // C ABI as a wasm32-freestanding module (browser / Node.js).
    const wasm_step = b.step("wasm", "Build the C ABI as a wasm32-freestanding module");
    const capi_wasm = b.addExecutable(.{
        .name = "zig_stark_capi",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/capi.zig"),
            .target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding }),
            .optimize = optimize,
        }),
    });
    capi_wasm.entry = .disabled; // pure export module, no _start
    capi_wasm.root_module.export_symbol_names = &.{
        "zs_binius_prove",    "zs_binius_verify",    "zs_free",    "zs_version",
        "zs_binius_prove_wm", "zs_binius_verify_wm", "zs_free_wm", "zs_binius_commit_wm",
    };
    const install_wasm = b.addInstallArtifact(capi_wasm, .{ .dest_sub_path = "zig_stark_capi.wasm" });
    wasm_step.dependOn(&install_wasm.step);

    // Fuzz / property stress: randomized gadget round-trips and tamper
    // rejection under the leak-checking allocator.
    const fuzz_exe = b.addExecutable(.{
        .name = "fuzz",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/fuzz.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig-stark", .module = lib },
            },
        }),
    });
    const run_fuzz = b.addRunArtifact(fuzz_exe);
    run_fuzz.addArg("2000");
    const fuzz_step = b.step("fuzz", "Run randomized gadget fuzz (prove/verify/tamper)");
    fuzz_step.dependOn(&run_fuzz.step);

    // N-API native addon for Node.js.
    const node_addon_step = b.step("node-addon", "Build the Node.js N-API addon (-Dnapi-include=<node include dir>)");
    if (b.option([]const u8, "napi-include", "Path to the Node include dir containing node_api.h")) |inc| {
        const capi_mod = b.addModule("capi", .{
            .root_source_file = b.path("src/capi.zig"),
            .target = target,
            .optimize = optimize,
        });
        const addon_mod = b.createModule(.{
            .root_source_file = b.path("bindings/node/addon.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "capi", .module = capi_mod },
            },
        });
        addon_mod.addIncludePath(.{ .cwd_relative = inc });
        const addon = b.addLibrary(.{ .name = "addon", .linkage = .dynamic, .root_module = addon_mod });
        addon.linker_allow_shlib_undefined = true; // N-API symbols resolve from Node at load
        const install = b.addInstallArtifact(addon, .{ .dest_sub_path = "addon.node" });
        node_addon_step.dependOn(&install.step);
    } else {
        node_addon_step.addError("{s}", .{"pass -Dnapi-include=<dir> (e.g. $HOME/.nvm/versions/node/vXX/include/node)"}) catch {};
    }

    // CUDA (E0a toolchain validation). Kernels are CUDA C -> PTX (committed in
    // src/cuda/kernels/) embedded into the test binary; the driver JITs them at
    // load. `cuda-hello` builds + runs the vecAdd validation kernel (requires a
    // GPU + CUDA driver); `cuda-kernels` regenerates the PTX with nvcc.
    const cuda_kernels_step = b.step("cuda-kernels", "Regenerate src/cuda/kernels/*.ptx with nvcc (requires nvcc)");
    const nvcc = b.addSystemCommand(&.{ "nvcc", "-ptx", "-arch=sm_86", "-o", "src/cuda/kernels/vecAdd.ptx", "src/cuda/kernels/vecAdd.cu" });
    cuda_kernels_step.dependOn(&nvcc.step);

    const cuda_hello_step = b.step("cuda-hello", "Build+run the CUDA hello kernel (requires GPU + driver)");
    const hello_mod = b.createModule(.{
        .root_source_file = b.path("src/cuda/hello_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    hello_mod.linkSystemLibrary("cuda", .{});
    const hello_exe = b.addExecutable(.{ .name = "cuda_hello", .root_module = hello_mod });
    const run_hello = b.addRunArtifact(hello_exe);
    cuda_hello_step.dependOn(&run_hello.step);

    // E1a: Gf256 tower multiplication bit-exactness vs tower.zig.
    const cuda_gf_step = b.step("cuda-gf", "Build+run the Gf256 mul bit-exactness test (requires GPU + driver)");
    const gf_mod = b.createModule(.{
        .root_source_file = b.path("src/cuda/gf_test.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "zig-stark", .module = lib },
        },
    });
    gf_mod.linkSystemLibrary("cuda", .{});
    const gf_exe = b.addExecutable(.{ .name = "cuda_gf", .root_module = gf_mod });
    const run_gf = b.addRunArtifact(gf_exe);
    cuda_gf_step.dependOn(&run_gf.step);
}
