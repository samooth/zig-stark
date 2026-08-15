//! `cuda-sumcheck` step: validates the GPU sum-check `values[t]` kernels.
//!
//! Requires an NVIDIA GPU + driver (CUDA 12 runtime `libcuda.so`). Not part of
//! CI. Checks:
//!   1. Single-field `E = F = Gf256`: per-round `values[t]` bit-exact with CPU.
//!   2. A full `BiniusStark(Gf256, Gf256)` proof through the GPU hook is
//!      byte-identical to the CPU proof and still verifies.
//!   3. Extension mode `F = Gf16, E = Gf2_128`: per-round `values[t]`
//!      bit-exact with CPU.
//!   4. A full `BiniusStark(Gf16, Gf2_128)` proof through the GPU hook is
//!      byte-identical to the CPU proof and still verifies.
//!   5. GPU-vs-CPU prover timings at a few circuit widths.

const std = @import("std");
const zig_stark = @import("zig-stark");
const ser = zig_stark.core.serialization;
const accel = zig_stark.binius.accel;
const sumcheck_gpu = @import("sumcheck_gpu.zig");

const F = zig_stark.binius.tower.Gf256;
const Gf16 = zig_stark.binius.tower.Gf16;

fn monotonicUs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(ts.nsec)) / 1_000;
}

const Summary = struct {
    cpu_ms: f64,
    gpu_ms: f64,
    speedup: f64,
};

fn benchSumcheck(
    alloc: std.mem.Allocator,
    prng: *std.Random.DefaultPrng,
    k: usize,
) !Summary {
    const Sumcheck = zig_stark.binius.sumcheck.Sumcheck(F);
    const n = @as(usize, 1) << @intCast(k);
    const m = 3;
    var tables = try alloc.alloc([]F, m);
    defer {
        for (tables) |t| alloc.free(t);
        alloc.free(tables);
    }
    for (0..m) |j| {
        tables[j] = try alloc.alloc(F, n);
        for (0..n) |i| tables[j][i] = F.fromInt(prng.random().int(u8));
    }
    const terms = [_]Sumcheck.Term{
        .{ .coeff = F.fromInt(1), .indices = &.{ 0, 1, 2 } },
        .{ .coeff = F.fromInt(2), .indices = &.{0} },
    };

    const t0 = monotonicUs();
    accel.gf256_values = null;
    var p_cpu = try Sumcheck.proveCombination(alloc, k, tables, &terms, null);
    defer p_cpu.deinit(alloc);
    const cpu_us = monotonicUs() - t0;

    const t1 = monotonicUs();
    sumcheck_gpu.enable();
    var p_gpu = try Sumcheck.proveCombination(alloc, k, tables, &terms, null);
    defer p_gpu.deinit(alloc);
    const gpu_us = monotonicUs() - t1;

    for (0..k) |r| {
        if (!std.mem.eql(u8, @as([]const u8, std.mem.sliceAsBytes(p_cpu.rounds[r])), std.mem.sliceAsBytes(p_gpu.rounds[r])))
            return error.RoundMismatch;
    }
    if (p_cpu.claimed_sum.value != p_gpu.claimed_sum.value) return error.ClaimMismatch;

    return .{
        .cpu_ms = @as(f64, @floatFromInt(cpu_us)) / 1000.0,
        .gpu_ms = @as(f64, @floatFromInt(gpu_us)) / 1000.0,
        .speedup = @as(f64, @floatFromInt(cpu_us)) / @as(f64, @floatFromInt(gpu_us)),
    };
}

fn benchSumcheck128(
    alloc: std.mem.Allocator,
    prng: *std.Random.DefaultPrng,
    k: usize,
) !Summary {
    const E2 = zig_stark.binius.tower.Gf2_128;
    const Sumcheck = zig_stark.binius.sumcheck.Sumcheck(E2);
    const n = @as(usize, 1) << @intCast(k);
    const m = 3;
    var tables = try alloc.alloc([]E2, m);
    defer {
        for (tables) |t| alloc.free(t);
        alloc.free(tables);
    }
    for (0..m) |j| {
        tables[j] = try alloc.alloc(E2, n);
        for (0..n) |i| tables[j][i] = E2.fromInt(prng.random().int(u128));
    }
    const terms = [_]Sumcheck.Term{
        .{ .coeff = E2.fromInt(1), .indices = &.{ 0, 1, 2 } },
        .{ .coeff = E2.fromInt(2), .indices = &.{0} },
    };

    const t0 = monotonicUs();
    accel.gf128_values = null;
    var p_cpu = try Sumcheck.proveCombination(alloc, k, tables, &terms, null);
    defer p_cpu.deinit(alloc);
    const cpu_us = monotonicUs() - t0;

    const t1 = monotonicUs();
    sumcheck_gpu.enable();
    var p_gpu = try Sumcheck.proveCombination(alloc, k, tables, &terms, null);
    defer p_gpu.deinit(alloc);
    const gpu_us = monotonicUs() - t1;

    for (0..k) |r| {
        if (!std.mem.eql(u8, @as([]const u8, std.mem.sliceAsBytes(p_cpu.rounds[r])), std.mem.sliceAsBytes(p_gpu.rounds[r])))
            return error.RoundMismatch;
    }
    if (p_cpu.claimed_sum.value != p_gpu.claimed_sum.value) return error.ClaimMismatch;

    return .{
        .cpu_ms = @as(f64, @floatFromInt(cpu_us)) / 1000.0,
        .gpu_ms = @as(f64, @floatFromInt(gpu_us)) / 1000.0,
        .speedup = @as(f64, @floatFromInt(cpu_us)) / @as(f64, @floatFromInt(gpu_us)),
    };
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    const alloc = gpa.allocator();
    defer _ = gpa.deinit();

    var prng = std.Random.DefaultPrng.init(0x5157_544a);

    // --- 1) Sum-check level: per-round values bit-exact with CPU ---
    const Sumcheck = zig_stark.binius.sumcheck.Sumcheck(F);
    const k = 6;
    const n = @as(usize, 1) << @intCast(k);
    const m = 3;
    var tables = try alloc.alloc([]F, m);
    defer {
        for (tables) |t| alloc.free(t);
        alloc.free(tables);
    }
    for (0..m) |j| {
        tables[j] = try alloc.alloc(F, n);
        for (0..n) |i| tables[j][i] = F.fromInt(prng.random().int(u8));
    }
    const terms = [_]Sumcheck.Term{
        .{ .coeff = F.fromInt(1), .indices = &.{ 0, 1, 2 } },
        .{ .coeff = F.fromInt(2), .indices = &.{0} },
    };

    accel.gf256_values = null;
    var p_cpu = try Sumcheck.proveCombination(alloc, k, tables, &terms, null);
    defer p_cpu.deinit(alloc);

    sumcheck_gpu.enable();
    var p_gpu = try Sumcheck.proveCombination(alloc, k, tables, &terms, null);
    defer p_gpu.deinit(alloc);

    for (0..k) |r| {
        if (!std.mem.eql(u8, std.mem.sliceAsBytes(p_cpu.rounds[r]), std.mem.sliceAsBytes(p_gpu.rounds[r]))) {
            std.debug.print("round {d}: GPU values diverge from CPU\n", .{r});
            return error.RoundMismatch;
        }
    }
    if (p_cpu.claimed_sum.value != p_gpu.claimed_sum.value) return error.ClaimMismatch;
    std.debug.print("sum-check Gf256 k={d}: GPU per-round values bit-exact with CPU\n", .{k});

    // --- 2) Full Stark through the GPU hook: proof bytes identical + verifies ---
    const E = F;
    const BatchPcs = zig_stark.binius.batchpcs.BatchFriPcsStark(F, E, 2, 4);
    const Adder = zig_stark.binius.adder.AdderWith(F, E, BatchPcs);
    const Stark = zig_stark.binius.stark.BiniusStarkFri(F, E, 2, 4);
    const k2 = 5;
    const n2 = @as(usize, 1) << @intCast(k2);
    const x = try alloc.alloc(u4, n2);
    defer alloc.free(x);
    const y = try alloc.alloc(u4, n2);
    defer alloc.free(y);
    for (0..n2) |i| {
        x[i] = @intCast((i * 3 + 5) % 16);
        y[i] = @intCast((i * 7 + 2) % 16);
    }
    const cols = try Adder.generateWitness(alloc, x, y);
    defer {
        for (cols) |c| alloc.free(c);
    }
    var roots: [Adder.num_columns]zig_stark.hash.Hash.Digest = undefined;
    for (0..Adder.num_columns) |c| {
        var tree = try BatchPcs.commit(alloc, cols[c]);
        roots[c] = tree.root();
        tree.deinit();
    }

    accel.gf256_values = null;
    var pf_cpu = try Stark.prove(alloc, k2, &cols, &Adder.constraints, &.{}, "");
    defer pf_cpu.deinit(alloc);
    const b_cpu = try ser.serialize(alloc, pf_cpu);
    defer alloc.free(b_cpu);

    sumcheck_gpu.enable();
    var pf_gpu = try Stark.prove(alloc, k2, &cols, &Adder.constraints, &.{}, "");
    defer pf_gpu.deinit(alloc);
    const b_gpu = try ser.serialize(alloc, pf_gpu);
    defer alloc.free(b_gpu);

    if (!std.mem.eql(u8, b_cpu, b_gpu)) {
        std.debug.print("STARK proof mismatch (cpu {d} vs gpu {d} bytes)\n", .{ b_cpu.len, b_gpu.len });
        return error.ProofMismatch;
    }
    if (!(try Stark.verify(alloc, k2, &roots, &Adder.constraints, &.{}, pf_gpu, "")))
        return error.VerifyFailed;
    std.debug.print("BiniusStark(Gf256) k={d}: GPU proof byte-identical to CPU ({d} bytes) and verifies\n", .{ k2, b_gpu.len });

    // --- 3) Gf2_128 sum-check level: per-round values bit-exact with CPU ---
    const E2 = zig_stark.binius.tower.Gf2_128;
    const SC128 = zig_stark.binius.sumcheck.Sumcheck(E2);
    const k3 = 5;
    const n3 = @as(usize, 1) << @intCast(k3);
    var tables128 = try alloc.alloc([]E2, m);
    defer {
        for (tables128) |t| alloc.free(t);
        alloc.free(tables128);
    }
    for (0..m) |j| {
        tables128[j] = try alloc.alloc(E2, n3);
        for (0..n3) |i| tables128[j][i] = E2.fromInt(prng.random().int(u128));
    }
    const terms128 = [_]SC128.Term{
        .{ .coeff = E2.fromInt(1), .indices = &.{ 0, 1, 2 } },
        .{ .coeff = E2.fromInt(2), .indices = &.{0} },
    };

    accel.gf128_values = null;
    var p128_cpu = try SC128.proveCombination(alloc, k3, tables128, &terms128, null);
    defer p128_cpu.deinit(alloc);

    sumcheck_gpu.enable();
    var p128_gpu = try SC128.proveCombination(alloc, k3, tables128, &terms128, null);
    defer p128_gpu.deinit(alloc);

    for (0..k3) |r| {
        if (!std.mem.eql(u8, std.mem.sliceAsBytes(p128_cpu.rounds[r]), std.mem.sliceAsBytes(p128_gpu.rounds[r]))) {
            std.debug.print("Gf2_128 round {d}: GPU values diverge from CPU\n", .{r});
            return error.RoundMismatch;
        }
    }
    if (p128_cpu.claimed_sum.value != p128_gpu.claimed_sum.value) return error.ClaimMismatch;
    std.debug.print("sum-check Gf2_128 k={d}: GPU per-round values bit-exact with CPU\n", .{k3});

    // --- 4) Full Stark in the extension mode (F=Gf16, E=Gf2_128) ---
    const BatchPcs128 = zig_stark.binius.batchpcs.BatchFriPcsStark(Gf16, E2, 2, 4);
    const Adder128 = zig_stark.binius.adder.AdderWith(Gf16, E2, BatchPcs128);
    const Stark128 = zig_stark.binius.stark.BiniusStarkFri(Gf16, E2, 2, 4);
    const k4 = 2; // k4 + log_blowup must fit F.BITS = 4 for Gf16 (FRI degree bound)
    const n4 = @as(usize, 1) << @intCast(k4);
    const x4 = try alloc.alloc(u4, n4);
    defer alloc.free(x4);
    const y4 = try alloc.alloc(u4, n4);
    defer alloc.free(y4);
    for (0..n4) |i| {
        x4[i] = @intCast((i * 3 + 5) % 16);
        y4[i] = @intCast((i * 7 + 2) % 16);
    }
    const cols128 = try Adder128.generateWitness(alloc, x4, y4);
    defer {
        for (cols128) |c| alloc.free(c);
    }
    var roots128: [Adder128.num_columns]zig_stark.hash.Hash.Digest = undefined;
    for (0..Adder128.num_columns) |c| {
        var tree = try BatchPcs128.commit(alloc, cols128[c]);
        roots128[c] = tree.root();
        tree.deinit();
    }

    accel.gf128_values = null;
    var pf128_cpu = try Stark128.prove(alloc, k4, &cols128, &Adder128.constraints, &.{}, "");
    defer pf128_cpu.deinit(alloc);
    const b128_cpu = try ser.serialize(alloc, pf128_cpu);
    defer alloc.free(b128_cpu);

    sumcheck_gpu.enable();
    var pf128_gpu = try Stark128.prove(alloc, k4, &cols128, &Adder128.constraints, &.{}, "");
    defer pf128_gpu.deinit(alloc);
    const b128_gpu = try ser.serialize(alloc, pf128_gpu);
    defer alloc.free(b128_gpu);

    if (!std.mem.eql(u8, b128_cpu, b128_gpu)) {
        std.debug.print("Gf2_128 STARK proof mismatch (cpu {d} vs gpu {d} bytes)\n", .{ b128_cpu.len, b128_gpu.len });
        return error.ProofMismatch;
    }
    if (!(try Stark128.verify(alloc, k4, &roots128, &Adder128.constraints, &.{}, pf128_gpu, "")))
        return error.VerifyFailed;
    std.debug.print("BiniusStark(Gf16,Gf2_128) k={d}: GPU proof byte-identical to CPU ({d} bytes) and verifies\n", .{ k4, b128_gpu.len });

    // --- 5) Benchmark ---
    for (4..10) |kb| {
        const s = try benchSumcheck(alloc, &prng, kb);
        std.debug.print("sum-check k={d}: cpu {d:.2} ms, gpu {d:.2} ms, speedup {d:.2}x\n", .{
            kb, s.cpu_ms, s.gpu_ms, s.speedup,
        });
    }
    for (4..8) |kb| {
        const s = try benchSumcheck128(alloc, &prng, kb);
        std.debug.print("Gf2_128 sum-check k={d}: cpu {d:.2} ms, gpu {d:.2} ms, speedup {d:.2}x\n", .{
            kb, s.cpu_ms, s.gpu_ms, s.speedup,
        });
    }

    std.debug.print("cuda-sumcheck: all checks passed\n", .{});
}
