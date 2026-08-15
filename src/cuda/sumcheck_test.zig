//! `cuda-sumcheck` step: validates the GPU sum-check `values[t]` kernel.
//!
//! Requires an NVIDIA GPU + driver (CUDA 12 runtime `libcuda.so`). Not part of
//! CI. Checks, for single-field `E = F = Gf256`:
//!   1. GPU per-round `values[t]` are bit-exact with the CPU path.
//!   2. A full `BiniusStark(Gf256, Gf256)` proof produced through the GPU hook
//!      is byte-identical to the CPU proof and still verifies.
//!   3. GPU-vs-CPU prover timings at a few circuit widths.

const std = @import("std");
const zig_stark = @import("zig-stark");
const ser = zig_stark.core.serialization;
const accel = zig_stark.binius.accel;
const sumcheck_gpu = @import("sumcheck_gpu.zig");

const F = zig_stark.binius.tower.Gf256;

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

    // --- 3) Benchmark ---
    for (4..10) |kb| {
        const s = try benchSumcheck(alloc, &prng, kb);
        std.debug.print("sum-check k={d}: cpu {d:.2} ms, gpu {d:.2} ms, speedup {d:.2}x\n", .{
            kb, s.cpu_ms, s.gpu_ms, s.speedup,
        });
    }

    std.debug.print("cuda-sumcheck: all checks passed\n", .{});
}
