//! `cuda-circlefft` step: validates the GPU M31 circle FFT kernels.
//!
//! Requires an NVIDIA GPU + driver (CUDA 12 runtime `libcuda.so`). Not part of
//! CI. Checks, for log_size 3..16 (n = 2^(log_size+1) up to 131072):
//!   1. GPU forward `circleFFT` is bit-exact with the CPU transform.
//!   2. GPU inverse `circleIFFT` is bit-exact with the CPU transform.
//!   3. GPU-vs-CPU prover timings at a few sizes.

const std = @import("std");
const zig_stark = @import("zig-stark");
const circlefft_gpu = @import("circlefft_gpu.zig");

const M31 = zig_stark.m31.M31;
const CircleCoset = zig_stark.circle_coset.CircleCoset;
const circle = zig_stark.ntt_circle;

fn monotonicUs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(ts.nsec)) / 1_000;
}

fn checkForward(
    alloc: std.mem.Allocator,
    prng: *std.Random.DefaultPrng,
    log_size: u32,
) !void {
    const half_coset = CircleCoset.canonicHalf(log_size);
    const n = half_coset.size() * 2;
    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    for (coeffs) |*c| c.* = M31.fromInt(prng.random().int(u32));
    const evals_cpu = try alloc.alloc(M31, n);
    defer alloc.free(evals_cpu);
    const evals_gpu = try alloc.alloc(M31, n);
    defer alloc.free(evals_gpu);

    try circle.circleFFT(alloc, coeffs, half_coset, evals_cpu);
    try circlefft_gpu.circleFFT(alloc, coeffs, half_coset, evals_gpu);
    for (evals_cpu, evals_gpu) |a, b| {
        if (a.value != b.value) return error.FftMismatch;
    }
}

fn checkInverse(
    alloc: std.mem.Allocator,
    prng: *std.Random.DefaultPrng,
    log_size: u32,
) !void {
    const half_coset = CircleCoset.canonicHalf(log_size);
    const n = half_coset.size() * 2;
    const evals = try alloc.alloc(M31, n);
    defer alloc.free(evals);
    for (evals) |*e| e.* = M31.fromInt(prng.random().int(u32));
    const coeffs_cpu = try alloc.alloc(M31, n);
    defer alloc.free(coeffs_cpu);
    const coeffs_gpu = try alloc.alloc(M31, n);
    defer alloc.free(coeffs_gpu);

    try circle.circleIFFT(alloc, evals, half_coset, coeffs_cpu);
    try circlefft_gpu.circleIFFT(alloc, evals, half_coset, coeffs_gpu);
    for (coeffs_cpu, coeffs_gpu) |a, b| {
        if (a.value != b.value) return error.IfftMismatch;
    }
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    const alloc = gpa.allocator();
    defer _ = gpa.deinit();

    var prng = std.Random.DefaultPrng.init(0xC1E2_2026);

    var log_size: u32 = 3;
    while (log_size <= 16) : (log_size += 1) {
        try checkForward(alloc, &prng, log_size);
        try checkInverse(alloc, &prng, log_size);
        std.debug.print("circleFFT log_size={d}: GPU forward+inverse bit-exact with CPU\n", .{log_size});
    }

    // Timing: forward FFT at the largest size, CPU vs GPU.
    const half_coset = CircleCoset.canonicHalf(16);
    const n = half_coset.size() * 2;
    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    const evals_cpu = try alloc.alloc(M31, n);
    defer alloc.free(evals_cpu);
    const evals_gpu = try alloc.alloc(M31, n);
    defer alloc.free(evals_gpu);
    for (coeffs) |*c| c.* = M31.fromInt(prng.random().int(u32));

    const t0 = monotonicUs();
    try circle.circleFFT(alloc, coeffs, half_coset, evals_cpu);
    const cpu_us = monotonicUs() - t0;

    const t1 = monotonicUs();
    try circlefft_gpu.circleFFT(alloc, coeffs, half_coset, evals_gpu);
    const gpu_us = monotonicUs() - t1;

    std.debug.print("circleFFT n={d}: cpu {d:.2} ms, gpu {d:.2} ms, speedup {d:.2}x\n", .{
        n,
        @as(f64, @floatFromInt(cpu_us)) / 1000.0,
        @as(f64, @floatFromInt(gpu_us)) / 1000.0,
        @as(f64, @floatFromInt(cpu_us)) / @as(f64, @floatFromInt(gpu_us)),
    });

    std.debug.print("cuda-circlefft: all checks passed\n", .{});
}
