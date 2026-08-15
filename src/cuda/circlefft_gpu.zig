//! GPU implementation of the M31 circle FFT (`ntt/circle.zig`). Bit-exact with
//! the CPU transform: the twiddle tree and every layer/twiddle relationship are
//! computed with the library's own functions, and only the butterfly layers,
//! the bit-reversal and the (de)interleave run on the GPU. Sizes below lg = 3
//! (and any launch when no GPU/driver is present) fall back to the CPU.
//!
//! This is E2 of the GPU roadmap. It is opt-in: nothing in the library depends
//! on CUDA.

const std = @import("std");
const cuda = @import("cuda.zig");
const zig_stark = @import("zig-stark");

const M31 = zig_stark.m31.M31;
const CircleCoset = zig_stark.circle_coset.CircleCoset;
const circle = zig_stark.ntt_circle;

const ptx = @embedFile("kernels/circlefft.ptx");

/// Lazily-initialized CUDA context + module (one per process).
var gpu: ?cuda.Cuda = null;
var ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var mutex: std.atomic.Mutex = .unlocked;

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

fn getCuda() ?*cuda.Cuda {
    if (!ready.load(.acquire)) {
        lockSpin(&mutex);
        if (!ready.load(.monotonic)) {
            gpu = cuda.Cuda.init(ptx) catch null;
            ready.store(true, .release);
        }
        mutex.unlock();
    }
    return if (gpu) |*g| g else null;
}

fn gridFor(count: usize) u32 {
    return @intCast((count + 255) / 256);
}

/// Forward circle FFT on the GPU (bit-exact with `circle.circleFFT`).
pub fn circleFFT(
    allocator: std.mem.Allocator,
    coeffs: []const M31,
    half_coset: CircleCoset,
    evals: []M31,
) !void {
    const n = coeffs.len;
    const half = n / 2;
    const lg = std.math.log2_int(usize, n);
    if (lg < 3) return circle.circleFFT(allocator, coeffs, half_coset, evals);
    const c = getCuda() orelse return circle.circleFFT(allocator, coeffs, half_coset, evals);

    const f_interleave = try c.func("circle_interleave");
    const f_layer = try c.func("circle_fft_layer");
    const f_bitreverse = try c.func("circle_bitreverse");

    const d_coeffs = try c.alloc(n * 4);
    defer c.free(d_coeffs);
    const d_values = try c.alloc(n * 4);
    defer c.free(d_values);
    const d_tree = try c.alloc(half * 4);
    defer c.free(d_tree);
    const d_circle = try c.alloc(half * 4);
    defer c.free(d_circle);

    try c.copyHtoD(d_coeffs, std.mem.sliceAsBytes(coeffs));

    const twiddles = try allocator.alloc(M31, half);
    defer allocator.free(twiddles);
    circle.precomputeTwiddles(half_coset, twiddles);
    try c.copyHtoD(d_tree, std.mem.sliceAsBytes(twiddles));

    const circle_tw = try allocator.alloc(M31, half);
    defer allocator.free(circle_tw);
    circle.circleTwiddles(circle.lineTwiddleSlice(twiddles, 0, @intCast(lg)), circle_tw);
    try c.copyHtoD(d_circle, std.mem.sliceAsBytes(circle_tw));

    const half32: u32 = @intCast(half);
    const n32: u32 = @intCast(n);
    const zero: u32 = 0;

    try c.launch(f_interleave, gridFor(half), 256, &[_]*const anyopaque{ &d_coeffs, &d_values, &half32 });

    // Line layers, largest to smallest: i = lg-1 .. 1.
    var i: u32 = @intCast(lg - 1);
    while (i >= 1) : (i -= 1) {
        const slice = circle.lineTwiddleSlice(twiddles, @intCast(i - 1), @intCast(lg));
        const len: u32 = @intCast(slice.len);
        const offset = twiddles.len - 2 * slice.len;
        var d_tw: cuda.CUdeviceptr = d_tree + @as(cuda.CUdeviceptr, @intCast(offset * 4));
        try c.launch(f_layer, gridFor(@as(usize, len) * (@as(usize, 1) << @intCast(i))), 256, &[_]*const anyopaque{
            &d_values, &d_tw, &n32, &i, &zero,
        });
    }

    // Circle layer (layer 0).
    const layer0: u32 = 0;
    try c.launch(f_layer, gridFor(half), 256, &[_]*const anyopaque{ &d_values, &d_circle, &n32, &layer0, &zero });

    try c.launch(f_bitreverse, gridFor(n), 256, &[_]*const anyopaque{ &d_values, &n32 });

    try c.copyDtoH(std.mem.sliceAsBytes(evals), d_values);
}

/// Inverse circle FFT on the GPU (bit-exact with `circle.circleIFFT`).
pub fn circleIFFT(
    allocator: std.mem.Allocator,
    evals: []const M31,
    half_coset: CircleCoset,
    coeffs: []M31,
) !void {
    const n = evals.len;
    const half = n / 2;
    const lg = std.math.log2_int(usize, n);
    if (lg < 3) return circle.circleIFFT(allocator, evals, half_coset, coeffs);
    const c = getCuda() orelse return circle.circleIFFT(allocator, evals, half_coset, coeffs);

    const f_bitreverse = try c.func("circle_bitreverse");
    const f_layer = try c.func("circle_fft_layer");
    const f_deinterleave = try c.func("circle_deinterleave");

    const d_values = try c.alloc(n * 4);
    defer c.free(d_values);
    const d_coeffs = try c.alloc(n * 4);
    defer c.free(d_coeffs);
    const d_tree = try c.alloc(half * 4);
    defer c.free(d_tree);
    const d_circle = try c.alloc(half * 4);
    defer c.free(d_circle);

    try c.copyHtoD(d_values, std.mem.sliceAsBytes(evals));

    const twiddles = try allocator.alloc(M31, half);
    defer allocator.free(twiddles);
    circle.precomputeTwiddles(half_coset, twiddles);
    for (twiddles) |*t| t.* = t.inv();
    try c.copyHtoD(d_tree, std.mem.sliceAsBytes(twiddles));

    const circle_tw = try allocator.alloc(M31, half);
    defer allocator.free(circle_tw);
    circle.circleTwiddles(circle.lineTwiddleSlice(twiddles, 0, @intCast(lg)), circle_tw);
    try c.copyHtoD(d_circle, std.mem.sliceAsBytes(circle_tw));

    const half32: u32 = @intCast(half);
    const n32: u32 = @intCast(n);
    const one: u32 = 1;

    try c.launch(f_bitreverse, gridFor(n), 256, &[_]*const anyopaque{ &d_values, &n32 });

    // Circle layer first (layer 0), then line layers smallest to largest.
    const layer0: u32 = 0;
    try c.launch(f_layer, gridFor(half), 256, &[_]*const anyopaque{ &d_values, &d_circle, &n32, &layer0, &one });

    const last: u32 = @intCast(lg - 1);
    var i: u32 = 1;
    while (i <= last) : (i += 1) {
        const slice = circle.lineTwiddleSlice(twiddles, @intCast(i - 1), @intCast(lg));
        const len: u32 = @intCast(slice.len);
        const offset = twiddles.len - 2 * slice.len;
        var d_tw: cuda.CUdeviceptr = d_tree + @as(cuda.CUdeviceptr, @intCast(offset * 4));
        try c.launch(f_layer, gridFor(@as(usize, len) * (@as(usize, 1) << @intCast(i))), 256, &[_]*const anyopaque{
            &d_values, &d_tw, &n32, &i, &one,
        });
    }

    const inv_n: u32 = M31.fromInt(@intCast(n)).inv().value;
    try c.launch(f_deinterleave, gridFor(half), 256, &[_]*const anyopaque{ &d_values, &d_coeffs, &half32, &inv_n });

    try c.copyDtoH(std.mem.sliceAsBytes(coeffs), d_coeffs);
}
