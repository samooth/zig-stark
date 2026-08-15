//! GPU implementations of the sum-check `values[t]` hook (`accel.zig`) for
//! Gf256 and Gf2_128. `enable()` registers both by setting
//! `accel.gf256_values`/`accel.gf128_values`; when not called from a
//! CUDA-enabled process (or when no GPU/driver is present) the hooks stay
//! null and the CPU path runs unchanged.

const std = @import("std");
const cuda = @import("cuda.zig");

const ptx = @embedFile("kernels/sumcheck.ptx");

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

/// Signature-compatible with `accel.Gf256ValuesFn`. Returns `null` (CPU
/// fallback) when CUDA is unavailable, and `dmax + 1` bytes otherwise.
pub fn computeValues(
    allocator: std.mem.Allocator,
    cur_flat: []const u8,
    len: usize,
    m: usize,
    coeffs: []const u8,
    indices: []const u32,
    offsets: []const u32,
    dmax: usize,
    half: usize,
) anyerror!?[]u8 {
    const c = getCuda() orelse return null;
    const f = try c.func("sumcheck_values");
    const nterms = coeffs.len;

    const dcur = try c.alloc(cur_flat.len);
    defer c.free(dcur);
    const dcoeffs = try c.alloc(coeffs.len);
    defer c.free(dcoeffs);
    const dindices = try c.alloc(indices.len * 4);
    defer c.free(dindices);
    const doffsets = try c.alloc(offsets.len * 4);
    defer c.free(doffsets);
    const packed_n = (dmax + 4) / 4;
    const dvalues = try c.alloc(packed_n * 4);
    defer c.free(dvalues);
    const values_packed = try allocator.alloc(u32, packed_n);
    defer allocator.free(values_packed);
    @memset(values_packed, 0);

    try c.copyHtoD(dcur, cur_flat);
    try c.copyHtoD(dcoeffs, coeffs);
    try c.copyHtoD(dindices, std.mem.sliceAsBytes(indices));
    try c.copyHtoD(doffsets, std.mem.sliceAsBytes(offsets));
    try c.copyHtoD(dvalues, std.mem.sliceAsBytes(values_packed));

    const len32: u32 = @intCast(len);
    const m32: u32 = @intCast(m);
    const nterms32: u32 = @intCast(nterms);
    const half32: u32 = @intCast(half);
    const dmax32: u32 = @intCast(dmax);
    var args = [_]*const anyopaque{
        &dcur,      &len32,    &m32,        &dcoeffs, &dindices,
        &doffsets,  &nterms32, &half32,     &dmax32,  &dvalues,
    };
    const grid: u32 = @intCast((half + 255) / 256);
    try c.launch(f, grid, 256, &args);
    try c.synchronize();
    try c.copyDtoH(std.mem.sliceAsBytes(values_packed), dvalues);

    const out = try allocator.alloc(u8, dmax + 1);
    for (0..dmax + 1) |t| {
        out[t] = @truncate(values_packed[t >> 2] >> @as(u5, @intCast((t & 3) * 8)));
    }
    return out;
}

/// Same host plumbing for the Gf2_128 round: every field element is 16 bytes
/// (a little-endian u128, two u64 limbs), and each `values[t]` is four packed
/// u32 limbs XORed by the kernel. Signature-compatible with `accel.Gf128ValuesFn`.
pub fn computeValues128(
    allocator: std.mem.Allocator,
    cur_flat: []const u8,
    len: usize,
    m: usize,
    coeffs: []const u8,
    indices: []const u32,
    offsets: []const u32,
    dmax: usize,
    half: usize,
) anyerror!?[]u8 {
    const c = getCuda() orelse return null;
    const f = try c.func("sumcheck_values128");
    const nterms = coeffs.len / 16;

    const dcur = try c.alloc(cur_flat.len);
    defer c.free(dcur);
    const dcoeffs = try c.alloc(coeffs.len);
    defer c.free(dcoeffs);
    const dindices = try c.alloc(indices.len * 4);
    defer c.free(dindices);
    const doffsets = try c.alloc(offsets.len * 4);
    defer c.free(doffsets);
    const limbs_n = (dmax + 1) * 4;
    const dvalues = try c.alloc(limbs_n * 4);
    defer c.free(dvalues);
    const values_packed = try allocator.alloc(u32, limbs_n);
    defer allocator.free(values_packed);
    @memset(values_packed, 0);

    try c.copyHtoD(dcur, cur_flat);
    try c.copyHtoD(dcoeffs, coeffs);
    try c.copyHtoD(dindices, std.mem.sliceAsBytes(indices));
    try c.copyHtoD(doffsets, std.mem.sliceAsBytes(offsets));
    try c.copyHtoD(dvalues, std.mem.sliceAsBytes(values_packed));

    const len32: u32 = @intCast(len);
    const m32: u32 = @intCast(m);
    const nterms32: u32 = @intCast(nterms);
    const half32: u32 = @intCast(half);
    const dmax32: u32 = @intCast(dmax);
    var args = [_]*const anyopaque{
        &dcur,      &len32,    &m32,        &dcoeffs, &dindices,
        &doffsets,  &nterms32, &half32,     &dmax32,  &dvalues,
    };
    const grid: u32 = @intCast((half + 255) / 256);
    try c.launch(f, grid, 256, &args);
    try c.synchronize();
    try c.copyDtoH(std.mem.sliceAsBytes(values_packed), dvalues);

    const out = try allocator.alloc(u8, (dmax + 1) * 16);
    for (0..dmax + 1) |t| {
        @memcpy(out[t * 16 ..][0..16], std.mem.sliceAsBytes(values_packed[t * 4 ..][0..4]));
    }
    return out;
}

/// Enable the GPU accelerator (call once at startup of a CUDA-enabled host).
pub fn enable() void {
    const accel = @import("zig-stark").binius.accel;
    accel.gf256_values = computeValues;
    accel.gf128_values = computeValues128;
}
