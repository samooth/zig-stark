const std = @import("std");
const zig_stark = @import("zig-stark");
const m31 = zig_stark.m31;
const circle_point = zig_stark.circle_point;
const circle_coset = zig_stark.circle_coset;
const ntt_circle = zig_stark.ntt_circle;
const ntt_classic = zig_stark.ntt_classic;

const M31 = m31.M31;
const CirclePoint = circle_point.CirclePoint;
const CircleCoset = circle_coset.CircleCoset;

/// Monotonic clock in nanoseconds (this Zig build lacks std.time.Timer;
/// Linux-only, which matches the rest of the project's native targets).
fn now() i128 {
    var ts: std.posix.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, @intCast(ts.sec)) * std.time.ns_per_s + @as(i128, @intCast(ts.nsec));
}

/// The point at index `i` of the domain `half_coset ++ half_coset.conjugate()`.
fn domainPoint(half_coset: CircleCoset, i: usize) CirclePoint {
    const half = half_coset.size();
    if (i < half) return half_coset.at(i);
    return half_coset.conjugate().at(i - half);
}

/// Time one `circleFFT` forward transform. Returns average ns per transform.
fn benchForward(
    alloc: std.mem.Allocator,
    half_coset: CircleCoset,
    coeffs: []const M31,
    evals: []M31,
    budget_ns: u64,
) !u64 {
    try ntt_circle.circleFFT(alloc, coeffs, half_coset, evals);
    const t0 = now();
    try ntt_circle.circleFFT(alloc, coeffs, half_coset, evals);
    const one: u64 = @intCast(now() - t0);
    const iters: u64 = @max(1, budget_ns / @max(one, 1));
    const t1 = now();
    for (0..iters) |_| {
        try ntt_circle.circleFFT(alloc, coeffs, half_coset, evals);
    }
    const total: u64 = @intCast(now() - t1);
    return total / iters;
}

/// Time one `circleIFFT` inverse transform. Returns average ns per transform.
fn benchInverse(
    alloc: std.mem.Allocator,
    half_coset: CircleCoset,
    evals: []const M31,
    recovered: []M31,
    budget_ns: u64,
) !u64 {
    try ntt_circle.circleIFFT(alloc, evals, half_coset, recovered);
    const t0 = now();
    try ntt_circle.circleIFFT(alloc, evals, half_coset, recovered);
    const one: u64 = @intCast(now() - t0);
    const iters: u64 = @max(1, budget_ns / @max(one, 1));
    const t1 = now();
    for (0..iters) |_| {
        try ntt_circle.circleIFFT(alloc, evals, half_coset, recovered);
    }
    const total: u64 = @intCast(now() - t1);
    return total / iters;
}

/// Time the naive per-point fold evaluation over the whole domain (O(n^2)).
/// Returns average ns per full-domain evaluation.
fn benchNaive(half_coset: CircleCoset, coeffs: []const M31, evals: []M31, budget_ns: u64) u64 {
    const n = evals.len;
    for (0..n) |i| evals[i] = ntt_circle.evalAtPoint(coeffs, domainPoint(half_coset, i));
    const t0 = now();
    for (0..n) |i| evals[i] = ntt_circle.evalAtPoint(coeffs, domainPoint(half_coset, i));
    const one: u64 = @intCast(now() - t0);
    const iters: u64 = @max(1, budget_ns / @max(one, 1));
    const t1 = now();
    for (0..iters) |_| {
        for (0..n) |i| evals[i] = ntt_circle.evalAtPoint(coeffs, domainPoint(half_coset, i));
    }
    const total: u64 = @intCast(now() - t1);
    return total / iters;
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    const alloc = gpa.allocator();
    var prng = std.Random.DefaultPrng.init(0xdeadbeef);
    const rnd = prng.random();

    const budget_ns: u64 = 100 * std.time.ns_per_ms;

    // Classic NTT: the field's multiplicative group has 2-adicity 1, so it is
    // only meaningful at size 2. Larger transforms use the circle FFT below.
    std.debug.print("classic NTT (n=2, only valid size over M31):\n", .{});
    var v = [_]M31{ M31.fromInt(3), M31.fromInt(5) };
    ntt_classic.nttForward(&v);
    ntt_classic.nttInverse(&v);
    if (!v[0].eq(M31.fromInt(3)) or !v[1].eq(M31.fromInt(5))) return error.BadClassicNtt;
    std.debug.print("  round-trip OK\n\n", .{});

    std.debug.print("circle FFT (times in ns per transform; fft/ifft include per-call twiddle computation):\n", .{});
    std.debug.print("  {s:>4} {s:>7} {s:>9} {s:>9} {s:>11} {s:>9}\n", .{
        "lg", "n", "fft", "ifft", "naive", "speedup",
    });

    var log_size: u32 = 1;
    while (log_size <= 16) : (log_size += 1) {
        const half_coset = CircleCoset.canonicHalf(log_size);
        const n = half_coset.size() * 2;
        const coeffs = try alloc.alloc(M31, n);
        defer alloc.free(coeffs);
        const evals = try alloc.alloc(M31, n);
        defer alloc.free(evals);
        const recovered = try alloc.alloc(M31, n);
        defer alloc.free(recovered);

        for (coeffs) |*c| c.* = M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS));

        const fft_ns = try benchForward(alloc, half_coset, coeffs, evals, budget_ns);
        const ifft_ns = try benchInverse(alloc, half_coset, evals, recovered, budget_ns);

        for (coeffs, recovered) |c, r| {
            if (!c.eq(r)) return error.BadRoundTrip;
        }

        var naive_ns: u64 = 0;
        if (n <= 1024) {
            naive_ns = benchNaive(half_coset, coeffs, evals, budget_ns);
        }

        if (naive_ns > 0) {
            const speedup: f64 = @as(f64, @floatFromInt(naive_ns)) / @as(f64, @floatFromInt(fft_ns));
            std.debug.print("  {d:>4} {d:>7} {d:>9} {d:>9} {d:>11} {d:.1}x\n", .{
                log_size, n, fft_ns, ifft_ns, naive_ns, speedup,
            });
        } else {
            std.debug.print("  {d:>4} {d:>7} {d:>9} {d:>9} {s:>11} {s:>9}\n", .{
                log_size, n, fft_ns, ifft_ns, "-", "-",
            });
        }
    }
}
