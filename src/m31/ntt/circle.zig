const std = @import("std");
const M31 = @import("../field/m31.zig").M31;
const CirclePoint = @import("../circle/point.zig").CirclePoint;
const CircleCoset = @import("../circle/coset.zig").CircleCoset;

/// Circle transforms over M31.
///
/// A "circle polynomial" on a circle domain of order 2^log_size is written as
///     f(P) = A(x_P) + y_P * B(x_P)
/// with deg A, B < 2^(log_size-1). Coefficients are stored in the FFT basis
///     A = a0 + a1*x + a2*pi(x) + a3*pi^2(x) + ...
///     B = b0 + b1*x + b2*pi(x) + b3*pi^2(x) + ...
/// where pi(x) = 2x^2 - 1 is the x-coordinate of point doubling.
///
/// The public coefficient layout is A-then-B: `coeffs[0..half]` holds A and
/// `coeffs[half..n]` holds B. Internally the transform uses stwo's interleaved
/// layout `[A0, B0, A1, B1, ...]` (the tensor-product basis y, x, pi(x), ...).
///
/// Domains are given as a half-coset `half_coset`; the full domain is
/// `half_coset ++ half_coset.conjugate()` (see `CircleCoset.canonicHalf`).
/// `circleFFT` writes `evals[i] = f(domain[i])` in natural order.
///
/// The transforms below are the O(n log n) recursive-fold algorithm from stwo
/// (crates/stwo/src/prover/backend/cpu/circle.rs), ported to the Fourier basis.
/// The recursion `f(P) = fold([y, x, pi(x), ...])` closes in this basis, unlike
/// the standard monomial basis which admits only the naive O(n * 2^n) evaluation.
fn butterfly(v0: *M31, v1: *M31, t: M31) void {
    const tmp = v1.mul(t);
    v1.* = v0.sub(tmp);
    v0.* = v0.add(tmp);
}

fn ibutterfly(v0: *M31, v1: *M31, t: M31) void {
    const tmp = v0.*;
    v0.* = tmp.add(v1.*);
    v1.* = tmp.sub(v1.*).mul(t);
}

fn fftLayerLoop(values: []M31, i: usize, h: usize, t: M31, inverse: bool) void {
    const step: usize = @as(usize, 1) << @intCast(i);
    const base = h << @as(u6, @intCast(i + 1));
    for (0..step) |l| {
        const idx0 = base + l;
        const idx1 = idx0 + step;
        var v0 = values[idx0];
        var v1 = values[idx1];
        if (inverse) {
            ibutterfly(&v0, &v1, t);
        } else {
            butterfly(&v0, &v1, t);
        }
        values[idx0] = v0;
        values[idx1] = v1;
    }
}

/// Precompute the twiddle tree for a half-coset into `out` (length
/// 2^half_coset.log_size). Each level k collects the bit-reversed x-values of
/// the first 2^(k-1) points of the current (doubling) coset; the last slot is
/// an arbitrary padding value.
fn slowPrecomputeTwiddles(half_coset: CircleCoset, out: []M31) void {
    var pos: usize = 0;
    var cur = half_coset;
    var k = half_coset.log_size;
    while (k > 0) : (k -= 1) {
        const m: usize = @as(usize, 1) << @intCast(k - 1);
        for (0..m) |i| out[pos + i] = cur.at(i).x;
        bitReverseSlice(out[pos .. pos + m]);
        pos += m;
        cur = cur.half();
    }
    std.debug.assert(pos + 1 == out.len);
    out[pos] = M31.one();
}

/// The `j`-th line-twiddle layer (0 = largest) as a slice of the twiddle tree.
fn lineTwiddleSlice(twiddles: []const M31, j: usize, lg: u32) []const M31 {
    const i_level = lg - 2 - @as(u32, @intCast(j));
    const len: usize = @as(usize, 1) << @intCast(i_level);
    const blen = twiddles.len;
    return twiddles[blen - 2 * len .. blen - len];
}

/// Compute the circle-layer twiddles (layer 0) from the first line twiddle
/// layer: each pair (x, y) expands to [y, -y, -x, x]. `out` has length
/// 2 * first.len.
fn circleTwiddles(first: []const M31, out: []M31) void {
    std.debug.assert(out.len == 2 * first.len);
    for (0..first.len / 2) |i| {
        const x = first[2 * i];
        const y = first[2 * i + 1];
        out[4 * i] = y;
        out[4 * i + 1] = y.neg();
        out[4 * i + 2] = x.neg();
        out[4 * i + 3] = x;
    }
}

fn pi(x: M31) M31 {
    return x.mul(x).mul(M31.fromInt(2)).sub(M31.one());
}

/// The folding factors (FFT-basis evaluation at `point`): [pi^(lg-2)(x), ...,
/// pi(x), x, y], i.e. `get_folding_alphas` in stwo, ready for `fold`.
fn getFoldingAlphas(point: CirclePoint, len: usize, out: []M31) void {
    std.debug.assert(out.len == len);
    if (len == 0) return;
    out[len - 1] = point.y;
    if (len > 1) {
        var x = point.x;
        var i: usize = len - 1;
        while (i > 0) {
            i -= 1;
            out[i] = x;
            x = pi(x);
        }
    }
}

/// Interleave A-then-B coefficients into stwo's `[A0, B0, A1, B1, ...]` order.
fn interleave(a: []const M31, b: []const M31, out: []M31) void {
    std.debug.assert(a.len == b.len);
    std.debug.assert(out.len == 2 * a.len);
    for (a, 0..) |va, i| {
        out[2 * i] = va;
        out[2 * i + 1] = b[i];
    }
}

/// Inverse of `interleave`.
fn deinterleave(c: []const M31, a: []M31, b: []M31) void {
    std.debug.assert(a.len == b.len);
    std.debug.assert(c.len == 2 * a.len);
    for (0..a.len) |i| {
        a[i] = c[2 * i];
        b[i] = c[2 * i + 1];
    }
}

fn bitReverseIndex(k: usize, width: usize) usize {
    var result: usize = 0;
    var x = k;
    var i: usize = 0;
    while (i < width) : (i += 1) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

/// In-place bit-reversal permutation of `vals` (length must be a power of two).
fn bitReverseSlice(vals: []M31) void {
    const width = std.math.log2_int(usize, vals.len);
    for (0..vals.len) |i| {
        const j = bitReverseIndex(i, width);
        if (i < j) std.mem.swap(M31, &vals[i], &vals[j]);
    }
}

/// The `k`-th coefficient of the interleaved layout, read from A-then-B.
fn interleavedAt(coeffs: []const M31, half: usize, k: usize) M31 {
    if (k % 2 == 0) return coeffs[k / 2];
    return coeffs[half + (k - 1) / 2];
}

/// The stwo `fold` reference applied to the interleaved coefficients over the
/// index range [start, start + len). `facs` are the folding factors.
fn foldRange(coeffs: []const M31, half: usize, start: usize, len: usize, facs: []const M31) M31 {
    if (len == 1) return interleavedAt(coeffs, half, start);
    const h = len / 2;
    const lhs = foldRange(coeffs, half, start, h, facs[1..]);
    const rhs = foldRange(coeffs, half, start + h, h, facs[1..]);
    return lhs.add(rhs.mul(facs[0]));
}

/// The point at index `i` of the domain `half_coset ++ half_coset.conjugate()`.
fn domainPoint(half_coset: CircleCoset, i: usize) CirclePoint {
    const half = half_coset.size();
    if (i < half) return half_coset.at(i);
    return half_coset.conjugate().at(i - half);
}

/// Evaluate the circle polynomial `coeffs` (A then B, each of length
/// domain.size()/2) at every point of the domain `half_coset ++ conjugate`,
/// writing `evals[i] = f(domain[i])` in natural order.
pub fn circleFFT(
    allocator: std.mem.Allocator,
    coeffs: []const M31,
    half_coset: CircleCoset,
    evals: []M31,
) !void {
    const n = coeffs.len;
    const half = n / 2;
    std.debug.assert(n >= 2);
    std.debug.assert(evals.len == n);
    std.debug.assert(half_coset.size() == half);
    const lg = std.math.log2_int(usize, n);

    interleave(coeffs[0..half], coeffs[half..n], evals);

    if (lg == 1) {
        const y = half_coset.at(0).y;
        butterfly(&evals[0], &evals[1], y);
    } else if (lg == 2) {
        const p = half_coset.at(0);
        const x = p.x;
        const y = p.y;
        butterfly(&evals[0], &evals[2], x);
        butterfly(&evals[1], &evals[3], x);
        butterfly(&evals[0], &evals[1], y);
        butterfly(&evals[2], &evals[3], y.neg());
    } else {
        const twiddles = try allocator.alloc(M31, half);
        defer allocator.free(twiddles);
        slowPrecomputeTwiddles(half_coset, twiddles);

        // Line layers, largest to smallest.
        var jj: usize = 0;
        while (jj < lg - 1) : (jj += 1) {
            const j = (lg - 2) - jj;
            const slice = lineTwiddleSlice(twiddles, j, lg);
            for (slice, 0..) |t, h| {
                fftLayerLoop(evals, j + 1, h, t, false);
            }
        }

        // Circle layer (layer 0).
        const circle_twiddles = try allocator.alloc(M31, half);
        defer allocator.free(circle_twiddles);
        circleTwiddles(lineTwiddleSlice(twiddles, 0, lg), circle_twiddles);
        for (circle_twiddles, 0..) |t, h| {
            fftLayerLoop(evals, 0, h, t, false);
        }
    }

    bitReverseSlice(evals);
}

/// Evaluate the circle polynomial at a single point (coeffs have length 2^n),
/// using the O(n) fold reference in the FFT basis.
pub fn evalAtPoint(coeffs: []const M31, point: CirclePoint) M31 {
    const n = coeffs.len;
    if (n == 1) return coeffs[0];
    const half = n / 2;
    const lg = std.math.log2_int(usize, n);
    var alphas: [32]M31 = undefined;
    getFoldingAlphas(point, lg, alphas[0..lg]);
    return foldRange(coeffs, half, 0, n, alphas[0..lg]);
}

/// Evaluate the circle polynomial (of order 2^log_size) at every point of a
/// coset, writing into `evals`.
pub fn circleEvalCoset(coeffs: []const M31, coset: CircleCoset, evals: []M31) void {
    std.debug.assert(coeffs.len == evals.len);
    for (0..evals.len) |i| {
        evals[i] = evalAtPoint(coeffs, coset.at(i));
    }
}

/// Interpolate: given `evals` on the domain `half_coset ++ conjugate` (natural
/// order, in the image of `circleFFT`), recover the FFT-basis coefficients (A
/// then B) into `coeffs`.
pub fn circleIFFT(
    allocator: std.mem.Allocator,
    evals: []const M31,
    half_coset: CircleCoset,
    coeffs: []M31,
) !void {
    const n = evals.len;
    const half = n / 2;
    std.debug.assert(n >= 2);
    std.debug.assert(coeffs.len == n);
    std.debug.assert(half_coset.size() == half);
    const lg = std.math.log2_int(usize, n);

    const values = try allocator.alloc(M31, n);
    defer allocator.free(values);
    @memcpy(values, evals);
    bitReverseSlice(values); // natural order -> stwo's bit-reversed input order

    if (lg == 1) {
        const y = half_coset.at(0).y;
        const yn_inv = y.mul(M31.fromInt(2)).inv();
        const y_inv = yn_inv.mul(M31.fromInt(2));
        const n_inv = yn_inv.mul(y);
        var v0 = values[0];
        var v1 = values[1];
        ibutterfly(&v0, &v1, y_inv);
        values[0] = v0.mul(n_inv);
        values[1] = v1.mul(n_inv);
    } else if (lg == 2) {
        const p = half_coset.at(0);
        const x = p.x;
        const y = p.y;
        const xyn_inv = x.mul(y).mul(M31.fromInt(4)).inv();
        const x_inv = xyn_inv.mul(y).mul(M31.fromInt(4));
        const y_inv = xyn_inv.mul(x).mul(M31.fromInt(4));
        const n_inv = xyn_inv.mul(x).mul(y);
        var v0 = values[0];
        var v1 = values[1];
        var v2 = values[2];
        var v3 = values[3];
        ibutterfly(&v0, &v1, y_inv);
        ibutterfly(&v2, &v3, y_inv.neg());
        ibutterfly(&v0, &v2, x_inv);
        ibutterfly(&v1, &v3, x_inv);
        values[0] = v0.mul(n_inv);
        values[1] = v1.mul(n_inv);
        values[2] = v2.mul(n_inv);
        values[3] = v3.mul(n_inv);
    } else {
        const twiddles = try allocator.alloc(M31, half);
        defer allocator.free(twiddles);
        slowPrecomputeTwiddles(half_coset, twiddles);
        for (twiddles) |*t| t.* = t.inv();

        // Circle layer first, then line layers smallest to largest.
        const circle_twiddles = try allocator.alloc(M31, half);
        defer allocator.free(circle_twiddles);
        circleTwiddles(lineTwiddleSlice(twiddles, 0, lg), circle_twiddles);
        for (circle_twiddles, 0..) |t, h| {
            fftLayerLoop(values, 0, h, t, true);
        }
        var j: usize = 0;
        while (j < lg - 1) : (j += 1) {
            const slice = lineTwiddleSlice(twiddles, j, lg);
            for (slice, 0..) |t, h| {
                fftLayerLoop(values, j + 1, h, t, true);
            }
        }

        const inv_n = M31.fromInt(@intCast(n)).inv();
        for (values) |*v| v.* = v.mul(inv_n);
    }

    deinterleave(values, coeffs[0..half], coeffs[half..n]);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn randomCoeffs(rnd: std.Random, allocator: std.mem.Allocator, n: usize) ![]M31 {
    const coeffs = try allocator.alloc(M31, n);
    for (coeffs) |*c| c.* = M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS));
    return coeffs;
}

test "circle FFT matches fold reference" {
    var prng = std.Random.DefaultPrng.init(31);
    const rnd = prng.random();
    var alloc = std.testing.allocator;

    var log_size: u32 = 1;
    while (log_size <= 8) : (log_size += 1) {
        const half_coset = CircleCoset.canonicHalf(log_size);
        const n = half_coset.size() * 2;
        const coeffs = try randomCoeffs(rnd, alloc, n);
        defer alloc.free(coeffs);
        const evals = try alloc.alloc(M31, n);
        defer alloc.free(evals);

        try circleFFT(alloc, coeffs, half_coset, evals);
        for (0..n) |i| {
            try std.testing.expect(evalAtPoint(coeffs, domainPoint(half_coset, i)).eq(evals[i]));
        }
    }
}

test "circle FFT round-trips with IFFT" {
    var prng = std.Random.DefaultPrng.init(31);
    const rnd = prng.random();
    var alloc = std.testing.allocator;

    var log_size: u32 = 1;
    while (log_size <= 8) : (log_size += 1) {
        const half_coset = CircleCoset.canonicHalf(log_size);
        const n = half_coset.size() * 2;
        const coeffs = try randomCoeffs(rnd, alloc, n);
        defer alloc.free(coeffs);
        const evals = try alloc.alloc(M31, n);
        defer alloc.free(evals);
        const recovered = try alloc.alloc(M31, n);
        defer alloc.free(recovered);

        try circleFFT(alloc, coeffs, half_coset, evals);
        try circleIFFT(alloc, evals, half_coset, recovered);
        for (coeffs, recovered) |c, r| {
            try std.testing.expect(c.eq(r));
        }
    }
}

test "circle FFT evaluates known constant" {
    const half_coset = CircleCoset.canonicHalf(3);
    const n = half_coset.size() * 2;
    var alloc = std.testing.allocator;
    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    const evals = try alloc.alloc(M31, n);
    defer alloc.free(evals);

    @memset(coeffs, M31.zero());
    coeffs[0] = M31.fromInt(7); // constant function f(P) = 7
    try circleFFT(alloc, coeffs, half_coset, evals);
    for (evals) |e| {
        try std.testing.expect(e.eq(M31.fromInt(7)));
    }
}

test "circle FFT evaluates x in the FFT basis" {
    const half_coset = CircleCoset.canonicHalf(3);
    const n = half_coset.size() * 2;
    var alloc = std.testing.allocator;
    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    const evals = try alloc.alloc(M31, n);
    defer alloc.free(evals);

    @memset(coeffs, M31.zero());
    coeffs[1] = M31.one(); // A(x) = x, B = 0  =>  f(P) = x_P
    try circleFFT(alloc, coeffs, half_coset, evals);
    for (0..n) |i| {
        try std.testing.expect(evals[i].eq(domainPoint(half_coset, i).x));
    }
}

test "circle FFT evaluates y times constant" {
    const half_coset = CircleCoset.canonicHalf(3);
    const n = half_coset.size() * 2;
    const half = n / 2;
    var alloc = std.testing.allocator;
    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    const evals = try alloc.alloc(M31, n);
    defer alloc.free(evals);

    @memset(coeffs, M31.zero());
    coeffs[half] = M31.fromInt(3); // A = 0, B(x) = 3  =>  f(P) = 3 y_P
    try circleFFT(alloc, coeffs, half_coset, evals);
    for (0..n) |i| {
        try std.testing.expect(evals[i].eq(domainPoint(half_coset, i).y.mul(M31.fromInt(3))));
    }
}

test "circle coset evaluation" {
    const half_coset = CircleCoset.canonicHalf(4);
    const coset = CircleCoset.standard(4);
    const n = half_coset.size() * 2;
    var alloc = std.testing.allocator;
    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    const evals_coset = try alloc.alloc(M31, n);
    defer alloc.free(evals_coset);

    for (coeffs) |*c| c.* = M31.fromInt(1);
    circleEvalCoset(coeffs, coset, evals_coset);
    for (0..n) |i| {
        try std.testing.expect(evals_coset[i].eq(evalAtPoint(coeffs, coset.at(i))));
    }
}
