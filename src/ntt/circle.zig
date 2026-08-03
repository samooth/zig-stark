const std = @import("std");
const M31 = @import("../field/m31.zig").M31;
const CircleDomain = @import("../circle/domain.zig").CircleDomain;
const CirclePoint = @import("../circle/point.zig").CirclePoint;
const CircleCoset = @import("../circle/coset.zig").CircleCoset;
const Univariate = @import("../poly/univariate.zig").Univariate;

/// Circle transforms over M31.
///
/// A "circle polynomial" on the order-2^n subgroup is written as
///     f(P) = A(x_P) + y_P * B(x_P)
/// with deg A, B < 2^(n-1). Its coefficient encoding is the concatenation of
/// A's coefficients (length 2^(n-1)) followed by B's (length 2^(n-1)),
/// total length 2^n — the same as the number of domain points.
///
/// NOTE: the evaluation map (A, B) -> (values on subgroup) has a 1-dimensional
/// kernel (the subspace is not all functions), so interpolation from values is
/// only defined up to that kernel. These routines return a canonical lift; any
/// lift round-trips back to the same values.
///
/// The implementations below are naive (O(n * 2^n)). An O(n log n) circle FFT
/// is planned (see TODO.md).
fn evalPoly(a: []const M31, b: []const M31, point: CirclePoint) M31 {
    return Univariate.eval(a, point.x).add(Univariate.eval(b, point.x).mul(point.y));
}

/// Evaluate the circle polynomial `coeffs` (A then B, each of length
/// domain.size()/2) at every point of `domain`, writing into `evals`.
pub fn circleFFT(coeffs: []const M31, domain: CircleDomain, evals: []M31) void {
    const n = domain.size();
    const half = n / 2;
    std.debug.assert(coeffs.len == n);
    std.debug.assert(evals.len == n);
    const a = coeffs[0..half];
    const b = coeffs[half..n];
    for (0..n) |i| {
        evals[i] = evalPoly(a, b, domain.get(i));
    }
}

/// Evaluate the circle polynomial at a single point (coeffs have length 2^n).
pub fn evalAtPoint(coeffs: []const M31, point: CirclePoint) M31 {
    const half = coeffs.len / 2;
    return evalPoly(coeffs[0..half], coeffs[half..], point);
}

/// Evaluate the circle polynomial (of order 2^log_size) at every point of a
/// coset, writing into `evals`.
pub fn circleEvalCoset(coeffs: []const M31, coset: CircleCoset, evals: []M31) void {
    const n = coset.size();
    const half = coeffs.len / 2;
    std.debug.assert(coeffs.len == n);
    std.debug.assert(evals.len == n);
    const a = coeffs[0..half];
    const b = coeffs[half..];
    for (0..n) |i| {
        evals[i] = evalPoly(a, b, coset.at(i));
    }
}

/// Interpolate: given `evals` on `domain` (which lie in the image of
/// `circleFFT`), recover canonical coefficients (A then B) into `coeffs`.
pub fn circleIFFT(
    allocator: std.mem.Allocator,
    evals: []const M31,
    domain: CircleDomain,
    coeffs: []M31,
) !void {
    const n = domain.size();
    const half = n / 2;
    std.debug.assert(evals.len == n);
    std.debug.assert(coeffs.len == n);

    const xs = try allocator.alloc(M31, half);
    defer allocator.free(xs);
    const a_vals = try allocator.alloc(M31, half);
    defer allocator.free(a_vals);
    const b_vals = try allocator.alloc(M31, half);
    defer allocator.free(b_vals);

    const inv_two = M31.fromInt(2).inv();
    for (0..half) |i| {
        const p = domain.get(i);
        xs[i] = p.x;
        // Same-x pair: P_i = (x, y) and P_{N-i} = (x, -y).
        // A(x) = (f(P) + f(-P)) / 2
        const neg = if (i == 0) @as(usize, 0) else n - i;
        a_vals[i] = evals[i].add(evals[neg]).mul(inv_two);
    }

    // B(x) = (f(P) - f(-P)) / (2 y_P). The value at the identity's x is a
    // free parameter (y = 0 there); choose 0 as the canonical lift.
    b_vals[0] = M31.zero();
    for (1..half) |i| {
        const p = domain.get(i);
        const two_y = p.y.mul(M31.fromInt(2));
        b_vals[i] = evals[i].sub(evals[n - i]).mul(two_y.inv());
    }

    try Univariate.interpolate(allocator, xs, a_vals, coeffs[0..half]);
    try Univariate.interpolate(allocator, xs, b_vals, coeffs[half..n]);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "circle FFT round-trips with IFFT" {
    var prng = std.Random.DefaultPrng.init(31);
    const rnd = prng.random();
    var alloc = std.testing.allocator;

    var log_size: u32 = 2;
    while (log_size <= 6) : (log_size += 1) {
        const dom = CircleDomain.standard(log_size);
        const n = dom.size();
        const coeffs = try alloc.alloc(M31, n);
        defer alloc.free(coeffs);
        const evals = try alloc.alloc(M31, n);
        defer alloc.free(evals);
        const recovered = try alloc.alloc(M31, n);
        defer alloc.free(recovered);

        for (coeffs) |*c| c.* = M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS));

        circleFFT(coeffs, dom, evals);
        try circleIFFT(alloc, evals, dom, recovered);
        // re-evaluate the recovered coefficients and compare
        const evals2 = try alloc.alloc(M31, n);
        defer alloc.free(evals2);
        circleFFT(recovered, dom, evals2);
        for (evals, evals2) |e1, e2| {
            try std.testing.expect(e1.eq(e2));
        }
    }
}

test "circle FFT evaluates known constant" {
    const dom = CircleDomain.standard(3);
    const n = dom.size();
    const half = n / 2;
    var alloc = std.testing.allocator;
    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    const evals = try alloc.alloc(M31, n);
    defer alloc.free(evals);

    @memset(coeffs[0..half], M31.zero());
    @memset(coeffs[half..n], M31.zero());
    coeffs[0] = M31.fromInt(7); // constant function f(P) = 7
    circleFFT(coeffs, dom, evals);
    for (evals) |e| {
        try std.testing.expect(e.eq(M31.fromInt(7)));
    }
}

test "circle FFT evaluates linear-in-x polynomial" {
    const dom = CircleDomain.standard(3);
    const n = dom.size();
    const half = n / 2;
    var alloc = std.testing.allocator;
    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    const evals = try alloc.alloc(M31, n);
    defer alloc.free(evals);

    @memset(coeffs[0..half], M31.zero());
    @memset(coeffs[half..n], M31.zero());
    coeffs[0] = M31.zero();
    coeffs[1] = M31.one(); // f(P) = x_P
    circleFFT(coeffs, dom, evals);
    for (0..n) |i| {
        try std.testing.expect(evals[i].eq(dom.get(i).x));
    }
}

test "circle FFT evaluates y times constant" {
    const dom = CircleDomain.standard(3);
    const n = dom.size();
    const half = n / 2;
    var alloc = std.testing.allocator;
    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    const evals = try alloc.alloc(M31, n);
    defer alloc.free(evals);

    @memset(coeffs[0..half], M31.zero());
    @memset(coeffs[half..n], M31.zero());
    coeffs[half] = M31.fromInt(3); // f(P) = 3 y_P
    circleFFT(coeffs, dom, evals);
    for (0..n) |i| {
        try std.testing.expect(evals[i].eq(dom.get(i).y.mul(M31.fromInt(3))));
    }
}

test "circle coset evaluation" {
    const dom = CircleDomain.standard(4);
    const coset = CircleCoset.standard(4);
    const n = dom.size();
    var alloc = std.testing.allocator;
    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    const evals_coset = try alloc.alloc(M31, n);
    defer alloc.free(evals_coset);

    // simple polynomial f(P) = x_P^2
    @memset(coeffs, M31.zero());
    coeffs[2] = M31.one();
    circleEvalCoset(coeffs, coset, evals_coset);
    for (0..n) |i| {
        const p = coset.at(i);
        try std.testing.expect(evals_coset[i].eq(p.x.mul(p.x)));
    }
}

test "circle evalAtPoint matches circleFFT" {
    const dom = CircleDomain.standard(4);
    const n = dom.size();
    var alloc = std.testing.allocator;
    const coeffs = try alloc.alloc(M31, n);
    defer alloc.free(coeffs);
    const evals = try alloc.alloc(M31, n);
    defer alloc.free(evals);

    for (coeffs) |*c| c.* = M31.fromInt(1);
    circleFFT(coeffs, dom, evals);
    for (0..n) |i| {
        try std.testing.expect(evalAtPoint(coeffs, dom.get(i)).eq(evals[i]));
    }
}
