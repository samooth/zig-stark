const std = @import("std");
const qm31 = @import("zig-stark").qm31;
const m31 = @import("zig-stark").m31;
const channel = @import("zig-stark").channel;
const stark = @import("zig-stark").stark;
const univariate = @import("zig-stark").univariate;

const QM31 = qm31.QM31;
const M31 = m31.M31;
const UnivariateQM31 = univariate.UnivariateQM31;

/// A single linear layer of a neural network: y = w . x  (a dot product of a
/// fixed weight vector `w` with a public input vector `x`).
///
/// The trace is a single accumulator column of length n = w.len: at row r it
/// holds the running partial dot product sum_{l<r} w_l * x_l. The transition
/// is row-dependent (each step adds w_r * x_r), so it is expressed as a
/// polynomial in the evaluation point: the increments are interpolated on the
/// trace subgroup H and the constraint
///
///     C(x) = acc(w*x) - acc(x) - inc(x)
///
/// vanishes on H exactly when the accumulator follows the recurrence.
const LinearAir = struct {
    pub const num_columns = 1;
    pub const num_transition_constraints = 1;
    pub const num_boundary = 2;

    const n = 8;
    const weights = [n]QM31{
        QM31.fromM31(M31.fromInt(1)),
        QM31.fromM31(M31.fromInt(2)),
        QM31.fromM31(M31.fromInt(3)),
        QM31.fromM31(M31.fromInt(4)),
        QM31.fromM31(M31.fromInt(5)),
        QM31.fromM31(M31.fromInt(6)),
        QM31.fromM31(M31.fromInt(7)),
        QM31.fromM31(M31.fromInt(8)),
    };

    pub const PublicInputs = struct {
        x: []const QM31,
        claimed_y: QM31,
    };

    // Increment polynomial inc(x): the interpolation over H of r -> w_r * x_r.
    var inc_coeffs: []QM31 = undefined;
    var inc_ready = false;
    var inc_alloc: std.mem.Allocator = undefined;

    pub fn deinit() void {
        if (inc_ready) inc_alloc.free(inc_coeffs);
        inc_ready = false;
    }

    /// Interpolate the row-dependent increments once. Must be called before
    /// `prove`/`verify` (both sides need the same polynomial).
    pub fn prepare(allocator: std.mem.Allocator, public: PublicInputs) !void {
        if (inc_ready) return;
        std.debug.assert(public.x.len == n);
        inc_alloc = allocator;

        const w = QM31.primitiveRootOfUnity(@intCast(@as(u32, @intCast(std.math.log2_int(usize, n)))));

        const h = try allocator.alloc(QM31, n);
        defer allocator.free(h);
        var acc = QM31.one();
        for (0..n) |r| {
            h[r] = acc;
            acc = acc.mul(w);
        }

        const ys = try allocator.alloc(QM31, n);
        defer allocator.free(ys);
        // Increment applied when stepping row r -> r+1 is w_{r+1} * x_{r+1}.
        // (The value at r = n-1 is never checked: the STARK composition
        // multiplies transitions by (x - w^{n-1}).)
        for (0..n) |r| ys[r] = weights[(r + 1) % n].mul(public.x[(r + 1) % n]);

        inc_coeffs = try allocator.alloc(QM31, n);
        try UnivariateQM31.interpolate(allocator, h, ys, inc_coeffs);
        inc_ready = true;
    }

    pub fn evalTransition(x: QM31, current: []const QM31, next: []const QM31, out: []QM31) void {
        std.debug.assert(inc_ready);
        out[0] = next[0].sub(current[0]).sub(UnivariateQM31.eval(inc_coeffs, x));
    }

    pub fn boundaryAssertions(public: PublicInputs, n_rows: usize, out: []stark.BoundaryAssertion) void {
        std.debug.assert(n_rows == n);
        out[0] = .{ .column = 0, .step = 0, .value = weights[0].mul(public.x[0]) };
        out[1] = .{ .column = 0, .step = n - 1, .value = public.claimed_y };
    }

    pub fn generateTrace(allocator: std.mem.Allocator, x: []const QM31) ![]const []const QM31 {
        std.debug.assert(x.len == n);
        const cols = try allocator.alloc([]const QM31, num_columns);
        const acc = try allocator.alloc(QM31, n);
        var sum = QM31.zero();
        for (0..n) |r| {
            sum = sum.add(weights[r].mul(x[r]));
            acc[r] = sum;
        }
        cols[0] = acc;
        return cols;
    }

    pub fn freeTrace(allocator: std.mem.Allocator, trace: []const []const QM31) void {
        for (trace) |col| allocator.free(col);
        allocator.free(trace);
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    const x = try alloc.alloc(QM31, LinearAir.n);
    defer alloc.free(x);
    for (0..LinearAir.n) |i| x[i] = QM31.fromM31(M31.fromInt(@intCast(i + 1)));

    const y = try computeY(x);
    const claimed_y = y;

    try LinearAir.prepare(alloc, .{ .x = x, .claimed_y = claimed_y });
    defer LinearAir.deinit();

    const params = stark.StarkParams{
        .trace_log = 3,
        .log_blowup = 3,
        .num_queries = 16,
        .remainder_log = 3,
    };
    const Stark = stark.GenericStark(LinearAir);

    const trace = try LinearAir.generateTrace(alloc, x);
    defer LinearAir.freeTrace(alloc, trace);

    var pchan = channel.Channel.init("zig-stark:ml_linear:example");
    var proof = try Stark.prove(alloc, params, .{ .x = x, .claimed_y = claimed_y }, trace, &pchan);
    defer proof.deinit();

    var vchan = channel.Channel.init("zig-stark:ml_linear:example");
    const ok = try Stark.verify(alloc, params, .{ .x = x, .claimed_y = claimed_y }, &proof, &vchan);

    std.debug.print("inputs:        ", .{});
    for (x) |xv| std.debug.print("{} ", .{xv.a.c0.value});
    std.debug.print("\n", .{});
    std.debug.print("weights:       ", .{});
    for (LinearAir.weights) |wv| std.debug.print("{} ", .{wv.a.c0.value});
    std.debug.print("\n", .{});
    std.debug.print("claimed y:     {d}\n", .{claimed_y.a.c0.value});
    std.debug.print("verifier accepted proof: {any}\n", .{ok});
    if (!ok) return error.VerificationFailed;

    // A forged claim (y + 1) must be rejected.
    var forged_chan = channel.Channel.init("zig-stark:ml_linear:example");
    const bad_y = claimed_y.add(QM31.one());
    const bad_ok = try Stark.verify(alloc, params, .{ .x = x, .claimed_y = bad_y }, &proof, &forged_chan);
    std.debug.print("verifier rejected forged claim: {any}\n", .{!bad_ok});
    if (bad_ok) return error.ForgedClaimAccepted;

    // The STARK claim should match a direct field-arithmetic computation.
    if (!claimed_y.eq(y)) return error.ClaimMismatch;
    std.debug.print("claim matches direct computation\n", .{});
}

fn computeY(x: []const QM31) !QM31 {
    std.debug.assert(x.len == LinearAir.n);
    var sum = QM31.zero();
    for (0..LinearAir.n) |r| sum = sum.add(LinearAir.weights[r].mul(x[r]));
    return sum;
}
