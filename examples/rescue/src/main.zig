const std = @import("std");
const qm31 = @import("zig-stark").qm31;
const m31 = @import("zig-stark").m31;
const channel = @import("zig-stark").channel;
const stark = @import("zig-stark").stark;
const univariate = @import("zig-stark").univariate;

const QM31 = qm31.QM31;
const M31 = m31.M31;
const UnivariateQM31 = univariate.UnivariateQM31;

/// Number of state elements (rate + capacity).
const s = 4;
/// Trace length: the trace stores n states; n - 1 rescue rounds are applied.
const n = 8;
const num_rounds = n - 1;

/// Rescue-Prime-style MDS matrix: circulant with first row (2, 3, 1, 1).
const mds = [s][s]u32{
    .{ 2, 3, 1, 1 },
    .{ 1, 2, 3, 1 },
    .{ 1, 1, 2, 3 },
    .{ 3, 1, 1, 2 },
};

/// Deterministic round constants, generated once at comptime.
const rc: [num_rounds][s]QM31 = blk: {
    var seed: u64 = 0x243f6a8885a308d3;
    var out: [num_rounds][s]QM31 = undefined;
    for (0..num_rounds) |r| {
        for (0..s) |j| {
            seed = seed *% 6364136223846793005 +% 1442695040888963407;
            out[r][j] = QM31.fromM31(M31.fromInt(@truncate(seed >> 33)));
        }
    }
    break :blk out;
};

/// One Rescue round: sbox (x^5), MDS linear layer, then round constants.
fn applyRound(r: usize, state: [s]QM31) [s]QM31 {
    var boxed: [s]QM31 = undefined;
    for (0..s) |j| boxed[j] = state[j].pow(5);
    var lin: [s]QM31 = undefined;
    for (0..s) |j| {
        var acc = QM31.zero();
        for (0..s) |l| acc = acc.add(boxed[l].mul(QM31.fromM31(M31.fromInt(mds[j][l]))));
        lin[j] = acc;
    }
    for (0..s) |j| lin[j] = lin[j].add(rc[r][j]);
    return lin;
}

/// AIR for the Rescue permutation: each trace step applies one round.
///
/// The sbox is x^5, so the transition constraints are degree-5 polynomials in
/// the columns; as polynomials in the evaluation point x (with columns of
/// degree < n) they have degree 5*(n - 1), which is why the STARK's FRI
/// commitment must be sized from `maxConstraintDegree` rather than the trace
/// length (see `src/stark/stark.zig`).
///
/// The round constants depend on the row, so they are interpolated over the
/// trace subgroup H: rc_poly[j](w^r) = rc[r][j] for the enforced rows
/// r < n - 1. Only the forward sbox is used: the M31 inverse sbox x -> x^(1/5)
/// is a high-degree polynomial that cannot appear in a low-degree constraint.
const RescueAir = struct {
    pub const num_columns = s;
    pub const num_transition_constraints = s;
    pub const num_boundary = 2 * s;

    pub const PublicInputs = struct {
        initial: [s]QM31,
        final: [s]QM31,
    };

    var rc_poly: [s][]QM31 = undefined;
    var rc_ready = false;
    var rc_alloc: std.mem.Allocator = undefined;

    pub fn deinit() void {
        if (rc_ready) {
            for (rc_poly) |p| rc_alloc.free(p);
        }
        rc_ready = false;
    }

    /// Interpolate the per-column round-constant polynomials once. Must be
    /// called before `prove`/`verify` (both sides need the same polynomials).
    pub fn prepare(allocator: std.mem.Allocator) !void {
        if (rc_ready) return;
        rc_alloc = allocator;

        const log = std.math.log2_int(usize, n);
        const w = QM31.primitiveRootOfUnity(@as(u64, @intCast(log)));
        const h = try allocator.alloc(QM31, n);
        defer allocator.free(h);
        var acc = QM31.one();
        for (0..n) |r| {
            h[r] = acc;
            acc = acc.mul(w);
        }

        for (0..s) |j| {
            const ys = try allocator.alloc(QM31, n);
            defer allocator.free(ys);
            for (0..n) |r| {
                ys[r] = if (r < num_rounds) rc[r][j] else QM31.zero();
            }
            rc_poly[j] = try allocator.alloc(QM31, n);
            try UnivariateQM31.interpolate(allocator, h, ys, rc_poly[j]);
        }
        rc_ready = true;
    }

    pub fn evalTransition(x: QM31, current: []const QM31, next: []const QM31, out: []QM31) void {
        std.debug.assert(rc_ready);
        for (0..s) |j| {
            var expect = QM31.zero();
            for (0..s) |l| {
                expect = expect.add(current[l].pow(5).mul(QM31.fromM31(M31.fromInt(mds[j][l]))));
            }
            expect = expect.add(UnivariateQM31.eval(rc_poly[j], x));
            out[j] = next[j].sub(expect);
        }
    }

    pub fn boundaryAssertions(public: PublicInputs, n_rows: usize, out: []stark.BoundaryAssertion) void {
        for (0..s) |j| {
            out[j] = .{ .column = j, .step = 0, .value = public.initial[j] };
            out[s + j] = .{ .column = j, .step = n_rows - 1, .value = public.final[j] };
        }
    }

    pub fn maxConstraintDegree(n_rows: usize) usize {
        return 5 * (n_rows - 1);
    }

    pub fn generateTrace(allocator: std.mem.Allocator, initial: [s]QM31) ![]const []const QM31 {
        const cols = try allocator.alloc([]const QM31, s);
        var bufs: [s][]QM31 = undefined;
        for (0..s) |j| bufs[j] = try allocator.alloc(QM31, n);
        var state = initial;
        for (0..n) |r| {
            for (0..s) |j| bufs[j][r] = state[j];
            if (r < num_rounds) state = applyRound(r, state);
        }
        for (0..s) |j| cols[j] = bufs[j];
        return cols;
    }

    pub fn freeTrace(allocator: std.mem.Allocator, trace: []const []const QM31) void {
        for (trace) |col| allocator.free(col);
        allocator.free(trace);
    }
};

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    const alloc = gpa.allocator();

    try RescueAir.prepare(alloc);
    defer RescueAir.deinit();

    const initial: [s]QM31 = .{
        QM31.fromM31(M31.fromInt(1)),
        QM31.fromM31(M31.fromInt(2)),
        QM31.fromM31(M31.fromInt(3)),
        QM31.fromM31(M31.fromInt(4)),
    };

    // Directly apply num_rounds rounds to obtain the claimed final state.
    var state = initial;
    for (0..num_rounds) |r| state = applyRound(r, state);
    const final_state = state;

    const params = stark.StarkParams{
        .trace_log = 3,
        .log_blowup = 3,
        .num_queries = 16,
        .remainder_log = 3,
    };
    const Stark = stark.GenericStark(RescueAir);

    const trace = try RescueAir.generateTrace(alloc, initial);
    defer RescueAir.freeTrace(alloc, trace);

    var pchan = channel.Channel.init("zig-stark:rescue:example");
    var proof = try Stark.prove(alloc, params, .{ .initial = initial, .final = final_state }, trace, &pchan);
    defer proof.deinit();

    var vchan = channel.Channel.init("zig-stark:rescue:example");
    const ok = try Stark.verify(alloc, params, .{ .initial = initial, .final = final_state }, &proof, &vchan);

    std.debug.print("initial state:  ", .{});
    for (initial) |v| std.debug.print("{} ", .{v.a.c0.value});
    std.debug.print("\n", .{});
    std.debug.print("final state:    ", .{});
    for (final_state) |v| std.debug.print("{} ", .{v.a.c0.value});
    std.debug.print("\n", .{});
    std.debug.print("verifier accepted proof: {any}\n", .{ok});
    if (!ok) return error.VerificationFailed;

    // A forged final state must be rejected.
    var forged_chan = channel.Channel.init("zig-stark:rescue:example");
    var bad_final = final_state;
    bad_final[0] = bad_final[0].add(QM31.one());
    const bad_ok = try Stark.verify(alloc, params, .{ .initial = initial, .final = bad_final }, &proof, &forged_chan);
    std.debug.print("verifier rejected forged final state: {any}\n", .{!bad_ok});
    if (bad_ok) return error.ForgedClaimAccepted;

    std.debug.print("claim matches direct round computation\n", .{});
}
