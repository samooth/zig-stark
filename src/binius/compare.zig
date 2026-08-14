const std = @import("std");
const StarkMod = @import("stark.zig");
const PcsMod = @import("pcs.zig");
const ConstraintDsl = @import("constraints.zig");
/// Bit-sliced comparison gadget for the Binius zero-check STARK.
///
/// Each hypercube point p ∈ {0,1}^k holds one pair of m-bit values `(x_p, y_p)`
/// and proves `x_p < y_p` for all 2^k instances in one batch. Ordering is not a
/// field-invariant property, so it is built bitwise from the top down:
///
///   - eq_i = "bits i+1..m-1 of x and y are equal"  (eq_m = 1)
///   - lt_i = "x < y decided by bits i..m-1"
///       lt_i = lt_{i+1} ∨ ((a_i,b_i) = (0,1) ∧ eq_{i+1})    (lt_m = 0)
///
/// The zero-check evaluates constraints at a random challenge τ via the kernel
/// identity Σ_x C(x)·β_τ(x) = C(τ) (with Σ_x β_τ(x) = 1), so constant terms —
/// the eq_m = 1 base — are enforceable, unlike a plain hypercube sum where a
/// constant integrates to zero in char 2. Written as polynomials (an AND as a
/// product, and XOR as field addition since a_i ≠ b_i is 1 + a_i + b_i):
///
///   - eq (m):  eq_i + eq_{i+1}·(1 + a_i + b_i) = 0        (eq_m = 1 baked in)
///   - lt (m):  lt_i + lt_{i+1} + eq_{i+1}·(b_i + a_i·b_i) = 0   (lt_m = 0)
///
/// Column layout (4·m columns): a_0..a_{m-1}, b_0..b_{m-1}, eq_0..eq_{m-1},
/// lt_0..lt_{m-1}. Constraints (4·m) hold at every point: booleanness on a and
/// b (2·m), the eq recurrence (m), and the lt recurrence (m). The eq and lt
/// columns are forced boolean by their recurrences, so only a and b need
/// explicit booleanness. The result is lt_0 (`colLt(0)`).
pub fn Compare(comptime F: type, comptime E: type, comptime m: usize) type {
    return CompareWith(F, E, m, PcsMod.CommittedMlePcs(F, E));
}

/// The comparison gadget wired into any `BiniusStarkWith` PCS.
pub fn CompareWith(comptime F: type, comptime E: type, comptime m: usize, comptime CP: type) type {
    comptime std.debug.assert(m >= 1);
    comptime std.debug.assert(m <= F.BITS);
    return struct {
        pub const num_bits = m;
        /// The integer type of one compared value.
        pub const UInt = std.meta.Int(.unsigned, m);
        pub const num_columns = 4 * m; // a, b, eq, lt
        pub const num_constraints = 4 * m; // 2m bool + m eq + m lt

        const Stark = StarkMod.BiniusStarkWith(F, E, CP);
        pub const Monomial = Stark.Monomial;
        pub const Constraint = Stark.Constraint;

        /// Column index of bit i of x (i in 0..m).
        pub inline fn colA(i: usize) usize {
            std.debug.assert(i < m);
            return i;
        }
        /// Column index of bit i of y (i in 0..m).
        pub inline fn colB(i: usize) usize {
            std.debug.assert(i < m);
            return m + i;
        }
        /// Column index of "bits i+1..m-1 equal" (i in 0..m).
        pub inline fn colEq(i: usize) usize {
            std.debug.assert(i < m);
            return 2 * m + i;
        }
        /// Column index of "x < y decided by bits i..m-1" (i in 0..m);
        /// `colLt(0)` is the comparison result.
        pub inline fn colLt(i: usize) usize {
            std.debug.assert(i < m);
            return 3 * m + i;
        }

        pub const constraints: [num_constraints]Constraint = blk: {
            var b: ConstraintDsl.Builder(Constraint, num_constraints, 14 * m) = .{ .mono = undefined };
            // Booleanness: the input bit columns are {0, 1}.
            for (0..m) |i| {
                b.bool(i, colA(i));
                b.bool(m + i, colB(i));
            }
            // eq recurrence: eq_i + eq_{i+1}(1 + a_i + b_i) = 0; for i = m-1
            // the eq_m = 1 base is a constant term (empty factors).
            for (0..m) |i| {
                const t = 2 * m + i;
                b.add(t, F.one(), &.{colEq(i)});
                if (i + 1 < m) {
                    b.add(t, F.one(), &.{colEq(i + 1)});
                    b.add(t, F.one(), &.{ colEq(i + 1), colA(i) });
                    b.add(t, F.one(), &.{ colEq(i + 1), colB(i) });
                } else {
                    b.add(t, F.one(), &.{});
                    b.add(t, F.one(), &.{colA(i)});
                    b.add(t, F.one(), &.{colB(i)});
                }
            }
            // lt recurrence: lt_i + lt_{i+1} + eq_{i+1}(b_i + a_i·b_i) = 0;
            // for i = m-1 the eq_m = 1 base drops the eq_{i+1} factors.
            for (0..m) |i| {
                const t = 3 * m + i;
                b.add(t, F.one(), &.{colLt(i)});
                if (i + 1 < m) {
                    b.add(t, F.one(), &.{colLt(i + 1)});
                    b.add(t, F.one(), &.{ colEq(i + 1), colB(i) });
                    b.add(t, F.one(), &.{ colEq(i + 1), colA(i), colB(i) });
                } else {
                    b.add(t, F.one(), &.{colB(i)});
                    b.add(t, F.one(), &.{ colA(i), colB(i) });
                }
            }
            const data = b.finish();
            var out: [num_constraints]Constraint = undefined;
            var off: usize = 0;
            for (0..num_constraints) |t| {
                out[t] = .{ .terms = data.mono[off .. off + data.cnt[t]] };
                off += data.cnt[t];
            }
            break :blk out;
        };

        /// Witness: `x` and `y` hold one `UInt` per hypercube point; produces
        /// the a, b, eq, and lt columns for all pairs.
        pub fn generateWitness(allocator: std.mem.Allocator, x: []const UInt, y: []const UInt) ![num_columns][]F {
            const n = x.len;
            std.debug.assert(y.len == n);
            var columns: [num_columns][]F = undefined;
            for (0..num_columns) |c| columns[c] = try allocator.alloc(F, n);

            for (0..n) |p| {
                var eq_acc: u1 = 1; // eq_m
                var lt_acc: u1 = 0; // lt_m
                var i = m;
                while (i > 0) {
                    i -= 1;
                    const ai: u1 = @intCast((x[p] >> @intCast(i)) & 1);
                    const bi: u1 = @intCast((y[p] >> @intCast(i)) & 1);
                    columns[colA(i)][p] = F.fromInt(ai);
                    columns[colB(i)][p] = F.fromInt(bi);
                    // lt_i = lt_{i+1} ∨ ((a_i,b_i)=(0,1) ∧ eq_{i+1}).
                    const at_low: u1 = if (ai == 0 and bi == 1) 1 else 0;
                    lt_acc = lt_acc ^ (at_low & eq_acc);
                    // eq_i = eq_{i+1} ∧ (a_i = b_i).
                    eq_acc = eq_acc & (1 ^ (ai ^ bi));
                    columns[colEq(i)][p] = F.fromInt(eq_acc);
                    columns[colLt(i)][p] = F.fromInt(lt_acc);
                }
            }
            return columns;
        }

        pub fn freeWitness(allocator: std.mem.Allocator, columns: []const []const F) void {
            for (columns) |c| allocator.free(c);
        }

        /// The result of one comparison (1 if x < y else 0).
        pub fn result(x: UInt, y: UInt) u1 {
            var eq_acc: u1 = 1;
            var lt_acc: u1 = 0;
            var i = m;
            while (i > 0) {
                i -= 1;
                const ai: u1 = @intCast((x >> @intCast(i)) & 1);
                const bi: u1 = @intCast((y >> @intCast(i)) & 1);
                const at_low: u1 = if (ai == 0 and bi == 1) 1 else 0;
                lt_acc = lt_acc ^ (at_low & eq_acc);
                eq_acc = eq_acc & (1 ^ (ai ^ bi));
            }
            return lt_acc;
        }

        /// Result of every comparison in the batch.
        pub fn results(x: []const UInt, y: []const UInt, out: []u1) void {
            for (x, y, out) |xv, yv, *o| o.* = result(xv, yv);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Gf16 = @import("tower.zig").Gf16;
const Gf256 = @import("tower.zig").Gf256;
const Hash = @import("../core/hash/hash.zig").Hash;
const Pcs = @import("pcs.zig").CommittedMlePcs;

test "compare result matches a reference less-than for all pairs" {
    inline for (.{ Gf16, Gf256 }) |F| {
        const C = Compare(F, F, 3);
        for (0..8) |xv| {
            for (0..8) |yv| {
                const expect: u1 = if (xv < yv) 1 else 0;
                try std.testing.expectEqual(expect, C.result(@intCast(xv), @intCast(yv)));
            }
        }
    }
}

test "compare witness columns carry the correct eq/lt chains" {
    const alloc = std.testing.allocator;
    const C = Compare(Gf16, Gf16, 3);

    const x = [_]u3{ 0, 1, 7, 2, 5, 6 };
    const y = [_]u3{ 1, 0, 7, 7, 2, 3 };
    const columns = try C.generateWitness(alloc, &x, &y);
    defer C.freeWitness(alloc, &columns);

    var out: [6]u1 = undefined;
    C.results(&x, &y, &out);
    for (0..6) |p| {
        try std.testing.expectEqual(out[p], columns[C.colLt(0)][p].value);
        // eq_i/lt_i are bits by construction.
        for (0..C.num_bits) |i| {
            try std.testing.expect(columns[C.colEq(i)][p].value < 2);
            try std.testing.expect(columns[C.colLt(i)][p].value < 2);
        }
        // Reconstruct x and y from the bit columns.
        var rx: u128 = 0;
        var ry: u128 = 0;
        for (0..C.num_bits) |i| {
            rx |= columns[C.colA(i)][p].value << @intCast(i);
            ry |= columns[C.colB(i)][p].value << @intCast(i);
        }
        try std.testing.expectEqual(@as(u128, x[p]), rx);
        try std.testing.expectEqual(@as(u128, y[p]), ry);
    }
}

test "compare STARK round trips and rejects an unordered witness" {
    const alloc = std.testing.allocator;
    const C = Compare(Gf256, Gf256, 4);
    const k = 2;
    const n = @as(usize, 1) << @intCast(k);
    const x = try alloc.alloc(C.UInt, n);
    const y = try alloc.alloc(C.UInt, n);
    defer {
        alloc.free(x);
        alloc.free(y);
    }
    for (0..n) |i| {
        x[i] = @intCast(i);
        y[i] = @intCast(i + 1);
    }

    const columns = try C.generateWitness(alloc, x, y);
    defer C.freeWitness(alloc, &columns);

    var proof = try C.Stark.prove(alloc, k, &columns, &C.constraints, &.{}, "cmp");
    defer proof.deinit(alloc);

    var roots: [C.num_columns]Hash.Digest = undefined;
    for (0..C.num_columns) |c| {
        var tree = try Pcs(Gf256, Gf256).commit(alloc, columns[c]);
        defer tree.deinit();
        roots[c] = tree.root();
    }
    try std.testing.expect(try C.Stark.verify(alloc, k, &roots, &C.constraints, &.{}, proof, "cmp"));

    // Swap the a and b columns: now x > y at every point, so the lt_0 residue
    // is the non-zero constant 1 on the hypercube. The zero-check sum is
    // Σ_x 1·β_τ(x) = 1 ≠ 0 (kernel identity), so rejection is guaranteed.
    var bad: [C.num_columns][]const Gf256 = undefined;
    for (0..C.num_columns) |c| bad[c] = columns[c];
    for (0..C.num_bits) |i| {
        const tmp = bad[C.colA(i)];
        bad[C.colA(i)] = bad[C.colB(i)];
        bad[C.colB(i)] = tmp;
    }

    var forged = try C.Stark.prove(alloc, k, &bad, &C.constraints, &.{}, "cmp");
    defer forged.deinit(alloc);

    var bad_roots: [C.num_columns]Hash.Digest = undefined;
    for (0..C.num_columns) |c| {
        var tree = try Pcs(Gf256, Gf256).commit(alloc, bad[c]);
        defer tree.deinit();
        bad_roots[c] = tree.root();
    }
    try std.testing.expect(!try C.Stark.verify(alloc, k, &bad_roots, &C.constraints, &.{}, forged, "cmp"));
}
