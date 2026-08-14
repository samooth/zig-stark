const std = @import("std");

/// Tiny comptime constraint-assembly DSL shared by the Binius gadget modules.
///
/// Every gadget exposes `constraints: [num_constraints]Stark.Constraint` built
/// at comptime; hand-assembling those repeats "open slot `t`, fill its terms,
/// bump `t`". `Builder` front-loads that bookkeeping:
///
///     const Stark = StarkMod.BiniusStarkWith(F, E, CP);
///     const constraints: [n]Stark.Constraint = blk: {
///         var b: constraints.Builder(Stark.Constraint, n, max_terms) = .{ .mono = undefined };
///         b.bool(t, col);             // appends w_col + w_col²
///         b.add(t, coeff, &.{col});   // appends coeff·w_col
///         const data = b.finish();
///         var out: [n]Stark.Constraint = undefined;
///         var off: usize = 0;
///         for (0..n) |t| {
///             out[t] = .{ .terms = data.mono[off .. off + data.cnt[t]] };
///             off += data.cnt[t];
///         }
///         break :blk out;
///     };
///
/// `max_terms` is a comptime upper bound on the total number of monomials
/// (asserted during construction). The monomial pool is handed out through the
/// comptime `const` returned by `finish()`, so the term slices stay
/// comptime-known and can live in a global `constraints` value.
pub fn Builder(comptime C: type, comptime n: usize, comptime max_terms: usize) type {
    const Monomial = std.meta.Elem(@FieldType(C, "terms"));
    const F = @FieldType(Monomial, "coeff");
    return struct {
        const Self = @This();

        mono: [max_terms]Monomial,
        cnt: [n]usize = [_]usize{0} ** n,
        total: usize = 0,

        /// Append the monomial `coeff·∏_{f∈factors} w_f` to constraint `t`.
        pub fn add(self: *Self, t: usize, coeff: F, factors: []const usize) void {
            std.debug.assert(self.total < max_terms);
            const i = self.total;
            self.mono[i] = .{ .coeff = coeff, .factors = factors };
            self.total += 1;
            self.cnt[t] += 1;
        }

        /// Append the booleanity pair `w_col + w_col²` (enforces w_col ∈ {0,1}).
        pub fn @"bool"(self: *Self, t: usize, col: usize) void {
            self.add(t, F.one(), &.{col});
            self.add(t, F.one(), &.{ col, col });
        }

        /// Copy the monomial pool out as a comptime `const` (the builder `var`
        /// itself can't be referenced by a global `constraints`).
        pub fn finish(self: *const Self) struct { mono: [max_terms]Monomial, cnt: [n]usize } {
            return .{ .mono = self.mono, .cnt = self.cnt };
        }
    };
}

/// Compose a gadget's constraints into `b` starting at constraint slot `t0`,
/// remapping every factor column index by `col_offset`. Composing gadgets in
/// one proof just appends each gadget's columns, so its factor indices shift
/// by the running column count:
///
///     // columns = rangecheck.columns ++ compare.columns
///     const combined = blk: {
///         var b: constraints.Builder(Constraint, total_n, max_terms) = .{ .mono = undefined };
///         constraints.shiftInto(b, 0, 0, RangeCheck.constraints);
///         constraints.shiftInto(b, RangeCheck.num_constraints, RangeCheck.num_columns, Compare.constraints);
///         const data = b.finish();
///         var out: [total_n]Constraint = undefined;
///         var off: usize = 0;
///         for (0..total_n) |t| {
///             out[t] = .{ .terms = data.mono[off .. off + data.cnt[t]] };
///             off += data.cnt[t];
///         }
///         break :blk out;
///     };
pub fn shiftInto(comptime B: type, b: *B, comptime t0: usize, comptime col_offset: usize, comptime src: anytype) void {
    const C = @TypeOf(src[0]);
    const Monomial = std.meta.Elem(@FieldType(C, "terms"));
    const F = @FieldType(Monomial, "coeff");
    for (src, 0..) |con, t| {
        for (con.terms) |mono| {
            const shifted: [mono.factors.len]usize = blk: {
                var tmp: [mono.factors.len]usize = undefined;
                for (mono.factors, 0..) |f, k| tmp[k] = f + col_offset;
                break :blk tmp;
            };
            b.add(t0 + t, @as(F, mono.coeff), &shifted);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const StarkMod = @import("stark.zig");
const Gf256 = @import("tower.zig").Gf256;
const Hash = @import("../core/hash/hash.zig").Hash;
const Pcs = @import("pcs.zig").CommittedMlePcs;

test "zero-check supports constant terms (empty monomial factors)" {
    // A constraint `w + 1 = 0` (w must be 1 everywhere) needs a constant term.
    // The zero-check evaluates at a random τ via Σ_x C(x)·β_τ(x) = C(τ) with
    // Σ_x β_τ(x) = 1, so the constant is enforceable (it would vanish under a
    // plain hypercube sum in char 2).
    const alloc = std.testing.allocator;
    const Stark = StarkMod.BiniusStark(Gf256, Gf256);
    const k = 2;
    const n = @as(usize, 1) << @intCast(k);

    const cs = [_]Stark.Constraint{.{
        .terms = &[_]Stark.Monomial{
            .{ .coeff = Gf256.one(), .factors = &.{0} },
            .{ .coeff = Gf256.one(), .factors = &.{} },
        },
    }};
    var w: [n]Gf256 = undefined;
    for (0..n) |i| w[i] = Gf256.one();
    const columns = [_][]const Gf256{&w};

    var proof = try Stark.prove(alloc, k, &columns, &cs, &.{}, "ct");
    defer proof.deinit(alloc);
    var roots: [1]Hash.Digest = undefined;
    {
        var tree = try Pcs(Gf256, Gf256).commit(alloc, columns[0]);
        defer tree.deinit();
        roots[0] = tree.root();
    }
    try std.testing.expect(try Stark.verify(alloc, k, &roots, &cs, &.{}, proof, "ct"));
}
