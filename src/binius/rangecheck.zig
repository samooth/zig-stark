const std = @import("std");
const StarkMod = @import("stark.zig");
const PcsMod = @import("pcs.zig");
const ConstraintDsl = @import("constraints.zig");
/// Range-check gadget for the Binius zero-check STARK.
///
/// Each hypercube point p ∈ {0,1}^k holds one field element `v_p` together with
/// `m` boolean bit columns `b_0..b_{m-1}` for m ≤ F.BITS. The constraint
///
///     v + Σ_{i<m} b_i·e_i = 0        (e_i = fromInt(1<<i), the tower basis)
///
/// pins `v` into the F₂-span of {e_0..e_{m-1}}, i.e. it *is* the m-bit value
/// Σ 2^i·b_i. So a single proof shows every element of the batch satisfies
/// `0 ≤ v < 2^m` — the base case of `BitPack` (which is exactly
/// `RangeCheck(F, E, F.BITS)`). Unlike `BitPack`, only `m` bit columns are
/// committed: the top `F.BITS - m` bits of `v` are forced to zero by the pack
/// equation, giving the range bound.
///
/// Column layout (m + 1 columns): b_0..b_{m-1}, then v.
/// Constraints (m + 1) hold at every point:
///
///   - booleanness (m): b_i + b_i² = 0
///   - pack (1):        v + Σ_i b_i·e_i = 0
pub fn RangeCheck(comptime F: type, comptime E: type, comptime m: usize) type {
    return RangeCheckWith(F, E, m, PcsMod.CommittedMlePcs(F, E));
}

/// The range-check gadget wired into any `BiniusStarkWith` PCS.
pub fn RangeCheckWith(comptime F: type, comptime E: type, comptime m: usize, comptime CP: type) type {
    comptime std.debug.assert(m >= 1);
    comptime std.debug.assert(m <= F.BITS);
    return struct {
        pub const num_bits = m;
        /// The integer type of one checked value (u3 for an [0,8) check on GF(16)).
        pub const UInt = std.meta.Int(.unsigned, m);
        pub const num_columns = m + 1; // b_0..b_{m-1}, v
        pub const num_constraints = m + 1; // m bool + 1 pack

        const Stark = StarkMod.BiniusStarkWith(F, E, CP);
        pub const Monomial = Stark.Monomial;
        pub const Constraint = Stark.Constraint;

        /// Column index of bit i (i in 0..m).
        pub inline fn colBit(i: usize) usize {
            std.debug.assert(i < m);
            return i;
        }

        /// Column index of the checked value.
        pub inline fn colValue() usize {
            return m;
        }

        pub const constraints: [num_constraints]Constraint = blk: {
            var b: ConstraintDsl.Builder(Constraint, num_constraints, 3 * m + 1) = .{ .mono = undefined };
            // Booleanness: every bit column is {0, 1}.
            for (0..m) |i| b.bool(i, colBit(i));
            // Pack: v + Σ_i b_i·e_i = 0 forces v into span{e_0..e_{m-1}}.
            b.add(m, F.one(), &.{colValue()});
            for (0..m) |i| b.add(m, F.fromInt(@as(u128, 1) << @intCast(i)), &.{colBit(i)});
            const data = b.finish();
            var out: [num_constraints]Constraint = undefined;
            var off: usize = 0;
            for (0..num_constraints) |t| {
                out[t] = .{ .terms = data.mono[off .. off + data.cnt[t]] };
                off += data.cnt[t];
            }
            break :blk out;
        };

        /// Witness: `values` holds one `UInt` per hypercube point (each must be
        /// < 2^m); produces the m bit columns plus the packed value column.
        pub fn generateWitness(allocator: std.mem.Allocator, values: []const UInt) ![num_columns][]F {
            const n = values.len;
            var columns: [num_columns][]F = undefined;
            for (0..num_columns) |c| columns[c] = try allocator.alloc(F, n);

            for (0..n) |p| {
                for (0..m) |i| {
                    columns[colBit(i)][p] = F.fromInt((values[p] >> @intCast(i)) & 1);
                }
                columns[colValue()][p] = F.fromInt(values[p]);
            }
            return columns;
        }

        pub fn freeWitness(allocator: std.mem.Allocator, columns: []const []const F) void {
            for (columns) |c| allocator.free(c);
        }

        /// The numeric value of a checked field element (identical to `BitPack`).
        pub inline fn result(v: F) UInt {
            return @as(UInt, @truncate(v.value));
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

test "range check witness decomposes and reconstructs every value" {
    const alloc = std.testing.allocator;
    inline for (.{ Gf16, Gf256 }) |F| {
        const m = 3;
        const R = RangeCheck(F, F, m);
        const n = @as(usize, 1) << @intCast(R.num_bits);
        const values = try alloc.alloc(R.UInt, n);
        defer alloc.free(values);
        for (0..n) |i| values[i] = @intCast(i);

        const columns = try R.generateWitness(alloc, values);
        defer R.freeWitness(alloc, &columns);

        for (0..n) |p| {
            var sum: u128 = 0;
            for (0..R.num_bits) |i| {
                const bit = @as(u128, @intCast((values[p] >> @intCast(i)) & 1));
                try std.testing.expectEqual(bit, columns[R.colBit(i)][p].value);
                sum |= bit << @intCast(i);
            }
            try std.testing.expectEqual(values[p], R.result(columns[R.colValue()][p]));
            try std.testing.expectEqual(sum, columns[R.colValue()][p].value);
        }
    }
}

test "range check STARK round trips and rejects out-of-range values" {
    const alloc = std.testing.allocator;
    const R = RangeCheck(Gf256, Gf256, 3);
    const k = 2;
    const n = @as(usize, 1) << @intCast(k);
    const values = try alloc.alloc(R.UInt, n);
    defer alloc.free(values);
    for (0..n) |i| values[i] = @intCast((i * 3 + 1) % 8);

    const columns = try R.generateWitness(alloc, values);
    defer R.freeWitness(alloc, &columns);

    var proof = try R.Stark.prove(alloc, k, &columns, &R.constraints, &.{}, "range");
    defer proof.deinit(alloc);

    var roots: [R.num_columns]Hash.Digest = undefined;
    for (0..R.num_columns) |c| {
        var tree = try Pcs(Gf256, Gf256).commit(alloc, columns[c]);
        defer tree.deinit();
        roots[c] = tree.root();
    }
    try std.testing.expect(try R.Stark.verify(alloc, k, &roots, &R.constraints, &.{}, proof, "range"));

    // Re-prove over a witness with an out-of-range value (v = 16, top bits
    // set): the pack equation leaves a non-zero residue on the hypercube, so
    // the zero-check sum is non-zero and rejection is guaranteed.
    var tampered: [n]Gf256 = undefined;
    for (0..n) |p| tampered[p] = Gf256.fromInt(16);
    var bad: [R.num_columns][]const Gf256 = undefined;
    for (0..R.num_columns) |c| bad[c] = columns[c];
    bad[R.colValue()] = &tampered;

    var forged = try R.Stark.prove(alloc, k, &bad, &R.constraints, &.{}, "range");
    defer forged.deinit(alloc);

    var bad_roots: [R.num_columns]Hash.Digest = undefined;
    for (0..R.num_columns) |c| {
        var tree = try Pcs(Gf256, Gf256).commit(alloc, bad[c]);
        defer tree.deinit();
        bad_roots[c] = tree.root();
    }
    try std.testing.expect(!try R.Stark.verify(alloc, k, &bad_roots, &R.constraints, &.{}, forged, "range"));
}
