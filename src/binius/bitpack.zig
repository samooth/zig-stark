const std = @import("std");
const StarkMod = @import("stark.zig");
const PcsMod = @import("pcs.zig");
/// Bit-pack gadget for the Binius zero-check STARK.
///
/// Each hypercube point p ∈ {0,1}^k holds one field element `v_p` together with
/// its bit-sliced decomposition into `num_bits = F.BITS` boolean columns
/// `b_0..b_{num_bits-1}`. In a binary tower field the bit string *is* the
/// coefficient vector in the standard basis {e_0, e_1, …}, e_i = fromInt(1<<i),
/// so
///
///     v_p = Σ_i b_i[p]·e_i
///
/// is a field identity: a packed value is exactly its bit decomposition. A
/// single proof verifies all 2^k elements of the batch at once.
///
/// Column layout (num_bits + 1 columns): b_0..b_{num_bits-1}, then v.
/// Constraints (num_bits + 1) hold at every point:
///
///   - booleanness (num_bits): b_i + b_i² = 0
///   - pack (1):               v + Σ_i b_i·e_i = 0
///
/// This is the primitive behind range checks and bit-manipulation gates: any
/// assertion "x is a valid uN whose bits are b" is `pack + booleanness`, so a
/// verifier can commit to bit columns and enforce the packed numeric value.
pub fn BitPack(comptime F: type, comptime E: type) type {
    return BitPackWith(F, E, PcsMod.CommittedMlePcs(F, E));
}

/// The bit-pack gadget wired into any `BiniusStarkWith` PCS.
pub fn BitPackWith(comptime F: type, comptime E: type, comptime CP: type) type {
    return struct {
        pub const num_bits = F.BITS;
        /// The integer type of one packed value (u4 for GF(16), u8 for GF(256)).
        pub const UInt = std.meta.Int(.unsigned, num_bits);
        pub const num_columns = num_bits + 1; // b_0..b_{num_bits-1}, v
        pub const num_constraints = num_bits + 1; // num_bits bool + 1 pack

        const Stark = StarkMod.BiniusStarkWith(F, E, CP);
        pub const Monomial = Stark.Monomial;
        pub const Constraint = Stark.Constraint;

        /// Column index of bit i (i in 0..num_bits).
        pub inline fn colBit(i: usize) usize {
            std.debug.assert(i < num_bits);
            return i;
        }

        /// Column index of the packed value.
        pub inline fn colValue() usize {
            return num_bits;
        }

        pub const constraints: [num_constraints]Constraint = blk: {
            var out: [num_constraints]Constraint = undefined;
            var t: usize = 0;

            // Booleanness: every bit column is {0, 1}.
            for (0..num_bits) |c| {
                const terms = [2]Monomial{
                    .{ .coeff = F.one(), .factors = &.{c} },
                    .{ .coeff = F.one(), .factors = &.{ c, c } },
                };
                out[t] = .{ .terms = &terms };
                t += 1;
            }

            // Pack: v + Σ_i b_i·e_i = 0, with e_i = fromInt(1 << i).
            const pack_terms = inner: {
                var tmp: [num_bits + 1]Monomial = undefined;
                tmp[0] = .{ .coeff = F.one(), .factors = &.{colValue()} };
                for (0..num_bits) |i| {
                    tmp[1 + i] = .{ .coeff = F.fromInt(@as(u128, 1) << @intCast(i)), .factors = &.{colBit(i)} };
                }
                break :inner tmp;
            };
            out[t] = .{ .terms = &pack_terms };
            break :blk out;
        };

        /// Witness: `values` holds one `UInt` per hypercube point; produces the
        /// num_bits bit columns plus the packed value column.
        pub fn generateWitness(allocator: std.mem.Allocator, values: []const UInt) ![num_columns][]F {
            const n = values.len;
            var columns: [num_columns][]F = undefined;
            for (0..num_columns) |c| columns[c] = try allocator.alloc(F, n);

            for (0..n) |p| {
                for (0..num_bits) |i| {
                    columns[colBit(i)][p] = F.fromInt((values[p] >> @intCast(i)) & 1);
                }
                columns[colValue()][p] = F.fromInt(values[p]);
            }
            return columns;
        }

        pub fn freeWitness(allocator: std.mem.Allocator, columns: []const []const F) void {
            for (columns) |c| allocator.free(c);
        }

        /// Unpack a field element to its numeric value (the bit string is the
        /// integer representation in the tower).
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

test "bitpack witness decomposes and reconstructs every value" {
    const alloc = std.testing.allocator;
    inline for (.{ Gf16, Gf256 }) |F| {
        const B = BitPack(F, F);
        const n = @as(usize, 1) << @intCast(B.num_bits);
        const values = try alloc.alloc(B.UInt, n);
        defer alloc.free(values);
        for (0..n) |i| values[i] = @intCast(i);

        const columns = try B.generateWitness(alloc, values);
        defer B.freeWitness(alloc, &columns);

        for (0..n) |p| {
            var sum: u128 = 0;
            for (0..B.num_bits) |i| {
                const bit = @as(u128, @intCast((values[p] >> @intCast(i)) & 1));
                try std.testing.expectEqual(bit, columns[B.colBit(i)][p].value);
                sum |= bit << @intCast(i);
            }
            try std.testing.expectEqual(values[p], B.result(columns[B.colValue()][p]));
            try std.testing.expectEqual(sum, columns[B.colValue()][p].value);
        }
    }
}

test "bitpack STARK round trips over Gf16 and Gf256" {
    const alloc = std.testing.allocator;
    inline for (.{ Gf16, Gf256 }) |F| {
        const B = BitPack(F, F);
        const k = 2;
        const n = @as(usize, 1) << @intCast(k);
        const values = try alloc.alloc(B.UInt, n);
        defer alloc.free(values);
        for (0..n) |i| values[i] = @intCast((i * 37 + 11) % (@as(usize, 1) << @intCast(B.num_bits)));

        const columns = try B.generateWitness(alloc, values);
        defer B.freeWitness(alloc, &columns);

        var proof = try B.Stark.prove(alloc, k, &columns, &B.constraints, &.{}, "bitpack");
        defer proof.deinit(alloc);

        var roots: [B.num_columns]Hash.Digest = undefined;
        for (0..B.num_columns) |c| {
            var tree = try Pcs(F, F).commit(alloc, columns[c]);
            defer tree.deinit();
            roots[c] = tree.root();
        }
        try std.testing.expect(try B.Stark.verify(alloc, k, &roots, &B.constraints, &.{}, proof, "bitpack"));
    }
}

test "bitpack STARK rejects a forged non-boolean witness" {
    const alloc = std.testing.allocator;
    const B = BitPack(Gf256, Gf256);
    const k = 2;
    const n = @as(usize, 1) << @intCast(k);
    const values = try alloc.alloc(B.UInt, n);
    defer alloc.free(values);
    for (0..n) |i| values[i] = @intCast((i * 5 + 3) % 256);

    const columns = try B.generateWitness(alloc, values);
    defer B.freeWitness(alloc, &columns);

    // Re-prove over a witness whose bit-0 column is 2 everywhere: the
    // booleanness violation is a non-zero constant on the hypercube, so the
    // zero-check sum is α ≠ 0 and rejection is guaranteed for any α ≠ 0.
    var tampered: [n]Gf256 = undefined;
    for (0..n) |p| tampered[p] = Gf256.fromInt(2);
    var bad: [B.num_columns][]const Gf256 = undefined;
    for (0..B.num_columns) |c| bad[c] = columns[c];
    bad[B.colBit(0)] = &tampered;

    var forged = try B.Stark.prove(alloc, k, &bad, &B.constraints, &.{}, "bitpack");
    defer forged.deinit(alloc);

    var roots: [B.num_columns]Hash.Digest = undefined;
    for (0..B.num_columns) |c| {
        var tree = try Pcs(Gf256, Gf256).commit(alloc, bad[c]);
        defer tree.deinit();
        roots[c] = tree.root();
    }
    try std.testing.expect(!try B.Stark.verify(alloc, k, &roots, &B.constraints, &.{}, forged, "bitpack"));
}
