const std = @import("std");
const StarkMod = @import("stark.zig");
const PcsMod = @import("pcs.zig");
const CoreHash = @import("../core/hash/hash.zig");
/// Bit-sliced ripple-carry adder gadget for the Binius zero-check STARK.
///
/// Each hypercube point p ∈ {0,1}^k holds one independent 4-bit addition
/// `x_p + y_p = s_p`, so a single proof verifies all 2^k additions in one
/// batch. Column layout (16 columns, indices below):
///
///     a_0..a_3,  b_0..b_3,  s_0..s_3,  c_1..c_4
///
/// with the incoming carry c_0 = 0 baked into the first carry constraint (so
/// there is no c_0 column). Sixteen constraints hold at every point:
///
///   - booleanness (8):  a_i + a_i² = 0, b_i + b_i² = 0
///   - sum, XOR (4):     s_i + a_i + b_i + c_i = 0
///   - carry (4):        c_{i+1} + a_i b_i + a_i c_i + b_i c_i = 0
///
/// This is the classic demonstration of why binary fields fit Boolean circuits:
/// XOR is field addition and the majority carry is a sum of three degree-2
/// monomials, with no carry-propagation cost in the constraint system.
pub fn Adder(comptime F: type, comptime E: type) type {
    return struct {
        pub const num_bits = 4;
        pub const num_columns = 4 * num_bits; // a, b, s, c (c_0 implicit)
        pub const num_constraints = 4 * num_bits; // 8 bool + 4 sum + 4 carry

        const Stark = StarkMod.BiniusStark(F, E, num_columns);
        pub const Monomial = Stark.Monomial;
        pub const Constraint = Stark.Constraint;

        pub inline fn colA(i: usize) usize {
            std.debug.assert(i < num_bits);
            return i;
        }
        pub inline fn colB(i: usize) usize {
            std.debug.assert(i < num_bits);
            return num_bits + i;
        }
        pub inline fn colS(i: usize) usize {
            std.debug.assert(i < num_bits);
            return 2 * num_bits + i;
        }
        /// Carry column c_i for i in 1..num_bits (c_0 = 0 is implicit).
        pub inline fn colC(i: usize) usize {
            std.debug.assert(i >= 1 and i <= num_bits);
            return 3 * num_bits + i - 1;
        }

        /// The full constraint system, fixed at comptime.
        pub const constraints: [num_constraints]Constraint = blk: {
            var out: [num_constraints]Constraint = undefined;
            var t: usize = 0;

            // Booleanness: every input bit column is {0,1}.
            for (0..2 * num_bits) |c| {
                const terms = [2]Monomial{
                    .{ .coeff = F.one(), .factors = &.{c} },
                    .{ .coeff = F.one(), .factors = &.{ c, c } },
                };
                out[t] = .{ .terms = &terms };
                t += 1;
            }

            // Sum: s_i + a_i + b_i + c_i = 0 (c_0 = 0 drops the carry term).
            for (0..num_bits) |i| {
                const terms = if (i == 0)
                    &[_]Monomial{
                        .{ .coeff = F.one(), .factors = &.{colS(0)} },
                        .{ .coeff = F.one(), .factors = &.{colA(0)} },
                        .{ .coeff = F.one(), .factors = &.{colB(0)} },
                    }
                else
                    &[_]Monomial{
                        .{ .coeff = F.one(), .factors = &.{colS(i)} },
                        .{ .coeff = F.one(), .factors = &.{colA(i)} },
                        .{ .coeff = F.one(), .factors = &.{colB(i)} },
                        .{ .coeff = F.one(), .factors = &.{colC(i)} },
                    };
                out[t] = .{ .terms = terms };
                t += 1;
            }

            // Carry: c_{i+1} + a_i b_i + a_i c_i + b_i c_i = 0 (c_0 = 0).
            for (0..num_bits) |i| {
                const terms = if (i == 0)
                    &[_]Monomial{
                        .{ .coeff = F.one(), .factors = &.{colC(1)} },
                        .{ .coeff = F.one(), .factors = &.{ colA(0), colB(0) } },
                    }
                else
                    &[_]Monomial{
                        .{ .coeff = F.one(), .factors = &.{colC(i + 1)} },
                        .{ .coeff = F.one(), .factors = &.{ colA(i), colB(i) } },
                        .{ .coeff = F.one(), .factors = &.{ colA(i), colC(i) } },
                        .{ .coeff = F.one(), .factors = &.{ colB(i), colC(i) } },
                    };
                out[t] = .{ .terms = terms };
                t += 1;
            }
            break :blk out;
        };

        /// Generate the witness columns for a batch of `n = x.len` additions:
        /// columns[c][p] holds bit c of instance p's adder.
        pub fn generateWitness(allocator: std.mem.Allocator, x: []const u4, y: []const u4) ![num_columns][]F {
            const n = x.len;
            std.debug.assert(y.len == n);
            var columns: [num_columns][]F = undefined;
            for (0..num_columns) |c| columns[c] = try allocator.alloc(F, n);

            for (0..n) |p| {
                var carry: u1 = 0;
                for (0..num_bits) |i| {
                    const ai: u1 = @intCast((x[p] >> @intCast(i)) & 1);
                    const bi: u1 = @intCast((y[p] >> @intCast(i)) & 1);
                    const si: u1 = ai ^ bi ^ carry;
                    const carry_next: u1 = (ai & bi) | (ai & carry) | (bi & carry);
                    columns[colA(i)][p] = F.fromInt(ai);
                    columns[colB(i)][p] = F.fromInt(bi);
                    columns[colS(i)][p] = F.fromInt(si);
                    if (i >= 1) columns[colC(i)][p] = F.fromInt(carry);
                    carry = carry_next;
                }
                columns[colC(num_bits)][p] = F.fromInt(carry);
            }
            return columns;
        }

        pub fn freeWitness(allocator: std.mem.Allocator, columns: []const []const F) void {
            for (columns) |c| allocator.free(c);
        }

        /// The numeric 5-bit result of one addition (16·c_4 + Σ_i 2^i·s_i).
        pub fn result(x: u4, y: u4) u8 {
            var carry: u1 = 0;
            var out: u8 = 0;
            for (0..num_bits) |i| {
                const ai: u1 = @intCast((x >> @intCast(i)) & 1);
                const bi: u1 = @intCast((y >> @intCast(i)) & 1);
                const si: u1 = ai ^ bi ^ carry;
                const carry_next: u1 = (ai & bi) | (ai & carry) | (bi & carry);
                out |= @as(u8, si) << @intCast(i);
                carry = carry_next;
            }
            out |= @as(u8, carry) << @intCast(num_bits);
            return out;
        }

        /// Numeric result of every instance in the batch.
        pub fn results(x: []const u4, y: []const u4, out: []u8) void {
            for (x, y, out) |xv, yv, *o| o.* = result(xv, yv);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Gf16 = @import("tower.zig").Gf16;
const Gf256 = @import("tower.zig").Gf256;
const TowerField = @import("tower.zig").TowerField;
const Gf2_128 = TowerField(7);

test "adder witness satisfies the constraints for all 256 input pairs" {
    inline for (.{ Gf16, Gf256 }) |F| {
        const A = Adder(F, F);
        for (0..16) |xv| {
            for (0..16) |yv| {
                try std.testing.expectEqual(@as(u8, @intCast(xv + yv)), A.result(@intCast(xv), @intCast(yv)));
            }
        }
    }
}

test "adder bit relations match a reference bit-sliced addition" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const A = Adder(Gf16, Gf16);

    const x = [_]u4{ 10, 0, 15, 8, 3 };
    const y = [_]u4{ 7, 0, 1, 8, 13 };
    const columns = try A.generateWitness(alloc, &x, &y);

    var out: [5]u8 = undefined;
    A.results(&x, &y, &out);
    for (0..5) |p| {
        try std.testing.expectEqual(@as(u8, x[p]) + @as(u8, y[p]), out[p]);
        // s bits + final carry reconstruct the numeric sum.
        var got: u8 = 0;
        for (0..A.num_bits) |i| {
            const si = columns[A.colS(i)][p];
            got |= @as(u8, @intCast(si.value)) << @intCast(i);
        }
        got |= @as(u8, @intCast(columns[A.colC(A.num_bits)][p].value)) << @intCast(A.num_bits);
        try std.testing.expectEqual(out[p], got);
    }
}

test "adder STARK round trips over the GF(2^128) extension" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const A = Adder(Gf16, Gf2_128);
    const CP = PcsMod.CommittedMlePcs(Gf16, Gf2_128);

    const k = 2;
    const x = [_]u4{ 10, 0, 15, 8 };
    const y = [_]u4{ 7, 0, 1, 8 };
    const columns = try A.generateWitness(alloc, &x, &y);

    var roots: [A.num_columns]CoreHash.Hash.Digest = undefined;
    for (0..A.num_columns) |c| {
        var tree = try CP.commit(alloc, columns[c]);
        defer tree.deinit();
        roots[c] = tree.root();
    }

    const proof = try A.Stark.prove(alloc, k, &columns, &A.constraints, &.{}, "");
    try std.testing.expect(try A.Stark.verify(alloc, k, &roots, &A.constraints, &.{}, proof, ""));
}
