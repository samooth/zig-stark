const std = @import("std");
const Polynomial = @import("polynomial.zig");
const SumcheckMod = @import("sumcheck.zig");

/// Multilinear evaluation protocol for a binary field `F`.
///
/// Proves the claim `y = f(r)` for a multilinear polynomial `f` supplied as
/// its 2^k hypercube evaluation table, by sum-checking the identity
///
///     f(r) = Σ_{x ∈ {0,1}^k} f(x) · β_r(x),
///
/// where β_r(x) = ∏_j ℓ_j(x_j) is the Lagrange kernel for the point `r` and
/// each ℓ_j(t) = t + (1 + r_j) is a univariate linear polynomial (char 2).
/// The composed summand is the product of the k+1 multilinear polynomials
/// `f, ℓ_0, …, ℓ_{k-1}`, so the existing `Sumcheck` applies directly.
///
/// The query point `r` is bound into the Fiat-Shamir transcript (SHA256) before
/// any challenge is derived, so a later commitment layer can seed the same
/// transcript with a Merkle root and the protocol becomes a polynomial
/// commitment scheme. In this module the verifier holds the table and recomputes
/// the final MLE value itself.
pub fn MlePcs(comptime F: type) type {
    return struct {
        const Self = @This();
        const Multilinear = Polynomial.Multilinear(F);
        const SC = SumcheckMod.Sumcheck(F);

        pub const Proof = struct {
            value: F,
            sumcheck: SC.Proof,
        };

        /// Deterministic transcript seed binding the query point `r`.
        fn seedFor(k: usize, r: []const F) [128]u8 {
            var buf = [_]u8{0} ** 128;
            var n: usize = 0;
            var b: [F.SIZE]u8 = undefined;
            for (r[0..k]) |v| {
                v.toBytes(&b);
                @memcpy(buf[n..][0..F.SIZE], &b);
                n += F.SIZE;
            }
            return buf;
        }

        /// Build the k univariate Lagrange-basis tables ℓ_j, each of length
        /// 2^k with entry i = bit_j(i) + (1 + r_j). Caller frees the returned
        /// slice and each inner table.
        pub fn kernelTables(
            allocator: std.mem.Allocator,
            k: usize,
            r: []const F,
        ) ![][]F {
            std.debug.assert(r.len == k);
            const n = @as(usize, 1) << @intCast(k);
            const tables = try allocator.alloc([]F, k);
            errdefer allocator.free(tables);
            for (0..k) |j| {
                tables[j] = try allocator.alloc(F, n);
                errdefer allocator.free(tables[j]);
                const rj = r[j];
                for (0..n) |i| {
                    const bit: u8 = @intFromBool((i >> @intCast(j)) & 1 == 1);
                    tables[j][i] = F.fromInt(bit).add(F.one().add(rj));
                }
            }
            return tables;
        }

        /// Lagrange kernel β_r(x) = ∏_j (x_j + 1 + r_j), for boolean x.
        pub fn kernelValue(r: []const F, x: []const F) F {
            var acc = F.one();
            for (r, x) |rj, xj| {
                acc = acc.mul(xj.add(F.one().add(rj)));
            }
            return acc;
        }

        /// Prover: evaluate `f` at `r` and produce a sum-check proof of
        /// `y = f(r)` over the composed product `f(x)·∏_j ℓ_j(x_j)`.
        pub fn proveEval(
            allocator: std.mem.Allocator,
            k: usize,
            table: []const F,
            r: []const F,
        ) !Proof {
            std.debug.assert(table.len == (@as(usize, 1) << @intCast(k)));
            const p = Multilinear{ .evals = table };
            const value = try p.eval(allocator, r);

            const kt = try kernelTables(allocator, k, r);
            defer {
                for (kt) |t| allocator.free(t);
                allocator.free(kt);
            }

            const tables = try allocator.alloc([]const F, k + 1);
            defer allocator.free(tables);
            tables[0] = table;
            for (0..k) |j| tables[j + 1] = kt[j];

            const seed = seedFor(k, r);
            const sp = try SC.proveSeeded(allocator, k, tables, &seed);
            return .{ .value = value, .sumcheck = sp };
        }

        /// Verifier: check the round equations, recompute the final MLE value
        /// of `f·∏ℓ_j` at the challenge point from the table, and confirm the
        /// claimed `value` really is `f(r)`.
        pub fn verifyEval(
            allocator: std.mem.Allocator,
            k: usize,
            table: []const F,
            r: []const F,
            proof: Proof,
        ) !bool {
            std.debug.assert(table.len == (@as(usize, 1) << @intCast(k)));

            const kt = try kernelTables(allocator, k, r);
            defer {
                for (kt) |t| allocator.free(t);
                allocator.free(kt);
            }

            const tables = try allocator.alloc([]const F, k + 1);
            defer allocator.free(tables);
            tables[0] = table;
            for (0..k) |j| tables[j + 1] = kt[j];

            const seed = seedFor(k, r);
            const ok = try SC.verifySeeded(allocator, k, tables, proof.sumcheck, &seed);
            if (!ok) return false;

            const p = Multilinear{ .evals = table };
            const value = try p.eval(allocator, r);
            return proof.value.eq(value);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Gf16 = @import("field.zig").Gf16;
const P = MlePcs(Gf16);

fn fe(x: u128) Gf16 {
    return Gf16.fromInt(x);
}

test "kernel identity equals multilinear extension at a point" {
    const alloc = std.testing.allocator;
    const k = 3;
    var table: [8]Gf16 = undefined;
    for (0..8) |i| table[i] = fe((i * 5 + 2) % 16);

    const r = [_]Gf16{ fe(3), fe(7), fe(1) };
    const mle = @import("polynomial.zig").Multilinear(Gf16){ .evals = &table };
    const expected = try mle.eval(alloc, &r);

    // Direct boolean-hypercube sum of f(x)·β_r(x)
    var sum = Gf16.zero();
    for (0..8) |i| {
        var x: [3]Gf16 = undefined;
        for (0..k) |j| x[j] = fe(@intFromBool((i >> @intCast(j)) & 1 == 1));
        sum = sum.add(table[i].mul(P.kernelValue(&r, &x)));
    }
    try std.testing.expectEqual(expected.value, sum.value);
}

test "kernelTables match kernelValue on boolean points" {
    const alloc = std.testing.allocator;
    const k = 2;
    const r = [_]Gf16{ fe(3), fe(5) };
    const kt = try P.kernelTables(alloc, k, &r);
    defer {
        for (kt) |t| alloc.free(t);
        alloc.free(kt);
    }
    for (0..4) |i| {
        var x: [2]Gf16 = undefined;
        for (0..2) |j| x[j] = fe(@intFromBool((i >> @intCast(j)) & 1 == 1));
        // product of ℓ_j entries at index i equals β_r(x)
        var acc = Gf16.one();
        for (0..k) |j| acc = acc.mul(kt[j][i]);
        try std.testing.expectEqual(P.kernelValue(&r, &x).value, acc.value);
    }
}

test "mle evaluation round trips for k=1..4" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    inline for (.{ 1, 2, 3, 4 }) |k| {
        const n = @as(usize, 1) << @intCast(k);
        var table: [16]Gf16 = undefined;
        for (0..n) |i| table[i] = fe((i * 7 + k * 3) % 16);

        var r: [4]Gf16 = undefined;
        for (0..k) |j| r[j] = fe((j * 3 + 5) % 16);

        const proof = try P.proveEval(alloc, k, table[0..n], r[0..k]);
        try std.testing.expect(try P.verifyEval(alloc, k, table[0..n], r[0..k], proof));
    }
}

test "tampered value or claimed sum fails verification" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const k = 3;
    var table: [8]Gf16 = undefined;
    for (0..8) |i| table[i] = fe((i * 7 + 1) % 16);
    const r = [_]Gf16{ fe(3), fe(7), fe(1) };

    const proof = try P.proveEval(alloc, k, &table, &r);
    try std.testing.expect(try P.verifyEval(alloc, k, &table, &r, proof));

    const bad_value = P.Proof{ .value = proof.value.add(fe(1)), .sumcheck = proof.sumcheck };
    try std.testing.expect(!try P.verifyEval(alloc, k, &table, &r, bad_value));

    const bad_sum = P.Proof{ .value = proof.value, .sumcheck = .{
        .claimed_sum = proof.sumcheck.claimed_sum.add(fe(1)),
        .rounds = proof.sumcheck.rounds,
    } };
    try std.testing.expect(!try P.verifyEval(alloc, k, &table, &r, bad_sum));
}

test "tampered table fails verification" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const k = 3;
    var table: [8]Gf16 = undefined;
    for (0..8) |i| table[i] = fe((i * 7 + 1) % 16);
    const r = [_]Gf16{ fe(3), fe(7), fe(1) };

    const proof = try P.proveEval(alloc, k, &table, &r);

    var other: [8]Gf16 = table;
    other[4] = other[4].add(fe(1));
    try std.testing.expect(!try P.verifyEval(alloc, k, &other, &r, proof));
}
