const std = @import("std");
const Polynomial = @import("polynomial.zig");
const SumcheckMod = @import("sumcheck.zig");
const CoreHash = @import("../core/hash/hash.zig");
const CoreMerkle = @import("../core/merkle/merkle.zig");

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
        pub fn seedFor(k: usize, r: []const F) [128]u8 {
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

        /// Result of the evaluation sum-check: the value and its proof.
        pub const EvalSumcheck = struct {
            value: F,
            sumcheck: SC.Proof,
        };

        /// Run the sum-check proving `y = f(r)` over the composed product
        /// `f(x)·∏_j ℓ_j(x_j)`, with the query point bound into the transcript.
        pub fn evalSumcheck(
            allocator: std.mem.Allocator,
            k: usize,
            table: []const F,
            r: []const F,
        ) !EvalSumcheck {
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

        /// Prover: evaluate `f` at `r` and produce a sum-check proof of
        /// `y = f(r)`.
        pub fn proveEval(
            allocator: std.mem.Allocator,
            k: usize,
            table: []const F,
            r: []const F,
        ) !Proof {
            const es = try evalSumcheck(allocator, k, table, r);
            return .{ .value = es.value, .sumcheck = es.sumcheck };
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

/// Committed multilinear PCS: binds an MLE table to a Merkle root and proves
/// evaluations at points. The proof carries the evaluation sum-check plus an
/// opening of every table entry (each leaf is one entry), so the verifier
/// recomputes `f` at the challenge point from committed data and the
/// sum-check + Schwartz-Zippel pins the prover's polynomial to the committed
/// one.
///
/// Proof size is O(2^k) (one Merkle path per entry): this is the simple,
/// fully sound construction over a plain Merkle tree. Sub-linear openings
/// require a packed / folded commitment (Binius's tower, Zeromorph-style
/// folding) and are a separate layer.
pub fn CommittedMlePcs(comptime F: type) type {
    return struct {
        const SC = SumcheckMod.Sumcheck(F);
        const M = MlePcs(F);
        const Hash = CoreHash.Hash;
        const MerkleTree = CoreMerkle.MerkleTree;
        const MerkleVerify = CoreMerkle.verify;

        pub const Proof = struct {
            value: F,
            sumcheck: SC.Proof,
            /// The 2^k opened leaves (the evaluation table) and one Merkle
            /// path per leaf, both indexed by the hypercube point.
            entries: []const F,
            paths: [][]Hash.Digest,
        };

        fn hashElement(v: F) Hash.Digest {
            var buf: [F.SIZE]u8 = undefined;
            v.toBytes(&buf);
            return Hash.hashBytes(&buf);
        }

        /// Commit a 2^k table: one Merkle leaf per evaluation.
        pub fn commit(allocator: std.mem.Allocator, table: []const F) !MerkleTree {
            const leaves = try allocator.alloc(Hash.Digest, table.len);
            defer allocator.free(leaves);
            for (table, 0..) |v, i| leaves[i] = hashElement(v);
            return MerkleTree.init(allocator, leaves);
        }

        /// Prover: evaluate `f` at `r` and open every committed leaf.
        pub fn proveEval(
            allocator: std.mem.Allocator,
            k: usize,
            table: []const F,
            r: []const F,
        ) !Proof {
            const n = @as(usize, 1) << @intCast(k);
            std.debug.assert(table.len == n);
            const es = try M.evalSumcheck(allocator, k, table, r);

            var tree = try commit(allocator, table);
            defer tree.deinit();
            const paths = try allocator.alloc([]Hash.Digest, n);
            errdefer allocator.free(paths);
            for (0..n) |i| paths[i] = try tree.open(i, allocator);

            return .{
                .value = es.value,
                .sumcheck = es.sumcheck,
                .entries = table,
                .paths = paths,
            };
        }

        /// Verifier: check the sum-check rounds, verify every opened leaf
        /// against the root, and recompute `f(r)` and `f(r')` from the
        /// committed entries.
        pub fn verifyEval(
            allocator: std.mem.Allocator,
            root: Hash.Digest,
            k: usize,
            r: []const F,
            proof: Proof,
        ) !bool {
            const n = @as(usize, 1) << @intCast(k);
            if (proof.entries.len != n or proof.paths.len != n) return false;
            if (proof.sumcheck.rounds.len != k) return false;

            const seed = M.seedFor(k, r);
            const rr = (try SC.runRounds(allocator, &seed, proof.sumcheck.claimed_sum, proof.sumcheck.rounds)) orelse return false;
            defer allocator.free(rr.challenges);

            for (0..n) |i| {
                const h = hashElement(proof.entries[i]);
                if (!MerkleVerify(root, i, h, proof.paths[i])) return false;
            }

            // f(p) = Σ_x β_p(x) f(x) for p = r and p = r'.
            var x: [64]F = undefined;
            var f_rprime = F.zero();
            var f_r = F.zero();
            for (0..n) |i| {
                for (0..k) |j| x[j] = F.fromInt(@intFromBool((i >> @intCast(j)) & 1 == 1));
                const beta_r = M.kernelValue(r, x[0..k]);
                const beta_rp = M.kernelValue(rr.challenges, x[0..k]);
                f_r = f_r.add(beta_r.mul(proof.entries[i]));
                f_rprime = f_rprime.add(beta_rp.mul(proof.entries[i]));
            }

            if (!f_r.eq(proof.value)) return false;
            return f_rprime.mul(M.kernelValue(r, rr.challenges)).eq(rr.current_sum);
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

const CP = CommittedMlePcs(Gf16);

test "committed pcs round trips for k=1..4 against the root" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    inline for (.{ 1, 2, 3, 4 }) |k| {
        const n = @as(usize, 1) << @intCast(k);
        var table: [16]Gf16 = undefined;
        for (0..n) |i| table[i] = fe((i * 9 + k * 5) % 16);

        var tree = try CP.commit(alloc, table[0..n]);
        const root = tree.root();

        var r: [4]Gf16 = undefined;
        for (0..k) |j| r[j] = fe((j * 11 + 2) % 16);

        const proof = try CP.proveEval(alloc, k, table[0..n], r[0..k]);
        try std.testing.expect(try CP.verifyEval(alloc, root, k, r[0..k], proof));
    }
}

test "committed pcs rejects wrong value, wrong root, tampered entries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const k = 3;
    var table: [8]Gf16 = undefined;
    for (0..8) |i| table[i] = fe((i * 9 + 2) % 16);
    const r = [_]Gf16{ fe(3), fe(7), fe(1) };

    var tree = try CP.commit(alloc, &table);
    const root = tree.root();

    const proof = try CP.proveEval(alloc, k, &table, &r);
    try std.testing.expect(try CP.verifyEval(alloc, root, k, &r, proof));

    // wrong claimed value
    const bad_value = CP.Proof{ .value = proof.value.add(fe(1)), .sumcheck = proof.sumcheck, .entries = proof.entries, .paths = proof.paths };
    try std.testing.expect(!try CP.verifyEval(alloc, root, k, &r, bad_value));

    // wrong root (different table committed)
    var other: [8]Gf16 = table;
    other[3] = other[3].add(fe(1));
    const other_tree = try CP.commit(alloc, &other);
    try std.testing.expect(!try CP.verifyEval(alloc, other_tree.root(), k, &r, proof));

    // tampered entry that fails the merkle opening
    var forged = CP.Proof{ .value = proof.value, .sumcheck = proof.sumcheck, .entries = proof.entries, .paths = proof.paths };
    const forged_entries = try alloc.dupe(Gf16, proof.entries);
    forged_entries[5] = forged_entries[5].add(fe(1));
    forged.entries = forged_entries;
    try std.testing.expect(!try CP.verifyEval(alloc, root, k, &r, forged));
}
