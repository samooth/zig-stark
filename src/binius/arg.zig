const std = @import("std");
const SumcheckMod = @import("sumcheck.zig");
const PcsMod = @import("pcs.zig");
const CoreHash = @import("../core/hash/hash.zig");

/// End-to-end Binius-style argument for a product-sum over committed MLEs.
///
/// Proves the claim
///
///     H = Σ_{x ∈ {0,1}^k} ∏_{j=1}^m f_j(x)
///
/// where each `f_j` is a multilinear polynomial supplied as its 2^k
/// hypercube table, and only the Merkle roots of the tables are public.
///
/// The protocol composes the two layers:
///
///   1. Sum-check over the product ∏ f_j, seeded by the Merkle roots. This
///      reduces the claim to the MLE evaluations f_j(τ) at the challenge
///      point τ (the verifier checks `∏_j f_j(τ) == current_sum`).
///   2. For each table, a committed MLE evaluation proof at τ via
///      `CommittedMlePcs` (Merkle opening of the entries + Schwartz-Zippel
///      pinning of the polynomial to the committed one).
///
/// This is the core of a Binius prover: commit witness columns, prove a
/// hypercube sum of their products, and open the few MLE evaluations the
/// sum-check leaves the verifier with.
pub fn BiniusArg(comptime F: type, comptime max_tables: usize) type {
    return struct {
        const SC = SumcheckMod.Sumcheck(F);
        const CP = PcsMod.CommittedMlePcs(F, F);
        const Hash = CoreHash.Hash;

        pub const MaxTables = max_tables;

        pub const EvalProof = struct {
            value: F,
            pcs: CP.Proof,
        };

        pub const Proof = struct {
            claimed_sum: F,
            main: SC.Proof,
            evals: []const EvalProof,
        };

        /// Seed the main sum-check transcript with the Merkle roots so the
        /// challenges are bound to the committed tables.
        fn seedForRoots(roots: []const Hash.Digest) [32]u8 {
            std.debug.assert(roots.len <= MaxTables);
            var buf: [MaxTables * 32]u8 = undefined;
            var n: usize = 0;
            for (roots) |root| {
                @memcpy(buf[n..][0..32], &root);
                n += 32;
            }
            return Hash.hashBytes(buf[0..n]);
        }

        /// Prover: commit the tables, run the main sum-check, and open every
        /// MLE evaluation at the challenge point.
        pub fn prove(
            allocator: std.mem.Allocator,
            k: usize,
            tables: []const []const F,
        ) !Proof {
            const m = tables.len;
            const n = @as(usize, 1) << @intCast(k);
            for (tables) |t| std.debug.assert(t.len == n);
            std.debug.assert(m <= MaxTables);

            var roots: [MaxTables]Hash.Digest = undefined;
            for (0..m) |j| {
                var tree = try CP.commit(allocator, tables[j]);
                defer tree.deinit();
                roots[j] = tree.root();
            }
            const seed = seedForRoots(roots[0..m]);

            const main = try SC.proveSeeded(allocator, k, tables, &seed);

            const rr = (try SC.runRounds(allocator, &seed, main.claimed_sum, main.rounds)) orelse return error.Sumcheck;
            defer allocator.free(rr.challenges);

            const evals = try allocator.alloc(EvalProof, m);
            errdefer allocator.free(evals);
            for (0..m) |j| {
                const pcs_proof = try CP.proveEval(allocator, k, tables[j], rr.challenges);
                evals[j] = .{ .value = pcs_proof.value, .pcs = pcs_proof };
            }

            return .{ .claimed_sum = main.claimed_sum, .main = main, .evals = evals };
        }

        /// Verifier: check the main sum-check rounds, verify each opened MLE
        /// evaluation against its root, and confirm the product of the
        /// evaluations matches the sum-check's terminal value.
        pub fn verify(
            allocator: std.mem.Allocator,
            k: usize,
            roots: []const Hash.Digest,
            claimed_sum: F,
            proof: Proof,
        ) !bool {
            const m = roots.len;
            if (proof.evals.len != m) return false;
            if (!proof.claimed_sum.eq(claimed_sum)) return false;
            for (proof.main.rounds) |coeffs| {
                if (coeffs.len != m + 1) return false;
            }

            const seed = seedForRoots(roots);
            const rr = (try SC.runRounds(allocator, &seed, proof.claimed_sum, proof.main.rounds)) orelse return false;
            defer allocator.free(rr.challenges);

            var prod = F.one();
            for (0..m) |j| {
                const ok = try CP.verifyEval(allocator, roots[j], k, rr.challenges, proof.evals[j].pcs);
                if (!ok) return false;
                prod = prod.mul(proof.evals[j].value);
            }
            return prod.eq(rr.current_sum);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Gf16 = @import("field.zig").Gf16;
const A = BiniusArg(Gf16, 16);

fn fe(x: u128) Gf16 {
    return Gf16.fromInt(x);
}

test "binius arg round trip for m=1 and m=2, k=1..3" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const Hash = CoreHash.Hash;

    inline for (.{ 1, 2, 3 }) |k| {
        const n = @as(usize, 1) << @intCast(k);
        var t0: [8]Gf16 = undefined;
        var t1: [8]Gf16 = undefined;
        for (0..n) |i| {
            t0[i] = fe((i * 7 + 3) % 16);
            t1[i] = fe((i * 3 + 11) % 16);
        }

        // m=1: sum of a single committed column
        {
            const tables = [_][]const Gf16{t0[0..n]};
            const expected = SumcheckMod.Sumcheck(Gf16).computeClaimedSum(n, &tables);
            const proof = try A.prove(alloc, k, &tables);

            var roots: [1]Hash.Digest = undefined;
            {
                var tree = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, t0[0..n]);
                roots[0] = tree.root();
            }
            try std.testing.expect(try A.verify(alloc, k, &roots, expected, proof));
        }

        // m=2: product-sum of two committed columns
        {
            const tables = [_][]const Gf16{ t0[0..n], t1[0..n] };
            const expected = SumcheckMod.Sumcheck(Gf16).computeClaimedSum(n, &tables);
            const proof = try A.prove(alloc, k, &tables);

            var roots: [2]Hash.Digest = undefined;
            {
                var tree0 = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, t0[0..n]);
                var tree1 = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, t1[0..n]);
                roots[0] = tree0.root();
                roots[1] = tree1.root();
            }
            try std.testing.expect(try A.verify(alloc, k, &roots, expected, proof));
        }
    }
}

test "binius arg rejects wrong claimed sum and wrong root" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const Hash = CoreHash.Hash;

    const k = 3;
    var t0: [8]Gf16 = undefined;
    var t1: [8]Gf16 = undefined;
    for (0..8) |i| {
        t0[i] = fe((i * 7 + 3) % 16);
        t1[i] = fe((i * 3 + 11) % 16);
    }
    const tables = [_][]const Gf16{ &t0, &t1 };
    const expected = SumcheckMod.Sumcheck(Gf16).computeClaimedSum(8, &tables);
    const proof = try A.prove(alloc, k, &tables);

    var roots: [2]Hash.Digest = undefined;
    {
        var tree0 = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &t0);
        var tree1 = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &t1);
        roots[0] = tree0.root();
        roots[1] = tree1.root();
    }
    try std.testing.expect(try A.verify(alloc, k, &roots, expected, proof));

    // wrong claimed sum
    try std.testing.expect(!try A.verify(alloc, k, &roots, expected.add(fe(1)), proof));

    // wrong root (tampered table committed)
    var bad: [8]Gf16 = t0;
    bad[2] = bad[2].add(fe(1));
    var bad_root: [2]Hash.Digest = roots;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &bad);
        bad_root[0] = tree.root();
    }
    try std.testing.expect(!try A.verify(alloc, k, &bad_root, expected, proof));
}
