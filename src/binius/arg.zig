const std = @import("std");
const SumcheckMod = @import("sumcheck.zig");
const PcsMod = @import("pcs.zig");
const FriPcsMod = @import("fripcs.zig");
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
///   2. For each table, a committed MLE evaluation proof at τ via the PCS
///      `CP` (e.g. `CommittedMlePcs`, opening every entry, or the sub-linear
///      polylog `FriPcs`).
///
/// This is the core of a Binius prover: commit witness columns, prove a
/// hypercube sum of their products, and open the few MLE evaluations the
/// sum-check leaves the verifier with.
///
/// `BiniusArg(F, max_tables)` is the classic single-field construction;
/// `BiniusArgWith(F, E, max_tables, CP)` runs the sum-check over the
/// extension field `E` of the witness field `F` (lifting the tables by the
/// zero-cost tower embedding) so the Schwartz-Zippel applications carry
/// soundness ≈ 1/|E| even for a small witness field `F`.
pub fn BiniusArg(comptime F: type, comptime max_tables: usize) type {
    return BiniusArgWith(F, F, max_tables, PcsMod.CommittedMlePcs(F, F));
}

/// Product-sum argument with a caller-chosen extension field `E` and
/// committed-MLE PCS `CP` (same interface as `BiniusStarkWith`:
/// `Proof`, `commit`, `proveEval`, `verifyEval`).
pub fn BiniusArgWith(comptime F: type, comptime E: type, comptime max_tables: usize, comptime CP: type) type {
    return struct {
        const SC = SumcheckMod.Sumcheck(E);
        const Hash = CoreHash.Hash;

        pub const MaxTables = max_tables;

        pub const EvalProof = struct {
            value: E,
            pcs: CP.Proof,
        };

        pub const Proof = struct {
            claimed_sum: E,
            main: SC.Proof,
            evals: []const EvalProof,
        };

        /// Embed the F tables into E (identity when E == F, zero-cost tower
        /// embedding otherwise) so the sum-check can run over E.
        fn liftTables(allocator: std.mem.Allocator, tables: []const []const F) ![]const []const E {
            const m = tables.len;
            const lifted = try allocator.alloc([]E, m);
            errdefer allocator.free(lifted);
            for (0..m) |j| {
                const t = try allocator.alloc(E, tables[j].len);
                errdefer allocator.free(t);
                if (E == F) {
                    for (tables[j], 0..) |v, i| t[i] = v;
                } else {
                    for (tables[j], 0..) |v, i| t[i] = E.embed(F.LEVEL, v);
                }
                lifted[j] = t;
            }
            return lifted;
        }

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

        /// Prover: commit the tables, run the main sum-check over the lifted
        /// tables, and open every MLE evaluation at the challenge point.
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

            const lifted = try liftTables(allocator, tables);
            defer {
                for (lifted) |lt| allocator.free(lt);
                allocator.free(lifted);
            }

            const main = try SC.proveSeeded(allocator, k, lifted, &seed);

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
            claimed_sum: E,
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

            var prod = E.one();
            for (0..m) |j| {
                const ok = try CP.verifyEval(allocator, roots[j], k, rr.challenges, proof.evals[j].pcs);
                if (!ok) return false;
                prod = prod.mul(proof.evals[j].value);
            }
            return prod.eq(rr.current_sum);
        }
    };
}

/// Product-sum argument with the sub-linear polylog FRI-Binius PCS
/// (`FriPcs` from `fripcs.zig`) as the committed-MLE layer.
pub fn BiniusArgFri(comptime F: type, comptime E: type, comptime max_tables: usize, comptime log_blowup: u8, comptime num_queries: usize) type {
    return BiniusArgWith(F, E, max_tables, FriPcsMod.FriPcs(F, E, log_blowup, num_queries));
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

const Tower = @import("tower.zig");

/// Hypercube sum of the product of E tables (matches `Sumcheck(E)` on the
/// lifted tables, the value the prover commits to).
fn expectedSumE(comptime E: type, n: usize, tables: []const []const E) E {
    var h = E.zero();
    for (0..n) |i| {
        var prod = E.one();
        for (tables) |t| prod = prod.mul(t[i]);
        h = h.add(prod);
    }
    return h;
}

test "binius arg extension-mode round trip (F=Gf16, E=Gf2_128)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const Hash = CoreHash.Hash;

    const F = Tower.Gf16;
    const E = Tower.Gf2_128;
    const Arg = BiniusArgWith(F, E, 16, @import("pcs.zig").CommittedMlePcs(F, E));

    inline for (.{ 1, 2, 3 }) |k| {
        const n = @as(usize, 1) << @intCast(k);
        var t0: [8]F = undefined;
        var t1: [8]F = undefined;
        for (0..n) |i| {
            t0[i] = F.fromInt((i * 7 + 3) % 16);
            t1[i] = F.fromInt((i * 3 + 11) % 16);
        }

        // m=1 and m=2 over the extension field
        {
            const tables = [_][]const F{t0[0..n]};
            const lifted = try Arg.liftTables(alloc, &tables);
            defer alloc.free(lifted[0]);
            const expected = expectedSumE(E, n, lifted);
            const proof = try Arg.prove(alloc, k, &tables);

            var roots: [1]Hash.Digest = undefined;
            var tree = try @import("pcs.zig").CommittedMlePcs(F, E).commit(alloc, t0[0..n]);
            roots[0] = tree.root();
            try std.testing.expect(try Arg.verify(alloc, k, &roots, expected, proof));
        }

        {
            const tables = [_][]const F{ t0[0..n], t1[0..n] };
            const lifted = try Arg.liftTables(alloc, &tables);
            defer {
                for (lifted) |lt| alloc.free(lt);
                alloc.free(lifted);
            }
            const expected = expectedSumE(E, n, lifted);
            const proof = try Arg.prove(alloc, k, &tables);

            var roots: [2]Hash.Digest = undefined;
            var tree0 = try @import("pcs.zig").CommittedMlePcs(F, E).commit(alloc, t0[0..n]);
            var tree1 = try @import("pcs.zig").CommittedMlePcs(F, E).commit(alloc, t1[0..n]);
            roots[0] = tree0.root();
            roots[1] = tree1.root();
            try std.testing.expect(try Arg.verify(alloc, k, &roots, expected, proof));
        }
    }
}

test "binius arg with FRI PCS round trip (single-field and extension)" {
    const Hash = CoreHash.Hash;

    // Single-field Gf256 (fast in Debug; FRI fold at D = k + 1).
    {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const F = Tower.Gf256;
        const Arg = BiniusArgFri(F, F, 16, 1, 2);

        inline for (.{ 1, 2, 3, 4 }) |k| {
            const n = @as(usize, 1) << @intCast(k);
            var t0: [16]F = undefined;
            var t1: [16]F = undefined;
            for (0..n) |i| {
                t0[i] = F.fromInt((i * 7 + 3) % 256);
                t1[i] = F.fromInt((i * 3 + 11) % 256);
            }
            const tables = [_][]const F{ t0[0..n], t1[0..n] };
            const lifted = try Arg.liftTables(alloc, &tables);
            defer {
                for (lifted) |lt| alloc.free(lt);
                alloc.free(lifted);
            }
            const expected = expectedSumE(F, n, lifted);
            const proof = try Arg.prove(alloc, k, &tables);

            var roots: [2]Hash.Digest = undefined;
            var tree0 = try @import("fripcs.zig").FriPcs(F, F, 1, 2).commit(alloc, t0[0..n]);
            var tree1 = try @import("fripcs.zig").FriPcs(F, F, 1, 2).commit(alloc, t1[0..n]);
            roots[0] = tree0.root();
            roots[1] = tree1.root();
            try std.testing.expect(try Arg.verify(alloc, k, &roots, expected, proof));
        }
    }

    // Extension mode F=Gf16, E=Gf2_128.
    {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const alloc = arena.allocator();

        const F = Tower.Gf16;
        const E = Tower.Gf2_128;
        const Arg = BiniusArgFri(F, E, 16, 1, 2);

        inline for (.{ 1, 2, 3 }) |k| {
            const n = @as(usize, 1) << @intCast(k);
            var t0: [8]F = undefined;
            var t1: [8]F = undefined;
            for (0..n) |i| {
                t0[i] = F.fromInt((i * 7 + 3) % 16);
                t1[i] = F.fromInt((i * 3 + 11) % 16);
            }
            const tables = [_][]const F{ t0[0..n], t1[0..n] };
            const lifted = try Arg.liftTables(alloc, &tables);
            defer {
                for (lifted) |lt| alloc.free(lt);
                alloc.free(lifted);
            }
            const expected = expectedSumE(E, n, lifted);
            const proof = try Arg.prove(alloc, k, &tables);

            var roots: [2]Hash.Digest = undefined;
            var tree0 = try @import("fripcs.zig").FriPcs(F, E, 1, 2).commit(alloc, t0[0..n]);
            var tree1 = try @import("fripcs.zig").FriPcs(F, E, 1, 2).commit(alloc, t1[0..n]);
            roots[0] = tree0.root();
            roots[1] = tree1.root();
            try std.testing.expect(try Arg.verify(alloc, k, &roots, expected, proof));
        }
    }
}

test "binius arg extension-mode rejects wrong claimed sum and wrong root" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const Hash = CoreHash.Hash;

    const F = Tower.Gf16;
    const E = Tower.Gf2_128;
    const Arg = BiniusArgWith(F, E, 16, @import("pcs.zig").CommittedMlePcs(F, E));

    const k = 3;
    var t0: [8]F = undefined;
    var t1: [8]F = undefined;
    for (0..8) |i| {
        t0[i] = F.fromInt((i * 7 + 3) % 16);
        t1[i] = F.fromInt((i * 3 + 11) % 16);
    }
    const tables = [_][]const F{ &t0, &t1 };
    const lifted = try Arg.liftTables(alloc, &tables);
    defer {
        for (lifted) |lt| alloc.free(lt);
        alloc.free(lifted);
    }
    const expected = expectedSumE(E, 8, lifted);
    const proof = try Arg.prove(alloc, k, &tables);

    var roots: [2]Hash.Digest = undefined;
    {
        var tree0 = try @import("pcs.zig").CommittedMlePcs(F, E).commit(alloc, &t0);
        var tree1 = try @import("pcs.zig").CommittedMlePcs(F, E).commit(alloc, &t1);
        roots[0] = tree0.root();
        roots[1] = tree1.root();
    }
    try std.testing.expect(try Arg.verify(alloc, k, &roots, expected, proof));

    // wrong claimed sum
    try std.testing.expect(!try Arg.verify(alloc, k, &roots, expected.add(E.one()), proof));

    // wrong root (tampered table committed)
    var bad: [8]F = t0;
    bad[2] = bad[2].add(F.one());
    var bad_root: [2]Hash.Digest = roots;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(F, E).commit(alloc, &bad);
        bad_root[0] = tree.root();
    }
    try std.testing.expect(!try Arg.verify(alloc, k, &bad_root, expected, proof));
}
