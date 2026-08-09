const std = @import("std");
const SumcheckMod = @import("sumcheck.zig");
const PcsMod = @import("pcs.zig");
const CoreHash = @import("../core/hash/hash.zig");

/// Binius STARK over a binary field `F`: proves that a set of Merkle-committed
/// witness columns satisfies a system of pointwise constraints on the boolean
/// hypercube {0,1}^k.
///
/// A constraint is a sum of monomials
///
///     R(x) = Σ_t c_t · ∏_{f ∈ t} w_f(x)  (∀ x ∈ {0,1}^k)   R(x) = 0,
///
/// enforced by the *zero-check*: pick a random point τ ∈ F^k and prove
///
///     Σ_{x ∈ {0,1}^k} R(x) · β_τ(x) = 0,
///
/// where β_τ(x) = ∏_j (x_j + 1 + τ_j) is the Lagrange kernel. By
/// Schwartz-Zippel on the MLE of R, this implies R vanishes on the whole
/// hypercube with overwhelming probability.
///
/// Expanding R into monomials, each term becomes a product-sum
/// Σ_x (∏ w_f(x))·β_τ(x) over the tables [w_{f₁}, …, w_{f_d}, ℓ₀, …, ℓₖ₋₁]
/// (the kernel tables), which the sum-check protocol proves. Each sum-check's
/// trailing claim reduces to the MLE evaluations w_f(τ') at its challenge
/// point, which the committed PCS opens against the witness Merkle roots.
///
/// Fiat-Shamir: the zero-check point τ and every sum-check seed are derived
/// from the commitment roots, so all challenges bind to the committed witness.
pub fn BiniusStark(comptime F: type) type {
    return struct {
        const SC = SumcheckMod.Sumcheck(F);
        const CP = PcsMod.CommittedMlePcs(F);
        const M = PcsMod.MlePcs(F);
        const Hash = CoreHash.Hash;
        const Sha256 = std.crypto.hash.sha2.Sha256;

        pub const MaxColumns = 16;

        /// One monomial c·∏_{f∈factors} w_f(x); `factors` may repeat a column
        /// index to encode powers (w·w = w²).
        pub const Monomial = struct {
            coeff: F,
            factors: []const usize,
        };

        /// A constraint Σ_t monomial_t(x) == 0 for all x ∈ {0,1}^k.
        pub const Constraint = struct {
            terms: []const Monomial,
        };

        /// Committed evaluation of one witness column at a challenge point.
        pub const EvalProof = struct {
            value: F,
            pcs: CP.Proof,
        };

        pub const TermProof = struct {
            claimed_sum: F,
            sumcheck: SC.Proof,
            /// One eval proof per *distinct* factor column, at the term's
            /// challenge point, in first-occurrence order of `factors`.
            evals: []const EvalProof,
        };

        pub const ConstraintProof = struct {
            terms: []const TermProof,
        };

        pub const Proof = struct {
            constraints: []const ConstraintProof,
        };

        fn seedForRoots(roots: []const Hash.Digest) [32]u8 {
            std.debug.assert(roots.len <= MaxColumns);
            var buf: [MaxColumns * 32]u8 = undefined;
            var n: usize = 0;
            for (roots) |r| {
                @memcpy(buf[n..][0..32], &r);
                n += 32;
            }
            return Hash.hashBytes(buf[0..n]);
        }

        /// Bind both the roots and the zero-check point into one seed.
        fn seedFor(roots: []const Hash.Digest, tau: []const F) [32]u8 {
            var h = Sha256.init(.{});
            const rs = seedForRoots(roots);
            h.update(&rs);
            var b: [F.SIZE]u8 = undefined;
            for (tau) |v| {
                v.toBytes(&b);
                h.update(&b);
            }
            var seed: [32]u8 = undefined;
            h.final(&seed);
            return seed;
        }

        /// Fiat-Shamir derivation of the random zero-check point τ ∈ F^k.
        fn challengePoint(allocator: std.mem.Allocator, k: usize, roots: []const Hash.Digest) ![]F {
            const rs = seedForRoots(roots);
            const tau = try allocator.alloc(F, k);
            errdefer allocator.free(tau);
            var buf: [32]u8 = undefined;
            for (0..k) |j| {
                var h = Sha256.init(.{});
                h.update(&rs);
                const b = [_]u8{@intCast(j & 0xff)};
                h.update(&b);
                h.final(&buf);
                if (F.SIZE == 1) {
                    tau[j] = F.fromInt(buf[31] & 0x0f);
                } else {
                    var out: [F.SIZE]u8 = undefined;
                    @memcpy(&out, buf[32 - F.SIZE ..][0..F.SIZE]);
                    tau[j] = F.fromBytes(out);
                }
            }
            return tau;
        }

        /// Prover: commit the witness columns, derive τ, run one sum-check per
        /// monomial term, and open the trailing MLE evaluations.
        pub fn prove(
            allocator: std.mem.Allocator,
            k: usize,
            columns: []const []const F,
            constraints: []const Constraint,
        ) !Proof {
            const m = columns.len;
            const n = @as(usize, 1) << @intCast(k);
            std.debug.assert(m <= MaxColumns);
            for (columns) |c| std.debug.assert(c.len == n);

            var roots: [MaxColumns]Hash.Digest = undefined;
            for (0..m) |j| {
                var tree = try CP.commit(allocator, columns[j]);
                defer tree.deinit();
                roots[j] = tree.root();
            }
            const rsl = roots[0..m];
            const tau = try challengePoint(allocator, k, rsl);
            defer allocator.free(tau);
            const seed = seedFor(rsl, tau);

            const kt = try M.kernelTables(allocator, k, tau);
            defer {
                for (kt) |t| allocator.free(t);
                allocator.free(kt);
            }

            const cproofs = try allocator.alloc(ConstraintProof, constraints.len);
            errdefer allocator.free(cproofs);
            for (constraints, 0..) |con, ci| {
                const tproofs = try allocator.alloc(TermProof, con.terms.len);
                errdefer allocator.free(tproofs);
                for (con.terms, 0..) |mono, ti| {
                    const d = mono.factors.len;
                    const tables = try allocator.alloc([]const F, d + k);
                    defer allocator.free(tables);
                    for (mono.factors, 0..) |fidx, l| tables[l] = columns[fidx];
                    for (0..k) |j| tables[d + j] = kt[j];

                    const sp = try SC.proveSeeded(allocator, k, tables, &seed);
                    const rr = (try SC.runRounds(allocator, &seed, sp.claimed_sum, sp.rounds)) orelse return error.Sumcheck;
                    defer allocator.free(rr.challenges);

                    // Distinct factor columns, in first-occurrence order.
                    var seen: [MaxColumns]bool = [_]bool{false} ** MaxColumns;
                    var distinct: [MaxColumns]usize = undefined;
                    var count: usize = 0;
                    for (mono.factors) |fidx| {
                        if (seen[fidx]) continue;
                        seen[fidx] = true;
                        distinct[count] = fidx;
                        count += 1;
                    }

                    const evals = try allocator.alloc(EvalProof, count);
                    errdefer allocator.free(evals);
                    for (0..count) |l| {
                        const e = try CP.proveEval(allocator, k, columns[distinct[l]], rr.challenges);
                        evals[l] = .{ .value = e.value, .pcs = e };
                    }

                    tproofs[ti] = .{ .claimed_sum = sp.claimed_sum, .sumcheck = sp, .evals = evals };
                }
                cproofs[ci] = .{ .terms = tproofs };
            }
            return .{ .constraints = cproofs };
        }

        /// Verifier: replay the sum-check rounds, verify the committed MLE
        /// evaluations against the roots, and check that each constraint's
        /// weighted sum of claimed values vanishes (the zero-check).
        pub fn verify(
            allocator: std.mem.Allocator,
            k: usize,
            roots: []const Hash.Digest,
            constraints: []const Constraint,
            proof: Proof,
        ) !bool {
            const m = roots.len;
            if (proof.constraints.len != constraints.len) return false;

            const tau = try challengePoint(allocator, k, roots);
            defer allocator.free(tau);
            const seed = seedFor(roots, tau);

            for (constraints, proof.constraints) |con, cproof| {
                if (con.terms.len != cproof.terms.len) return false;
                var acc = F.zero();
                for (con.terms, cproof.terms) |mono, tproof| {
                    if (tproof.sumcheck.rounds.len != k) return false;
                    const rr = (try SC.runRounds(allocator, &seed, tproof.claimed_sum, tproof.sumcheck.rounds)) orelse return false;
                    defer allocator.free(rr.challenges);

                    // Distinct factor columns, in first-occurrence order.
                    var seen: [MaxColumns]bool = [_]bool{false} ** MaxColumns;
                    var distinct: [MaxColumns]usize = undefined;
                    var count: usize = 0;
                    for (mono.factors) |fidx| {
                        if (fidx >= m) return false;
                        if (seen[fidx]) continue;
                        seen[fidx] = true;
                        distinct[count] = fidx;
                        count += 1;
                    }
                    if (tproof.evals.len != count) return false;

                    var value_of: [MaxColumns]F = undefined;
                    for (0..count) |l| {
                        const ok = try CP.verifyEval(allocator, roots[distinct[l]], k, rr.challenges, tproof.evals[l].pcs);
                        if (!ok) return false;
                        value_of[distinct[l]] = tproof.evals[l].value;
                    }

                    // Final sum-check value: ∏ w_f(τ') · β_τ(τ') (with
                    // multiplicity for repeated factors).
                    var prod = F.one();
                    for (mono.factors) |fidx| prod = prod.mul(value_of[fidx]);
                    prod = prod.mul(M.kernelValue(tau, rr.challenges));
                    if (!prod.eq(rr.current_sum)) return false;

                    acc = acc.add(mono.coeff.mul(tproof.claimed_sum));
                }
                if (!acc.isZero()) return false;
            }
            return true;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Gf16 = @import("tower.zig").Gf16;
const Gf256 = @import("tower.zig").Gf256;
const ScriptGf16 = @import("field.zig").Gf16;
const S = BiniusStark(Gf16);

fn fe(x: u128) Gf16 {
    return Gf16.fromInt(x);
}

test "booleanness constraint round trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const k = 3;
    var w: [8]Gf16 = undefined;
    for (0..8) |i| w[i] = fe(@intFromBool((i * 3 + 1) % 2 == 1));

    // R = w·w + w == 0 (in char 2, w² - w = w² + w).
    const booleanness = [_]S.Monomial{
        .{ .coeff = fe(1), .factors = &.{0} }, // w
        .{ .coeff = fe(1), .factors = &.{ 0, 0 } }, // w·w
    };
    const constraints = [_]S.Constraint{.{
        .terms = &booleanness,
    }};

    const columns = [_][]const Gf16{&w};
    const proof = try S.prove(alloc, k, &columns, &constraints);

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf16).commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(try S.verify(alloc, k, &roots, &constraints, proof));
}

test "non-boolean witness is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const k = 3;
    var w: [8]Gf16 = undefined;
    for (0..8) |i| w[i] = fe((i * 3 + 1) % 16); // includes values ≥ 2
    w[3] = fe(2);

    const booleanness = [_]S.Monomial{
        .{ .coeff = fe(1), .factors = &.{0} },
        .{ .coeff = fe(1), .factors = &.{ 0, 0 } },
    };
    const constraints = [_]S.Constraint{.{
        .terms = &booleanness,
    }};
    const columns = [_][]const Gf16{&w};
    const proof = try S.prove(alloc, k, &columns, &constraints);

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try CP.commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(!try S.verify(alloc, k, &roots, &constraints, proof));
}

test "multiplication relation h = f·g" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const k = 3;
    var f: [8]Gf16 = undefined;
    var g: [8]Gf16 = undefined;
    var h: [8]Gf16 = undefined;
    for (0..8) |i| {
        f[i] = fe((i * 5 + 2) % 16);
        g[i] = fe((i * 3 + 7) % 16);
        h[i] = f[i].mul(g[i]);
    }

    // R = h + f·g == 0
    const rel = [_]S.Monomial{
        .{ .coeff = fe(1), .factors = &.{2} }, // h
        .{ .coeff = fe(1), .factors = &.{ 0, 1 } }, // f·g
    };
    const constraints = [_]S.Constraint{.{
        .terms = &rel,
    }};
    const columns = [_][]const Gf16{ &f, &g, &h };
    const proof = try S.prove(alloc, k, &columns, &constraints);

    var roots: [3]CoreHash.Hash.Digest = undefined;
    {
        var tf = try CP.commit(alloc, &f);
        var tg = try CP.commit(alloc, &g);
        var th = try CP.commit(alloc, &h);
        roots[0] = tf.root();
        roots[1] = tg.root();
        roots[2] = th.root();
    }
    try std.testing.expect(try S.verify(alloc, k, &roots, &constraints, proof));
}

test "wrong product is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const k = 3;
    var f: [8]Gf16 = undefined;
    var g: [8]Gf16 = undefined;
    var h: [8]Gf16 = undefined;
    for (0..8) |i| {
        f[i] = fe((i * 5 + 2) % 16);
        g[i] = fe((i * 3 + 7) % 16);
        h[i] = f[i].mul(g[i]);
    }
    h[2] = h[2].add(fe(1)); // break one entry

    const rel = [_]S.Monomial{
        .{ .coeff = fe(1), .factors = &.{2} },
        .{ .coeff = fe(1), .factors = &.{ 0, 1 } },
    };
    const constraints = [_]S.Constraint{.{
        .terms = &rel,
    }};
    const columns = [_][]const Gf16{ &f, &g, &h };
    const proof = try S.prove(alloc, k, &columns, &constraints);

    var roots: [3]CoreHash.Hash.Digest = undefined;
    {
        var tf = try CP.commit(alloc, &f);
        var tg = try CP.commit(alloc, &g);
        var th = try CP.commit(alloc, &h);
        roots[0] = tf.root();
        roots[1] = tg.root();
        roots[2] = th.root();
    }
    try std.testing.expect(!try S.verify(alloc, k, &roots, &constraints, proof));
}

test "multiple constraints in one proof" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const k = 3;
    var w: [8]Gf16 = undefined;
    var f: [8]Gf16 = undefined;
    var g: [8]Gf16 = undefined;
    var h: [8]Gf16 = undefined;
    for (0..8) |i| {
        w[i] = fe(@intFromBool((i % 2) == 0));
        f[i] = fe((i * 5 + 2) % 16);
        g[i] = fe((i * 3 + 7) % 16);
        h[i] = f[i].mul(g[i]);
    }

    const bool_terms = [_]S.Monomial{
        .{ .coeff = fe(1), .factors = &.{0} },
        .{ .coeff = fe(1), .factors = &.{ 0, 0 } },
    };
    const prod_terms = [_]S.Monomial{
        .{ .coeff = fe(1), .factors = &.{3} }, // h
        .{ .coeff = fe(1), .factors = &.{ 1, 2 } }, // f·g
    };
    const constraints = [_]S.Constraint{
        .{ .terms = &bool_terms },
        .{ .terms = &prod_terms },
    };
    const columns = [_][]const Gf16{ &w, &f, &g, &h };
    const proof = try S.prove(alloc, k, &columns, &constraints);

    var roots: [4]CoreHash.Hash.Digest = undefined;
    {
        var tw = try CP.commit(alloc, &w);
        var tf = try CP.commit(alloc, &f);
        var tg = try CP.commit(alloc, &g);
        var th = try CP.commit(alloc, &h);
        roots[0] = tw.root();
        roots[1] = tf.root();
        roots[2] = tg.root();
        roots[3] = th.root();
    }
    try std.testing.expect(try S.verify(alloc, k, &roots, &constraints, proof));
}

test "tampered root is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const k = 3;
    var w: [8]Gf16 = undefined;
    for (0..8) |i| w[i] = fe(@intFromBool((i * 3 + 1) % 2 == 1));

    const booleanness = [_]S.Monomial{
        .{ .coeff = fe(1), .factors = &.{0} },
        .{ .coeff = fe(1), .factors = &.{ 0, 0 } },
    };
    const constraints = [_]S.Constraint{.{
        .terms = &booleanness,
    }};
    const columns = [_][]const Gf16{&w};
    const proof = try S.prove(alloc, k, &columns, &constraints);

    // Flip one witness bit and commit the tampered column.
    var bad: [8]Gf16 = w;
    bad[2] = fe(2);
    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try CP.commit(alloc, &bad);
        roots[0] = tree.root();
    }
    try std.testing.expect(!try S.verify(alloc, k, &roots, &constraints, proof));
}

test "stark runs over tower GF(256)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const SF = BiniusStark(Gf256);

    const k = 2;
    var w: [4]Gf256 = undefined;
    for (0..4) |i| w[i] = Gf256.fromInt(if (i % 2 == 0) @as(u128, 0) else 1);

    const bool_terms = [_]SF.Monomial{
        .{ .coeff = Gf256.one(), .factors = &.{0} },
        .{ .coeff = Gf256.one(), .factors = &.{ 0, 0 } },
    };
    const constraints = [_]SF.Constraint{.{
        .terms = &bool_terms,
    }};
    const columns = [_][]const Gf256{&w};
    const proof = try SF.prove(alloc, k, &columns, &constraints);

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf256).commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(try SF.verify(alloc, k, &roots, &constraints, proof));
}

test "stark runs over the Script field GF(16)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const SF = BiniusStark(ScriptGf16);

    const k = 2;
    var w: [4]ScriptGf16 = undefined;
    for (0..4) |i| w[i] = ScriptGf16.fromInt(if (i % 2 == 0) @as(u128, 0) else 1);

    const bool_terms = [_]SF.Monomial{
        .{ .coeff = ScriptGf16.one(), .factors = &.{0} },
        .{ .coeff = ScriptGf16.one(), .factors = &.{ 0, 0 } },
    };
    const constraints = [_]SF.Constraint{.{
        .terms = &bool_terms,
    }};
    const columns = [_][]const ScriptGf16{&w};
    const proof = try SF.prove(alloc, k, &columns, &constraints);

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(ScriptGf16).commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(try SF.verify(alloc, k, &roots, &constraints, proof));
}
