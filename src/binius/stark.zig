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
///     R_t(x) = Σ_u c_u · ∏_{f ∈ u} w_f(x)  (∀ x ∈ {0,1}^k)   R_t(x) = 0,
///
/// enforced by the *zero-check*: pick a random point τ ∈ F^k and prove
///
///     Σ_{x ∈ {0,1}^k} R_t(x) · β_τ(x) = 0,
///
/// where β_τ(x) = ∏_j (x_j + 1 + τ_j) is the Lagrange kernel. By
/// Schwartz-Zippel on the MLE of R_t, this implies R_t vanishes on the whole
/// hypercube with overwhelming probability.
///
/// All constraints are combined into a *single* sum-check. After committing the
/// witness, random combination coefficients α_t ∈ F are derived by Fiat-Shamir
/// and the prover sum-checks the linear combination
///
///     g(x) = Σ_t α_t · R_t(x) · β_τ(x)
///
/// to zero in one k-round protocol. Expanding R_t into monomials, each term is
/// a product of tables [w_{f₁}, …, w_{f_d}, ℓ₀, …, ℓ_{k-1}] (the kernel
/// tables), which the combination sum-check folds. The trailing claim reduces
/// to the MLE evaluations w_f(τ') at the single challenge point, which the
/// committed PCS opens for every distinct factor column in one batch.
///
/// Fiat-Shamir: the zero-check point τ, the combination coefficients α_t, and
/// every sum-check challenge are derived from the commitment roots, so all
/// randomness binds to the committed witness.
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

        pub const Proof = struct {
            /// Single zero-check sum-check over the random-linear combination
            /// of all constraints; its claimed sum is zero.
            sumcheck: SC.Proof,
            /// One eval proof per *distinct* factor column, at the sum-check's
            /// challenge point, in first-occurrence order of `factors`.
            evals: []const EvalProof,
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

        /// Fiat-Shamir derivation of the random combination coefficients α_t
        /// binding each constraint into the combined zero-check sum-check.
        fn combinationCoeffs(allocator: std.mem.Allocator, count: usize, seed: *const [32]u8) ![]F {
            const alphas = try allocator.alloc(F, count);
            errdefer allocator.free(alphas);
            var buf: [32]u8 = undefined;
            for (0..count) |t| {
                var h = Sha256.init(.{});
                h.update(seed);
                const b = [_]u8{@intCast(t & 0xff)};
                h.update(&b);
                h.final(&buf);
                if (F.SIZE == 1) {
                    alphas[t] = F.fromInt(buf[31] & 0x0f);
                } else {
                    var out: [F.SIZE]u8 = undefined;
                    @memcpy(&out, buf[32 - F.SIZE ..][0..F.SIZE]);
                    alphas[t] = F.fromBytes(out);
                }
            }
            return alphas;
        }

        /// Flatten all constraints into combination terms over the shared
        /// tables [w_0..w_{m-1}, ℓ_0..ℓ_{k-1}]: term coeff = α_t·c_u and
        /// indices = the factor columns followed by the k kernel-table slots.
        fn buildTerms(
            allocator: std.mem.Allocator,
            m: usize,
            k: usize,
            alphas: []const F,
            constraints: []const Constraint,
        ) ![]SC.Term {
            var total: usize = 0;
            for (constraints) |con| total += con.terms.len;
            const terms = try allocator.alloc(SC.Term, total);
            errdefer allocator.free(terms);
            var ti: usize = 0;
            for (constraints, 0..) |con, t| {
                for (con.terms) |mono| {
                    const d = mono.factors.len;
                    const indices = try allocator.alloc(usize, d + k);
                    for (mono.factors, 0..) |fidx, l| indices[l] = fidx;
                    for (0..k) |j| indices[d + j] = m + j;
                    terms[ti] = .{ .coeff = alphas[t].mul(mono.coeff), .indices = indices };
                    ti += 1;
                }
            }
            return terms;
        }

        /// Per-variable degree bound of the combined summand, used by both
        /// sides to fix the round interpolation width.
        fn maxDegree(k: usize, constraints: []const Constraint) usize {
            var dmax: usize = 0;
            for (constraints) |con| {
                for (con.terms) |mono| dmax = @max(dmax, mono.factors.len + k);
            }
            return dmax;
        }

        /// Prover: commit the witness columns, derive τ and α_t, run a single
        /// combined zero-check sum-check, and open each distinct factor column
        /// once at the challenge point.
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
            const alphas = try combinationCoeffs(allocator, constraints.len, &seed);
            defer allocator.free(alphas);

            const kt = try M.kernelTables(allocator, k, tau);
            defer {
                for (kt) |t| allocator.free(t);
                allocator.free(kt);
            }

            // Shared tables: witness columns followed by the kernel tables.
            const tables = try allocator.alloc([]const F, m + k);
            defer allocator.free(tables);
            for (0..m) |j| tables[j] = columns[j];
            for (0..k) |j| tables[m + j] = kt[j];

            const terms = try buildTerms(allocator, m, k, alphas, constraints);
            defer {
                for (terms) |tm| allocator.free(tm.indices);
                allocator.free(terms);
            }

            const sp = try SC.proveCombination(allocator, k, tables, terms, &seed);
            const rr = (try SC.runRounds(allocator, &seed, sp.claimed_sum, sp.rounds)) orelse return error.Sumcheck;
            defer allocator.free(rr.challenges);

            // Distinct factor columns across all constraints, in
            // first-occurrence order; open each once at the challenge point.
            var seen: [MaxColumns]bool = [_]bool{false} ** MaxColumns;
            var distinct: [MaxColumns]usize = undefined;
            var count: usize = 0;
            for (constraints) |con| {
                for (con.terms) |mono| {
                    for (mono.factors) |fidx| {
                        if (seen[fidx]) continue;
                        seen[fidx] = true;
                        distinct[count] = fidx;
                        count += 1;
                    }
                }
            }

            const evals = try allocator.alloc(EvalProof, count);
            errdefer allocator.free(evals);
            for (0..count) |l| {
                const e = try CP.proveEval(allocator, k, columns[distinct[l]], rr.challenges);
                evals[l] = .{ .value = e.value, .pcs = e };
            }

            return .{ .sumcheck = sp, .evals = evals };
        }

        /// Verifier: derive τ and α_t, replay the combined sum-check rounds,
        /// verify every committed MLE evaluation against its root, and check
        /// that the combined constraint sum vanishes (the zero-check).
        pub fn verify(
            allocator: std.mem.Allocator,
            k: usize,
            roots: []const Hash.Digest,
            constraints: []const Constraint,
            proof: Proof,
        ) !bool {
            const m = roots.len;

            const tau = try challengePoint(allocator, k, roots);
            defer allocator.free(tau);
            const seed = seedFor(roots, tau);
            const alphas = try combinationCoeffs(allocator, constraints.len, &seed);
            defer allocator.free(alphas);

            // The zero-check: the combined constraint sum must vanish.
            if (!proof.sumcheck.claimed_sum.isZero()) return false;
            if (proof.sumcheck.rounds.len != k) return false;
            const dmax = maxDegree(k, constraints);
            for (proof.sumcheck.rounds) |coeffs| {
                if (coeffs.len != dmax + 1) return false;
            }

            const rr = (try SC.runRounds(allocator, &seed, proof.sumcheck.claimed_sum, proof.sumcheck.rounds)) orelse return false;
            defer allocator.free(rr.challenges);

            // Distinct factor columns, first-occurrence order, each opened once.
            var seen: [MaxColumns]bool = [_]bool{false} ** MaxColumns;
            var distinct: [MaxColumns]usize = undefined;
            var count: usize = 0;
            for (constraints) |con| {
                for (con.terms) |mono| {
                    for (mono.factors) |fidx| {
                        if (fidx >= m) return false;
                        if (seen[fidx]) continue;
                        seen[fidx] = true;
                        distinct[count] = fidx;
                        count += 1;
                    }
                }
            }
            if (proof.evals.len != count) return false;

            var value_of: [MaxColumns]F = undefined;
            for (0..count) |l| {
                const ok = try CP.verifyEval(allocator, roots[distinct[l]], k, rr.challenges, proof.evals[l].pcs);
                if (!ok) return false;
                value_of[distinct[l]] = proof.evals[l].value;
            }

            // Final value of the combined summand at the challenge point:
            // Σ_t α_t · Σ_u c_u · (∏_f w_f(τ')) · β_τ(τ').
            var acc = F.zero();
            for (constraints, 0..) |con, t| {
                for (con.terms) |mono| {
                    var prod = F.one();
                    for (mono.factors) |fidx| prod = prod.mul(value_of[fidx]);
                    prod = prod.mul(M.kernelValue(tau, rr.challenges));
                    acc = acc.add(alphas[t].mul(mono.coeff).mul(prod));
                }
            }
            return acc.eq(rr.current_sum);
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
    const SF = BiniusStark(Gf256);

    // w ≡ 2 is constant, so the zero-check sum R = w + w·w = 2 + 4 = 6 is a
    // non-zero constant on the hypercube. Its random combination survives any
    // τ, so rejection is guaranteed as long as α_0 ≠ 0 (1/256 for GF(2^8)).
    const k = 2;
    var w: [4]Gf256 = undefined;
    for (0..4) |i| w[i] = Gf256.fromInt(2);

    const booleanness = [_]SF.Monomial{
        .{ .coeff = Gf256.one(), .factors = &.{0} },
        .{ .coeff = Gf256.one(), .factors = &.{ 0, 0 } },
    };
    const constraints = [_]SF.Constraint{.{
        .terms = &booleanness,
    }};
    const columns = [_][]const Gf256{&w};
    const proof = try SF.prove(alloc, k, &columns, &constraints);

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf256).commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(!try SF.verify(alloc, k, &roots, &constraints, proof));
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
        var tf = try @import("pcs.zig").CommittedMlePcs(Gf16).commit(alloc, &f);
        var tg = try @import("pcs.zig").CommittedMlePcs(Gf16).commit(alloc, &g);
        var th = try @import("pcs.zig").CommittedMlePcs(Gf16).commit(alloc, &h);
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
    const SF = BiniusStark(Gf256);

    // h ≡ 1 while f = g = 0 makes R = h + f·g ≡ 1, a non-zero constant, so
    // the zero-check survives any τ and rejection only needs α_0 ≠ 0.
    const k = 2;
    var f: [4]Gf256 = undefined;
    var g: [4]Gf256 = undefined;
    var h: [4]Gf256 = undefined;
    for (0..4) |i| {
        f[i] = Gf256.zero();
        g[i] = Gf256.zero();
        h[i] = Gf256.one();
    }

    const rel = [_]SF.Monomial{
        .{ .coeff = Gf256.one(), .factors = &.{2} }, // h
        .{ .coeff = Gf256.one(), .factors = &.{ 0, 1 } }, // f·g
    };
    const constraints = [_]SF.Constraint{.{
        .terms = &rel,
    }};
    const columns = [_][]const Gf256{ &f, &g, &h };
    const proof = try SF.prove(alloc, k, &columns, &constraints);

    var roots: [3]CoreHash.Hash.Digest = undefined;
    {
        var tf = try @import("pcs.zig").CommittedMlePcs(Gf256).commit(alloc, &f);
        var tg = try @import("pcs.zig").CommittedMlePcs(Gf256).commit(alloc, &g);
        var th = try @import("pcs.zig").CommittedMlePcs(Gf256).commit(alloc, &h);
        roots[0] = tf.root();
        roots[1] = tg.root();
        roots[2] = th.root();
    }
    try std.testing.expect(!try SF.verify(alloc, k, &roots, &constraints, proof));
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
        var tw = try @import("pcs.zig").CommittedMlePcs(Gf16).commit(alloc, &w);
        var tf = try @import("pcs.zig").CommittedMlePcs(Gf16).commit(alloc, &f);
        var tg = try @import("pcs.zig").CommittedMlePcs(Gf16).commit(alloc, &g);
        var th = try @import("pcs.zig").CommittedMlePcs(Gf16).commit(alloc, &h);
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
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf16).commit(alloc, &bad);
        roots[0] = tree.root();
    }
    try std.testing.expect(!try S.verify(alloc, k, &roots, &constraints, proof));
}

test "batched constraints open each distinct column once" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const k = 3;
    var w: [8]Gf16 = undefined;
    var f: [8]Gf16 = undefined;
    var g: [8]Gf16 = undefined;
    for (0..8) |i| {
        const v = fe(@intFromBool((i % 2) == 0));
        w[i] = v;
        f[i] = v; // f == w
        g[i] = v; // g == w
    }

    // Three constraints all referencing column 0: 6 term slots but only 3
    // distinct columns, so the proof must carry exactly 3 eval proofs.
    const c0 = [_]S.Monomial{
        .{ .coeff = fe(1), .factors = &.{0} },
        .{ .coeff = fe(1), .factors = &.{ 0, 0 } }, // w + w·w = 0
    };
    const c1 = [_]S.Monomial{
        .{ .coeff = fe(1), .factors = &.{0} },
        .{ .coeff = fe(1), .factors = &.{1} }, // w + f = 0
    };
    const c2 = [_]S.Monomial{
        .{ .coeff = fe(1), .factors = &.{0} },
        .{ .coeff = fe(1), .factors = &.{2} }, // w + g = 0
    };
    const constraints = [_]S.Constraint{
        .{ .terms = &c0 },
        .{ .terms = &c1 },
        .{ .terms = &c2 },
    };
    const columns = [_][]const Gf16{ &w, &f, &g };
    const proof = try S.prove(alloc, k, &columns, &constraints);
    try std.testing.expectEqual(@as(usize, 3), proof.evals.len);

    var roots: [3]CoreHash.Hash.Digest = undefined;
    {
        var tw = try @import("pcs.zig").CommittedMlePcs(Gf16).commit(alloc, &w);
        var tf = try @import("pcs.zig").CommittedMlePcs(Gf16).commit(alloc, &f);
        var tg = try @import("pcs.zig").CommittedMlePcs(Gf16).commit(alloc, &g);
        roots[0] = tw.root();
        roots[1] = tf.root();
        roots[2] = tg.root();
    }
    try std.testing.expect(try S.verify(alloc, k, &roots, &constraints, proof));
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
