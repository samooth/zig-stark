const std = @import("std");
const SumcheckMod = @import("sumcheck.zig");
const PcsMod = @import("pcs.zig");
const CoreHash = @import("../core/hash/hash.zig");
const Channel = @import("../core/channel/channel.zig").Channel;

/// Binius STARK over a binary field `F` (the witness/base field) with the
/// protocol run over the extension field `E` (take `E = F` for the plain
/// single-field setting): proves that a set of Merkle-committed witness columns
/// satisfies a system of pointwise constraints on the boolean hypercube
/// {0,1}^k.
///
/// A constraint is a sum of monomials
///
///     R_t(x) = Σ_u c_u · ∏_{f ∈ u} w_f(x)  (∀ x ∈ {0,1}^k)   R_t(x) = 0,
///
/// enforced by the *zero-check*: pick a random point τ ∈ E^k and prove
///
///     Σ_{x ∈ {0,1}^k} R_t(x) · β_τ(x) = 0,
///
/// where β_τ(x) = ∏_j (x_j + 1 + τ_j) is the Lagrange kernel. By
/// Schwartz-Zippel on the MLE of R_t, this implies R_t vanishes on the whole
/// hypercube with overwhelming probability.
///
/// All constraints are combined into a *single* sum-check. After committing the
/// witness, random combination coefficients α_t ∈ E are derived by Fiat-Shamir
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
/// The randomness (τ, α_t, the round challenges, and the PCS query points) is
/// sampled in `E` while the witness, the committed tables, and the Merkle
/// leaves stay in `F` and are embedded into `E` (zero-cost, same bit pattern)
/// when they enter the sum-check. Working over a large extension `E` makes the
/// degree-1 sum-check polynomial identity argument sound even for a tiny base
/// field `F` (e.g. GF(16) or GF(256)) and upgrades the soundness of the whole
/// protocol to ≈ 1/|E| per Schwartz-Zippel application; with `E = F` this is
/// the classic construction with soundness ≈ 1/|F|.
///
/// Fiat-Shamir: a single transcript (the core `Channel`) absorbs the public
/// input bytes, the boundary pins, and the commitment roots, then samples the
/// zero-check point τ, the combination coefficients α_t, and seeds the inner
/// sum-check transcript, so all randomness binds to the public statement and
/// the committed witness.
pub fn BiniusStark(comptime F: type, comptime E: type, comptime max_cols: usize) type {
    return StarkInner(F, E, max_cols, PcsMod.CommittedMlePcs(F, E));
}

/// Same zero-check STARK, but with a caller-chosen committed-MLE PCS. The PCS
/// must expose `Proof`, `commit(allocator, table) -> MerkleTree`,
/// `proveEval(allocator, k, table, r) -> Proof` and
/// `verifyEval(allocator, root, k, r, proof) -> bool`. `CommittedMlePcs` opens
/// all 2^k entries; `PackedPcsStark` (from `packed_pcs.zig`) opens only the
/// packed rows and a few sampled columns, giving sub-linear proofs.
pub fn BiniusStarkWith(comptime F: type, comptime E: type, comptime max_cols: usize, comptime CP: type) type {
    return StarkInner(F, E, max_cols, CP);
}

fn StarkInner(comptime F: type, comptime E: type, comptime max_cols: usize, comptime CP: type) type {
    return struct {
        const SC = SumcheckMod.Sumcheck(E);
        const M = PcsMod.MlePcs(F, E);
        const Hash = CoreHash.Hash;

        /// Fiat-Shamir domain separator for this protocol.
        const domain = "zig-stark:binius-stark";

        pub const MaxColumns = max_cols;

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

        /// Boundary assertion pinning witness column `col` to `value` at the
        /// boolean hypercube point `point` (an index in [0, 2^k)). Enforced as
        /// the indicator constraint δ_p(x)·(w_col(x) + value) = 0 for all x,
        /// with δ_p(x) = ∏_j (x_j + 1 + p_j) the Lagrange indicator of `p`, so
        /// it folds into the same zero-check as the user constraints.
        pub const Pin = struct {
            col: usize,
            point: usize,
            value: F,
        };

        /// Committed evaluation of one witness column at a challenge point.
        pub const EvalProof = struct {
            value: E,
            pcs: CP.Proof,
        };

        pub const Proof = struct {
            /// Single zero-check sum-check over the random-linear combination
            /// of all constraints; its claimed sum is zero.
            sumcheck: SC.Proof,
            /// One eval proof per *distinct* factor column, at the sum-check's
            /// challenge point, in first-occurrence order of `factors`.
            evals: []EvalProof,

            pub fn deinit(self: *Proof, allocator: std.mem.Allocator) void {
                self.sumcheck.deinit(allocator);
                for (self.evals) |*e| e.pcs.deinit(allocator);
                allocator.free(self.evals);
            }
        };

        /// Derive the protocol randomness from a single Fiat-Shamir channel.
        ///
        /// The channel absorbs the public input bytes, then the boundary pins
        /// (col, point, value), then the commitment roots, samples the
        /// zero-check point τ ∈ E^k, the combination coefficients α_t (one per
        /// constraint, user and pin), and finally the seed that binds the inner
        /// sum-check transcript. Prover and verifier must replay the transcript
        /// identically; the caller frees `tau` and `alphas`.
        fn deriveChallenges(
            allocator: std.mem.Allocator,
            k: usize,
            roots: []const Hash.Digest,
            num_constraints: usize,
            pins: []const Pin,
            public_inputs: []const u8,
            out_seed: *[32]u8,
        ) !struct { tau: []E, alphas: []E } {
            std.debug.assert(roots.len <= max_cols);
            var ch = Channel.init(domain);
            ch.absorbBytes(public_inputs);
            var ubuf: [8]u8 = undefined;
            for (pins) |pin| {
                std.mem.writeInt(u64, &ubuf, pin.col, .little);
                ch.absorbBytes(&ubuf);
                std.mem.writeInt(u64, &ubuf, pin.point, .little);
                ch.absorbBytes(&ubuf);
                ch.absorb(pin.value);
            }
            for (roots) |r| ch.absorbDigest(r);

            const tau = try allocator.alloc(E, k);
            errdefer allocator.free(tau);
            for (0..k) |j| tau[j] = ch.sample(E);

            const alphas = try allocator.alloc(E, num_constraints);
            errdefer allocator.free(alphas);
            for (0..num_constraints) |t| alphas[t] = ch.sample(E);

            ch.sampleBytes(out_seed);
            return .{ .tau = tau, .alphas = alphas };
        }

        /// Flatten all constraints into combination terms over the shared
        /// tables [w_0..w_{m-1}, ℓ_0..ℓ_{k-1}]: term coeff = α_t·c_u and
        /// indices = the factor columns followed by the k kernel-table slots.
        fn buildTerms(
            allocator: std.mem.Allocator,
            m: usize,
            k: usize,
            alphas: []const E,
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
                    terms[ti] = .{ .coeff = alphas[t].mul(M.lift(mono.coeff)), .indices = indices };
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

        /// The distinct pinned points in first-occurrence order. The pin-kernel
        /// tables are laid out k at a time per distinct point, so both sides
        /// must agree on this ordering. Caller frees the returned slice.
        fn distinctPoints(allocator: std.mem.Allocator, pins: []const Pin) ![]usize {
            var seen = std.AutoHashMap(usize, void).init(allocator);
            defer seen.deinit();
            var out: std.ArrayList(usize) = .empty;
            defer out.deinit(allocator);
            for (pins) |pin| {
                if (seen.contains(pin.point)) continue;
                try seen.put(pin.point, {});
                try out.append(allocator, pin.point);
            }
            return try out.toOwnedSlice(allocator);
        }

        /// Build the boundary-pin constraints appended after the user's: for
        /// each pin (col, point → value) the indicator constraint
        ///
        ///     δ_p(x)·(w_col(x) + value) = 0,  δ_p(x) = ∏_j (x_j + 1 + p_j),
        ///
        /// whose two monomials are `1·δ_p·w_col` and `value·δ_p`. The pin-kernel
        /// tables ℓ_j = x_j + 1 + p_j occupy shared-table slots
        /// [m + k + dp·k .. m + k + (dp+1)·k) for the dp-th distinct point, so
        /// both prover and verifier can address them without committing them.
        /// The caller frees the returned slice, each constraint's `terms`, and
        /// each term's `factors`.
        fn buildPinConstraints(
            allocator: std.mem.Allocator,
            k: usize,
            m: usize,
            pins: []const Pin,
        ) ![]Constraint {
            const pts = try distinctPoints(allocator, pins);
            defer allocator.free(pts);

            const out = try allocator.alloc(Constraint, pins.len);
            var filled: usize = 0;
            errdefer {
                for (0..filled) |i| {
                    for (out[i].terms) |tm| allocator.free(tm.factors);
                    allocator.free(out[i].terms);
                }
                allocator.free(out);
            }

            for (pins, 0..) |pin, i| {
                var dp: usize = 0;
                while (pts[dp] != pin.point) dp += 1;
                const base = m + k + dp * k;

                const terms = try allocator.alloc(Monomial, 2);
                const fa = try allocator.alloc(usize, k + 1);
                for (0..k) |j| fa[j] = base + j;
                fa[k] = pin.col;
                const fb = try allocator.alloc(usize, k);
                for (0..k) |j| fb[j] = base + j;

                terms[0] = .{ .coeff = F.one(), .factors = fa };
                terms[1] = .{ .coeff = pin.value, .factors = fb };
                out[i] = .{ .terms = terms };
                filled += 1;
            }
            return out;
        }

        /// Append the built pin constraints after the user's and copy into one
        /// contiguous slice (used by both sides so the α_t indexing matches).
        fn combineConstraints(
            allocator: std.mem.Allocator,
            constraints: []const Constraint,
            pin_constraints: []const Constraint,
        ) ![]Constraint {
            const out = try allocator.alloc(Constraint, constraints.len + pin_constraints.len);
            for (constraints, 0..) |c, i| out[i] = c;
            for (pin_constraints, 0..) |c, i| out[constraints.len + i] = c;
            return out;
        }

        /// Prover: commit the witness columns, derive τ and α_t from the
        /// transcript (public inputs + pins + roots), run a single combined
        /// zero-check sum-check over the user and pin constraints, and open
        /// each distinct factor column once at the challenge point.
        pub fn prove(
            allocator: std.mem.Allocator,
            k: usize,
            columns: []const []const F,
            constraints: []const Constraint,
            pins: []const Pin,
            public_inputs: []const u8,
        ) !Proof {
            const m = columns.len;
            const n = @as(usize, 1) << @intCast(k);
            std.debug.assert(m <= max_cols);
            for (columns) |c| std.debug.assert(c.len == n);
            for (pins) |pin| {
                std.debug.assert(pin.col < m);
                std.debug.assert(pin.point < n);
            }

            var roots: [max_cols]Hash.Digest = undefined;
            for (0..m) |j| {
                var tree = try CP.commit(allocator, columns[j]);
                defer tree.deinit();
                roots[j] = tree.root();
            }
            const rsl = roots[0..m];

            var seed: [32]u8 = undefined;
            const dch = try deriveChallenges(allocator, k, rsl, constraints.len + pins.len, pins, public_inputs, &seed);
            defer allocator.free(dch.tau);
            defer allocator.free(dch.alphas);
            const tau = dch.tau;
            const alphas = dch.alphas;

            const kt = try M.kernelTables(allocator, k, tau);
            defer {
                for (kt) |t| allocator.free(t);
                allocator.free(kt);
            }

            const pts = try distinctPoints(allocator, pins);
            defer allocator.free(pts);

            // Lift the witness columns into E (zero-cost embedding) so all
            // shared tables used by the sum-check live in the extension field.
            const lifted_cols = try allocator.alloc([]E, m);
            var filled: usize = 0;
            errdefer {
                for (0..filled) |j| allocator.free(lifted_cols[j]);
                allocator.free(lifted_cols);
            }
            for (0..m) |j| {
                lifted_cols[j] = try allocator.alloc(E, n);
                filled += 1;
                for (columns[j], 0..) |v, i| lifted_cols[j][i] = M.lift(v);
            }
            defer {
                for (lifted_cols) |lc| allocator.free(lc);
                allocator.free(lifted_cols);
            }

            // Shared tables: witness columns, τ-kernel, then the pin-kernel
            // tables (k per distinct pin point).
            const tables = try allocator.alloc([]const E, m + k + pts.len * k);
            defer allocator.free(tables);
            for (0..m) |j| tables[j] = lifted_cols[j];
            for (0..k) |j| tables[m + j] = kt[j];

            const pin_tables = try allocator.alloc([]E, pts.len * k);
            var pfilled: usize = 0;
            errdefer {
                for (0..pfilled) |i| allocator.free(pin_tables[i]);
                allocator.free(pin_tables);
            }
            for (pts, 0..) |p, dp| {
                var pvec: [64]E = undefined;
                for (0..k) |j| pvec[j] = E.fromInt(@intFromBool((p >> @intCast(j)) & 1 == 1));
                const pt = try M.kernelTables(allocator, k, pvec[0..k]);
                for (0..k) |j| {
                    tables[m + k + dp * k + j] = pt[j];
                    pin_tables[pfilled] = pt[j];
                    pfilled += 1;
                }
            }
            defer {
                for (0..pfilled) |i| allocator.free(pin_tables[i]);
                allocator.free(pin_tables);
            }

            const pin_constraints = try buildPinConstraints(allocator, k, m, pins);
            defer {
                for (pin_constraints) |con| {
                    for (con.terms) |tm| allocator.free(tm.factors);
                    allocator.free(con.terms);
                }
                allocator.free(pin_constraints);
            }
            const combined = try combineConstraints(allocator, constraints, pin_constraints);
            defer allocator.free(combined);

            const terms = try buildTerms(allocator, m, k, alphas, combined);
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
            for (combined) |con| {
                for (con.terms) |mono| {
                    for (mono.factors) |fidx| {
                        if (fidx >= m) continue; // pin-kernel tables are public, not opened
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

        /// Verifier: replay the transcript (public inputs + pins + roots),
        /// derive τ and α_t, replay the combined sum-check rounds, verify every
        /// committed MLE evaluation against its root, and check that the
        /// combined constraint sum (user + pins) vanishes (the zero-check).
        pub fn verify(
            allocator: std.mem.Allocator,
            k: usize,
            roots: []const Hash.Digest,
            constraints: []const Constraint,
            pins: []const Pin,
            proof: Proof,
            public_inputs: []const u8,
        ) !bool {
            const m = roots.len;
            const n = @as(usize, 1) << @intCast(k);
            for (pins) |pin| {
                if (pin.col >= m) return false;
                if (pin.point >= n) return false;
            }

            var seed: [32]u8 = undefined;
            const dch = try deriveChallenges(allocator, k, roots, constraints.len + pins.len, pins, public_inputs, &seed);
            defer allocator.free(dch.tau);
            defer allocator.free(dch.alphas);
            const tau = dch.tau;
            const alphas = dch.alphas;

            // The zero-check: the combined constraint sum must vanish.
            if (!proof.sumcheck.claimed_sum.isZero()) return false;
            if (proof.sumcheck.rounds.len != k) return false;

            const pts = try distinctPoints(allocator, pins);
            defer allocator.free(pts);
            const pin_constraints = try buildPinConstraints(allocator, k, m, pins);
            defer {
                for (pin_constraints) |con| {
                    for (con.terms) |tm| allocator.free(tm.factors);
                    allocator.free(con.terms);
                }
                allocator.free(pin_constraints);
            }
            const combined = try combineConstraints(allocator, constraints, pin_constraints);
            defer allocator.free(combined);

            const dmax = maxDegree(k, combined);
            for (proof.sumcheck.rounds) |coeffs| {
                if (coeffs.len != dmax + 1) return false;
            }

            const total_tables = m + k + pts.len * k;
            for (combined) |con| {
                for (con.terms) |mono| {
                    for (mono.factors) |fidx| {
                        if (fidx >= total_tables) return false;
                    }
                }
            }

            const rr = (try SC.runRounds(allocator, &seed, proof.sumcheck.claimed_sum, proof.sumcheck.rounds)) orelse return false;
            defer allocator.free(rr.challenges);

            // Distinct witness factor columns, first-occurrence order; pin-kernel
            // slots (≥ m) are public tables and are never opened.
            var seen: [MaxColumns]bool = [_]bool{false} ** MaxColumns;
            var distinct: [MaxColumns]usize = undefined;
            var count: usize = 0;
            for (combined) |con| {
                for (con.terms) |mono| {
                    for (mono.factors) |fidx| {
                        if (fidx >= m) continue;
                        if (fidx >= max_cols) return false;
                        if (seen[fidx]) continue;
                        seen[fidx] = true;
                        distinct[count] = fidx;
                        count += 1;
                    }
                }
            }
            if (proof.evals.len != count) return false;

            var value_of: [MaxColumns]E = undefined;
            for (0..count) |l| {
                const ok = try CP.verifyEval(allocator, roots[distinct[l]], k, rr.challenges, proof.evals[l].pcs);
                if (!ok) return false;
                value_of[distinct[l]] = proof.evals[l].value;
            }

            // Final value of the combined summand at the challenge point:
            // Σ_t α_t · Σ_u c_u · (∏ over every factor of its table value at
            // τ') with the τ-kernel slots [m..m+k) and pin-kernel slots
            // [m+k..) evaluated directly (ℓ_j(t) = t + 1 + r_j for boolean r_j
            // from the pinned point). Coefficients c_u ∈ F are lifted into E.
            var acc = E.zero();
            for (combined, 0..) |con, t| {
                for (con.terms) |mono| {
                    var prod = E.one();
                    for (mono.factors) |fidx| {
                        if (fidx < m) {
                            prod = prod.mul(value_of[fidx]);
                        } else if (fidx < m + k) {
                            const j = fidx - m;
                            prod = prod.mul(E.one().add(tau[j]).add(rr.challenges[j]));
                        } else {
                            const off = fidx - m - k;
                            const dp = off / k;
                            const j = off % k;
                            const pj = E.fromInt(@intFromBool((pts[dp] >> @intCast(j)) & 1 == 1));
                            prod = prod.mul(E.one().add(pj).add(rr.challenges[j]));
                        }
                    }
                    for (0..k) |j| prod = prod.mul(E.one().add(tau[j]).add(rr.challenges[j]));
                    acc = acc.add(alphas[t].mul(M.lift(mono.coeff)).mul(prod));
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
const TowerField = @import("tower.zig").TowerField;
const Gf2_128 = TowerField(7);
const ScriptGf16 = @import("field.zig").Gf16;
const S = BiniusStark(Gf16, Gf16, 16);

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
    const proof = try S.prove(alloc, k, &columns, &constraints, &.{}, "");

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(try S.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
}

test "non-boolean witness is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const SF = BiniusStark(Gf256, Gf256, 16);

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
    const proof = try SF.prove(alloc, k, &columns, &constraints, &.{}, "");

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf256, Gf256).commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(!try SF.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
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
    const proof = try S.prove(alloc, k, &columns, &constraints, &.{}, "");

    var roots: [3]CoreHash.Hash.Digest = undefined;
    {
        var tf = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &f);
        var tg = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &g);
        var th = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &h);
        roots[0] = tf.root();
        roots[1] = tg.root();
        roots[2] = th.root();
    }
    try std.testing.expect(try S.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
}

test "wrong product is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const SF = BiniusStark(Gf256, Gf256, 16);

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
    const proof = try SF.prove(alloc, k, &columns, &constraints, &.{}, "");

    var roots: [3]CoreHash.Hash.Digest = undefined;
    {
        var tf = try @import("pcs.zig").CommittedMlePcs(Gf256, Gf256).commit(alloc, &f);
        var tg = try @import("pcs.zig").CommittedMlePcs(Gf256, Gf256).commit(alloc, &g);
        var th = try @import("pcs.zig").CommittedMlePcs(Gf256, Gf256).commit(alloc, &h);
        roots[0] = tf.root();
        roots[1] = tg.root();
        roots[2] = th.root();
    }
    try std.testing.expect(!try SF.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
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
    const proof = try S.prove(alloc, k, &columns, &constraints, &.{}, "");

    var roots: [4]CoreHash.Hash.Digest = undefined;
    {
        var tw = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &w);
        var tf = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &f);
        var tg = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &g);
        var th = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &h);
        roots[0] = tw.root();
        roots[1] = tf.root();
        roots[2] = tg.root();
        roots[3] = th.root();
    }
    try std.testing.expect(try S.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
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
    const proof = try S.prove(alloc, k, &columns, &constraints, &.{}, "");

    // Flip one witness bit and commit the tampered column.
    var bad: [8]Gf16 = w;
    bad[2] = fe(2);
    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &bad);
        roots[0] = tree.root();
    }
    try std.testing.expect(!try S.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
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
    const proof = try S.prove(alloc, k, &columns, &constraints, &.{}, "");
    try std.testing.expectEqual(@as(usize, 3), proof.evals.len);

    var roots: [3]CoreHash.Hash.Digest = undefined;
    {
        var tw = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &w);
        var tf = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &f);
        var tg = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf16).commit(alloc, &g);
        roots[0] = tw.root();
        roots[1] = tf.root();
        roots[2] = tg.root();
    }
    try std.testing.expect(try S.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
}

test "stark runs over tower GF(256)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const SF = BiniusStark(Gf256, Gf256, 16);

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
    const proof = try SF.prove(alloc, k, &columns, &constraints, &.{}, "");

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf256, Gf256).commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(try SF.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
}

test "challenges span the full GF(256) field" {
    var ch = Channel.init(BiniusStark(Gf256, Gf256, 16).domain);
    ch.absorbBytes("");
    ch.absorbDigest(CoreHash.Hash.hashBytes("roots"));

    // Regression for the 4-bit mask bug: sampled challenges must span more
    // than the 16 values reachable with a 4-bit sample on an 8-bit field.
    var seen = [_]bool{false} ** 256;
    var count: usize = 0;
    for (0..128) |_| {
        const v = ch.sample(Gf256);
        if (!seen[@as(usize, @intCast(v.value))]) {
            seen[@as(usize, @intCast(v.value))] = true;
            count += 1;
        }
    }
    try std.testing.expect(count > 16);
}

test "public inputs are bound by the Fiat-Shamir transcript" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const SF = BiniusStark(Gf256, Gf256, 16);

    const k = 3;
    var w: [8]Gf256 = undefined;
    for (0..8) |i| w[i] = Gf256.fromInt(@intFromBool((i * 3 + 1) % 2 == 1));

    const booleanness = [_]SF.Monomial{
        .{ .coeff = Gf256.one(), .factors = &.{0} },
        .{ .coeff = Gf256.one(), .factors = &.{ 0, 0 } },
    };
    const constraints = [_]SF.Constraint{.{
        .terms = &booleanness,
    }};
    const columns = [_][]const Gf256{&w};
    const pub_in = "pinned statement: k=3";

    const proof = try SF.prove(alloc, k, &columns, &constraints, &.{}, pub_in);

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf256, Gf256).commit(alloc, &w);
        roots[0] = tree.root();
    }
    // The same public input verifies...
    try std.testing.expect(try SF.verify(alloc, k, &roots, &constraints, &.{}, proof, pub_in));
    // ...but any alteration breaks the challenge chain and rejects.
    try std.testing.expect(!try SF.verify(alloc, k, &roots, &constraints, &.{}, proof, "pinned statement: k=2"));
    try std.testing.expect(!try SF.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
}

test "boundary pins round trip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const SF = BiniusStark(Gf256, Gf256, 16);

    const k = 3;
    var w: [8]Gf256 = undefined;
    for (0..8) |i| w[i] = Gf256.fromInt(@intFromBool((i * 3 + 1) % 2 == 1));

    const booleanness = [_]SF.Monomial{
        .{ .coeff = Gf256.one(), .factors = &.{0} },
        .{ .coeff = Gf256.one(), .factors = &.{ 0, 0 } },
    };
    const constraints = [_]SF.Constraint{.{
        .terms = &booleanness,
    }};
    const columns = [_][]const Gf256{&w};

    // Pin column 0 at two points to their committed values; the same point
    // used twice (point 6) exercises the distinct-point dedup.
    const pins = [_]SF.Pin{
        .{ .col = 0, .point = 1, .value = w[1] },
        .{ .col = 0, .point = 6, .value = w[6] },
        .{ .col = 0, .point = 6, .value = w[6] },
    };
    const proof = try SF.prove(alloc, k, &columns, &constraints, &pins, "");

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf256, Gf256).commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(try SF.verify(alloc, k, &roots, &constraints, &pins, proof, ""));
}

test "wrong boundary pin value is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const SF = BiniusStark(Gf256, Gf256, 16);

    const k = 3;
    var w: [8]Gf256 = undefined;
    for (0..8) |i| w[i] = Gf256.fromInt(@intFromBool((i * 3 + 1) % 2 == 1));

    const booleanness = [_]SF.Monomial{
        .{ .coeff = Gf256.one(), .factors = &.{0} },
        .{ .coeff = Gf256.one(), .factors = &.{ 0, 0 } },
    };
    const constraints = [_]SF.Constraint{.{
        .terms = &booleanness,
    }};
    const columns = [_][]const Gf256{&w};

    const pins = [_]SF.Pin{
        .{ .col = 0, .point = 1, .value = w[1] },
        .{ .col = 0, .point = 6, .value = w[6] },
    };
    const proof = try SF.prove(alloc, k, &columns, &constraints, &pins, "");

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf256, Gf256).commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(try SF.verify(alloc, k, &roots, &constraints, &pins, proof, ""));

    // A wrong pin value is a public statement the honest witness violates, so
    // the zero-check over the altered constraints must reject.
    const bad_pins = [_]SF.Pin{
        .{ .col = 0, .point = 1, .value = w[1].add(Gf256.one()) },
        .{ .col = 0, .point = 6, .value = w[6] },
    };
    try std.testing.expect(!try SF.verify(alloc, k, &roots, &constraints, &bad_pins, proof, ""));
}

test "pinned constraint proves a boundary evaluation" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const SF = BiniusStark(Gf256, Gf256, 16);

    // The witness is random (no constraints at all); the only thing a verifier
    // learns is the pinned evaluations. An honest proof with matching pins
    // passes, and re-proving over a witness that contradicts a pin fails.
    const k = 3;
    var w: [8]Gf256 = undefined;
    for (0..8) |i| w[i] = Gf256.fromInt(@as(u128, (i * 5 + 2) % 256));

    const constraints = [_]SF.Constraint{};
    const columns = [_][]const Gf256{&w};
    const pins = [_]SF.Pin{
        .{ .col = 0, .point = 3, .value = w[3] },
        .{ .col = 0, .point = 5, .value = w[5] },
    };
    const proof = try SF.prove(alloc, k, &columns, &constraints, &pins, "");

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf256, Gf256).commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(try SF.verify(alloc, k, &roots, &constraints, &pins, proof, ""));

    // Same pins but a witness with w[3] flipped: the pin constraint is violated
    // at point 3, so the zero-check rejects the forged re-proof.
    var bad: [8]Gf256 = w;
    bad[3] = bad[3].add(Gf256.one());
    var bad_roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf256, Gf256).commit(alloc, &bad);
        bad_roots[0] = tree.root();
    }
    const bad_cols = [_][]const Gf256{&bad};
    const forged = try SF.prove(alloc, k, &bad_cols, &constraints, &pins, "");
    try std.testing.expect(!try SF.verify(alloc, k, &bad_roots, &constraints, &pins, forged, ""));
}

test "stark runs over the Script field GF(16)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const SF = BiniusStark(ScriptGf16, ScriptGf16, 16);

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
    const proof = try SF.prove(alloc, k, &columns, &constraints, &.{}, "");

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(ScriptGf16, ScriptGf16).commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(try SF.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
}

test "stark with boundary pins over the GF(2^128) extension" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const SF = BiniusStark(Gf16, Gf2_128, 16);

    const k = 3;
    var w: [8]Gf16 = undefined;
    for (0..8) |i| w[i] = fe(@intFromBool((i * 3 + 1) % 2 == 1));

    const booleanness = [_]SF.Monomial{
        .{ .coeff = fe(1), .factors = &.{0} },
        .{ .coeff = fe(1), .factors = &.{ 0, 0 } },
    };
    const constraints = [_]SF.Constraint{.{
        .terms = &booleanness,
    }};
    const columns = [_][]const Gf16{&w};
    const pins = [_]SF.Pin{
        .{ .col = 0, .point = 1, .value = w[1] },
        .{ .col = 0, .point = 6, .value = w[6] },
    };
    const proof = try SF.prove(alloc, k, &columns, &constraints, &pins, "");

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try @import("pcs.zig").CommittedMlePcs(Gf16, Gf2_128).commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(try SF.verify(alloc, k, &roots, &constraints, &pins, proof, ""));

    // A wrong pin value is a public statement the honest witness violates, so
    // the zero-check over the altered constraints must reject.
    const bad_pins = [_]SF.Pin{
        .{ .col = 0, .point = 1, .value = w[1].add(fe(1)) },
        .{ .col = 0, .point = 6, .value = w[6] },
    };
    try std.testing.expect(!try SF.verify(alloc, k, &roots, &constraints, &bad_pins, proof, ""));
}

// ---------------------------------------------------------------------------
// Packed-PCS opening mode (sub-linear commitments via PackedPcsStark)
// ---------------------------------------------------------------------------

const PcsPacked = @import("packed_pcs.zig");

test "packed PCS mode: booleanness round trip over Gf16" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const Pcs = PcsPacked.PackedPcsStark(Gf16, Gf16, .{ .k2 = 1, .log_blowup = 2, .num_queries = 6 });
    const SP = BiniusStarkWith(Gf16, Gf16, 16, Pcs);

    const k = 3;
    var w: [8]Gf16 = undefined;
    for (0..8) |i| w[i] = fe(@intFromBool((i * 3 + 1) % 2 == 1));

    const booleanness = [_]SP.Monomial{
        .{ .coeff = fe(1), .factors = &.{0} },
        .{ .coeff = fe(1), .factors = &.{ 0, 0 } },
    };
    const constraints = [_]SP.Constraint{.{
        .terms = &booleanness,
    }};

    const columns = [_][]const Gf16{&w};
    const proof = try SP.prove(alloc, k, &columns, &constraints, &.{}, "");

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try Pcs.commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(try SP.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
}

test "packed PCS mode: multiplication relation h = f·g over Gf256 at k=6" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const Pcs = PcsPacked.PackedPcsStark(Gf256, Gf256, .{ .k2 = 3, .log_blowup = 2, .num_queries = 6 });
    const SP = BiniusStarkWith(Gf256, Gf256, 16, Pcs);

    const k = 6;
    var f: [64]Gf256 = undefined;
    var g: [64]Gf256 = undefined;
    var h: [64]Gf256 = undefined;
    for (0..64) |i| {
        f[i] = Gf256.fromInt((i * 5 + 2) % 256);
        g[i] = Gf256.fromInt((i * 3 + 7) % 256);
        h[i] = f[i].mul(g[i]);
    }

    // R = h + f·g == 0
    const rel = [_]SP.Monomial{
        .{ .coeff = Gf256.one(), .factors = &.{2} },
        .{ .coeff = Gf256.one(), .factors = &.{ 0, 1 } },
    };
    const constraints = [_]SP.Constraint{.{
        .terms = &rel,
    }};

    const columns = [_][]const Gf256{ &f, &g, &h };
    const proof = try SP.prove(alloc, k, &columns, &constraints, &.{}, "");

    var roots: [3]CoreHash.Hash.Digest = undefined;
    {
        var tf = try Pcs.commit(alloc, &f);
        var tg = try Pcs.commit(alloc, &g);
        var th = try Pcs.commit(alloc, &h);
        roots[0] = tf.root();
        roots[1] = tg.root();
        roots[2] = th.root();
    }
    try std.testing.expect(try SP.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
}

test "packed PCS mode: round trip in the extension field (F=Gf16, E=Gf2^128)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const Pcs = PcsPacked.PackedPcsStark(Gf16, Gf2_128, .{ .k2 = 1, .log_blowup = 2, .num_queries = 6 });
    const SP = BiniusStarkWith(Gf16, Gf2_128, 16, Pcs);

    const k = 2;
    var w: [4]Gf16 = undefined;
    for (0..4) |i| w[i] = fe(@intFromBool((i * 3 + 1) % 2 == 1));

    const booleanness = [_]SP.Monomial{
        .{ .coeff = fe(1), .factors = &.{0} },
        .{ .coeff = fe(1), .factors = &.{ 0, 0 } },
    };
    const constraints = [_]SP.Constraint{.{
        .terms = &booleanness,
    }};

    const columns = [_][]const Gf16{&w};
    const proof = try SP.prove(alloc, k, &columns, &constraints, &.{}, "");

    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try Pcs.commit(alloc, &w);
        roots[0] = tree.root();
    }
    try std.testing.expect(try SP.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
}

test "packed PCS mode: wrong product is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const Pcs = PcsPacked.PackedPcsStark(Gf16, Gf16, .{ .k2 = 1, .log_blowup = 2, .num_queries = 6 });
    const SP = BiniusStarkWith(Gf16, Gf16, 16, Pcs);

    // h' = h + 1 is not f·g; the prover's witness violates the constraint, so
    // the zero-check sum Σ (h' + f·g) = Σ 1 = 1 ≠ 0 survives any τ and the
    // packed-PCS openings (which are honest w.r.t. the committed roots) cannot
    // rescue it.
    const k = 3;
    var f: [8]Gf16 = undefined;
    var g: [8]Gf16 = undefined;
    var hp: [8]Gf16 = undefined;
    for (0..8) |i| {
        f[i] = fe((i * 5 + 2) % 16);
        g[i] = fe((i * 3 + 7) % 16);
        hp[i] = f[i].mul(g[i]).add(fe(1));
    }

    const rel = [_]SP.Monomial{
        .{ .coeff = fe(1), .factors = &.{2} },
        .{ .coeff = fe(1), .factors = &.{ 0, 1 } },
    };
    const constraints = [_]SP.Constraint{.{
        .terms = &rel,
    }};

    const columns = [_][]const Gf16{ &f, &g, &hp };
    const proof = try SP.prove(alloc, k, &columns, &constraints, &.{}, "");

    var roots: [3]CoreHash.Hash.Digest = undefined;
    {
        var tf = try Pcs.commit(alloc, &f);
        var tg = try Pcs.commit(alloc, &g);
        var th = try Pcs.commit(alloc, &hp);
        roots[0] = tf.root();
        roots[1] = tg.root();
        roots[2] = th.root();
    }
    try std.testing.expect(!try SP.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
}

test "packed PCS mode: wrong commitment root is rejected" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const Pcs = PcsPacked.PackedPcsStark(Gf16, Gf16, .{ .k2 = 1, .log_blowup = 2, .num_queries = 6 });
    const SP = BiniusStarkWith(Gf16, Gf16, 16, Pcs);

    const k = 3;
    var w: [8]Gf16 = undefined;
    for (0..8) |i| w[i] = fe(@intFromBool((i * 3 + 1) % 2 == 1));
    var wrong: [8]Gf16 = w;
    wrong[0] = wrong[0].add(fe(1));

    const booleanness = [_]SP.Monomial{
        .{ .coeff = fe(1), .factors = &.{0} },
        .{ .coeff = fe(1), .factors = &.{ 0, 0 } },
    };
    const constraints = [_]SP.Constraint{.{
        .terms = &booleanness,
    }};

    const columns = [_][]const Gf16{&w};
    const proof = try SP.prove(alloc, k, &columns, &constraints, &.{}, "");

    // Commit a different table: the Merkle opening of the opened column can no
    // longer match, so the packed PCS evaluation check fails.
    var roots: [1]CoreHash.Hash.Digest = undefined;
    {
        var tree = try Pcs.commit(alloc, &wrong);
        roots[0] = tree.root();
    }
    try std.testing.expect(!try SP.verify(alloc, k, &roots, &constraints, &.{}, proof, ""));
}
