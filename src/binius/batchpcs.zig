const std = @import("std");

const Tower = @import("tower.zig");
const FriMod = @import("fripcs.zig");
const CoreHash = @import("../core/hash/hash.zig");
const CoreMerkle = @import("../core/merkle/merkle.zig");

/// Batched FRI-Binius committed MLE PCS: opens `c` columns at ONE point with a
/// single FRI proof whose per-layer Merkle trees are *shared* across columns.
///
/// The STARK opens every distinct witness column at the same challenge point
/// τ'. Running `c` independent `FriPcs` proofs repeats the dominant cost
/// `num_queries` times per column: the per-query Merkle paths. This module
/// folds all `c` columns' codes in lockstep (each column with its own
/// sum-check round challenges, so every claimed evaluation stays individually
/// bound) but commits each folded layer as ONE tree whose leaf hashes the
/// `c` symbol pairs at that position. A query then opens every column with a
/// single Merkle path per round, cutting the path section by a factor of `c`.
///
/// Soundness is unchanged from `FriPcs`: each column's eval sum-check binds
/// `f_j(r)` individually (its own coeffs/challenges in the transcript), the
/// fold identity `fold^k(code_j, ch) = f_j(ch)` binds the committed code to
/// the final sum-check claim via `claim_k == final_folded·∏_j(1+r_j+ch_j)`,
/// and the per-column fold chains are verified against the shared trees with
/// Merkle paths. Sharing the tree only commits the same values in one Merkle
/// structure instead of `c`; it does not change what is proven.
pub fn BatchFriPcs(
    comptime F: type,
    comptime E: type,
    comptime log_blowup: u8,
    comptime num_queries: usize,
) type {
    const Hash = CoreHash.Hash;
    const MerkleTree = CoreMerkle.MerkleTree;
    const Digest = Hash.Digest;
    const Ntt = FriMod.Ntt;
    const foldCodeE = FriMod.foldCodeE;
    const foldLo = FriMod.foldLo;
    const eqEvalE = FriMod.eqEvalE;
    const sampleQueries = FriMod.sampleQueries;
    const Transcript = FriMod.Transcript;
    const absorbElem = FriMod.absorbElem;
    const sampleE = FriMod.sampleE;
    const log2Len = FriMod.log2Len;

    return struct {
        const Self = @This();

        pub const Round = struct {
            /// `coeffs[c*3..(c+1)*3]` holds column c's [eval_at_0, mid, eval_at_inf].
            coeffs: []E,
            /// one fold challenge per column (each column's own sum-check).
            challenge: []E,
        };

        pub const LayerProof = struct {
            /// one opened pair per column at the shared query position.
            s0: []E,
            s1: []E,
            /// shared Merkle path (all columns in the same layer tree).
            path: []Digest,
        };

        pub const Query = struct {
            /// leaf index in the shared layer-0 tree, ∈ [0, 2^(D-1)).
            index: usize,
            /// one shared opening per round (layers 0..k-1).
            layers: []LayerProof,
        };

        pub const Proof = struct {
            /// claimed MLE evaluation per column at `r` (sum-check claim_0).
            values: []E,
            /// one round of per-column sum-check data per fold step.
            rounds: []Round,
            /// shared roots of the folded layers 1..k, in round order.
            layer_roots: []Digest,
            /// root of the shared layer-0 tree.
            layer0_root: Digest,
            /// per-column constant fully-folded code values.
            final_folded: []E,
            /// shared queries (each opens every column).
            queries: []Query,

            /// Owns `values`, `rounds` (and each round's slices), `layer_roots`,
            /// `final_folded`, `queries`, and each query's layers/paths/symbols;
            /// release with `deinit(allocator)` using the allocator passed to
            /// `proveEvalBatch`.
            pub fn deinit(self: *Proof, allocator: std.mem.Allocator) void {
                for (self.rounds) |*r| {
                    allocator.free(r.coeffs);
                    allocator.free(r.challenge);
                }
                allocator.free(self.rounds);
                for (self.queries) |*q| {
                    for (q.layers) |*lp| {
                        allocator.free(lp.s0);
                        allocator.free(lp.s1);
                        allocator.free(lp.path);
                    }
                    allocator.free(q.layers);
                }
                allocator.free(self.queries);
                allocator.free(self.layer_roots);
                allocator.free(self.final_folded);
                allocator.free(self.values);
            }
        };

        /// Leaf hash over all `c` columns' symbol pairs at one position.
        fn hashPairs(allocator: std.mem.Allocator, pairs: []const []const E) !Digest {
            const c = pairs.len;
            const buf = try allocator.alloc(u8, c * 2 * E.SIZE);
            defer allocator.free(buf);
            var off: usize = 0;
            for (pairs) |p| {
                var a: [E.SIZE]u8 = undefined;
                var b: [E.SIZE]u8 = undefined;
                p[0].toBytes(&a);
                p[1].toBytes(&b);
                @memcpy(buf[off..][0..E.SIZE], &a);
                @memcpy(buf[off + E.SIZE ..][0..E.SIZE], &b);
                off += 2 * E.SIZE;
            }
            return Hash.hashBytes(buf);
        }

        /// Per-column commit of the layer-0 code tree (the STARK's roots).
        pub fn commit(allocator: std.mem.Allocator, table: []const F) !MerkleTree {
            return FriMod.FriPcs(F, E, log_blowup, num_queries).commit(allocator, table);
        }

        pub fn proveEvalBatch(
            allocator: std.mem.Allocator,
            k: usize,
            tables: []const []const F,
            roots: []const Digest,
            r: []const E,
        ) !Proof {
            const c = tables.len;
            std.debug.assert(c >= 1);
            std.debug.assert(roots.len == c);
            std.debug.assert(k >= 1);
            std.debug.assert(k == log2Len(tables[0].len));
            std.debug.assert(r.len == k);
            const D: u8 = @intCast(k + log_blowup);
            std.debug.assert(log_blowup >= 1);
            std.debug.assert(D <= F.BITS);
            const total_leaves0: usize = @as(usize, 1) << @intCast(D - 1);
            std.debug.assert(num_queries >= 1 and num_queries <= total_leaves0);

            var tmp = std.heap.ArenaAllocator.init(allocator);
            defer tmp.deinit();
            const ta = tmp.allocator();

            var ntt = try Ntt(F).init(ta, D);

            // Per-column working state: lifted mle, eq kernel, and current code.
            const mles = try ta.alloc([]E, c);
            const eqs = try ta.alloc([]E, c);
            // code_layers[j][round] = column j's code at fold round `round`
            // (round 0 is the layer-0 code). Used for the shared trees + queries.
            const code_layers = try ta.alloc([]E, c * (k + 1));
            var values = try allocator.alloc(E, c);
            errdefer allocator.free(values);
            const claims = try ta.alloc(E, c);

            for (0..c) |j| {
                const mle = try ta.alloc(E, tables[j].len);
                for (tables[j], 0..) |v, i| mle[i] = E.embed(F.LEVEL, v);
                mles[j] = mle;
                const eq = try ta.alloc(E, tables[j].len);
                for (0..tables[j].len) |i| eq[i] = eqEvalE(E, r, i);
                eqs[j] = eq;

                var s = E.zero();
                for (0..tables[j].len) |i| s = s.add(mle[i].mul(eq[i]));
                values[j] = s;
                claims[j] = s;

                const code = try ntt.encode(ta, tables[j], log_blowup);
                const lifted = try ta.alloc(E, code.len);
                for (code, 0..) |v, i| lifted[i] = E.embed(F.LEVEL, v);
                code_layers[j * (k + 1)] = lifted;
            }

            // Shared layer-0 tree over all columns' pairs.
            const l0_leaves = try ta.alloc(Digest, total_leaves0);
            const pair_buf = try ta.alloc([]const E, c);
            for (0..total_leaves0) |p| {
                for (0..c) |j| pair_buf[j] = code_layers[j * (k + 1)][p << 1 .. (p << 1) + 2];
                l0_leaves[p] = try hashPairs(ta, pair_buf);
            }
            const tree0 = try MerkleTree.init(ta, l0_leaves);
            const layer0_root = tree0.root();

            // Transcript: bind the per-column commitments and the eval point,
            // then the per-column sum-check data, layer roots, and queries.
            var t = Transcript.init(&layer0_root);
            for (roots) |rt| t.absorb(&rt);
            for (r) |v| absorbElem(E, &t, v);

            const twE = try ta.alloc([]E, D);
            for (0..D) |i| {
                twE[i] = try ta.alloc(E, ntt.twiddles[i].len);
                for (ntt.twiddles[i], 0..) |tw, j| twE[i][j] = E.embed(F.LEVEL, tw);
            }

            const rounds = try allocator.alloc(Round, k);
            errdefer allocator.free(rounds);
            const layer_roots = try allocator.alloc(Digest, k);
            errdefer allocator.free(layer_roots);

            var trees = try ta.alloc(MerkleTree, k + 1);
            trees[0] = tree0;
            var mle_cur = mles;
            var eq_cur = eqs;
            var claim_cur = claims;

            for (0..k) |round| {
                // Per-column sum-check coefficients for this round.
                var coeffs = try allocator.alloc(E, c * 3);
                errdefer allocator.free(coeffs);
                for (0..c) |j| {
                    const half = mle_cur[j].len >> 1;
                    var eval_at_0 = E.zero();
                    var eval_at_inf = E.zero();
                    for (0..half) |i| {
                        eval_at_0 = eval_at_0.add(mle_cur[j][i << 1].mul(eq_cur[j][i << 1]));
                        const mv = mle_cur[j][i << 1].add(mle_cur[j][(i << 1) | 1]);
                        const ev = eq_cur[j][i << 1].add(eq_cur[j][(i << 1) | 1]);
                        eval_at_inf = eval_at_inf.add(mv.mul(ev));
                    }
                    const eval_at_1 = claim_cur[j].sub(eval_at_0);
                    coeffs[j * 3] = eval_at_0;
                    coeffs[j * 3 + 1] = eval_at_0.add(eval_at_1).add(eval_at_inf);
                    coeffs[j * 3 + 2] = eval_at_inf;
                }
                for (coeffs) |*cv| absorbElem(E, &t, cv.*);

                // Sample one fold challenge per column, then fold each column's
                // mle, eq, and code with its own challenge.
                const challenge = try allocator.alloc(E, c);
                errdefer allocator.free(challenge);
                const nxt_mles = try ta.alloc([]E, c);
                const nxt_eqs = try ta.alloc([]E, c);
                const nxt_codes = try ta.alloc([]E, c);
                for (0..c) |j| {
                    const r_j = sampleE(E, &t);
                    challenge[j] = r_j;
                    claim_cur[j] = coeffs[j * 3].add(coeffs[j * 3 + 1].mul(r_j)).add(coeffs[j * 3 + 2].mul(r_j.mul(r_j)));

                    const nxt_mle = try ta.alloc(E, mle_cur[j].len >> 1);
                    const nxt_eq = try ta.alloc(E, eq_cur[j].len >> 1);
                    foldLo(E, mle_cur[j], r_j, nxt_mle);
                    foldLo(E, eq_cur[j], r_j, nxt_eq);
                    nxt_mles[j] = nxt_mle;
                    nxt_eqs[j] = nxt_eq;

                    const prev_code = code_layers[j * (k + 1) + round];
                    const nxt_code = try ta.alloc(E, prev_code.len >> 1);
                    for (0..prev_code.len >> 1) |i| {
                        nxt_code[i] = foldCodeE(E, twE[round][i], prev_code[i << 1], prev_code[(i << 1) | 1], r_j);
                    }
                    nxt_codes[j] = nxt_code;
                    code_layers[j * (k + 1) + round + 1] = nxt_code;
                }
                rounds[round] = .{ .coeffs = coeffs, .challenge = challenge };
                mle_cur = nxt_mles;
                eq_cur = nxt_eqs;

                // Shared tree for this round's folded layer over all columns.
                const nxt_total = @as(usize, 1) << @intCast(D - 1 - (round + 1));
                const lv = try ta.alloc(Digest, nxt_total);
                for (0..nxt_total) |p| {
                    for (0..c) |j| pair_buf[j] = nxt_codes[j][p << 1 .. (p << 1) + 2];
                    lv[p] = try hashPairs(ta, pair_buf);
                }
                const tr = try MerkleTree.init(ta, lv);
                layer_roots[round] = tr.root();
                t.absorb(&tr.root());
                trees[round + 1] = tr;
            }

            const final_folded = try allocator.alloc(E, c);
            errdefer allocator.free(final_folded);
            for (0..c) |j| {
                final_folded[j] = code_layers[j * (k + 1) + k][0];
                absorbElem(E, &t, final_folded[j]);
            }

            const indices = try sampleQueries(allocator, &t, num_queries, total_leaves0);
            defer allocator.free(indices);

            const queries = try allocator.alloc(Query, num_queries);
            errdefer allocator.free(queries);
            for (indices, 0..) |idx, qi| {
                queries[qi] = .{ .index = idx, .layers = try allocator.alloc(LayerProof, k) };
                var leaf = idx;
                for (0..k) |round| {
                    const lp = &queries[qi].layers[round];
                    lp.path = try trees[round].open(leaf, allocator);
                    lp.s0 = try allocator.alloc(E, c);
                    lp.s1 = try allocator.alloc(E, c);
                    for (0..c) |j| {
                        const cd = code_layers[j * (k + 1) + round];
                        lp.s0[j] = cd[leaf << 1];
                        lp.s1[j] = cd[(leaf << 1) | 1];
                    }
                    leaf >>= 1;
                }
            }

            return .{
                .values = values,
                .rounds = rounds,
                .layer_roots = layer_roots,
                .layer0_root = layer0_root,
                .final_folded = final_folded,
                .queries = queries,
            };
        }

        pub fn verifyEvalBatch(
            allocator: std.mem.Allocator,
            roots: []const Digest,
            k: usize,
            r: []const E,
            proof: Proof,
        ) !bool {
            const c = roots.len;
            if (c == 0) return false;
            if (k < 1) return false;
            if (r.len != k) return false;
            const D: u8 = @intCast(k + log_blowup);
            std.debug.assert(log_blowup >= 1);
            std.debug.assert(D <= F.BITS);
            const total_leaves0: usize = @as(usize, 1) << @intCast(D - 1);
            std.debug.assert(num_queries >= 1 and num_queries <= total_leaves0);

            if (proof.values.len != c) return false;
            if (proof.final_folded.len != c) return false;
            if (proof.rounds.len != k) return false;
            if (proof.layer_roots.len != k) return false;
            if (proof.queries.len != num_queries) return false;

            var tmp = std.heap.ArenaAllocator.init(allocator);
            defer tmp.deinit();
            const ta = tmp.allocator();
            const ntt = try Ntt(F).init(ta, D);
            const twE = try ta.alloc([]E, D);
            for (0..D) |i| {
                twE[i] = try ta.alloc(E, ntt.twiddles[i].len);
                for (ntt.twiddles[i], 0..) |tw, j| twE[i][j] = E.embed(F.LEVEL, tw);
            }

            // Replay the transcript.
            var t = Transcript.init(&proof.layer0_root);
            for (roots) |rt| t.absorb(&rt);
            for (r) |v| absorbElem(E, &t, v);

            var claims = try ta.alloc(E, c);
            for (0..c) |j| claims[j] = proof.values[j];

            for (0..k) |round| {
                const rr = proof.rounds[round];
                if (rr.coeffs.len != c * 3) return false;
                if (rr.challenge.len != c) return false;
                for (0..c) |j| {
                    const coeffs = rr.coeffs[j * 3 .. j * 3 + 3];
                    // p(0) + p(1) == claim ⇔ c1 + c2 == claim (char 2).
                    if (!coeffs[1].add(coeffs[2]).eq(claims[j])) return false;
                    for (coeffs) |*cv| absorbElem(E, &t, cv.*);
                }
                for (0..c) |j| {
                    const r_j = sampleE(E, &t);
                    if (!r_j.eq(rr.challenge[j])) return false;
                    const coeffs = rr.coeffs[j * 3 .. j * 3 + 3];
                    claims[j] = coeffs[0].add(coeffs[1].mul(r_j)).add(coeffs[2].mul(r_j.mul(r_j)));
                }
                t.absorb(&proof.layer_roots[round]);
            }

            // claim_k^j = final_folded[j]·∏_{j'}(1 + r_{j'} + ch^{(j)}_{j'}).
            for (0..c) |j| {
                var eq_factor = E.one();
                for (0..k) |j2| {
                    eq_factor = eq_factor.mul(E.one().add(r[j2]).add(proof.rounds[j2].challenge[j]));
                }
                absorbElem(E, &t, proof.final_folded[j]);
                if (!claims[j].eq(proof.final_folded[j].mul(eq_factor))) return false;
            }

            const indices = try sampleQueries(allocator, &t, num_queries, total_leaves0);
            defer allocator.free(indices);

            // Shared per-round leaf hash for the queried position.
            const sym = try ta.alloc(E, c * 2);
            const pairs = try ta.alloc([]const E, c);

            for (indices, 0..) |q, qi| {
                const query = proof.queries[qi];
                if (query.index != q) return false;
                if (query.layers.len != k) return false;
                for (query.layers) |lp| {
                    if (lp.s0.len != c or lp.s1.len != c) return false;
                }

                var leaf = q;
                const folded = try ta.alloc(E, c);
                for (0..k) |round| {
                    const lp = query.layers[round];
                    if (round > 0) {
                        const expected = if ((leaf & 1) == 1) lp.s1 else lp.s0;
                        for (0..c) |j| if (!folded[j].eq(expected[j])) return false;
                        leaf >>= 1;
                    }
                    for (0..c) |j| {
                        sym[j * 2] = lp.s0[j];
                        sym[j * 2 + 1] = lp.s1[j];
                        pairs[j] = sym[j * 2 .. j * 2 + 2];
                    }
                    const round_root = if (round == 0) proof.layer0_root else proof.layer_roots[round - 1];
                    const leaf_hash = try hashPairs(ta, pairs);
                    if (!CoreMerkle.verify(round_root, leaf, leaf_hash, lp.path)) return false;
                    for (0..c) |j| {
                        folded[j] = foldCodeE(E, twE[round][leaf], lp.s0[j], lp.s1[j], proof.rounds[round].challenge[j]);
                    }
                }
                for (0..c) |j| if (!folded[j].eq(proof.final_folded[j])) return false;
            }
            return true;
        }
    };
}

/// `BiniusStarkWith` adapter exposing the batched PCS interface used by
/// `stark.zig`: `Proof`, `commit`, `proveEvalBatch`, `verifyEvalBatch`.
pub fn BatchFriPcsStark(
    comptime F: type,
    comptime E: type,
    comptime log_blowup: u8,
    comptime num_queries: usize,
) type {
    const P = BatchFriPcs(F, E, log_blowup, num_queries);
    const Hash = CoreHash.Hash;
    const MerkleTree = CoreMerkle.MerkleTree;

    return struct {
        pub const Proof = P.Proof;
        pub const BatchProof = P.Proof;

        pub fn commit(allocator: std.mem.Allocator, table: []const F) !MerkleTree {
            return P.commit(allocator, table);
        }

        pub fn proveEvalBatch(
            allocator: std.mem.Allocator,
            k: usize,
            tables: []const []const F,
            roots: []const Hash.Digest,
            r: []const E,
        ) !Proof {
            return P.proveEvalBatch(allocator, k, tables, roots, r);
        }

        pub fn verifyEvalBatch(
            allocator: std.mem.Allocator,
            roots: []const Hash.Digest,
            k: usize,
            r: []const E,
            proof: Proof,
        ) !bool {
            return P.verifyEvalBatch(allocator, roots, k, r, proof);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Gf16 = Tower.Gf16;
const Gf256 = Tower.Gf256;
const Gf2_128 = Tower.Gf2_128;
const Polynomial = @import("polynomial.zig");

fn prng(seed: u64) std.Random.DefaultPrng {
    return std.Random.DefaultPrng.init(seed);
}

fn randomTable(allocator: std.mem.Allocator, comptime F: type, k: u8, seed: u64) ![]F {
    const N = @as(usize, 1) << @intCast(k);
    const t = try allocator.alloc(F, N);
    var r = prng(seed);
    for (t) |*v| v.* = F.fromInt(r.random().uintLessThan(u32, std.math.maxInt(u32)));
    return t;
}

fn randomPointE(allocator: std.mem.Allocator, comptime E: type, k: u8, seed: u64) ![]E {
    const r = try allocator.alloc(E, k);
    var rnd = prng(seed);
    for (r) |*v| v.* = E.fromInt(rnd.random().uintLessThan(u32, std.math.maxInt(u32)));
    return r;
}

fn batchRoundTrip(
    comptime F: type,
    comptime E: type,
    comptime k: u8,
    comptime c: usize,
    comptime log_blowup: u8,
    comptime num_queries: usize,
    seed: u64,
) !void {
    const a = std.testing.allocator;
    const P = BatchFriPcs(F, E, log_blowup, num_queries);
    const n = @as(usize, 1) << @intCast(k);

    const tables = try a.alloc([]F, c);
    defer {
        for (tables) |t| a.free(t);
        a.free(tables);
    }
    const roots = try a.alloc(CoreHash.Hash.Digest, c);
    defer a.free(roots);
    for (0..c) |j| {
        tables[j] = try randomTable(a, F, k, seed + j);
        var tree = try P.commit(a, tables[j]);
        defer tree.deinit();
        roots[j] = tree.root();
    }
    const r = try randomPointE(a, E, k, seed + 100);
    defer a.free(r);

    var proof = try P.proveEvalBatch(a, k, tables, roots, r);
    defer proof.deinit(a);

    // Every claimed value equals the direct multilinear evaluation.
    for (0..c) |j| {
        const lifted = try a.alloc(E, n);
        defer a.free(lifted);
        for (tables[j], 0..) |v, i| lifted[i] = E.embed(F.LEVEL, v);
        const direct = try (Polynomial.Multilinear(E){ .evals = lifted }).eval(a, r);
        try std.testing.expectEqual(direct.value, proof.values[j].value);
    }
    try std.testing.expect(try P.verifyEvalBatch(a, roots, k, r, proof));
}

test "batch FRI PCS: honest round-trips (base fields)" {
    try batchRoundTrip(Gf16, Gf16, 2, 2, 1, 2, 600);
    try batchRoundTrip(Gf16, Gf16, 2, 3, 2, 2, 601);
    try batchRoundTrip(Gf256, Gf256, 3, 4, 1, 3, 602);
    try batchRoundTrip(Gf256, Gf256, 4, 3, 2, 4, 603);
}

test "batch FRI PCS: honest round-trips (extension field)" {
    try batchRoundTrip(Gf16, Gf2_128, 2, 2, 1, 2, 700);
    try batchRoundTrip(Gf16, Gf2_128, 2, 4, 2, 2, 701);
    try batchRoundTrip(Gf256, Gf2_128, 3, 3, 1, 3, 702);
}

test "batch FRI PCS: rejects tampered proofs" {
    const a = std.testing.allocator;
    const F = Gf16;
    const E = Gf16;
    const k: u8 = 2;
    const c = 3;
    const P = BatchFriPcs(F, E, 1, 2);

    const tables = try a.alloc([]F, c);
    defer {
        for (tables) |t| a.free(t);
        a.free(tables);
    }
    const roots = try a.alloc(CoreHash.Hash.Digest, c);
    defer a.free(roots);
    for (0..c) |j| {
        tables[j] = try randomTable(a, F, k, 800 + j);
        var tree = try P.commit(a, tables[j]);
        defer tree.deinit();
        roots[j] = tree.root();
    }
    const r = try randomPointE(a, E, k, 900);
    defer a.free(r);

    // Tampered claimed value.
    {
        var p = try P.proveEvalBatch(a, k, tables, roots, r);
        defer p.deinit(a);
        p.values[0] = E.one().add(p.values[0]);
        try std.testing.expect(!try P.verifyEvalBatch(a, roots, k, r, p));
    }
    // Tampered coefficient.
    {
        var p = try P.proveEvalBatch(a, k, tables, roots, r);
        defer p.deinit(a);
        p.rounds[0].coeffs[1] = E.one().add(p.rounds[0].coeffs[1]);
        try std.testing.expect(!try P.verifyEvalBatch(a, roots, k, r, p));
    }
    // Tampered final folded value of one column.
    {
        var p = try P.proveEvalBatch(a, k, tables, roots, r);
        defer p.deinit(a);
        p.final_folded[2] = E.one().add(p.final_folded[2]);
        try std.testing.expect(!try P.verifyEvalBatch(a, roots, k, r, p));
    }
    // Tampered query symbol of one column.
    {
        var p = try P.proveEvalBatch(a, k, tables, roots, r);
        defer p.deinit(a);
        p.queries[0].layers[0].s0[1] = E.one().add(p.queries[0].layers[0].s0[1]);
        try std.testing.expect(!try P.verifyEvalBatch(a, roots, k, r, p));
    }
    // Wrong per-column commitment root.
    {
        var p = try P.proveEvalBatch(a, k, tables, roots, r);
        defer p.deinit(a);
        const bad_roots = try a.dupe(CoreHash.Hash.Digest, roots);
        defer a.free(bad_roots);
        bad_roots[0] = CoreHash.Hash.hashBytes("other");
        try std.testing.expect(!try P.verifyEvalBatch(a, bad_roots, k, r, p));
    }
}
