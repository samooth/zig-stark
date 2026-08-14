const std = @import("std");

const Tower = @import("tower.zig");
const pack = @import("pack.zig");
const CoreHash = @import("../core/hash/hash.zig");
const CoreMerkle = @import("../core/merkle/merkle.zig");
const Polynomial = @import("polynomial.zig");

/// DP24 / LCH14 "novel polynomial basis" additive NTT + FRI twiddle-fold,
/// scalar (unpacked) form, restricted to our tower fields.
///
/// Let β_0 = fromInt(1) = 1, β_j = fromInt(2^j) be the canonical tower basis,
/// U_i = span{β_0..β_{i-1}}, and Ŵ_i(X) the *normalized subspace polynomial*
/// of degree 2^i vanishing on U_i with Ŵ_i(β_i) = 1. The FRI-eval protocol
/// (eprint 2024/504, original FRI-Binius version) folds the NTT-encoded code
/// with challenges r so that the fully folded value equals
///     Σ_i v[i]·eq_r(i)      (eq_r(i) = ∏_j (bit_j(i) ? r_j : 1+r_j)),
/// i.e. the multilinear dot product of the message table v with the eq kernel.
///
/// Twiddles: `twiddles[i][j]` = Ŵ_i evaluated at Σ_b (bit_b(j)·β_{i+1+b}),
/// enumerated in counting order over the basis β_{i+1}..β_{D-1}
/// (`expanded_subspace_evals` in the reference implementation).
pub fn Ntt(comptime F: type) type {
    return struct {
        const Self = @This();

        /// log2 of the NTT domain dimension (code length = 2^D).
        log_domain_size: u8,
        /// `twiddles[i]` has 2^(log_domain_size - i - 1) elements.
        twiddles: []const []const F,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, log_domain_size: u8) !Self {
            std.debug.assert(log_domain_size >= 1 and log_domain_size <= F.BITS);
            const D = log_domain_size;
            const s_evals = try allocator.alloc([]F, D);
            errdefer allocator.free(s_evals);
            const norm = try allocator.alloc(F, D);
            defer allocator.free(norm);

            // i = 0: W_0(X) = X, so W_0(β_0) = 1 and s_evals[0][b] = β_{1+b}.
            norm[0] = F.one();
            s_evals[0] = try allocator.alloc(F, D - 1);
            for (1..D) |j| s_evals[0][j - 1] = F.fromInt(@as(u128, 1) << @intCast(j));
            for (1..D) |i| {
                const norm_prev = norm[i - 1];
                const prev = s_evals[i - 1];
                // prev[0] = W_{i-1}(β_i), prev[b+1] = W_{i-1}(β_{i+1+b}).
                norm[i] = subspaceMap(prev[0], norm_prev);
                s_evals[i] = try allocator.alloc(F, D - i - 1);
                for (1..D - i) |b| s_evals[i][b - 1] = subspaceMap(prev[b], norm_prev);
            }
            errdefer for (s_evals) |se| allocator.free(se);

            // Normalize W_i → Ŵ_i = W_i/W_i(β_i), then expand to counting order.
            const twiddles = try allocator.alloc([]F, D);
            errdefer allocator.free(twiddles);
            for (0..D) |i| {
                const inv = norm[i].inv();
                const basis_evals = s_evals[i];
                var expanded = try allocator.alloc(F, @as(usize, 1) << @intCast(D - i - 1));
                expanded[0] = F.zero();
                for (basis_evals, 0..) |e, b| {
                    const half: usize = @as(usize, 1) << @intCast(b);
                    for (0..half) |k| expanded[half + k] = expanded[k].add(e.mul(inv));
                }
                allocator.free(basis_evals);
                twiddles[i] = expanded;
            }
            allocator.free(s_evals);
            return .{ .log_domain_size = D, .twiddles = twiddles, .allocator = allocator };
        }

        pub fn deinit(self: *Self) void {
            for (self.twiddles) |t| self.allocator.free(t);
            self.allocator.free(self.twiddles);
            self.* = undefined;
        }

        fn subspaceMap(e: F, c: F) F {
            return e.mul(e).add(c.mul(e));
        }

        /// The forward additive NTT: message (2^log_y coefficients of the novel
        /// basis polynomial) -> evaluations over the coset `coset` of the domain
        /// of dimension log_y + coset_bits. `out.len == msg.len` (== 2^log_y).
        pub fn forwardTransform(self: Self, out: []F, log_y: u8, coset: u32) void {
            const D = self.log_domain_size;
            for (0..log_y) |rev| {
                const i = log_y - 1 - rev; // layer i = log_y-1 .. 0, twiddles[i]
                const coset_offset: usize = @as(usize, coset) << @intCast(log_y - 1 - i);
                const num_blocks = @as(usize, 1) << @intCast(log_y - 1 - i);
                for (0..num_blocks) |k| {
                    const t = self.twiddles[i][coset_offset | k];
                    const block: usize = @as(usize, 1) << @intCast(i);
                    for (0..block) |l| {
                        const idx0 = (k << @intCast(i + 1)) | l;
                        const idx1 = idx0 | block;
                        out[idx0] = out[idx0].add(out[idx1].mul(t));
                        out[idx1] = out[idx1].add(out[idx0]);
                    }
                }
            }
            _ = D;
        }

        /// The inverse additive NTT: evaluations over the coset `coset` (as
        /// produced by `forwardTransform`) -> novel-basis coefficients, in
        /// place. The forward butterfly `a' = a + b·t; b' = b + a'` has
        /// determinant 1, so its inverse is `b = a' + b'; a = a' + b·t`,
        /// applied over the layers in reverse order.
        pub fn inverseForwardTransform(self: Self, out: []F, log_y: u8, coset: u32) void {
            const D = self.log_domain_size;
            for (0..log_y) |rev| {
                const i = rev; // layers in increasing order (reverse of forward)
                const coset_offset: usize = @as(usize, coset) << @intCast(log_y - 1 - i);
                const num_blocks = @as(usize, 1) << @intCast(log_y - 1 - i);
                for (0..num_blocks) |k| {
                    const t = self.twiddles[i][coset_offset | k];
                    const block: usize = @as(usize, 1) << @intCast(i);
                    for (0..block) |l| {
                        const idx0 = (k << @intCast(i + 1)) | l;
                        const idx1 = idx0 | block;
                        const ap = out[idx0];
                        const bp = out[idx1];
                        const b = ap.add(bp);
                        out[idx0] = ap.add(b.mul(t));
                        out[idx1] = b;
                    }
                }
            }
            _ = D;
        }

        /// Encode the message table (2^log_size elements) into the rate
        /// `2^log_blowup` FRI code: concatenation over the 2^log_blowup cosets
        /// of the forward transform on the dim-(log_size + log_blowup) domain.
        /// Result length = 2^(log_size + log_blowup).
        pub fn encode(self: Self, allocator: std.mem.Allocator, msg: []const F, log_blowup: u8) ![]F {
            const log_y = self.log_domain_size - log_blowup;
            std.debug.assert(msg.len == @as(usize, 1) << @intCast(log_y));
            const num_cosets: u32 = @as(u32, 1) << @intCast(log_blowup);
            const code = try allocator.alloc(F, msg.len * num_cosets);
            for (0..num_cosets) |c| {
                @memcpy(code[c * msg.len .. (c + 1) * msg.len], msg);
                self.forwardTransform(code[c * msg.len .. (c + 1) * msg.len], log_y, @intCast(c));
            }
            return code;
        }

        /// FRI fold of the current codeword (length 2^(D-rnd)) with challenge r.
        /// Output length = code.len/2, into `out`.
        pub fn foldCode(self: Self, code: []const F, rnd: u8, r: F, out: []F) void {
            const n = code.len >> 1;
            for (0..n) |i| {
                const A = code[i << 1];
                const B = code[(i << 1) | 1];
                const t = self.twiddles[rnd][i];
                const v = A.add(B);
                const u = A.add(v.mul(t));
                out[i] = u.add(v.add(u).mul(r)); // u + (v-u)·r
            }
        }
    };
}

/// eq_r(i) = ∏_j (bit_j(i) ? r_j : 1 + r_j); matches `pack.betaOnH`.
pub fn eqEval(comptime F: type, r: []const F, i: usize) F {
    var acc = F.one();
    for (r, 0..) |rj, j| {
        const bit: u8 = @intFromBool((i >> @intCast(j)) & 1 == 1);
        acc = acc.mul(if (bit == 1) rj else F.one().add(rj));
    }
    return acc;
}

/// Fold a plain table with `fold_lo`: out[i] = t[2i] + r·(t[2i]+t[2i+1]).
/// Folding a table of size 2^m with challenges r[0..m] yields
/// Σ_i t[i]·eq_r(i).
pub fn foldLo(comptime T: type, t: []const T, r: T, out: []T) void {
    const n = t.len >> 1;
    for (0..n) |i| {
        const a = t[i << 1];
        const b = t[(i << 1) | 1];
        out[i] = a.add(a.add(b).mul(r));
    }
}

/// eq_r(i) over an extension field E (matches `eqEval` lifted).
pub fn eqEvalE(comptime E: type, r: []const E, i: usize) E {
    var acc = E.one();
    for (r, 0..) |rj, j| {
        const bit: u8 = @intFromBool((i >> @intCast(j)) & 1 == 1);
        acc = acc.mul(if (bit == 1) rj else E.one().add(rj));
    }
    return acc;
}

/// The reference FRI-Binius fold of a symbol pair `(a, b)` with challenge `r`
/// and twiddle `tw` (= Ŵ_round evaluated at the pair's coset point):
/// v = a+b, u = a + v·tw, fold = u + (u+v)·r  (char 2).
pub fn foldCodeE(comptime E: type, tw: E, a: E, b: E, r: E) E {
    const v = a.add(b);
    const u = a.add(v.mul(tw));
    return u.add(v.add(u).mul(r));
}

/// Hash of an adjacent symbol pair `(a, b)` — one Merkle leaf.
pub fn pairHash(comptime E: type, a: E, b: E) CoreHash.Hash.Digest {
    var buf: [2 * E.SIZE]u8 = undefined;
    var a_buf: [E.SIZE]u8 = undefined;
    var b_buf: [E.SIZE]u8 = undefined;
    a.toBytes(&a_buf);
    b.toBytes(&b_buf);
    @memcpy(buf[0..E.SIZE], &a_buf);
    @memcpy(buf[E.SIZE..], &b_buf);
    return CoreHash.Hash.hashBytes(&buf);
}

pub fn log2Len(n: usize) usize {
    std.debug.assert(n != 0 and (n & (n - 1)) == 0);
    return std.math.log2_int(usize, n);
}

/// Streaming Fiat-Shamir transcript (absorb / sample from a Blake3 chain).
pub const Transcript = struct {
    h: std.crypto.hash.Blake3,
    buf: [64]u8,
    have: usize,

    pub fn init(bytes: []const u8) Transcript {
        var t = Transcript{ .h = std.crypto.hash.Blake3.init(.{}), .buf = undefined, .have = 0 };
        t.absorb(bytes);
        return t;
    }

    pub fn absorb(self: *Transcript, bytes: []const u8) void {
        self.h.update(bytes);
    }

    pub fn sample(self: *Transcript) u64 {
        while (self.have < 8) {
            var out: [32]u8 = undefined;
            self.h.final(&out);
            self.h = std.crypto.hash.Blake3.init(.{});
            @memcpy(self.buf[self.have..][0..32], &out);
            self.have += 32;
        }
        const v = std.mem.readInt(u64, self.buf[self.have - 8 ..][0..8], .little);
        self.have -= 8;
        return v;
    }
};

pub fn absorbElem(comptime E: type, t: *Transcript, v: E) void {
    var b: [E.SIZE]u8 = undefined;
    v.toBytes(&b);
    t.absorb(&b);
}

pub fn sampleE(comptime E: type, t: *Transcript) E {
    var b: [E.SIZE]u8 = undefined;
    for (0..E.SIZE) |i| b[i] = @truncate(t.sample());
    return E.fromBytes(b);
}

/// The sub-linear FRI-Binius committed MLE PCS (DP24 / eprint 2024/504):
/// the message is encoded with the additive NTT at rate 2^log_blowup, the
/// committed code is folded k times in lockstep with the sum-check that
/// proves the evaluation claim, and the verifier checks a few folded pairs
/// with Merkle paths.
///
/// The fully folded code is constant and equals Σ_i v[i]·eq_r(i) (verified
/// numerically for all our fields), so the last layer reduces to a single
/// value `final_folded_value` that must equal the final sum-check claim.
///
/// Implements the interface used by `BiniusStarkWith`: `commit`,
/// `proveEval`, `verifyEval`.
pub fn FriPcs(
    comptime F: type,
    comptime E: type,
    comptime log_blowup: u8,
    comptime num_queries: usize,
) type {
    const Hash = CoreHash.Hash;
    const MerkleTree = CoreMerkle.MerkleTree;
    const Digest = Hash.Digest;

    return struct {
        const Self = @This();

        pub const Round = struct {
            coeffs: [3]E,
            challenge: E,
        };

        pub const LayerProof = struct {
            s0: E,
            s1: E,
            path: []Digest,
        };

        pub const Query = struct {
            /// leaf index in the layer-0 tree, ∈ [0, 2^(D-1)).
            index: usize,
            /// one opening per round (layers 0..k-1).
            layers: []LayerProof,
        };

        pub const Proof = struct {
            /// the claimed MLE evaluation at the point (sum-check claim_0).
            value: E,
            rounds: []Round,
            /// roots of the folded layers 1..k, in round order.
            layer_roots: []Digest,
            /// the constant fully-folded code value.
            final_folded_value: E,
            queries: []Query,

            /// Owns `rounds`, `layer_roots`, `queries`, and each query's layers
            /// and paths; release with `deinit(allocator)` using the allocator
            /// passed to `proveEval`.
            pub fn deinit(self: *Proof, allocator: std.mem.Allocator) void {
                for (self.queries) |q| {
                    for (q.layers) |lp| allocator.free(lp.path);
                    allocator.free(q.layers);
                }
                allocator.free(self.queries);
                allocator.free(self.layer_roots);
                allocator.free(self.rounds);
            }
        };

        pub fn commit(allocator: std.mem.Allocator, table: []const F) !MerkleTree {
            const k = log2Len(table.len);
            const D: u8 = @intCast(k + log_blowup);
            std.debug.assert(log_blowup >= 1);
            std.debug.assert(D <= F.BITS);

            var tmp = std.heap.ArenaAllocator.init(allocator);
            defer tmp.deinit();
            const ta = tmp.allocator();

            var ntt = try Ntt(F).init(ta, D);
            const code = try ntt.encode(ta, table, log_blowup);
            const lifted = try ta.alloc(E, code.len);
            for (code, 0..) |v, i| lifted[i] = E.embed(F.LEVEL, v);
            const leaves = try ta.alloc(Digest, code.len >> 1);
            for (0..code.len >> 1) |p| leaves[p] = pairHash(E, lifted[p << 1], lifted[(p << 1) | 1]);
            return try MerkleTree.init(allocator, leaves);
        }

        pub fn proveEval(
            allocator: std.mem.Allocator,
            k: usize,
            table: []const F,
            r: []const E,
        ) !Proof {
            std.debug.assert(k >= 1);
            std.debug.assert(k == log2Len(table.len));
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

            // Lifted message table and the eq-r kernel table.
            const mle = try ta.alloc(E, table.len);
            for (table, 0..) |v, i| mle[i] = E.embed(F.LEVEL, v);
            const eq = try ta.alloc(E, table.len);
            for (0..table.len) |i| eq[i] = eqEvalE(E, r, i);

            var s = E.zero();
            for (0..table.len) |i| s = s.add(mle[i].mul(eq[i]));

            // Layer-0 code and its pair-leaf tree.
            const code = try ntt.encode(ta, table, log_blowup);
            const lifted = try ta.alloc(E, code.len);
            for (code, 0..) |v, i| lifted[i] = E.embed(F.LEVEL, v);
            const l0_leaves = try ta.alloc(Digest, code.len >> 1);
            for (0..code.len >> 1) |p| l0_leaves[p] = pairHash(E, lifted[p << 1], lifted[(p << 1) | 1]);
            const tree0 = try MerkleTree.init(ta, l0_leaves);
            const root0 = tree0.root();

            var t = Transcript.init(&root0);
            for (r) |v| absorbElem(E, &t, v);
            absorbElem(E, &t, s);

            // Twiddles lifted to E for the code folds.
            const twE = try ta.alloc([]E, D);
            for (0..D) |i| {
                twE[i] = try ta.alloc(E, ntt.twiddles[i].len);
                for (ntt.twiddles[i], 0..) |tw, j| twE[i][j] = E.embed(F.LEVEL, tw);
            }

            const rounds = try allocator.alloc(Round, k);
            errdefer allocator.free(rounds);
            const layer_roots = try allocator.alloc(Digest, k);
            errdefer allocator.free(layer_roots);

            var code_layers = try ta.alloc([]E, k + 1);
            var trees = try ta.alloc(MerkleTree, k + 1);
            code_layers[0] = lifted;
            trees[0] = tree0;

            var mle_cur = mle;
            var eq_cur = eq;
            var cur_code = lifted;
            var claim = s;

            for (0..k) |round| {
                // Sum-check round: coefficients of the honest univariate
                // partial sum p(X) = Σ_i (mle[2i] + (mle[2i]+mle[2i+1])X)
                //                       · (eq[2i] + (eq[2i]+eq[2i+1])X).
                const half = mle_cur.len >> 1;
                var eval_at_0 = E.zero();
                var eval_at_inf = E.zero();
                for (0..half) |i| {
                    eval_at_0 = eval_at_0.add(mle_cur[i << 1].mul(eq_cur[i << 1]));
                    const mv = mle_cur[i << 1].add(mle_cur[(i << 1) | 1]);
                    const ev = eq_cur[i << 1].add(eq_cur[(i << 1) | 1]);
                    eval_at_inf = eval_at_inf.add(mv.mul(ev));
                }
                const eval_at_1 = claim.sub(eval_at_0);
                const coeffs = [3]E{ eval_at_0, eval_at_0.add(eval_at_1).add(eval_at_inf), eval_at_inf };

                for (&coeffs) |*c| absorbElem(E, &t, c.*);
                const r_j = sampleE(E, &t);
                rounds[round] = .{ .coeffs = coeffs, .challenge = r_j };
                claim = coeffs[0].add(coeffs[1].mul(r_j)).add(coeffs[2].mul(r_j.mul(r_j)));

                // Fold the message and eq tables with the same challenge.
                const nxt_mle = try ta.alloc(E, mle_cur.len >> 1);
                const nxt_eq = try ta.alloc(E, eq_cur.len >> 1);
                foldLo(E, mle_cur, r_j, nxt_mle);
                foldLo(E, eq_cur, r_j, nxt_eq);
                mle_cur = nxt_mle;
                eq_cur = nxt_eq;

                // Fold the code with the same challenge.
                const nxt_code = try ta.alloc(E, cur_code.len >> 1);
                for (0..cur_code.len >> 1) |i| {
                    nxt_code[i] = foldCodeE(E, twE[round][i], cur_code[i << 1], cur_code[(i << 1) | 1], r_j);
                }
                cur_code = nxt_code;

                // Commit the folded layer and bind its root.
                const lv = try ta.alloc(Digest, cur_code.len >> 1);
                for (0..cur_code.len >> 1) |p| lv[p] = pairHash(E, cur_code[p << 1], cur_code[(p << 1) | 1]);
                const tr = try MerkleTree.init(ta, lv);
                layer_roots[round] = tr.root();
                t.absorb(&tr.root());
                code_layers[round + 1] = cur_code;
                trees[round + 1] = tr;
            }

            const final_folded = cur_code[0];
            absorbElem(E, &t, final_folded);

            // Sample distinct query leaves in the layer-0 tree.
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
                    const cd = code_layers[round];
                    lp.s0 = cd[leaf << 1];
                    lp.s1 = cd[(leaf << 1) | 1];
                    leaf >>= 1;
                }
            }

            return .{
                .value = s,
                .rounds = rounds,
                .layer_roots = layer_roots,
                .final_folded_value = final_folded,
                .queries = queries,
            };
        }

        pub fn verifyEval(
            allocator: std.mem.Allocator,
            root: Digest,
            k: usize,
            r: []const E,
            proof: Proof,
        ) !bool {
            std.debug.assert(k >= 1);
            std.debug.assert(r.len == k);
            const D: u8 = @intCast(k + log_blowup);
            std.debug.assert(log_blowup >= 1);
            std.debug.assert(D <= F.BITS);
            const total_leaves0: usize = @as(usize, 1) << @intCast(D - 1);
            std.debug.assert(num_queries >= 1 and num_queries <= total_leaves0);

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
            var t = Transcript.init(&root);
            for (r) |v| absorbElem(E, &t, v);
            absorbElem(E, &t, proof.value);

            var claim = proof.value;
            for (0..k) |round| {
                const coeffs = proof.rounds[round].coeffs;
                // p(0) + p(1) == claim  ⇔  c1 + c2 == claim (char 2).
                if (!coeffs[1].add(coeffs[2]).eq(claim)) return false;
                for (&coeffs) |*c| absorbElem(E, &t, c.*);
                const r_j = sampleE(E, &t);
                if (!r_j.eq(proof.rounds[round].challenge)) return false;
                claim = coeffs[0].add(coeffs[1].mul(r_j)).add(coeffs[2].mul(r_j.mul(r_j)));
                t.absorb(&proof.layer_roots[round]);
            }

            absorbElem(E, &t, proof.final_folded_value);
            // The final claim must match the fully folded code, scaled by the
            // fold residual of the eq kernel: claim_k = code_k[0]·∏_j (1+r_j+ch_j)
            // (the fold challenges ch_j are sampled, not the eval point r_j).
            var eq_factor = E.one();
            for (0..k) |j| eq_factor = eq_factor.mul(E.one().add(r[j]).add(proof.rounds[j].challenge));
            if (!claim.eq(proof.final_folded_value.mul(eq_factor))) return false;

            const indices = try sampleQueries(allocator, &t, num_queries, total_leaves0);
            defer allocator.free(indices);

            for (indices, 0..) |q, qi| {
                const query = proof.queries[qi];
                if (query.index != q) return false;
                if (query.layers.len != k) return false;

                var leaf = q;
                var folded: E = undefined;
                for (0..k) |round| {
                    const lp = query.layers[round];
                    if (round > 0) {
                        const expected = if ((leaf & 1) == 1) lp.s1 else lp.s0;
                        if (!folded.eq(expected)) return false;
                        leaf >>= 1;
                    }
                    const round_root = if (round == 0) root else proof.layer_roots[round - 1];
                    if (!CoreMerkle.verify(round_root, leaf, pairHash(E, lp.s0, lp.s1), lp.path)) return false;
                    folded = foldCodeE(E, twE[round][leaf], lp.s0, lp.s1, proof.rounds[round].challenge);
                }
                if (!folded.eq(proof.final_folded_value)) return false;
            }
            return true;
        }
    };
}

pub fn sampleQueries(
    allocator: std.mem.Allocator,
    t: *Transcript,
    num_queries: usize,
    total: usize,
) ![]usize {
    var qset = std.AutoHashMap(usize, void).init(allocator);
    defer qset.deinit();
    var list: std.ArrayList(usize) = .empty;
    defer list.deinit(allocator);
    while (list.items.len < num_queries) {
        const idx = @as(usize, @intCast(t.sample())) % total;
        if (qset.contains(idx)) continue;
        try qset.put(idx, {});
        try list.append(allocator, idx);
    }
    return try list.toOwnedSlice(allocator);
}

/// `BiniusStarkWith` adapter: exposes the PCS interface used by `stark.zig`
/// (`Proof`, `commit`, `proveEval`, `verifyEval`) for `FriPcs`.
pub fn FriPcsStark(
    comptime F: type,
    comptime E: type,
    comptime log_blowup: u8,
    comptime num_queries: usize,
) type {
    const P = FriPcs(F, E, log_blowup, num_queries);
    const Hash = CoreHash.Hash;
    const MerkleTree = CoreMerkle.MerkleTree;

    return struct {
        pub const Proof = P.Proof;

        pub fn commit(allocator: std.mem.Allocator, table: []const F) !MerkleTree {
            return P.commit(allocator, table);
        }

        pub fn proveEval(allocator: std.mem.Allocator, k: usize, table: []const F, r: []const E) !Proof {
            return P.proveEval(allocator, k, table, r);
        }

        pub fn verifyEval(allocator: std.mem.Allocator, root: Hash.Digest, k: usize, r: []const E, proof: Proof) !bool {
            return P.verifyEval(allocator, root, k, r, proof);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Gf16 = Tower.Gf16;
const Gf256 = Tower.Gf256;
const Gf2_128 = Tower.Gf2_128;

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

fn randomPoint(allocator: std.mem.Allocator, comptime F: type, k: u8, seed: u64) ![]F {
    const r = try allocator.alloc(F, k);
    var rnd = prng(seed);
    for (r) |*v| v.* = F.fromInt(rnd.random().uintLessThan(u32, std.math.maxInt(u32)));
    return r;
}

fn testFoldIdentity(comptime F: type, k: u8, log_blowup: u8, seed: u64) !void {
    const a = std.testing.allocator;

    const msg = try randomTable(a, F, k, seed);
    defer a.free(msg);
    const r = try randomPoint(a, F, k, seed + 1);
    defer a.free(r);

    const D = k + log_blowup;
    var ntt = try Ntt(F).init(a, D);
    defer ntt.deinit();
    const code = try ntt.encode(a, msg, log_blowup);
    defer a.free(code);

    // Fold all k rounds (the message rounds).
    var cur = try a.dupe(F, code);
    for (0..k) |rnd| {
        const next = try a.alloc(F, cur.len >> 1);
        ntt.foldCode(cur, @intCast(rnd), r[rnd], next);
        a.free(cur);
        cur = next;
    }
    defer a.free(cur);

    // Reference: Σ_i msg[i]·eq_r(i).
    var expect = F.zero();
    for (msg, 0..) |v, i| {
        expect = expect.add(v.mul(eqEval(F, r, i)));
    }
    try std.testing.expectEqual(expect, cur[0]);
}

test "NTT fold identity (rate 1): fold(code, r) == Σ v·eq_r" {
    try testFoldIdentity(Gf16, 2, 0, 100);
    try testFoldIdentity(Gf16, 3, 0, 101);
    try testFoldIdentity(Gf16, 4, 0, 102);
    try testFoldIdentity(Gf256, 2, 0, 103);
    try testFoldIdentity(Gf256, 3, 0, 104);
    try testFoldIdentity(Gf256, 5, 0, 105);
}

test "NTT fold identity (rate 4): fold(code, r) == Σ v·eq_r" {
    try testFoldIdentity(Gf16, 2, 2, 200);
    try testFoldIdentity(Gf256, 3, 2, 202);
    try testFoldIdentity(Gf256, 4, 2, 203);
}

test "inverse additive NTT inverts the forward transform" {
    // forward ∘ inverse == identity on novel-basis messages (cosets 0..2^b-1).
    const a = std.testing.allocator;
    inline for (.{ Gf16, Gf256 }) |F| {
        const Dmax = @as(u8, @intCast(@min(F.BITS, 5)));
        var D: u8 = 1;
        while (D <= Dmax) : (D += 1) {
            var ntt = try Ntt(F).init(a, D);
            defer ntt.deinit();
            const log_y = D - 1;
            const num_cosets: u32 = @as(u32, 1) << @intCast(1);
            for (0..num_cosets) |coset| {
                const msg = try randomTable(a, F, log_y, @as(u64, D) * 100 + coset);
                defer a.free(msg);
                const fwd = try a.dupe(F, msg);
                defer a.free(fwd);
                ntt.forwardTransform(fwd, log_y, @intCast(coset));
                ntt.inverseForwardTransform(fwd, log_y, @intCast(coset));
                for (msg, fwd) |orig, back| try std.testing.expect(orig.eq(back));
            }
        }
    }
}

test "novel basis eval matches the forward additive NTT" {
    // pack.novelEval is the O(N) single-point evaluation in the novel basis; it
    // must agree with the NTT's forward transform (O(N log N)) at every domain
    // point for a zero-padded message (the "codeword extension" in fromInt order).
    const a = std.testing.allocator;
    inline for (.{ Gf16, Gf256 }) |F| {
        const kmax = @as(u8, @intCast(@min(F.BITS, 5) - 1)); // D = k + 1 <= F.BITS
        var k: u8 = 1;
        while (k <= kmax) : (k += 1) {
            const msg = try randomTable(a, F, k, @as(u64, k) * 7 + 3);
            defer a.free(msg);
            const D = k + 1;
            var ntt = try Ntt(F).init(a, D);
            defer ntt.deinit();
            const padded = try a.alloc(F, @as(usize, 1) << @intCast(D));
            defer a.free(padded);
            @memset(padded, F.zero());
            @memcpy(padded[0..msg.len], msg);
            ntt.forwardTransform(padded, D, 0);
            for (0..padded.len) |i| {
                const want = try pack.novelEval(a, F, k, msg, F.fromInt(i));
                try std.testing.expect(padded[i].eq(want));
            }
        }
    }
}

test "fold_lo chain == Σ t·eq_r (table fold)" {
    const a = std.testing.allocator;
    const k = 4;
    const t = try randomTable(a, Gf16, k, 77);
    defer a.free(t);
    const r = try randomPoint(a, Gf16, k, 78);
    defer a.free(r);
    var cur = try a.dupe(Gf16, t);
    var next = try a.alloc(Gf16, t.len >> 1);
    for (0..k) |rnd| {
        foldLo(Gf16, cur, r[rnd], next);
        const tmp = cur;
        cur = next;
        next = tmp;
    }
    defer a.free(cur);
    defer a.free(next);
    var expect = Gf16.zero();
    for (t, 0..) |v, i| expect = expect.add(v.mul(eqEval(Gf16, r, i)));
    try std.testing.expectEqual(expect, cur[0]);
}

fn randomPointE(allocator: std.mem.Allocator, comptime E: type, k: u8, seed: u64) ![]E {
    const r = try allocator.alloc(E, k);
    var rnd = prng(seed);
    for (r) |*v| v.* = E.fromInt(rnd.random().uintLessThan(u32, std.math.maxInt(u32)));
    return r;
}

fn testFriRoundTrip(comptime F: type, comptime E: type, comptime k: u8, comptime log_blowup: u8, comptime num_queries: usize, seed: u64) !void {
    const a = std.testing.allocator;

    const table = try randomTable(a, F, k, seed);
    defer a.free(table);
    const r = try randomPointE(a, E, k, seed + 7);
    defer a.free(r);
    const n = @as(usize, 1) << @intCast(k);

    var expect = E.zero();
    for (0..n) |i| expect = expect.add(E.embed(F.LEVEL, table[i]).mul(eqEvalE(E, r, i)));

    const P = FriPcs(F, E, log_blowup, num_queries);
    var tree = try P.commit(std.testing.allocator, table);
    defer tree.deinit();
    const root = tree.root();

    var proof = try P.proveEval(std.testing.allocator, k, table, r);
    defer proof.deinit(std.testing.allocator);

    try std.testing.expect(proof.value.eq(expect));
    try std.testing.expect(try P.verifyEval(std.testing.allocator, root, k, r, proof));
}

test "FRI PCS: honest round-trips (base fields)" {
    try testFriRoundTrip(Gf16, Gf16, 2, 1, 2, 300);
    try testFriRoundTrip(Gf16, Gf16, 2, 2, 2, 301);
    try testFriRoundTrip(Gf256, Gf256, 3, 1, 3, 302);
    try testFriRoundTrip(Gf256, Gf256, 3, 2, 3, 303);
    try testFriRoundTrip(Gf256, Gf256, 4, 2, 4, 304);
}

test "FRI PCS: honest round-trips (extension field)" {
    try testFriRoundTrip(Gf16, Gf2_128, 2, 1, 2, 400);
    try testFriRoundTrip(Gf16, Gf2_128, 2, 2, 2, 401);
    try testFriRoundTrip(Gf256, Gf2_128, 3, 1, 3, 402);
    try testFriRoundTrip(Gf256, Gf2_128, 3, 2, 3, 403);
}

test "FRI PCS: rejects tampered proofs" {
    const a = std.testing.allocator;

    const F = Gf16;
    const E = Gf16;
    const k: u8 = 2;
    const log_blowup: u8 = 1;
    const P = FriPcs(F, E, log_blowup, 2);

    const table = try randomTable(a, F, k, 500);
    defer a.free(table);
    const r = try randomPointE(a, E, k, 501);
    defer a.free(r);

    var tree = try P.commit(std.testing.allocator, table);
    defer tree.deinit();
    const root = tree.root();

    var proof = try P.proveEval(std.testing.allocator, k, table, r);
    defer proof.deinit(std.testing.allocator);

    // Baseline verifies.
    try std.testing.expect(try P.verifyEval(std.testing.allocator, root, k, r, proof));

    // Tampered value.
    {
        var p = try P.proveEval(std.testing.allocator, k, table, r);
        defer p.deinit(std.testing.allocator);
        p.value = E.one().add(p.value);
        try std.testing.expect(!try P.verifyEval(std.testing.allocator, root, k, r, p));
    }
    // Tampered coefficient.
    {
        var p = try P.proveEval(std.testing.allocator, k, table, r);
        defer p.deinit(std.testing.allocator);
        p.rounds[0].coeffs[0] = E.one().add(p.rounds[0].coeffs[0]);
        try std.testing.expect(!try P.verifyEval(std.testing.allocator, root, k, r, p));
    }
    // Tampered final folded value.
    {
        var p = try P.proveEval(std.testing.allocator, k, table, r);
        defer p.deinit(std.testing.allocator);
        p.final_folded_value = E.one().add(p.final_folded_value);
        try std.testing.expect(!try P.verifyEval(std.testing.allocator, root, k, r, p));
    }
    // Tampered query symbol.
    {
        var p = try P.proveEval(std.testing.allocator, k, table, r);
        defer p.deinit(std.testing.allocator);
        p.queries[0].layers[0].s0 = E.one().add(p.queries[0].layers[0].s0);
        try std.testing.expect(!try P.verifyEval(std.testing.allocator, root, k, r, p));
    }
    // Wrong root.
    {
        var p = try P.proveEval(std.testing.allocator, k, table, r);
        defer p.deinit(std.testing.allocator);
        const bad_root = CoreHash.Hash.hashBytes("other");
        try std.testing.expect(!try P.verifyEval(std.testing.allocator, bad_root, k, r, p));
    }
}
