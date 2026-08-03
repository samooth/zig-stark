const std = @import("std");
const QM31 = @import("../field/qm31.zig").QM31;
const Hash = @import("../hash/hash.zig").Hash;
const Channel = @import("../channel/channel.zig").Channel;
const MerkleTree = @import("../merkle/merkle.zig").MerkleTree;
const merkleVerify = @import("../merkle/merkle.zig").verify;
const UnivariateQM31 = @import("../poly/univariate.zig").UnivariateQM31;
const Fri = @import("../fri/fri.zig");

pub const BoundaryAssertion = struct {
    column: usize,
    /// Row index (0-based); point = omega^step in H.
    step: usize,
    value: QM31,
};

/// DEEP-FRI STARK for an AIR over QM31.
///
/// Protocol sketch (all randomness via the shared `Channel`):
///   1. Interpolate each trace column to a polynomial f_j over the subgroup
///      H = <w> (|H| = 2^trace_log); evaluate on the domain
///      D = FRI_OFFSET * <w_ev> of size 2^(trace_log + log_blowup) and commit.
///   2. Sample transition weights alpha and boundary weights beta.
///   3. Build the composition polynomial
///        Hc(x) = sum alpha_k * C_k(x) * (x - w^(n-1))
///              + sum beta_k * (f_{col}(x) - v_k) * Z_H(x) / (x - p_k)
///      which vanishes on H, so Hc(x) = Z_H(x) * Q(x); commit Q's codeword.
///   4. Sample z; send the DEEP evaluations f_j(z), f_j(w*z), Q(z); sample
///      DEEP weights gamma; commit the combined polynomial
///        g(x) = sum gamma_j      * (f_j(x)   - f_j(z))   / (x - z)
///             + sum gamma_{m+j}  * (f_j(w*x) - f_j(w*z)) / (x - z)
///             + gamma_{2m} * (Q(x) - Q(z)) / (x - z)
///      via FRI on the same domain D.
///   5. For each FRI query, reveal the trace/quotient values at x0 and w*x0
///      (authenticated by their Merkle trees) and check the DEEP identity and
///      Hc(x0) == Z_H(x0) * Q(x0).
///
/// The AIR type must provide:
///   - `num_columns`, `num_transition_constraints`, `num_boundary`
///   - `evalTransition(x, current, next, out)`: writes transition constraints.
///     `x` is the evaluation point; for row-dependent constraints it should be
///     written as a polynomial in `x` that vanishes on H.
///   - `boundaryAssertions(public_inputs, n, out)`: fills boundary assertions
pub const StarkParams = struct {
    trace_log: u8,
    log_blowup: u8 = 3,
    num_queries: usize = 16,
    remainder_log: u8 = 3,

    pub fn traceLen(self: StarkParams) usize {
        return @as(usize, 1) << @intCast(self.trace_log);
    }
    pub fn domainLen(self: StarkParams) usize {
        return @as(usize, 1) << @intCast(self.trace_log + self.log_blowup);
    }
    pub fn shift(self: StarkParams) usize {
        return @as(usize, 1) << @intCast(self.log_blowup);
    }
    pub fn friParams(self: StarkParams) Fri.FriParams {
        return .{
            .log_size = self.trace_log,
            .log_blowup = self.log_blowup,
            .num_queries = self.num_queries,
            .remainder_log = self.remainder_log,
        };
    }
};

pub fn GenericStark(comptime Air: type) type {
    return struct {
        const Self = @This();
        const F = QM31;

        pub const QueryReveal = struct {
            query_index: usize,
            /// length 2m + 1: [j] = f_j(x0), [m + j] = f_j(w*x0), [2m] = Q(x0).
            values: []F,
            /// matching Merkle paths (same length as `values`).
            paths: [][]Hash.Digest,
        };

        pub const Proof = struct {
            params: StarkParams,
            allocator: std.mem.Allocator,
            trace_roots: []Hash.Digest,
            quotient_root: Hash.Digest,
            /// length 2m + 1: f_j(z), f_j(w*z), then Q(z).
            deep_evals: []F,
            fri: Fri.Proof,
            queries: []QueryReveal,

            pub fn deinit(self: *Proof) void {
                for (self.queries) |*q| {
                    for (q.paths) |p| self.allocator.free(p);
                    self.allocator.free(q.paths);
                    self.allocator.free(q.values);
                }
                self.allocator.free(self.queries);
                self.allocator.free(self.deep_evals);
                self.allocator.free(self.trace_roots);
                self.fri.deinit();
            }
        };

        const m = Air.num_columns;
        const num_trans = Air.num_transition_constraints;
        const num_bound = Air.num_boundary;

        /// `trace` is a list of `num_columns` column slices, each of length
        /// 2^trace_log. `public_inputs` drives the boundary assertions.
        pub fn prove(
            allocator: std.mem.Allocator,
            params: StarkParams,
            public_inputs: Air.PublicInputs,
            trace: []const []const F,
            channel: *Channel,
        ) !Proof {
            const n = params.traceLen();
            const N = params.domainLen();
            const shift = params.shift();
            const n_trans = 2 * m + 1;
            std.debug.assert(trace.len == m);
            for (trace) |col| std.debug.assert(col.len == n);

            const w = F.primitiveRootOfUnity(params.trace_log);
            const w_ev = F.primitiveRootOfUnity(params.trace_log + params.log_blowup);

            // H points and interpolation of each column.
            const h_points = try allocator.alloc(F, n);
            defer allocator.free(h_points);
            h_points[0] = F.one();
            for (1..n) |i| h_points[i] = h_points[i - 1].mul(w);

            const coeffs = try allocator.alloc([]F, m);
            errdefer allocator.free(coeffs);
            for (0..m) |j| {
                coeffs[j] = try allocator.alloc(F, n);
                errdefer allocator.free(coeffs[j]);
                try UnivariateQM31.interpolate(allocator, h_points, trace[j], coeffs[j]);
            }

            // Domain D points and trace codewords.
            const d_points = try allocator.alloc(F, N);
            defer allocator.free(d_points);
            d_points[0] = Fri.FRI_OFFSET;
            for (1..N) |i| d_points[i] = d_points[i - 1].mul(w_ev);

            const codewords = try allocator.alloc([]F, m);
            errdefer allocator.free(codewords);
            for (0..m) |j| {
                codewords[j] = try allocator.alloc(F, N);
                errdefer allocator.free(codewords[j]);
                for (0..N) |i| codewords[j][i] = UnivariateQM31.eval(coeffs[j], d_points[i]);
            }

            // Commit the trace columns.
            const trace_roots = try allocator.alloc(Hash.Digest, m);
            errdefer allocator.free(trace_roots);
            const trace_trees = try allocator.alloc(MerkleTree, m);
            errdefer allocator.free(trace_trees);
            for (0..m) |j| {
                const leaves = try hashCodeword(allocator, codewords[j]);
                defer allocator.free(leaves);
                trace_trees[j] = try MerkleTree.init(allocator, leaves);
                trace_roots[j] = trace_trees[j].root();
                channel.absorbDigest(trace_roots[j]);
            }

            // Sample transition and boundary weights.
            const alphas = try allocator.alloc(F, num_trans);
            defer allocator.free(alphas);
            for (alphas) |*a| a.* = channel.sampleQM31();
            const boundary = try allocator.alloc(BoundaryAssertion, num_bound);
            defer allocator.free(boundary);
            Air.boundaryAssertions(public_inputs, n, boundary);
            const betas = try allocator.alloc(F, num_bound);
            defer allocator.free(betas);
            for (betas) |*b| b.* = channel.sampleQM31();

            // Z_H and the quotient Q = Hc / Z_H on D.
            const q_codeword = try allocator.alloc(F, N);
            errdefer allocator.free(q_codeword);
            {
                const zh = try allocator.alloc(F, N);
                defer allocator.free(zh);
                const inv_zh = try allocator.alloc(F, N);
                defer allocator.free(inv_zh);
                for (0..N) |i| {
                    zh[i] = d_points[i].pow(@as(u64, @intCast(n))).sub(F.one());
                    inv_zh[i] = zh[i].inv();
                }
                const last_point = h_points[n - 1];
                const current = try allocator.alloc(F, m);
                defer allocator.free(current);
                const next = try allocator.alloc(F, m);
                defer allocator.free(next);
                const res = try allocator.alloc(F, num_trans);
                defer allocator.free(res);

                for (0..N) |i| {
                    for (0..m) |j| {
                        current[j] = codewords[j][i];
                        next[j] = codewords[j][(i + shift) % N];
                    }
                    Air.evalTransition(d_points[i], current, next, res);
                    var h_val = F.zero();
                    for (0..num_trans) |k| {
                        h_val = h_val.add(alphas[k].mul(res[k].mul(d_points[i].sub(last_point))));
                    }
                    for (0..num_bound) |k| {
                        const p_k = w.pow(@as(u64, @intCast(boundary[k].step)));
                        const term = codewords[boundary[k].column][i].sub(boundary[k].value)
                            .mul(zh[i]).mul(d_points[i].sub(p_k).inv());
                        h_val = h_val.add(betas[k].mul(term));
                    }
                    q_codeword[i] = h_val.mul(inv_zh[i]);
                }
            }

            // Commit the quotient.
            const q_leaves = try hashCodeword(allocator, q_codeword);
            defer allocator.free(q_leaves);
            var quotient_tree = try MerkleTree.init(allocator, q_leaves);
            defer quotient_tree.deinit();
            const quotient_root = quotient_tree.root();
            channel.absorbDigest(quotient_root);

            // Sample z and compute the DEEP evaluations.
            const z = channel.sampleQM31();
            const wz = z.mul(w);
            const deep_evals = try allocator.alloc(F, n_trans);
            errdefer allocator.free(deep_evals);
            for (0..m) |j| {
                deep_evals[j] = UnivariateQM31.eval(coeffs[j], z);
                deep_evals[m + j] = UnivariateQM31.eval(coeffs[j], wz);
            }
            deep_evals[2 * m] = try computeQuotientAt(
                allocator,
                params,
                public_inputs,
                z,
                coeffs,
                n,
                w,
                alphas,
                betas,
            );
            channel.absorbQM31s(deep_evals);

            const gammas = try allocator.alloc(F, n_trans);
            defer allocator.free(gammas);
            for (gammas) |*g| g.* = channel.sampleQM31();

            // DEEP combined polynomial codeword on D.
            const g_codeword = try allocator.alloc(F, N);
            errdefer allocator.free(g_codeword);
            for (0..N) |i| {
                const inv_dz = d_points[i].sub(z).inv();
                var g_val = F.zero();
                for (0..m) |j| {
                    g_val = g_val.add(gammas[j].mul(codewords[j][i].sub(deep_evals[j]).mul(inv_dz)));
                    g_val = g_val.add(gammas[m + j].mul(codewords[j][(i + shift) % N].sub(deep_evals[m + j]).mul(inv_dz)));
                }
                g_val = g_val.add(gammas[2 * m].mul(q_codeword[i].sub(deep_evals[2 * m]).mul(inv_dz)));
                g_codeword[i] = g_val;
            }

            // Commit g via FRI on the same domain.
            const fri_proof = try Fri.proveCodeword(allocator, params.friParams(), g_codeword, channel);

            // Per-query reveals of trace and quotient values.
            const queries = try allocator.alloc(QueryReveal, params.num_queries);
            errdefer allocator.free(queries);
            for (queries) |*q| {
                q.values = try allocator.alloc(F, n_trans);
                errdefer allocator.free(q.values);
                q.paths = try allocator.alloc([]Hash.Digest, n_trans);
                errdefer allocator.free(q.paths);
            }
            for (queries, 0..) |*q, qi| {
                const p0 = fri_proof.queries[qi].index;
                q.query_index = p0;
                for (0..m) |j| {
                    const pn = (p0 + shift) % N;
                    q.values[j] = codewords[j][p0];
                    q.paths[j] = try trace_trees[j].open(p0, allocator);
                    q.values[m + j] = codewords[j][pn];
                    q.paths[m + j] = try trace_trees[j].open(pn, allocator);
                }
                q.values[2 * m] = q_codeword[p0];
                q.paths[2 * m] = try quotient_tree.open(p0, allocator);
            }

            // Cleanup.
            for (trace_trees) |*t| t.deinit();
            allocator.free(trace_trees);
            for (codewords) |c| allocator.free(c);
            allocator.free(codewords);
            for (coeffs) |c| allocator.free(c);
            allocator.free(coeffs);
            allocator.free(g_codeword);
            allocator.free(q_codeword);

            return .{
                .params = params,
                .allocator = allocator,
                .trace_roots = trace_roots,
                .quotient_root = quotient_root,
                .deep_evals = deep_evals,
                .fri = fri_proof,
                .queries = queries,
            };
        }

        pub fn verify(
            allocator: std.mem.Allocator,
            params: StarkParams,
            public_inputs: Air.PublicInputs,
            proof: *const Proof,
            channel: *Channel,
        ) !bool {
            const n = params.traceLen();
            const N = params.domainLen();
            const shift = params.shift();
            const n_trans = 2 * m + 1;
            if (proof.trace_roots.len != m) return false;
            if (proof.deep_evals.len != n_trans) return false;

            const w = F.primitiveRootOfUnity(params.trace_log);
            const w_ev = F.primitiveRootOfUnity(params.trace_log + params.log_blowup);

            // Replay the transcript.
            for (0..m) |j| channel.absorbDigest(proof.trace_roots[j]);
            const alphas = try allocator.alloc(F, num_trans);
            defer allocator.free(alphas);
            for (alphas) |*a| a.* = channel.sampleQM31();
            const boundary = try allocator.alloc(BoundaryAssertion, num_bound);
            defer allocator.free(boundary);
            Air.boundaryAssertions(public_inputs, n, boundary);
            const betas = try allocator.alloc(F, num_bound);
            defer allocator.free(betas);
            for (betas) |*b| b.* = channel.sampleQM31();

            channel.absorbDigest(proof.quotient_root);
            const z = channel.sampleQM31();
            channel.absorbQM31s(proof.deep_evals);
            const gammas = try allocator.alloc(F, n_trans);
            defer allocator.free(gammas);
            for (gammas) |*g| g.* = channel.sampleQM31();

            // FRI verification (also samples FRI alphas / remainder / queries).
            if (!try Fri.verify(allocator, params.friParams(), &proof.fri, channel)) return false;

            const last_point = w.pow(@as(u64, @intCast(n - 1)));
            for (proof.queries, 0..) |qv, qi| {
                if (qv.query_index != proof.fri.queries[qi].index) return false;
                const p0 = qv.query_index;

                // Merkle checks for trace and quotient reveals.
                for (0..m) |j| {
                    const pn = (p0 + shift) % N;
                    if (!merkleVerify(proof.trace_roots[j], p0, Hash.hashQM31(qv.values[j]), qv.paths[j])) return false;
                    if (!merkleVerify(proof.trace_roots[j], pn, Hash.hashQM31(qv.values[m + j]), qv.paths[m + j])) return false;
                }
                if (!merkleVerify(proof.quotient_root, p0, Hash.hashQM31(qv.values[2 * m]), qv.paths[2 * m])) return false;

                const x0 = Fri.FRI_OFFSET.mul(w_ev.pow(@as(u64, @intCast(p0))));

                // DEEP identity: g(x0) must match the FRI leaf at p0.
                const inv_dz = x0.sub(z).inv();
                var g_val = F.zero();
                for (0..m) |j| {
                    g_val = g_val.add(gammas[j].mul(qv.values[j].sub(proof.deep_evals[j]).mul(inv_dz)));
                    g_val = g_val.add(gammas[m + j].mul(qv.values[m + j].sub(proof.deep_evals[m + j]).mul(inv_dz)));
                }
                g_val = g_val.add(gammas[2 * m].mul(qv.values[2 * m].sub(proof.deep_evals[2 * m]).mul(inv_dz)));

                // The FRI first-layer leaf at index p0 is one of the two revealed
                // layer-0 values (positions p1 and p1 + N/2).
                const n1 = N / 2;
                const p1 = p0 % n1;
                const pair0 = proof.fri.queries[qi].pairs[0];
                const fri_leaf = if (p0 == p1) pair0.value0 else pair0.value1;
                if (!g_val.eq(fri_leaf)) return false;

                // Constraint check: Hc(x0) == Z_H(x0) * Q(x0).
                const current = qv.values[0..m];
                const next = qv.values[m .. 2 * m];
                const res = try allocator.alloc(F, num_trans);
                defer allocator.free(res);
                Air.evalTransition(x0, current, next, res);
                var h_val = F.zero();
                for (0..num_trans) |k| {
                    h_val = h_val.add(alphas[k].mul(res[k].mul(x0.sub(last_point))));
                }
                const zh = x0.pow(@as(u64, @intCast(n))).sub(F.one());
                for (0..num_bound) |k| {
                    const p_k = w.pow(@as(u64, @intCast(boundary[k].step)));
                    const term = qv.values[boundary[k].column].sub(boundary[k].value)
                        .mul(zh).mul(x0.sub(p_k).inv());
                    h_val = h_val.add(betas[k].mul(term));
                }
                if (!h_val.eq(zh.mul(qv.values[2 * m]))) return false;
            }
            return true;
        }

        fn hashCodeword(allocator: std.mem.Allocator, codeword: []const F) ![]Hash.Digest {
            const leaves = try allocator.alloc(Hash.Digest, codeword.len);
            for (codeword, 0..) |v, i| leaves[i] = Hash.hashQM31(v);
            return leaves;
        }

        /// Q(z) = Hc(z) / Z_H(z), evaluated directly via Horner (no need to
        /// interpolate the quotient codeword).
        fn computeQuotientAt(
            allocator: std.mem.Allocator,
            params: StarkParams,
            public_inputs: Air.PublicInputs,
            z: F,
            coeffs: []const []const F,
            n: usize,
            w: F,
            alphas: []const F,
            betas: []const F,
        ) !F {
            _ = params;
            const boundary = try allocator.alloc(BoundaryAssertion, num_bound);
            defer allocator.free(boundary);
            Air.boundaryAssertions(public_inputs, n, boundary);

            const current = try allocator.alloc(F, m);
            defer allocator.free(current);
            const next = try allocator.alloc(F, m);
            defer allocator.free(next);
            for (0..m) |j| {
                current[j] = UnivariateQM31.eval(coeffs[j], z);
                next[j] = UnivariateQM31.eval(coeffs[j], z.mul(w));
            }

            const res = try allocator.alloc(F, num_trans);
            defer allocator.free(res);
            Air.evalTransition(z, current, next, res);
            const last_point = w.pow(@as(u64, @intCast(n - 1)));
            var h_val = F.zero();
            for (0..num_trans) |k| {
                h_val = h_val.add(alphas[k].mul(res[k].mul(z.sub(last_point))));
            }
            const zh = z.pow(@as(u64, @intCast(n))).sub(F.one());
            for (0..num_bound) |k| {
                const p_k = w.pow(@as(u64, @intCast(boundary[k].step)));
                const term = current[boundary[k].column].sub(boundary[k].value)
                    .mul(zh).mul(z.sub(p_k).inv());
                h_val = h_val.add(betas[k].mul(term));
            }
            return h_val.mul(zh.inv());
        }
    };
}

// ---------------------------------------------------------------------------
// Fibonacci AIR (used by tests and examples)
// ---------------------------------------------------------------------------

pub const FibAir = struct {
    pub const num_columns = 2;
    pub const num_transition_constraints = 2;
    pub const num_boundary = 3;
    pub const PublicInputs = struct {
        claimed_fib: QM31,
    };

    /// Frame: current[j] = column j at step i, next[j] = column j at step i+1.
    pub fn evalTransition(x: QM31, current: []const QM31, next: []const QM31, out: []QM31) void {
        _ = x;
        // a_{i+1} = b_i
        out[0] = next[0].sub(current[1]);
        // b_{i+1} = a_i + b_i
        out[1] = next[1].sub(current[0]).sub(current[1]);
    }

    pub fn boundaryAssertions(public: PublicInputs, n: usize, out: []BoundaryAssertion) void {
        out[0] = .{ .column = 0, .step = 0, .value = QM31.zero() }; // fib(0) = 0
        out[1] = .{ .column = 1, .step = 0, .value = QM31.one() }; // fib(1) = 1
        out[2] = .{ .column = 0, .step = n - 1, .value = public.claimed_fib }; // fib(n) = claimed
    }

    /// Generate a valid trace of length n for the Fibonacci sequence:
    /// column 0 = fib(i), column 1 = fib(i+1).
    pub fn generateTrace(allocator: std.mem.Allocator, n: usize) ![]const []const QM31 {
        const cols = try allocator.alloc([]const QM31, num_columns);
        const col_a = try allocator.alloc(QM31, n);
        const col_b = try allocator.alloc(QM31, n);
        var a = QM31.zero();
        var b = QM31.one();
        for (0..n) |i| {
            col_a[i] = a;
            col_b[i] = b;
            const na = b;
            const nb = a.add(b);
            a = na;
            b = nb;
        }
        cols[0] = col_a;
        cols[1] = col_b;
        return cols;
    }

    pub fn freeTrace(allocator: std.mem.Allocator, trace: []const []const QM31) void {
        for (trace) |col| allocator.free(col);
        allocator.free(trace);
    }
};

test "STARK Fibonacci prove/verify round-trip" {
    const alloc = std.testing.allocator;
    const params = StarkParams{ .trace_log = 4, .log_blowup = 3, .num_queries = 12 };
    const n = params.traceLen();

    const trace = try FibAir.generateTrace(alloc, n);
    defer FibAir.freeTrace(alloc, trace);
    // claimed fib(n) is the last value of column 0.
    const claimed = trace[0][n - 1];

    var pchan = Channel.init("zig-stark:stark:fib");
    const Stark = GenericStark(FibAir);
    var proof = try Stark.prove(alloc, params, .{ .claimed_fib = claimed }, trace, &pchan);
    defer proof.deinit();

    var vchan = Channel.init("zig-stark:stark:fib");
    const ok = try Stark.verify(alloc, params, .{ .claimed_fib = claimed }, &proof, &vchan);
    try std.testing.expect(ok);
}

test "STARK rejects wrong claimed fib" {
    const alloc = std.testing.allocator;
    const params = StarkParams{ .trace_log = 4, .log_blowup = 3, .num_queries = 12 };
    const n = params.traceLen();

    const trace = try FibAir.generateTrace(alloc, n);
    defer FibAir.freeTrace(alloc, trace);
    const claimed = trace[0][n - 1].add(QM31.one());

    var pchan = Channel.init("zig-stark:stark:fib");
    const Stark = GenericStark(FibAir);
    var proof = try Stark.prove(alloc, params, .{ .claimed_fib = claimed }, trace, &pchan);
    defer proof.deinit();

    var vchan = Channel.init("zig-stark:stark:fib");
    const ok = try Stark.verify(alloc, params, .{ .claimed_fib = claimed }, &proof, &vchan);
    try std.testing.expect(!ok);
}

test "STARK rejects tampered trace commitment" {
    const alloc = std.testing.allocator;
    const params = StarkParams{ .trace_log = 4, .log_blowup = 3, .num_queries = 12 };
    const n = params.traceLen();

    const trace = try FibAir.generateTrace(alloc, n);
    defer FibAir.freeTrace(alloc, trace);
    const claimed = trace[0][n - 1];

    var pchan = Channel.init("zig-stark:stark:fib");
    const Stark = GenericStark(FibAir);
    var proof = try Stark.prove(alloc, params, .{ .claimed_fib = claimed }, trace, &pchan);
    defer proof.deinit();

    // Tamper with a revealed trace value.
    proof.queries[0].values[0] = proof.queries[0].values[0].add(QM31.one());

    var vchan = Channel.init("zig-stark:stark:fib");
    const ok = try Stark.verify(alloc, params, .{ .claimed_fib = claimed }, &proof, &vchan);
    try std.testing.expect(!ok);
}
