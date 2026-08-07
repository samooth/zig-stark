const std = @import("std");
const QM31 = @import("../field/qm31.zig").QM31;
const M31 = @import("../field/m31.zig").M31;
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
///      Preprocessed (lookup table) columns, if any, are committed first and
///      their roots absorbed before the trace roots.
///   2. Sample the LogUp lookup challenges (per lookup column alpha, per
///      relation alpha) and commit the synthesized accumulator columns.
///   3. Sample transition weights alpha and boundary weights beta.
///   4. Build the composition polynomial
///        Hc(x) = sum alpha_k * C_k(x) * (x - w^(n-1))
///              + sum beta_k * (f_{col}(x) - v_k) * Z_H(x) / (x - p_k)
///              + (cyclic LogUp constraints, no (x - w^(n-1)) factor)
///      which vanishes on H, so Hc(x) = Z_H(x) * Q(x); commit Q's codeword.
///   5. Sample z; send the DEEP evaluations f_j(z), f_j(w*z), Q(z); sample
///      DEEP weights gamma; commit the combined polynomial
///        g(x) = sum gamma_j      * (f_j(x)   - f_j(z))   / (x - z)
///             + sum gamma_{m+j}  * (f_j(w*x) - f_j(w*z)) / (x - z)
///             + gamma_{2m} * (Q(x) - Q(z)) / (x - z)
///      via FRI on the same domain D.
///   6. For each FRI query, reveal the trace/accumulator/preprocessed/quotient
///      values at x0 and w*x0 (authenticated by their Merkle trees) and check
///      the DEEP identity and Hc(x0) == Z_H(x0) * Q(x0).
///
/// The AIR type must provide:
///   - `num_columns`, `num_transition_constraints`, `num_boundary`
///   - `evalTransition(x, current, next, out)`: writes transition constraints.
///     `x` is the evaluation point; for row-dependent constraints it should be
///     written as a polynomial in `x` that vanishes on H.
///   - `boundaryAssertions(public_inputs, n, out)`: fills boundary assertions
///   - `maxConstraintDegree(n)`: the maximum degree (in x) of any transition
///     constraint polynomial, assuming column polynomials have degree < n.
///     This sizes the FRI commitment for the DEEP combined polynomial; AIRs
///     with non-linear constraints (e.g. an x^5 sbox) must return more than
///     n - 1 so the quotient's degree fits the FRI code.
///
/// LogUp lookups (all optional; an AIR without lookups is unchanged):
///   - `num_preprocessed`, `num_lookup_columns`, `num_lookup_relations`
///   - per relation: `lookup_selector_columns`, `lookup_key_columns`
///     [relation][column], `lookup_table_columns` [relation][column], and
///     `lookup_multiplicity_columns`.
///
/// GenericStark fully synthesizes the LogUp machinery from this metadata: per
/// relation it appends one accumulator column (trace index `num_columns + r`),
/// a cyclic accumulator transition constraint, a cyclic selector-binarity
/// constraint `sel(1 - sel) = 0`, and a boundary assertion `acc[0] = 0`. The
/// combined key (resp. table key) is the linear combination
/// `sum_j alpha_j * col_j` with per-column challenges sampled from the channel
/// after the preprocessed and trace roots are committed; both prover and
/// verifier derive identical values from the metadata, so no AIR-side
/// `evalLookup` hook is required (and restricting to the linear combination is
/// itself a soundness guard: non-linear key functions can break the multiset
/// argument). The design choice and the transcript order are documented in
/// `docs/protocol.md`.
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
};

pub fn GenericStark(comptime Air: type) type {
    return struct {
        const Self = @This();
        const F = QM31;

        pub const QueryReveal = struct {
            query_index: usize,
            /// length reveal_len: [0..m_total) = f_j(x0) for trace+accumulator
            /// columns, [m_total..2*m_total) = f_j(w*x0), [2*m_total] = Q(x0),
            /// [2*m_total+1..reveal_len) = preprocessed column values at x0.
            values: []F,
            /// matching Merkle paths (same length as `values`).
            paths: [][]Hash.Digest,
        };

        pub const Proof = struct {
            params: StarkParams,
            allocator: std.mem.Allocator,
            trace_roots: []Hash.Digest,
            /// Preprocessed column roots (length num_preprocessed), absorbed
            /// before the trace roots; null when the AIR has none.
            preprocessed_roots: ?[]Hash.Digest = null,
            /// Accumulator column roots (length num_lookup_relations), absorbed
            /// after the lookup challenges are sampled; null when the AIR has
            /// no lookups.
            accumulator_roots: ?[]Hash.Digest = null,
            quotient_root: Hash.Digest,
            /// length 2*m_total + 1: f_j(z), f_j(w*z), then Q(z).
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
                if (self.preprocessed_roots) |roots| self.allocator.free(roots);
                if (self.accumulator_roots) |roots| self.allocator.free(roots);
                self.fri.deinit();
            }
        };

        const m = Air.num_columns;
        const num_trans = Air.num_transition_constraints;
        const num_bound = Air.num_boundary;

        // ---- Preprocessed columns and LogUp lookup metadata (all optional;
        // existing AIRs need not declare any of them). ----
        const n_pre: usize = if (@hasDecl(Air, "num_preprocessed")) Air.num_preprocessed else 0;
        const n_lookup_cols: usize = if (@hasDecl(Air, "num_lookup_columns")) Air.num_lookup_columns else 0;
        const n_rel: usize = if (@hasDecl(Air, "num_lookup_relations")) Air.num_lookup_relations else 0;

        // Per-relation metadata, extracted comptime. Combined keys are the
        // deterministic linear combination sum_j alpha_j * col_j over the
        // declared key (resp. table) columns. Relations may use different
        // numbers of key columns (variable-length lists).
        const selectors: [n_rel]usize = lookupSelectorColumns(Air, n_rel);
        const key_cols: [n_rel][]const usize = lookupKeyColumns(Air, n_rel);
        const table_cols: [n_rel][]const usize = lookupTableColumns(Air, n_rel);
        const mult_cols: [n_rel]usize = lookupMultColumns(Air, n_rel);

        comptime {
            if (n_rel > 0) {
                if (n_pre == 0)
                    @compileError("GenericStark: AIR has lookups (num_lookup_relations > 0) but num_preprocessed == 0");
                if (n_lookup_cols == 0)
                    @compileError("GenericStark: AIR has lookups (num_lookup_relations > 0) but num_lookup_columns == 0");
                if (!@hasDecl(Air, "lookup_selector_columns"))
                    @compileError("GenericStark: AIR with lookups must declare lookup_selector_columns (per relation)");
                if (!@hasDecl(Air, "lookup_key_columns"))
                    @compileError("GenericStark: AIR with lookups must declare lookup_key_columns (per relation, per key column)");
                if (!@hasDecl(Air, "lookup_table_columns"))
                    @compileError("GenericStark: AIR with lookups must declare lookup_table_columns (per relation, per table column)");
                if (!@hasDecl(Air, "lookup_multiplicity_columns"))
                    @compileError("GenericStark: AIR with lookups must declare lookup_multiplicity_columns (per relation)");
            }
        }

        // Synthesized LogUp machinery. Per relation r GenericStark appends:
        //   - one accumulator column at trace index m + r,
        //   - a cyclic accumulator transition constraint (no (x - w^(n-1))
        //     factor, so it is checked on every row of H including the last,
        //     where the "next" accumulator wraps to acc[0] = 0),
        //   - a cyclic selector-binarity constraint sel(1 - sel),
        //   - a boundary assertion acc[0] = 0.
        // With acc[0] = 0 and the cyclic transition the running sum telescopes
        // to zero:  sum_i [sel_i*m_i/(alpha-key_i) - (1-sel_i)/(alpha-tkey_i)]
        // = 0, which holds iff the multisets (with multiplicities) match.
        const m_total = m + n_rel; // committed trace columns (main + accumulators)
        const n_trans_total = num_trans + 2 * n_rel;
        const total_bound = num_bound + n_rel;
        const n_deep = 2 * m_total + 1; // DEEP combination terms (trace+acc + Q)
        const reveal_len = 2 * m_total + 1 + n_pre; // per-query revealed values

        /// The DEEP combined polynomial g has degree < degree_g. With d_c =
        /// Self.maxConstraintDegree(n): the transition part of the composition
        /// has degree <= d_c + 1, the boundary part <= 2n - 2, so the quotient
        /// Q = Hc / Z_H has degree <= max(d_c + 1, 2n - 2) - n and
        ///   degree_g = max(n - 1, d_c - n).
        /// The FRI log size is the smallest power-of-two bound above degree_g.
        fn compositionLogSize(n: usize) u8 {
            const d_c = Self.maxConstraintDegree(n);
            const degree_g = @max(n - 1, d_c -| n);
            var log: u8 = 0;
            var bound: usize = 1;
            while (bound <= degree_g) : (log += 1) bound <<= 1;
            return log;
        }

        /// Effective maximum constraint degree: the AIR-reported degree, padded
        /// to honestly cover the synthesized LogUp constraints. The combined
        /// lookup constraint
        ///   sel*[(acc_next-acc)(alpha-key) - m]
        /// + (1-sel)*[(acc_next-acc)(alpha-tkey) + 1]
        /// is a product of up to three degree-<n polynomials (sel, acc_next-acc,
        /// alpha-key), so its degree is <= 3(n-1); the selector-binarity
        /// constraint sel(1-sel) is <= 2(n-1). Note the cyclic constraints are
        /// added to the composition without the (x - w^(n-1)) factor, so they
        /// contribute maxConstraintDegree(n) directly to Hc, the same as the
        /// base constraints' post-factor bound.
        fn maxConstraintDegree(n: usize) usize {
            const air_degree = Air.maxConstraintDegree(n);
            const lookup_degree: usize = if (n_rel > 0) 3 * (n - 1) else 0;
            return @max(air_degree, lookup_degree);
        }

        /// FRI parameters for g. The FRI domain equals the trace domain
        /// D (size 2^(trace_log + log_blowup)); the FRI blowup is the rate gap
        /// between the combined-degree bound and that domain.
        fn friParams(params: StarkParams) Fri.FriParams {
            const n = params.traceLen();
            const log_size = Self.compositionLogSize(n);
            const domain_log = params.trace_log + params.log_blowup;
            std.debug.assert(log_size <= domain_log);
            std.debug.assert(params.remainder_log < domain_log);
            std.debug.assert(params.remainder_log >= domain_log - log_size);
            return .{
                .log_size = log_size,
                .log_blowup = domain_log - log_size,
                .num_queries = params.num_queries,
                .remainder_log = params.remainder_log,
            };
        }

        /// Combined lookup key from `cols` (a comptime-known per-relation list
        /// of column indices): sum_j alpha_j * row[c_j].
        fn combinedKey(cols: []const usize, alpha_cols: []const F, row_values: []const F) F {
            var k = F.zero();
            for (cols, 0..) |c, j| k = k.add(alpha_cols[j].mul(row_values[c]));
            return k;
        }

        /// Denominator-cleared LogUp transition constraint for relation `r` at a
        /// row. This is a polynomial identity (no field inversions), valid on
        /// every row:
        ///   sel * [(acc_next - acc)(alpha - key) - m]
        /// + (1 - sel) * [(acc_next - acc)(alpha - tkey) + 1]
        /// On a lookup row (sel = 1) this reduces to (acc_next - acc)(alpha-key)
        /// = m; on a table row (sel = 0) to (acc_next - acc)(alpha-tkey) = -1.
        /// The table branch carries the minus sign: the running sum telescopes
        /// to  sum sel*m/(alpha-key) - sum (1-sel)/(alpha-tkey) = 0, i.e. the
        /// multiset identity sum m/(alpha-key) = sum 1/(alpha-tkey).
        fn lookupConstraintAt(
            r: usize,
            alpha_cols: []const F,
            alpha_rels: []const F,
            row_trace: []const F,
            row_pre: []const F,
            acc_current: F,
            acc_next: F,
        ) F {
            const sel = row_trace[selectors[r]];
            const mult = row_trace[mult_cols[r]];
            const key = combinedKey(key_cols[r], alpha_cols, row_trace);
            const tkey = combinedKey(table_cols[r], alpha_cols, row_pre);
            const dacc = acc_next.sub(acc_current);
            const lookup_branch = dacc.mul(alpha_rels[r].sub(key)).sub(mult);
            const table_branch = dacc.mul(alpha_rels[r].sub(tkey)).add(F.one());
            return sel.mul(lookup_branch).add(F.one().sub(sel).mul(table_branch));
        }

        /// Honest LogUp running-sum step for relation `r` at a row:
        ///   sel * m / (alpha - key) - (1 - sel) / (alpha - tkey).
        /// Uses field inversion, so the sampled alpha must not equal any key or
        /// tkey value; for a random QM31 challenge this holds with overwhelming
        /// probability (2n / |QM31| failure bound).
        fn rowContribution(
            r: usize,
            alpha_cols: []const F,
            alpha_rels: []const F,
            row_trace: []const F,
            row_pre: []const F,
        ) F {
            const sel = row_trace[selectors[r]];
            const mult = row_trace[mult_cols[r]];
            const key = combinedKey(key_cols[r], alpha_cols, row_trace);
            const tkey = combinedKey(table_cols[r], alpha_cols, row_pre);
            const lookup_term = sel.mul(mult.mul(alpha_rels[r].sub(key).inv()));
            const table_term = F.one().sub(sel).mul(alpha_rels[r].sub(tkey).inv());
            return lookup_term.sub(table_term);
        }

        /// `trace` is a list of `Air.num_columns` column slices, each of length
        /// 2^trace_log. `public_inputs` drives the boundary assertions. AIRs
        /// without preprocessed columns (num_preprocessed == 0) can use this
        /// directly; lookup AIRs must use `proveWithPreprocessed`.
        pub fn prove(
            allocator: std.mem.Allocator,
            params: StarkParams,
            public_inputs: Air.PublicInputs,
            trace: []const []const F,
            channel: *Channel,
        ) !Proof {
            return proveWithPreprocessed(allocator, params, public_inputs, &.{}, trace, channel);
        }

        /// Like `prove`, but takes the preprocessed (lookup table) columns.
        /// `trace` must have `Air.num_columns` columns and `preprocessed`
        /// `num_preprocessed` columns, each of length 2^trace_log.
        ///
        /// Transcript order (prover and verifier must agree):
        ///   1. absorb preprocessed roots, then the main trace roots;
        ///   2. sample the per-column lookup challenges alpha_col and the
        ///      per-relation challenges alpha_rel;
        ///   3. compute and commit the accumulator columns (their roots are
        ///      absorbed after the lookup challenges, so the accumulator --
        ///      which depends on alpha -- is bound by a later challenge);
        ///   4. sample transition weights, boundary assertions (incl. the
        ///      synthesized acc[0] = 0), boundary weights, then the quotient,
        ///      z, DEEP evaluations, DEEP weights and FRI as usual.
        pub fn proveWithPreprocessed(
            allocator: std.mem.Allocator,
            params: StarkParams,
            public_inputs: Air.PublicInputs,
            preprocessed: []const []const F,
            trace: []const []const F,
            channel: *Channel,
        ) !Proof {
            const n = params.traceLen();
            const N = params.domainLen();
            const shift = params.shift();
            std.debug.assert(trace.len == m);
            for (trace) |col| std.debug.assert(col.len == n);
            std.debug.assert(preprocessed.len == n_pre);
            for (preprocessed) |col| std.debug.assert(col.len == n);

            const w = F.primitiveRootOfUnity(params.trace_log);
            const w_ev = F.primitiveRootOfUnity(params.trace_log + params.log_blowup);

            // H points and interpolation of each column.
            const h_points = try allocator.alloc(F, n);
            defer allocator.free(h_points);
            h_points[0] = F.one();
            for (1..n) |i| h_points[i] = h_points[i - 1].mul(w);

            const coeffs = try allocator.alloc([]F, m_total);
            errdefer allocator.free(coeffs);
            for (0..m) |j| {
                coeffs[j] = try allocator.alloc(F, n);
                errdefer allocator.free(coeffs[j]);
                try UnivariateQM31.interpolate(allocator, h_points, trace[j], coeffs[j]);
            }

            const pre_coeffs = try allocator.alloc([]F, n_pre);
            errdefer allocator.free(pre_coeffs);
            for (0..n_pre) |j| {
                pre_coeffs[j] = try allocator.alloc(F, n);
                errdefer allocator.free(pre_coeffs[j]);
                try UnivariateQM31.interpolate(allocator, h_points, preprocessed[j], pre_coeffs[j]);
            }

            // Domain D points.
            const d_points = try allocator.alloc(F, N);
            defer allocator.free(d_points);
            d_points[0] = Fri.FRI_OFFSET;
            for (1..N) |i| d_points[i] = d_points[i - 1].mul(w_ev);

            // Preprocessed codewords and their commitment (absorbed first).
            const pre_codewords = try allocator.alloc([]F, n_pre);
            errdefer allocator.free(pre_codewords);
            for (0..n_pre) |j| {
                pre_codewords[j] = try allocator.alloc(F, N);
                errdefer allocator.free(pre_codewords[j]);
                for (0..N) |i| pre_codewords[j][i] = UnivariateQM31.eval(pre_coeffs[j], d_points[i]);
            }
            const pre_roots: ?[]Hash.Digest = if (n_pre > 0) try allocator.alloc(Hash.Digest, n_pre) else null;
            errdefer if (pre_roots) |roots| allocator.free(roots);
            const pre_trees = try allocator.alloc(MerkleTree, n_pre);
            errdefer allocator.free(pre_trees);
            for (0..n_pre) |j| {
                const leaves = try hashCodeword(allocator, pre_codewords[j]);
                defer allocator.free(leaves);
                pre_trees[j] = try MerkleTree.init(allocator, leaves);
                if (pre_roots) |roots| {
                    roots[j] = pre_trees[j].root();
                    channel.absorbDigest(roots[j]);
                }
            }

            // Trace codewords and commitment.
            const codewords = try allocator.alloc([]F, m_total);
            errdefer allocator.free(codewords);
            for (0..m) |j| {
                codewords[j] = try allocator.alloc(F, N);
                errdefer allocator.free(codewords[j]);
                for (0..N) |i| codewords[j][i] = UnivariateQM31.eval(coeffs[j], d_points[i]);
            }
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

            // Sample the lookup challenges after the preprocessed + trace roots.
            const alpha_cols = try allocator.alloc(F, n_lookup_cols);
            defer allocator.free(alpha_cols);
            for (alpha_cols) |*a| a.* = channel.sampleQM31();
            const alpha_rels = try allocator.alloc(F, n_rel);
            defer allocator.free(alpha_rels);
            for (alpha_rels) |*a| a.* = channel.sampleQM31();

            // Fill the accumulator columns on H: acc[0] = 0 and
            //   acc[i+1] = acc[i] + sel*m/(alpha-key) - (1-sel)/(alpha-tkey).
            // For an honest trace the total contribution is 0, so acc[n-1] =
            // -contrib(n-1) and the cyclic transition at the last row (where the
            // "next" value wraps to acc[0] = 0) closes the sum to 0.
            const acc_h = try allocator.alloc([]F, n_rel);
            errdefer allocator.free(acc_h);
            const h_row = try allocator.alloc(F, m);
            defer allocator.free(h_row);
            const h_pre = try allocator.alloc(F, n_pre);
            defer allocator.free(h_pre);
            for (0..n_rel) |r| {
                acc_h[r] = try allocator.alloc(F, n);
                errdefer allocator.free(acc_h[r]);
                acc_h[r][0] = F.zero();
            }
            for (1..n) |i| {
                for (0..m) |j| h_row[j] = trace[j][i - 1];
                for (0..n_pre) |j| h_pre[j] = preprocessed[j][i - 1];
                for (0..n_rel) |r| {
                    acc_h[r][i] = acc_h[r][i - 1].add(rowContribution(r, alpha_cols, alpha_rels, h_row, h_pre));
                }
            }

            // Interpolate, evaluate and commit the accumulator columns.
            const acc_trees = try allocator.alloc(MerkleTree, n_rel);
            errdefer allocator.free(acc_trees);
            const acc_roots: ?[]Hash.Digest = if (n_rel > 0) try allocator.alloc(Hash.Digest, n_rel) else null;
            errdefer if (acc_roots) |roots| allocator.free(roots);
            for (0..n_rel) |r| {
                coeffs[m + r] = try allocator.alloc(F, n);
                errdefer allocator.free(coeffs[m + r]);
                try UnivariateQM31.interpolate(allocator, h_points, acc_h[r], coeffs[m + r]);
                codewords[m + r] = try allocator.alloc(F, N);
                errdefer allocator.free(codewords[m + r]);
                for (0..N) |i| codewords[m + r][i] = UnivariateQM31.eval(coeffs[m + r], d_points[i]);
                const leaves = try hashCodeword(allocator, codewords[m + r]);
                defer allocator.free(leaves);
                acc_trees[r] = try MerkleTree.init(allocator, leaves);
                if (acc_roots) |roots| {
                    roots[r] = acc_trees[r].root();
                    channel.absorbDigest(roots[r]);
                }
            }

            // Sample transition and boundary weights.
            const alphas = try allocator.alloc(F, n_trans_total);
            defer allocator.free(alphas);
            for (alphas) |*a| a.* = channel.sampleQM31();
            const boundary = try allocator.alloc(BoundaryAssertion, total_bound);
            defer allocator.free(boundary);
            Air.boundaryAssertions(public_inputs, n, boundary[0..num_bound]);
            for (0..n_rel) |r| {
                boundary[num_bound + r] = .{ .column = m + r, .step = 0, .value = F.zero() };
            }
            const betas = try allocator.alloc(F, total_bound);
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
                const current = try allocator.alloc(F, m_total);
                defer allocator.free(current);
                const next = try allocator.alloc(F, m_total);
                defer allocator.free(next);
                const row_pre = try allocator.alloc(F, n_pre);
                defer allocator.free(row_pre);
                const res = try allocator.alloc(F, num_trans);
                defer allocator.free(res);

                for (0..N) |i| {
                    for (0..m_total) |j| {
                        current[j] = codewords[j][i];
                        next[j] = codewords[j][(i + shift) % N];
                    }
                    for (0..n_pre) |j| row_pre[j] = pre_codewords[j][i];
                    Air.evalTransition(d_points[i], current[0..m], next[0..m], res);
                    var h_val = F.zero();
                    for (0..num_trans) |k| {
                        h_val = h_val.add(alphas[k].mul(res[k].mul(d_points[i].sub(last_point))));
                    }
                    // Cyclic LogUp constraints: no (x - w^(n-1)) factor, so they
                    // are enforced on every row of H including the last, where
                    // the accumulator wraps around to acc[0] = 0.
                    for (0..n_rel) |r| {
                        const c = lookupConstraintAt(r, alpha_cols, alpha_rels, current, row_pre, current[m + r], next[m + r]);
                        h_val = h_val.add(alphas[num_trans + r].mul(c));
                    }
                    for (0..n_rel) |r| {
                        const sel = current[selectors[r]];
                        const c_bin = sel.mul(F.one().sub(sel));
                        h_val = h_val.add(alphas[num_trans + n_rel + r].mul(c_bin));
                    }
                    for (0..total_bound) |k| {
                        const p_k = w.pow(@as(u64, @intCast(boundary[k].step)));
                        const term = current[boundary[k].column].sub(boundary[k].value)
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
            const deep_evals = try allocator.alloc(F, n_deep);
            errdefer allocator.free(deep_evals);
            for (0..m_total) |j| {
                deep_evals[j] = UnivariateQM31.eval(coeffs[j], z);
                deep_evals[m_total + j] = UnivariateQM31.eval(coeffs[j], wz);
            }
            deep_evals[2 * m_total] = try computeQuotientAt(
                allocator,
                params,
                public_inputs,
                z,
                coeffs,
                pre_coeffs,
                n,
                w,
                alphas,
                betas,
                boundary,
                alpha_cols,
                alpha_rels,
            );
            channel.absorbQM31s(deep_evals);

            const gammas = try allocator.alloc(F, n_deep);
            defer allocator.free(gammas);
            for (gammas) |*g| g.* = channel.sampleQM31();

            // DEEP combined polynomial codeword on D.
            const g_codeword = try allocator.alloc(F, N);
            errdefer allocator.free(g_codeword);
            for (0..N) |i| {
                const inv_dz = d_points[i].sub(z).inv();
                var g_val = F.zero();
                for (0..m_total) |j| {
                    g_val = g_val.add(gammas[j].mul(codewords[j][i].sub(deep_evals[j]).mul(inv_dz)));
                    g_val = g_val.add(gammas[m_total + j].mul(codewords[j][(i + shift) % N].sub(deep_evals[m_total + j]).mul(inv_dz)));
                }
                g_val = g_val.add(gammas[2 * m_total].mul(q_codeword[i].sub(deep_evals[2 * m_total]).mul(inv_dz)));
                g_codeword[i] = g_val;
            }

            // Commit g via FRI on the same domain.
            const fri_proof = try Fri.proveCodeword(allocator, Self.friParams(params), g_codeword, channel);

            // Per-query reveals: trace + accumulator at x0 and w*x0, Q at x0,
            // preprocessed at x0.
            const queries = try allocator.alloc(QueryReveal, params.num_queries);
            errdefer allocator.free(queries);
            for (queries) |*q| {
                q.values = try allocator.alloc(F, reveal_len);
                errdefer allocator.free(q.values);
                q.paths = try allocator.alloc([]Hash.Digest, reveal_len);
                errdefer allocator.free(q.paths);
            }
            for (queries, 0..) |*q, qi| {
                const p0 = fri_proof.queries[qi].index;
                q.query_index = p0;
                const pn = (p0 + shift) % N;
                for (0..m) |j| {
                    q.values[j] = codewords[j][p0];
                    q.paths[j] = try trace_trees[j].open(p0, allocator);
                    q.values[m_total + j] = codewords[j][pn];
                    q.paths[m_total + j] = try trace_trees[j].open(pn, allocator);
                }
                for (0..n_rel) |r| {
                    q.values[m + r] = codewords[m + r][p0];
                    q.paths[m + r] = try acc_trees[r].open(p0, allocator);
                    q.values[m_total + m + r] = codewords[m + r][pn];
                    q.paths[m_total + m + r] = try acc_trees[r].open(pn, allocator);
                }
                q.values[2 * m_total] = q_codeword[p0];
                q.paths[2 * m_total] = try quotient_tree.open(p0, allocator);
                for (0..n_pre) |k| {
                    q.values[2 * m_total + 1 + k] = pre_codewords[k][p0];
                    q.paths[2 * m_total + 1 + k] = try pre_trees[k].open(p0, allocator);
                }
            }

            // Cleanup.
            for (trace_trees) |*t| t.deinit();
            allocator.free(trace_trees);
            for (pre_trees) |*t| t.deinit();
            allocator.free(pre_trees);
            for (acc_trees) |*t| t.deinit();
            allocator.free(acc_trees);
            for (codewords) |c| allocator.free(c);
            allocator.free(codewords);
            for (pre_codewords) |c| allocator.free(c);
            allocator.free(pre_codewords);
            for (coeffs) |c| allocator.free(c);
            allocator.free(coeffs);
            for (pre_coeffs) |c| allocator.free(c);
            allocator.free(pre_coeffs);
            for (acc_h) |c| allocator.free(c);
            allocator.free(acc_h);
            allocator.free(g_codeword);
            allocator.free(q_codeword);

            return .{
                .params = params,
                .allocator = allocator,
                .trace_roots = trace_roots,
                .preprocessed_roots = pre_roots,
                .accumulator_roots = acc_roots,
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
            if (proof.trace_roots.len != m) return false;
            if (proof.deep_evals.len != n_deep) return false;
            if (n_pre > 0 and proof.preprocessed_roots == null) return false;
            if (n_rel > 0 and proof.accumulator_roots == null) return false;

            const w = F.primitiveRootOfUnity(params.trace_log);
            const w_ev = F.primitiveRootOfUnity(params.trace_log + params.log_blowup);

            // Replay the transcript in the exact order the prover wrote it.
            for (0..n_pre) |k| channel.absorbDigest(proof.preprocessed_roots.?[k]);
            for (0..m) |j| channel.absorbDigest(proof.trace_roots[j]);
            const alpha_cols = try allocator.alloc(F, n_lookup_cols);
            defer allocator.free(alpha_cols);
            for (alpha_cols) |*a| a.* = channel.sampleQM31();
            const alpha_rels = try allocator.alloc(F, n_rel);
            defer allocator.free(alpha_rels);
            for (alpha_rels) |*a| a.* = channel.sampleQM31();
            for (0..n_rel) |r| channel.absorbDigest(proof.accumulator_roots.?[r]);

            const alphas = try allocator.alloc(F, n_trans_total);
            defer allocator.free(alphas);
            for (alphas) |*a| a.* = channel.sampleQM31();
            const boundary = try allocator.alloc(BoundaryAssertion, total_bound);
            defer allocator.free(boundary);
            Air.boundaryAssertions(public_inputs, n, boundary[0..num_bound]);
            for (0..n_rel) |r| {
                boundary[num_bound + r] = .{ .column = m + r, .step = 0, .value = F.zero() };
            }
            const betas = try allocator.alloc(F, total_bound);
            defer allocator.free(betas);
            for (betas) |*b| b.* = channel.sampleQM31();

            channel.absorbDigest(proof.quotient_root);
            const z = channel.sampleQM31();
            channel.absorbQM31s(proof.deep_evals);
            const gammas = try allocator.alloc(F, n_deep);
            defer allocator.free(gammas);
            for (gammas) |*g| g.* = channel.sampleQM31();

            // FRI verification (also samples FRI alphas / remainder / queries).
            if (!try Fri.verify(allocator, Self.friParams(params), &proof.fri, channel)) return false;

            const last_point = w.pow(@as(u64, @intCast(n - 1)));
            for (proof.queries, 0..) |qv, qi| {
                if (qv.query_index != proof.fri.queries[qi].index) return false;
                if (qv.values.len != reveal_len) return false;
                const p0 = qv.query_index;
                const pn = (p0 + shift) % N;

                // Merkle checks for trace + accumulator (at p0 and pn), quotient
                // and preprocessed (at p0) reveals.
                for (0..m) |j| {
                    if (!merkleVerify(proof.trace_roots[j], p0, Hash.hashQM31(qv.values[j]), qv.paths[j])) return false;
                    if (!merkleVerify(proof.trace_roots[j], pn, Hash.hashQM31(qv.values[m_total + j]), qv.paths[m_total + j])) return false;
                }
                for (0..n_rel) |r| {
                    if (!merkleVerify(proof.accumulator_roots.?[r], p0, Hash.hashQM31(qv.values[m + r]), qv.paths[m + r])) return false;
                    if (!merkleVerify(proof.accumulator_roots.?[r], pn, Hash.hashQM31(qv.values[m_total + m + r]), qv.paths[m_total + m + r])) return false;
                }
                if (!merkleVerify(proof.quotient_root, p0, Hash.hashQM31(qv.values[2 * m_total]), qv.paths[2 * m_total])) return false;
                for (0..n_pre) |k| {
                    if (!merkleVerify(proof.preprocessed_roots.?[k], p0, Hash.hashQM31(qv.values[2 * m_total + 1 + k]), qv.paths[2 * m_total + 1 + k])) return false;
                }

                const x0 = Fri.FRI_OFFSET.mul(w_ev.pow(@as(u64, @intCast(p0))));

                // DEEP identity: g(x0) must match the FRI leaf at p0.
                const inv_dz = x0.sub(z).inv();
                var g_val = F.zero();
                for (0..m_total) |j| {
                    g_val = g_val.add(gammas[j].mul(qv.values[j].sub(proof.deep_evals[j]).mul(inv_dz)));
                    g_val = g_val.add(gammas[m_total + j].mul(qv.values[m_total + j].sub(proof.deep_evals[m_total + j]).mul(inv_dz)));
                }
                g_val = g_val.add(gammas[2 * m_total].mul(qv.values[2 * m_total].sub(proof.deep_evals[2 * m_total]).mul(inv_dz)));

                // The FRI first-layer leaf at index p0 is one of the two revealed
                // layer-0 values (positions p1 and p1 + N/2).
                const n1 = N / 2;
                const p1 = p0 % n1;
                const pair0 = proof.fri.queries[qi].pairs[0];
                const fri_leaf = if (p0 == p1) pair0.value0 else pair0.value1;
                if (!g_val.eq(fri_leaf)) return false;

                // Constraint check: Hc(x0) == Z_H(x0) * Q(x0). Includes the
                // cyclic LogUp constraints (no (x - w^(n-1)) factor).
                const current = qv.values[0..m_total];
                const next = qv.values[m_total .. 2 * m_total];
                const row_pre = qv.values[2 * m_total + 1 .. reveal_len];
                const res = try allocator.alloc(F, num_trans);
                defer allocator.free(res);
                Air.evalTransition(x0, current[0..m], next[0..m], res);
                var h_val = F.zero();
                for (0..num_trans) |k| {
                    h_val = h_val.add(alphas[k].mul(res[k].mul(x0.sub(last_point))));
                }
                for (0..n_rel) |r| {
                    const c = lookupConstraintAt(r, alpha_cols, alpha_rels, current, row_pre, current[m + r], next[m + r]);
                    h_val = h_val.add(alphas[num_trans + r].mul(c));
                }
                for (0..n_rel) |r| {
                    const sel = current[selectors[r]];
                    const c_bin = sel.mul(F.one().sub(sel));
                    h_val = h_val.add(alphas[num_trans + n_rel + r].mul(c_bin));
                }
                const zh = x0.pow(@as(u64, @intCast(n))).sub(F.one());
                for (0..total_bound) |k| {
                    const p_k = w.pow(@as(u64, @intCast(boundary[k].step)));
                    const term = current[boundary[k].column].sub(boundary[k].value)
                        .mul(zh).mul(x0.sub(p_k).inv());
                    h_val = h_val.add(betas[k].mul(term));
                }
                if (!h_val.eq(zh.mul(qv.values[2 * m_total]))) return false;
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
            pre_coeffs: []const []const F,
            n: usize,
            w: F,
            alphas: []const F,
            betas: []const F,
            boundary: []const BoundaryAssertion,
            alpha_cols: []const F,
            alpha_rels: []const F,
        ) !F {
            _ = params;
            _ = public_inputs;

            const current = try allocator.alloc(F, m_total);
            defer allocator.free(current);
            const next = try allocator.alloc(F, m_total);
            defer allocator.free(next);
            for (0..m_total) |j| {
                current[j] = UnivariateQM31.eval(coeffs[j], z);
                next[j] = UnivariateQM31.eval(coeffs[j], z.mul(w));
            }
            const row_pre = try allocator.alloc(F, n_pre);
            defer allocator.free(row_pre);
            for (0..n_pre) |j| row_pre[j] = UnivariateQM31.eval(pre_coeffs[j], z);

            const res = try allocator.alloc(F, num_trans);
            defer allocator.free(res);
            Air.evalTransition(z, current[0..m], next[0..m], res);
            const last_point = w.pow(@as(u64, @intCast(n - 1)));
            var h_val = F.zero();
            for (0..num_trans) |k| {
                h_val = h_val.add(alphas[k].mul(res[k].mul(z.sub(last_point))));
            }
            for (0..n_rel) |r| {
                const c = lookupConstraintAt(r, alpha_cols, alpha_rels, current, row_pre, current[m + r], next[m + r]);
                h_val = h_val.add(alphas[num_trans + r].mul(c));
            }
            for (0..n_rel) |r| {
                const sel = current[selectors[r]];
                const c_bin = sel.mul(F.one().sub(sel));
                h_val = h_val.add(alphas[num_trans + n_rel + r].mul(c_bin));
            }
            const zh = z.pow(@as(u64, @intCast(n))).sub(F.one());
            for (0..total_bound) |k| {
                const p_k = w.pow(@as(u64, @intCast(boundary[k].step)));
                const term = current[boundary[k].column].sub(boundary[k].value)
                    .mul(zh).mul(z.sub(p_k).inv());
                h_val = h_val.add(betas[k].mul(term));
            }
            return h_val.mul(zh.inv());
        }
    };
}

/// Comptime helper: per-relation selector column indices.
fn lookupSelectorColumns(comptime Air: type, comptime n_rel: usize) [n_rel]usize {
    return comptime if (n_rel > 0) Air.lookup_selector_columns else [_]usize{};
}

/// Comptime helper: per-relation key column indices (variable lengths).
fn lookupKeyColumns(comptime Air: type, comptime n_rel: usize) [n_rel][]const usize {
    return comptime if (n_rel > 0) Air.lookup_key_columns else [_][]const usize{};
}

/// Comptime helper: per-relation table column indices (variable lengths).
fn lookupTableColumns(comptime Air: type, comptime n_rel: usize) [n_rel][]const usize {
    return comptime if (n_rel > 0) Air.lookup_table_columns else [_][]const usize{};
}

/// Comptime helper: per-relation multiplicity column indices.
fn lookupMultColumns(comptime Air: type, comptime n_rel: usize) [n_rel]usize {
    return comptime if (n_rel > 0) Air.lookup_multiplicity_columns else [_]usize{};
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

    /// Both constraints are linear in the columns, so as polynomials in x
    /// they have degree < n.
    pub fn maxConstraintDegree(n: usize) usize {
        return n - 1;
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

/// Small integer as a QM31.
fn fq(x: u32) QM31 {
    return QM31.fromM31(M31.fromInt(x));
}

// ---------------------------------------------------------------------------
// Range-check AIR: a single lookup relation with one key column. Every trace
// row (selector = 1) claims its `value` (with multiplicity 1) appears in the
// preprocessed range table.
// ---------------------------------------------------------------------------

pub const RangeCheckAir = struct {
    pub const num_columns = 3; // [value, mult, selector]
    pub const num_preprocessed = 1; // [table]
    pub const num_transition_constraints = 0;
    pub const num_boundary = 0;
    pub const num_lookup_columns = 1;
    pub const num_lookup_relations = 1;
    pub const lookup_selector_columns = [1]usize{2};
    pub const lookup_key_columns = [1][]const usize{&.{0}};
    pub const lookup_table_columns = [1][]const usize{&.{0}};
    pub const lookup_multiplicity_columns = [1]usize{1};

    pub const PublicInputs = struct {};

    pub fn evalTransition(x: QM31, current: []const QM31, next: []const QM31, out: []QM31) void {
        _ = x;
        _ = current;
        _ = next;
        _ = out;
    }

    pub fn maxConstraintDegree(n: usize) usize {
        return n - 1;
    }

    pub fn boundaryAssertions(public: PublicInputs, n: usize, out: []BoundaryAssertion) void {
        _ = public;
        _ = n;
        _ = out;
    }

    /// Honest trace: rows 0..7 are lookup rows (sel=1) carrying values 0..3
    /// twice each with multiplicity 1; rows 8..15 are table rows (sel=0) whose
    /// table column entries the preprocessed table must supply. The lookup
    /// multiset {0,0,1,1,2,2,3,3} matches the table multiset.
    pub fn generateTrace(allocator: std.mem.Allocator, n: usize) ![]const []const QM31 {
        const cols = try allocator.alloc([]const QM31, num_columns);
        const value = try allocator.alloc(QM31, n);
        const mult = try allocator.alloc(QM31, n);
        const sel = try allocator.alloc(QM31, n);
        for (0..n) |i| {
            if (i < n / 2) {
                value[i] = fq(@intCast(i % 4));
                mult[i] = QM31.one();
                sel[i] = QM31.one();
            } else {
                value[i] = QM31.zero();
                mult[i] = QM31.zero();
                sel[i] = QM31.zero();
            }
        }
        cols[0] = value;
        cols[1] = mult;
        cols[2] = sel;
        return cols;
    }

    /// Table: values 0..3 twice each, aligned with the sel=0 (table) rows.
    pub fn generateTable(allocator: std.mem.Allocator, n: usize) ![]const []const QM31 {
        const table = try allocator.alloc(QM31, n);
        for (0..n) |i| {
            if (i < n / 2) table[i] = QM31.zero() else table[i] = fq(@intCast(i % 4));
        }
        const cols = try allocator.alloc([]const QM31, num_preprocessed);
        cols[0] = table;
        return cols;
    }

    pub fn freeTrace(allocator: std.mem.Allocator, trace: []const []const QM31) void {
        for (trace) |col| allocator.free(col);
        allocator.free(trace);
    }

    pub fn freeTable(allocator: std.mem.Allocator, table: []const []const QM31) void {
        for (table) |col| allocator.free(col);
        allocator.free(table);
    }
};

// ---------------------------------------------------------------------------
// AND-table AIR: a single lookup relation with a two-column key (x, y) against
// the table of all bit pairs, exercising the multi-column combined key.
// ---------------------------------------------------------------------------

pub const AndTableAir = struct {
    pub const num_columns = 3; // [x, y, selector]
    pub const num_preprocessed = 2; // [ta, tb]
    pub const num_transition_constraints = 0;
    pub const num_boundary = 0;
    pub const num_lookup_columns = 2;
    pub const num_lookup_relations = 1;
    pub const lookup_selector_columns = [1]usize{2};
    pub const lookup_key_columns = [1][]const usize{&.{ 0, 1 }};
    pub const lookup_table_columns = [1][]const usize{&.{ 0, 1 }};
    pub const lookup_multiplicity_columns = [1]usize{2};

    pub const PublicInputs = struct {};

    pub fn evalTransition(x: QM31, current: []const QM31, next: []const QM31, out: []QM31) void {
        _ = x;
        _ = current;
        _ = next;
        _ = out;
    }

    pub fn maxConstraintDegree(n: usize) usize {
        return n - 1;
    }

    pub fn boundaryAssertions(public: PublicInputs, n: usize, out: []BoundaryAssertion) void {
        _ = public;
        _ = n;
        _ = out;
    }

    /// Honest trace: rows 0..7 are lookup rows (sel=1) carrying the four bit
    /// pairs twice each; rows 8..15 are table rows (sel=0).
    pub fn generateTrace(allocator: std.mem.Allocator, n: usize) ![]const []const QM31 {
        const cols = try allocator.alloc([]const QM31, num_columns);
        const x_col = try allocator.alloc(QM31, n);
        const y_col = try allocator.alloc(QM31, n);
        const sel = try allocator.alloc(QM31, n);
        for (0..n) |i| {
            if (i < n / 2) {
                x_col[i] = fq(@intCast((i % 4) & 1));
                y_col[i] = fq(@intCast((i % 4) >> 1));
                sel[i] = QM31.one();
            } else {
                x_col[i] = QM31.zero();
                y_col[i] = QM31.zero();
                sel[i] = QM31.zero();
            }
        }
        cols[0] = x_col;
        cols[1] = y_col;
        cols[2] = sel;
        return cols;
    }

    /// The table of all four bit pairs, aligned with the sel=0 (table) rows.
    pub fn generateTable(allocator: std.mem.Allocator, n: usize) ![]const []const QM31 {
        const ta = try allocator.alloc(QM31, n);
        const tb = try allocator.alloc(QM31, n);
        for (0..n) |i| {
            if (i < n / 2) {
                ta[i] = QM31.zero();
                tb[i] = QM31.zero();
            } else {
                ta[i] = fq(@intCast((i % 4) & 1));
                tb[i] = fq(@intCast((i % 4) >> 1));
            }
        }
        const cols = try allocator.alloc([]const QM31, num_preprocessed);
        cols[0] = ta;
        cols[1] = tb;
        return cols;
    }

    pub fn freeTrace(allocator: std.mem.Allocator, trace: []const []const QM31) void {
        for (trace) |col| allocator.free(col);
        allocator.free(trace);
    }

    pub fn freeTable(allocator: std.mem.Allocator, table: []const []const QM31) void {
        for (table) |col| allocator.free(col);
        allocator.free(table);
    }
};

// ---------------------------------------------------------------------------
// Multiplicity AIR: one key column `value` with a real multiplicity column.
// Exercises multiplicity > 1 (a single trace row can stand for several table
// entries) and multiplicity 0 (inactive rows).
// ---------------------------------------------------------------------------

pub const MultiplicityAir = struct {
    pub const num_columns = 3; // [value, mult, selector]
    pub const num_preprocessed = 1; // [table]
    pub const num_transition_constraints = 0;
    pub const num_boundary = 0;
    pub const num_lookup_columns = 1;
    pub const num_lookup_relations = 1;
    pub const lookup_selector_columns = [1]usize{2};
    pub const lookup_key_columns = [1][]const usize{&.{0}};
    pub const lookup_table_columns = [1][]const usize{&.{0}};
    pub const lookup_multiplicity_columns = [1]usize{1};

    pub const PublicInputs = struct {};

    pub fn evalTransition(x: QM31, current: []const QM31, next: []const QM31, out: []QM31) void {
        _ = x;
        _ = current;
        _ = next;
        _ = out;
    }

    pub fn maxConstraintDegree(n: usize) usize {
        return n - 1;
    }

    pub fn boundaryAssertions(public: PublicInputs, n: usize, out: []BoundaryAssertion) void {
        _ = public;
        _ = n;
        _ = out;
    }

    /// Honest trace: rows 0..3 are lookup rows (sel=1) carrying values 0..3
    /// each with multiplicity 3; rows 4..15 are table rows (sel=0). The lookup
    /// multiset {0^3,1^3,2^3,3^3} matches the table multiset below.
    pub fn generateTrace(allocator: std.mem.Allocator, n: usize) ![]const []const QM31 {
        std.debug.assert(n >= 4);
        const cols = try allocator.alloc([]const QM31, num_columns);
        const value = try allocator.alloc(QM31, n);
        const mult = try allocator.alloc(QM31, n);
        const sel = try allocator.alloc(QM31, n);
        for (0..n) |i| {
            if (i < 4) {
                value[i] = fq(@intCast(i));
                mult[i] = fq(3);
                sel[i] = QM31.one();
            } else {
                value[i] = QM31.zero();
                mult[i] = QM31.zero();
                sel[i] = QM31.zero();
            }
        }
        cols[0] = value;
        cols[1] = mult;
        cols[2] = sel;
        return cols;
    }

    /// Table: values 0..3 each repeated 3 times over the sel=0 (table) rows.
    pub fn generateTable(allocator: std.mem.Allocator, n: usize) ![]const []const QM31 {
        const table = try allocator.alloc(QM31, n);
        for (0..n) |i| {
            if (i < 4) table[i] = QM31.zero() else table[i] = fq(@intCast(i % 4));
        }
        const cols = try allocator.alloc([]const QM31, num_preprocessed);
        cols[0] = table;
        return cols;
    }

    pub fn freeTrace(allocator: std.mem.Allocator, trace: []const []const QM31) void {
        for (trace) |col| allocator.free(col);
        allocator.free(trace);
    }

    pub fn freeTable(allocator: std.mem.Allocator, table: []const []const QM31) void {
        for (table) |col| allocator.free(col);
        allocator.free(table);
    }
};

fn lookupRoundTrip(comptime Air: type, n: usize) !bool {
    const alloc = std.testing.allocator;
    const params = StarkParams{ .trace_log = 4, .log_blowup = 3, .num_queries = 16 };
    _ = n;

    const trace = try Air.generateTrace(alloc, params.traceLen());
    defer Air.freeTrace(alloc, trace);
    const table = try Air.generateTable(alloc, params.traceLen());
    defer Air.freeTable(alloc, table);

    const Stark = GenericStark(Air);
    var pchan = Channel.init("zig-stark:stark:lookup");
    var proof = try Stark.proveWithPreprocessed(alloc, params, .{}, table, trace, &pchan);
    defer proof.deinit();

    var vchan = Channel.init("zig-stark:stark:lookup");
    return try Stark.verify(alloc, params, .{}, &proof, &vchan);
}

test "STARK lookup: range check round-trip" {
    try std.testing.expect(try lookupRoundTrip(RangeCheckAir, 16));
}

test "STARK lookup: AND table round-trip" {
    try std.testing.expect(try lookupRoundTrip(AndTableAir, 16));
}

test "STARK lookup: multiplicity round-trip" {
    try std.testing.expect(try lookupRoundTrip(MultiplicityAir, 16));
}

fn lookupTamperTest(comptime Air: type, tamper_index: usize) !bool {
    const alloc = std.testing.allocator;
    const params = StarkParams{ .trace_log = 4, .log_blowup = 3, .num_queries = 16 };

    const trace = try Air.generateTrace(alloc, params.traceLen());
    defer Air.freeTrace(alloc, trace);
    const table = try Air.generateTable(alloc, params.traceLen());
    defer Air.freeTable(alloc, table);

    const Stark = GenericStark(Air);
    var pchan = Channel.init("zig-stark:stark:lookup");
    var proof = try Stark.proveWithPreprocessed(alloc, params, .{}, table, trace, &pchan);
    defer proof.deinit();

    // Tamper with a revealed value to break the multiset identity / DEEP check.
    proof.queries[0].values[tamper_index] = proof.queries[0].values[tamper_index].add(QM31.one());

    var vchan = Channel.init("zig-stark:stark:lookup");
    return try Stark.verify(alloc, params, .{}, &proof, &vchan);
}

test "STARK lookup: range check rejects tampered value" {
    try std.testing.expect(!try lookupTamperTest(RangeCheckAir, 0));
}

test "STARK lookup: AND table rejects tampered key" {
    try std.testing.expect(!try lookupTamperTest(AndTableAir, 0));
}

test "STARK lookup: multiplicity rejects tampered multiplicity" {
    try std.testing.expect(!try lookupTamperTest(MultiplicityAir, 1));
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
