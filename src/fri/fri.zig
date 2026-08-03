const std = @import("std");
const QM31 = @import("../field/qm31.zig").QM31;
const M31 = @import("../field/m31.zig").M31;
const CM31 = @import("../field/cm31.zig").CM31;
const Hash = @import("../hash/hash.zig").Hash;
const Channel = @import("../channel/channel.zig").Channel;
const MerkleTree = @import("../merkle/merkle.zig").MerkleTree;
const merkleVerify = @import("../merkle/merkle.zig").verify;
const UnivariateQM31 = @import("../poly/univariate.zig").UnivariateQM31;

/// FRI (Fast Reed-Solomon Interactive Oracle Proof) over QM31.
///
/// A polynomial of degree < 2^log_size is committed by evaluating it on a
/// multiplicative coset D_0 = offset * <w_0> of size 2^(log_size + log_blowup)
/// and committing each layer of the FRI fold to a Merkle tree.
///
/// Layer i has domain D_i = offset^(2^i) * <w_i> where w_{i+1} = w_i^2, so
/// D_{i+1}[j] = (D_i[j])^2. With a random alpha, the fold combines the
/// even/odd parts of the polynomial:
///
///   f_{i+1}(x^2) = (f_i(x) + f_i(-x)) / 2
///                + alpha_i * x^{-1} * (f_i(x) - f_i(-x)) / 2
///
/// which halves the degree each round. The final layer is interpolated and
/// sent directly as the "remainder" polynomial.
///
/// Queries reveal the actual field values (for the fold arithmetic) together
/// with their Merkle authentication paths; the verifier hashes the values and
/// checks them against the committed root.
///
/// Fiat-Shamir ordering (prover and verifier must agree):
///   absorb root_i, sample alpha_i  (for each committed layer i)
///   absorb remainder
///   sample query indices
pub const FRI_OFFSET: QM31 = .{ .a = CM31.one(), .b = CM31.one() };

pub const FriParams = struct {
    /// 2^log_size = number of polynomial coefficients (degree < 2^log_size).
    log_size: u8,
    /// Evaluation domain size = 2^(log_size + log_blowup).
    log_blowup: u8 = 3,
    num_queries: usize = 24,
    /// The remainder polynomial has degree < 2^remainder_log.
    remainder_log: u8 = 3,

    pub fn domainLogSize(self: FriParams) u8 {
        return self.log_size + self.log_blowup;
    }

    /// Number of committed FRI layers (folds performed).
    pub fn numFoldRounds(self: FriParams) u8 {
        return self.domainLogSize() - self.remainder_log;
    }
};

/// The pair of values (and their Merkle paths) revealed for one layer of one query.
pub const Pair = struct {
    value0: QM31,
    value1: QM31,
    path0: []Hash.Digest,
    path1: []Hash.Digest,
};

pub const Query = struct {
    /// Initial domain index p_0; p_{i+1} = p_i mod n_{i+1}.
    index: usize,
    /// One `Pair` per committed layer, in layer order.
    pairs: []Pair,
};

pub const Proof = struct {
    params: FriParams,
    allocator: std.mem.Allocator,
    /// Merkle root of each committed layer (length = numFoldRounds).
    roots: []Hash.Digest,
    /// Remainder polynomial coefficients (length = 2^remainder_log).
    remainder: []QM31,
    queries: []Query,

    pub fn deinit(self: *Proof) void {
        for (self.queries) |*q| {
            for (q.pairs) |pair| {
                self.allocator.free(pair.path0);
                self.allocator.free(pair.path1);
            }
            self.allocator.free(q.pairs);
        }
        self.allocator.free(self.queries);
        self.allocator.free(self.remainder);
        self.allocator.free(self.roots);
    }
};

/// Point D_layer[j] = offset^(2^layer) * w_layer^j.
fn domainPoint(params: FriParams, layer: u8, j: usize) QM31 {
    const dlog = params.domainLogSize();
    const w = QM31.primitiveRootOfUnity(dlog - layer);
    const offset = FRI_OFFSET.pow(@as(u64, 1) << @intCast(layer));
    return offset.mul(w.pow(@as(u64, @intCast(j))));
}

/// Materialize all points of layer `layer` (indices 0..size).
fn domainPoints(allocator: std.mem.Allocator, params: FriParams, layer: u8) ![]QM31 {
    const dlog = params.domainLogSize();
    const n = @as(usize, 1) << @intCast(dlog - layer);
    const points = try allocator.alloc(QM31, n);
    errdefer allocator.free(points);
    const w = QM31.primitiveRootOfUnity(dlog - layer);
    const offset = FRI_OFFSET.pow(@as(u64, 1) << @intCast(layer));
    var acc = offset;
    for (0..n) |j| {
        points[j] = acc;
        acc = acc.mul(w);
    }
    return points;
}

fn invTwo() QM31 {
    return QM31.fromM31(M31.fromInt(2).inv());
}

/// f_{i+1} fold value at D_{i+1}[j], from layer-i values at the pair
/// (D_i[j], -D_i[j]).
fn foldValue(g: QM31, y0: QM31, y1: QM31, alpha: QM31) QM31 {
    const inv_two = invTwo();
    const half_sum = y0.add(y1).mul(inv_two);
    const half_diff = y0.sub(y1).mul(g.inv()).mul(inv_two);
    return half_sum.add(alpha.mul(half_diff));
}

/// Produce a full FRI proof for `coeffs` (a QM31 polynomial of degree
/// < 2^log_size). `channel` is advanced by absorbing commitments and sampling
/// Fiat-Shamir challenges.
pub fn prove(
    allocator: std.mem.Allocator,
    params: FriParams,
    coeffs: []const QM31,
    channel: *Channel,
) !Proof {
    std.debug.assert(coeffs.len == @as(usize, 1) << @intCast(params.log_size));
    const dlog = params.domainLogSize();
    const n0 = @as(usize, 1) << @intCast(dlog);
    const dom0 = try domainPoints(allocator, params, 0);
    defer allocator.free(dom0);
    const ev0 = try allocator.alloc(QM31, n0);
    errdefer allocator.free(ev0);
    for (0..n0) |j| ev0[j] = UnivariateQM31.eval(coeffs, dom0[j]);
    defer allocator.free(ev0);
    return proveCodeword(allocator, params, ev0, channel);
}

/// Produce a full FRI proof for an already-computed evaluation codeword on the
/// FRI domain (length 2^domainLogSize). This lets callers commit polynomials
/// whose coefficients are not directly available (e.g. DEEP quotients), as
/// long as the codeword is consistent with a low-degree polynomial.
pub fn proveCodeword(
    allocator: std.mem.Allocator,
    params: FriParams,
    codeword: []const QM31,
    channel: *Channel,
) !Proof {
    const L = params.numFoldRounds();
    const dlog = params.domainLogSize();
    const n0 = @as(usize, 1) << @intCast(dlog);
    std.debug.assert(L >= 1);
    std.debug.assert(codeword.len == n0);

    // All layer evaluation domains (indices 0..L).
    const layer_doms = try allocator.alloc([]QM31, L + 1);
    errdefer allocator.free(layer_doms);
    for (0..L + 1) |i| {
        layer_doms[i] = try domainPoints(allocator, params, @intCast(i));
        errdefer allocator.free(layer_doms[i]);
    }

    // Layer evaluations (indices 0..L).
    const layers = try allocator.alloc([]QM31, L + 1);
    errdefer allocator.free(layers);

    // Layer 0: the provided codeword.
    const ev0 = try allocator.alloc(QM31, n0);
    errdefer allocator.free(ev0);
    @memcpy(ev0, codeword);
    layers[0] = ev0;

    const roots = try allocator.alloc(Hash.Digest, L);
    errdefer allocator.free(roots);

    const trees = try allocator.alloc(MerkleTree, L);
    errdefer allocator.free(trees);

    // Commit layer 0 and fold.
    const inv_two = invTwo();
    for (0..L) |i| {
        // Commit layer i.
        const ni = layers[i].len;
        const nnext = ni / 2;
        const leaves = try allocator.alloc(Hash.Digest, ni);
        errdefer allocator.free(leaves);
        for (layers[i], 0..) |v, j| leaves[j] = Hash.hashQM31(v);
        trees[i] = try MerkleTree.init(allocator, leaves);
        allocator.free(leaves);
        roots[i] = trees[i].root();
        channel.absorbDigest(roots[i]);

        // Sample the fold challenge and build the next layer.
        const alpha = channel.sampleQM31();
        const ev_next = try allocator.alloc(QM31, nnext);
        errdefer allocator.free(ev_next);
        const dom_i = layer_doms[i];
        for (0..nnext) |j| {
            const y0 = layers[i][j];
            const y1 = layers[i][j + nnext];
            const half_sum = y0.add(y1).mul(inv_two);
            const half_diff = y0.sub(y1).mul(dom_i[j].inv()).mul(inv_two);
            ev_next[j] = half_sum.add(alpha.mul(half_diff));
        }
        layers[i + 1] = ev_next;
    }

    // Remainder: the final folded layer is a codeword of the final code
    // RS[d_L, L_L] with d_L = 2^(remainder_log - log_blowup) over the
    // 2^remainder_log points of layer L. Interpolating a strict subset of the
    // points recovers that codeword for an honest prover; for a non-low-degree
    // input the final layer is not a codeword and this remainder cannot match
    // the folds at randomly queried positions.
    std.debug.assert(params.remainder_log >= params.log_blowup);
    const rem_coeffs = @as(usize, 1) << @intCast(params.remainder_log - params.log_blowup);
    const remainder = try allocator.alloc(QM31, rem_coeffs);
    errdefer allocator.free(remainder);
    try UnivariateQM31.interpolate(allocator, layer_doms[L][0..rem_coeffs], layers[L][0..rem_coeffs], remainder);
    channel.absorbQM31s(remainder);

    // Query indices (sampled after all commitments are absorbed).
    const queries = try allocator.alloc(Query, params.num_queries);
    errdefer allocator.free(queries);
    for (queries) |*q| {
        q.pairs = try allocator.alloc(Pair, L);
        errdefer allocator.free(q.pairs);
        const p0 = channel.sampleIndex(n0);
        q.index = p0;
        var p = p0;
        for (0..L) |i| {
            const ni = @as(usize, 1) << @intCast(dlog - i);
            const nnext = ni / 2;
            const pn = p % nnext;
            q.pairs[i] = .{
                .value0 = layers[i][pn],
                .value1 = layers[i][pn + nnext],
                .path0 = try trees[i].open(pn, allocator),
                .path1 = try trees[i].open(pn + nnext, allocator),
            };
            p = pn;
        }
    }

    // Free temporary layer storage.
    for (layer_doms) |ld| allocator.free(ld);
    allocator.free(layer_doms);
    for (layers) |lv| allocator.free(lv);
    allocator.free(layers);
    for (trees) |*t| t.deinit();
    allocator.free(trees);

    return .{
        .params = params,
        .allocator = allocator,
        .roots = roots,
        .remainder = remainder,
        .queries = queries,
    };
}

/// Verify a FRI proof against the transcript. Returns false on any Merkle,
/// fold-consistency, or remainder mismatch.
pub fn verify(
    allocator: std.mem.Allocator,
    params: FriParams,
    proof: *const Proof,
    channel: *Channel,
) !bool {
    const L = params.numFoldRounds();
    const dlog = params.domainLogSize();
    const n0 = @as(usize, 1) << @intCast(dlog);
    if (proof.roots.len != L) return false;
    if (proof.queries.len != params.num_queries) return false;

    // Replay the transcript: absorb roots, resample alphas, absorb remainder,
    // resample the same query indices.
    const alphas = try allocator.alloc(QM31, L);
    defer allocator.free(alphas);
    for (0..L) |i| {
        channel.absorbDigest(proof.roots[i]);
        alphas[i] = channel.sampleQM31();
    }
    channel.absorbQM31s(proof.remainder);

    for (proof.queries) |q| {
        // Check the resampled index matches.
        if (channel.sampleIndex(n0) != q.index) return false;

        var p = q.index;
        var prev_fold: ?QM31 = null;
        for (0..L) |i| {
            const ni = @as(usize, 1) << @intCast(dlog - i);
            const nnext = ni / 2;
            const pn = p % nnext;
            const pair = q.pairs[i];

            // Values must hash to the leaves committed under root_i.
            if (!merkleVerify(proof.roots[i], pn, Hash.hashQM31(pair.value0), pair.path0)) return false;
            if (!merkleVerify(proof.roots[i], pn + nnext, Hash.hashQM31(pair.value1), pair.path1)) return false;

            // The previous fold produced the value at position p in this layer;
            // p is always one of the two revealed positions.
            if (i > 0) {
                const matched = if (p == pn) pair.value0 else if (p == pn + nnext) pair.value1 else unreachable;
                if (!prev_fold.?.eq(matched)) return false;
            }

            const g = domainPoint(params, @intCast(i), pn);
            const fv = foldValue(g, pair.value0, pair.value1, alphas[i]);

            if (i == L - 1) {
                // Compare against the remainder polynomial evaluated at D_L[pn].
                const h = domainPoint(params, @intCast(i + 1), pn);
                if (!UnivariateQM31.eval(proof.remainder, h).eq(fv)) return false;
            }

            prev_fold = fv;
            p = pn;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn randomQM31(rnd: std.Random) QM31 {
    return QM31.new(
        CM31.new(M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS)), M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS))),
        CM31.new(M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS)), M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS))),
    );
}

test "FRI fold halves degree" {
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    const alpha = randomQM31(rnd);
    // f(x) = 1 + x + 2x^2 + 3x^3
    const f = [_]QM31{
        QM31.fromM31(M31.fromInt(1)),
        QM31.fromM31(M31.fromInt(1)),
        QM31.fromM31(M31.fromInt(2)),
        QM31.fromM31(M31.fromInt(3)),
    };
    const params = FriParams{ .log_size = 2, .log_blowup = 0 };
    const dom = try domainPoints(std.testing.allocator, params, 0);
    defer std.testing.allocator.free(dom);
    var ev: [4]QM31 = undefined;
    for (0..4) |j| ev[j] = UnivariateQM31.eval(&f, dom[j]);
    var ev_next: [2]QM31 = undefined;
    for (0..2) |j| ev_next[j] = foldValue(dom[j], ev[j], ev[j + 2], alpha);

    // The fold must agree with the actual folded polynomial at D_1 points.
    const d1 = try domainPoints(std.testing.allocator, params, 1);
    defer std.testing.allocator.free(d1);
    // folded poly: even coeffs (1, 2) + alpha * odd coeffs (1, 3)
    const folded = [_]QM31{
        QM31.fromM31(M31.fromInt(1)).add(alpha.mul(QM31.fromM31(M31.fromInt(1)))),
        QM31.fromM31(M31.fromInt(2)).add(alpha.mul(QM31.fromM31(M31.fromInt(3)))),
    };
    for (0..2) |j| {
        const expect_v = UnivariateQM31.eval(&folded, d1[j]);
        try std.testing.expect(ev_next[j].eq(expect_v));
    }
}

test "FRI prove/verify round-trips" {
    var prng = std.Random.DefaultPrng.init(42);
    const rnd = prng.random();
    const params = FriParams{ .log_size = 4, .log_blowup = 3, .num_queries = 8 };
    const n_coeffs = @as(usize, 1) << @intCast(params.log_size);
    const coeffs = try std.testing.allocator.alloc(QM31, n_coeffs);
    defer std.testing.allocator.free(coeffs);
    for (coeffs) |*c| c.* = randomQM31(rnd);

    var pchan = Channel.init("zig-stark:fri:test");
    var proof = try prove(std.testing.allocator, params, coeffs, &pchan);
    defer proof.deinit();

    var vchan = Channel.init("zig-stark:fri:test");
    const ok = try verify(std.testing.allocator, params, &proof, &vchan);
    try std.testing.expect(ok);
}

test "FRI rejects tampered remainder" {
    var prng = std.Random.DefaultPrng.init(43);
    const rnd = prng.random();
    const params = FriParams{ .log_size = 4, .log_blowup = 3, .num_queries = 8 };
    const n_coeffs = @as(usize, 1) << @intCast(params.log_size);
    const coeffs = try std.testing.allocator.alloc(QM31, n_coeffs);
    defer std.testing.allocator.free(coeffs);
    for (coeffs) |*c| c.* = randomQM31(rnd);

    var pchan = Channel.init("zig-stark:fri:test");
    var proof = try prove(std.testing.allocator, params, coeffs, &pchan);
    defer proof.deinit();

    // Flip a coefficient of the remainder.
    proof.remainder[0] = proof.remainder[0].add(QM31.one());

    var vchan = Channel.init("zig-stark:fri:test");
    const ok = try verify(std.testing.allocator, params, &proof, &vchan);
    try std.testing.expect(!ok);
}

test "FRI rejects tampered query leaf" {
    var prng = std.Random.DefaultPrng.init(44);
    const rnd = prng.random();
    const params = FriParams{ .log_size = 4, .log_blowup = 3, .num_queries = 8 };
    const n_coeffs = @as(usize, 1) << @intCast(params.log_size);
    const coeffs = try std.testing.allocator.alloc(QM31, n_coeffs);
    defer std.testing.allocator.free(coeffs);
    for (coeffs) |*c| c.* = randomQM31(rnd);

    var pchan = Channel.init("zig-stark:fri:test");
    var proof = try prove(std.testing.allocator, params, coeffs, &pchan);
    defer proof.deinit();

    // Tamper with a revealed value in the first query.
    proof.queries[0].pairs[0].value0 = proof.queries[0].pairs[0].value0.add(QM31.one());

    var vchan = Channel.init("zig-stark:fri:test");
    const ok = try verify(std.testing.allocator, params, &proof, &vchan);
    try std.testing.expect(!ok);
}
