//! Additive FRI: a low-degree test for univariate polynomials over the tower field.
//!
//! The domain is an additive (GF(2)-linear) subgroup of the tower field F, taken in the
//! "low-bits" basis: the point with index j < 2^D is the field element `fromInt(j)`
//! (the set bits of j select the basis elements {1, 2, 4, ...}). FRI over an additive
//! subgroup halves the domain not by multiplying by a root of unity but by the halving map
//!
//!     q(x) = x^2 + h*x          h = distance between the two points of a pair
//!
//! which is GF(2)-linear with kernel {0, h}, so it is 2-to-1 and maps the pair {x, x+h}
//! onto a single point q(x) of the smaller domain. Because the tower field is algebraic
//! over GF(2), squaring and rooting are field automorphisms, and the "column interpolation"
//! fold
//!
//!     f'(y) = ( f(x)*(alpha + x + h) + f(x+h)*(alpha + x) ) / h
//!
//! maps a polynomial of degree < d on D_i to one of degree < d/2 on D_{i+1}. (With the
//! low-bits basis the pair distance h is `fromInt(2^(D-1))` only at layer 0; at deeper
//! layers it is recovered from the points themselves, since points[i][j + n/2] =
//! points[i][j] + h_i for a fixed h_i.)
//!
//! The prover commits each folded layer with a Merkle tree, samples the fold challenges
//! alpha and the query positions from a Fiat-Shamir transcript, and opens the queried
//! positions across all layers. The verifier recomputes the folds on the opened values and
//! checks consistency against the remainder, interpolated from the last layer.

const std = @import("std");
const Hash = @import("../core/hash/hash.zig").Hash;
const MerkleTree = @import("../core/merkle/merkle.zig").MerkleTree;
const MerkleVerify = @import("../core/merkle/merkle.zig").verify;
const Tower = @import("tower.zig");
const Sumcheck = @import("sumcheck.zig").Sumcheck;

pub fn AdditiveFri(comptime F: type) type {
    return struct {
        pub const BITS = F.BITS;
        pub const SIZE = F.SIZE;
        const Self = @This();

        /// Parameters of the FRI instance.
        pub const Params = struct {
            /// log2 of the polynomial degree bound (degree < 2^log_size).
            log_size: u8,
            /// log2 of the rate (codeword length = 2^(log_size + log_blowup)).
            log_blowup: u8,
            /// log2 of the size of the final (interpolated) layer.
            log_remainder: u8,
            /// number of query positions opened by the verifier.
            num_queries: usize,
        };

        pub const Layer = struct {
            codeword: []const F,
            hash: Hash.Digest,
            tree: *MerkleTree,
        };

        pub const LayerProof = struct {
            value0: F,
            value1: F,
            /// One Merkle path: the FRI fold-pair {pn, pn+half} is packed into a
            /// single tree leaf, so a query opens one path per layer.
            path: []Hash.Digest,
        };

        pub const LayerProofs = struct {
            proofs: []LayerProof,
        };

        pub const Query = struct {
            index: usize,
            layers: LayerProofs,
        };

        pub const Proof = struct {
            layers: []Layer,
            alphas: []F,
            remainder: []F,
            queries: []Query,

            pub fn deinit(self: Proof, allocator: std.mem.Allocator) void {
                for (self.layers) |layer| {
                    allocator.free(layer.codeword);
                    layer.tree.deinit();
                    allocator.destroy(layer.tree);
                }
                allocator.free(self.layers);
                allocator.free(self.alphas);
                allocator.free(self.remainder);
                for (self.queries) |q| {
                    for (q.layers.proofs) |lp| {
                        allocator.free(lp.path);
                    }
                    allocator.free(q.layers.proofs);
                }
                allocator.free(self.queries);
            }
        };

        /// Fiat-Shamir transcript (Blake3, via `core/hash`). Both prover and verifier
        /// replay the identical sequence: layer roots, fold challenges, remainder, query
        /// positions.
        const Transcript = struct {
            buf: Hash.Digest,

            fn init(seed: []const u8) Transcript {
                return .{ .buf = Hash.hashBytes(seed) };
            }

            fn sampleField(self: *Transcript) F {
                self.buf = Hash.hashBytes(&self.buf);
                const v = if (SIZE == 1)
                    F.fromInt(self.buf[31])
                else
                    F.fromBytes(self.buf[32 - SIZE ..][0..SIZE]);
                return v;
            }

            /// Sample an index in [0, bound) where bound is a power of two.
            fn sampleIndex(self: *Transcript, bound: usize) usize {
                const v = self.sampleField();
                return @as(usize, @intCast(v.value & (bound - 1)));
            }

            fn absorbDigest(self: *Transcript, d: Hash.Digest) void {
                self.buf = Hash.hash2(self.buf, d);
            }

            fn absorbCoeffs(self: *Transcript, coeffs: []const F) void {
                for (coeffs) |c| {
                    var b: [SIZE]u8 = undefined;
                    c.toBytes(&b);
                    self.buf = Hash.hash2(self.buf, Hash.hashBytes(&b));
                }
            }
        };

        /// Hash a FRI fold-pair into one leaf digest: the two field elements'
        /// bytes are concatenated and hashed once (halving the per-layer leaf
        /// count and the number of Blake3 calls vs one digest per element).
        fn hashPair(a: F, b: F) Hash.Digest {
            var buf: [2 * SIZE]u8 = undefined;
            a.toBytes(buf[0..SIZE]);
            b.toBytes(buf[SIZE..]);
            return Hash.hashBytes(&buf);
        }

        fn evalCoeffs(coeffs: []const F, x: F) F {
            var acc = F.zero();
            var i: usize = coeffs.len;
            while (i > 0) {
                i -= 1;
                acc = acc.mul(x).add(coeffs[i]);
            }
            return acc;
        }

        /// The domain points of every layer. points[i] has 2^(D - i) elements with
        /// points[i+1][j] = q_i(points[i][j]) for the halving map q_i(x) = x*(x + h_i)
        /// where h_i is the distance between the two points of a pair at layer i.
        fn buildPoints(
            allocator: std.mem.Allocator,
            log_size: u8,
            log_blowup: u8,
            log_remainder: u8,
        ) ![][]F {
            const D = log_size + log_blowup;
            const L = D - log_remainder;
            var points = try allocator.alloc([]F, L + 1);
            errdefer allocator.free(points);
            points[0] = try allocator.alloc(F, @as(usize, 1) << @intCast(D));
            for (points[0], 0..) |*p, j| p.* = F.fromInt(j);
            var hprev = F.fromInt(@as(u32, 1) << @intCast(D - 1));
            for (1..L + 1) |i| {
                const n = @as(usize, 1) << @intCast(D - i);
                points[i] = try allocator.alloc(F, n);
                for (points[i - 1][0..n], 0..) |x, j| {
                    points[i][j] = x.mul(x.add(hprev));
                }
                if (i < L) {
                    hprev = points[i][0].add(points[i][@as(usize, 1) << @intCast(D - i - 1)]);
                }
            }
            return points;
        }

        fn freePoints(allocator: std.mem.Allocator, points: [][]F) void {
            for (points) |p| allocator.free(p);
            allocator.free(points);
        }

        /// The FRI fold of the pair {x, x+h} onto q(x) = x*(x+h).
        fn foldValue(x: F, xh: F, v0: F, v1: F, alpha: F) F {
            const h = x.add(xh);
            const t0 = v0.mul(alpha.add(xh));
            const t1 = v1.mul(alpha.add(x));
            return t0.add(t1).mul(h.inv());
        }

        fn commitLayer(allocator: std.mem.Allocator, codeword: []const F) !Layer {
            const half = codeword.len / 2;
            const leaves = try allocator.alloc(Hash.Digest, half);
            defer allocator.free(leaves);
            for (0..half) |j| leaves[j] = hashPair(codeword[j], codeword[j + half]);
            var tree = try allocator.create(MerkleTree);
            tree.* = try MerkleTree.init(allocator, leaves);
            return Layer{ .codeword = codeword, .hash = tree.root(), .tree = tree };
        }

        /// Prove that `coeffs` (a polynomial of degree < 2^log_size) is low-degree by
        /// evaluating it on the additive domain and running FRI on the resulting codeword.
        pub fn prove(
            allocator: std.mem.Allocator,
            params: Params,
            coeffs: []const F,
            seed: []const u8,
        ) !Proof {
            const D = params.log_size + params.log_blowup;
            const codeword = try allocator.alloc(F, @as(usize, 1) << @intCast(D));
            defer allocator.free(codeword);
            for (codeword, 0..) |*c, j| c.* = evalCoeffs(coeffs, F.fromInt(j));
            return proveCodeword(allocator, params, codeword, seed);
        }

        /// Run FRI on an existing codeword (evaluations on the additive domain of size
        /// 2^(log_size + log_blowup)). The codeword is copied, so the caller keeps it.
        pub fn proveCodeword(
            allocator: std.mem.Allocator,
            params: Params,
            codeword: []const F,
            seed: []const u8,
        ) !Proof {
            const D = params.log_size + params.log_blowup;
            const L = D - params.log_remainder;
            std.debug.assert(D <= BITS);
            std.debug.assert(params.log_remainder >= params.log_blowup);
            std.debug.assert(params.log_remainder <= D);

            const owned = try allocator.dupe(F, codeword);
            errdefer allocator.free(owned);

            const points = try buildPoints(allocator, params.log_size, params.log_blowup, params.log_remainder);
            defer freePoints(allocator, points);

            const layers = try allocator.alloc(Layer, L);
            const alphas = try allocator.alloc(F, L);
            var committed: usize = 0;
            errdefer {
                for (layers[0..committed]) |layer| {
                    allocator.free(layer.codeword);
                    layer.tree.deinit();
                    allocator.destroy(layer.tree);
                }
                allocator.free(layers);
                allocator.free(alphas);
            }

            var t = Transcript.init(seed);
            var cur = owned;
            for (0..L) |i| {
                layers[i] = try commitLayer(allocator, cur);
                committed = i + 1;
                t.absorbDigest(layers[i].hash);
                const alpha = t.sampleField();
                alphas[i] = alpha;

                const half = @as(usize, 1) << @intCast(D - i - 1);
                const next = try allocator.alloc(F, half);
                for (0..half) |j| {
                    next[j] = foldValue(points[i][j], points[i][j + half], cur[j], cur[j + half], alpha);
                }
                cur = next;
            }

            // Interpolate the remainder from the first coefficients of the last layer.
            const rem_coeffs = @as(usize, 1) << @intCast(params.log_remainder - params.log_blowup);
            const remainder = try Sumcheck(F).interpolateCoeffs(allocator, points[L][0..rem_coeffs], cur[0..rem_coeffs]);
            allocator.free(cur);
            t.absorbCoeffs(remainder);

            // Sample query positions (bound to the transcript for Fiat-Shamir soundness).
            const n0 = @as(usize, 1) << @intCast(D);
            const queries = try allocator.alloc(Query, params.num_queries);
            var qbuilt: usize = 0;
            errdefer {
                for (queries[0..qbuilt]) |q| {
                    for (q.layers.proofs) |lp| {
                        allocator.free(lp.path);
                    }
                    allocator.free(q.layers.proofs);
                }
                allocator.free(queries);
            }
            for (0..params.num_queries) |qi| {
                queries[qi] = try buildQuery(allocator, params, layers, t.sampleIndex(n0));
                qbuilt = qi + 1;
            }

            return Proof{
                .layers = layers,
                .alphas = alphas,
                .remainder = remainder,
                .queries = queries,
            };
        }

        fn buildQuery(
            allocator: std.mem.Allocator,
            params: Params,
            layers: []Layer,
            index: usize,
        ) !Query {
            const D = params.log_size + params.log_blowup;
            const L = layers.len;
            var proofs = try allocator.alloc(LayerProof, L);
            var p = index;
            for (0..L) |i| {
                const half = @as(usize, 1) << @intCast(D - i - 1);
                const pn = p % half;
                proofs[i] = LayerProof{
                    .value0 = layers[i].codeword[pn],
                    .value1 = layers[i].codeword[pn + half],
                    .path = try layers[i].tree.open(pn, allocator),
                };
                p = pn;
            }
            return Query{ .index = index, .layers = .{ .proofs = proofs } };
        }

        /// Verify a FRI proof for a committed codeword (given by the first layer root).
        /// `seed` must match the seed used by the prover (e.g. other commitments).
        pub fn verify(
            allocator: std.mem.Allocator,
            params: Params,
            root: Hash.Digest,
            proof: Proof,
            seed: []const u8,
        ) !bool {
            const D = params.log_size + params.log_blowup;
            const L = D - params.log_remainder;
            if (proof.layers.len != L or proof.alphas.len != L or proof.queries.len != params.num_queries)
                return false;
            if (!std.mem.eql(u8, &proof.layers[0].hash, &root)) return false;

            const points = try buildPoints(allocator, params.log_size, params.log_blowup, params.log_remainder);
            defer freePoints(allocator, points);

            var t = Transcript.init(seed);
            for (proof.layers, proof.alphas) |layer, alpha| {
                t.absorbDigest(layer.hash);
                // The fold challenge must be the one sampled by the transcript.
                if (!t.sampleField().eq(alpha)) return false;
            }
            t.absorbCoeffs(proof.remainder);

            const n0 = @as(usize, 1) << @intCast(D);
            for (proof.queries) |q| {
                if (q.index >= n0) return false;
                // The query position must be the one sampled by the transcript.
                if (t.sampleIndex(n0) != q.index) return false;

                var p = q.index;
                var prev_fold: F = undefined;
                for (0..L) |i| {
                    const half = @as(usize, 1) << @intCast(D - i - 1);
                    const pn = p % half;
                    const lp = q.layers.proofs[i];

                    // Authenticate the opened fold-pair against the layer root
                    // (one leaf packs both values, so a single path suffices).
                    if (!MerkleVerify(proof.layers[i].hash, pn, hashPair(lp.value0, lp.value1), lp.path)) return false;

                    if (i > 0) {
                        // The fold from the previous layer must match the value opened
                        // at the query position of this layer.
                        const v = if (p == pn) lp.value0 else lp.value1;
                        if (!prev_fold.eq(v)) return false;
                    }

                    // The two opened values must fold to the value at the next layer.
                    prev_fold = foldValue(points[i][pn], points[i][pn + half], lp.value0, lp.value1, proof.alphas[i]);
                    p = pn;
                }

                // Check the remainder at the position of the last layer.
                if (!prev_fold.eq(evalCoeffs(proof.remainder, points[L][p]))) return false;
            }
            return true;
        }
    };
}

const testing = std.testing;
const Gf16 = Tower.Gf16;
const Gf256 = Tower.Gf256;

fn prng(seed: u64) std.Random.DefaultPrng {
    return std.Random.DefaultPrng.init(seed);
}

fn roundTrip(comptime F: type, params: AdditiveFri(F).Params, coeffs: []const F) !void {
    const alloc = testing.allocator;
    const proof = try AdditiveFri(F).prove(alloc, params, coeffs, "seed");
    defer proof.deinit(alloc);
    try testing.expect(try AdditiveFri(F).verify(alloc, params, proof.layers[0].hash, proof, "seed"));
}

test "AdditiveFri: round-trip Gf16" {
    const params = AdditiveFri(Gf16).Params{
        .log_size = 2,
        .log_blowup = 1,
        .log_remainder = 1,
        .num_queries = 4,
    };
    var coeffs = [_]Gf16{Gf16.zero()} ** 4;
    var r = prng(42);
    for (&coeffs) |*c| c.* = Gf16.fromInt(r.random().uintLessThan(u32, std.math.maxInt(u32)));
    try roundTrip(Gf16, params, &coeffs);
}

test "AdditiveFri: round-trip Gf256" {
    const params = AdditiveFri(Gf256).Params{
        .log_size = 3,
        .log_blowup = 2,
        .log_remainder = 2,
        .num_queries = 4,
    };
    var coeffs = [_]Gf256{Gf256.zero()} ** 8;
    var r = prng(43);
    for (&coeffs) |*c| c.* = Gf256.fromInt(r.random().uintLessThan(u32, std.math.maxInt(u32)));
    try roundTrip(Gf256, params, &coeffs);
}

test "AdditiveFri: rejects tampered remainder" {
    const alloc = testing.allocator;
    const params = AdditiveFri(Gf256).Params{
        .log_size = 3,
        .log_blowup = 2,
        .log_remainder = 2,
        .num_queries = 8,
    };
    var coeffs = [_]Gf256{Gf256.zero()} ** 8;
    var r = prng(44);
    for (&coeffs) |*c| c.* = Gf256.fromInt(r.random().uintLessThan(u32, std.math.maxInt(u32)));

    var proof = try AdditiveFri(Gf256).prove(alloc, params, &coeffs, "seed");
    defer proof.deinit(alloc);

    proof.remainder[0] = proof.remainder[0].add(Gf256.one());
    try testing.expect(!try AdditiveFri(Gf256).verify(alloc, params, proof.layers[0].hash, proof, "seed"));
}

test "AdditiveFri: rejects tampered leaf" {
    const alloc = testing.allocator;
    const params = AdditiveFri(Gf256).Params{
        .log_size = 3,
        .log_blowup = 2,
        .log_remainder = 2,
        .num_queries = 8,
    };
    var coeffs = [_]Gf256{Gf256.zero()} ** 8;
    var r = prng(45);
    for (&coeffs) |*c| c.* = Gf256.fromInt(r.random().uintLessThan(u32, std.math.maxInt(u32)));

    var proof = try AdditiveFri(Gf256).prove(alloc, params, &coeffs, "seed");
    defer proof.deinit(alloc);

    // Flip a bit in the first opened layer-0 value: the Merkle path no longer matches.
    proof.queries[0].layers.proofs[0].value0 = proof.queries[0].layers.proofs[0].value0.add(Gf256.one());
    try testing.expect(!try AdditiveFri(Gf256).verify(alloc, params, proof.layers[0].hash, proof, "seed"));
}

test "AdditiveFri: rejects non-low-degree codeword" {
    const alloc = testing.allocator;
    const params = AdditiveFri(Gf256).Params{
        .log_size = 3,
        .log_blowup = 2,
        .log_remainder = 2,
        .num_queries = 12,
    };

    // A random function on the domain is far from any low-degree polynomial.
    const D = params.log_size + params.log_blowup;
    const codeword = try alloc.alloc(Gf256, @as(usize, 1) << @intCast(D));
    defer alloc.free(codeword);
    var r = prng(46);
    for (codeword) |*c| c.* = Gf256.fromInt(r.random().uintLessThan(u32, std.math.maxInt(u32)));

    const proof = try AdditiveFri(Gf256).proveCodeword(alloc, params, codeword, "seed");
    defer proof.deinit(alloc);

    try testing.expect(!try AdditiveFri(Gf256).verify(alloc, params, proof.layers[0].hash, proof, "seed"));
}
