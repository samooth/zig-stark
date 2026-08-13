const std = @import("std");
const PackedMle = @import("pack.zig").PackedMle;
const Polynomial = @import("polynomial.zig");
const CoreHash = @import("../core/hash/hash.zig");
const CoreMerkle = @import("../core/merkle/merkle.zig");

/// Sub-linear MLE evaluation over a tower field, Binius-V0 style.
///
/// The 2^k evaluation table is viewed as a 2^{k1} × 2^{k2} matrix
/// (k = k1 + k2, k2 ≤ BITS). Each row is *packed* into a univariate
/// polynomial row_i of degree < 2^{k2} with row_i(x_j) = M[i][j] for
/// x_j = fromInt(j) (`PackedMle.interpolate`). The rows are Reed-Solomon
/// extended over the additive domain {x_j : j < 2^{k2+log_blowup}} and the
/// matrix is committed as a Merkle tree over *columns*: leaf c hashes column
/// c (the extended entries of every row at position c).
///
/// Evaluation at r = (r_row, r_col): the row-combined polynomial
///
///     t(X) = Σ_{i < 2^{k1}} β_{r_row}(i)·row_i(X),   β_r(i) = ∏_j (bit_j(i) + 1 + r_j),
///
/// satisfies f(r) = Σ_{j < 2^{k2}} β_{r_col}(j)·t(x_j). The prover sends
/// t's 2^{k2} coefficients; the verifier
///   1. checks t against q sampled columns of the committed matrix
///      (t(x_c) == Σ_i β_{r_row}(i)·column_c[i]), and
///   2. computes f(r) = Σ_j β_{r_col}(j)·t(x_j) directly,
/// so verifier time and proof size are O(2^{k2}) + O(q·2^{k1}): sub-linear in
/// 2^k for k1 ≈ k2 ≈ k/2.
///
/// Soundness: a false row-combination δ(X) = t - Σ_i β_{r_row}(i)·row_i(X)
/// is a nonzero polynomial of degree < 2^{k2}, so it vanishes on a random
/// extended-domain column with probability ≤ 2^{k2}/2^{k2+log_blowup} =
/// 2^{-log_blowup} (Schwartz-Zippel / Reed-Solomon distance); q sampled
/// columns give soundness 2^{-log_blowup·q}. The committed columns pin the
/// rows exactly (Merkle), so an accepted t is (w.h.p.) the true combination
/// and the verifier's computed value is f(r) of the committed table.
pub fn PackedPcs(comptime F: type, comptime E: type) type {
    return struct {
        const Hash = CoreHash.Hash;
        const MerkleTree = CoreMerkle.MerkleTree;
        const MerkleVerify = CoreMerkle.verify;
        const Pack = PackedMle(F);

        pub const Params = struct {
            /// log2 of the number of rows.
            k1: u8,
            /// log2 of the row length (packed elements per row).
            k2: u8,
            /// log2 of the Reed-Solomon rate: extended domain size 2^{k2+log_blowup}.
            log_blowup: u8,
            /// number of columns opened by the verifier.
            num_queries: usize,

            pub fn k(self: Params) u8 {
                return self.k1 + self.k2;
            }
            pub fn d2(self: Params) u8 {
                return self.k2 + self.log_blowup;
            }
        };

        pub const Column = struct {
            index: usize,
            values: []F,
            path: []Hash.Digest,
        };

        pub const Proof = struct {
            value: E,
            t: []E,
            columns: []Column,

            /// Owns `t`, `columns`, and each column's `values`/`path`; release
            /// with `deinit(allocator)` using the allocator passed to `proveEval`.
            pub fn deinit(self: *Proof, allocator: std.mem.Allocator) void {
                allocator.free(self.t);
                for (self.columns) |c| {
                    allocator.free(c.values);
                    allocator.free(c.path);
                }
                allocator.free(self.columns);
            }
        };

        /// Embed a base-field element into the extension field (identity for E = F).
        fn lift(x: F) E {
            if (F == E) return x;
            return E.embed(F.LEVEL, x);
        }

        /// Lagrange kernel β_r(i) = ∏_j (bit_j(i) + 1 + r_j) over E.
        fn kernel(dim: u8, r: []const E, i: usize) E {
            var acc = E.one();
            for (0..dim) |j| {
                const bit: u8 = @intFromBool((i >> @intCast(j)) & 1 == 1);
                acc = acc.mul(E.fromInt(bit).add(E.one().add(r[j])));
            }
            return acc;
        }

        fn evalF(coeffs: []const F, x: F) F {
            var acc = F.zero();
            var i: usize = coeffs.len;
            while (i > 0) {
                i -= 1;
                acc = acc.mul(x).add(coeffs[i]);
            }
            return acc;
        }

        fn evalE(coeffs: []const E, x: E) E {
            var acc = E.zero();
            var i: usize = coeffs.len;
            while (i > 0) {
                i -= 1;
                acc = acc.mul(x).add(coeffs[i]);
            }
            return acc;
        }

        fn hashElement(v: F) Hash.Digest {
            var b: [F.SIZE]u8 = undefined;
            v.toBytes(&b);
            return Hash.hashBytes(&b);
        }

        fn hashColumn(col: []const F) Hash.Digest {
            var acc = Hash.hashBytes("zig-stark:column");
            for (col) |v| {
                acc = Hash.hash2(acc, hashElement(v));
            }
            return acc;
        }

        const Transcript = struct {
            buf: Hash.Digest,

            fn init(seed: Hash.Digest) Transcript {
                return .{ .buf = seed };
            }

            fn sampleIndex(self: *Transcript, bound: usize) usize {
                self.buf = Hash.hashBytes(&self.buf);
                const v = if (E.SIZE == 1)
                    E.fromInt(self.buf[31])
                else
                    E.fromBytes((self.buf[32 - E.SIZE ..][0..E.SIZE]).*);
                return @as(usize, @intCast(v.value & (bound - 1)));
            }

            fn absorb(self: *Transcript, bytes: []const u8) void {
                self.buf = Hash.hash2(self.buf, Hash.hashBytes(bytes));
            }

            fn absorbElem(self: *Transcript, v: E) void {
                var b: [E.SIZE]u8 = undefined;
                v.toBytes(&b);
                self.absorb(&b);
            }
        };

        /// Pack every row into a univariate polynomial (degree < 2^{k2}).
        fn buildRows(allocator: std.mem.Allocator, params: Params, table: []const F) ![][]F {
            const n1: usize = @as(usize, 1) << @intCast(params.k1);
            const n2: usize = @as(usize, 1) << @intCast(params.k2);
            std.debug.assert(table.len == n1 * n2);
            const rows = try allocator.alloc([]F, n1);
            errdefer {
                for (rows) |rw| allocator.free(rw);
                allocator.free(rows);
            }
            for (0..n1) |i| {
                rows[i] = try Pack.interpolate(allocator, params.k2, table[i * n2 ..][0..n2]);
            }
            return rows;
        }

        /// RS-extension of every row over the additive domain {fromInt(j)}.
        fn buildCodewords(allocator: std.mem.Allocator, params: Params, rows: []const []F) ![][]F {
            const n1: usize = @as(usize, 1) << @intCast(params.k1);
            const d2n: usize = @as(usize, 1) << @intCast(params.d2());
            const cw = try allocator.alloc([]F, n1);
            errdefer {
                for (cw) |c| allocator.free(c);
                allocator.free(cw);
            }
            for (0..n1) |i| {
                const c = try allocator.alloc(F, d2n);
                for (0..d2n) |j| c[j] = evalF(rows[i], F.fromInt(j));
                cw[i] = c;
            }
            return cw;
        }

        fn freeRows(allocator: std.mem.Allocator, rows: [][]F) void {
            for (rows) |rw| allocator.free(rw);
            allocator.free(rows);
        }

        fn freeCodewords(allocator: std.mem.Allocator, cw: [][]F) void {
            for (cw) |c| allocator.free(c);
            allocator.free(cw);
        }

        fn commitCodewords(allocator: std.mem.Allocator, params: Params, cw: []const []F) !MerkleTree {
            const n1: usize = @as(usize, 1) << @intCast(params.k1);
            const d2n: usize = @as(usize, 1) << @intCast(params.d2());
            const leaves = try allocator.alloc(Hash.Digest, d2n);
            defer allocator.free(leaves);
            const col = try allocator.alloc(F, n1);
            defer allocator.free(col);
            for (0..d2n) |c| {
                for (0..n1) |i| col[i] = cw[i][c];
                leaves[c] = hashColumn(col);
            }
            return MerkleTree.init(allocator, leaves);
        }

        /// Commit a 2^k table: a Merkle tree over the columns of the packed,
        /// RS-extended matrix.
        pub fn commit(allocator: std.mem.Allocator, params: Params, table: []const F) !MerkleTree {
            const rows = try buildRows(allocator, params, table);
            defer freeRows(allocator, rows);
            const cw = try buildCodewords(allocator, params, rows);
            defer freeCodewords(allocator, cw);
            return commitCodewords(allocator, params, cw);
        }

        /// The commitment root of a table (for callers that keep only the digest).
        pub fn rootOf(allocator: std.mem.Allocator, params: Params, table: []const F) !Hash.Digest {
            var tree = try commit(allocator, params, table);
            defer tree.deinit();
            return tree.root();
        }

        fn sampleDistinct(
            transcript: *Transcript,
            allocator: std.mem.Allocator,
            d2n: usize,
            num: usize,
        ) ![]usize {
            if (num > d2n) return error.TooManyQueries;
            const out = try allocator.alloc(usize, num);
            errdefer allocator.free(out);
            var chosen = std.AutoHashMap(usize, void).init(allocator);
            defer chosen.deinit();
            var got: usize = 0;
            while (got < num) {
                const c = transcript.sampleIndex(d2n);
                const gop = try chosen.getOrPut(c);
                if (gop.found_existing) continue;
                out[got] = c;
                got += 1;
            }
            return out;
        }

        /// Prover: combine the rows at r, open q sampled columns, and return
        /// the evaluation value f(r) together with the row-combination t.
        pub fn proveEval(
            allocator: std.mem.Allocator,
            params: Params,
            table: []const F,
            r: []const E,
        ) !Proof {
            const k = params.k();
            std.debug.assert(r.len == k);
            const n1: usize = @as(usize, 1) << @intCast(params.k1);
            const n2: usize = @as(usize, 1) << @intCast(params.k2);
            const d2n: usize = @as(usize, 1) << @intCast(params.d2());
            const r_col = r[0..params.k2];
            const r_row = r[params.k2..];

            const rows = try buildRows(allocator, params, table);
            defer freeRows(allocator, rows);
            const cw = try buildCodewords(allocator, params, rows);
            defer freeCodewords(allocator, cw);

            // t(X) = Σ_i β_{r_row}(i)·row_i(X), coefficients in E.
            const t = try allocator.alloc(E, n2);
            errdefer allocator.free(t);
            @memset(t, E.zero());
            for (0..n1) |i| {
                const b = kernel(params.k1, r_row, i);
                for (0..n2) |j| t[j] = t[j].add(b.mul(lift(rows[i][j])));
            }

            // f(r) = Σ_j β_{r_col}(j)·t(x_j).
            var value = E.zero();
            for (0..n2) |j| {
                const beta = kernel(params.k2, r_col, j);
                value = value.add(beta.mul(evalE(t, lift(F.fromInt(j)))));
            }

            var tree = try commitCodewords(allocator, params, cw);
            defer tree.deinit();

            var ts = Transcript.init(tree.root());
            for (r) |v| ts.absorbElem(v);
            ts.absorbElem(value);
            for (t) |v| ts.absorbElem(v);
            const idxs = try sampleDistinct(&ts, allocator, d2n, params.num_queries);
            defer allocator.free(idxs);

            const columns = try allocator.alloc(Column, params.num_queries);
            errdefer allocator.free(columns);
            var built: usize = 0;
            errdefer {
                for (columns[0..built]) |c| {
                    allocator.free(c.values);
                    allocator.free(c.path);
                }
            }
            const scratch = try allocator.alloc(F, n1);
            defer allocator.free(scratch);
            for (0..params.num_queries) |qi| {
                const c = idxs[qi];
                for (0..n1) |i| scratch[i] = cw[i][c];
                const values = try allocator.dupe(F, scratch);
                const path = try tree.open(c, allocator);
                columns[qi] = .{ .index = c, .values = values, .path = path };
                built = qi + 1;
            }

            return Proof{ .value = value, .t = t, .columns = columns };
        }

        /// Verifier: given the column commitment root and an eval claim at r,
        /// check t on the sampled columns and recompute f(r).
        pub fn verifyEval(
            allocator: std.mem.Allocator,
            params: Params,
            root: Hash.Digest,
            r: []const E,
            proof: Proof,
        ) !bool {
            const k = params.k();
            if (r.len != k) return false;
            const n1: usize = @as(usize, 1) << @intCast(params.k1);
            const n2: usize = @as(usize, 1) << @intCast(params.k2);
            const d2n: usize = @as(usize, 1) << @intCast(params.d2());
            if (proof.t.len != n2) return false;
            if (proof.columns.len != params.num_queries) return false;
            const r_col = r[0..params.k2];
            const r_row = r[params.k2..];

            // Replay the transcript to recover the sampled columns.
            var ts = Transcript.init(root);
            for (r) |v| ts.absorbElem(v);
            ts.absorbElem(proof.value);
            for (proof.t) |v| ts.absorbElem(v);
            const idxs = try sampleDistinct(&ts, allocator, d2n, params.num_queries);
            defer allocator.free(idxs);

            for (proof.columns, idxs) |col, expected| {
                if (col.index != expected) return false;
                if (col.values.len != n1) return false;
                if (!MerkleVerify(root, col.index, hashColumn(col.values), col.path)) return false;

                // t(x_c) must equal the β_{r_row}-combination of column c.
                var combo = E.zero();
                for (0..n1) |i| {
                    combo = combo.add(kernel(params.k1, r_row, i).mul(lift(col.values[i])));
                }
                if (!combo.eq(evalE(proof.t, lift(F.fromInt(col.index))))) return false;
            }

            // f(r) = Σ_j β_{r_col}(j)·t(x_j).
            var value = E.zero();
            for (0..n2) |j| {
                const beta = kernel(params.k2, r_col, j);
                value = value.add(beta.mul(evalE(proof.t, lift(F.fromInt(j)))));
            }
            return proof.value.eq(value);
        }
    };
}

/// Packing configuration for the STARK adapter. The row length `k2` and the
/// Reed-Solomon rate are capped by the base field: the extended domain has
/// `2^(k2 + log_blowup)` points and must sit inside the field, so
/// `k2 + log_blowup <= F.BITS` (the element bit-width, e.g. 4 for Gf16).
pub const StarkPackedConfig = struct {
    /// log2 of the row length (packed elements per row).
    k2: u8,
    /// log2 of the RS rate.
    log_blowup: u8,
    /// number of columns the verifier samples.
    num_queries: usize,
};

/// Adapter exposing `PackedPcs` behind the same interface the zero-check STARK
/// expects of `CommittedMlePcs`: `commit(allocator, table)`,
/// `proveEval(allocator, k, table, r)` and `verifyEval(allocator, root, k, r,
/// proof)`, with the packing params derived from `k` and the comptime `config`.
/// This makes `PackedPcs` a drop-in alternative opening mode for `BiniusStark`
/// (`BiniusStarkWith`), so proofs stay sub-linear instead of opening all 2^k
/// entries.
pub fn PackedPcsStark(comptime F: type, comptime E: type, comptime config: StarkPackedConfig) type {
    return struct {
        const P = PackedPcs(F, E);
        const Hash = CoreHash.Hash;
        const MerkleTree = CoreMerkle.MerkleTree;

        pub const Proof = P.Proof;

        fn params(k: usize) P.Params {
            std.debug.assert(config.k2 <= k);
            std.debug.assert(config.k2 + config.log_blowup <= F.BITS);
            return .{
                .k1 = @intCast(k - config.k2),
                .k2 = config.k2,
                .log_blowup = config.log_blowup,
                .num_queries = config.num_queries,
            };
        }

        pub fn commit(allocator: std.mem.Allocator, table: []const F) !MerkleTree {
            const k = std.math.log2_int(usize, table.len);
            return P.commit(allocator, params(k), table);
        }

        pub fn proveEval(allocator: std.mem.Allocator, k: usize, table: []const F, r: []const E) !Proof {
            return P.proveEval(allocator, params(k), table, r);
        }

        pub fn verifyEval(allocator: std.mem.Allocator, root: Hash.Digest, k: usize, r: []const E, proof: Proof) !bool {
            return P.verifyEval(allocator, params(k), root, r, proof);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Tower = @import("tower.zig");
const Gf16 = Tower.Gf16;
const Gf256 = Tower.Gf256;
const Gf2_128 = Tower.TowerField(7);

fn prng(seed: u64) std.Random.DefaultPrng {
    return std.Random.DefaultPrng.init(seed);
}

fn randomTable(allocator: std.mem.Allocator, comptime F: type, n: usize, seed: u64) ![]F {
    const t = try allocator.alloc(F, n);
    var r = prng(seed);
    for (t) |*v| v.* = F.fromInt(r.random().uintLessThan(u32, std.math.maxInt(u32)));
    return t;
}

fn randomPoint(allocator: std.mem.Allocator, comptime E: type, k: usize, seed: u64) ![]E {
    const p = try allocator.alloc(E, k);
    var r = prng(seed);
    for (p) |*v| v.* = E.fromInt(r.random().uintLessThan(u32, std.math.maxInt(u32)));
    return p;
}

fn roundTrip(comptime F: type, comptime E: type, params: PackedPcs(F, E).Params, seed: u64) !void {
    const alloc = std.testing.allocator;

    const n: usize = @as(usize, 1) << @intCast(params.k());
    const table = try randomTable(alloc, F, n, seed);
    defer alloc.free(table);
    const r = try randomPoint(alloc, E, params.k(), seed + 1);
    defer alloc.free(r);

    const root = try PackedPcs(F, E).rootOf(alloc, params, table);
    var proof = try PackedPcs(F, E).proveEval(alloc, params, table, r);
    defer proof.deinit(alloc);
    try std.testing.expect(try PackedPcs(F, E).verifyEval(alloc, params, root, r, proof));

    // The packed eval equals the direct multilinear evaluation of the table.
    const lifted = try alloc.alloc(E, n);
    defer alloc.free(lifted);
    for (table, 0..) |v, i| lifted[i] = if (F == E) v else E.embed(F.LEVEL, v);
    const direct = try (Polynomial.Multilinear(E){ .evals = lifted }).eval(alloc, r);
    try std.testing.expectEqual(proof.value.value, direct.value);
}

test "packed pcs round trips over Gf16" {
    const params = PackedPcs(Gf16, Gf16).Params{
        .k1 = 2,
        .k2 = 2,
        .log_blowup = 1,
        .num_queries = 6,
    };
    try roundTrip(Gf16, Gf16, params, 101);
}

test "packed pcs round trips over Gf256 with k1 != k2" {
    const params = PackedPcs(Gf256, Gf256).Params{
        .k1 = 3,
        .k2 = 3,
        .log_blowup = 2,
        .num_queries = 6,
    };
    try roundTrip(Gf256, Gf256, params, 202);
}

test "packed pcs round trips in the extension field (F=Gf16, E=Gf2^128)" {
    const params = PackedPcs(Gf16, Gf2_128).Params{
        .k1 = 2,
        .k2 = 2,
        .log_blowup = 1,
        .num_queries = 6,
    };
    try roundTrip(Gf16, Gf2_128, params, 303);
}

test "packed pcs rejects tampered row combination t" {
    const alloc = std.testing.allocator;
    const params = PackedPcs(Gf16, Gf16).Params{
        .k1 = 2,
        .k2 = 2,
        .log_blowup = 1,
        .num_queries = 8,
    };
    const n: usize = @as(usize, 1) << @intCast(params.k());
    const table = try randomTable(alloc, Gf16, n, 11);
    defer alloc.free(table);
    const r = try randomPoint(alloc, Gf16, params.k(), 12);
    defer alloc.free(r);

    const root = try PackedPcs(Gf16, Gf16).rootOf(alloc, params, table);
    var proof = try PackedPcs(Gf16, Gf16).proveEval(alloc, params, table, r);
    defer proof.deinit(alloc);

    // Flip a coefficient of the row-combination: column checks must fail.
    proof.t[0] = proof.t[0].add(Gf16.one());
    try std.testing.expect(!try PackedPcs(Gf16, Gf16).verifyEval(alloc, params, root, r, proof));
}

test "packed pcs rejects wrong claimed value" {
    const alloc = std.testing.allocator;
    const params = PackedPcs(Gf16, Gf16).Params{
        .k1 = 2,
        .k2 = 2,
        .log_blowup = 1,
        .num_queries = 8,
    };
    const n: usize = @as(usize, 1) << @intCast(params.k());
    const table = try randomTable(alloc, Gf16, n, 21);
    defer alloc.free(table);
    const r = try randomPoint(alloc, Gf16, params.k(), 22);
    defer alloc.free(r);

    const root = try PackedPcs(Gf16, Gf16).rootOf(alloc, params, table);
    var proof = try PackedPcs(Gf16, Gf16).proveEval(alloc, params, table, r);
    defer proof.deinit(alloc);

    proof.value = proof.value.add(Gf16.one());
    try std.testing.expect(!try PackedPcs(Gf16, Gf16).verifyEval(alloc, params, root, r, proof));
}

test "packed pcs rejects tampered opened column value" {
    const alloc = std.testing.allocator;
    const params = PackedPcs(Gf16, Gf16).Params{
        .k1 = 2,
        .k2 = 2,
        .log_blowup = 1,
        .num_queries = 8,
    };
    const n: usize = @as(usize, 1) << @intCast(params.k());
    const table = try randomTable(alloc, Gf16, n, 31);
    defer alloc.free(table);
    const r = try randomPoint(alloc, Gf16, params.k(), 32);
    defer alloc.free(r);

    const root = try PackedPcs(Gf16, Gf16).rootOf(alloc, params, table);
    var proof = try PackedPcs(Gf16, Gf16).proveEval(alloc, params, table, r);
    defer proof.deinit(alloc);

    proof.columns[0].values[0] = proof.columns[0].values[0].add(Gf16.one());
    try std.testing.expect(!try PackedPcs(Gf16, Gf16).verifyEval(alloc, params, root, r, proof));
}

test "packed pcs rejects wrong commitment root" {
    const alloc = std.testing.allocator;
    const params = PackedPcs(Gf16, Gf16).Params{
        .k1 = 2,
        .k2 = 2,
        .log_blowup = 1,
        .num_queries = 8,
    };
    const n: usize = @as(usize, 1) << @intCast(params.k());
    const table = try randomTable(alloc, Gf16, n, 41);
    defer alloc.free(table);
    const r = try randomPoint(alloc, Gf16, params.k(), 42);
    defer alloc.free(r);

    const other = try randomTable(alloc, Gf16, n, 43);
    defer alloc.free(other);
    other[0] = other[0].add(Gf16.one());
    const wrong_root = try PackedPcs(Gf16, Gf16).rootOf(alloc, params, other);

    var proof = try PackedPcs(Gf16, Gf16).proveEval(alloc, params, table, r);
    defer proof.deinit(alloc);
    try std.testing.expect(!try PackedPcs(Gf16, Gf16).verifyEval(alloc, params, wrong_root, r, proof));
}
