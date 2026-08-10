const std = @import("std");
const Polynomial = @import("polynomial.zig");

/// Sum-check protocol over a binary field `F` for the claim
///
///     H = Σ_{x ∈ {0,1}^k} g(x),    g(x) = ∏_{j=1}^m f_j(x),
///
/// where each `f_j` is a multilinear polynomial supplied as its 2^k hypercube
/// evaluation table. The Fiat-Shamir transcript uses SHA256 and a per-round
/// challenge `r_i` taken as the last byte of the digest masked to the field's
/// bit width (4 bits for GF(16), mirroring the Bitcoin Script verifier), so a
/// proof produced here can be re-checked on-chain.
///
/// Convention: round i folds the *lowest* remaining variable (adjacent table
/// pairs `(2j, 2j+1)`), which is exactly the ordering used by
/// `Multilinear.eval`, so the verifier's final MLE-product check reuses it.
pub fn Sumcheck(comptime F: type) type {
    return struct {
        const Self = @This();
        const Sha256 = std.crypto.hash.sha2.Sha256;
        const Multilinear = Polynomial.Multilinear(F);

        pub const Proof = struct {
            claimed_sum: F,
            /// rounds[i] = m+1 low-first coefficients of the univariate
            /// polynomial s_i(t) = Σ_{rest} ∏_j f_j^(i)(rest, t).
            rounds: []const []const F,

            pub fn deinit(self: *Proof, allocator: std.mem.Allocator) void {
                for (self.rounds) |coeffs| allocator.free(coeffs);
                allocator.free(self.rounds);
            }
        };

        /// One monomial c·∏_{j∈indices} tables[j] of a linear combination;
        /// `indices` may repeat a table to encode powers.
        pub const Term = struct {
            coeff: F,
            indices: []const usize,
        };

        /// Fiat-Shamir transcript (SHA256, challenge = last byte of digest masked
        /// to the field's bit width).
        pub const Transcript = struct {
            buf: [32]u8,

            pub fn init(claimed: F) Transcript {
                var b: [F.SIZE]u8 = undefined;
                claimed.toBytes(&b);
                var t = Transcript{ .buf = undefined };
                Sha256.hash(&b, &t.buf, .{});
                return t;
            }

            /// Seed the transcript from arbitrary bytes (used by the multilinear
            /// PCS to bind a Merkle root before deriving challenges).
            pub fn initBytes(seed: []const u8) Transcript {
                var t = Transcript{ .buf = undefined };
                Sha256.hash(seed, &t.buf, .{});
                return t;
            }

            pub fn absorb(self: *Transcript, coeffs: []const F) F {
                var hasher = Sha256.init(.{});
                hasher.update(&self.buf);
                var b: [F.SIZE]u8 = undefined;
                for (coeffs) |c| {
                    c.toBytes(&b);
                    hasher.update(&b);
                }
                hasher.final(&self.buf);
                if (F.SIZE == 1) {
                    // fromInt masks to the field's bit width (4 bits for GF(16),
                    // 8 bits for GF(256)), so the challenge uses the full space.
                    return F.fromInt(self.buf[31]);
                }
                var out: [F.SIZE]u8 = undefined;
                @memcpy(&out, self.buf[32 - F.SIZE ..][0..F.SIZE]);
                return F.fromBytes(out);
            }
        };

        /// Result of running the round-consistency checks: the recomputed
        /// per-round challenges and the final running sum (the claimed MLE
        /// product value at the challenge point).
        pub const RoundResult = struct {
            challenges: []F,
            current_sum: F,
        };

        /// Replay the round checks `s_i(0) + s_i(1) == sum_i` and derive the
        /// challenges. Returns null if any round check fails. The caller must
        /// free `challenges`.
        pub fn runRounds(
            allocator: std.mem.Allocator,
            seed: ?[]const u8,
            claimed: F,
            rounds: []const []const F,
        ) !?RoundResult {
            var transcript = if (seed) |s| Transcript.initBytes(s) else Transcript.init(claimed);
            const challenges = try allocator.alloc(F, rounds.len);
            errdefer allocator.free(challenges);
            var current_sum = claimed;
            for (rounds, 0..) |coeffs, i| {
                const s0 = evalPoly(coeffs, F.zero());
                const s1 = evalPoly(coeffs, F.one());
                if (!s0.add(s1).eq(current_sum)) return null;
                const r_i = transcript.absorb(coeffs);
                challenges[i] = r_i;
                current_sum = evalPoly(coeffs, r_i);
            }
            return .{ .challenges = challenges, .current_sum = current_sum };
        }

        /// Lagrange interpolation of a univariate polynomial (degree < n) from
        /// n distinct points; returns low-first coefficients. Characteristic-2
        /// aware: (t - x_j) becomes (t + x_j).
        pub fn interpolateCoeffs(
            allocator: std.mem.Allocator,
            points: []const F,
            values: []const F,
        ) ![]F {
            std.debug.assert(points.len == values.len);
            const n = points.len;
            std.debug.assert(n <= 64);

            const coeffs = try allocator.alloc(F, n);
            errdefer allocator.free(coeffs);
            @memset(coeffs, F.zero());

            var basis: [64]F = undefined;
            for (0..n) |i| {
                basis[0] = F.one();
                var deg: usize = 1;
                var denom = F.one();
                for (0..n) |j| {
                    if (j == i) continue;
                    // basis *= (t + points[j]) using a scratch copy.
                    var next: [64]F = undefined;
                    for (0..deg + 1) |d| {
                        const lo = if (d == 0) F.zero() else basis[d - 1];
                        const hi = if (d == deg) F.zero() else basis[d];
                        next[d] = lo.add(points[j].mul(hi));
                    }
                    @memcpy(basis[0 .. deg + 1], next[0 .. deg + 1]);
                    denom = denom.mul(points[i].add(points[j]));
                    deg += 1;
                }
                const scale = denom.inv().mul(values[i]);
                for (0..deg) |d| {
                    coeffs[d] = coeffs[d].add(basis[d].mul(scale));
                }
            }
            return coeffs;
        }

        /// Horner evaluation of a low-first coefficient array.
        pub fn evalPoly(coeffs: []const F, x: F) F {
            var acc = F.zero();
            var i = coeffs.len;
            while (i > 0) {
                i -= 1;
                acc = acc.mul(x).add(coeffs[i]);
            }
            return acc;
        }

        /// Hypercube sum of the product of the tables (the claimed value H).
        pub fn computeClaimedSum(n: usize, tables: []const []const F) F {
            var h = F.zero();
            for (0..n) |idx| {
                var prod = F.one();
                for (tables) |t| prod = prod.mul(t[idx]);
                h = h.add(prod);
            }
            return h;
        }

        /// Hypercube sum of a linear combination of table products:
        /// Σ_x Σ_t term_t.coeff · ∏_{j∈term_t.indices} tables[j][x].
        pub fn computeCombinationSum(n: usize, tables: []const []const F, terms: []const Term) F {
            var h = F.zero();
            for (0..n) |idx| {
                for (terms) |tm| {
                    var prod = tm.coeff;
                    for (tm.indices) |ti| prod = prod.mul(tables[ti][idx]);
                    h = h.add(prod);
                }
            }
            return h;
        }

        /// Prover for a sum-check over a linear combination of table products,
        ///
        ///     g(x) = Σ_t coeff_t · ∏_{j∈indices_t} tables[j](x),
        ///
        /// with each round interpolated at d+1 points, where
        /// d = max_t |indices_t| is the per-variable degree bound (every table
        /// is multilinear, so a product of d tables has degree ≤ d in each
        /// variable). This is the batching primitive behind the Binius
        /// zero-check: many constraints combine into a single k-round protocol.
        pub fn proveCombination(
            allocator: std.mem.Allocator,
            k: usize,
            tables: []const []const F,
            terms: []const Term,
            seed: ?[]const u8,
        ) !Proof {
            const n = @as(usize, 1) << @intCast(k);
            for (tables) |t| std.debug.assert(t.len == n);
            var dmax: usize = 0;
            for (terms) |tm| dmax = @max(dmax, tm.indices.len);
            std.debug.assert(dmax + 1 <= 64);

            const h = computeCombinationSum(n, tables, terms);
            var transcript = if (seed) |s| Transcript.initBytes(s) else Transcript.init(h);

            const m = tables.len;
            var cur = try allocator.alloc([]F, m);
            defer allocator.free(cur);
            for (0..m) |j| {
                cur[j] = try allocator.dupe(F, tables[j]);
            }
            defer {
                for (cur) |ct| allocator.free(ct);
            }

            const rounds = try allocator.alloc([]F, k);
            errdefer allocator.free(rounds);

            var len = n;
            var i: usize = 0;
            while (i < k) : (i += 1) {
                const half = len / 2;

                // Evaluate s_i at the d+1 points t = 0..d, then interpolate.
                const points = try allocator.alloc(F, dmax + 1);
                defer allocator.free(points);
                const values = try allocator.alloc(F, dmax + 1);
                defer allocator.free(values);
                for (0..dmax + 1) |t| {
                    points[t] = F.fromInt(t);
                    var s = F.zero();
                    for (0..half) |rest| {
                        for (terms) |tm| {
                            var prod = tm.coeff;
                            for (tm.indices) |ti| {
                                const a = cur[ti][2 * rest];
                                const b = cur[ti][2 * rest + 1];
                                prod = prod.mul(a.add(points[t].mul(a.add(b))));
                            }
                            s = s.add(prod);
                        }
                    }
                    values[t] = s;
                }

                const coeffs = try interpolateCoeffs(allocator, points, values);
                rounds[i] = coeffs;

                const r_i = transcript.absorb(coeffs);
                for (cur) |ct| {
                    for (0..half) |rest| {
                        const a = ct[2 * rest];
                        const b = ct[2 * rest + 1];
                        ct[rest] = a.add(r_i.mul(a.add(b)));
                    }
                }
                len = half;
            }

            return .{ .claimed_sum = h, .rounds = rounds };
        }

        /// Off-chain prover. `tables` has m tables of length 2^k.
        pub fn prove(
            allocator: std.mem.Allocator,
            k: usize,
            tables: []const []const F,
        ) !Proof {
            return proveSeeded(allocator, k, tables, null);
        }

        /// Prover with an optional transcript seed (the PCS binds a Merkle root
        /// before the challenges are derived).
        pub fn proveSeeded(
            allocator: std.mem.Allocator,
            k: usize,
            tables: []const []const F,
            seed: ?[]const u8,
        ) !Proof {
            const m = tables.len;
            const n = @as(usize, 1) << @intCast(k);
            for (tables) |t| std.debug.assert(t.len == n);
            std.debug.assert(m + 1 <= 64);

            const h = computeClaimedSum(n, tables);
            var transcript = if (seed) |s| Transcript.initBytes(s) else Transcript.init(h);

            var cur = try allocator.alloc([]F, m);
            defer allocator.free(cur);
            for (0..m) |j| {
                cur[j] = try allocator.dupe(F, tables[j]);
            }
            defer {
                for (cur) |ct| allocator.free(ct);
            }

            const rounds = try allocator.alloc([]F, k);
            errdefer allocator.free(rounds);

            var len = n;
            var i: usize = 0;
            while (i < k) : (i += 1) {
                const half = len / 2;

                // Evaluate s_i at the m+1 points t = 0..m, then interpolate.
                const points = try allocator.alloc(F, m + 1);
                defer allocator.free(points);
                const values = try allocator.alloc(F, m + 1);
                defer allocator.free(values);
                for (0..m + 1) |t| {
                    points[t] = F.fromInt(t);
                    var s = F.zero();
                    for (0..half) |rest| {
                        var prod = F.one();
                        for (cur) |ct| {
                            const a = ct[2 * rest];
                            const b = ct[2 * rest + 1];
                            prod = prod.mul(a.add(points[t].mul(a.add(b))));
                        }
                        s = s.add(prod);
                    }
                    values[t] = s;
                }

                const coeffs = try interpolateCoeffs(allocator, points, values);
                rounds[i] = coeffs;

                const r_i = transcript.absorb(coeffs);
                for (cur) |ct| {
                    for (0..half) |rest| {
                        const a = ct[2 * rest];
                        const b = ct[2 * rest + 1];
                        ct[rest] = a.add(r_i.mul(a.add(b)));
                    }
                }
                len = half;
            }

            return .{ .claimed_sum = h, .rounds = rounds };
        }

        /// Verifier: checks the round consistency equations, recomputes the
        /// challenges from the transcript, and checks the final MLE equality.
        pub fn verify(
            allocator: std.mem.Allocator,
            k: usize,
            tables: []const []const F,
            proof: Proof,
        ) !bool {
            return verifySeeded(allocator, k, tables, proof, null);
        }

        /// Verifier with an optional transcript seed, matching `proveSeeded`.
        pub fn verifySeeded(
            allocator: std.mem.Allocator,
            k: usize,
            tables: []const []const F,
            proof: Proof,
            seed: ?[]const u8,
        ) !bool {
            const m = tables.len;
            const n = @as(usize, 1) << @intCast(k);
            for (tables) |t| std.debug.assert(t.len == n);
            if (proof.rounds.len != k) return false;
            for (proof.rounds) |coeffs| {
                if (coeffs.len != m + 1) return false;
            }

            const rr = (try runRounds(allocator, seed, proof.claimed_sum, proof.rounds)) orelse return false;
            defer allocator.free(rr.challenges);

            var prod = F.one();
            for (tables) |table| {
                const p = Multilinear{ .evals = table };
                const ev = try p.eval(allocator, rr.challenges);
                prod = prod.mul(ev);
            }
            return prod.eq(rr.current_sum);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Gf16 = @import("field.zig").Gf16;
const T = Sumcheck(Gf16);

fn fe(x: u128) Gf16 {
    return Gf16.fromInt(x);
}

test "interpolate recovers linear polynomial" {
    const alloc = std.testing.allocator;
    // s(t) = 3 + 5t over GF(16)
    const points = [_]Gf16{ fe(0), fe(1) };
    const values = [_]Gf16{ fe(3), fe(3).add(fe(5)) };
    const coeffs = try T.interpolateCoeffs(alloc, &points, &values);
    defer alloc.free(coeffs);
    try std.testing.expectEqual(@as(u128, 3), coeffs[0].value);
    try std.testing.expectEqual(@as(u128, 5), coeffs[1].value);
    // matches at a third point t = 7
    const ref = fe(3).add(fe(5).mul(fe(7)));
    try std.testing.expectEqual(ref.value, T.evalPoly(coeffs, fe(7)).value);
}

test "interpolate recovers quadratic polynomial" {
    const alloc = std.testing.allocator;
    // s(t) = 2 + 3t + 4t^2 over GF(16); note 4*4 = x^4 ≡ x + 1 = 3.
    const points = [_]Gf16{ fe(0), fe(1), fe(2) };
    const values = [_]Gf16{ fe(2), fe(2).add(fe(3)).add(fe(4)), fe(2).add(fe(6)).add(fe(3)) };
    const coeffs = try T.interpolateCoeffs(alloc, &points, &values);
    defer alloc.free(coeffs);
    try std.testing.expectEqual(@as(u128, 2), coeffs[0].value);
    try std.testing.expectEqual(@as(u128, 3), coeffs[1].value);
    try std.testing.expectEqual(@as(u128, 4), coeffs[2].value);
}

test "prove/verify round trip, k=1 m=1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const tables = [_][]const Gf16{&.{ fe(3), fe(7) }};
    const proof = try T.prove(alloc, 1, &tables);
    try std.testing.expect(proof.claimed_sum.eq(fe(3).add(fe(7))));
    try std.testing.expect(try T.verify(alloc, 1, &tables, proof));
}

test "prove/verify round trip, product of two multilinears k=2" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const t0 = [_]Gf16{ fe(1), fe(2), fe(3), fe(4) };
    const t1 = [_]Gf16{ fe(5), fe(6), fe(7), fe(8) };
    const tables = [_][]const Gf16{ &t0, &t1 };
    const proof = try T.prove(alloc, 2, &tables);
    try std.testing.expect(try T.verify(alloc, 2, &tables, proof));
}

test "prove/verify round trip, k=3 m=1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const t0 = [_]Gf16{ fe(5), fe(2), fe(9), fe(1), fe(3), fe(7), fe(4), fe(6) };
    const tables = [_][]const Gf16{&t0};
    const proof = try T.prove(alloc, 3, &tables);
    try std.testing.expect(try T.verify(alloc, 3, &tables, proof));
}

test "tampered claimed sum fails verification" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const t0 = [_]Gf16{ fe(1), fe(2), fe(3), fe(4) };
    const t1 = [_]Gf16{ fe(5), fe(6), fe(7), fe(8) };
    const tables = [_][]const Gf16{ &t0, &t1 };
    const proof = try T.prove(alloc, 2, &tables);
    const bad = T.Proof{ .claimed_sum = proof.claimed_sum.add(fe(1)), .rounds = proof.rounds };
    try std.testing.expect(!try T.verify(alloc, 2, &tables, bad));
}

test "claimed sum equals direct hypercube product sum" {
    const t0 = [_]Gf16{ fe(5), fe(2), fe(9), fe(1), fe(3), fe(7), fe(4), fe(6) };
    const t1 = [_]Gf16{ fe(0), fe(0), fe(0), fe(0), fe(0), fe(0), fe(0), fe(0) };
    const tables = [_][]const Gf16{ &t0, &t1 };
    try std.testing.expectEqual(@as(u128, 0), T.computeClaimedSum(8, &tables).value);
}

test "combination sum-check round trips" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();
    const t0 = [_]Gf16{ fe(1), fe(2), fe(3), fe(4) };
    const t1 = [_]Gf16{ fe(5), fe(6), fe(7), fe(8) };
    const t2 = [_]Gf16{ fe(3), fe(1), fe(9), fe(2) };
    const tables = [_][]const Gf16{ &t0, &t1, &t2 };

    // g(x) = 2·t0(x)·t2(x) + 3·t1(x)
    const terms = [_]T.Term{
        .{ .coeff = fe(2), .indices = &.{ 0, 2 } },
        .{ .coeff = fe(3), .indices = &.{1} },
    };

    const sp = try T.proveCombination(alloc, 2, &tables, &terms, null);
    const rr = (try T.runRounds(alloc, null, sp.claimed_sum, sp.rounds)) orelse return error.TestUnexpectedResult;
    defer alloc.free(rr.challenges);

    // claimed sum equals the direct hypercube combination sum
    var direct = Gf16.zero();
    for (0..4) |i| {
        direct = direct.add(fe(2).mul(t0[i].mul(t2[i]))).add(fe(3).mul(t1[i]));
    }
    try std.testing.expect(direct.eq(sp.claimed_sum));

    // final round value equals g at the challenge point
    const Multilinear = @import("polynomial.zig").Multilinear(Gf16);
    const p0 = Multilinear{ .evals = &t0 };
    const p1 = Multilinear{ .evals = &t1 };
    const p2 = Multilinear{ .evals = &t2 };
    const v0 = try p0.eval(alloc, rr.challenges);
    const v1 = try p1.eval(alloc, rr.challenges);
    const v2 = try p2.eval(alloc, rr.challenges);
    const expected = fe(2).mul(v0.mul(v2)).add(fe(3).mul(v1));
    try std.testing.expect(expected.eq(rr.current_sum));
}

test "challenges span the full GF(256) field" {
    // Regression for the 4-bit mask bug: for a 1-byte field the challenge must
    // use the full BITS bits, not just the low 4.
    const Gf256 = @import("tower.zig").Gf256;
    var t = Sumcheck(Gf256).Transcript.initBytes("challenge-space");
    var seen = [_]bool{false} ** 256;
    var count: usize = 0;
    for (0..64) |i| {
        const c = t.absorb(&[_]Gf256{Gf256.fromInt(i)});
        if (!seen[@as(usize, @intCast(c.value))]) {
            seen[@as(usize, @intCast(c.value))] = true;
            count += 1;
        }
    }
    try std.testing.expect(count > 16);
}
