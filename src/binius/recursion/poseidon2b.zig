const std = @import("std");
const StarkMod = @import("../stark.zig");
const PcsMod = @import("../pcs.zig");

/// Poseidon2b permutation over the binary tower, as an in-circuit gadget for
/// the Binius zero-check STARK (ePrint 2025/1893, "Poseidon(2)b", Table 1).
///
/// Parameter set used here is the reference Binius one from
/// `Poseidon-Hash/Poseidon2b` -> `binius_poseidon2b/crates/circuits/src/hades/
/// poseidon2b_x7_64_512.rs`: field GF(2^64), state t = 8, S-box x^7,
/// R_F = 10 full rounds and R_P = 29 partial rounds. In the tower used by this
/// repo those constants live in `tower.zig` as `Gf2_64 = TowerField(6)` (the
/// degree-2 subfield of `Gf2_128 = TowerField(7)`), which is exactly the
/// `n = 64` domain of the paper.
///
/// Reference permutation structure (mirrored verbatim from `plain_permutation`):
///
///     state <- M_E . state              (initial linear layer, M_E = MDS_FULL)
///     for r in 0..(R_F + R_P):
///       full:   state <- M_E . (state + rc[i][r])^7          (r < 5 or r >= 34)
///       partial:state <- M_P . ((state[0] + rc[0][r])^7, state[1..])  (else)
///
/// where `rc` is a [8][39] round-constant table and `M_P = 1 + diag(mu)` is the
/// O(t) partial matrix. All constant values below are transcribed verbatim from
/// the reference circuit (its `BinaryField64b` uses the same Wiedemann tower bit
/// representation as this repo, so `F.fromInt(u64)` gives the identical field
/// element).
///
/// The gadget commits the full state at every round boundary ("row" layout):
/// column `s*t + i` holds element `i` of state `s`, with `s = 0` the raw input,
/// `s = 1` the initial-MDS image, and `s = r+2` the state after round `r`.
/// This keeps every constraint degree-<=7 (the S-box) with no virtual-column
/// machinery, at the cost of more committed columns than the paper's
/// S-box-only arithmetization (which needs linear-combination oracle columns
/// this DSL does not have). The constraint system is built at runtime (the tower
/// field multiplication is faster there than under comptime evaluation).
pub const state_size = 8;
pub const rate = 4;
pub const capacity = 4;
pub const r_full = 10;
pub const r_partial = 29;
pub const n_rounds = r_full + r_partial;
pub const num_states = 2 + n_rounds; // input, initial-MDS image, one per round

/// Full-round external matrix M_E (tensor M_4 structure, non-MDS for n = 64).
pub const MDS_FULL = [state_size][state_size]u64{
    .{ 0xa, 0xe, 0x2, 0x6, 0x5, 0x7, 0x1, 0x3 },
    .{ 0x8, 0xc, 0x2, 0x2, 0x4, 0x6, 0x1, 0x1 },
    .{ 0x2, 0x6, 0xa, 0xe, 0x1, 0x3, 0x5, 0x7 },
    .{ 0x2, 0x2, 0x8, 0xc, 0x1, 0x1, 0x4, 0x6 },
    .{ 0x5, 0x7, 0x1, 0x3, 0xa, 0xe, 0x2, 0x6 },
    .{ 0x4, 0x6, 0x1, 0x1, 0x8, 0xc, 0x2, 0x2 },
    .{ 0x1, 0x3, 0x5, 0x7, 0x2, 0x6, 0xa, 0xe },
    .{ 0x1, 0x1, 0x4, 0x6, 0x2, 0x2, 0x8, 0xc },
};

/// Partial (internal) matrix M_P = 1 + diag(mu), in explicit O(t) form.
pub const MDS_PARTIAL = [state_size][state_size]u64{
    .{ 0x81, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 },
    .{ 0x1, 0x2, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1 },
    .{ 0x1, 0x1, 0x200, 0x1, 0x1, 0x1, 0x1, 0x1 },
    .{ 0x1, 0x1, 0x1, 0x80, 0x1, 0x1, 0x1, 0x1 },
    .{ 0x1, 0x1, 0x1, 0x1, 0x2000, 0x1, 0x1, 0x1 },
    .{ 0x1, 0x1, 0x1, 0x1, 0x1, 0x1000, 0x1, 0x1 },
    .{ 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x4000, 0x1 },
    .{ 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x40 },
};

/// Round constants rc[i][r] (only rc[0][r] is used in partial rounds).
pub const RC = [state_size][n_rounds]u64{
    .{ 0x68, 0x34, 0x1d, 0x2c, 0x1d, 0x4b, 0x32, 0x55, 0x7a, 0x79, 0x3d, 0x59, 0x1c, 0x41, 0x5f, 0x65, 0x40, 0x6b, 0x48, 0x48, 0x54, 0x8, 0x43, 0x12, 0x40, 0x56, 0x6, 0xa, 0x36, 0x76, 0x5d, 0x73, 0x7, 0x47, 0x68, 0x4b, 0x3a, 0xe, 0x23 },
    .{ 0x7b, 0x10, 0x4b, 0x5e, 0x59, 0x1b, 0x4, 0x61, 0x4b, 0x5c, 0x4d, 0x35, 0x26, 0x6f, 0x1c, 0x72, 0x16, 0x55, 0x31, 0x17, 0x64, 0x3c, 0x28, 0x69, 0x4e, 0x44, 0x63, 0x27, 0x29, 0x50, 0x65, 0x7d, 0xb, 0x1f, 0x60, 0x78, 0x12, 0x5d, 0x49 },
    .{ 0x12, 0x76, 0x37, 0x1d, 0x9, 0x6d, 0x79, 0x6c, 0x3e, 0x47, 0x7a, 0x4c, 0x1b, 0x3a, 0x7c, 0x2c, 0x7a, 0x62, 0x70, 0x7, 0x58, 0x23, 0x1, 0x47, 0x28, 0x7e, 0x63, 0x47, 0x1b, 0x15, 0x7d, 0x6b, 0x5d, 0x6, 0x33, 0x39, 0x68, 0x54, 0x58 },
    .{ 0x67, 0x5c, 0x60, 0x39, 0x49, 0xc, 0x39, 0x4c, 0x56, 0x4e, 0x7f, 0x4b, 0x12, 0x34, 0x24, 0x16, 0x25, 0x25, 0xe, 0x68, 0x55, 0x51, 0x33, 0x43, 0x50, 0x72, 0x1a, 0x3b, 0x6f, 0x52, 0x4, 0x34, 0x6f, 0x53, 0x33, 0x48, 0x49, 0x21, 0x46 },
    .{ 0x41, 0x8, 0x78, 0x60, 0x6d, 0x58, 0x1a, 0x15, 0x5e, 0x1d, 0x35, 0x10, 0x4d, 0x11, 0x57, 0x7e, 0x37, 0x78, 0x19, 0x6b, 0x6f, 0xa, 0x8, 0x5b, 0x78, 0x7c, 0x9, 0x52, 0xf, 0x1e, 0x45, 0x7d, 0x50, 0x35, 0x71, 0x2c, 0x4d, 0x61, 0x6 },
    .{ 0x2d, 0x40, 0x50, 0xd, 0x72, 0x2a, 0x1c, 0x3e, 0x56, 0x7, 0x77, 0x63, 0x39, 0x56, 0x3f, 0x1a, 0x60, 0x54, 0x1d, 0x2e, 0x68, 0x3f, 0x6a, 0x22, 0x58, 0x71, 0x3c, 0x7b, 0x64, 0x6c, 0x15, 0x54, 0x7f, 0x3b, 0x69, 0x59, 0x2b, 0xf, 0x2c },
    .{ 0x6f, 0x65, 0x7d, 0x10, 0x59, 0x35, 0x3, 0x4, 0x2, 0x62, 0x4b, 0x5c, 0x4a, 0x57, 0x4c, 0x61, 0x48, 0x6e, 0x4e, 0x16, 0x12, 0x40, 0x59, 0x59, 0x38, 0x44, 0x70, 0x77, 0x37, 0x11, 0x47, 0x29, 0x16, 0x78, 0x4c, 0x20, 0x4c, 0x1d, 0xc },
    .{ 0x31, 0x37, 0x38, 0x66, 0x44, 0x44, 0x65, 0x2c, 0x26, 0xf, 0x68, 0x7, 0x3f, 0x4e, 0x40, 0x46, 0x60, 0x16, 0x60, 0x2c, 0x2c, 0x5, 0x59, 0x6a, 0x34, 0x10, 0x27, 0x2f, 0x49, 0x30, 0x63, 0x56, 0x36, 0x15, 0x7a, 0x76, 0x39, 0x71, 0x72 },
};

/// Round `r` is full iff `r < R_F/2` or `r >= R_F/2 + R_P` (5 + 29 + 5).
pub fn isFull(r: usize) bool {
    return r < r_full / 2 or r >= r_full / 2 + r_partial;
}

/// The S-box x -> x^7 (3 squarings + 1 multiplication over the tower).
pub fn sbox(comptime F: type, x: F) F {
    return x.pow(7);
}

/// Reference host permutation over any tower field `F` with `t = 8` elements,
/// mirroring the reference circuit's `plain_permutation` exactly.
pub fn permutationState(comptime F: type, st: *[state_size]F) void {
    var tmp: [state_size]F = undefined;
    for (0..state_size) |i| {
        var acc = F.zero();
        for (0..state_size) |j| acc = acc.add(F.fromInt(MDS_FULL[i][j]).mul(st[j]));
        tmp[i] = acc;
    }
    st.* = tmp;

    for (0..n_rounds) |r| {
        if (isFull(r)) {
            for (0..state_size) |i| st[i] = st[i].add(F.fromInt(RC[i][r]));
            for (0..state_size) |i| st[i] = sbox(F, st[i]);
            for (0..state_size) |i| {
                var acc = F.zero();
                for (0..state_size) |j| acc = acc.add(F.fromInt(MDS_FULL[i][j]).mul(st[j]));
                tmp[i] = acc;
            }
        } else {
            st[0] = st[0].add(F.fromInt(RC[0][r]));
            st[0] = sbox(F, st[0]);
            for (0..state_size) |i| {
                var acc = F.zero();
                for (0..state_size) |j| acc = acc.add(F.fromInt(MDS_PARTIAL[i][j]).mul(st[j]));
                tmp[i] = acc;
            }
        }
        st.* = tmp;
    }
}

/// Poseidon2b permutation wired into any `BiniusStarkWith` PCS.
pub fn Permutation(comptime F: type, comptime E: type) type {
    return PermutationWith(F, E, PcsMod.CommittedMlePcs(F, E));
}

/// Same gadget with a caller-chosen committed-MLE PCS.
pub fn PermutationWith(comptime F: type, comptime E: type, comptime CP: type) type {
    return struct {
        pub const num_columns = state_size * num_states;
        pub const num_constraints = state_size * (1 + n_rounds); // init + rounds

        const Stark = StarkMod.BiniusStarkWith(F, E, CP);
        pub const Monomial = Stark.Monomial;
        pub const Constraint = Stark.Constraint;

        /// Column of element `i` in state `s` (s in 0..num_states).
        pub inline fn colState(s: usize, i: usize) usize {
            std.debug.assert(s < num_states and i < state_size);
            return s * state_size + i;
        }

        /// Manual constraint accumulator backed by a single arena allocation:
        /// `monos` holds every monomial; `factors` holds every factor index;
        /// `starts`/`lens` slice `monos` into per-constraint terms.
        const Accum = struct {
            monos: []Monomial,
            factors: []usize,
            starts: []usize,
            lens: []usize,
            mi: usize,
            fi: usize,
            ci: usize,

            fn add(self: *@This(), t: usize, coeff: F, fs: []const usize) void {
                while (self.ci <= t) {
                    self.starts[self.ci] = self.mi;
                    if (self.ci < t) self.lens[self.ci] = 0;
                    self.ci += 1;
                }
                const f0 = self.fi;
                for (fs) |f| {
                    self.factors[self.fi] = f;
                    self.fi += 1;
                }
                self.monos[self.mi] = .{ .coeff = coeff, .factors = self.factors[f0..self.fi] };
                self.mi += 1;
                self.lens[t] += 1;
            }
        };

        /// Full-round transition constraint for output element `j` of round `r`:
        /// `state[r+2][j] + Sum_k M_E[j][k]*(state[r+1][k] + rc[k][r])^7 = 0`.
        /// The binomial `(x + c)^7` expands to 8 monomials `c^(7-q)*x^q` (all
        /// binomial coefficients are 1 mod 2).
        fn addFull(a: *Accum, t_idx: usize, r: usize, j: usize) void {
            a.add(t_idx, F.one(), &.{colState(r + 2, j)});
            for (0..state_size) |k| {
                const c_pow = F.fromInt(RC[k][r]);
                const in_col = colState(r + 1, k);
                for (0..8) |q| {
                    const coeff = F.fromInt(MDS_FULL[j][k]).mul(c_pow.pow(7 - q));
                    var factors: [8]usize = undefined;
                    for (0..q) |f| factors[f] = in_col;
                    a.add(t_idx, coeff, factors[0..q]);
                }
            }
        }

        /// Partial-round transition constraint for output element `j` of round
        /// `r`: `state[r+2][j] + Sum_k M_P[j][k]*g_k = 0` with `g_0 = (state[0]+rc[0][r])^7`
        /// and `g_k = state[r+1][k]` for k >= 1.
        fn addPartial(a: *Accum, t_idx: usize, r: usize, j: usize) void {
            a.add(t_idx, F.one(), &.{colState(r + 2, j)});
            const c_pow = F.fromInt(RC[0][r]);
            for (0..8) |q| {
                const coeff = F.fromInt(MDS_PARTIAL[j][0]).mul(c_pow.pow(7 - q));
                var factors: [8]usize = undefined;
                for (0..q) |f| factors[f] = colState(r + 1, 0);
                a.add(t_idx, coeff, factors[0..q]);
            }
            for (1..state_size) |k| {
                a.add(t_idx, F.fromInt(MDS_PARTIAL[j][k]), &.{colState(r + 1, k)});
            }
        }

        /// Build the full constraint system at runtime into `allocator` (use an
        /// `ArenaAllocator`). The returned slice, and the factor slices its
        /// monomials point to, live until `allocator` is freed.
        pub fn buildConstraints(allocator: std.mem.Allocator) ![]const Constraint {
            const total_monos = 72 + (10 * 8 * 65) + (29 * 8 * 16);
            const max_factors = total_monos * 8;
            var a = Accum{
                .monos = try allocator.alloc(Monomial, total_monos),
                .factors = try allocator.alloc(usize, max_factors),
                .starts = try allocator.alloc(usize, num_constraints),
                .lens = try allocator.alloc(usize, num_constraints),
                .mi = 0,
                .fi = 0,
                .ci = 0,
            };
            for (0..num_constraints) |c| {
                a.starts[c] = 0;
                a.lens[c] = 0;
            }

            for (0..state_size) |j| {
                a.add(j, F.one(), &.{colState(1, j)});
                for (0..state_size) |k| {
                    a.add(j, F.fromInt(MDS_FULL[j][k]), &.{colState(0, k)});
                }
            }
            var t_idx: usize = state_size;
            for (0..n_rounds) |r| {
                for (0..state_size) |j| {
                    if (isFull(r)) {
                        addFull(&a, t_idx, r, j);
                    } else {
                        addPartial(&a, t_idx, r, j);
                    }
                    t_idx += 1;
                }
            }

            var out = try allocator.alloc(Constraint, num_constraints);
            for (0..num_constraints) |t| {
                out[t] = .{ .terms = a.monos[a.starts[t] .. a.starts[t] + a.lens[t]] };
            }
            std.debug.assert(a.mi == total_monos);
            return out;
        }

        /// Witness columns for `n` independent permutation instances: column
        /// `colState(s, i)` holds element `i` of state `s` at point `p`.
        pub fn generateWitness(allocator: std.mem.Allocator, inputs: []const [state_size]F) ![num_columns][]F {
            const n = inputs.len;
            var columns: [num_columns][]F = undefined;
            for (0..num_columns) |c| columns[c] = try allocator.alloc(F, n);

            for (0..n) |p| {
                var st: [state_size]F = inputs[p];
                for (0..state_size) |i| columns[colState(0, i)][p] = st[i];
                var init_: [state_size]F = undefined;
                for (0..state_size) |i| {
                    var acc = F.zero();
                    for (0..state_size) |j| acc = acc.add(F.fromInt(MDS_FULL[i][j]).mul(st[j]));
                    init_[i] = acc;
                }
                st = init_;
                for (0..state_size) |i| columns[colState(1, i)][p] = st[i];
                for (0..n_rounds) |r| {
                    var next: [state_size]F = undefined;
                    if (isFull(r)) {
                        for (0..state_size) |i| st[i] = st[i].add(F.fromInt(RC[i][r]));
                        for (0..state_size) |i| st[i] = sbox(F, st[i]);
                        for (0..state_size) |i| {
                            var acc = F.zero();
                            for (0..state_size) |j| acc = acc.add(F.fromInt(MDS_FULL[i][j]).mul(st[j]));
                            next[i] = acc;
                        }
                    } else {
                        st[0] = st[0].add(F.fromInt(RC[0][r]));
                        st[0] = sbox(F, st[0]);
                        for (0..state_size) |i| {
                            var acc = F.zero();
                            for (0..state_size) |j| acc = acc.add(F.fromInt(MDS_PARTIAL[i][j]).mul(st[j]));
                            next[i] = acc;
                        }
                    }
                    st = next;
                    for (0..state_size) |i| columns[colState(r + 2, i)][p] = st[i];
                }
            }
            return columns;
        }

        pub fn freeWitness(allocator: std.mem.Allocator, columns: []const []const F) void {
            for (columns) |c| allocator.free(c);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const Gf2_64 = @import("../tower.zig").Gf2_64;
const Gf2_128 = @import("../tower.zig").Gf2_128;
const CoreHash = @import("../../core/hash/hash.zig");

fn elementsFromBytes(comptime F: type, bytes: []const u8) [state_size]F {
    var out: [state_size]F = undefined;
    for (0..state_size) |i| {
        var b: [8]u8 = @splat(0);
        const off = i * 8;
        if (off < bytes.len) @memcpy(b[0..@min(8, bytes.len - off)], bytes[off..@min(bytes.len, off + 8)]);
        out[i] = F.fromBytes(b);
    }
    return out;
}

test "poseidon2b witness satisfies every constraint at every point" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const P = Permutation(Gf2_64, Gf2_128);
    const inputs = [_][state_size]Gf2_64{
        elementsFromBytes(Gf2_64, "input-0000"),
        elementsFromBytes(Gf2_64, "input-0001"),
        elementsFromBytes(Gf2_64, "input-0002"),
        elementsFromBytes(Gf2_64, "input-0003"),
    };
    const columns = try P.generateWitness(alloc, &inputs);
    defer P.freeWitness(alloc, &columns);
    const constraints = try P.buildConstraints(arena.allocator());

    const n = inputs.len;
    for (constraints) |con| {
        for (0..n) |p| {
            var acc = Gf2_64.zero();
            for (con.terms) |mono| {
                var prod = mono.coeff;
                for (mono.factors) |f| prod = prod.mul(columns[f][p]);
                acc = acc.add(prod);
            }
            try std.testing.expect(acc.isZero());
        }
    }
}

test "poseidon2b permutation STARK round-trips over GF(2^128) extension" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const P = Permutation(Gf2_64, Gf2_128);
    const k = 2;
    const inputs = [_][state_size]Gf2_64{
        elementsFromBytes(Gf2_64, "input-0000"),
        elementsFromBytes(Gf2_64, "input-0001"),
        elementsFromBytes(Gf2_64, "input-0002"),
        elementsFromBytes(Gf2_64, "input-0003"),
    };
    const columns = try P.generateWitness(alloc, &inputs);
    defer P.freeWitness(alloc, &columns);
    const constraints = try P.buildConstraints(arena.allocator());

    var roots: [P.num_columns]CoreHash.Hash.Digest = undefined;
    for (0..P.num_columns) |c| {
        var tree = try PcsMod.CommittedMlePcs(Gf2_64, Gf2_128).commit(alloc, columns[c]);
        defer tree.deinit();
        roots[c] = tree.root();
    }

    var proof = try P.Stark.prove(alloc, k, &columns, constraints, &.{}, "r0-perm");
    defer proof.deinit(alloc);
    try std.testing.expect(try P.Stark.verify(alloc, k, &roots, constraints, &.{}, proof, "r0-perm"));

    for (0..inputs.len) |p| {
        var st: [state_size]Gf2_64 = inputs[p];
        permutationState(Gf2_64, &st);
        for (0..state_size) |i| {
            try std.testing.expectEqual(st[i].value, columns[P.colState(num_states - 1, i)][p].value);
        }
    }
}
