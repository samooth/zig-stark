const std = @import("std");
const zig_stark = @import("zig-stark");

const stark = zig_stark.stark;
const channel = zig_stark.channel;
const qm31 = zig_stark.qm31;
const QM31 = qm31.QM31;
const ser = zig_stark.core.serialization;

fn roundTrip(trace_log: u8, tampered_claim: bool) !bool {
    const alloc = std.testing.allocator;
    const params = stark.StarkParams{
        .trace_log = trace_log,
        .log_blowup = 3,
        .num_queries = 16,
        .remainder_log = 3,
    };
    const n = params.traceLen();

    const trace = try stark.FibAir.generateTrace(alloc, n);
    defer stark.FibAir.freeTrace(alloc, trace);
    var claimed = trace[0][n - 1];
    if (tampered_claim) claimed = claimed.add(QM31.one());

    const Stark = stark.GenericStark(stark.FibAir);

    var pchan = channel.Channel.init("zig-stark:e2e");
    var proof = try Stark.prove(alloc, params, .{ .claimed_fib = claimed }, trace, &pchan);
    defer proof.deinit();

    var vchan = channel.Channel.init("zig-stark:e2e");
    return try Stark.verify(alloc, params, .{ .claimed_fib = claimed }, &proof, &vchan);
}

test "e2e: full Fibonacci STARK prove/verify round-trip" {
    try std.testing.expect(try roundTrip(8, false));
}

test "e2e: Fibonacci STARK rejects wrong claimed fib" {
    try std.testing.expect(!try roundTrip(8, true));
}

test "e2e: Fibonacci STARK round-trip at small trace" {
    try std.testing.expect(try roundTrip(4, false));
}

fn biniusAdderRoundTrip(k: usize, tamper: bool) !bool {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const F = zig_stark.binius.tower.Gf16;
    const E = zig_stark.binius.tower.Gf2_128;
    const Adder = zig_stark.binius.adder.Adder(F, E);
    const Stark = zig_stark.binius.stark.BiniusStark(F, E);
    const CommittedPcs = zig_stark.binius.pcs.CommittedMlePcs(F, E);
    const Hash = zig_stark.hash.Hash;

    const n = @as(usize, 1) << @intCast(k);
    const x = try alloc.alloc(u4, n);
    const y = try alloc.alloc(u4, n);
    for (0..n) |i| {
        x[i] = @intCast((i * 3 + 5) % 16);
        y[i] = @intCast((i * 7 + 2) % 16);
    }

    const columns = try Adder.generateWitness(alloc, x, y);
    var proof = try Stark.prove(alloc, k, &columns, &Adder.constraints, &.{}, "");
    defer proof.deinit(alloc);

    if (tamper) {
        // Flip one sum bit in a re-committed witness: the roots no longer
        // match the proof, so the verifier rejects.
        var bad: [Adder.num_columns][]F = undefined;
        for (0..Adder.num_columns) |c| bad[c] = try alloc.dupe(F, columns[c]);
        bad[Adder.colS(1)][3] = bad[Adder.colS(1)][3].add(F.one());
        var bad_roots: [Adder.num_columns]Hash.Digest = undefined;
        for (0..Adder.num_columns) |c| {
            var tree = try CommittedPcs.commit(alloc, bad[c]);
            bad_roots[c] = tree.root();
        }
        return try Stark.verify(alloc, k, &bad_roots, &Adder.constraints, &.{}, proof, "");
    }

    var roots: [Adder.num_columns]Hash.Digest = undefined;
    for (0..Adder.num_columns) |c| {
        var tree = try CommittedPcs.commit(alloc, columns[c]);
        roots[c] = tree.root();
    }
    return try Stark.verify(alloc, k, &roots, &Adder.constraints, &.{}, proof, "");
}

test "e2e: Binius 4-bit adder batch prove/verify round-trip" {
    try std.testing.expect(try biniusAdderRoundTrip(4, false));
}

test "e2e: Binius adder rejects tampered committed witness" {
    try std.testing.expect(!try biniusAdderRoundTrip(4, true));
}

fn biniusAdderFriRoundTrip(k: usize, tamper: bool) !bool {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const F = zig_stark.binius.tower.Gf256;
    const E = zig_stark.binius.tower.Gf2_128;
    const BatchPcs = zig_stark.binius.batchpcs.BatchFriPcsStark(F, E, 2, 4);
    const Adder = zig_stark.binius.adder.AdderWith(F, E, BatchPcs);
    const Stark = zig_stark.binius.stark.BiniusStarkFri(F, E, 2, 4);
    const Hash = zig_stark.hash.Hash;

    const n = @as(usize, 1) << @intCast(k);
    const x = try alloc.alloc(u4, n);
    const y = try alloc.alloc(u4, n);
    for (0..n) |i| {
        x[i] = @intCast((i * 3 + 5) % 16);
        y[i] = @intCast((i * 7 + 2) % 16);
    }

    const columns = try Adder.generateWitness(alloc, x, y);
    var proof = try Stark.prove(alloc, k, &columns, &Adder.constraints, &.{}, "");
    defer proof.deinit(alloc);

    if (tamper) {
        // Re-commit a modified witness: the roots no longer match the proof,
        // so the verifier rejects.
        var bad: [Adder.num_columns][]F = undefined;
        for (0..Adder.num_columns) |c| bad[c] = try alloc.dupe(F, columns[c]);
        bad[Adder.colS(1)][3] = bad[Adder.colS(1)][3].add(F.one());
        var bad_roots: [Adder.num_columns]Hash.Digest = undefined;
        for (0..Adder.num_columns) |c| {
            var tree = try BatchPcs.commit(alloc, bad[c]);
            bad_roots[c] = tree.root();
        }
        return try Stark.verify(alloc, k, &bad_roots, &Adder.constraints, &.{}, proof, "");
    }

    var roots: [Adder.num_columns]Hash.Digest = undefined;
    for (0..Adder.num_columns) |c| {
        var tree = try BatchPcs.commit(alloc, columns[c]);
        roots[c] = tree.root();
    }
    return try Stark.verify(alloc, k, &roots, &Adder.constraints, &.{}, proof, "");
}

test "e2e: Binius 4-bit adder with sub-linear FRI PCS round-trip" {
    try std.testing.expect(try biniusAdderFriRoundTrip(4, false));
}

test "e2e: Binius adder with FRI PCS rejects tampered committed witness" {
    try std.testing.expect(!try biniusAdderFriRoundTrip(4, true));
}

/// Field/digest "units" in the PCS eval section of a FRI-PCS Stark proof.
/// Handles both the per-column `[]EvalProof` section (slice) and the shared
/// `BatchProof` section (struct) of a batched PCS.
fn friEvalUnits(proof: anytype) usize {
    var total: usize = 0;
    if (@hasField(@TypeOf(proof.evals), "values")) {
        const b = proof.evals;
        total += b.values.len + b.final_folded.len;
        for (b.rounds) |r| total += r.coeffs.len + 1;
        total += b.layer_roots.len;
        for (b.queries) |q| {
            for (q.layers) |lp| total += 2 + lp.path.len;
        }
    } else {
        for (proof.evals) |e| {
            const p = e.pcs;
            total += 2; // claimed value + final folded value
            total += p.rounds.len * 4; // 3 coeffs + challenge per round
            total += p.layer_roots.len;
            for (p.queries) |q| {
                for (q.layers) |lp| total += 2 + lp.path.len;
            }
        }
    }
    return total;
}

/// Field/digest "units" in the PCS eval section of a committed-MLE Stark proof
/// (the 2^k opened leaves + their Merkle paths dominate).
fn cmleEvalUnits(proof: anytype) usize {
    var total: usize = 0;
    for (proof.evals) |e| {
        const p = e.pcs;
        total += 1 + p.entries.len;
        for (p.paths) |path| total += path.len;
    }
    return total;
}

test "e2e: FRI PCS proof size is sub-linear vs committed-MLE (k = 4..6)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Single-field (E = F = Gf256): the proof-size structure is identical to
    // extension mode, but the zero-check sum-check runs in fast byte-level
    // arithmetic instead of the slow Gf2_128 tower mul in Debug builds.
    const F = zig_stark.binius.tower.Gf256;
    const E = zig_stark.binius.tower.Gf256;
    const Hash = zig_stark.hash.Hash;
    const BatchPcs = zig_stark.binius.batchpcs.BatchFriPcsStark(F, E, 2, 4);
    const CommittedPcs = zig_stark.binius.pcs.CommittedMlePcs(F, E);

    const AdderFri = zig_stark.binius.adder.AdderWith(F, E, BatchPcs);
    const StarkFri = zig_stark.binius.stark.BiniusStarkFri(F, E, 2, 4);
    const AdderCm = zig_stark.binius.adder.AdderWith(F, E, CommittedPcs);
    const StarkCm = zig_stark.binius.stark.BiniusStarkWith(F, E, CommittedPcs);

    var prev_fri: usize = 0;
    var cm_last: usize = 0;
    for (4..7) |k| {
        const n = @as(usize, 1) << @intCast(k);
        const x = try alloc.alloc(u4, n);
        const y = try alloc.alloc(u4, n);
        for (0..n) |i| {
            x[i] = @intCast((i * 3 + 5) % 16);
            y[i] = @intCast((i * 7 + 2) % 16);
        }

        const cols = try AdderFri.generateWitness(alloc, x, y);
        var pf = try StarkFri.prove(alloc, k, &cols, &AdderFri.constraints, &.{}, "");
        defer pf.deinit(alloc);
        var roots: [AdderFri.num_columns]Hash.Digest = undefined;
        for (0..AdderFri.num_columns) |c| {
            var tree = try BatchPcs.commit(alloc, cols[c]);
            roots[c] = tree.root();
        }
        try std.testing.expect(try StarkFri.verify(alloc, k, &roots, &AdderFri.constraints, &.{}, pf, ""));
        const fri_units = friEvalUnits(pf);

        const cols_cm = try AdderCm.generateWitness(alloc, x, y);
        var pc = try StarkCm.prove(alloc, k, &cols_cm, &AdderCm.constraints, &.{}, "");
        defer pc.deinit(alloc);
        var roots_cm: [AdderCm.num_columns]Hash.Digest = undefined;
        for (0..AdderCm.num_columns) |c| {
            var tree = try CommittedPcs.commit(alloc, cols_cm[c]);
            roots_cm[c] = tree.root();
        }
        try std.testing.expect(try StarkCm.verify(alloc, k, &roots_cm, &AdderCm.constraints, &.{}, pc, ""));
        const cm_units = cmleEvalUnits(pc);

        if (prev_fri != 0) {
            // FRI proof grows strictly sub-exponentially (< 2x per k step).
            try std.testing.expect(fri_units < 2 * prev_fri);
        }
        prev_fri = fri_units;
        cm_last = cm_units;
    }
    // The crossover has decisively passed by k = 6: the FRI proof is smaller
    // than the committed-MLE proof, which grows O(2^k · k) in entries+paths.
    try std.testing.expect(prev_fri < cm_last);
}

test "e2e: BiniusArg FRI PCS proof size is sub-linear vs committed-MLE (k = 4..6)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Single-field Gf256 for Debug speed; the proof-size structure is the
    // same as extension mode.
    const F = zig_stark.binius.tower.Gf256;
    const E = zig_stark.binius.tower.Gf256;
    const Hash = zig_stark.hash.Hash;
    const ArgFri = zig_stark.binius.arg.BiniusArgFri(F, E, 2, 4);
    const ArgCm = zig_stark.binius.arg.BiniusArgWith(F, E, zig_stark.binius.pcs.CommittedMlePcs(F, E));

    var prev_fri: usize = 0;
    var cm_last: usize = 0;
    for (4..7) |k| {
        const n = @as(usize, 1) << @intCast(k);
        var t0: [64]F = undefined;
        var t1: [64]F = undefined;
        for (0..n) |i| {
            t0[i] = F.fromInt((i * 7 + 3) % 256);
            t1[i] = F.fromInt((i * 3 + 11) % 256);
        }
        const tables = [_][]const F{ t0[0..n], t1[0..n] };

        const expected_fri = try ArgFri.prove(alloc, k, &tables);
        const expected_cm = try ArgCm.prove(alloc, k, &tables);

        var roots: [2]Hash.Digest = undefined;
        {
            var tree0 = try zig_stark.binius.fripcs.FriPcs(F, E, 2, 4).commit(alloc, t0[0..n]);
            var tree1 = try zig_stark.binius.fripcs.FriPcs(F, E, 2, 4).commit(alloc, t1[0..n]);
            roots[0] = tree0.root();
            roots[1] = tree1.root();
        }
        try std.testing.expect(try ArgFri.verify(alloc, k, &roots, expected_cm.claimed_sum, expected_fri));

        const fri_units = friEvalUnits(expected_fri);

        var roots_cm: [2]Hash.Digest = undefined;
        {
            var tree0 = try zig_stark.binius.pcs.CommittedMlePcs(F, E).commit(alloc, t0[0..n]);
            var tree1 = try zig_stark.binius.pcs.CommittedMlePcs(F, E).commit(alloc, t1[0..n]);
            roots_cm[0] = tree0.root();
            roots_cm[1] = tree1.root();
        }
        try std.testing.expect(try ArgCm.verify(alloc, k, &roots_cm, expected_cm.claimed_sum, expected_cm));
        const cm_units = cmleEvalUnits(expected_cm);

        if (prev_fri != 0) {
            // FRI proof grows strictly sub-exponentially (< 2x per k step).
            try std.testing.expect(fri_units < 2 * prev_fri);
        }
        prev_fri = fri_units;
        cm_last = cm_units;
    }
    // FRI wins by k = 6: the committed-MLE proof grows O(2^k · k) in
    // entries+paths, the FRI one polynomially in k·queries.
    try std.testing.expect(prev_fri < cm_last);
}

// ---------------------------------------------------------------------------
// Proof serialization round-trips: serialize -> deserialize -> verify. A
// deserialized proof must be byte-identical in behavior (verifier accepts) and
// own its memory (deinit is leak-free).
// ---------------------------------------------------------------------------

fn biniusRoundTrip(tamper: bool) !bool {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const F = zig_stark.binius.tower.Gf256;
    const E = zig_stark.binius.tower.Gf2_128;
    const Adder = zig_stark.binius.adder.Adder(F, E);
    const Stark = zig_stark.binius.stark.BiniusStark(F, E);
    const CommittedPcs = zig_stark.binius.pcs.CommittedMlePcs(F, E);
    const Hash = zig_stark.hash.Hash;

    const k = 3;
    const n = @as(usize, 1) << @intCast(k);
    const x = try alloc.alloc(u4, n);
    const y = try alloc.alloc(u4, n);
    for (0..n) |i| {
        x[i] = @intCast((i * 3 + 5) % 16);
        y[i] = @intCast((i * 7 + 2) % 16);
    }

    const columns = try Adder.generateWitness(alloc, x, y);
    var proof = try Stark.prove(alloc, k, &columns, &Adder.constraints, &.{}, "");
    defer proof.deinit(alloc);

    if (tamper) {
        // Flip one committed bit before serializing: the deserialized proof
        // still verifies against the tampered roots only if the roots match
        // the *tampered* witness — the round trip must not change rejection.
        var bad: [Adder.num_columns][]F = undefined;
        for (0..Adder.num_columns) |c| bad[c] = try alloc.dupe(F, columns[c]);
        bad[Adder.colS(1)][3] = bad[Adder.colS(1)][3].add(F.one());
        var bad_roots: [Adder.num_columns]Hash.Digest = undefined;
        for (0..Adder.num_columns) |c| {
            var tree = try CommittedPcs.commit(alloc, bad[c]);
            bad_roots[c] = tree.root();
        }
        return try Stark.verify(alloc, k, &bad_roots, &Adder.constraints, &.{}, proof, "");
    }

    var roots: [Adder.num_columns]Hash.Digest = undefined;
    for (0..Adder.num_columns) |c| {
        var tree = try CommittedPcs.commit(alloc, columns[c]);
        roots[c] = tree.root();
    }
    // Round-trip the proof, then verify with the *deserialized* copy.
    const bytes = try ser.serialize(alloc, proof);
    defer alloc.free(bytes);
    var rt = try ser.deserialize(alloc, bytes, Stark.Proof);
    defer rt.deinit(alloc);
    return try Stark.verify(alloc, k, &roots, &Adder.constraints, &.{}, rt, "");
}

test "e2e: Binius STARK proof (CommittedMlePcs) survives serialization round-trip" {
    try std.testing.expect(try biniusRoundTrip(false));
}

test "e2e: Binius STARK proof round-trip preserves tamper rejection" {
    try std.testing.expect(!try biniusRoundTrip(true));
}

fn biniusFriRoundTrip(tamper: bool) !bool {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Single-field Gf256 keeps the FRI sum-check fast in Debug.
    const F = zig_stark.binius.tower.Gf256;
    const E = zig_stark.binius.tower.Gf256;
    const BatchPcs = zig_stark.binius.batchpcs.BatchFriPcsStark(F, E, 2, 4);
    const Adder = zig_stark.binius.adder.AdderWith(F, E, BatchPcs);
    const Stark = zig_stark.binius.stark.BiniusStarkFri(F, E, 2, 4);
    const Hash = zig_stark.hash.Hash;

    const k = 3;
    const n = @as(usize, 1) << @intCast(k);
    const x = try alloc.alloc(u4, n);
    const y = try alloc.alloc(u4, n);
    for (0..n) |i| {
        x[i] = @intCast((i * 3 + 5) % 16);
        y[i] = @intCast((i * 7 + 2) % 16);
    }

    const columns = try Adder.generateWitness(alloc, x, y);
    var proof = try Stark.prove(alloc, k, &columns, &Adder.constraints, &.{}, "");
    defer proof.deinit(alloc);

    if (tamper) {
        var bad: [Adder.num_columns][]F = undefined;
        for (0..Adder.num_columns) |c| bad[c] = try alloc.dupe(F, columns[c]);
        bad[Adder.colS(1)][3] = bad[Adder.colS(1)][3].add(F.one());
        var bad_roots: [Adder.num_columns]Hash.Digest = undefined;
        for (0..Adder.num_columns) |c| {
            var tree = try BatchPcs.commit(alloc, bad[c]);
            bad_roots[c] = tree.root();
        }
        return try Stark.verify(alloc, k, &bad_roots, &Adder.constraints, &.{}, proof, "");
    }

    var roots: [Adder.num_columns]Hash.Digest = undefined;
    for (0..Adder.num_columns) |c| {
        var tree = try BatchPcs.commit(alloc, columns[c]);
        roots[c] = tree.root();
    }
    const bytes = try ser.serialize(alloc, proof);
    defer alloc.free(bytes);
    var rt = try ser.deserialize(alloc, bytes, Stark.Proof);
    defer rt.deinit(alloc);
    return try Stark.verify(alloc, k, &roots, &Adder.constraints, &.{}, rt, "");
}

test "e2e: Binius FRI STARK proof (BatchFriPcs) survives serialization round-trip" {
    try std.testing.expect(try biniusFriRoundTrip(false));
}

test "e2e: Binius FRI STARK proof round-trip preserves tamper rejection" {
    try std.testing.expect(!try biniusFriRoundTrip(true));
}

fn biniusArgRoundTrip() !bool {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const F = zig_stark.binius.tower.Gf256;
    const E = zig_stark.binius.tower.Gf256;
    const ArgFri = zig_stark.binius.arg.BiniusArgFri(F, E, 2, 4);
    const ArgCm = zig_stark.binius.arg.BiniusArgWith(F, E, zig_stark.binius.pcs.CommittedMlePcs(F, E));

    const k = 3;
    const n = @as(usize, 1) << @intCast(k);
    var t0: [64]F = undefined;
    var t1: [64]F = undefined;
    for (0..n) |i| {
        t0[i] = F.fromInt((i * 7 + 3) % 256);
        t1[i] = F.fromInt((i * 3 + 11) % 256);
    }
    const tables = [_][]const F{ t0[0..n], t1[0..n] };

    const pf = try ArgFri.prove(alloc, k, &tables);
    const pc = try ArgCm.prove(alloc, k, &tables);

    var roots: [2]zig_stark.hash.Hash.Digest = undefined;
    {
        var tree0 = try zig_stark.binius.fripcs.FriPcs(F, E, 2, 4).commit(alloc, t0[0..n]);
        var tree1 = try zig_stark.binius.fripcs.FriPcs(F, E, 2, 4).commit(alloc, t1[0..n]);
        roots[0] = tree0.root();
        roots[1] = tree1.root();
    }
    var roots_cm: [2]zig_stark.hash.Hash.Digest = undefined;
    {
        var tree0 = try zig_stark.binius.pcs.CommittedMlePcs(F, E).commit(alloc, t0[0..n]);
        var tree1 = try zig_stark.binius.pcs.CommittedMlePcs(F, E).commit(alloc, t1[0..n]);
        roots_cm[0] = tree0.root();
        roots_cm[1] = tree1.root();
    }

    const bf = try ser.serialize(alloc, pf);
    defer alloc.free(bf);
    var rt_fri = try ser.deserialize(alloc, bf, ArgFri.Proof);
    defer rt_fri.deinit(alloc);
    const ok_fri = try ArgFri.verify(alloc, k, &roots, pc.claimed_sum, rt_fri);

    const bc = try ser.serialize(alloc, pc);
    defer alloc.free(bc);
    var rt_cm = try ser.deserialize(alloc, bc, ArgCm.Proof);
    defer rt_cm.deinit(alloc);
    const ok_cm = try ArgCm.verify(alloc, k, &roots_cm, pc.claimed_sum, rt_cm);

    return ok_fri and ok_cm;
}

test "e2e: BiniusArg proofs (FriPcs + CommittedMlePcs) survive serialization round-trip" {
    try std.testing.expect(try biniusArgRoundTrip());
}

fn m31RoundTrip(trace_log: u8) !bool {
    const alloc = std.testing.allocator;
    const params = stark.StarkParams{
        .trace_log = trace_log,
        .log_blowup = 3,
        .num_queries = 16,
        .remainder_log = 3,
    };
    const n = params.traceLen();

    const trace = try stark.FibAir.generateTrace(alloc, n);
    defer stark.FibAir.freeTrace(alloc, trace);
    const claimed = trace[0][n - 1];

    const Stark = stark.GenericStark(stark.FibAir);

    var pchan = channel.Channel.init("zig-stark:e2e-ser");
    var proof = try Stark.prove(alloc, params, .{ .claimed_fib = claimed }, trace, &pchan);
    defer proof.deinit();

    const bytes = try ser.serialize(alloc, proof);
    defer alloc.free(bytes);
    var rt = try ser.deserialize(alloc, bytes, Stark.Proof);
    defer rt.deinit();

    var vchan = channel.Channel.init("zig-stark:e2e-ser");
    return try Stark.verify(alloc, params, .{ .claimed_fib = claimed }, &rt, &vchan);
}

test "e2e: M31 Fibonacci STARK proof survives serialization round-trip" {
    try std.testing.expect(try m31RoundTrip(6));
}
