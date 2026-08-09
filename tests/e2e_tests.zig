const std = @import("std");
const zig_stark = @import("zig-stark");

const stark = zig_stark.stark;
const channel = zig_stark.channel;
const qm31 = zig_stark.qm31;
const QM31 = qm31.QM31;

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
    const Stark = zig_stark.binius.stark.BiniusStark(F);
    const Adder = zig_stark.binius.adder.Adder(F);
    const CommittedPcs = zig_stark.binius.pcs.CommittedMlePcs(F);
    const Hash = zig_stark.hash.Hash;

    const n = @as(usize, 1) << @intCast(k);
    const x = try alloc.alloc(u4, n);
    const y = try alloc.alloc(u4, n);
    for (0..n) |i| {
        x[i] = @intCast((i * 3 + 5) % 16);
        y[i] = @intCast((i * 7 + 2) % 16);
    }

    const columns = try Adder.generateWitness(alloc, x, y);
    const proof = try Stark.prove(alloc, k, &columns, &Adder.constraints);

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
        return try Stark.verify(alloc, k, &bad_roots, &Adder.constraints, proof);
    }

    var roots: [Adder.num_columns]Hash.Digest = undefined;
    for (0..Adder.num_columns) |c| {
        var tree = try CommittedPcs.commit(alloc, columns[c]);
        roots[c] = tree.root();
    }
    return try Stark.verify(alloc, k, &roots, &Adder.constraints, proof);
}

test "e2e: Binius 4-bit adder batch prove/verify round-trip" {
    try std.testing.expect(try biniusAdderRoundTrip(4, false));
}

test "e2e: Binius adder rejects tampered committed witness" {
    try std.testing.expect(!try biniusAdderRoundTrip(4, true));
}
