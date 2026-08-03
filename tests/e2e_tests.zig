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
