const std = @import("std");
const qm31 = @import("zig-stark").qm31;
const channel = @import("zig-stark").channel;
const stark = @import("zig-stark").stark;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();

    const Channel = channel.Channel;
    const Stark = stark.GenericStark(stark.FibAir);

    const params = stark.StarkParams{
        .trace_log = 8,
        .log_blowup = 3,
        .num_queries = 16,
        .remainder_log = 3,
    };
    const n = params.traceLen();

    const trace = try stark.FibAir.generateTrace(alloc, n);
    defer stark.FibAir.freeTrace(alloc, trace);
    const claimed = trace[0][n - 1];

    var pchan = Channel.init("zig-stark:fibonacci:example");
    var proof = try Stark.prove(alloc, params, .{ .claimed_fib = claimed }, trace, &pchan);
    defer proof.deinit();

    var vchan = Channel.init("zig-stark:fibonacci:example");
    const ok = try Stark.verify(alloc, params, .{ .claimed_fib = claimed }, &proof, &vchan);

    std.debug.print("trace length: {d}\n", .{n});
    std.debug.print("verifier accepted proof: {any}\n", .{ok});
    if (!ok) return error.VerificationFailed;

    const expect = try computeFib(alloc, n);
    if (!claimed.eq(expect)) return error.ClaimMismatch;
    std.debug.print("claimed fib(n) matches direct computation\n", .{});
}

fn computeFib(alloc: std.mem.Allocator, n: usize) !qm31.QM31 {
    const cols = try stark.FibAir.generateTrace(alloc, n);
    defer stark.FibAir.freeTrace(alloc, cols);
    return cols[0][n - 1];
}
