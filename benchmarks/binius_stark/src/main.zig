const std = @import("std");
const zig_stark = @import("zig-stark");
const binius = zig_stark.binius;
const Hash = zig_stark.hash.Hash;

const Gf16 = binius.tower.Gf16;
const Gf256 = binius.tower.Gf256;

/// Monotonic clock in nanoseconds (Linux-only, matching the repo's native
/// targets).
fn now() i128 {
    var ts: std.posix.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, @intCast(ts.sec)) * std.time.ns_per_s + @as(i128, @intCast(ts.nsec));
}

/// Prove and verify one batch of 4-bit additions over `F` with the protocol
/// run in the extension field `E`, reporting wall-clock prove/verify times and
/// the in-memory proof-size breakdown. Eval openings open every hypercube
/// entry (no low-degree test), so they dominate at large k — the benchmark
/// makes that O(2^k) blow-up explicit.
fn runField(comptime F: type, comptime E: type, alloc: std.mem.Allocator, rnd: std.Random) !void {
    const Adder = binius.adder.Adder(F, E);
    const Stark = binius.stark.BiniusStark(F, E);
    const CommittedPcs = binius.pcs.CommittedMlePcs(F, E);

    std.debug.print("\nfield {s} (SIZE={d}), extension {s} (SIZE={d})\n", .{ @typeName(F), F.SIZE, @typeName(E), E.SIZE });
    std.debug.print("  {s:>3} {s:>6} {s:>10} {s:>10} {s:>10} {s:>12} {s:>10}\n", .{
        "k", "n", "prove_ms", "verify_ms", "sumcheck_B", "eval_open_B", "total_KB",
    });

    var k: usize = 3;
    while (k <= 11) : (k += 1) {
        const n = @as(usize, 1) << @intCast(k);
        const x = try alloc.alloc(u4, n);
        defer alloc.free(x);
        const y = try alloc.alloc(u4, n);
        defer alloc.free(y);
        for (0..n) |i| {
            x[i] = @intCast(rnd.uintLessThan(u8, 16));
            y[i] = @intCast(rnd.uintLessThan(u8, 16));
        }

        const columns = try Adder.generateWitness(alloc, x, y);
        defer Adder.freeWitness(alloc, &columns);

        const t0 = now();
        const proof = try Stark.prove(alloc, k, &columns, &Adder.constraints, &.{}, "");
        const prove_ms: f64 = @as(f64, @floatFromInt(now() - t0)) / @as(f64, @floatFromInt(std.time.ns_per_ms));

        var roots: [Adder.num_columns]Hash.Digest = undefined;
        for (0..Adder.num_columns) |c| {
            var tree = try CommittedPcs.commit(alloc, columns[c]);
            roots[c] = tree.root();
        }
        const t1 = now();
        const ok = try Stark.verify(alloc, k, &roots, &Adder.constraints, &.{}, proof, "");
        const verify_ms: f64 = @as(f64, @floatFromInt(now() - t1)) / @as(f64, @floatFromInt(std.time.ns_per_ms));
        if (!ok) return error.VerificationFailed;

        const dmax = 2 + k; // max monomial factors (2) + k kernel tables
        const sumcheck_b = k * (dmax + 1) * E.SIZE;
        const eval_b = Adder.num_columns * n * (F.SIZE + k * 32);
        const total_b = sumcheck_b + eval_b;

        std.debug.print("  {d:>3} {d:>6} {d:>10.2} {d:>10.2} {d:>10} {d:>12} {d:>10.1}\n", .{
            k, n, prove_ms, verify_ms, sumcheck_b, eval_b, @as(f64, @floatFromInt(total_b)) / 1024.0,
        });
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const alloc = gpa.allocator();
    var prng = std.Random.DefaultPrng.init(0xbeefcafe);
    const rnd = prng.random();

    std.debug.print("binius zero-check STARK over a batch of 4-bit additions\n", .{});
    std.debug.print("(16 columns, 16 constraints; eval openings open all 2^k entries per column)\n", .{});
    try runField(Gf16, Gf16, alloc, rnd);
    try runField(Gf256, Gf256, alloc, rnd);
    try runField(Gf256, binius.tower.Gf2_128, alloc, rnd);
}
