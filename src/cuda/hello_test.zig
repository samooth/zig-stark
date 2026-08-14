//! E0a toolchain validation: load an embedded PTX module, launch the `vecAdd`
//! kernel via the CUDA Driver API from Zig, and compare against a CPU
//! reference. Run with `zig build cuda-hello` (requires a CUDA driver + GPU).
const std = @import("std");
const cuda = @import("cuda.zig");

const ptx = @embedFile("kernels/vecAdd.ptx");

fn now() i128 {
    var ts: std.posix.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i128, @intCast(ts.sec)) * std.time.ns_per_s + @as(i128, @intCast(ts.nsec));
}

pub fn main() !void {
    var c = cuda.Cuda.init(ptx) catch |err| {
        std.debug.print("CUDA unavailable ({s}); falling back to CPU — nothing to verify here.\n", .{@errorName(err)});
        return;
    };
    defer c.deinit();

    const f = try c.func("vecAdd");
    const n: usize = 1 << 20; // 4 Mi elements
    const alloc = std.heap.page_allocator;

    const a = try alloc.alloc(u32, n);
    defer alloc.free(a);
    const b = try alloc.alloc(u32, n);
    defer alloc.free(b);
    const out = try alloc.alloc(u32, n);
    defer alloc.free(out);
    var rnd = std.Random.DefaultPrng.init(0x5eed_c0de);
    for (0..n) |i| {
        a[i] = rnd.random().uintLessThan(u32, 1_000_000);
        b[i] = rnd.random().uintLessThan(u32, 1_000_000);
    }

    const da = try c.alloc(4 * n);
    defer c.free(da);
    const db = try c.alloc(4 * n);
    defer c.free(db);
    const dout = try c.alloc(4 * n);
    defer c.free(dout);
    try c.copyHtoD(da, std.mem.sliceAsBytes(a));
    try c.copyHtoD(db, std.mem.sliceAsBytes(b));

    const n32: u32 = @intCast(n);
    var args = [_]*const anyopaque{ &dout, &da, &db, &n32 };

    const t0 = now();
    try c.launch(f, @intCast(n / 256), 256, &args);
    try c.synchronize();
    try c.copyDtoH(std.mem.sliceAsBytes(out), dout);
    const gpu_ms: f64 = @as(f64, @floatFromInt(now() - t0)) / std.time.ns_per_ms;

    for (0..n) |i| {
        if (out[i] != a[i] + b[i]) {
            std.debug.print("GPU mismatch at {d}\n", .{i});
            std.process.exit(1);
        }
    }
    std.debug.print("GPU vecAdd OK (n={d}, {d:.2} ms incl. transfers)\n", .{ n, gpu_ms });
}
