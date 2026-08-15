//! E1a validation: the GPU Gf256 tower multiplication must be bit-exact with
//! `tower.zig` (TowerField(3) Karatsuba recursion). Run with `zig build cuda-gf`.
const std = @import("std");
const cuda = @import("cuda.zig");
const zig_stark = @import("zig-stark");

const ptx = @embedFile("kernels/gf256.ptx");

pub fn main() !void {
    var c = cuda.Cuda.init(ptx) catch |err| {
        std.debug.print("CUDA unavailable ({s}); nothing to verify here.\n", .{@errorName(err)});
        return;
    };
    defer c.deinit();

    const f = try c.func("gf_mul");
    const n: usize = 1 << 20;
    const alloc = std.heap.page_allocator;

    const a = try alloc.alloc(u8, n);
    defer alloc.free(a);
    const b = try alloc.alloc(u8, n);
    defer alloc.free(b);
    const out = try alloc.alloc(u8, n);
    defer alloc.free(out);
    var rnd = std.Random.DefaultPrng.init(0x6f6f);
    for (0..n) |i| {
        a[i] = rnd.random().int(u8);
        b[i] = rnd.random().int(u8);
    }

    const da = try c.alloc(n);
    defer c.free(da);
    const db = try c.alloc(n);
    defer c.free(db);
    const dout = try c.alloc(n);
    defer c.free(dout);
    try c.copyHtoD(da, a);
    try c.copyHtoD(db, b);

    const n32: u32 = @intCast(n);
    var args = [_]*const anyopaque{ &dout, &da, &db, &n32 };
    try c.launch(f, @intCast(n / 256), 256, &args);
    try c.synchronize();
    try c.copyDtoH(out, dout);

    for (0..n) |i| {
        const want = zig_stark.binius.tower.Gf256.fromInt(a[i]).mul(zig_stark.binius.tower.Gf256.fromInt(b[i])).value;
        if (out[i] != @as(u8, @intCast(want))) {
            std.debug.print("Gf256 mul mismatch at {d}: a={d} b={d} gpu={d} cpu={d}\n", .{ i, a[i], b[i], out[i], want });
            std.process.exit(1);
        }
    }
    std.debug.print("GPU Gf256 mul bit-exact with tower.zig over {d} samples\n", .{n});
}
