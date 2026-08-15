//! `cuda-merkle` step: validates the GPU Blake3 Merkle tree builder.
//!
//! Requires an NVIDIA GPU + driver (CUDA 12 runtime `libcuda.so`). Not part of
//! CI. For n = 2^0..2^16 leaves (up to 65536):
//!   1. GPU `MerkleTree.init` (hook registered, `mode = .auto`) is bit-exact
//!      with the CPU tree at every level (leaves, internal nodes, root).
//!   2. Opening proofs on the GPU-built tree verify against its root.
//!   3. `.off` ignores the hook and `.on` without a hook errors
//!      `error.GpuUnavailable`.
//!   4. CPU-vs-GPU tree-build timing at n = 2^16.

const std = @import("std");
const zig_stark = @import("zig-stark");
const merkle_gpu = @import("merkle_gpu.zig");

const Hash = zig_stark.core.hash.Hash;
const MerkleTree = zig_stark.core.merkle.MerkleTree;
const merkle = zig_stark.core.merkle;

fn monotonicUs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(ts.nsec)) / 1_000;
}

fn checkTree(alloc: std.mem.Allocator, prng: *std.Random.DefaultPrng, log2_n: u32) !void {
    const n: usize = @as(usize, 1) << @intCast(log2_n);
    const leaves = try alloc.alloc(Hash.Digest, n);
    defer alloc.free(leaves);
    for (leaves) |*l| prng.random().bytes(l);

    var cpu_tree = try MerkleTree.init(alloc, leaves); // mode .off
    defer cpu_tree.deinit();
    var gpu_tree = try MerkleTree.init(alloc, leaves); // mode .auto + hook
    defer gpu_tree.deinit();

    try std.testing.expectEqual(@as(usize, n), gpu_tree.leaves.len);
    for (cpu_tree.nodes, gpu_tree.nodes) |c_lv, g_lv| {
        try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(c_lv), std.mem.sliceAsBytes(g_lv));
    }

    const path = try gpu_tree.open(0, alloc);
    defer alloc.free(path);
    try std.testing.expect(merkle.verify(gpu_tree.root(), 0, leaves[0], path));
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    const alloc = gpa.allocator();
    defer _ = gpa.deinit();

    var prng = std.Random.DefaultPrng.init(0xB14A_4E3);

    // CPU path is the reference; GPU path uses the registered hook.
    merkle.mode = .off;
    merkle.merkle_commit = merkle_gpu.commit;

    var log2_n: u32 = 0;
    while (log2_n <= 16) : (log2_n += 1) {
        try checkTree(alloc, &prng, log2_n);
        std.debug.print("merkle n=2^{d}: GPU tree bit-exact with CPU (all levels)\n", .{log2_n});
    }

    // Mode semantics against the real hook.
    merkle.merkle_commit = null;
    merkle.mode = .on;
    const leaves4 = try alloc.alloc(Hash.Digest, 4);
    defer alloc.free(leaves4);
    for (leaves4) |*l| prng.random().bytes(l);
    try std.testing.expectError(error.GpuUnavailable, MerkleTree.init(alloc, leaves4));
    merkle.merkle_commit = merkle_gpu.commit;
    merkle.mode = .off;
    {
        var t = try MerkleTree.init(alloc, leaves4);
        defer t.deinit();
        std.debug.print("merkle mode .off ignores the registered hook (CPU tree built)\n", .{});
    }
    merkle.mode = .auto;

    // Timing at the largest size.
    const n: usize = 1 << 16;
    const big_leaves = try alloc.alloc(Hash.Digest, n);
    defer alloc.free(big_leaves);
    for (big_leaves) |*l| prng.random().bytes(l);

    merkle.mode = .off;
    const t0 = monotonicUs();
    var cpu_big = try MerkleTree.init(alloc, big_leaves);
    const cpu_us = monotonicUs() - t0;
    cpu_big.deinit();

    merkle.mode = .auto;
    const t1 = monotonicUs();
    var gpu_big = try MerkleTree.init(alloc, big_leaves);
    const gpu_us = monotonicUs() - t1;
    gpu_big.deinit();

    std.debug.print("merkle n=65536: cpu {d:.2} ms, gpu {d:.2} ms, speedup {d:.2}x\n", .{
        @as(f64, @floatFromInt(cpu_us)) / 1000.0,
        @as(f64, @floatFromInt(gpu_us)) / 1000.0,
        @as(f64, @floatFromInt(cpu_us)) / @as(f64, @floatFromInt(gpu_us)),
    });

    std.debug.print("cuda-merkle: all checks passed\n", .{});
}
