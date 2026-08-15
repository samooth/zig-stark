//! GPU Merkle tree builder, registered via the `merkle_commit` hook in
//! `core/merkle/merkle.zig`. `enable()` registers it; while registered,
//! `MerkleTree.init` runs the internal `hash2` reduce on the GPU (one
//! `merkle_layer` launch per level) and copies every level back, so opening
//! proofs keep working. Leaves are still hashed on the CPU (each caller
//! serializes field bytes differently). Returns `null` (CPU fallback) when no
//! GPU/driver is present.

const std = @import("std");
const cuda = @import("cuda.zig");
const zig_stark = @import("zig-stark");

const Hash = zig_stark.core.hash.Hash;
const MerkleTree = zig_stark.core.merkle.MerkleTree;

const ptx = @embedFile("kernels/merkle.ptx");

/// Lazily-initialized CUDA context + module (one per process).
var gpu: ?cuda.Cuda = null;
var ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var mutex: std.atomic.Mutex = .unlocked;

fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.atomic.spinLoopHint();
}

fn getCuda() ?*cuda.Cuda {
    if (!ready.load(.acquire)) {
        lockSpin(&mutex);
        if (!ready.load(.monotonic)) {
            gpu = cuda.Cuda.init(ptx) catch null;
            ready.store(true, .release);
        }
        mutex.unlock();
    }
    return if (gpu) |*g| g else null;
}

/// Signature-compatible with `core.merkle.MerkleCommitFn`. Returns `null`
/// (CPU fallback) when CUDA is unavailable, a fully built `MerkleTree`
/// otherwise.
pub fn commit(
    allocator: std.mem.Allocator,
    leaves: []const Hash.Digest,
) anyerror!?MerkleTree {
    const n = leaves.len;

    // Trivial tree (no internal nodes): avoid a GPU round-trip.
    if (n == 1) {
        const nodes = try allocator.alloc([]Hash.Digest, 1);
        errdefer allocator.free(nodes);
        nodes[0] = try allocator.dupe(Hash.Digest, leaves);
        errdefer allocator.free(nodes[0]);
        return .{ .allocator = allocator, .leaves = nodes[0], .nodes = nodes };
    }

    const c = getCuda() orelse return null;
    const f = try c.func("merkle_layer");

    const depth: usize = @intCast(std.math.log2_int(usize, n));
    const nodes = try allocator.alloc([]Hash.Digest, depth + 1);
    var alloc_levels: usize = 0;
    errdefer {
        for (0..alloc_levels) |i| allocator.free(nodes[i]);
        allocator.free(nodes);
    }
    nodes[0] = try allocator.dupe(Hash.Digest, leaves);
    alloc_levels = 1;

    const d_a = try c.alloc(n * 32);
    defer c.free(d_a);
    const d_b = try c.alloc(n * 32);
    defer c.free(d_b);
    try c.copyHtoD(d_a, std.mem.sliceAsBytes(leaves));

    var src = d_a;
    var dst = d_b;
    var len = n;
    var level: usize = 1;
    while (level <= depth) : (level += 1) {
        const out_len = len / 2;
        nodes[level] = try allocator.alloc(Hash.Digest, out_len);
        alloc_levels = level + 1;
        const n32: u32 = @intCast(len);
        const grid: u32 = @intCast((out_len + 255) / 256);
        try c.launch(f, grid, 256, &[_]*const anyopaque{ &src, &dst, &n32 });
        try c.copyDtoH(std.mem.sliceAsBytes(nodes[level]), dst);
        std.mem.swap(cuda.CUdeviceptr, &src, &dst);
        len = out_len;
    }

    return .{ .allocator = allocator, .leaves = nodes[0], .nodes = nodes };
}

/// Enable the GPU accelerator (call once at startup of a CUDA-enabled host).
pub fn enable() void {
    const merkle = zig_stark.core.merkle;
    merkle.merkle_commit = commit;
}
