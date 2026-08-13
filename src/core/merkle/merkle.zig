const std = @import("std");
const Hash = @import("../hash/hash.zig").Hash;

/// Binary Merkle tree over a power-of-two number of leaves.
/// Leaves are `Hash.Digest` values (produced by the caller, typically from
/// field-element hashing); internal nodes are `hash2(left, right)`.
///
/// Owns its memory and stores the allocator it was built with; release with
/// `deinit()` (no allocator argument).
pub const MerkleTree = struct {
    allocator: std.mem.Allocator,
    leaves: []Hash.Digest,
    nodes: [][]Hash.Digest, // level 0 = leaves, level h = parents

    pub const Root = Hash.Digest;

    pub fn init(allocator: std.mem.Allocator, leaves: []const Hash.Digest) !MerkleTree {
        const n = leaves.len;
        std.debug.assert(n > 0 and (n & (n - 1)) == 0); // power of two

        const depth: usize = @intCast(std.math.log2_int(usize, n)); // 0 for n = 1
        const num_levels = depth + 1;

        const nodes = try allocator.alloc([]Hash.Digest, num_levels);
        errdefer allocator.free(nodes);

        var len = n;
        for (0..num_levels) |level| {
            nodes[level] = try allocator.alloc(Hash.Digest, len);
            errdefer allocator.free(nodes[level]);
            len >>= 1;
        }

        const leaf_copy = nodes[0];
        @memcpy(leaf_copy, leaves);

        for (0..depth) |level| {
            const half = nodes[level].len / 2;
            for (0..half) |i| {
                nodes[level + 1][i] = Hash.hash2(nodes[level][2 * i], nodes[level][2 * i + 1]);
            }
        }

        return .{ .allocator = allocator, .leaves = leaf_copy, .nodes = nodes };
    }

    pub fn root(self: MerkleTree) Root {
        return self.nodes[self.nodes.len - 1][0];
    }

    pub fn deinit(self: *MerkleTree) void {
        for (self.nodes) |lv| self.allocator.free(lv);
        self.allocator.free(self.nodes);
    }

    /// The opening proof for leaf `index`: the sibling digests along the path.
    pub fn open(self: MerkleTree, index: usize, allocator: std.mem.Allocator) ![]Hash.Digest {
        std.debug.assert(index < self.leaves.len);
        const path_len: usize = @intCast(std.math.log2_int(usize, self.leaves.len));
        const path = try allocator.alloc(Hash.Digest, path_len);
        var idx = index;
        for (0..path_len) |level| {
            const sibling = idx ^ 1;
            path[level] = self.nodes[level][sibling];
            idx >>= 1;
        }
        return path;
    }
};

/// Standalone verification of a Merkle opening.
pub fn verify(
    root: Hash.Digest,
    index: usize,
    leaf: Hash.Digest,
    path: []const Hash.Digest,
) bool {
    var digest = leaf;
    var idx = index;
    for (path) |sibling| {
        if (idx & 1 == 0) {
            digest = Hash.hash2(digest, sibling);
        } else {
            digest = Hash.hash2(sibling, digest);
        }
        idx >>= 1;
    }
    return std.mem.eql(u8, &digest, &root);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "merkle root is deterministic" {
    const alloc = std.testing.allocator;
    const leaves = [_]Hash.Digest{ Hash.hashBytes("a"), Hash.hashBytes("b"), Hash.hashBytes("c"), Hash.hashBytes("d") };
    var t1 = try MerkleTree.init(alloc, &leaves);
    defer t1.deinit();
    var t2 = try MerkleTree.init(alloc, &leaves);
    defer t2.deinit();
    try std.testing.expectEqualSlices(u8, &t1.root(), &t2.root());
}

test "merkle open/verify round-trips" {
    const alloc = std.testing.allocator;
    const n = 16;
    var leaves: [n]Hash.Digest = undefined;
    for (0..n) |i| {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, i, .little);
        leaves[i] = Hash.hashBytes(&buf);
    }
    var tree = try MerkleTree.init(alloc, &leaves);
    defer tree.deinit();

    for (0..n) |i| {
        const path = try tree.open(i, alloc);
        defer alloc.free(path);
        try std.testing.expect(verify(tree.root(), i, leaves[i], path));
    }
}

test "merkle tampered leaf fails" {
    const alloc = std.testing.allocator;
    const n = 8;
    var leaves: [n]Hash.Digest = undefined;
    for (0..n) |i| {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, i, .little);
        leaves[i] = Hash.hashBytes(&buf);
    }
    var tree = try MerkleTree.init(alloc, &leaves);
    defer tree.deinit();

    const path = try tree.open(3, alloc);
    defer alloc.free(path);
    // correct leaf verifies
    try std.testing.expect(verify(tree.root(), 3, leaves[3], path));
    // wrong leaf fails
    const wrong = Hash.hashBytes("tampered");
    try std.testing.expect(!verify(tree.root(), 3, wrong, path));
    // wrong index fails
    try std.testing.expect(!verify(tree.root(), 4, leaves[3], path));
}

test "merkle single leaf" {
    const alloc = std.testing.allocator;
    const leaves = [_]Hash.Digest{Hash.hashBytes("solo")};
    var tree = try MerkleTree.init(alloc, &leaves);
    defer tree.deinit();
    try std.testing.expectEqualSlices(u8, &leaves[0], &tree.root());
    const path = try tree.open(0, alloc);
    defer alloc.free(path);
    try std.testing.expectEqual(@as(usize, 0), path.len);
    try std.testing.expect(verify(tree.root(), 0, leaves[0], path));
}
