const std = @import("std");

/// Hashing utilities for the proof transcript and Merkle commitments.
/// Uses Blake3 under the hood; all functions are deterministic and
/// allocation-free. Field-specific hashing (M31/CM31/QM31) lives in
/// `src/m31/hash.zig` so this module stays field-agnostic.
pub const Hash = struct {
    pub const Digest = [32]u8;
    const Blake3 = std.crypto.hash.Blake3;

    pub fn hashBytes(msg: []const u8) Digest {
        var out: Digest = undefined;
        Blake3.hash(msg, &out, .{});
        return out;
    }

    pub fn hash2(a: Digest, b: Digest) Digest {
        var h = Blake3.init(.{});
        h.update("zig-stark:pair");
        h.update(&a);
        h.update(&b);
        var out: Digest = undefined;
        h.final(&out);
        return out;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "hash known vector (empty input)" {
    // Blake3("")
    const empty = [_]u8{};
    const d = Hash.hashBytes(&empty);
    const expected = [_]u8{
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6,
        0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
        0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7,
        0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
    };
    try std.testing.expectEqualSlices(u8, &expected, &d);
}

test "hash is deterministic and sensitive to input" {
    const a = Hash.hashBytes("hello");
    const b = Hash.hashBytes("hello");
    const c = Hash.hashBytes("hellp");
    try std.testing.expectEqualSlices(u8, &a, &b);
    try std.testing.expect(!std.mem.eql(u8, &a, &c));
}

test "hash2 differs from hashing the concatenation" {
    const a = Hash.hashBytes("a");
    const b = Hash.hashBytes("b");
    const c = Hash.hash2(a, b);
    var combined: [64]u8 = undefined;
    @memcpy(combined[0..32], &a);
    @memcpy(combined[32..64], &b);
    const d = Hash.hashBytes(&combined);
    try std.testing.expect(!std.mem.eql(u8, &c, &d));
}
