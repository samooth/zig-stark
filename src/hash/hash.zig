const std = @import("std");
const M31 = @import("../field/m31.zig").M31;
const CM31 = @import("../field/cm31.zig").CM31;
const QM31 = @import("../field/qm31.zig").QM31;

/// Hashing utilities for the proof transcript and Merkle commitments.
/// Uses Blake3 under the hood; all functions are deterministic and
/// allocation-free.
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

    pub fn hashM31(v: M31) Digest {
        var buf: [M31.SIZE]u8 = undefined;
        v.toBytes(&buf);
        return hashBytes(&buf);
    }

    pub fn hashM31s(values: []const M31) Digest {
        var h = Blake3.init(.{});
        var buf: [M31.SIZE]u8 = undefined;
        for (values) |v| {
            v.toBytes(&buf);
            h.update(&buf);
        }
        var out: Digest = undefined;
        h.final(&out);
        return out;
    }

    pub fn hashCM31(v: CM31) Digest {
        var buf: [CM31.SIZE]u8 = undefined;
        v.toBytes(&buf);
        return hashBytes(&buf);
    }

    pub fn hashQM31(v: QM31) Digest {
        var buf: [QM31.SIZE]u8 = undefined;
        v.toBytes(&buf);
        return hashBytes(&buf);
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

test "field element hashing is deterministic" {
    const x = M31.fromInt(12345);
    try std.testing.expectEqualSlices(u8, &Hash.hashM31(x), &Hash.hashM31(x));
    try std.testing.expect(!std.mem.eql(u8, &Hash.hashM31(M31.fromInt(12345)), &Hash.hashM31(M31.fromInt(12346))));

    const vals = [_]M31{ M31.one(), M31.fromInt(2), M31.fromInt(3) };
    try std.testing.expectEqualSlices(u8, &Hash.hashM31s(&vals), &Hash.hashM31s(&vals));
}

test "field extension hashing" {
    const c = CM31.i();
    const q = QM31.one();
    try std.testing.expectEqualSlices(u8, &Hash.hashCM31(c), &Hash.hashCM31(c));
    try std.testing.expectEqualSlices(u8, &Hash.hashQM31(q), &Hash.hashQM31(q));
}
