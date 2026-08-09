const std = @import("std");
const M31 = @import("field/m31.zig").M31;
const CM31 = @import("field/cm31.zig").CM31;
const QM31 = @import("field/qm31.zig").QM31;
const Hash = @import("../core/hash/hash.zig").Hash;

/// Field-specific hashing for the M31 / CM31 / QM31 tower. Kept out of
/// `core/hash` so the core module stays agnostic to the field tower.
pub fn hashM31(v: M31) Hash.Digest {
    var buf: [M31.SIZE]u8 = undefined;
    v.toBytes(&buf);
    return Hash.hashBytes(&buf);
}

pub fn hashM31s(values: []const M31) Hash.Digest {
    var h = std.crypto.hash.Blake3.init(.{});
    var buf: [M31.SIZE]u8 = undefined;
    for (values) |v| {
        v.toBytes(&buf);
        h.update(&buf);
    }
    var out: Hash.Digest = undefined;
    h.final(&out);
    return out;
}

pub fn hashCM31(v: CM31) Hash.Digest {
    var buf: [CM31.SIZE]u8 = undefined;
    v.toBytes(&buf);
    return Hash.hashBytes(&buf);
}

pub fn hashQM31(v: QM31) Hash.Digest {
    var buf: [QM31.SIZE]u8 = undefined;
    v.toBytes(&buf);
    return Hash.hashBytes(&buf);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "field element hashing is deterministic" {
    const x = M31.fromInt(12345);
    try std.testing.expectEqualSlices(u8, &hashM31(x), &hashM31(x));
    try std.testing.expect(!std.mem.eql(u8, &hashM31(M31.fromInt(12345)), &hashM31(M31.fromInt(12346))));

    const vals = [_]M31{ M31.one(), M31.fromInt(2), M31.fromInt(3) };
    try std.testing.expectEqualSlices(u8, &hashM31s(&vals), &hashM31s(&vals));
}

test "field extension hashing" {
    const c = CM31.i();
    const q = QM31.one();
    try std.testing.expectEqualSlices(u8, &hashCM31(c), &hashCM31(c));
    try std.testing.expectEqualSlices(u8, &hashQM31(q), &hashQM31(q));
}
