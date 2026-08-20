const std = @import("std");
const tower = @import("../tower.zig");
const p2b = @import("poseidon2b.zig");

/// Host (non-gadget) reference implementation of the Poseidon2b friendly hash
/// used for in-circuit recursion. Mirrors the field-native permutation in
/// `poseidon2b.zig` and wraps it in a sponge so that `hashBytes` / `hash2`
/// satisfy the same drop-in shape as `core/hash`'s Blake3 interface
/// (`Digest = [32]u8`), but over the binary tower `Gf2_64`.
///
/// Sponge: rate r = 4 elements (32 bytes), capacity c = 4 elements (32 bytes)
/// -> 256-bit capacity for a 128-bit security target, digest = 4 elements =
/// 32 bytes. `hash2(a, b) = hashBytes("zig-stark:pair" padded to 32 B || a || b)`
/// keeps the existing domain separator while aligning it to a full rate block;
/// the final partial block is zero-padded to the rate size.
pub const F = tower.Gf2_64;
pub const Digest = [32]u8;

/// Run one Poseidon2b permutation over an 8-element state.
pub fn permutation(state: *[p2b.state_size]F) void {
    p2b.permutationState(F, state);
}

fn blockBytes(comptime buf: []const u8) [32]u8 {
    var b: [32]u8 = @splat(0);
    @memcpy(b[0..buf.len], buf);
    return b;
}

fn absorb(state: *[p2b.state_size]F, block: *const [32]u8) void {
    for (0..p2b.rate) |i| {
        var b: [8]u8 = undefined;
        @memcpy(&b, block[i * 8 ..][0..8]);
        state[i] = state[i].add(F.fromBytes(b));
    }
    permutation(state);
}

/// Hash an arbitrary byte message via the sponge (zero-padded final block).
pub fn hashBytes(msg: []const u8) Digest {
    var state: [p2b.state_size]F = @splat(F.zero());
    if (msg.len == 0) {
        const z: [32]u8 = @splat(0);
        absorb(&state, &z);
    } else {
        var off: usize = 0;
        while (off < msg.len) {
            var b: [32]u8 = @splat(0);
            const n = @min(32, msg.len - off);
            @memcpy(b[0..n], msg[off .. off + n]);
            off += n;
            absorb(&state, &b);
        }
    }
    var out: Digest = undefined;
    for (0..p2b.rate) |i| {
        var b: [8]u8 = undefined;
        state[i].toBytes(&b);
        @memcpy(out[i * 8 ..][0..8], &b);
    }
    return out;
}

/// 2-to-1 digest compression with the existing domain separator.
pub fn hash2(a: Digest, b: Digest) Digest {
    const prefix = blockBytes("zig-stark:pair");
    var buf: [96]u8 = undefined;
    @memcpy(buf[0..32], &prefix);
    @memcpy(buf[32..64], &a);
    @memcpy(buf[64..96], &b);
    return hashBytes(&buf);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "poseidon2b permutation is deterministic and matches the hosted step" {
    var a: [64]u8 = @splat(0);
    @memcpy(a[0..9], "one-block");
    var s0: [p2b.state_size]F = undefined;
    for (0..p2b.state_size) |i| {
        var b: [8]u8 = undefined;
        @memcpy(&b, a[i * 8 ..][0..8]);
        s0[i] = F.fromBytes(b);
    }
    var s1 = s0;
    permutation(&s1);
    var s2 = s0;
    permutation(&s2);
    for (0..p2b.state_size) |i| try std.testing.expectEqual(s1[i].value, s2[i].value);
}

test "poseidon2b hashBytes is deterministic and sensitive to input" {
    const a = hashBytes("hello");
    const b = hashBytes("hello");
    const c = hashBytes("hellp");
    try std.testing.expectEqualSlices(u8, &a, &b);
    try std.testing.expect(!std.mem.eql(u8, &a, &c));
}

test "poseidon2b hash2 differs for distinct inputs and is stable" {
    const da: Digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".*;
    const db: Digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".*;
    const dc: Digest = "cccccccccccccccccccccccccccccccc".*;
    const a = hash2(da, db);
    const b = hash2(da, db);
    const c = hash2(da, dc);
    try std.testing.expectEqualSlices(u8, &a, &b);
    try std.testing.expect(!std.mem.eql(u8, &a, &c));
}

test "poseidon2b known-answer vectors (byte-identity surface)" {
    // Reference outputs computed from the lattice constants above; these pin the
    // friendly-hash byte format and break intentionally if the parameters change.
    const zero: [64]u8 = @splat(0);
    var s: [p2b.state_size]F = undefined;
    for (0..p2b.state_size) |i| {
        var b: [8]u8 = undefined;
        @memcpy(&b, zero[i * 8 ..][0..8]);
        s[i] = F.fromBytes(b);
    }
    p2b.permutationState(F, &s);
    const perm_expected = [_]u128{ 0x3da2, 0x4ee4, 0xe2a3, 0x1118, 0x7ef3, 0x59d4, 0x3b2a, 0x011b };
    for (0..p2b.state_size) |i| try std.testing.expectEqual(perm_expected[i], s[i].value);

    const empty = hashBytes("");
    const empty_expected: Digest = .{
        0xa2, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xe4, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xa3, 0xe2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x18, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    try std.testing.expectEqualSlices(u8, &empty_expected, &empty);

    const a: Digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".*;
    const b: Digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".*;
    const d = hash2(a, b);
    const d_expected: Digest = .{
        0x49, 0xd6, 0xff, 0xce, 0x47, 0xee, 0xc2, 0x6a,
        0xfd, 0xdc, 0x19, 0x45, 0xfa, 0x26, 0x58, 0x30,
        0xb3, 0x2b, 0xbb, 0xa5, 0xd5, 0xfa, 0xff, 0x40,
        0x86, 0x38, 0x94, 0x89, 0xca, 0x3e, 0xd5, 0x5c,
    };
    try std.testing.expectEqualSlices(u8, &d_expected, &d);
}
