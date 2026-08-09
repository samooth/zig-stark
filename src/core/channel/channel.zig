const std = @import("std");
const Hash = @import("../hash/hash.zig").Hash;

/// Fiat-Shamir transcript. Both prover and verifier absorb the same messages
/// in the same order; challenges are derived deterministically from the
/// transcript state, so no randomness needs to be communicated.
///
/// The channel is field-agnostic: field elements are absorbed/sampled through
/// their `toBytes`/`fromBytes`/`SIZE` interface (see `absorb`, `absorbMany`,
/// `sample`).
pub const Channel = struct {
    const Blake3 = std.crypto.hash.Blake3;

    hasher: Blake3,

    pub fn init(domain_separator: []const u8) Channel {
        var h = Blake3.init(.{});
        h.update("zig-stark:channel");
        h.update(domain_separator);
        return .{ .hasher = h };
    }

    pub fn absorbBytes(self: *Channel, data: []const u8) void {
        self.hasher.update(data);
    }

    pub fn absorbDigest(self: *Channel, digest: Hash.Digest) void {
        self.hasher.update(&digest);
    }

    /// Absorb a single serializable element (any type exposing
    /// `SIZE`, `toBytes`, `fromBytes`).
    pub fn absorb(self: *Channel, value: anytype) void {
        const T = @TypeOf(value);
        var buf: [T.SIZE]u8 = undefined;
        value.toBytes(&buf);
        self.hasher.update(&buf);
    }

    /// Absorb a slice of serializable elements.
    pub fn absorbMany(self: *Channel, values: anytype) void {
        for (values) |v| self.absorb(v);
    }

    fn sampleBytes(self: *Channel, out: []u8) void {
        // Derive challenge bytes from the current transcript state and absorb
        // the derived bytes back into the transcript, so later samples are
        // always fresh (correct Fiat-Shamir).
        var counter: u64 = 0;
        var remaining = out;
        while (remaining.len > 0) {
            var snapshot = self.hasher;
            snapshot.update("zig-stark:sample");
            var cbuf: [8]u8 = undefined;
            std.mem.writeInt(u64, &cbuf, counter, .little);
            snapshot.update(&cbuf);
            var block: [32]u8 = undefined;
            snapshot.final(&block);
            self.hasher.update(&block);
            const n = @min(remaining.len, block.len);
            @memcpy(remaining[0..n], block[0..n]);
            remaining = remaining[n..];
            counter += 1;
        }
    }

    /// Sample a random element of a serializable field type `T`.
    pub fn sample(self: *Channel, comptime T: type) T {
        var buf: [T.SIZE]u8 = undefined;
        self.sampleBytes(&buf);
        return T.fromBytes(buf);
    }

    /// Sample a random index in [0, n).
    pub fn sampleIndex(self: *Channel, n: usize) usize {
        std.debug.assert(n > 0);
        const bits: usize = @intCast(std.math.log2_int(usize, n) + 1);
        const bytes_needed = (bits + 7) / 8;
        var buf: [8]u8 = undefined;
        self.sampleBytes(buf[0..bytes_needed]);
        var value: usize = 0;
        for (0..bytes_needed) |i| {
            value = (value << 8) | buf[i];
        }
        // rejection-sample a uniform value in [0, n)
        const mask: usize = (@as(usize, 1) << @intCast(bits)) - 1;
        var v = value & mask;
        while (v >= n) {
            self.sampleBytes(buf[0..bytes_needed]);
            value = 0;
            for (0..bytes_needed) |i| {
                value = (value << 8) | buf[i];
            }
            v = value & mask;
        }
        return v;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const M31 = @import("../../m31/field/m31.zig").M31;
const QM31 = @import("../../m31/field/qm31.zig").QM31;

test "channel sampling is deterministic for same transcript" {
    var c1 = Channel.init("test");
    var c2 = Channel.init("test");
    c1.absorb(M31.fromInt(7));
    c2.absorb(M31.fromInt(7));
    try std.testing.expect(c1.sample(M31).eq(c2.sample(M31)));
}

test "channel sampling differs across transcripts" {
    var c1 = Channel.init("test");
    var c2 = Channel.init("test");
    c1.absorb(M31.fromInt(7));
    c2.absorb(M31.fromInt(8));
    // extremely unlikely to collide
    try std.testing.expect(!c1.sample(M31).eq(c2.sample(M31)));
}

test "channel sampleIndex is in range" {
    var c = Channel.init("idx");
    const sizes = [_]usize{ 1, 2, 3, 7, 8, 100, 1024 };
    for (sizes) |n| {
        var i: usize = 0;
        while (i < 50) : (i += 1) {
            const v = c.sampleIndex(n);
            try std.testing.expect(v < n);
        }
    }
}

test "channel sampleIndex covers range roughly uniformly" {
    var c = Channel.init("uniform");
    const n = 8;
    var counts = [_]usize{0} ** 8;
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        const v = c.sampleIndex(n);
        std.debug.assert(v < n);
        counts[v] += 1;
    }
    for (counts) |cnt| {
        // 4000/8 = 500 expected; allow wide margin
        try std.testing.expect(cnt > 200 and cnt < 800);
    }
}

test "channel generic sample QM31" {
    var c = Channel.init("qm31");
    const v = c.sample(QM31);
    // 16-byte element must reduce to a valid QM31 (serialization round-trips)
    var buf: [QM31.SIZE]u8 = undefined;
    v.toBytes(&buf);
    const back = QM31.fromBytes(buf);
    try std.testing.expect(back.eq(v));
}
