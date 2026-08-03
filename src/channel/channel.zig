const std = @import("std");
const M31 = @import("../field/m31.zig").M31;
const QM31 = @import("../field/qm31.zig").QM31;
const Hash = @import("../hash/hash.zig").Hash;

/// Fiat-Shamir transcript. Both prover and verifier absorb the same messages
/// in the same order; challenges are derived deterministically from the
/// transcript state, so no randomness needs to be communicated.
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

    pub fn absorbM31(self: *Channel, v: M31) void {
        var buf: [M31.SIZE]u8 = undefined;
        v.toBytes(&buf);
        self.hasher.update(&buf);
    }

    pub fn absorbM31s(self: *Channel, values: []const M31) void {
        var buf: [M31.SIZE]u8 = undefined;
        for (values) |v| {
            v.toBytes(&buf);
            self.hasher.update(&buf);
        }
    }

    pub fn absorbQM31(self: *Channel, v: QM31) void {
        var buf: [QM31.SIZE]u8 = undefined;
        v.toBytes(&buf);
        self.hasher.update(&buf);
    }

    pub fn absorbQM31s(self: *Channel, values: []const QM31) void {
        var buf: [QM31.SIZE]u8 = undefined;
        for (values) |v| {
            v.toBytes(&buf);
            self.hasher.update(&buf);
        }
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

    /// Sample a random M31 field element.
    pub fn sampleM31(self: *Channel) M31 {
        var buf: [M31.SIZE]u8 = undefined;
        self.sampleBytes(&buf);
        return M31.fromBytes(buf);
    }

    /// Sample a random QM31 field element.
    pub fn sampleQM31(self: *Channel) QM31 {
        var buf: [QM31.SIZE]u8 = undefined;
        self.sampleBytes(&buf);
        return QM31.fromBytes(buf);
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

test "channel sampling is deterministic for same transcript" {
    var c1 = Channel.init("test");
    var c2 = Channel.init("test");
    c1.absorbM31(M31.fromInt(7));
    c2.absorbM31(M31.fromInt(7));
    try std.testing.expect(c1.sampleM31().eq(c2.sampleM31()));
}

test "channel sampling differs across transcripts" {
    var c1 = Channel.init("test");
    var c2 = Channel.init("test");
    c1.absorbM31(M31.fromInt(7));
    c2.absorbM31(M31.fromInt(8));
    // extremely unlikely to collide
    try std.testing.expect(!c1.sampleM31().eq(c2.sampleM31()));
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
