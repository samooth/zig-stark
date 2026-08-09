const std = @import("std");
const M31 = @import("m31.zig").M31;

pub const CM31 = struct {
    c0: M31,
    c1: M31,

    pub fn new(c0: M31, c1: M31) CM31 {
        return .{ .c0 = c0, .c1 = c1 };
    }

    pub fn fromM31(x: M31) CM31 {
        return .{ .c0 = x, .c1 = M31.zero() };
    }

    pub fn add(self: CM31, other: CM31) CM31 {
        return .{
            .c0 = self.c0.add(other.c0),
            .c1 = self.c1.add(other.c1),
        };
    }

    pub fn sub(self: CM31, other: CM31) CM31 {
        return .{
            .c0 = self.c0.sub(other.c0),
            .c1 = self.c1.sub(other.c1),
        };
    }

    pub fn mul(self: CM31, other: CM31) CM31 {
        const ac = self.c0.mul(other.c0);
        const bd = self.c1.mul(other.c1);
        const ad = self.c0.mul(other.c1);
        const bc = self.c1.mul(other.c0);
        return .{
            .c0 = ac.sub(bd),
            .c1 = ad.add(bc),
        };
    }

    pub fn neg(self: CM31) CM31 {
        return .{ .c0 = self.c0.neg(), .c1 = self.c1.neg() };
    }

    pub fn inv(self: CM31) CM31 {
        const norm = self.c0.mul(self.c0).add(self.c1.mul(self.c1));
        const norm_inv = norm.inv();
        return .{
            .c0 = self.c0.mul(norm_inv),
            .c1 = self.c1.neg().mul(norm_inv),
        };
    }

    pub fn eq(self: CM31, other: CM31) bool {
        return self.c0.eq(other.c0) and self.c1.eq(other.c1);
    }

    pub fn zero() CM31 {
        return .{ .c0 = M31.zero(), .c1 = M31.zero() };
    }
    pub fn one() CM31 {
        return .{ .c0 = M31.one(), .c1 = M31.zero() };
    }
    pub fn i() CM31 {
        return .{ .c0 = M31.zero(), .c1 = M31.one() };
    }

    pub fn mulByI(self: CM31) CM31 {
        return .{ .c0 = self.c1.neg(), .c1 = self.c0 };
    }

    pub const SIZE = 8;

    pub fn toBytes(self: CM31, out: *[SIZE]u8) void {
        self.c0.toBytes(out[0..4]);
        self.c1.toBytes(out[4..8]);
    }

    pub fn fromBytes(bytes: [SIZE]u8) CM31 {
        return .{
            .c0 = M31.fromBytes(bytes[0..4].*),
            .c1 = M31.fromBytes(bytes[4..8].*),
        };
    }
};

fn refCMAdd(a: CM31, b: CM31) CM31 {
    return .{
        .c0 = .{ .value = @as(u32, @intCast((@as(u64, a.c0.value) + b.c0.value) % M31.MODULUS_U64)) },
        .c1 = .{ .value = @as(u32, @intCast((@as(u64, a.c1.value) + b.c1.value) % M31.MODULUS_U64)) },
    };
}

fn refCMMul(a: CM31, b: CM31) CM31 {
    const ac = (@as(u64, a.c0.value) * b.c0.value) % M31.MODULUS_U64;
    const bd = (@as(u64, a.c1.value) * b.c1.value) % M31.MODULUS_U64;
    const ad = (@as(u64, a.c0.value) * b.c1.value) % M31.MODULUS_U64;
    const bc = (@as(u64, a.c1.value) * b.c0.value) % M31.MODULUS_U64;
    return .{
        .c0 = .{ .value = @as(u32, @intCast((ac + M31.MODULUS_U64 - bd) % M31.MODULUS_U64)) },
        .c1 = .{ .value = @as(u32, @intCast((ad + bc) % M31.MODULUS_U64)) },
    };
}

test "CM31 arithmetic against u64 reference" {
    var prng = std.Random.DefaultPrng.init(5);
    const rnd = prng.random();
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        const a = CM31.new(M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS)), M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS)));
        const b = CM31.new(M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS)), M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS)));
        try std.testing.expect(refCMAdd(a, b).eq(a.add(b)));
        try std.testing.expect(refCMMul(a, b).eq(a.mul(b)));
        // sub == add(neg)
        try std.testing.expect(a.add(b.neg()).eq(a.sub(b)));
    }
}

test "CM31 extension identities" {
    const i_ = CM31.i();
    try std.testing.expect(i_.mul(i_).eq(CM31.one().neg()));
    const one = CM31.one();
    const zero = CM31.zero();
    try std.testing.expect(zero.add(one).eq(one));
    try std.testing.expect(one.mul(one).eq(one));
    try std.testing.expect(i_.mulByI().eq(one.neg()));
    try std.testing.expect(one.mulByI().eq(i_));
    try std.testing.expect(i_.mulByI().mulByI().eq(i_.neg()));
    try std.testing.expect(i_.mulByI().mulByI().mulByI().eq(one));
}

test "CM31 inverse" {
    var prng = std.Random.DefaultPrng.init(6);
    const rnd = prng.random();
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var a = CM31.new(M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS)), M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS)));
        if (a.c0.value == 0 and a.c1.value == 0) a = CM31.one();
        try std.testing.expect(a.mul(a.inv()).eq(CM31.one()));
    }
}

test "CM31 serialization round-trip" {
    var prng = std.Random.DefaultPrng.init(10);
    const rnd = prng.random();
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const x = CM31.new(M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS)), M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS)));
        var buf: [CM31.SIZE]u8 = undefined;
        x.toBytes(&buf);
        const y = CM31.fromBytes(buf);
        try std.testing.expect(x.eq(y));
    }
    var buf: [CM31.SIZE]u8 = undefined;
    CM31.i().toBytes(&buf);
    try std.testing.expectEqual(@as(u8, 0), buf[0]);
    try std.testing.expectEqual(@as(u8, 1), buf[4]);
}
