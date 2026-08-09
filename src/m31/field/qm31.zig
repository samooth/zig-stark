const std = @import("std");
const M31 = @import("m31.zig").M31;
const CM31 = @import("cm31.zig").CM31;

pub const QM31 = struct {
    a: CM31,
    b: CM31,

    pub fn new(a: CM31, b: CM31) QM31 {
        return .{ .a = a, .b = b };
    }

    pub fn fromM31(x: M31) QM31 {
        return .{ .a = CM31.fromM31(x), .b = CM31.zero() };
    }

    pub fn add(self: QM31, other: QM31) QM31 {
        return .{ .a = self.a.add(other.a), .b = self.b.add(other.b) };
    }

    pub fn sub(self: QM31, other: QM31) QM31 {
        return .{ .a = self.a.sub(other.a), .b = self.b.sub(other.b) };
    }

    pub fn mul(self: QM31, other: QM31) QM31 {
        const ab0 = self.a.mul(other.a);
        const ab1 = self.b.mul(other.b);
        const cross = self.a.add(self.b).mul(other.a.add(other.b));
        return .{
            .a = ab0.sub(ab1.mulByI()),
            .b = cross.sub(ab0).sub(ab1),
        };
    }

    pub fn neg(self: QM31) QM31 {
        return .{ .a = self.a.neg(), .b = self.b.neg() };
    }

    pub fn inv(self: QM31) QM31 {
        const a2 = self.a.mul(self.a);
        const b2i = self.b.mul(self.b).mulByI();
        const norm = a2.add(b2i);
        const norm_inv = norm.inv();
        return .{
            .a = self.a.mul(norm_inv),
            .b = self.b.neg().mul(norm_inv),
        };
    }

    pub fn eq(self: QM31, other: QM31) bool {
        return self.a.eq(other.a) and self.b.eq(other.b);
    }

    /// Square-and-multiply exponentiation. `exp` fits in 64 bits, which
    /// covers every exponent used by the group operations in this codebase
    /// (the QM31 multiplicative group has order p^2 - 1 with p = 2^31 - 1).
    pub fn pow(self: QM31, exp: u64) QM31 {
        var base = self;
        var e = exp;
        var result = QM31.one();
        while (e > 0) {
            if (e & 1 != 0) result = result.mul(base);
            base = base.mul(base);
            e >>= 1;
        }
        return result;
    }

    pub fn zero() QM31 {
        return .{ .a = CM31.zero(), .b = CM31.zero() };
    }
    pub fn one() QM31 {
        return .{ .a = CM31.one(), .b = CM31.zero() };
    }

    pub const SIZE = 16;

    /// A primitive 2^32-th root of unity: the QM31 multiplicative group has
    /// order p^2 - 1 = 2^32 * (2^30 - 1), so roots of order up to 2^32 exist.
    pub const TWO_ADIC_ROOT: QM31 = fromBytes(.{
        0x60, 0x1f, 0x3d, 0x34, 0x32, 0x39, 0xa0, 0x6a,
        0xa0, 0xd6, 0x51, 0x61, 0x91, 0xe7, 0x86, 0x3e,
    });

    /// A primitive 2^log_size-th root of unity (0 <= log_size <= 32).
    pub fn primitiveRootOfUnity(log_size: u64) QM31 {
        std.debug.assert(log_size <= 32);
        return TWO_ADIC_ROOT.pow(@as(u64, 1) << @intCast(32 - log_size));
    }

    pub fn toBytes(self: QM31, out: *[SIZE]u8) void {
        self.a.toBytes(out[0..8]);
        self.b.toBytes(out[8..16]);
    }

    pub fn fromBytes(bytes: [SIZE]u8) QM31 {
        return .{
            .a = CM31.fromBytes(bytes[0..8].*),
            .b = CM31.fromBytes(bytes[8..16].*),
        };
    }
};

fn refQMMul(a: QM31, b: QM31) QM31 {
    // (a0 + b0·j)(a1 + b1·j) with j^2 = -i
    const ab0 = refCMMul(a.a, b.a);
    const ab1 = refCMMul(a.b, b.b);
    const cross = refCMAdd(a.a, a.b);
    const other = refCMAdd(b.a, b.b);
    const cross_mul = refCMMul(cross, other);
    return .{
        .a = refCMSub(ab0, refCMMulByI(ab1)),
        .b = refCMSub(refCMSub(cross_mul, ab0), ab1),
    };
}

fn refCMMulByI(x: CM31) CM31 {
    return .{ .c0 = .{ .value = if (x.c1.value == 0) 0 else M31.MODULUS - x.c1.value }, .c1 = x.c0 };
}

fn refCMAdd(a: CM31, b: CM31) CM31 {
    return .{
        .c0 = .{ .value = @as(u32, @intCast((@as(u64, a.c0.value) + b.c0.value) % M31.MODULUS_U64)) },
        .c1 = .{ .value = @as(u32, @intCast((@as(u64, a.c1.value) + b.c1.value) % M31.MODULUS_U64)) },
    };
}

fn refCMSub(a: CM31, b: CM31) CM31 {
    return .{
        .c0 = .{ .value = @as(u32, @intCast((@as(u64, a.c0.value) + M31.MODULUS_U64 - b.c0.value) % M31.MODULUS_U64)) },
        .c1 = .{ .value = @as(u32, @intCast((@as(u64, a.c1.value) + M31.MODULUS_U64 - b.c1.value) % M31.MODULUS_U64)) },
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

fn randCM31(rnd: std.Random) CM31 {
    return CM31.new(M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS)), M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS)));
}

test "QM31 arithmetic against reference" {
    var prng = std.Random.DefaultPrng.init(21);
    const rnd = prng.random();
    var i: usize = 0;
    while (i < 300) : (i += 1) {
        const a = QM31.new(randCM31(rnd), randCM31(rnd));
        const b = QM31.new(randCM31(rnd), randCM31(rnd));
        // add
        try std.testing.expect(a.add(b).a.eq(refCMAdd(a.a, b.a)));
        try std.testing.expect(a.add(b).b.eq(refCMAdd(a.b, b.b)));
        // sub
        try std.testing.expect(a.sub(b).a.eq(refCMSub(a.a, b.a)));
        try std.testing.expect(a.sub(b).b.eq(refCMSub(a.b, b.b)));
        // mul
        const ref = refQMMul(a, b);
        try std.testing.expect(a.mul(b).a.eq(ref.a));
        try std.testing.expect(a.mul(b).b.eq(ref.b));
    }
}

test "QM31 tower identities" {
    // embed M31: one(), and check extension relation b-multiplication uses j^2 = -i
    const one = QM31.one();
    const zero = QM31.zero();
    try std.testing.expect(one.add(zero).eq(one));
    try std.testing.expect(one.mul(one).eq(one));
    // (0 + 1·j)^2 should equal -i embedded
    const j = QM31.new(CM31.zero(), CM31.one());
    const minus_i = QM31.new(CM31.i().neg(), CM31.zero());
    try std.testing.expect(j.mul(j).eq(minus_i));
}

test "QM31 inverse" {
    var prng = std.Random.DefaultPrng.init(22);
    const rnd = prng.random();
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var a = QM31.new(randCM31(rnd), randCM31(rnd));
        if (a.a.c0.value == 0 and a.a.c1.value == 0 and a.b.c0.value == 0 and a.b.c1.value == 0) {
            a = QM31.one();
        }
        try std.testing.expect(a.mul(a.inv()).eq(QM31.one()));
    }
}

test "QM31 two-adic roots" {
    // TWO_ADIC_ROOT has exact order 2^32.
    const minus_one = QM31.fromM31(M31.fromInt(1).neg());
    try std.testing.expect(QM31.TWO_ADIC_ROOT.pow(@as(u64, 1) << 32).eq(QM31.one()));
    try std.testing.expect(QM31.TWO_ADIC_ROOT.pow(@as(u64, 1) << 31).eq(minus_one));
    // primitiveRootOfUnity produces roots of the requested order for all sizes.
    var log_size: u64 = 0;
    while (log_size <= 12) : (log_size += 1) {
        const w = QM31.primitiveRootOfUnity(log_size);
        try std.testing.expect(w.pow(@as(u64, 1) << @intCast(log_size)).eq(QM31.one()));
        if (log_size > 0) {
            try std.testing.expect(!w.pow(@as(u64, 1) << @intCast(log_size - 1)).eq(QM31.one()));
        }
    }
}

test "QM31 serialization round-trip" {
    var prng = std.Random.DefaultPrng.init(23);
    const rnd = prng.random();
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const x = QM31.new(randCM31(rnd), randCM31(rnd));
        var buf: [QM31.SIZE]u8 = undefined;
        x.toBytes(&buf);
        const y = QM31.fromBytes(buf);
        try std.testing.expect(x.eq(y));
    }
    var buf: [QM31.SIZE]u8 = undefined;
    QM31.one().toBytes(&buf);
    try std.testing.expectEqual(@as(u8, 1), buf[0]);
    try std.testing.expectEqual(@as(u8, 0), buf[15]);
}
