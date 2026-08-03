const std = @import("std");

/// The prime field M31 = F_(2^31 - 1), a Mersenne prime field.
///
/// Note: the multiplicative group F_p* has order p - 1 = 2 * 1073741823, so its
/// 2-adicity is only 1. Standard radix-2 NTTs therefore only work for sizes
/// up to 2. The full 2-power structure needed for FFTs lives on the circle
/// group (see `src/circle` and `src/ntt/circle.zig`), which has order 2^31.
pub const M31 = struct {
    pub const MODULUS: u32 = 2147483647; // 2^31 - 1
    pub const MODULUS_U64: u64 = 2147483647;
    pub const GENERATOR: u32 = 31; // primitive root of F_p*
    pub const TWO_ADICITY: u32 = 1;
    pub const TWO_ADIC_ROOT: u32 = MODULUS - 1; // -1, the 2^1-th primitive root
    pub const SIZE = 4; // serialized size in bytes

    value: u32,

    pub fn fromInt(x: u32) M31 {
        if (x >= MODULUS) return .{ .value = x % MODULUS };
        return .{ .value = x };
    }

    pub fn fromInt64(x: u64) M31 {
        return .{ .value = @as(u32, @intCast(x % MODULUS_U64)) };
    }

    pub fn add(self: M31, other: M31) M31 {
        const sum = @as(u64, self.value) + @as(u64, other.value);
        var result = sum;
        if (result >= MODULUS_U64) result -= MODULUS_U64;
        result = (result & MODULUS_U64) + (result >> 31);
        if (result >= MODULUS_U64) result -= MODULUS_U64;
        return .{ .value = @as(u32, @intCast(result)) };
    }

    pub fn sub(self: M31, other: M31) M31 {
        if (self.value >= other.value) {
            return .{ .value = self.value - other.value };
        }
        return .{ .value = MODULUS - (other.value - self.value) };
    }

    pub fn mul(self: M31, other: M31) M31 {
        const prod = @as(u64, self.value) * @as(u64, other.value);
        const lo = @as(u32, @intCast(prod & MODULUS_U64));
        const hi = @as(u32, @intCast(prod >> 31));
        var result = @as(u64, lo) + @as(u64, hi);
        if (result >= MODULUS_U64) result -= MODULUS_U64;
        if (result >= MODULUS_U64) result -= MODULUS_U64;
        return .{ .value = @as(u32, @intCast(result)) };
    }

    pub fn neg(self: M31) M31 {
        if (self.value == 0) return self;
        return .{ .value = MODULUS - self.value };
    }

    pub fn inv(self: M31) M31 {
        std.debug.assert(self.value != 0);
        return self.pow(MODULUS - 2);
    }

    pub fn pow(self: M31, exp: u32) M31 {
        var result = M31.one();
        var base_val = self;
        var e = exp;
        while (e > 0) : (e >>= 1) {
            if (e & 1 == 1) result = result.mul(base_val);
            base_val = base_val.mul(base_val);
        }
        return result;
    }

    pub fn eq(self: M31, other: M31) bool {
        return self.value == other.value;
    }

    pub fn zero() M31 {
        return .{ .value = 0 };
    }
    pub fn one() M31 {
        return .{ .value = 1 };
    }

    pub fn primitiveRootOfUnity(n: u32) M31 {
        std.debug.assert(n <= (1 << TWO_ADICITY));
        std.debug.assert((n & (n - 1)) == 0);
        const exp = (MODULUS - 1) / n;
        return M31.fromInt(TWO_ADIC_ROOT).pow(exp);
    }

    pub fn toBytes(self: M31, out: *[SIZE]u8) void {
        std.mem.writeInt(u32, out[0..4], self.value, .little);
    }

    pub fn fromBytes(bytes: [SIZE]u8) M31 {
        const raw = std.mem.readInt(u32, bytes[0..4], .little);
        return M31.fromInt(raw);
    }

    // SIMD operations
    pub const Vec8 = @Vector(8, u32);

    pub fn addVec8(a: Vec8, b: Vec8) Vec8 {
        const aa: [8]u32 = a;
        const bb: [8]u32 = b;
        var result: [8]u32 = undefined;
        for (0..8) |i| {
            var s = @as(u64, aa[i]) + @as(u64, bb[i]);
            if (s >= MODULUS_U64) s -= MODULUS_U64;
            s = (s & MODULUS_U64) + (s >> 31);
            if (s >= MODULUS_U64) s -= MODULUS_U64;
            result[i] = @as(u32, @intCast(s));
        }
        return result;
    }

    pub fn subVec8(a: Vec8, b: Vec8) Vec8 {
        const aa: [8]u32 = a;
        const bb: [8]u32 = b;
        var result: [8]u32 = undefined;
        for (0..8) |i| {
            if (aa[i] >= bb[i]) {
                result[i] = aa[i] - bb[i];
            } else {
                result[i] = MODULUS - (bb[i] - aa[i]);
            }
        }
        return result;
    }

    pub fn mulVec8(a: Vec8, b: Vec8) Vec8 {
        const aa: [8]u32 = a;
        const bb: [8]u32 = b;
        var result: [8]u32 = undefined;
        for (0..8) |i| {
            const prod = @as(u64, aa[i]) * @as(u64, bb[i]);
            const lo = @as(u32, @intCast(prod & MODULUS_U64));
            const hi = @as(u32, @intCast(prod >> 31));
            var r = @as(u64, lo) + @as(u64, hi);
            if (r >= MODULUS_U64) r -= MODULUS_U64;
            if (r >= MODULUS_U64) r -= MODULUS_U64;
            result[i] = @as(u32, @intCast(r));
        }
        return result;
    }
};

pub fn getRootOfUnity(n: u32) M31 {
    return M31.primitiveRootOfUnity(n);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn refAdd(a: u64, b: u64) u64 {
    return (a + b) % M31.MODULUS_U64;
}

fn refSub(a: u64, b: u64) u64 {
    return (a + M31.MODULUS_U64 - b) % M31.MODULUS_U64;
}

fn refMul(a: u64, b: u64) u64 {
    return (a * b) % M31.MODULUS_U64;
}

test "M31 add/sub/mul against u64 reference" {
    var prng = std.Random.DefaultPrng.init(42);
    const rnd = prng.random();
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const a = rnd.uintLessThan(u32, M31.MODULUS);
        const b = rnd.uintLessThan(u32, M31.MODULUS);
        const x = M31.fromInt(a);
        const y = M31.fromInt(b);
        try std.testing.expectEqual(refAdd(a, b), x.add(y).value);
        try std.testing.expectEqual(refSub(a, b), x.sub(y).value);
        try std.testing.expectEqual(refMul(a, b), x.mul(y).value);
    }
}

test "M31 edge cases" {
    const zero = M31.zero();
    const one = M31.one();
    const max = M31.fromInt(M31.MODULUS - 1);

    try std.testing.expect(zero.add(zero).eq(zero));
    try std.testing.expect(zero.add(one).eq(one));
    try std.testing.expect(max.add(one).eq(zero));
    try std.testing.expect(one.add(max).eq(zero));
    try std.testing.expect(max.sub(max).eq(zero));
    try std.testing.expect(zero.sub(one).eq(max));
    try std.testing.expect(max.mul(max).eq(one));
    try std.testing.expect(zero.mul(max).eq(zero));
    try std.testing.expect(one.neg().eq(max));
    try std.testing.expect(zero.neg().eq(zero));
}

test "M31 fromInt reduces mod p" {
    try std.testing.expect(M31.fromInt(M31.MODULUS).eq(M31.zero()));
    try std.testing.expect(M31.fromInt(M31.MODULUS + 5).eq(M31.fromInt(5)));
    try std.testing.expect(M31.fromInt(0).eq(M31.zero()));
    const big: u64 = (1 << 40) + 12345;
    try std.testing.expectEqual(@as(u32, @intCast(big % M31.MODULUS_U64)), M31.fromInt64(big).value);
}

test "M31 inverse and pow" {
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        const a = rnd.uintLessThan(u32, M31.MODULUS - 1) + 1;
        const x = M31.fromInt(a);
        try std.testing.expect(x.mul(x.inv()).eq(M31.one()));
        try std.testing.expect(x.pow(1).eq(x));
        try std.testing.expect(x.pow(0).eq(M31.one()));
    }
    try std.testing.expect(M31.one().inv().eq(M31.one()));
}

test "M31 Fermat: x^(p-1) == 1" {
    var prng = std.Random.DefaultPrng.init(3);
    const rnd = prng.random();
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        const a = rnd.uintLessThan(u32, M31.MODULUS - 1) + 1;
        try std.testing.expect(M31.fromInt(a).pow(M31.MODULUS - 1).eq(M31.one()));
    }
}

test "M31 primitive roots of unity" {
    const root2 = M31.primitiveRootOfUnity(2);
    try std.testing.expect(root2.mul(root2).eq(M31.one()));
    try std.testing.expect(root2.eq(M31.fromInt(M31.MODULUS - 1)));
    const root1 = M31.primitiveRootOfUnity(1);
    try std.testing.expect(root1.eq(M31.one()));
}

test "M31 generator is a primitive root" {
    const g = M31.fromInt(M31.GENERATOR);
    // order must be p-1: g^((p-1)/q) != 1 for each prime q | p-1
    const odd = @as(u64, 1073741823);
    try std.testing.expect(g.pow(M31.MODULUS - 1).eq(M31.one()));
    // 2-adic factor
    try std.testing.expect(!g.pow(@as(u32, @intCast(odd))).eq(M31.one()));
    // check against known small prime factors of p-1 = 2*3^2*7*11*31*151*331
    const factors = [_]u32{ 3, 7, 11, 31, 151, 331 };
    for (factors) |q| {
        const exp = @as(u32, @intCast(odd / q));
        try std.testing.expect(!g.pow(exp).eq(M31.one()));
    }
}

test "M31 serialization round-trip" {
    var prng = std.Random.DefaultPrng.init(99);
    const rnd = prng.random();
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const x = M31.fromInt(rnd.uintLessThan(u32, M31.MODULUS));
        var buf: [M31.SIZE]u8 = undefined;
        x.toBytes(&buf);
        const y = M31.fromBytes(buf);
        try std.testing.expect(x.eq(y));
        try std.testing.expectEqual(@as(usize, 4), M31.SIZE);
    }
    // known byte encoding of 1
    var buf: [M31.SIZE]u8 = undefined;
    M31.one().toBytes(&buf);
    try std.testing.expectEqual(@as(u8, 1), buf[0]);
    try std.testing.expectEqual(@as(u8, 0), buf[1]);
}

test "M31 SIMD matches scalar" {
    var prng = std.Random.DefaultPrng.init(11);
    const rnd = prng.random();
    var a_arr: [8]u32 = undefined;
    var b_arr: [8]u32 = undefined;
    for (0..8) |i| {
        a_arr[i] = rnd.uintLessThan(u32, M31.MODULUS);
        b_arr[i] = rnd.uintLessThan(u32, M31.MODULUS);
    }
    const a: M31.Vec8 = a_arr;
    const b: M31.Vec8 = b_arr;
    const add: [8]u32 = M31.addVec8(a, b);
    const sub: [8]u32 = M31.subVec8(a, b);
    const mul: [8]u32 = M31.mulVec8(a, b);
    for (0..8) |i| {
        const x = M31.fromInt(a_arr[i]);
        const y = M31.fromInt(b_arr[i]);
        try std.testing.expectEqual(x.add(y).value, add[i]);
        try std.testing.expectEqual(x.sub(y).value, sub[i]);
        try std.testing.expectEqual(x.mul(y).value, mul[i]);
    }
}
