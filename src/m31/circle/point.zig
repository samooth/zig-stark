const std = @import("std");
const M31 = @import("../field/m31.zig").M31;

/// A point on the circle C = { (x, y) : x^2 + y^2 = 1 } over M31.
///
/// The circle forms a cyclic group of order 2^31 under
/// (x1,y1) ⊕ (x2,y2) = (x1x2 - y1y2, x1y2 + y1x2).
pub const CirclePoint = struct {
    x: M31,
    y: M31,

    pub fn new(x: M31, y: M31) CirclePoint {
        return .{ .x = x, .y = y };
    }

    pub fn add(self: CirclePoint, other: CirclePoint) CirclePoint {
        return .{
            .x = self.x.mul(other.x).sub(self.y.mul(other.y)),
            .y = self.x.mul(other.y).add(self.y.mul(other.x)),
        };
    }

    pub fn double(self: CirclePoint) CirclePoint {
        return .{
            .x = self.x.mul(self.x).sub(self.y.mul(self.y)),
            .y = self.x.mul(self.y).mul(M31.fromInt(2)),
        };
    }

    pub fn neg(self: CirclePoint) CirclePoint {
        return .{ .x = self.x, .y = self.y.neg() };
    }

    pub fn onCircle(self: CirclePoint) bool {
        const x2 = self.x.mul(self.x);
        const y2 = self.y.mul(self.y);
        return x2.add(y2).eq(M31.one());
    }

    pub fn isIdentity(self: CirclePoint) bool {
        return self.x.eq(M31.one()) and self.y.eq(M31.zero());
    }

    pub fn identity() CirclePoint {
        return CirclePoint.new(M31.one(), M31.zero());
    }

    /// A generator of the full circle group (order 2^31).
    pub fn generator() CirclePoint {
        return CirclePoint.new(M31.fromInt(1268011823), M31.fromInt(2));
    }

    /// A generator of the unique subgroup of order 2^log_size.
    /// The full-circle generator has order 2^31, so G^(2^(31 - log_size))
    /// generates the order-2^log_size subgroup.
    pub fn generatorWithOrder(log_size: u32) CirclePoint {
        std.debug.assert(log_size <= 31);
        const exp: u64 = @as(u64, 1) << @intCast(31 - log_size);
        return CirclePoint.generator().mulScalar(exp);
    }

    /// Constant-time-ish fixed-window scalar multiplication (window width 4).
    /// Returns self * scalar in the circle group.
    pub fn mulScalar(self: CirclePoint, scalar: u64) CirclePoint {
        const w: u6 = 4;
        const table_size: usize = 1 << w; // 16
        var table: [table_size]CirclePoint = undefined;
        table[0] = CirclePoint.identity();
        table[1] = self;
        table[2] = self.add(self);
        var i: usize = 3;
        while (i < table_size) : (i += 1) {
            table[i] = table[i - 1].add(self);
        }

        var result = CirclePoint.identity();
        const n_digits = @divExact(@as(usize, @bitSizeOf(u64)), w);
        var d: usize = n_digits;
        while (d > 0) {
            d -= 1;
            result = result.double().double().double().double();
            const digit = (scalar >> @intCast(@as(u6, @intCast(d * w)))) & 0xf;
            result = result.add(table[digit]);
        }
        return result;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "circle point is on the circle" {
    const gen = CirclePoint.generator();
    try std.testing.expect(gen.onCircle());
    try std.testing.expect(CirclePoint.identity().onCircle());
    try std.testing.expect(gen.neg().onCircle());
}

test "circle point group properties" {
    const identity = CirclePoint.identity();
    const gen = CirclePoint.generator();

    // identity: P + id = P
    try std.testing.expect(gen.add(identity).x.eq(gen.x));
    try std.testing.expect(gen.add(identity).y.eq(gen.y));
    // inverse: P + (-P) = id
    const inv = gen.neg();
    try std.testing.expect(gen.add(inv).isIdentity());
    // associativity on a sample
    const a = gen.mulScalar(7);
    const b = gen.mulScalar(11);
    const c = gen.mulScalar(13);
    const lhs = a.add(b).add(c);
    const rhs = a.add(b.add(c));
    try std.testing.expect(lhs.x.eq(rhs.x));
    try std.testing.expect(lhs.y.eq(rhs.y));
    // commutativity
    try std.testing.expect(a.add(b).x.eq(b.add(a).x));
    try std.testing.expect(a.add(b).y.eq(b.add(a).y));
    // double == add self
    try std.testing.expect(gen.double().x.eq(gen.add(gen).x));
    try std.testing.expect(gen.double().y.eq(gen.add(gen).y));
}

test "circle generator has order 2^31" {
    const gen = CirclePoint.generator();
    // G^(2^31) = identity
    const full = gen.mulScalar(@as(u64, 1) << 31);
    try std.testing.expect(full.isIdentity());
    // G^(2^30) != identity
    const half = gen.mulScalar(@as(u64, 1) << 30);
    try std.testing.expect(!half.isIdentity());
}

test "circle generator order-2^k subgroups" {
    var k: u32 = 1;
    while (k <= 20) : (k += 1) {
        const gen_k = CirclePoint.generatorWithOrder(k);
        try std.testing.expect(gen_k.mulScalar(@as(u64, 1) << @intCast(k)).isIdentity());
        if (k > 1) {
            try std.testing.expect(!gen_k.mulScalar(@as(u64, 1) << @intCast(k - 1)).isIdentity());
        }
    }
}

test "circle scalar multiplication matches double-and-add reference" {
    var prng = std.Random.DefaultPrng.init(77);
    const rnd = prng.random();
    const gen = CirclePoint.generator();
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        const scalar = rnd.uintLessThan(u64, 1 << 40);
        const fast = gen.mulScalar(scalar);
        // naive reference
        var result = CirclePoint.identity();
        var base = gen;
        var s = scalar;
        while (s > 0) : (s >>= 1) {
            if (s & 1 == 1) result = result.add(base);
            base = base.double();
        }
        try std.testing.expect(fast.x.eq(result.x));
        try std.testing.expect(fast.y.eq(result.y));
    }
    // scalar 0 and 1
    try std.testing.expect(gen.mulScalar(0).isIdentity());
    try std.testing.expect(gen.mulScalar(1).x.eq(gen.x));
}
