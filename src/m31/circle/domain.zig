const std = @import("std");
const M31 = @import("../field/m31.zig").M31;
const CirclePoint = @import("point.zig").CirclePoint;

/// A subgroup of the circle group of order 2^log_size.
pub const CircleDomain = struct {
    initial: CirclePoint,
    log_size: u32,

    pub fn new(initial: CirclePoint, log_size: u32) CircleDomain {
        return .{ .initial = initial, .log_size = log_size };
    }

    pub fn size(self: CircleDomain) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }

    /// The point at index i (0 <= i < size).
    pub fn get(self: CircleDomain, index: usize) CirclePoint {
        std.debug.assert(index < self.size());
        return self.initial.mulScalar(@as(u64, @intCast(index)));
    }

    /// The canonical subgroup of order 2^log_size.
    pub fn standard(log_size: u32) CircleDomain {
        const gen = CirclePoint.generatorWithOrder(log_size);
        return CircleDomain.new(gen, log_size);
    }

    pub fn xValues(self: CircleDomain, allocator: std.mem.Allocator) ![]M31 {
        const n = self.size();
        var result = try allocator.alloc(M31, n);
        for (0..n) |i| {
            result[i] = self.get(i).x;
        }
        return result;
    }
};

test "circle domain properties" {
    const dom = CircleDomain.standard(4);
    try std.testing.expectEqual(@as(usize, 16), dom.size());
    // first point is identity
    try std.testing.expect(dom.get(0).isIdentity());
    // all points on circle
    for (0..dom.size()) |i| {
        try std.testing.expect(dom.get(i).onCircle());
    }
    // index arithmetic: get(i).add(get(j)) == get((i+j) mod size)
    try std.testing.expect(dom.get(3).add(dom.get(5)).x.eq(dom.get(8).x));
    try std.testing.expect(dom.get(3).add(dom.get(5)).y.eq(dom.get(8).y));
    // wrapping: get(7).add(get(9)) == get(0) (7 + 9 = 16 ≡ 0)
    try std.testing.expect(dom.get(7).add(dom.get(9)).isIdentity());
    // negation: get(i).neg() == get((size - i) mod size)
    try std.testing.expect(dom.get(3).neg().x.eq(dom.get(13).x));
    try std.testing.expect(dom.get(3).neg().y.eq(dom.get(13).y));
}

test "circle domain xValues" {
    const dom = CircleDomain.standard(3);
    var alloc = std.testing.allocator;
    const xs = try dom.xValues(alloc);
    defer alloc.free(xs);
    try std.testing.expectEqual(@as(usize, 8), xs.len);
    for (0..xs.len) |i| {
        try std.testing.expect(xs[i].eq(dom.get(i).x));
    }
}

test "circle domain sizes are powers of two" {
    var k: u32 = 1;
    while (k <= 15) : (k += 1) {
        const dom = CircleDomain.standard(k);
        try std.testing.expectEqual(@as(usize, 1) << @intCast(k), dom.size());
    }
}
