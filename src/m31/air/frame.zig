const std = @import("std");

pub fn EvaluationFrame(comptime Field: type) type {
    return struct {
        current: []const Field,
        next: []const Field,

        pub fn new(current: []const Field, next: []const Field) @This() {
            return .{ .current = current, .next = next };
        }
    };
}
