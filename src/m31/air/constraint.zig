const std = @import("std");

pub fn BoundaryConstraint(comptime Field: type) type {
    return struct {
        column: usize,
        step: usize,
        value: Field,
    };
}

pub fn TransitionConstraint(comptime Field: type) type {
    return struct {
        degree: usize,
        evaluate: *const fn (current: []const Field, next: []const Field, result: []Field) void,
    };
}
