const std = @import("std");

pub fn Air(comptime BaseField: type, comptime PublicInputs: type) type {
    _ = PublicInputs;
    return struct {
        pub const EvaluationFrame = struct {
            current: []const BaseField,
            next: []const BaseField,
        };

        pub const Assertion = struct {
            column: usize,
            step: usize,
            value: BaseField,
        };

        pub const Constraint = struct {
            degree: usize,
            evaluate: *const fn (frame: EvaluationFrame, result: []BaseField) void,
        };
    };
}
