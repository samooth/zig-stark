const std = @import("std");

pub fn ExecutionTrace(comptime Field: type) type {
    return struct {
        const Self = @This();
        data: []Field,
        num_rows: usize,
        num_cols: usize,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, num_rows: usize, num_cols: usize) !Self {
            const data = try allocator.alloc(Field, num_rows * num_cols);
            @memset(data, Field.zero());
            return .{
                .data = data,
                .num_rows = num_rows,
                .num_cols = num_cols,
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.data);
        }

        pub fn get(self: Self, row: usize, col: usize) Field {
            return self.data[row * self.num_cols + col];
        }

        pub fn set(self: *Self, row: usize, col: usize, value: Field) void {
            self.data[row * self.num_cols + col] = value;
        }

        pub fn getRow(self: Self, row: usize) []const Field {
            return self.data[row * self.num_cols .. (row + 1) * self.num_cols];
        }

        pub fn getCol(self: Self, col: usize, allocator: std.mem.Allocator) ![]Field {
            var result = try allocator.alloc(Field, self.num_rows);
            for (0..self.num_rows) |i| {
                result[i] = self.get(i, col);
            }
            return result;
        }
    };
}
