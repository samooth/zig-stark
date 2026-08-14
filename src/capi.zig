//! C ABI for the Binius zero-check STARK.
//!
//! Exposes prove/verify over the canonical serialized wire format
//! (`core/serialization.zig`), so any host (C, Rust, Go, Node, a browser)
//! can drive the protocol without knowing Zig comptime types. The instantiation
//! is fixed at compile time: `F = tower.Gf256`, `E = tower.Gf2_128`,
//! `CP = CommittedMlePcs` (see the README for how to build other configs).
//!
//! The host supplies an allocator through `HostAllocator` (ctx + alloc/free
//! callbacks); every returned buffer is allocated with it and must be released
//! with the same callbacks. Buffers the host passes in are borrowed, never
//! freed, and are expected to live for the duration of the call.
//!
//! Wire format (little-endian, see `docs/wire.md`): field elements are
//! `SIZE` bytes (Gf256: 1 byte, Gf2_128: 16), slices are `u64`-length
//! prefixed, `usize` is 8 bytes, optionals carry a 1-byte presence flag.
//!   - columns:    `[]const []const F`  (one 2^k-entry column per witness col)
//!   - constraints: `[]const Constraint` (term coeff is 1 byte, factors are u64)
//!   - pins:       `[]const Pin`        (col: u64, point: u64, value: 1 byte)
//!   - roots:      `[]const Hash.Digest` (32 bytes each)
//!   - proof:      the serialized `Stark.Proof`.
//!
//! Return codes: 0 on success, -1 generic error, -2 malformed input bytes,
//! -3 out of memory, -4 protocol error (prove/verify failed).

const std = @import("std");
const builtin = @import("builtin");
const Ser = @import("core/serialization.zig");
const Hash = @import("core/hash/hash.zig").Hash;
const F = @import("binius/tower.zig").Gf256;
const E = @import("binius/tower.zig").Gf2_128;
const Stark = @import("binius/stark.zig").BiniusStark(F, E);

const Error = error{ InvalidInput, OutOfMemory, Protocol };

fn errCode(err: anyerror) c_int {
    return switch (err) {
        error.OutOfMemory => -3,
        error.InvalidInput, error.TrailingBytes, error.UnexpectedEnd => -2,
        error.Protocol => -4,
        else => -1,
    };
}

/// Host-provided memory management callbacks. `alloc` must return memory the
/// host can free later with `free`; both are invoked with `ctx`.
pub const HostAllocator = extern struct {
    ctx: ?*anyopaque,
    alloc: ?*const fn (ctx: ?*anyopaque, size: usize) callconv(.c) ?[*]u8,
    free: ?*const fn (ctx: ?*anyopaque, ptr: [*]u8, size: usize) callconv(.c) void,
};

const Header = struct { orig: usize, size: usize };

/// Wrap `HostAllocator` as a `std.mem.Allocator`. Each allocation stores a
/// small header (original base pointer and size) just before the aligned
/// payload so `free` can hand the exact block back to the host. `resize` /
/// `remap` are unimplemented (the std allocator falls back to copy).
fn allocImpl(ctx: *anyopaque, n: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
    _ = ra;
    const host: *HostAllocator = @ptrCast(@alignCast(ctx));
    const alloc_fn = host.alloc orelse return null;
    const min_bytes = @max(alignment.toByteUnits(), @alignOf(Header));
    const pad = min_bytes - 1;
    const total = @sizeOf(Header) + pad + n;
    const base = alloc_fn(host.ctx, total) orelse return null;
    const base_addr: usize = @intFromPtr(base);
    const payload_addr = std.mem.alignForward(usize, base_addr + @sizeOf(Header), min_bytes);
    const header_ptr: *Header = @ptrFromInt(payload_addr - @sizeOf(Header));
    header_ptr.* = .{ .orig = base_addr, .size = total };
    return @ptrFromInt(payload_addr);
}

fn resizeImpl(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
    _ = ctx;
    _ = memory;
    _ = alignment;
    _ = new_len;
    _ = ra;
    return false;
}

fn remapImpl(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
    _ = ctx;
    _ = memory;
    _ = alignment;
    _ = new_len;
    _ = ra;
    return null;
}

fn freeImpl(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
    _ = alignment;
    _ = ra;
    const host: *HostAllocator = @ptrCast(@alignCast(ctx));
    const free_fn = host.free orelse return;
    const addr: usize = @intFromPtr(memory.ptr);
    const header_ptr: *Header = @ptrFromInt(addr - @sizeOf(Header));
    const h = header_ptr.*;
    free_fn(host.ctx, @ptrFromInt(h.orig), h.size);
}

fn makeAllocator(host: *const HostAllocator) std.mem.Allocator {
    return .{
        .ptr = @ptrCast(@constCast(host)),
        .vtable = &.{
            .alloc = allocImpl,
            .resize = resizeImpl,
            .remap = remapImpl,
            .free = freeImpl,
        },
    };
}

fn sliceOf(ptr: ?[*]const u8, len: usize) []const u8 {
    return if (ptr) |p| p[0..len] else &[_]u8{};
}

/// Prove a generic zero-check statement. Inputs are serialized bytes (see the
/// module doc); on success `out_proof`/`out_len` point to a host-allocated
/// serialized `Stark.Proof` the caller must free with the same `HostAllocator`.
pub export fn zs_binius_prove(
    host: HostAllocator,
    k: u8,
    columns_ptr: ?[*]const u8,
    columns_len: usize,
    constraints_ptr: ?[*]const u8,
    constraints_len: usize,
    pins_ptr: ?[*]const u8,
    pins_len: usize,
    domain_ptr: ?[*]const u8,
    domain_len: usize,
    out_proof: *[*]u8,
    out_len: *usize,
) callconv(.c) c_int {
    const alloc = makeAllocator(&host);
    const columns_bytes = sliceOf(columns_ptr, columns_len);
    const constraints_bytes = sliceOf(constraints_ptr, constraints_len);
    const pins_bytes = sliceOf(pins_ptr, pins_len);
    const domain = sliceOf(domain_ptr, domain_len);

    const result = prove(alloc, k, columns_bytes, constraints_bytes, pins_bytes, domain) catch |err| return errCode(err);
    out_proof.* = result.ptr;
    out_len.* = result.len;
    return 0;
}

fn prove(
    alloc: std.mem.Allocator,
    k: u8,
    columns_bytes: []const u8,
    constraints_bytes: []const u8,
    pins_bytes: []const u8,
    domain: []const u8,
) ![]u8 {
    const columns = try Ser.deserialize(alloc, columns_bytes, []const []const F);
    defer {
        for (columns) |c| alloc.free(c);
        alloc.free(columns);
    }
    const constraints = try Ser.deserialize(alloc, constraints_bytes, []const Stark.Constraint);
    defer {
        for (constraints) |c| {
            for (c.terms) |m| alloc.free(m.factors);
            alloc.free(c.terms);
        }
        alloc.free(constraints);
    }
    const pins = try Ser.deserialize(alloc, pins_bytes, []const Stark.Pin);
    defer alloc.free(pins);

    var proof = try Stark.prove(alloc, k, columns, constraints, pins, domain);
    defer proof.deinit(alloc);
    return try Ser.serialize(alloc, proof);
}

/// Verify a serialized proof against the committed roots and statement.
/// `out_ok` receives 1/0. Returns 0 on success, or a negative error code if
/// the inputs could not be deserialized.
pub export fn zs_binius_verify(
    host: HostAllocator,
    k: u8,
    roots_ptr: ?[*]const u8,
    roots_len: usize,
    constraints_ptr: ?[*]const u8,
    constraints_len: usize,
    pins_ptr: ?[*]const u8,
    pins_len: usize,
    proof_ptr: ?[*]const u8,
    proof_len: usize,
    domain_ptr: ?[*]const u8,
    domain_len: usize,
    out_ok: *bool,
) callconv(.c) c_int {
    const alloc = makeAllocator(&host);
    const roots_bytes = sliceOf(roots_ptr, roots_len);
    const constraints_bytes = sliceOf(constraints_ptr, constraints_len);
    const pins_bytes = sliceOf(pins_ptr, pins_len);
    const proof_bytes = sliceOf(proof_ptr, proof_len);
    const domain = sliceOf(domain_ptr, domain_len);

    const ok = verify(alloc, k, roots_bytes, constraints_bytes, pins_bytes, proof_bytes, domain) catch |err| return errCode(err);
    out_ok.* = ok;
    return 0;
}

fn verify(
    alloc: std.mem.Allocator,
    k: u8,
    roots_bytes: []const u8,
    constraints_bytes: []const u8,
    pins_bytes: []const u8,
    proof_bytes: []const u8,
    domain: []const u8,
) !bool {
    const roots = try Ser.deserialize(alloc, roots_bytes, []const Hash.Digest);
    defer alloc.free(roots);
    const constraints = try Ser.deserialize(alloc, constraints_bytes, []const Stark.Constraint);
    defer {
        for (constraints) |c| {
            for (c.terms) |m| alloc.free(m.factors);
            alloc.free(c.terms);
        }
        alloc.free(constraints);
    }
    const pins = try Ser.deserialize(alloc, pins_bytes, []const Stark.Pin);
    defer alloc.free(pins);
    var proof = try Ser.deserialize(alloc, proof_bytes, Stark.Proof);
    defer proof.deinit(alloc);
    return try Stark.verify(alloc, k, roots, constraints, pins, proof, domain);
}

/// Free a buffer previously returned by `zs_binius_prove` (or any buffer the
/// ABI handed back). The caller passes the same `HostAllocator` used for the
/// call plus the returned pointer/length; the underlying host block (including
/// the internal alignment header) is released.
pub export fn zs_free(host: HostAllocator, ptr: ?[*]u8, len: usize) callconv(.c) void {
    if (ptr) |p| makeAllocator(&host).free(p[0..len]);
}

/// Version / configuration string of this ABI instantiation.
pub export fn zs_version() callconv(.c) [*:0]const u8 {
    return "zig-stark 0.2.0 binius capi (Gf256/Gf2_128/CommittedMlePcs)";
}

// ---------------------------------------------------------------------------
// wasm path: host-provided malloc/free (imported). JS supplies these over the
// module's linear memory, so no HostAllocator fn-pointer struct is needed.
// ---------------------------------------------------------------------------

extern fn zig_stark_malloc(size: usize) ?[*]u8;
extern fn zig_stark_free(ptr: [*]u8, size: usize) void;

/// On wasm the externs are host imports; on other targets they are never
/// referenced (comptime-eliminated), so the native link stays clean.
fn importedMalloc(size: usize) ?[*]u8 {
    if (comptime builtin.cpu.arch == .wasm32) return zig_stark_malloc(size);
    @panic("_wm path is wasm-only");
}

fn importedFree(ptr: [*]u8, size: usize) void {
    if (comptime builtin.cpu.arch == .wasm32) {
        zig_stark_free(ptr, size);
        return;
    }
    @panic("_wm path is wasm-only");
}

fn importedAllocImpl(ctx: *anyopaque, n: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
    _ = ctx;
    _ = ra;
    const min_bytes = @max(alignment.toByteUnits(), @alignOf(Header));
    const pad = min_bytes - 1;
    const total = @sizeOf(Header) + pad + n;
    const base = importedMalloc(total) orelse return null;
    const base_addr: usize = @intFromPtr(base);
    const payload_addr = std.mem.alignForward(usize, base_addr + @sizeOf(Header), min_bytes);
    const header_ptr: *Header = @ptrFromInt(payload_addr - @sizeOf(Header));
    header_ptr.* = .{ .orig = base_addr, .size = total };
    return @ptrFromInt(payload_addr);
}

fn importedFreeImpl(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
    _ = ctx;
    _ = alignment;
    _ = ra;
    const addr: usize = @intFromPtr(memory.ptr);
    const header_ptr: *Header = @ptrFromInt(addr - @sizeOf(Header));
    const h = header_ptr.*;
    importedFree(@ptrFromInt(h.orig), h.size);
}

fn makeImportedAllocator() std.mem.Allocator {
    return .{
        .ptr = @constCast(@as(*anyopaque, @ptrFromInt(@alignOf(usize)))),
        .vtable = &.{
            .alloc = importedAllocImpl,
            .resize = resizeImpl,
            .remap = remapImpl,
            .free = importedFreeImpl,
        },
    };
}

pub export fn zs_binius_prove_wm(
    k: u8,
    columns_ptr: ?[*]const u8,
    columns_len: usize,
    constraints_ptr: ?[*]const u8,
    constraints_len: usize,
    pins_ptr: ?[*]const u8,
    pins_len: usize,
    domain_ptr: ?[*]const u8,
    domain_len: usize,
    out_proof: *[*]u8,
    out_len: *usize,
) callconv(.c) c_int {
    const alloc = makeImportedAllocator();
    const result = prove(
        alloc,
        k,
        sliceOf(columns_ptr, columns_len),
        sliceOf(constraints_ptr, constraints_len),
        sliceOf(pins_ptr, pins_len),
        sliceOf(domain_ptr, domain_len),
    ) catch |err| return errCode(err);
    out_proof.* = result.ptr;
    out_len.* = result.len;
    return 0;
}

pub export fn zs_binius_verify_wm(
    k: u8,
    roots_ptr: ?[*]const u8,
    roots_len: usize,
    constraints_ptr: ?[*]const u8,
    constraints_len: usize,
    pins_ptr: ?[*]const u8,
    pins_len: usize,
    proof_ptr: ?[*]const u8,
    proof_len: usize,
    domain_ptr: ?[*]const u8,
    domain_len: usize,
    out_ok: *bool,
) callconv(.c) c_int {
    const alloc = makeImportedAllocator();
    const ok = verify(
        alloc,
        k,
        sliceOf(roots_ptr, roots_len),
        sliceOf(constraints_ptr, constraints_len),
        sliceOf(pins_ptr, pins_len),
        sliceOf(proof_ptr, proof_len),
        sliceOf(domain_ptr, domain_len),
    ) catch |err| return errCode(err);
    out_ok.* = ok;
    return 0;
}

pub export fn zs_free_wm(ptr: ?[*]u8, len: usize) callconv(.c) void {
    if (ptr) |p| makeImportedAllocator().free(p[0..len]);
}

/// Commit the witness columns and return the serialized `[]const Hash.Digest`
/// roots (one per column), allocated with the imported malloc/free.
pub export fn zs_binius_commit_wm(
    k: u8,
    columns_ptr: ?[*]const u8,
    columns_len: usize,
    out_roots: *[*]u8,
    out_len: *usize,
) callconv(.c) c_int {
    _ = k;
    const alloc = makeImportedAllocator();
    const columns = Ser.deserialize(alloc, sliceOf(columns_ptr, columns_len), []const []const F) catch |err| return errCode(err);
    defer {
        for (columns) |c| alloc.free(c);
        alloc.free(columns);
    }
    const roots = alloc.alloc(Hash.Digest, columns.len) catch return -3;
    defer alloc.free(roots);
    for (0..columns.len) |c| {
        var tree = @import("binius/pcs.zig").CommittedMlePcs(F, E).commit(alloc, columns[c]) catch return -3;
        defer tree.deinit();
        roots[c] = tree.root();
    }
    const bytes = Ser.serialize(alloc, roots) catch return -3;
    out_roots.* = bytes.ptr;
    out_len.* = bytes.len;
    return 0;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;
const Tower = @import("binius/tower.zig");
const Adder = @import("binius/adder.zig").Adder(F, E);

/// A `HostAllocator` backed by `std.testing.allocator`, exercising the full
/// header/alignment/free path under the leak checker.
const TestHost = struct {
    base: std.mem.Allocator,
    fn allocFn(ctx: ?*anyopaque, size: usize) callconv(.c) ?[*]u8 {
        const th: *TestHost = @ptrCast(@alignCast(ctx.?));
        const slice = th.base.alloc(u8, size) catch return null;
        return slice.ptr;
    }

    fn freeFn(ctx: ?*anyopaque, ptr: [*]u8, size: usize) callconv(.c) void {
        const th: *TestHost = @ptrCast(@alignCast(ctx.?));
        th.base.free(ptr[0..size]);
    }

    fn host(self: *TestHost) HostAllocator {
        return .{ .ctx = self, .alloc = allocFn, .free = freeFn };
    }
};

test "capi prove/verify round-trips a 4-bit adder batch" {
    const alloc = testing.allocator;
    const k = 3;
    const n: usize = @as(usize, 1) << @intCast(k);

    const x = try alloc.alloc(u4, n);
    defer alloc.free(x);
    const y = try alloc.alloc(u4, n);
    defer alloc.free(y);
    for (0..n) |i| {
        x[i] = @intCast((i * 3 + 5) % 16);
        y[i] = @intCast((i * 7 + 2) % 16);
    }
    const columns = try Adder.generateWitness(alloc, x, y);
    defer Adder.freeWitness(alloc, &columns);

    var host = TestHost{ .base = alloc };
    const h = host.host();

    const columns_bytes = try Ser.serialize(alloc, @as([]const []F, columns[0..]));
    defer alloc.free(columns_bytes);
    const constraints_bytes = try Ser.serialize(alloc, @as([]const Stark.Constraint, Adder.constraints[0..]));
    defer alloc.free(constraints_bytes);
    const pins_bytes = try Ser.serialize(alloc, @as([]const Stark.Pin, &.{}));
    defer alloc.free(pins_bytes);

    // Prove through the ABI.
    var proof_ptr: [*]u8 = undefined;
    var proof_len: usize = 0;
    const pc = zs_binius_prove(
        h,
        k,
        columns_bytes.ptr,
        columns_bytes.len,
        constraints_bytes.ptr,
        constraints_bytes.len,
        pins_bytes.ptr,
        pins_bytes.len,
        "capi",
        4,
        &proof_ptr,
        &proof_len,
    );
    try testing.expectEqual(@as(c_int, 0), pc);
    defer zs_free(h, proof_ptr, proof_len);

    // Commit the roots (host allocator) and verify through the ABI.
    const roots_buf = try alloc.alloc(Hash.Digest, Adder.num_columns);
    defer alloc.free(roots_buf);
    {
        const CP = @import("binius/pcs.zig").CommittedMlePcs(F, E);
        for (0..Adder.num_columns) |c| {
            var tree = try CP.commit(alloc, columns[c]);
            defer tree.deinit();
            roots_buf[c] = tree.root();
        }
    }
    const roots_bytes = try Ser.serialize(alloc, roots_buf);
    defer alloc.free(roots_bytes);

    var ok: bool = undefined;
    const vc = zs_binius_verify(
        h,
        k,
        roots_bytes.ptr,
        roots_bytes.len,
        constraints_bytes.ptr,
        constraints_bytes.len,
        pins_bytes.ptr,
        pins_bytes.len,
        proof_ptr,
        proof_len,
        "capi",
        4,
        &ok,
    );
    try testing.expectEqual(@as(c_int, 0), vc);
    try testing.expect(ok);
}

test "capi rejects a tampered proof" {
    const alloc = testing.allocator;
    const k = 3;
    const n: usize = @as(usize, 1) << @intCast(k);

    const x = try alloc.alloc(u4, n);
    defer alloc.free(x);
    const y = try alloc.alloc(u4, n);
    defer alloc.free(y);
    for (0..n) |i| {
        x[i] = @intCast((i * 3 + 5) % 16);
        y[i] = @intCast((i * 7 + 2) % 16);
    }
    const columns = try Adder.generateWitness(alloc, x, y);
    defer Adder.freeWitness(alloc, &columns);

    var host = TestHost{ .base = alloc };
    const h = host.host();

    const columns_bytes = try Ser.serialize(alloc, @as([]const []F, columns[0..]));
    defer alloc.free(columns_bytes);
    const constraints_bytes = try Ser.serialize(alloc, @as([]const Stark.Constraint, Adder.constraints[0..]));
    defer alloc.free(constraints_bytes);
    const pins_bytes = try Ser.serialize(alloc, @as([]const Stark.Pin, &.{}));
    defer alloc.free(pins_bytes);

    var proof_ptr: [*]u8 = undefined;
    var proof_len: usize = 0;
    try testing.expectEqual(@as(c_int, 0), zs_binius_prove(
        h,
        k,
        columns_bytes.ptr,
        columns_bytes.len,
        constraints_bytes.ptr,
        constraints_bytes.len,
        pins_bytes.ptr,
        pins_bytes.len,
        "capi",
        4,
        &proof_ptr,
        &proof_len,
    ));
    const proof_bytes = proof_ptr[0..proof_len];
    defer zs_free(h, proof_ptr, proof_len);

    // Flip one byte in the proof: the deserialized proof still parses (the
    // wire format is length-prefixed), but verification must reject it.
    const tampered = try alloc.dupe(u8, proof_bytes);
    defer alloc.free(tampered);
    tampered[proof_len / 2] ^= 0x01;

    const roots_buf = try alloc.alloc(Hash.Digest, Adder.num_columns);
    defer alloc.free(roots_buf);
    {
        const CP = @import("binius/pcs.zig").CommittedMlePcs(F, E);
        for (0..Adder.num_columns) |c| {
            var tree = try CP.commit(alloc, columns[c]);
            defer tree.deinit();
            roots_buf[c] = tree.root();
        }
    }
    const roots_bytes = try Ser.serialize(alloc, roots_buf);
    defer alloc.free(roots_bytes);

    var ok: bool = undefined;
    try testing.expectEqual(@as(c_int, 0), zs_binius_verify(
        h,
        k,
        roots_bytes.ptr,
        roots_bytes.len,
        constraints_bytes.ptr,
        constraints_bytes.len,
        pins_bytes.ptr,
        pins_bytes.len,
        tampered.ptr,
        tampered.len,
        "capi",
        4,
        &ok,
    ));
    try testing.expect(!ok);
}

test "capi internal prove/verify are leak-free with testing.allocator" {
    const alloc = testing.allocator;
    const k = 3;
    const n: usize = @as(usize, 1) << @intCast(k);
    const x = try alloc.alloc(u4, n);
    defer alloc.free(x);
    const y = try alloc.alloc(u4, n);
    defer alloc.free(y);
    for (0..n) |i| {
        x[i] = @intCast((i * 3 + 5) % 16);
        y[i] = @intCast((i * 7 + 2) % 16);
    }
    const columns = try Adder.generateWitness(alloc, x, y);
    defer Adder.freeWitness(alloc, &columns);

    const columns_bytes = try Ser.serialize(alloc, @as([]const []F, columns[0..]));
    defer alloc.free(columns_bytes);
    const constraints_bytes = try Ser.serialize(alloc, @as([]const Stark.Constraint, Adder.constraints[0..]));
    defer alloc.free(constraints_bytes);
    const pins_bytes = try Ser.serialize(alloc, @as([]const Stark.Pin, &.{}));
    defer alloc.free(pins_bytes);

    const proof_bytes = try prove(alloc, k, columns_bytes, constraints_bytes, pins_bytes, "capi");
    defer alloc.free(proof_bytes);

    const roots_buf = try alloc.alloc(Hash.Digest, Adder.num_columns);
    defer alloc.free(roots_buf);
    {
        const CP = @import("binius/pcs.zig").CommittedMlePcs(F, E);
        for (0..Adder.num_columns) |c| {
            var tree = try CP.commit(alloc, columns[c]);
            defer tree.deinit();
            roots_buf[c] = tree.root();
        }
    }
    const roots_bytes = try Ser.serialize(alloc, roots_buf);
    defer alloc.free(roots_bytes);

    const ok = try verify(alloc, k, roots_bytes, constraints_bytes, pins_bytes, proof_bytes, "capi");
    try testing.expect(ok);
}
