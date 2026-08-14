//! N-API native addon (`.node`) for Node.js.
//!
//! Wraps the Binius C ABI (`src/capi.zig`) so Node gets native speed instead of
//! wasm. The JS API mirrors the wasm binding: inputs are the serialized
//! wire-format buffers (columns / constraints / pins / proof) plus `k` and a
//! domain string; `proveColumns(k, columns, constraints, pins, domain)` returns
//! `{ proof: Buffer, roots: Buffer }` and
//! `verify(k, roots, constraints, pins, proof, domain)` returns a boolean.
//!
//! Build (headers of your Node install, e.g.
//! `$HOME/.nvm/versions/node/v24.14.0/include/node`):
//!
//!     zig build node-addon -Doptimize=ReleaseFast \
//!         -Dnapi-include=$HOME/.nvm/versions/node/v24.14.0/include/node

const std = @import("std");
const c = @cImport({
    @cInclude("node_api.h");
});
const capi = @import("capi");

/// Per-call host allocator over an arena. Everything the ABI allocates is
/// released when the arena is destroyed after the JS buffers are copied.
const Host = struct {
    arena: std.heap.ArenaAllocator,

    fn init() Host {
        return .{ .arena = std.heap.ArenaAllocator.init(std.heap.page_allocator) };
    }

    fn deinit(self: *Host) void {
        self.arena.deinit();
    }

    fn host(self: *Host) capi.HostAllocator {
        return .{ .ctx = self, .alloc = allocCb, .free = freeCb };
    }

    fn allocCb(ctx: ?*anyopaque, size: usize) callconv(.c) ?[*]u8 {
        const h: *Host = @ptrCast(@alignCast(ctx.?));
        const a = h.arena.allocator(); // .ptr = &h.arena (valid, h is stable)
        const s = a.alloc(u8, size) catch return null;
        return s.ptr;
    }

    fn freeCb(ctx: ?*anyopaque, ptr: [*]u8, size: usize) callconv(.c) void {
        const h: *Host = @ptrCast(@alignCast(ctx.?));
        const a = h.arena.allocator();
        a.free(ptr[0..size]);
    }
};

fn throwErr(env: c.napi_env, msg: []const u8) void {
    const s = if (msg.len > 255) msg[0..255] else msg;
    _ = c.napi_throw_error(env, null, @ptrCast(s.ptr));
}

fn arg(env: c.napi_env, info: c.napi_callback_info, i: usize) !c.napi_value {
    var argc: usize = 8;
    var args: [8]c.napi_value = undefined;
    if (c.napi_get_cb_info(env, info, &argc, &args, null, null) != c.napi_ok) return error.Napi;
    if (i >= argc) return error.MissingArg;
    return args[i];
}

fn getBuffer(env: c.napi_env, value: c.napi_value) ![]const u8 {
    var data: ?*anyopaque = null;
    var len: usize = 0;
    if (c.napi_get_buffer_info(env, value, &data, &len) != c.napi_ok) return error.NotBuffer;
    const ptr: [*]const u8 = @ptrCast(data.?);
    return ptr[0..len];
}

fn getInt(env: c.napi_env, value: c.napi_value) !i32 {
    var out: i32 = 0;
    if (c.napi_get_value_int32(env, value, &out) != c.napi_ok) return error.NotInt;
    return out;
}

fn getString(env: c.napi_env, value: c.napi_value) ![]u8 {
    var size: usize = 0;
    if (c.napi_get_value_string_utf8(env, value, null, 0, &size) != c.napi_ok) return error.NotString;
    const buf = try std.heap.page_allocator.alloc(u8, size + 1); // +1 for the null terminator
    var copied: usize = 0;
    _ = c.napi_get_value_string_utf8(env, value, @ptrCast(buf.ptr), buf.len, &copied);
    return buf[0..size];
}

fn makeBuffer(env: c.napi_env, data: []const u8) !c.napi_value {
    var out: c.napi_value = undefined;
    _ = c.napi_create_buffer_copy(env, data.len, @ptrCast(data.ptr), null, &out);
    return out;
}

fn makeBool(env: c.napi_env, value: bool) !c.napi_value {
    var out: c.napi_value = undefined;
    _ = c.napi_get_boolean(env, value, &out);
    return out;
}

fn proveColumns(env: c.napi_env, info: c.napi_callback_info) !c.napi_value {
    const k: u8 = @intCast(try getInt(env, try arg(env, info, 0)));
    const columns = try getBuffer(env, try arg(env, info, 1));
    const constraints = try getBuffer(env, try arg(env, info, 2));
    const pins = try getBuffer(env, try arg(env, info, 3));
    const domain = try getString(env, try arg(env, info, 4));
    defer std.heap.page_allocator.free(domain);

    var host = Host.init();
    defer host.deinit();
    const h = host.host();

    var proof_ptr: [*]u8 = undefined;
    var proof_len: usize = 0;
    const rc = capi.zs_binius_prove(
        h,
        k,
        columns.ptr,
        columns.len,
        constraints.ptr,
        constraints.len,
        pins.ptr,
        pins.len,
        domain.ptr,
        domain.len,
        &proof_ptr,
        &proof_len,
    );
    if (rc != 0) return error.Protocol;

    var roots_ptr: [*]u8 = undefined;
    var roots_len: usize = 0;
    const rc2 = capi.zs_binius_commit(h, k, columns.ptr, columns.len, &roots_ptr, &roots_len);
    if (rc2 != 0) return error.Protocol;

    const proof_val = try makeBuffer(env, proof_ptr[0..proof_len]);
    const roots_val = try makeBuffer(env, roots_ptr[0..roots_len]);
    var obj: c.napi_value = undefined;
    _ = c.napi_create_object(env, &obj);
    _ = c.napi_set_named_property(env, obj, "proof", proof_val);
    _ = c.napi_set_named_property(env, obj, "roots", roots_val);
    return obj;
}

fn proveColumnsCb(env: c.napi_env, info: c.napi_callback_info) callconv(.c) c.napi_value {
    return proveColumns(env, info) catch |err| {
        throwErr(env, switch (err) {
            error.MissingArg => "proveColumns: expected (k, columns, constraints, pins, domain)",
            error.NotBuffer => "proveColumns: arguments must be Buffers",
            error.NotInt => "proveColumns: k must be a number",
            error.NotString => "proveColumns: domain must be a string",
            else => "proveColumns: protocol error",
        });
        return null;
    };
}

fn verify(env: c.napi_env, info: c.napi_callback_info) !c.napi_value {
    const k: u8 = @intCast(try getInt(env, try arg(env, info, 0)));
    const roots = try getBuffer(env, try arg(env, info, 1));
    const constraints = try getBuffer(env, try arg(env, info, 2));
    const pins = try getBuffer(env, try arg(env, info, 3));
    const proof = try getBuffer(env, try arg(env, info, 4));
    const domain = try getString(env, try arg(env, info, 5));
    defer std.heap.page_allocator.free(domain);

    var host = Host.init();
    defer host.deinit();
    const h = host.host();

    var ok: bool = undefined;
    const rc = capi.zs_binius_verify(
        h,
        k,
        roots.ptr,
        roots.len,
        constraints.ptr,
        constraints.len,
        pins.ptr,
        pins.len,
        proof.ptr,
        proof.len,
        domain.ptr,
        domain.len,
        &ok,
    );
    if (rc != 0) return error.Protocol;
    return try makeBool(env, ok);
}

fn verifyCb(env: c.napi_env, info: c.napi_callback_info) callconv(.c) c.napi_value {
    return verify(env, info) catch |err| {
        throwErr(env, switch (err) {
            error.MissingArg => "verify: expected (k, roots, constraints, pins, proof, domain)",
            error.NotBuffer => "verify: arguments must be Buffers",
            error.NotInt => "verify: k must be a number",
            error.NotString => "verify: domain must be a string",
            else => "verify: protocol error",
        });
        return null;
    };
}

fn versionCb(env: c.napi_env, info: c.napi_callback_info) callconv(.c) c.napi_value {
    _ = info;
    const s = capi.zs_version();
    const len = std.mem.len(s);
    return makeBuffer(env, s[0..len]) catch null;
}

fn registerFn(env: c.napi_env, exports: c.napi_value, comptime name: []const u8, cb: c.napi_callback) !void {
    var fn_val: c.napi_value = undefined;
    if (c.napi_create_function(env, name.ptr, name.len, cb, null, &fn_val) != c.napi_ok) return error.Napi;
    if (c.napi_set_named_property(env, exports, name.ptr, fn_val) != c.napi_ok) return error.Napi;
}

export fn napi_register_module_v1(env: c.napi_env, exports: c.napi_value) c.napi_value {
    registerFn(env, exports, "version", versionCb) catch {};
    registerFn(env, exports, "proveColumns", proveColumnsCb) catch {};
    registerFn(env, exports, "verify", verifyCb) catch {};
    return exports;
}
