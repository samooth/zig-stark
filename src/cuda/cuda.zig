//! Minimal CUDA Driver API bindings + a small device context helper.
//!
//! Why manual `extern "c"` instead of `@cImport("cuda.h")`: Zig 0.16's
//! `@cImport` mislinks the Driver API symbols (calling `cuInit` through the
//! translated header segfaults), while plain `extern "c"` declarations work
//! reliably. This module is opt-in: it is only compiled when a CUDA-enabled
//! build requests it, and every call is checked; the caller falls back to CPU
//! when `Cuda.init` fails (no driver, no device, ...).
//!
//! Kernels are CUDA C compiled to PTX by `nvcc` and embedded via `@embedFile`,
//! so there is no runtime `.ptx` file dependency (the driver JITs the PTX). A
//! `zig build cuda-kernels` step regenerates the PTX when `nvcc` is available.

const std = @import("std");

pub const CUresult = c_uint;
pub const CUdevice = c_int;
pub const CUdeviceptr = u64;
pub const CUcontext = ?*anyopaque;
pub const CUmodule = ?*anyopaque;
pub const CUfunction = ?*anyopaque;
pub const success: CUresult = 0;

extern "c" fn cuInit(Flags: c_uint) CUresult;
extern "c" fn cuDeviceGetCount(count: *c_int) CUresult;
extern "c" fn cuDeviceGet(device: *CUdevice, ordinal: c_int) CUresult;
extern "c" fn cuCtxCreate(pctx: *CUcontext, flags: c_uint, dev: CUdevice) CUresult;
extern "c" fn cuCtxDestroy(ctx: CUcontext) CUresult;
extern "c" fn cuModuleLoadData(module: *CUmodule, image: *const anyopaque) CUresult;
extern "c" fn cuModuleUnload(module: CUmodule) CUresult;
extern "c" fn cuModuleGetFunction(hfunc: *CUfunction, hmod: CUmodule, name: [*:0]const u8) CUresult;
extern "c" fn cuLaunchKernel(
    f: CUfunction,
    gridX: c_uint,
    gridY: c_uint,
    gridZ: c_uint,
    blockX: c_uint,
    blockY: c_uint,
    blockZ: c_uint,
    sharedMemBytes: c_uint,
    stream: ?*anyopaque,
    kernelParams: [*c]?*const anyopaque,
    extra: ?*anyopaque,
) CUresult;
extern "c" fn cuMemAlloc(dptr: *CUdeviceptr, bytesize: usize) CUresult;
extern "c" fn cuMemFree(dptr: CUdeviceptr) CUresult;
extern "c" fn cuMemcpyHtoD(dst: CUdeviceptr, src: *const anyopaque, count: usize) CUresult;
extern "c" fn cuMemcpyDtoH(dst: *anyopaque, src: CUdeviceptr, count: usize) CUresult;
extern "c" fn cuCtxSynchronize() CUresult;
extern "c" fn cuGetErrorString(err: CUresult, pStr: *[*c]const u8) CUresult;

/// Map a `CUresult` to a Zig error; on failure the message is logged to
/// stderr and `error.CudaFailure` is returned.
pub fn check(status: CUresult) !void {
    if (status != success) {
        var msg: [*c]const u8 = undefined;
        _ = cuGetErrorString(status, &msg);
        std.debug.print("CUDA error {d}: {s}\n", .{ status, std.mem.span(msg) });
        return error.CudaFailure;
    }
}

/// An initialized CUDA context with one loaded module (an embedded PTX image).
pub const Cuda = struct {
    ctx: CUcontext,
    module: CUmodule,

    /// Initialize the driver, pick device 0, create a context, and load the
    /// module from the raw PTX bytes. Returns `error.NoCudaDevice` when there
    /// is no usable GPU, and `error.CudaFailure` on driver errors — callers use
    /// this to fall back to the CPU path.
    pub fn init(ptx: []const u8) !Cuda {
        try check(cuInit(0));
        var count: c_int = 0;
        try check(cuDeviceGetCount(&count));
        if (count == 0) return error.NoCudaDevice;
        var dev: CUdevice = undefined;
        try check(cuDeviceGet(&dev, 0));
        var ctx: CUcontext = undefined;
        try check(cuCtxCreate(&ctx, 0, dev));
        var module: CUmodule = undefined;
        try check(cuModuleLoadData(&module, ptx.ptr));
        return .{ .ctx = ctx, .module = module };
    }

    pub fn deinit(self: *Cuda) void {
        _ = cuModuleUnload(self.module);
        _ = cuCtxDestroy(self.ctx);
        self.* = undefined;
    }

    /// Look up a kernel by its (unmangled) name in the loaded module.
    pub fn func(self: *Cuda, name: [:0]const u8) !CUfunction {
        var f: CUfunction = undefined;
        try check(cuModuleGetFunction(&f, self.module, name.ptr));
        return f;
    }

    /// Allocate `bytes` of device memory.
    pub fn alloc(self: *Cuda, bytes: usize) !CUdeviceptr {
        _ = self;
        var ptr: CUdeviceptr = undefined;
        try check(cuMemAlloc(&ptr, bytes));
        return ptr;
    }

    pub fn free(self: *Cuda, ptr: CUdeviceptr) void {
        _ = self;
        _ = cuMemFree(ptr);
    }

    pub fn copyHtoD(self: *Cuda, dst: CUdeviceptr, src: []const u8) !void {
        _ = self;
        try check(cuMemcpyHtoD(dst, src.ptr, src.len));
    }

    pub fn copyDtoH(self: *Cuda, dst: []u8, src: CUdeviceptr) !void {
        _ = self;
        try check(cuMemcpyDtoH(dst.ptr, src, dst.len));
    }

    /// Launch `f` with a 1-D grid/block. `params` are pointers to the kernel
    /// argument *values* (the classic `void**` Driver API style), e.g.
    /// `&[_]*const anyopaque{ &dptr, &n }`.
    pub fn launch(self: *Cuda, f: CUfunction, grid: u32, block: u32, params: []const *const anyopaque) !void {
        _ = self;
        std.debug.assert(params.len <= 32);
        var buf: [32]*const anyopaque = undefined;
        @memcpy(buf[0..params.len], params);
        try check(cuLaunchKernel(f, grid, 1, 1, block, 1, 1, 0, null, @ptrCast(&buf), null));
    }

    /// Block until all pending work completes (also surfaces kernel errors).
    pub fn synchronize(self: *Cuda) !void {
        _ = self;
        try check(cuCtxSynchronize());
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "cuda error mapping returns CudaFailure" {
    try std.testing.expectError(error.CudaFailure, check(0x1e)); // CUDA_ERROR_INVALID_VALUE
}
