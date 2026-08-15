// Circle FFT over M31 for the Binius-stack CUDA kernels. Bit-exact with
// src/m31/ntt/circle.zig (stwo-style recursive-fold algorithm ported to the
// Fourier basis): the same interleaved [A0,B0,A1,B1,...] layout, the same
// per-layer butterfly loops, and the same bit-reversal order.
//
// The host path (src/cuda/circlefft_gpu.zig) precomputes the twiddle tree on
// the CPU with the library's own precomputeTwiddles, so every twiddle matches
// the CPU transform exactly and only the butterflies run on the GPU. Each
// layer is one kernel launch: layer `i` (block size 2^(i+1), step 2^i) has
// n/2^(i+1) blocks, each block `b` using twiddle `t = twiddles[b]`, and thread
// x = b*step + l handles the (b, l) butterfly.
//
// The inverse transform uses the same layer kernel with `inverse` set, feeding
// the inverted twiddle tree (host-side `inv`) with the circle layer first.
//
// Regenerate the PTX with: nvcc -ptx -arch=sm_86 -o circlefft.ptx circlefft.cu

#define M31_P 2147483647U

extern "C" __device__ __forceinline__ unsigned int m31_add(unsigned int a, unsigned int b) {
    unsigned long long sum = (unsigned long long)a + (unsigned long long)b;
    unsigned long long r = sum;
    if (r >= M31_P) r -= M31_P;
    r = (r & M31_P) + (r >> 31);
    if (r >= M31_P) r -= M31_P;
    return (unsigned int)r;
}

extern "C" __device__ __forceinline__ unsigned int m31_sub(unsigned int a, unsigned int b) {
    if (a >= b) return a - b;
    return M31_P - (b - a);
}

extern "C" __device__ __forceinline__ unsigned int m31_mul(unsigned int a, unsigned int b) {
    unsigned long long prod = (unsigned long long)a * (unsigned long long)b;
    unsigned int lo = (unsigned int)(prod & M31_P);
    unsigned int hi = (unsigned int)(prod >> 31);
    unsigned long long r = (unsigned long long)lo + (unsigned long long)hi;
    if (r >= M31_P) r -= M31_P;
    if (r >= M31_P) r -= M31_P;
    return (unsigned int)r;
}

extern "C" __device__ __forceinline__ unsigned int m31_neg(unsigned int a) {
    return a == 0 ? 0 : M31_P - a;
}

// Interleave A-then-B coefficients into [A0, B0, A1, B1, ...].
extern "C" __global__ void circle_interleave(
    const unsigned int* a, unsigned int* out, unsigned int half) {
    unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= half) return;
    out[2 * i] = a[i];
    out[2 * i + 1] = a[half + i];
}

// One butterfly layer (forward or inverse), as described above. `twiddles` is
// the host-prepared slice for this layer (length = n/2^(i+1)).
extern "C" __global__ void circle_fft_layer(
    unsigned int* values,
    const unsigned int* twiddles,
    unsigned int n,
    unsigned int i,
    unsigned int inverse) {
    unsigned int step = 1u << i;
    unsigned int blocks = n >> (i + 1);
    unsigned int x = blockIdx.x * blockDim.x + threadIdx.x;
    if (x >= blocks * step) return;
    unsigned int b = x / step;
    unsigned int l = x - b * step;
    unsigned int t = twiddles[b];
    unsigned int idx0 = (b << (i + 1)) + l;
    unsigned int idx1 = idx0 + step;
    unsigned int v0 = values[idx0];
    unsigned int v1 = values[idx1];
    if (inverse) {
        unsigned int tmp = v0;
        v0 = m31_add(tmp, v1);
        v1 = m31_mul(m31_sub(tmp, v1), t);
    } else {
        unsigned int tmp = m31_mul(v1, t);
        v1 = m31_sub(v0, tmp);
        v0 = m31_add(v0, tmp);
    }
    values[idx0] = v0;
    values[idx1] = v1;
}

// In-place bit-reversal permutation (length n, a power of two).
extern "C" __global__ void circle_bitreverse(unsigned int* values, unsigned int n) {
    unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    unsigned int x = i, r = 0;
    unsigned int tmp = n >> 1;
    while (tmp) {
        r = (r << 1) | (x & 1);
        x >>= 1;
        tmp >>= 1;
    }
    if (i < r) {
        unsigned int t = values[i];
        values[i] = values[r];
        values[r] = t;
    }
}

// Inverse interleave (with the IFFT normalization factor): recover A then B
// from the interleaved layout, scaling each by inv_n.
extern "C" __global__ void circle_deinterleave(
    const unsigned int* c, unsigned int* a, unsigned int half, unsigned int inv_n) {
    unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= half) return;
    a[i] = m31_mul(c[2 * i], inv_n);
    a[half + i] = m31_mul(c[2 * i + 1], inv_n);
}