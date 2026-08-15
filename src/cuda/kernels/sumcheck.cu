#include "gf256.h"
#include "gf128.h"

// One round of the Binius zero-check sum-check evaluation over Gf256:
//
//   values[t] = Σ_{rest<half} Σ_{terms} coeff·∏_{f} (cur[f][2·rest] +
//               t·(cur[f][2·rest] + cur[f][2·rest+1])),   t = 0..dmax
//
// (char-2 addition is XOR). Each thread handles one `rest` position and
// atomically XORs its per-t contributions into `values_packed` (4 t's per u32,
// pre-zeroed), which the host unpacks. `sumcheck_values128` below is the same
// evaluation over Gf(2^128) for the extension-field sum-check.
//
// Regenerate the PTX with: nvcc -ptx -arch=sm_86 -o sumcheck.ptx sumcheck.cu

extern "C" __global__ void sumcheck_values(
    const unsigned char* cur_flat,   // m*len table bytes
    unsigned int len,
    unsigned int m,
    const unsigned char* coeffs,     // nterms
    const unsigned int* indices_flat, // total factor indices
    const unsigned int* offsets,     // nterms+1
    unsigned int nterms,
    unsigned int half,               // len/2
    unsigned int dmax,               // max factor count per term
    unsigned int* values_packed)     // ceil((dmax+1)/4) u32, pre-zeroed
{
    unsigned int rest = blockIdx.x * blockDim.x + threadIdx.x;
    if (rest >= half) return;

    for (unsigned int t = 0; t <= dmax; t++) {
        unsigned char s = 0;
        for (unsigned int term = 0; term < nterms; term++) {
            unsigned char prod = coeffs[term];
            for (unsigned int k = offsets[term]; k < offsets[term + 1]; k++) {
                unsigned int f = indices_flat[k];
                unsigned char a = cur_flat[f * len + 2 * rest];
                unsigned char b = cur_flat[f * len + 2 * rest + 1];
                prod = gf256_mul(prod, a ^ gf256_mul((unsigned char)t, a ^ b));
            }
            s ^= prod;
        }
        atomicXor(&values_packed[t >> 2], ((unsigned int)s) << ((t & 3) * 8));
    }
}

// The same round evaluation over Gf(2^128) (the extension-field sum-check in
// the Gf16/Gf256 + Gf2_128 modes). Each value is 16 bytes (two u64 limbs), so
// `cur_flat` is m*len*16 bytes, `coeffs` nterms*16 bytes, and each t's
// contribution is XORed into four consecutive u32 limbs of `values_packed`
// ((dmax+1)*4 u32, pre-zeroed) — one atomicXor per limb, all threads into the
// same addresses. `t` is the integer round point as a 128-bit tower element.
extern "C" __global__ void sumcheck_values128(
    const unsigned long long* cur_flat,   // m*len*2 u64 (each value = 2 limbs)
    unsigned int len,
    unsigned int m,
    const unsigned long long* coeffs,     // nterms*2 u64
    const unsigned int* indices_flat,     // total factor indices
    const unsigned int* offsets,          // nterms+1
    unsigned int nterms,
    unsigned int half,                    // len/2
    unsigned int dmax,                    // max factor count per term
    unsigned int* values_packed)          // (dmax+1)*4 u32, pre-zeroed
{
    unsigned int rest = blockIdx.x * blockDim.x + threadIdx.x;
    if (rest >= half) return;

    for (unsigned int t = 0; t <= dmax; t++) {
        gf128 s = { 0, 0 };
        gf128 tp = { (unsigned long long)t, 0 };
        for (unsigned int term = 0; term < nterms; term++) {
            gf128 prod = { coeffs[2 * term], coeffs[2 * term + 1] };
            for (unsigned int k = offsets[term]; k < offsets[term + 1]; k++) {
                unsigned int f = indices_flat[k];
                gf128 a = { cur_flat[(f * len + 2 * rest) * 2],
                            cur_flat[(f * len + 2 * rest) * 2 + 1] };
                gf128 b = { cur_flat[(f * len + 2 * rest + 1) * 2],
                            cur_flat[(f * len + 2 * rest + 1) * 2 + 1] };
                gf128 ab = gf128_xor(a, b);
                gf128 v = gf128_xor(a, gf2_128_mul(tp, ab));
                prod = gf2_128_mul(prod, v);
            }
            s = gf128_xor(s, prod);
        }
        atomicXor(&values_packed[t * 4 + 0], (unsigned int)(s.lo & 0xFFFFFFFFULL));
        atomicXor(&values_packed[t * 4 + 1], (unsigned int)(s.lo >> 32));
        atomicXor(&values_packed[t * 4 + 2], (unsigned int)(s.hi & 0xFFFFFFFFULL));
        atomicXor(&values_packed[t * 4 + 3], (unsigned int)(s.hi >> 32));
    }
}
