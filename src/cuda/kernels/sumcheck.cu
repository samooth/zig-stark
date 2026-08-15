#include "gf256.h"

// One round of the Binius zero-check sum-check evaluation over Gf256:
//
//   values[t] = Σ_{rest<half} Σ_{terms} coeff·∏_{f} (cur[f][2·rest] +
//               t·(cur[f][2·rest] + cur[f][2·rest+1])),   t = 0..dmax
//
// (char-2 addition is XOR). Each thread handles one `rest` position and
// atomically XORs its per-t contributions into `values_packed` (4 t's per u32,
// pre-zeroed), which the host unpacks.
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
