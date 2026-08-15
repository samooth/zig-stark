#include "gf256.h"

// Validation kernel: out[i] = gf256_mul(a[i], b[i]).
extern "C" __global__ void gf_mul(unsigned char* out, const unsigned char* a, const unsigned char* b, unsigned int n) {
    unsigned int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) out[i] = gf256_mul(a[i], b[i]);
}
