// 128-bit tower field arithmetic for the Binius CUDA kernels. Bit-exact with
// src/binius/tower.zig TowerField(7) (Wiedemann tower, Cantor basis) via the
// same Karatsuba recursion used by gf256.h:
//
//     (a0 + a1·y)(b0 + b1·y) = (c0 + c1) + (c2 + c0 + c1 + c1·β)·y
//
// with c0 = a0·b0, c1 = a1·b1, c2 = (a0+a1)(b0+b1) and the level-L quadratic
// constant β = X_{L-2} (GF4 β=1, GF16 β=0b10, GF256 β=0b0100, 16-bit β=0x10,
// 32-bit β=0x100, 64-bit β=0x10000, 128-bit β=0x100000000).
//
// CUDA has no 128-bit integer type, so Gf(2^128) elements are a pair of u64s
// (lo, hi), matching the little-endian byte layout of a u128.

#ifndef GF128_H
#define GF128_H

#include "gf256.h"

// level 4: GF(2^16)
extern "C" __device__ __forceinline__ unsigned short gf2_16_mul(unsigned short a, unsigned short b) {
    unsigned short a0 = a & 0xFF, a1 = (a >> 8) & 0xFF;
    unsigned short b0 = b & 0xFF, b1 = (b >> 8) & 0xFF;
    unsigned short c0 = gf256_mul(a0, b0);
    unsigned short c1 = gf256_mul(a1, b1);
    unsigned short c2 = gf256_mul(a0 ^ a1, b0 ^ b1);
    unsigned short lo = c0 ^ c1;
    unsigned short hi = c2 ^ c0 ^ c1 ^ gf256_mul(c1, 0x10); // c1·X_2
    return (unsigned short)(lo | (hi << 8));
}

// level 5: GF(2^32)
extern "C" __device__ __forceinline__ unsigned int gf2_32_mul(unsigned int a, unsigned int b) {
    unsigned int a0 = a & 0xFFFF, a1 = (a >> 16) & 0xFFFF;
    unsigned int b0 = b & 0xFFFF, b1 = (b >> 16) & 0xFFFF;
    unsigned int c0 = gf2_16_mul(a0, b0);
    unsigned int c1 = gf2_16_mul(a1, b1);
    unsigned int c2 = gf2_16_mul(a0 ^ a1, b0 ^ b1);
    unsigned int lo = c0 ^ c1;
    unsigned int hi = c2 ^ c0 ^ c1 ^ gf2_16_mul(c1, 0x100); // c1·X_3
    return lo | (hi << 16);
}

// level 6: GF(2^64)
extern "C" __device__ __forceinline__ unsigned long long gf2_64_mul(unsigned long long a, unsigned long long b) {
    unsigned long long a0 = a & 0xFFFFFFFFULL, a1 = (a >> 32) & 0xFFFFFFFFULL;
    unsigned long long b0 = b & 0xFFFFFFFFULL, b1 = (b >> 32) & 0xFFFFFFFFULL;
    unsigned long long c0 = gf2_32_mul((unsigned int)a0, (unsigned int)b0);
    unsigned long long c1 = gf2_32_mul((unsigned int)a1, (unsigned int)b1);
    unsigned long long c2 = gf2_32_mul((unsigned int)(a0 ^ a1), (unsigned int)(b0 ^ b1));
    unsigned long long lo = c0 ^ c1;
    unsigned long long hi = c2 ^ c0 ^ c1 ^ gf2_32_mul((unsigned int)c1, 0x10000U); // c1·X_4
    return lo | (hi << 32);
}

typedef struct { unsigned long long lo, hi; } gf128;

extern "C" __device__ __forceinline__ gf128 gf128_xor(gf128 a, gf128 b) {
    gf128 r = { a.lo ^ b.lo, a.hi ^ b.hi };
    return r;
}

// level 7: GF(2^128)
extern "C" __device__ __forceinline__ gf128 gf2_128_mul(gf128 a, gf128 b) {
    unsigned long long c0 = gf2_64_mul(a.lo, b.lo);
    unsigned long long c1 = gf2_64_mul(a.hi, b.hi);
    unsigned long long c2 = gf2_64_mul(a.lo ^ a.hi, b.lo ^ b.hi);
    unsigned long long lo = c0 ^ c1;
    unsigned long long hi = c2 ^ c0 ^ c1 ^ gf2_64_mul(c1, 0x100000000ULL); // c1·X_5
    gf128 r = { lo, hi };
    return r;
}

#endif // GF128_H
