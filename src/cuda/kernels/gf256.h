// Shared Gf256 (tower) device arithmetic for the Binius CUDA kernels.
// Bit-exact with src/binius/tower.zig TowerField(3) (Wiedemann tower, Cantor
// basis): the Karatsuba recursion (a0 + a1·y)(b0 + b1·y) with beta = X_{i-2}
// (GF4 beta=1, GF16 beta=0b10, GF256 beta=0b0100).

#ifndef GF256_H
#define GF256_H

extern "C" __device__ __forceinline__ unsigned char gf4_mul(unsigned char a, unsigned char b) {
    unsigned char a0 = a & 1, a1 = (a >> 1) & 1;
    unsigned char b0 = b & 1, b1 = (b >> 1) & 1;
    unsigned char c0 = a0 & b0;
    unsigned char c1 = a1 & b1;
    unsigned char c2 = (a0 ^ a1) & (b0 ^ b1);
    return (c0 ^ c1) | ((c2 ^ c0) << 1); // + c1 + c1·1
}

extern "C" __device__ __forceinline__ unsigned char gf16_mul(unsigned char a, unsigned char b) {
    unsigned char a0 = a & 0x3, a1 = (a >> 2) & 0x3;
    unsigned char b0 = b & 0x3, b1 = (b >> 2) & 0x3;
    unsigned char c0 = gf4_mul(a0, b0);
    unsigned char c1 = gf4_mul(a1, b1);
    unsigned char c2 = gf4_mul(a0 ^ a1, b0 ^ b1);
    unsigned char lo = c0 ^ c1;
    unsigned char hi = c2 ^ c0 ^ c1 ^ gf4_mul(c1, 0x2); // c1·X_0
    return lo | (hi << 2);
}

extern "C" __device__ __forceinline__ unsigned char gf256_mul(unsigned char a, unsigned char b) {
    unsigned char a0 = a & 0xF, a1 = (a >> 4) & 0xF;
    unsigned char b0 = b & 0xF, b1 = (b >> 4) & 0xF;
    unsigned char c0 = gf16_mul(a0, b0);
    unsigned char c1 = gf16_mul(a1, b1);
    unsigned char c2 = gf16_mul(a0 ^ a1, b0 ^ b1);
    unsigned char lo = c0 ^ c1;
    unsigned char hi = c2 ^ c0 ^ c1 ^ gf16_mul(c1, 0x4); // c1·X_1
    return lo | (hi << 4);
}

#endif // GF256_H
