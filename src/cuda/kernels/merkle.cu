// Merkle tree building over Blake3 for the Binius-stack CUDA kernels. Bit-exact
// with src/core/hash/hash.zig's `hash2(a, b)` = Blake3("zig-stark:pair" || a || b):
// an 80-byte single-chunk message (14-byte domain prefix + two 32-byte digests),
// implemented with the reference Blake3 compression (BLAKE2s-style 7-round
// mixing with the sigma schedule).
//
// The host path (src/cuda/merkle_gpu.zig) feeds it pre-hashed leaves and runs
// one `merkle_layer` launch per level: thread i hashes child pair (2i, 2i+1) of
// `src` into digest i of `dst`, ping-ponging between two device buffers until
// the root. Leaves are hashed on the CPU (each caller serializes field bytes
// differently); only the internal hash2 reduce runs on the GPU.
//
// Regenerate the PTX with: nvcc -ptx -arch=sm_86 -o merkle.ptx merkle.cu

#include <string.h>
#include <stdint.h>

#define IV0 0x6A09E667u
#define IV1 0xBB67AE85u
#define IV2 0x3C6EF372u
#define IV3 0xA54FF53Au
#define IV4 0x510E527Fu
#define IV5 0x9B05688Cu
#define IV6 0x1F83D9ABu
#define IV7 0x5BE0CD19u

#define CHUNK_START 1u
#define CHUNK_END 2u
#define ROOT 8u

// Blake3 sigma schedule (index 0 is the identity). Constant memory (device-side
// static arrays are invisible to device code).
__constant__ uint32_t SIGMA0[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
__constant__ uint32_t SIGMA1[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};
__constant__ uint32_t SIGMA2[16] = {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1};
__constant__ uint32_t SIGMA3[16] = {4, 12, 13, 2, 3, 10, 6, 7, 14, 8, 9, 15, 5, 1, 0, 11};
__constant__ uint32_t SIGMA4[16] = {13, 2, 3, 10, 12, 4, 14, 7, 6, 1, 15, 8, 11, 0, 5, 9};
__constant__ uint32_t SIGMA5[16] = {10, 12, 4, 13, 3, 14, 15, 2, 6, 8, 11, 9, 7, 5, 0, 1};
__constant__ uint32_t SIGMA6[16] = {12, 13, 10, 4, 14, 3, 6, 15, 2, 0, 7, 1, 11, 8, 5, 9};

__device__ __forceinline__ uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32u - n));
}

__device__ __forceinline__ void g_round(
    uint32_t* s, uint32_t a, uint32_t b, uint32_t c, uint32_t d,
    uint32_t mx, uint32_t my) {
    s[a] = s[a] + s[b] + mx;
    s[d] = rotr32(s[d] ^ s[a], 16);
    s[c] = s[c] + s[d];
    s[b] = rotr32(s[b] ^ s[c], 12);
    s[a] = s[a] + s[b] + my;
    s[d] = rotr32(s[d] ^ s[a], 8);
    s[c] = s[c] + s[d];
    s[b] = rotr32(s[b] ^ s[c], 7);
}

__device__ __forceinline__ void round_fn(uint32_t s[16], const uint32_t* m, const uint32_t* schedule) {
    g_round(s, 0, 4, 8, 12, m[schedule[0]], m[schedule[1]]);
    g_round(s, 1, 5, 9, 13, m[schedule[2]], m[schedule[3]]);
    g_round(s, 2, 6, 10, 14, m[schedule[4]], m[schedule[5]]);
    g_round(s, 3, 7, 11, 15, m[schedule[6]], m[schedule[7]]);
    g_round(s, 0, 5, 10, 15, m[schedule[8]], m[schedule[9]]);
    g_round(s, 1, 6, 11, 12, m[schedule[10]], m[schedule[11]]);
    g_round(s, 2, 7, 8, 13, m[schedule[12]], m[schedule[13]]);
    g_round(s, 3, 4, 9, 14, m[schedule[14]], m[schedule[15]]);
}

__device__ void blake3_compress(
    const uint32_t cv[8], const uint32_t m[16], uint64_t counter,
    uint32_t block_len, uint32_t flags, uint32_t out[16]) {
    uint32_t s[16];
    s[0] = cv[0]; s[1] = cv[1]; s[2] = cv[2]; s[3] = cv[3];
    s[4] = cv[4]; s[5] = cv[5]; s[6] = cv[6]; s[7] = cv[7];
    s[8] = IV0; s[9] = IV1; s[10] = IV2; s[11] = IV3;
    s[12] = IV4 ^ (uint32_t)(counter & 0xFFFFFFFFull);
    s[13] = IV5 ^ (uint32_t)(counter >> 32);
    s[14] = IV6 ^ block_len;
    s[15] = IV7 ^ flags;
    round_fn(s, m, SIGMA0);
    round_fn(s, m, SIGMA1);
    round_fn(s, m, SIGMA2);
    round_fn(s, m, SIGMA3);
    round_fn(s, m, SIGMA4);
    round_fn(s, m, SIGMA5);
    round_fn(s, m, SIGMA6);
    out[0] = s[0] ^ s[8] ^ m[0];
    out[1] = s[1] ^ s[9] ^ m[1];
    out[2] = s[2] ^ s[10] ^ m[2];
    out[3] = s[3] ^ s[11] ^ m[3];
    out[4] = s[4] ^ s[12] ^ m[4];
    out[5] = s[5] ^ s[13] ^ m[5];
    out[6] = s[6] ^ s[14] ^ m[6];
    out[7] = s[7] ^ s[15] ^ m[7];
    out[8] = s[8] ^ cv[0];
    out[9] = s[9] ^ cv[1];
    out[10] = s[10] ^ cv[2];
    out[11] = s[11] ^ cv[3];
    out[12] = s[12] ^ cv[4];
    out[13] = s[13] ^ cv[5];
    out[14] = s[14] ^ cv[6];
    out[15] = s[15] ^ cv[7];
}

__device__ __forceinline__ void load_words(const unsigned char* b, uint32_t w[16]) {
#pragma unroll
    for (int i = 0; i < 16; i++) {
        uint32_t o = (uint32_t)(i * 4);
        w[i] = (uint32_t)b[o] | ((uint32_t)b[o + 1] << 8) |
               ((uint32_t)b[o + 2] << 16) | ((uint32_t)b[o + 3] << 24);
    }
}

// Blake3("zig-stark:pair" || a || b) for 32-byte digests a and b.
__device__ void blake3_hash2(const unsigned char* a, const unsigned char* b, unsigned char* out) {
    // 80-byte single-chunk message: 14-byte prefix, then a (32), then b (32).
    // Only the first full 64-byte block is compressed into the chaining value;
    // the final partial block feeds the root output compression directly.
    static const uint32_t iv[8] = {IV0, IV1, IV2, IV3, IV4, IV5, IV6, IV7};
    unsigned char block0[64];
    unsigned char block1[64];
    static const unsigned char prefix[14] = {'z', 'i', 'g', '-', 's', 't', 'a', 'r', 'k', ':', 'p', 'a', 'i', 'r'};
    memcpy(block0, prefix, 14);
    memcpy(block0 + 14, a, 32);
    memcpy(block0 + 46, b, 18);
    memcpy(block1, b + 18, 14);
    memset(block1 + 14, 0, 50);

    uint32_t m0[16], m1[16], cv[8], w[16];
    load_words(block0, m0);
    load_words(block1, m1);

    blake3_compress(iv, m0, 0, 64, CHUNK_START, w);
    for (int i = 0; i < 8; i++) cv[i] = w[i];
    blake3_compress(cv, m1, 1, 14, CHUNK_END | ROOT, w);

    for (int i = 0; i < 8; i++) {
        uint32_t o = (uint32_t)(i * 4);
        out[o] = (unsigned char)(w[i]);
        out[o + 1] = (unsigned char)(w[i] >> 8);
        out[o + 2] = (unsigned char)(w[i] >> 16);
        out[o + 3] = (unsigned char)(w[i] >> 24);
    }
}

// One level of the tree: `n` input digests -> n/2 output digests (hash2 pairs).
extern "C" __global__ void merkle_layer(const unsigned char* src, unsigned char* dst, uint32_t n) {
    uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    uint32_t half = n >> 1;
    if (i >= half) return;
    blake3_hash2(src + 64 * i, src + 64 * i + 32, dst + 32 * i);
}